package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeReader returns canned results per server name.
type fakeReader struct {
	byName map[string]ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return ReadResult{}, err
	}
	return f.byName[srv.Name], nil
}

// testConfig: alice(key1)->web-1; server orphan has no grants.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: orphan, host: 10.0.0.9, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("test config: %v", err)
	}
	return cfg
}

func TestAuditOneCompliant(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if !res.Compliant() {
		t.Errorf("want compliant, got %+v", res)
	}
	if len(res.Diff.OK) != 1 {
		t.Errorf("OK = %d, want 1", len(res.Diff.OK))
	}
}

func TestAuditOneDrift(t *testing.T) {
	cfg := testConfig(t)
	// web-1 has an unauthorized key installed and alice's key missing.
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 9) + "\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if res.Compliant() {
		t.Error("want non-compliant")
	}
	if len(res.Diff.Missing) != 1 || len(res.Diff.Unauthorized) != 1 {
		t.Errorf("Missing=%d Unauthorized=%d, want 1/1",
			len(res.Diff.Missing), len(res.Diff.Unauthorized))
	}
}

func TestAuditOneConnectionError(t *testing.T) {
	cfg := testConfig(t)
	boom := errors.New("dial tcp: connection refused")
	r := &fakeReader{errs: map[string]error{"web-1": boom}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if res.Compliant() {
		t.Error("errored server must be non-compliant")
	}
	if !errors.Is(res.Err, boom) {
		t.Errorf("Err = %v, want the reader error", res.Err)
	}
}

func TestAuditOneFileAbsent(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1": {FileAbsent: true},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if !res.FileAbsent {
		t.Error("FileAbsent not propagated")
	}
	if len(res.Diff.Missing) != 1 {
		t.Errorf("Missing = %d, want 1 (desired key not installed)", len(res.Diff.Missing))
	}
}

func TestAuditOneParseErrors(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\ngarbage\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if len(res.ParseErrs) != 1 {
		t.Fatalf("ParseErrs = %d, want 1", len(res.ParseErrs))
	}
	if res.Compliant() {
		t.Error("unparseable file must be non-compliant")
	}
}

func TestAuditOneNoUsersGranted(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]ReadResult{
		"orphan": {Content: []byte(testkeys.Line(t, 9) + "\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[1], 0)
	if !res.NoUsersGranted {
		t.Error("NoUsersGranted = false, want true")
	}
	if len(res.Diff.Unauthorized) != 1 {
		t.Errorf("Unauthorized = %d, want 1", len(res.Diff.Unauthorized))
	}
}

// gateReader tracks concurrency and can block until released or ctx expiry.
type gateReader struct {
	inflight, maxSeen atomic.Int32
	block             map[string]bool // server names that hang until ctx is done
	delay             time.Duration
}

func (g *gateReader) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (ReadResult, error) {
	cur := g.inflight.Add(1)
	defer g.inflight.Add(-1)
	for {
		prev := g.maxSeen.Load()
		if cur <= prev || g.maxSeen.CompareAndSwap(prev, cur) {
			break
		}
	}
	if g.block[srv.Name] {
		<-ctx.Done()
		return ReadResult{}, fmt.Errorf("read %s: %w", srv.Name, ctx.Err())
	}
	if g.delay > 0 {
		time.Sleep(g.delay)
	}
	return ReadResult{}, nil
}

// fleetConfig builds a config with n servers named srv-00 .. srv-N, no users.
func fleetConfig(t testing.TB, n int) *config.Config {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("servers:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "  - {name: srv-%02d, host: 10.0.0.%d, user: deploy}\n", i, i+1)
	}
	cfg, err := config.Parse([]byte(sb.String()))
	if err != nil {
		t.Fatalf("fleetConfig: %v", err)
	}
	return cfg
}

func TestRunPoolCap(t *testing.T) {
	cfg := fleetConfig(t, 20)
	g := &gateReader{delay: 20 * time.Millisecond}
	Run(context.Background(), cfg, g, Options{Parallel: 3})
	gotMax := g.maxSeen.Load()
	if gotMax > 3 {
		t.Errorf("max concurrent reads = %d, want <= 3", gotMax)
	}
	if gotMax < 2 {
		t.Errorf("max concurrent reads = %d, want >= 2 (pool should actually run in parallel)", gotMax)
	}
}

func TestRunDeterministicOrder(t *testing.T) {
	cfg := fleetConfig(t, 10)
	g := &gateReader{delay: time.Millisecond}
	results := Run(context.Background(), cfg, g, Options{Parallel: 8})
	if len(results) != 10 {
		t.Fatalf("results = %d, want 10", len(results))
	}
	for i, r := range results {
		want := fmt.Sprintf("srv-%02d", i)
		if r.Server.Name != want {
			t.Fatalf("results[%d] = %s, want %s (sorted by name)", i, r.Server.Name, want)
		}
	}
}

func TestRunHangingServerDoesNotPoisonOthers(t *testing.T) {
	cfg := fleetConfig(t, 5)
	g := &gateReader{block: map[string]bool{"srv-02": true}}
	results := Run(context.Background(), cfg, g, Options{
		Parallel:         5,
		PerServerTimeout: 50 * time.Millisecond,
	})
	var hung, fine int
	for _, r := range results {
		if r.Server.Name == "srv-02" {
			if r.Err == nil {
				t.Error("hanging server should have timed out with an error")
			}
			hung++
		} else if r.Err == nil {
			fine++
		}
	}
	if hung != 1 || fine != 4 {
		t.Errorf("hung=%d fine=%d, want 1/4", hung, fine)
	}
}
