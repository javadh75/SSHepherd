package audit

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// bastionManifest: alice (k1) granted every server; edge is a jump_only
// bastion, n servers sit behind it, and db-1 is direct.
func bastionManifest(t *testing.T, n int) *config.Config {
	t.Helper()
	var b strings.Builder
	b.WriteString("users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\nservers:\n")
	b.WriteString("  - {name: edge, host: edge.example.com, user: jump, jump_only: true}\n")
	for i := range n {
		fmt.Fprintf(&b, "  - {name: web-%02d, host: 10.0.1.%d, user: deploy, via: edge}\n", i+1, i+1)
	}
	b.WriteString("  - {name: db-1, host: 10.0.2.1, user: deploy}\naccess:\n  - {user: alice, servers: [\"*\"]}\n")
	cfg, err := config.Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// gaugeReader holds each read for hold (honoring ctx) and records the most
// reads in flight through a bastion at once.
type gaugeReader struct {
	hold      time.Duration
	now, peak atomic.Int32
	mu        sync.Mutex
	read      []string
	content   []byte
}

func (g *gaugeReader) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (fleet.ReadResult, error) {
	g.mu.Lock()
	g.read = append(g.read, srv.Name)
	g.mu.Unlock()
	if srv.Via != "" {
		n := g.now.Add(1)
		defer g.now.Add(-1)
		for { // raise peak to n (revive: no empty loop body)
			p := g.peak.Load()
			if n <= p || g.peak.CompareAndSwap(p, n) {
				break
			}
		}
	}
	select {
	case <-time.After(g.hold):
		return fleet.ReadResult{Content: g.content}, nil
	case <-ctx.Done():
		return fleet.ReadResult{}, fmt.Errorf("read %s: %w", srv.Name, ctx.Err())
	}
}

// TestRunNeverReadsJumpOnly: the jump_only row is added without a reader
// call or a fan-out slot, and is no error.
func TestRunNeverReadsJumpOnly(t *testing.T) {
	cfg := bastionManifest(t, 1)
	g := &gaugeReader{}
	results := Run(context.Background(), cfg, g, Options{Parallel: 1})
	if len(results) != 3 || results[1].Server.Name != "edge" || results[1].Err != nil {
		t.Fatalf("results = %+v, want edge listed with no error", results)
	}
	for _, name := range g.read {
		if name == "edge" {
			t.Fatal("the jump_only server was read")
		}
	}
}

// TestRunCapsReadsPerBastion (OP2): never more than fleet.HopCap reads in
// flight through one bastion, whatever --parallel says.
func TestRunCapsReadsPerBastion(t *testing.T) {
	g := &gaugeReader{hold: 30 * time.Millisecond}
	Run(context.Background(), bastionManifest(t, 3*fleet.HopCap), g, Options{Parallel: 32})
	if p := g.peak.Load(); p > fleet.HopCap || p < 2 {
		t.Errorf("peak reads through edge = %d, want 2..%d", p, fleet.HopCap)
	}
}

// TestRunCapsReadsThroughWholeChain: a read behind mid1 or mid2 takes a
// slot on edge too (its whole chain, root first), so the reads in flight
// through edge stay at fleet.HopCap however they split between the inner
// bastions. Every server here except edge and db-1 sits behind edge, so the
// gauge's "has a via" count is the count through edge.
func TestRunCapsReadsThroughWholeChain(t *testing.T) {
	var b strings.Builder
	b.WriteString("users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\nservers:\n")
	b.WriteString("  - {name: edge, host: edge.example.com, user: jump, jump_only: true}\n")
	b.WriteString("  - {name: mid1, host: 10.0.8.1, user: ops, via: edge}\n  - {name: mid2, host: 10.0.9.1, user: ops, via: edge}\n")
	for i := range fleet.HopCap {
		fmt.Fprintf(&b, "  - {name: a-%02d, host: 10.0.1.%d, user: deploy, via: mid1}\n", i+1, i+1)
		fmt.Fprintf(&b, "  - {name: b-%02d, host: 10.0.2.%d, user: deploy, via: mid2}\n", i+1, i+1)
	}
	b.WriteString("  - {name: db-1, host: 10.0.3.1, user: deploy}\naccess:\n  - {user: alice, servers: [\"*\"]}\n")
	cfg, err := config.Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	g := &gaugeReader{hold: 30 * time.Millisecond}
	Run(context.Background(), cfg, g, Options{Parallel: 64})
	if p := g.peak.Load(); p > fleet.HopCap {
		t.Errorf("peak reads through edge = %d, want at most %d (a read takes a slot on every bastion of its chain)", p, fleet.HopCap)
	}
}

// TestRunBastionWaitBurnsNoBudget: the slot is taken before the per-server
// timeout starts, so a server queued behind a full bastion still gets its
// whole budget. It passes before Step 3 too (no limiter: all 17 reads run
// at once inside 250ms); it pins the slot-before-budget order against
// mutant 16, and TestRunCapsReadsPerBastion is the failing-first test.
func TestRunBastionWaitBurnsNoBudget(t *testing.T) {
	g := &gaugeReader{hold: 150 * time.Millisecond}
	for _, r := range Run(context.Background(), bastionManifest(t, 2*fleet.HopCap), g, Options{Parallel: 32, PerServerTimeout: 250 * time.Millisecond}) {
		if r.Err != nil {
			t.Errorf("%s: %v (the wait for a bastion slot used its budget)", r.Server.Name, r.Err)
		}
	}
}

// TestRunCancelWhileWaitingForBastion: Ctrl-C releases a server still
// queued behind a full bastion without reading it.
func TestRunCancelWhileWaitingForBastion(t *testing.T) {
	g := &gaugeReader{hold: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	results := Run(ctx, bastionManifest(t, fleet.HopCap+1), g, Options{Parallel: 32})
	if n := len(g.read); n != fleet.HopCap+1 { // HopCap through edge, plus db-1
		t.Errorf("reads started = %d, want %d", n, fleet.HopCap+1)
	}
	for _, r := range results {
		if r.Server.JumpOnly {
			continue
		}
		if k := fleet.ErrorKindOf(r.Err); k != fleet.ErrorKindCanceled {
			t.Errorf("%s: kind %q, want canceled", r.Server.Name, k)
		}
	}
}

// hopFail is a transport-like error at a bastion (audit cannot import
// sshconn, ARC-8).
type hopFail struct {
	kind fleet.ErrorKind
	hop  string
}

func (e hopFail) Error() string              { return "via " + e.hop + ": presented key changed" }
func (e hopFail) ErrorKind() fleet.ErrorKind { return e.kind }
func (e hopFail) FailedHop() string          { return e.hop }
func (e hopFail) ErrorHint() string {
	return "HOST KEY CHANGED for edge.example.com:22 — possible impersonation"
}

// scriptedReader serves content to every server, except the ones errs
// fails.
type scriptedReader struct {
	content []byte
	errs    map[string]error
}

func (s scriptedReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (fleet.ReadResult, error) {
	if err := s.errs[srv.Name]; err != nil {
		return fleet.ReadResult{}, err
	}
	return fleet.ReadResult{Content: s.content}, nil
}

// renderBoth checks the text and JSON reports against name's goldens
// (checkGolden, internal/audit/report_test.go:24, reads testdata/NAME).
func renderBoth(t *testing.T, cfg *config.Config, results []ServerResult, name string) {
	t.Helper()
	var text, js bytes.Buffer
	Render(&text, cfg, results, RenderOptions{})
	if err := RenderJSON(&js, cfg, results, JSONOptions{}); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, name+".golden", text.Bytes())
	checkGolden(t, name+".golden.json", js.Bytes())
}

// TestRenderJumpOnlyGolden: the jump only row, the via head, status
// jump_only, summary.jump_only, exit 0.
func TestRenderJumpOnlyGolden(t *testing.T) {
	cfg := bastionManifest(t, 1)
	results := Run(context.Background(), cfg, scriptedReader{content: []byte(testkeys.Line(t, 1) + "\n")}, Options{Parallel: 4})
	if code := ExitCode(cfg, results); code != 0 {
		t.Errorf("ExitCode = %d, want 0", code)
	}
	renderBoth(t, cfg, results, "report_jump_only")
}

// TestRenderViaFailedGolden: one changed bastion key behind two servers is
// one host-key alert, exit 2, via_failed on each.
func TestRenderViaFailedGolden(t *testing.T) {
	cfg := bastionManifest(t, 2)
	changed := hopFail{kind: fleet.ErrorKindHostKeyChanged, hop: "edge"}
	results := Run(context.Background(), cfg, scriptedReader{content: []byte(testkeys.Line(t, 1) + "\n"),
		errs: map[string]error{"web-01": changed, "web-02": changed}}, Options{Parallel: 4})
	if code := ExitCode(cfg, results); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
	if c := tallyResults(cfg, results); c.hostKeyAlerts != 1 || c.jumpOnly != 1 {
		t.Errorf("tally = %+v, want 1 alert and 1 jump only", c)
	}
	renderBoth(t, cfg, results, "report_via_failed")
}

// TestUnknownBastionKeyIsNoAlert: an unrecorded bastion key stops the
// tunnel (unreachable, exit 1) but is no host-key alert: nothing changed,
// so nobody is paged (D28).
func TestUnknownBastionKeyIsNoAlert(t *testing.T) {
	cfg := bastionManifest(t, 2)
	unknown := hopFail{kind: fleet.ErrorKindHostKeyUnknown, hop: "edge"}
	results := Run(context.Background(), cfg, scriptedReader{content: []byte(testkeys.Line(t, 1) + "\n"),
		errs: map[string]error{"web-01": unknown, "web-02": unknown}}, Options{Parallel: 4})
	if code := ExitCode(cfg, results); code != 1 {
		t.Errorf("ExitCode = %d, want 1", code)
	}
	if c := tallyResults(cfg, results); c.hostKeyAlerts != 0 || c.unreachable != 2 {
		t.Errorf("tally = %+v, want no alert and 2 unreachable", c)
	}
}

// TestHostKeyAlertsDedupeManagedBastion: a managed bastion's own changed
// key and the same failure on every server behind it are one alert
// (alertSource keys both by the bastion's name).
func TestHostKeyAlertsDedupeManagedBastion(t *testing.T) {
	cfg, err := config.Parse([]byte("users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\nservers:\n" +
		"  - {name: edge, host: edge.example.com, user: jump}\n" +
		"  - {name: web-01, host: 10.0.1.1, user: deploy, via: edge}\n  - {name: web-02, host: 10.0.1.2, user: deploy, via: edge}\n" +
		"access:\n  - {user: alice, servers: [\"*\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	own := hopFail{kind: fleet.ErrorKindHostKeyChanged} // no FailedHop: the bastion's own row
	behind := hopFail{kind: fleet.ErrorKindHostKeyChanged, hop: "edge"}
	results := Run(context.Background(), cfg, scriptedReader{errs: map[string]error{"edge": own, "web-01": behind, "web-02": behind}}, Options{Parallel: 4})
	if c := tallyResults(cfg, results); c.hostKeyAlerts != 1 || c.unreachable != 3 {
		t.Errorf("tally = %+v, want 1 alert over 3 unreachable", c)
	}
	if code := ExitCode(cfg, results); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
}
