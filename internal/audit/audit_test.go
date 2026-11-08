package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/clog"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// discardLogger is passed to direct auditOne calls that don't exercise
// logging themselves (see TestRunLogsPerServer for the logging behavior).
var discardLogger = slog.New(slog.DiscardHandler)

// fakeReader returns canned results per server name.
type fakeReader struct {
	byName map[string]fleet.ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (fleet.ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return fleet.ReadResult{}, err
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0, discardLogger)
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 9) + "\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0, discardLogger)
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
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0, discardLogger)
	if res.Compliant() {
		t.Error("errored server must be non-compliant")
	}
	if !errors.Is(res.Err, boom) {
		t.Errorf("Err = %v, want the reader error", res.Err)
	}
}

func TestAuditOneFileAbsent(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {FileAbsent: true},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0, discardLogger)
	if !res.FileAbsent {
		t.Error("FileAbsent not propagated")
	}
	if len(res.Diff.Missing) != 1 {
		t.Errorf("Missing = %d, want 1 (desired key not installed)", len(res.Diff.Missing))
	}
}

func TestAuditOneParseErrors(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\ngarbage\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0, discardLogger)
	if len(res.ParseErrs) != 1 {
		t.Fatalf("ParseErrs = %d, want 1", len(res.ParseErrs))
	}
	if res.Compliant() {
		t.Error("unparseable file must be non-compliant")
	}
}

func TestAuditOneNoUsersGranted(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"orphan": {Content: []byte(testkeys.Line(t, 9) + "\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[1], 0, discardLogger)
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

func (g *gateReader) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (fleet.ReadResult, error) {
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
		return fleet.ReadResult{}, fmt.Errorf("read %s: %w", srv.Name, ctx.Err())
	}
	if g.delay > 0 {
		time.Sleep(g.delay)
	}
	return fleet.ReadResult{}, nil
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
	// A real clog handler (not discard) so concurrent workers exercise the
	// handler mutex under genuine contention; the race detector is the assert.
	var logBuf bytes.Buffer
	log := slog.New(clog.NewHandler(&logBuf, clog.Options{Level: slog.LevelDebug}))
	Run(context.Background(), cfg, g, Options{Parallel: 3, Logger: log})
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

// TestRunLogsPerServer pins the live per-server telemetry: failures WARN as
// they happen, successes leave a DEBUG breadcrumb with a duration.
func TestRunLogsPerServer(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{errs: map[string]error{
		"web-2": errors.New("dial tcp: connection refused"),
	}}
	var buf bytes.Buffer
	log := slog.New(clog.NewHandler(&buf, clog.Options{Level: slog.LevelDebug}))
	Run(context.Background(), cfg, reader, Options{Parallel: 2, Logger: log})

	got := buf.String()
	if !strings.Contains(got, "warn: web-2: dial tcp: connection refused") {
		t.Errorf("log = %q, want a live warn line for web-2", got)
	}
	if !strings.Contains(got, "audited") || !strings.Contains(got, "server=web-1") {
		t.Errorf("log = %q, want a debug audited line for web-1", got)
	}
	if strings.Contains(got, "warn: web-1") {
		t.Errorf("log = %q, drift must not warn — only read failures do", got)
	}
}

// countingReader counts reads; any read after cancellation is a wasted dial.
type countingReader struct{ calls atomic.Int32 }

func (c *countingReader) ReadAuthorizedKeys(ctx context.Context, _ config.Server) (fleet.ReadResult, error) {
	c.calls.Add(1)
	return fleet.ReadResult{}, fmt.Errorf("read: %w", ctx.Err())
}

// TestRunPreCanceledReadsNothing: a run whose ctx is already canceled takes
// no slot, dials nothing, and marks every server canceled without a warning.
func TestRunPreCanceledReadsNothing(t *testing.T) {
	cfg := fleetConfig(t, 50)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := &countingReader{}
	var logBuf bytes.Buffer
	log := slog.New(clog.NewHandler(&logBuf, clog.Options{Level: slog.LevelDebug}))
	results := Run(ctx, cfg, r, Options{Parallel: 1, Logger: log})
	if n := r.calls.Load(); n != 0 {
		t.Errorf("reader called %d times on a canceled run, want 0", n)
	}
	for _, res := range results {
		if fleet.ErrorKindOf(res.Err) != fleet.ErrorKindCanceled {
			t.Fatalf("%s: err %v (kind %q), want canceled", res.Server.Name, res.Err, fleet.ErrorKindOf(res.Err))
		}
	}
	if strings.Contains(logBuf.String(), "warn:") {
		t.Errorf("canceled servers must not warn:\n%s", logBuf.String())
	}
}

// cancelingReader cancels the run from inside the first read (Ctrl-C
// mid-fan-out) and reports the canceled ctx, like sshconn would.
type cancelingReader struct {
	countingReader
	cancel context.CancelFunc
}

func (c *cancelingReader) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (fleet.ReadResult, error) {
	c.cancel()
	return c.countingReader.ReadAuthorizedKeys(ctx, srv)
}

func TestRunCancelMidFanOutStopsQueue(t *testing.T) {
	cfg := fleetConfig(t, 50)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &cancelingReader{cancel: cancel}
	var logBuf bytes.Buffer
	log := slog.New(clog.NewHandler(&logBuf, clog.Options{Level: slog.LevelDebug}))
	Run(ctx, cfg, r, Options{Parallel: 1, Logger: log})
	if n := r.calls.Load(); n != 1 {
		t.Errorf("reads = %d, want 1 (queued servers must not dial after Ctrl-C)", n)
	}
	if strings.Contains(logBuf.String(), "warn:") {
		t.Errorf("canceled reads must not warn:\n%s", logBuf.String())
	}
}

// blockingReader parks the first read until release is closed, ignoring
// ctx (a read stuck in a slow handshake), and counts every read.
type blockingReader struct {
	countingReader
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingReader) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (fleet.ReadResult, error) {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	return b.countingReader.ReadAuthorizedKeys(ctx, srv)
}

// runWorkers counts the goroutines Run started that are still alive.
func runWorkers() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for g := range bytes.SplitSeq(buf, []byte("\n\n")) {
		if bytes.Contains(g, []byte("internal/audit.Run.func")) {
			n++
		}
	}
	return n
}

// TestRunCancelReleasesQueuedServers (COR-7): Ctrl-C ends a server that is
// still waiting for a fan-out slot at once — it does not wait for the slot
// a slow read holds. With --parallel 1 and the only slot stuck in a read
// that ignores ctx, the queued servers' workers must be gone before that
// read returns.
func TestRunCancelReleasesQueuedServers(t *testing.T) {
	cfg := fleetConfig(t, 3)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := &blockingReader{entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan []ServerResult)
	go func() { done <- Run(ctx, cfg, r, Options{Parallel: 1}) }()
	<-r.entered
	cancel()
	deadline := time.Now().Add(5 * time.Second)
	for runWorkers() > 1 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	left := runWorkers()
	close(r.release)
	results := <-done
	if left != 1 {
		t.Errorf("%d fan-out workers alive after cancel while one read holds the only slot, want 1 (queued servers must not wait for a slot)", left)
	}
	if n := r.calls.Load(); n != 1 {
		t.Errorf("reads = %d, want 1", n)
	}
	for _, res := range results {
		if fleet.ErrorKindOf(res.Err) != fleet.ErrorKindCanceled {
			t.Errorf("%s: err %v (kind %q), want canceled", res.Server.Name, res.Err, fleet.ErrorKindOf(res.Err))
		}
	}
}

// TestRunNilLoggerSafe: Options.Logger is optional.
func TestRunNilLoggerSafe(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{}
	Run(context.Background(), cfg, reader, Options{Parallel: 1}) // must not panic
}

func TestAuditOneRetainsContentAndSessionKey(t *testing.T) {
	cfg := testConfig(t)
	content := testkeys.Line(t, 1) + "\n"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(content), SessionKeyFP: "SHA256:sessionkey"},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0, discardLogger)
	if string(res.Content) != content {
		t.Errorf("Content = %q, want the raw bytes retained (apply's byte-exact convergence input)", res.Content)
	}
	if res.SessionKeyFP != "SHA256:sessionkey" {
		t.Errorf("SessionKeyFP = %q, want carried through", res.SessionKeyFP)
	}
}

func TestRunServerSubset(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1":  {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"orphan": {Content: []byte("")},
	}}
	results := Run(context.Background(), cfg, r, Options{
		Parallel: 2,
		Servers:  []config.Server{cfg.Servers[1]}, // orphan only
	})
	if len(results) != 1 || results[0].Server.Name != "orphan" {
		t.Fatalf("results = %d (%v), want exactly the orphan subset", len(results), results)
	}
	// nil Servers still means the whole fleet.
	if got := len(Run(context.Background(), cfg, r, Options{Parallel: 2})); got != 2 {
		t.Errorf("nil subset audited %d servers, want 2", got)
	}
}

func fpOf(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("fpOf(%d): %v", seed, err)
	}
	return k.Fingerprint
}

func TestAuditOneReadsHeaderSerial(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(authkeys.Header(8) + "\n" + testkeys.Line(t, 1) + "\n"), Keys2: []byte("k2\n"), Keys2Err: errors.New("x")},
		"web-2": {FileAbsent: true},
	}}
	res := Run(context.Background(), cfg, reader, Options{Parallel: 1})
	if res[0].HeaderSerial != 8 || !res[0].HeaderManaged || string(res[0].Keys2) != "k2\n" || res[0].Keys2Err == nil {
		t.Errorf("web-1 = %+v", res[0])
	}
	if res[1].HeaderManaged || res[1].HeaderSerial != 0 {
		t.Errorf("an absent file has no header: %+v", res[1])
	}
}

// TestGrantedFingerprintsDemotesRiskyLines (WP-5): every connection offers
// a server's granted keys plain first, then lines that may reject the login
// (from=, expiry-time=, restrict), then forced commands, then cert-only
// lines — stable within each group.
func TestGrantedFingerprintsDemotesRiskyLines(t *testing.T) {
	y := `
users:
  - {name: op, operator: true, keys: ["from=\"10.0.0.0/8\" ` + testkeys.Line(t, 1) + `"]}
  - {name: backup, keys: ["command=\"rrsync -ro /\" ` + testkeys.Line(t, 2) + `"]}
  - {name: ca, keys: ["cert-authority ` + testkeys.Line(t, 4) + `"]}
  - {name: admin, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: s, host: 10.0.0.1, user: deploy}
access:
  - {user: backup, servers: [s]}
  - {user: ca, servers: [s]}
  - {user: admin, servers: [s]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	// DesiredFor: op, backup, ca, admin. Offer: plain, then from=/expiry/restrict,
	// then command=, then cert-only — stable within each group.
	want := []string{fpOf(t, 3), fpOf(t, 1), fpOf(t, 2), fpOf(t, 4)}
	if got := GrantedFingerprints(cfg, "s"); !slices.Equal(got, want) {
		t.Errorf("GrantedFingerprints = %v, want %v", got, want)
	}
}
