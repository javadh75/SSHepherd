package audit

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

// reportConfig: alice(k1)+bob(k2) -> web-1; nothing -> web-2.
func reportConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, comment: "alice@sshepherd", keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("reportConfig: %v", err)
	}
	return cfg
}

// driftResults builds the standard drift scenario: web-1 with alice ok, bob
// missing, one unauthorized key and one parse error; web-2 unreachable.
func driftResults(t *testing.T, cfg *config.Config) []ServerResult {
	t.Helper()
	reader := &fakeReader{
		byName: map[string]fleet.ReadResult{
			"web-1": {Content: []byte(
				testkeys.Line(t, 1) + " alice@laptop\n" +
					testkeys.Line(t, 9) + " who@is-this\n" +
					"garbage entry\n")},
		},
		errs: map[string]error{
			"web-2": dialRefused("10.0.0.2"),
		},
	}
	return Run(context.Background(), cfg, reader, Options{Parallel: 2})
}

// testDialHint mirrors sshconn.DialHint (audit cannot import sshconn);
// internal/sshconn's TestAuditGoldenCarriesDialHint pins the two equal.
const testDialHint = "check the host, port, and firewall; a host reachable only through a bastion needs via: in the manifest"

// dialRefused is the error sshconn returns for a refused TCP connect.
func dialRefused(ip string) error {
	return hintedErr{kindedErr{fleet.ErrorKindDial, (&net.OpError{Op: "dial", Net: "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 22},
		Err:  os.NewSyscallError("connect", syscall.ECONNREFUSED)}).Error()}, testDialHint}
}

// TestRenderHintOncePerDistinctHint: two servers failing the same way print
// the [kind] head each and the hint line once; a different hint prints too.
func TestRenderHintOncePerDistinctHint(t *testing.T) {
	cfg := fleetConfig(t, 3)
	reader := &fakeReader{errs: map[string]error{
		"srv-00": dialRefused("10.0.0.1"),
		"srv-01": dialRefused("10.0.0.2"),
		"srv-02": hintedErr{kindedErr{fleet.ErrorKindHostKeyChanged, "ssh deploy@10.0.0.3:22: knownhosts: key mismatch"}, "HOST KEY CHANGED for 10.0.0.3:22"},
	}}
	var buf bytes.Buffer
	Render(&buf, cfg, Run(context.Background(), cfg, reader, Options{Parallel: 1}), RenderOptions{})
	out := buf.String()
	if n := strings.Count(out, "  hint: "+testDialHint+"\n"); n != 1 {
		t.Errorf("dial hint printed %d times, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "ERROR [dial]: dial tcp 10.0.0."); n != 2 {
		t.Errorf("want two [dial] heads, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, "  hint: HOST KEY CHANGED for 10.0.0.3:22\n") {
		t.Errorf("a distinct hint must still print:\n%s", out)
	}
	checkGolden(t, "report_hints.golden", buf.Bytes())
}

func TestRenderDrift(t *testing.T) {
	cfg := reportConfig(t)
	// web-1: alice ok, bob missing, one unauthorized, one parse error.
	// web-2: unreachable.
	results := driftResults(t, cfg)
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_drift.golden", buf.Bytes())
	if ExitCode(cfg, results) != 1 {
		t.Errorf("ExitCode = %d, want 1", ExitCode(cfg, results))
	}
}

// ansiRE strips SGR sequences; see TestRenderColorStrippedEqualsPlain.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// TestRenderColorStrippedEqualsPlain pins the two load-bearing invariants at
// once: color adds nothing but SGR codes (content identical), and because
// every glyph-column SGR prefix has equal length, tabwriter computes the
// same column widths — so stripping color must reproduce the plain output
// byte-for-byte, alignment included. Both fixtures run so the ‼/CRITICAL
// operator rows are under the invariant too.
func TestRenderColorStrippedEqualsPlain(t *testing.T) {
	driftCfg := reportConfig(t)
	criticalCfg := operatorConfig(t)
	memCfg := memoryConfig(t, "  - {user: alice, servers: [web-1], date: 2026-11-08}\n  - {fingerprint: "+fpOf(t, 8)+", date: 2026-11-08}\n")
	forgedCfg := memoryConfig(t, "")
	serialResults := memoryRun(t, forgedCfg, memFiles(t, authkeys.Header(8), []byte{1, 2, 3}, []byte{1, 2}))
	serialResults[1].HeaderSerial = 9999
	trustCfg := trustConfig(t, testkeys.Line(t, 1), "")
	certOnly := runOne(t, trustCfg, fleet.ReadResult{Content: content("cert-authority "+testkeys.Line(t, 1), testkeys.Line(t, 2))})
	for _, fix := range []struct {
		name     string
		cfg      *config.Config
		results  []ServerResult
		comments bool
	}{
		{"drift", driftCfg, driftResults(t, driftCfg), false},
		{"critical", criticalCfg, criticalResults(t, criticalCfg), false},
		{"comment drift", driftCfg, commentDriftResults(t, driftCfg), true},
		{"revocation memory", memCfg, memoryRun(t, memCfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3, 9}, []byte{1, 2, 3, 8})), false},
		{"serial notes", forgedCfg, serialResults, false},
		{"posture", trustCfg, postureResults(t, trustCfg), false},
		{"operator cannot log in", trustCfg, []ServerResult{certOnly}, false},
	} {
		t.Run(fix.name, func(t *testing.T) {
			var plain, colored bytes.Buffer
			Render(&plain, fix.cfg, fix.results, RenderOptions{Comments: fix.comments})
			Render(&colored, fix.cfg, fix.results, RenderOptions{Color: true, Comments: fix.comments})

			if plain.String() == colored.String() {
				t.Fatal("colored output is identical to plain — no color was applied")
			}
			stripped := ansiRE.ReplaceAllString(colored.String(), "")
			if stripped != plain.String() {
				t.Errorf("stripped colored output differs from plain:\n--- stripped ---\n%s\n--- plain ---\n%s",
					stripped, plain.String())
			}
		})
	}
}

// TestRenderErrorHeadIsOneLine pins the report-forgery defense: a hostile
// error containing newlines must not become extra report lines.
func TestRenderErrorHeadIsOneLine(t *testing.T) {
	cfg := reportConfig(t)
	results := []ServerResult{{
		Server: cfg.Servers[0],
		Err:    errors.New("dial failed\n  ✓ forged-user SHA256:xxx ssh-ed25519 present & authorized\nSummary: 99/99 servers compliant"),
	}}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	got := buf.String()
	if strings.Count(got, "forged-user") != 1 {
		t.Fatalf("forged content missing or duplicated:\n%s", got)
	}
	line, _, _ := strings.Cut(got, "\n")
	if !strings.Contains(line, "forged-user") || !strings.Contains(line, "Summary: 99/99") {
		t.Errorf("hostile newlines were not collapsed into the head line:\n%s", got)
	}
}

func TestRenderDriftColorGolden(t *testing.T) {
	cfg := reportConfig(t)
	var buf bytes.Buffer
	Render(&buf, cfg, driftResults(t, cfg), RenderOptions{Color: true})
	checkGolden(t, "report_drift_color.golden", buf.Bytes())
}

func TestRenderCompliant(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_compliant.golden", buf.Bytes())
	if ExitCode(cfg, results) != 0 {
		t.Errorf("ExitCode = %d, want 0", ExitCode(cfg, results))
	}
}

func TestRenderEmptyFleet(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, &config.Config{}, nil, RenderOptions{})
	if !bytes.Contains(buf.Bytes(), []byte("0 servers")) {
		t.Errorf("empty-fleet output = %q, want a '0 servers' note", buf.String())
	}
	if ExitCode(&config.Config{}, nil) != 0 {
		t.Errorf("ExitCode(empty) = %d, want 0", ExitCode(&config.Config{}, nil))
	}
}

// TestExitCodeSeverity pins the monitoring-style scheme from the 2026-07-16
// spec: 0 compliant, 1 drift/unreachable, 2 critical — critical wins over
// everything, unreachable alone is only 1 (nothing knowable about its keys).
func TestExitCodeSeverity(t *testing.T) {
	driftCfg := reportConfig(t)
	critCfg := operatorConfig(t)
	tests := []struct {
		name    string
		cfg     *config.Config
		results []ServerResult
		want    int
	}{
		{"empty fleet", &config.Config{}, nil, 0},
		{"drift plus unreachable, no critical", driftCfg, driftResults(t, driftCfg), 1},
		{"critical present", critCfg, criticalResults(t, critCfg), 2},
		{"unreachable only", critCfg, []ServerResult{
			{Server: critCfg.Servers[0], Err: errors.New("dial tcp: connection refused")},
		}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.cfg, tt.results); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRenderFileAbsentDiagnostic(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {FileAbsent: true},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	if !strings.Contains(out, "another key source") {
		t.Errorf("file-absent diagnostic missing from:\n%s", out)
	}
}

// overrideConfig: alice(k1) -> web-1, which reads a custom
// authorized_keys_file (the path is override-test input).
func overrideConfig(t *testing.T, path string) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, authorized_keys_file: "` + path + `"}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("overrideConfig: %v", err)
	}
	return cfg
}

// TestRenderFileAbsentOverrideGolden pins the path-aware absent note: with
// an authorized_keys_file override set, the note names the overridden path
// and leads with the override-mismatch hypothesis (the operator already
// declared a path, so "sshd has a custom AuthorizedKeysFile" is moot).
func TestRenderFileAbsentOverrideGolden(t *testing.T) {
	cfg := overrideConfig(t, "/etc/ssh/keys/deploy")
	reader := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 1})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	if !strings.Contains(out, "/etc/ssh/keys/deploy is absent") {
		t.Errorf("absent note must name the overridden path:\n%s", out)
	}
	if !strings.Contains(out, "override may not match sshd's AuthorizedKeysFile") {
		t.Errorf("absent note must lead with the override-mismatch hypothesis:\n%s", out)
	}
	checkGolden(t, "report_absent_override.golden", buf.Bytes())
}

// TestRenderEmptyFileOverrideNamesPath: the empty-file paradox note likewise
// names the overridden path when one is set.
func TestRenderEmptyFileOverrideNamesPath(t *testing.T) {
	cfg := overrideConfig(t, "/etc/ssh/keys/deploy")
	reader := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte{}}}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 1})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	if !strings.Contains(out, "/etc/ssh/keys/deploy is empty") {
		t.Errorf("empty note must name the overridden path:\n%s", out)
	}
	if !strings.Contains(out, "override may not match sshd's AuthorizedKeysFile") {
		t.Errorf("empty note must lead with the override-mismatch hypothesis:\n%s", out)
	}
}

// TestRenderExplicitDefaultIsOverride pins a locked decision: setting
// authorized_keys_file to the default ~/.ssh/authorized_keys explicitly IS
// an override — the operator declared a path, so the note is path-aware.
func TestRenderExplicitDefaultIsOverride(t *testing.T) {
	cfg := overrideConfig(t, "~/.ssh/authorized_keys")
	reader := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 1})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	if !strings.Contains(out, "~/.ssh/authorized_keys is absent") {
		t.Errorf("explicit-default note must name the path:\n%s", out)
	}
	if !strings.Contains(out, "override may not match sshd's AuthorizedKeysFile") {
		t.Errorf("explicit-default note must use the override wording:\n%s", out)
	}
}

func TestRenderUnauthorizedKnownOwnerIsNamed(t *testing.T) {
	cfg := reportConfig(t)
	// web-2: alice ok; bob's key is installed although bob is NOT granted
	// web-2 — the unauthorized row must name bob, not "(unknown)".
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})

	var unauthorized []string
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "installed but UNAUTHORIZED") {
			unauthorized = append(unauthorized, line)
		}
	}
	if len(unauthorized) != 1 {
		t.Fatalf("unauthorized rows = %d, want 1:\n%s", len(unauthorized), buf.String())
	}
	if !strings.Contains(unauthorized[0], "bob") {
		t.Errorf("unauthorized row = %q, want it to name bob", unauthorized[0])
	}
	if strings.Contains(unauthorized[0], "(unknown)") {
		t.Errorf("unauthorized row = %q, must not label a known manifest key (unknown)", unauthorized[0])
	}
	if ExitCode(cfg, results) != 1 {
		t.Errorf("ExitCode = %d, want 1", ExitCode(cfg, results))
	}
}

// TestRenderUnauthorizedOptionsOnlyForUnknownKeys: the " · options:"
// suffix is for keys the manifest does not own. bob's key, installed with
// options on a server he is not granted, keeps the plain cell; an unknown
// key with the same options shows them.
func TestRenderUnauthorizedOptionsOnlyForUnknownKeys(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\nno-pty " + testkeys.Line(t, 2) + "\nno-pty " + testkeys.Line(t, 9) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	rows := map[string]string{}
	for line := range strings.Lines(buf.String()) {
		for _, label := range []string{"bob", "(unknown)"} {
			if strings.Contains(line, " "+label+" ") && strings.Contains(line, "UNAUTHORIZED") {
				rows[label] = line
			}
		}
	}
	for label, want := range map[string]string{
		"bob":       "installed but UNAUTHORIZED\n",
		"(unknown)": `installed but UNAUTHORIZED · options: "no-pty"` + "\n",
	} {
		if !strings.HasSuffix(rows[label], want) {
			t.Errorf("%s row = %q, want it to end %q\nreport:\n%s", label, rows[label], want, buf.String())
		}
	}
}

// commentDriftResults builds a fleet whose ONLY divergence is cosmetic:
// every desired fingerprint is present, but alice's key on web-1 carries a
// stale on-server comment ("alice@laptop" vs her manifest comment
// "alice@sshepherd"). bob's key carries "bob" — exactly his desired
// name-fallback comment — and web-2's copy of alice's key already matches.
func commentDriftResults(t *testing.T, cfg *config.Config) []ServerResult {
	t.Helper()
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(
			testkeys.Line(t, 1) + " alice@laptop\n" +
				testkeys.Line(t, 2) + " bob\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + " alice@sshepherd\n")},
	}}
	return Run(context.Background(), cfg, reader, Options{Parallel: 2})
}

// TestRenderCommentsGolden pins the --comments human rendering: exactly one
// OK row gains the informational annotation, plain text only.
func TestRenderCommentsGolden(t *testing.T) {
	cfg := reportConfig(t)
	results := commentDriftResults(t, cfg)
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{Comments: true})
	out := buf.String()
	if got := strings.Count(out, "comment differs"); got != 1 {
		t.Errorf("comment-differs rows = %d, want 1:\n%s", got, out)
	}
	if !strings.Contains(out, `comment differs: "alice@laptop" → "alice@sshepherd"`) {
		t.Errorf("annotation must show actual → desired:\n%s", out)
	}
	checkGolden(t, "report_comments.golden", buf.Bytes())
}

// TestRenderCommentsOffIsSilent: without the flag the very same drifting
// fleet renders no annotation at all — the default report shape is pinned
// byte-for-byte by the existing goldens, this pins the substring half.
func TestRenderCommentsOffIsSilent(t *testing.T) {
	cfg := reportConfig(t)
	var buf bytes.Buffer
	Render(&buf, cfg, commentDriftResults(t, cfg), RenderOptions{})
	if strings.Contains(buf.String(), "comment differs") {
		t.Errorf("comment drift leaked into the default report:\n%s", buf.String())
	}
}

// TestCommentDriftExitCodeNeutral pins the memo's hard rule: comment drift
// is cosmetic — a fleet whose only divergence is comments stays compliant
// with exit 0, with and without --comments.
func TestCommentDriftExitCodeNeutral(t *testing.T) {
	cfg := reportConfig(t)
	results := commentDriftResults(t, cfg)
	if got := ExitCode(cfg, results); got != 0 {
		t.Fatalf("ExitCode = %d, want 0 (comment drift must not affect it)", got)
	}
	for _, opts := range []RenderOptions{{}, {Comments: true}} {
		var buf bytes.Buffer
		Render(&buf, cfg, results, opts)
		if !strings.Contains(buf.String(), "Summary: 2/2 servers compliant") ||
			!strings.Contains(buf.String(), "exit 0") {
			t.Errorf("Comments=%v summary must stay compliant/exit 0:\n%s", opts.Comments, buf.String())
		}
	}
}

// operatorConfig: op(k3) is an operator (desired everywhere); alice(k1) -> web-1.
func operatorConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: op, operator: true, comment: "op@sshepherd", keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("operatorConfig: %v", err)
	}
	return cfg
}

// criticalResults builds the standard critical scenario: web-1 with the
// operator key missing (alice present), web-2 with the authorized_keys file
// absent — the operator key is desired and missing there too.
func criticalResults(t *testing.T, cfg *config.Config) []ServerResult {
	t.Helper()
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"web-2": {FileAbsent: true},
	}}
	return Run(context.Background(), cfg, reader, Options{Parallel: 2})
}

func TestRenderCriticalOperatorMissing(t *testing.T) {
	cfg := operatorConfig(t)
	// web-1: operator key missing (CRITICAL), alice present.
	// web-2: file absent — the operator key is desired and missing → CRITICAL too.
	results := criticalResults(t, cfg)
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	if got := strings.Count(out, "CRITICAL: operator key"); got != 2 {
		t.Errorf("CRITICAL rows = %d, want 2:\n%s", got, out)
	}
	if !strings.Contains(out, "(2 critical)") {
		t.Errorf("summary lacks the critical count:\n%s", out)
	}
	if ExitCode(cfg, results) != 2 {
		t.Errorf("ExitCode = %d, want 2 (critical drift)", ExitCode(cfg, results))
	}
	checkGolden(t, "report_critical.golden", buf.Bytes())
}

func TestRenderCriticalColorGolden(t *testing.T) {
	cfg := operatorConfig(t)
	var buf bytes.Buffer
	Render(&buf, cfg, criticalResults(t, cfg), RenderOptions{Color: true})
	checkGolden(t, "report_critical_color.golden", buf.Bytes())
}

func TestRenderUnreachableServerNotCritical(t *testing.T) {
	cfg := operatorConfig(t)
	// web-1 fully compliant; web-2 unreachable — nothing knowable about its
	// keys, so it must stay a plain ERROR, not a critical finding.
	reader := &fakeReader{
		byName: map[string]fleet.ReadResult{
			"web-1": {Content: []byte(testkeys.Line(t, 3) + "\n" + testkeys.Line(t, 1) + "\n")},
		},
		errs: map[string]error{"web-2": errors.New("dial tcp 10.0.0.2:22: connection refused")},
	}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	if strings.Contains(buf.String(), "CRITICAL") {
		t.Errorf("unreachable server must not render CRITICAL:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "(0 critical)") {
		t.Errorf("summary should show 0 critical:\n%s", buf.String())
	}
}

func TestCriticalCountsServersNotKeys(t *testing.T) {
	// Two operators, both missing from the single audited server: the summary
	// must count one critical server, not two critical keys.
	y := `
users:
  - {name: op-a, operator: true, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: op-b, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 1})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	if got := strings.Count(out, "CRITICAL: operator key"); got != 2 {
		t.Errorf("CRITICAL rows = %d, want 2:\n%s", got, out)
	}
	if !strings.Contains(out, "(1 critical)") {
		t.Errorf("summary must count servers, not keys:\n%s", out)
	}
}

// TestRenderUnknownKeyShowsComment: an unowned key is labeled with its
// sanitized on-server comment (quoted, capped at 40 runes) and its options
// ride in the status cell; a comment-less key stays a bare (unknown).
func TestRenderUnknownKeyShowsComment(t *testing.T) {
	cfg := reportConfig(t)
	long := strings.Repeat("x", 60)
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n" +
			`from="10.0.0.0/8",no-pty ` + testkeys.Line(t, 9) + " alice@laptop\n" +
			testkeys.Line(t, 8) + "\n" +
			testkeys.Line(t, 7) + " evil\u202e\x1b[31m\n" +
			testkeys.Line(t, 6) + " " + long + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		`(unknown) "alice@laptop"`,
		`installed but UNAUTHORIZED · options: "from=\"10.0.0.0/8\",no-pty"`,
		`(unknown) "evil[31m"`,                         // ESC and U+202E stripped, %q-quoted
		`(unknown) "` + strings.Repeat("x", 39) + `…"`, // capped at 40 runes
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	if strings.ContainsAny(out, "\x1b\u202e") {
		t.Errorf("hostile comment bytes reached the report:\n%q", out)
	}
	// Seed 8 has no comment: its row's label cell is a bare (unknown).
	if !regexp.MustCompile(`⚠\s+\(unknown\)\s+SHA256:`).MatchString(out) {
		t.Errorf("comment-less unowned key must keep a bare (unknown) label:\n%s", out)
	}
}
