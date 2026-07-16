package audit

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
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
		byName: map[string]ReadResult{
			"web-1": {Content: []byte(
				testkeys.Line(t, 1) + " alice@laptop\n" +
					testkeys.Line(t, 9) + " who@is-this\n" +
					"garbage entry\n")},
		},
		errs: map[string]error{
			"web-2": errors.New("dial tcp 10.0.0.2:22: connection refused"),
		},
	}
	return Run(context.Background(), cfg, reader, Options{Parallel: 2})
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
	for _, fix := range []struct {
		name    string
		cfg     *config.Config
		results []ServerResult
	}{
		{"drift", driftCfg, driftResults(t, driftCfg)},
		{"critical", criticalCfg, criticalResults(t, criticalCfg)},
	} {
		t.Run(fix.name, func(t *testing.T) {
			var plain, colored bytes.Buffer
			Render(&plain, fix.cfg, fix.results, RenderOptions{})
			Render(&colored, fix.cfg, fix.results, RenderOptions{Color: true})

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
	reader := &fakeReader{byName: map[string]ReadResult{
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
	reader := &fakeReader{byName: map[string]ReadResult{
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

func TestRenderUnauthorizedKnownOwnerIsNamed(t *testing.T) {
	cfg := reportConfig(t)
	// web-2: alice ok; bob's key is installed although bob is NOT granted
	// web-2 — the unauthorized row must name bob, not "(unknown)".
	reader := &fakeReader{byName: map[string]ReadResult{
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
	reader := &fakeReader{byName: map[string]ReadResult{
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
		byName: map[string]ReadResult{
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
	reader := &fakeReader{byName: map[string]ReadResult{
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
