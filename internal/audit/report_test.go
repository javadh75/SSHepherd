package audit

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"os"
	"path/filepath"
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

func TestRenderDrift(t *testing.T) {
	cfg := reportConfig(t)
	// web-1: alice ok, bob missing, one unauthorized, one parse error.
	// web-2: unreachable.
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
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results)
	checkGolden(t, "report_drift.golden", buf.Bytes())
	if ExitCode(results) != 1 {
		t.Errorf("ExitCode = %d, want 1", ExitCode(results))
	}
}

func TestRenderCompliant(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results)
	checkGolden(t, "report_compliant.golden", buf.Bytes())
	if ExitCode(results) != 0 {
		t.Errorf("ExitCode = %d, want 0", ExitCode(results))
	}
}

func TestRenderEmptyFleet(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, &config.Config{}, nil)
	if !bytes.Contains(buf.Bytes(), []byte("0 servers")) {
		t.Errorf("empty-fleet output = %q, want a '0 servers' note", buf.String())
	}
	if ExitCode(nil) != 0 {
		t.Errorf("ExitCode(nil) = %d, want 0", ExitCode(nil))
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
	Render(&buf, cfg, results)
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
	Render(&buf, cfg, results)

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
	if ExitCode(results) != 1 {
		t.Errorf("ExitCode = %d, want 1", ExitCode(results))
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

func TestRenderCriticalOperatorMissing(t *testing.T) {
	cfg := operatorConfig(t)
	// web-1: operator key missing (CRITICAL), alice present.
	// web-2: file absent — the operator key is desired and missing → CRITICAL too.
	reader := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"web-2": {FileAbsent: true},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results)
	out := buf.String()
	if got := strings.Count(out, "CRITICAL: operator key"); got != 2 {
		t.Errorf("CRITICAL rows = %d, want 2:\n%s", got, out)
	}
	if !strings.Contains(out, "(2 critical)") {
		t.Errorf("summary lacks the critical count:\n%s", out)
	}
	if ExitCode(results) != 1 {
		t.Errorf("ExitCode = %d, want 1 (severity is render-only)", ExitCode(results))
	}
	checkGolden(t, "report_critical.golden", buf.Bytes())
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
	Render(&buf, cfg, results)
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
	Render(&buf, cfg, results)
	out := buf.String()
	if got := strings.Count(out, "CRITICAL: operator key"); got != 2 {
		t.Errorf("CRITICAL rows = %d, want 2:\n%s", got, out)
	}
	if !strings.Contains(out, "(1 critical)") {
		t.Errorf("summary must count servers, not keys:\n%s", out)
	}
}
