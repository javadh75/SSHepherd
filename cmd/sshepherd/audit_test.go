package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshepherd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestAuditMissingConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", "no-such-file.yaml"}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
}

func TestAuditInvalidConfig(t *testing.T) {
	path := writeConfig(t, "users: [\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestAuditEmptyFleet(t *testing.T) {
	// No servers -> exit 0 and a "0 servers" note; must not require an agent.
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "0 servers") {
		t.Errorf("stdout = %q, want '0 servers' note", out.String())
	}
}

// TestAuditJSONEmptyFleet: --json must emit exactly one valid JSON document
// on stdout — nothing else — and exit 0. Like the human empty-fleet path,
// it must not require an agent.
func TestAuditJSONEmptyFleet(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users: []
servers: []
access: []
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path, "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	var rep struct {
		Schema  int               `json:"schema"`
		Servers []json.RawMessage `json:"servers"`
		Summary struct {
			Servers  int `json:"servers"`
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
	}
	// Unmarshal the WHOLE stdout: any human-report text before or after the
	// document (or a second document) fails here.
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not exactly one JSON document: %v\n%s", err, out.String())
	}
	if rep.Schema != 1 || rep.Summary.Servers != 0 || rep.Summary.ExitCode != 0 {
		t.Errorf("report = %+v, want schema 1, 0 servers, exit 0", rep)
	}
	if rep.Servers == nil {
		t.Errorf("servers must be [], not null:\n%s", out.String())
	}
	if strings.Contains(out.String(), "Summary:") {
		t.Errorf("human summary leaked into --json stdout:\n%s", out.String())
	}
}

// TestAuditJSONMainPath pins the properties unique to the non-empty fleet:
// the JSON document reaches stdout even though the verdict is non-zero, and
// the embedded exit_code matches the process exit.
func TestAuditJSONMainPath(t *testing.T) {
	path, kh := unreachableFleet(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path, "--known-hosts", kh, "--json"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	var rep struct {
		Summary struct {
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
		Servers []struct {
			Status string  `json:"status"`
			Error  *string `json:"error"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not exactly one JSON document: %v\n%s", err, out.String())
	}
	if rep.Summary.ExitCode != code {
		t.Errorf("summary.exit_code = %d, want the process exit %d", rep.Summary.ExitCode, code)
	}
	if len(rep.Servers) != 1 || rep.Servers[0].Status != "unreachable" || rep.Servers[0].Error == nil {
		t.Errorf("servers = %+v, want one unreachable entry carrying its error", rep.Servers)
	}
}

func TestAuditNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr = %q, want agent guidance", errBuf.String())
	}
}

func TestAuditInvalidParallel(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path, "--parallel", "0"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestAuditBadKnownHosts(t *testing.T) {
	// A live (fake) agent gets past the agent preflight; a nonexistent
	// known_hosts must then fail once with exit 3, not once per server.
	fakeAgent(t)

	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`)
	kh := filepath.Join(t.TempDir(), "does-not-exist")
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path, "--known-hosts", kh}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "known_hosts") {
		t.Errorf("stderr = %q, want known_hosts preflight error", errBuf.String())
	}
}

// TestAuditPhaseLogs: normal mode narrates phases on stderr.
func TestAuditPhaseLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, []byte("users: []\nservers: []\naccess: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "loaded manifest: 0 users, 0 servers") {
		t.Errorf("stderr = %q, want the loaded-manifest phase line", errBuf.String())
	}
}

// TestAuditQuietSilencesPhases: -q leaves stderr empty on a clean run.
func TestAuditQuietSilencesPhases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, []byte("users: []\nservers: []\naccess: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "-q", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty under -q", errBuf.String())
	}
	if !strings.Contains(out.String(), "0 servers configured") {
		t.Errorf("stdout = %q, the product must survive -q", out.String())
	}
}

// TestAuditColorFlagReachesReport pins the spec promises "--color=never
// yields plain bytes" and that --color=always paints the stdout report —
// the a.reportColor → Render wire has no other cmd-level coverage.
func TestAuditColorFlagReachesReport(t *testing.T) {
	path, kh := unreachableFleet(t)

	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--color=always", "--config", path, "--known-hosts", kh}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("--color=always exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "\x1b[0;31m") {
		t.Errorf("stdout = %q, want the painted ERROR head under --color=always", out.String())
	}
	if !strings.Contains(errBuf.String(), "\x1b[") {
		t.Errorf("stderr = %q, want colored logs under --color=always", errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	code = run([]string{"audit", "--color=never", "--config", path, "--known-hosts", kh}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("--color=never exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if strings.Contains(out.String(), "\x1b") {
		t.Errorf("stdout = %q, want no escape bytes under --color=never", out.String())
	}
	if strings.Contains(errBuf.String(), "\x1b") {
		t.Errorf("stderr = %q, want no escape bytes under --color=never", errBuf.String())
	}
}

// TestAuditVerboseFormat: -v switches stderr to the timestamped format.
func TestAuditVerboseFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, []byte("users: []\nservers: []\naccess: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "-v", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "INFO") {
		t.Errorf("stderr = %q, want verbose INFO tags", errBuf.String())
	}
}

// TestAuditCommentWarningReachesStderr: a comment: on a multi-key user is a
// non-fatal validation warning — audit surfaces it on stderr via the leveled
// logger and proceeds normally.
func TestAuditCommentWarningReachesStderr(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, comment: "alice@corp", keys: ["`+testkeys.Line(t, 1)+`", "`+testkeys.Line(t, 2)+`"]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (a warning must not fail the run; stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), `user "alice": comment is set on a user with 2 keys`) {
		t.Errorf("stderr = %q, want the multi-key comment warning", errBuf.String())
	}
}

// TestAuditCommentsFlag: --comments parses and reaches both renderers; on an
// empty fleet it changes nothing (exit 0, --json stays one valid document).
func TestAuditCommentsFlag(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, "users: []\nservers: []\naccess: []\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--comments", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("--comments exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--comments", "--json", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("--comments --json exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !json.Valid(out.Bytes()) {
		t.Errorf("--comments --json stdout is not valid JSON:\n%s", out.String())
	}
}

// verdictConfig: op (operator, key 1) desired everywhere; alice (key 2) -> web-1.
func verdictConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("verdictConfig: %v", err)
	}
	return cfg
}

func mustParseKey(t *testing.T, line string) authkeys.Key {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("mustParseKey(%q): %v", line, err)
	}
	return *k
}

// TestAuditVerdict pins the sentinel choice: ExitCode 2 -> errCriticalDrift,
// 1 -> errNonCompliant, 0 -> nil.
func TestAuditVerdict(t *testing.T) {
	cfg := verdictConfig(t)
	opKey := mustParseKey(t, testkeys.Line(t, 1))
	aliceKey := mustParseKey(t, testkeys.Line(t, 2))

	compliant := []audit.ServerResult{{Server: cfg.Servers[0]}}
	drift := []audit.ServerResult{{Server: cfg.Servers[0],
		Diff: authkeys.Result{Missing: []authkeys.Key{aliceKey}}}}
	critical := []audit.ServerResult{{Server: cfg.Servers[0],
		Diff: authkeys.Result{Missing: []authkeys.Key{opKey}}}}

	if err := auditVerdict(cfg, compliant); err != nil {
		t.Errorf("compliant verdict = %v, want nil", err)
	}
	if err := auditVerdict(cfg, drift); !errors.Is(err, errNonCompliant) {
		t.Errorf("drift verdict = %v, want errNonCompliant", err)
	}
	if err := auditVerdict(cfg, critical); !errors.Is(err, errCriticalDrift) {
		t.Errorf("critical verdict = %v, want errCriticalDrift", err)
	}
}
