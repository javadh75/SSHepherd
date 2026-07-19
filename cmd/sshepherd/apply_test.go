package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// applyFleetYAML: one user granted one server (host/port injected).
func applyFleetYAML(t *testing.T, hostPort string) string {
	t.Helper()
	return `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, ` + hostPort + `, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
}

func TestApplyMissingConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", "no-such-file.yaml"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
}

func TestApplyInvalidParallel(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--parallel", "0"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestApplyDryRunYesConflict(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--dry-run", "--yes"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (mutually exclusive flags)", code)
	}
}

func TestApplyUnknownServer(t *testing.T) {
	// Checked before any preflight: a canary typo must fail fast, not
	// silently apply nothing — and must not require an agent.
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--server", "nope"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), `unknown server "nope"`) {
		t.Errorf("stderr = %q, want the unknown-server error", errBuf.String())
	}
}

func TestApplyNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr = %q, want agent guidance", errBuf.String())
	}
}

func TestApplyEmptyFleet(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "0 servers targeted — nothing to apply") {
		t.Errorf("stdout = %q, want the empty summary", out.String())
	}
}

func TestApplyLogsManifestWarnings(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - name: alice
    comment: "alice — platform team"
    keys: ["`+testkeys.Line(t, 1)+`", "`+testkeys.Line(t, 2)+`"]
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "comment is set on a user with 2 keys") {
		t.Errorf("stderr = %q, want the multi-key comment warning", errBuf.String())
	}
}

// TestApplyDryRunUnreachable drives the full run() path against a fleet
// whose one server refuses connections: plan renders the ERROR head, the
// summary counts it, exit is 1, and nothing prompted.
func TestApplyDryRunUnreachable(t *testing.T) {
	path, kh := unreachableFleet(t) // fake agent + closed port, from adopt_test.go
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", path, "--known-hosts", kh, "--dry-run"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "ERROR:") {
		t.Errorf("stdout = %q, want the unreachable head", out.String())
	}
	if !strings.Contains(out.String(), "1 unreachable  → exit 1") {
		t.Errorf("stdout = %q, want the summary counting the unreachable server", out.String())
	}
}

// Without --dry-run the behavior is identical when no server needs a write:
// nothing to confirm, so no prompt and no TTY requirement.
func TestApplyUnreachableNoPromptNeeded(t *testing.T) {
	path, kh := unreachableFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "[y/N]") {
		t.Errorf("stderr = %q, must not prompt when nothing needs a write", errBuf.String())
	}
}

func TestApplyServerFilterSkippedNote(t *testing.T) {
	fakeAgent(t)
	kh := writeEmptyKnownHosts(t)
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
  - {name: web-2, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", path, "--known-hosts", kh, "--dry-run", "--server", "web-1"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "(1 servers skipped by --server)") {
		t.Errorf("stdout = %q, want the skipped-by-server note", out.String())
	}
	if strings.Contains(out.String(), "web-2") {
		t.Errorf("stdout = %q, must not mention the skipped server", out.String())
	}
	if !strings.Contains(out.String(), "0/1 servers converged") {
		t.Errorf("stdout = %q, counts must be over the 1 targeted server only", out.String())
	}
}

func TestConfirm(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		tty     bool
		yes     bool
		wantOK  bool
		wantErr bool
	}{
		{"--yes bypasses the prompt", "", false, true, true, false},
		{"non-TTY without --yes errors", "", false, false, false, true},
		{"tty y", "y\n", true, false, true, false},
		{"tty Y", "Y\n", true, false, true, false},
		{"tty yes", "yes\n", true, false, true, false},
		{"tty n", "n\n", true, false, false, false},
		{"tty empty defaults to no", "\n", true, false, false, false},
		{"tty EOF declines", "", true, false, false, false},
		{"tty garbage declines", "sure why not\n", true, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errBuf bytes.Buffer
			ok, err := confirm(strings.NewReader(tt.in), &errBuf, tt.tty, tt.yes, 3, 12)
			if ok != tt.wantOK || (err != nil) != tt.wantErr {
				t.Fatalf("confirm = (%v, %v), want (%v, err=%v)", ok, err, tt.wantOK, tt.wantErr)
			}
			if tt.tty && !tt.yes {
				if !strings.Contains(errBuf.String(), "apply 3 of 12 servers? [y/N]") {
					t.Errorf("prompt = %q, want the exact question on stderr", errBuf.String())
				}
			} else if errBuf.Len() != 0 {
				t.Errorf("wrote %q to stderr without a TTY prompt", errBuf.String())
			}
		})
	}
}

func TestStdioIsTTYOnBuffers(t *testing.T) {
	if stdioIsTTY(strings.NewReader(""), &bytes.Buffer{}) {
		t.Error("buffers must never count as a TTY")
	}
}

func TestSelectServers(t *testing.T) {
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: a, host: h1, user: u}
  - {name: b, host: h2, user: u}
  - {name: c, host: h3, user: u}
access:
  - {user: alice, servers: [a, b, c]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	t.Run("no names selects the fleet", func(t *testing.T) {
		got, err := selectServers(cfg, nil)
		if err != nil || len(got) != 3 {
			t.Fatalf("got %d servers, err %v; want 3", len(got), err)
		}
	})
	t.Run("subset keeps manifest order and dedupes", func(t *testing.T) {
		got, err := selectServers(cfg, []string{"c", "a", "c"})
		if err != nil {
			t.Fatalf("selectServers: %v", err)
		}
		if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
			t.Fatalf("got %v, want [a c] in manifest order", got)
		}
	})
	t.Run("unknown name errors", func(t *testing.T) {
		if _, err := selectServers(cfg, []string{"a", "nope"}); err == nil || !strings.Contains(err.Error(), `unknown server "nope"`) {
			t.Fatalf("err = %v, want the unknown-server error", err)
		}
	})
}

// writeEmptyKnownHosts creates an empty known_hosts for closed-port fleets.
func writeEmptyKnownHosts(t *testing.T) string {
	t.Helper()
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return kh
}

func strconvItoa(n int) string { return strconv.Itoa(n) }
