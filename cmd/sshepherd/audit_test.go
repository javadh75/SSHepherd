package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, errBuf.String())
	}
}

func TestAuditInvalidConfig(t *testing.T) {
	path := writeConfig(t, "users: [\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
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
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr = %q, want agent guidance", errBuf.String())
	}
}

func TestAuditInvalidParallel(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path, "--parallel", "0"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestAuditBadKnownHosts(t *testing.T) {
	// A live (fake) agent gets past the agent preflight; a nonexistent
	// known_hosts must then fail once with exit 2, not once per server.
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
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, errBuf.String())
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
