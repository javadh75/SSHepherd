//go:build integration

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// itE2E reads the integration env (scripts/integration.sh) or skips, and
// builds the real binary once per test.
func itE2E(t *testing.T) (bin, host, port, kh, pubLine string) {
	t.Helper()
	host = os.Getenv("SSHEPHERD_IT_HOST")
	if host == "" {
		t.Skip("integration env not set; run via make integration")
	}
	port = os.Getenv("SSHEPHERD_IT_PORT")
	kh = os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS")
	pub, err := os.ReadFile(os.Getenv("SSHEPHERD_IT_PUB"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PUB: %v", err)
	}
	bin = filepath.Join(t.TempDir(), "sshepherd")
	out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin, host, port, kh, strings.TrimSpace(string(pub))
}

// runBin executes the built binary with the inherited environment (the
// harness's SSH_AUTH_SOCK) and returns exit code, stdout, stderr.
func runBin(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, args...)
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return code, out.String(), errBuf.String()
}

func writeE2EManifest(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestE2EApplyLoop drives the built binary through the spec's full write
// loop against the docker fleet: adopt → apply --yes (first write,
// normalizes everything) → apply --dry-run (no-op, byte-stable) → revoke by
// manifest edit → apply --dry-run (plan) → apply --yes → audit exits 0 —
// then the lockout guard trips on a manifest holding none of the agent's
// keys, and a final audit proves the file was untouched. Ordered subtests:
// each stage's on-server state is the next stage's input.
func TestE2EApplyLoop(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	dir := t.TempDir()

	// m0: the operator's key (held by the harness agent) on server e2e.
	m0 := writeE2EManifest(t, dir, "m0.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
servers:
  - {name: e2e, host: `+host+`, port: `+port+`, user: e2e}
`)
	adopted := filepath.Join(dir, "adopted.yaml")

	t.Run("adopt discovers the stale key", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "adopt", "--config", m0, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("adopt exit = %d (stderr: %s)", code, stderr)
		}
		if !strings.Contains(out, "adopted from") {
			t.Fatalf("adopt output lacks an adopted user:\n%s", out)
		}
		if err := os.WriteFile(adopted, []byte(out), 0o600); err != nil {
			t.Fatalf("write adopted manifest: %v", err)
		}
	})

	t.Run("first apply normalizes and verifies", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", adopted, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		if !strings.Contains(out, "applied · verified") {
			t.Errorf("apply output lacks the applied·verified outcome:\n%s", out)
		}
	})

	t.Run("re-apply is a byte-stable no-op", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", adopted, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("dry-run exit = %d, want 0 (converged) (stderr: %s)\n%s", code, stderr, out)
		}
		if !strings.Contains(out, "converged (no changes)") {
			t.Errorf("dry-run output lacks convergence:\n%s", out)
		}
	})

	t.Run("revoking the stale grant plans a remove", func(t *testing.T) {
		code, out, _ := runBin(t, bin, "apply", "--dry-run", "--config", m0, "--known-hosts", kh)
		if code != 1 {
			t.Fatalf("dry-run exit = %d, want 1 (pending change)\n%s", code, out)
		}
		if !strings.Contains(out, "remove (unauthorized)") {
			t.Errorf("plan lacks the remove row:\n%s", out)
		}
	})

	t.Run("apply the revoke and audit clean", func(t *testing.T) {
		if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		if code, out, stderr := runBin(t, bin, "audit", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("audit exit = %d, want 0 — the distribute→audit loop must close (stderr: %s)\n%s", code, stderr, out)
		}
	})

	t.Run("lockout guard refuses and leaves the file alone", func(t *testing.T) {
		ghost := writeE2EManifest(t, dir, "ghost.yaml", `
users:
  - {name: ghost, keys: ["`+testkeys.Line(t, 42)+`"]}
servers:
  - {name: e2e, host: `+host+`, port: `+port+`, user: e2e}
access:
  - {user: ghost, servers: [e2e]}
`)
		code, out, _ := runBin(t, bin, "apply", "--yes", "--config", ghost, "--known-hosts", kh)
		if code != 1 {
			t.Fatalf("lockout apply exit = %d, want 1\n%s", code, out)
		}
		if !strings.Contains(out, "REFUSED:") || !strings.Contains(out, "lock this session out") {
			t.Errorf("output lacks the guard refusal:\n%s", out)
		}
		// The file is untouched: the m0 audit still passes byte-for-byte.
		if code, out, stderr := runBin(t, bin, "audit", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("post-refusal audit exit = %d, want 0 (the refused write must not have touched the file) (stderr: %s)\n%s", code, stderr, out)
		}
	})
}
