//go:build integration

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// itKeys returns the directory of the harness's headless key files
// (scripts/integration.sh): ci_old (unencrypted), ci_new and enc (encrypted,
// with ci_new.pass / enc.pass).
func itKeys(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("SSHEPHERD_IT_KEYS")
	if dir == "" {
		t.Skip("integration env not set; run via make integration")
	}
	return dir
}

// itPubLine reads a harness public key line.
func itPubLine(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name+".pub")) // #nosec G304 -- harness key dir (SSHEPHERD_IT_KEYS)
	if err != nil {
		t.Fatalf("%s.pub: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}

// runHeadless executes the binary with SSH_AUTH_SOCK removed from its
// environment: only --identity keys can authenticate.
func runHeadless(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, args...) // #nosec G204 -- the binary this test just built
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	var out, errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return code, out.String(), errBuf.String()
}

func TestIntegrationIdentityAudit(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: ci, keys: ["`+itPubLine(t, keys, "ci_old")+`"]}
servers:
  - {name: idaudit, host: `+host+`, port: `+port+`, user: idaudit}
access:
  - {user: ci, servers: [idaudit]}
`)
	code, out, stderr := runHeadless(t, bin, "audit", "--config", m, "--known-hosts", kh, "--identity", filepath.Join(keys, "ci_old"))
	if code != 0 {
		t.Fatalf("headless audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
	if !strings.Contains(stderr, "identity loaded") {
		t.Errorf("stderr lacks the identity-loaded line:\n%s", stderr)
	}
	// Without the key file and without an agent there is nothing to log in with.
	if code, _, stderr := runHeadless(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 3 || !strings.Contains(stderr, "SSH_AUTH_SOCK") {
		t.Errorf("agent-less audit without --identity: exit %d, stderr %q; want 3 with agent guidance", code, stderr)
	}
}

func TestIntegrationIdentityApplyEncrypted(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: op, operator: true, keys: ["`+itPubLine(t, keys, "enc")+`"]}
servers:
  - {name: idenc, host: `+host+`, port: `+port+`, user: idenc}
`)
	args := []string{"apply", "--yes", "--config", m, "--known-hosts", kh,
		"--identity", filepath.Join(keys, "enc"), "--identity-passphrase-file", filepath.Join(keys, "enc.pass")}
	code, out, stderr := runHeadless(t, bin, args...)
	if code != 0 || !strings.Contains(out, "applied · verified") {
		t.Fatalf("headless encrypted apply exit = %d, want 0 + applied (stderr: %s)\n%s", code, stderr, out)
	}
	if strings.Contains(stderr+out, "enc-passphrase") {
		t.Error("the passphrase reached the output")
	}
	if code, out, stderr := runHeadless(t, bin, args...); code != 0 || !strings.Contains(out, "converged (no changes)") {
		t.Fatalf("re-apply exit = %d, want a converged no-op (stderr: %s)\n%s", code, stderr, out)
	}
}

// TestIntegrationHeadlessRotation is the motivating case: the manifest
// replaces ci_old with ci_new; one --identity is refused naming the fix;
// both keys rotate (the probe proves ci_new); ci_new alone is then a no-op.
// The rotation passes --offer-all-keys: the restricted offer would present
// only ci_new, which is not installed yet, so old + new would fail auth.
func TestIntegrationHeadlessRotation(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: ci, operator: true, keys: ["`+itPubLine(t, keys, "ci_new")+`"]}
servers:
  - {name: rotate, host: `+host+`, port: `+port+`, user: rotate}
`)
	base := []string{"apply", "--yes", "--config", m, "--known-hosts", kh}
	oldKey := []string{"--identity", filepath.Join(keys, "ci_old")}
	newKey := []string{"--identity", filepath.Join(keys, "ci_new"), "--identity-passphrase", filepath.Join(keys, "ci_new") + "=" + filepath.Join(keys, "ci_new.pass")}

	t.Run("old key alone is refused, naming the fix", func(t *testing.T) {
		code, out, _ := runHeadless(t, bin, append(base, oldKey...)...)
		if code != 1 || !strings.Contains(out, "pass the new key with another --identity") {
			t.Fatalf("exit = %d, want 1 with the rotation hint\n%s", code, out)
		}
	})
	t.Run("old + new rotates; the probe proves the new key", func(t *testing.T) {
		code, out, stderr := runHeadless(t, bin, append(append(append(base, "--offer-all-keys"), oldKey...), newKey...)...)
		if code != 0 || !strings.Contains(out, "applied · verified") {
			t.Fatalf("exit = %d, want 0 + applied (stderr: %s)\n%s", code, stderr, out)
		}
		if !strings.Contains(out, "removes the key this session logged in with") {
			t.Errorf("plan lacks the rotate note:\n%s", out)
		}
	})
	t.Run("new key alone is a no-op", func(t *testing.T) {
		code, out, stderr := runHeadless(t, bin, append(base, newKey...)...)
		if code != 0 || !strings.Contains(out, "converged (no changes)") {
			t.Fatalf("exit = %d, want a converged no-op (stderr: %s)\n%s", code, stderr, out)
		}
	})
}

// TestE2EHeadlessLoop: adopt → apply → audit with only --identity, no agent.
func TestE2EHeadlessLoop(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	dir := t.TempDir()
	id := []string{"--identity", filepath.Join(keys, "ci_old")}
	m0 := writeE2EManifest(t, dir, "m0.yaml", `
users:
  - {name: ci, operator: true, keys: ["`+itPubLine(t, keys, "ci_old")+`"]}
servers:
  - {name: e2eh, host: `+host+`, port: `+port+`, user: e2eh}
`)
	adopted := filepath.Join(dir, "adopted.yaml")
	code, out, stderr := runHeadless(t, bin, append([]string{"adopt", "--config", m0, "--known-hosts", kh, "-o", adopted}, id...)...)
	if code != 0 {
		t.Fatalf("headless adopt exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if code, out, stderr = runHeadless(t, bin, append([]string{"apply", "--yes", "--config", m0, "--known-hosts", kh}, id...)...); code != 0 {
		t.Fatalf("headless apply (revoking the stale key) exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if !strings.Contains(out, "remove (unauthorized)") {
		t.Errorf("apply did not remove the stale key:\n%s", out)
	}
	if code, out, stderr = runHeadless(t, bin, append([]string{"audit", "--config", m0, "--known-hosts", kh}, id...)...); code != 0 {
		t.Fatalf("headless audit exit = %d, want 0 — the loop must close (stderr: %s)\n%s", code, stderr, out)
	}
	if b, err := os.ReadFile(adopted); err != nil || !strings.Contains(string(b), "adopted from e2eh") { // #nosec G304 -- t.TempDir path
		t.Errorf("adopted manifest lacks the stale key (%v):\n%s", err, b)
	}
}

// TestIntegrationHeadlessRotateCommand: 'rotate' with no agent — the old
// key logs in, the new key (encrypted, passphrase file) survives the guard
// and is what the post-write probe proves; the manifest now holds the new
// key and a headless audit with only the new key is clean.
func TestIntegrationHeadlessRotateCommand(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: ci, operator: true, keys: ["`+itPubLine(t, keys, "ci_old")+`"]}
servers:
  - {name: rotatecmd, host: `+host+`, port: `+port+`, user: rotatecmd}
`)
	ciOld, ciNew := filepath.Join(keys, "ci_old"), filepath.Join(keys, "ci_new")
	code, out, stderr := runHeadless(t, bin, "rotate", "ci", "--old", ciOld+".pub", "--new", ciNew+".pub",
		"--operator", "--yes", "--config", m, "--known-hosts", kh,
		"--identity", ciOld, "--identity", ciNew, "--identity-passphrase", ciNew+"="+ciNew+".pass")
	if code != 0 || !strings.Contains(out, "applied · verified") {
		t.Fatalf("headless rotate exit = %d, want 0 + applied (stderr: %s)\n%s", code, stderr, out)
	}
	b, err := os.ReadFile(m) // #nosec G304 -- t.TempDir path
	if err != nil {
		t.Fatal(err)
	}
	newFields := strings.Fields(itPubLine(t, keys, "ci_new"))
	if !strings.Contains(string(b), newFields[1]) || strings.Contains(string(b), strings.Fields(itPubLine(t, keys, "ci_old"))[1]) {
		t.Errorf("manifest does not hold exactly the new key:\n%s", b)
	}
	if code, out, stderr := runHeadless(t, bin, "audit", "--config", m, "--known-hosts", kh,
		"--identity", ciNew, "--identity-passphrase", ciNew+"="+ciNew+".pass"); code != 0 {
		t.Fatalf("headless audit with the new key exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
}
