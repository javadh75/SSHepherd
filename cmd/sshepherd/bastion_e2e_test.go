//go:build integration

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestE2EBastion drives the built binary through container A as a bastion
// to container C, which only A can reach (spec S5 Tests): apply and audit
// through a managed bastion; audit exit 0 through a jump_only bastion whose
// account has a nologin shell; a changed bastion key is exit 2 for audit
// (one alert, via_failed) and 1 for apply; a refused forward is 1; and the
// forwarding guard refuses a bastion key line that cannot forward.
func TestE2EBastion(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	target := os.Getenv("SSHEPHERD_IT_TARGET_HOST")
	if target == "" {
		t.Fatal("SSHEPHERD_IT_TARGET_HOST not set: scripts/integration.sh must start the internal container")
	}
	dir := t.TempDir()
	mk := func(name, bastionUser, bastionFlags, keyOpts, webUser string) string {
		return writeE2EManifest(t, dir, name, `
users:
  - {name: op, operator: true, keys: ['`+keyOpts+pub+`']}
servers:
  - {name: bastion, host: `+host+`, port: `+port+`, user: `+bastionUser+bastionFlags+`}
  - {name: web, host: `+target+`, port: 22, user: `+webUser+`, via: bastion}
`)
	}

	// The guard first, while nothing is written: the managed apply below
	// removes hope2e's stale key, so it bumps its manifest's serial (D4b)
	// and a serial-0 copy would then be refused as stale before the guard
	// is reached.
	guarded := mk("guarded.yaml", "jump", "", "no-port-forwarding ", "hope2e")
	code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", guarded, "--known-hosts", kh)
	if code != 1 || !strings.Contains(out, "none of the surviving keys you hold may forward through bastion") {
		t.Fatalf("apply --dry-run with a non-forwarding bastion key exit = %d, want 1 (stderr: %s)\n%s", code, stderr, out)
	}

	managed := mk("managed.yaml", "jump", "", "", "hope2e")
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", managed, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply through the bastion exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", managed, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit after apply exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}

	nologin := mk("nologin.yaml", "jumpnl", ", jump_only: true", "", "hopped")
	code, out, stderr = runBin(t, bin, "audit", "--json", "--config", nologin, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, `"status": "jump_only"`) {
		t.Fatalf("audit through a nologin jump_only bastion exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}

	swapped := filepath.Join(dir, "known_hosts_swapped")
	if err := os.WriteFile(swapped, []byte(swapBastionKey(t, kh, host, port)), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr = runBin(t, bin, "audit", "--json", "--config", nologin, "--known-hosts", swapped)
	if code != 2 || !strings.Contains(out, `"via_failed": "bastion"`) || !strings.Contains(out, `"host_key_alerts": 1`) {
		t.Fatalf("audit with a changed bastion key exit = %d, want 2 with via_failed (stderr: %s)\n%s", code, stderr, out)
	}
	if code, out, stderr = runBin(t, bin, "apply", "--dry-run", "--config", managed, "--known-hosts", swapped); code != 1 {
		t.Fatalf("apply with a changed bastion key exit = %d, want 1 (stderr: %s)\n%s", code, stderr, out)
	}

	nofwd := mk("nofwd.yaml", "jumpnofwd", ", jump_only: true", "", "hopped")
	code, out, stderr = runBin(t, bin, "audit", "--json", "--config", nofwd, "--known-hosts", kh)
	if code != 1 || !strings.Contains(out, `"error_kind": "dial"`) || !strings.Contains(out, "allow TCP forwarding for this account") {
		t.Fatalf("audit through a non-forwarding bastion exit = %d, want 1 (stderr: %s)\n%s", code, stderr, out)
	}
}

// swapBastionKey returns known_hosts with the bastion's (container A's)
// keys replaced by container B's: a changed bastion key.
func swapBastionKey(t *testing.T, kh, host, port string) string {
	t.Helper()
	portB := os.Getenv("SSHEPHERD_IT_PORT_B")
	var lines []string
	for _, l := range strings.Split(strings.TrimSpace(readFile(t, kh)), "\n") {
		switch {
		case strings.HasPrefix(l, "["+host+"]:"+port+" "):
		case strings.HasPrefix(l, "["+host+"]:"+portB+" "):
			lines = append(lines, l, strings.Replace(l, "]:"+portB+" ", "]:"+port+" ", 1))
		default:
			lines = append(lines, l)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}
