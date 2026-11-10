//go:build integration

package main

import (
	"strings"
	"testing"
)

// TestE2EGrantRestrictions (spec S7 Tests): against real sshd, per-grant
// restrictions render per server, the post-write login check still proves
// the operator's key with a grant restriction on it, a re-apply is a no-op
// and audit is clean; a second grant with other restrictions is a policy
// conflict: audit exits 2 and apply refuses that server only (exit 1).
func TestE2EGrantRestrictions(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	material := func(line string) string {
		f := strings.Fields(line)
		return f[0] + " " + f[1]
	}
	dir := t.TempDir()
	base := "users:\n  - {name: op, operator: true, keys: [\"" + pub + "\"]}\n  - {name: alice, keys: [\"" + stale + "\"]}\n" +
		"servers:\n  - {name: rsta, host: " + host + ", port: " + port + ", user: rsta}\n" +
		"  - {name: rstb, host: " + host + ", port: " + port + ", user: rstb}\n" +
		"access:\n  - {user: op, servers: [\"*\"], options: [no-pty, no-x11-forwarding]}\n" +
		"  - {user: alice, servers: [rsta], options: ['from=\"10.0.0.0/8\"', no-agent-forwarding]}\n" +
		"  - {user: alice, servers: [rstb]}\n"
	m := writeE2EManifest(t, dir, "restrict.yaml", base)
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if got := e2eRemoteCat(t, host, port, kh, "rsta"); !strings.Contains(got, "no-pty,no-x11-forwarding "+material(pub)) ||
		!strings.Contains(got, `from="10.0.0.0/8",no-agent-forwarding `+material(stale)) {
		t.Errorf("rsta does not carry both grants' options:\n%s", got)
	}
	if got := e2eRemoteCat(t, host, port, kh, "rstb"); !strings.Contains(got, "\n"+material(stale)+" ") {
		t.Errorf("rstb must hold alice's key with no options:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", m, "--known-hosts", kh); code != 0 || strings.Count(out, "converged (no changes)") != 2 {
		t.Fatalf("re-apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	clash := writeE2EManifest(t, dir, "clash.yaml", base+"  - {user: alice, servers: [rsta]}\n")
	if code, out, stderr := runBin(t, bin, "audit", "--config", clash, "--known-hosts", kh); code != 2 || !strings.Contains(out, "a key gets one set of restrictions on a server") {
		t.Fatalf("clash: audit exit = %d, want 2 (stderr: %s)\n%s", code, stderr, out)
	}
	code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", clash, "--known-hosts", kh)
	if code != 1 || !strings.Contains(out, `REFUSED: user "alice": server "rsta" is granted by access[1]`) || strings.Count(out, "converged (no changes)") != 1 {
		t.Errorf("clash: apply --dry-run exit = %d, want 1 with rsta refused and rstb converged (stderr: %s)\n%s", code, stderr, out)
	}
}
