//go:build integration

package main

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// TestE2EPreserve (spec S6 Tests, "Integration"): a Gitea-style command=
// line with its "# gitea public key" mark survives apply under the marker
// against real sshd, a re-apply is a no-op and audit is clean (exit 0);
// dropping the rule plans its removal; a key tombstone beats preserve:
// (audit 2, and apply removes the line and the marker).
func TestE2EPreserve(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	gitea := `command="/usr/local/bin/gitea --config=/etc/gitea/app.ini serv key-7",no-port-forwarding,no-pty ` + stale
	if strings.Contains(gitea, "'") {
		t.Fatalf("the seeded line must not hold a single quote: %s", gitea)
	}
	// sshconn.Exec runs single-line scripts only, so the seed is one printf.
	e2eRemote(t, host, port, kh, "presv", `printf '%s\n' '# gitea public key' '`+gitea+`' >> "$HOME/.ssh/authorized_keys"`)
	dir := t.TempDir()
	server := `  - {name: presv, host: ` + host + `, port: ` + port + `, user: presv`
	rule := `, preserve: [{command: '/usr/local/bin/gitea --config=/etc/gitea/app.ini serv key-[0-9]+'}]}`
	users := "users:\n  - {name: op, operator: true, keys: [\"" + pub + "\"]}\nservers:\n"
	m := writeE2EManifest(t, dir, "preserve.yaml", users+server+rule+"\n")
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if got := e2eRemoteCat(t, host, port, kh, "presv"); !strings.HasSuffix(got, authkeys.PreserveMarker+"\n# gitea public key\n"+gitea+"\n") {
		t.Fatalf("the kept section is not at the end of the file:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", m, "--known-hosts", kh); code != 0 || !strings.Contains(out, "converged (no changes)") {
		t.Fatalf("re-apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 || !strings.Contains(out, "externally managed (preserve: command)") {
		t.Fatalf("audit exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	norule := writeE2EManifest(t, dir, "norule.yaml", users+server+"}\n")
	if code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", norule, "--known-hosts", kh); code != 1 || !strings.Contains(out, "remove (unauthorized)") {
		t.Fatalf("without the rule: apply --dry-run exit = %d, want 1 and a remove row (stderr: %s)\n%s", code, stderr, out)
	}
	k, err := authkeys.ParseLine(stale)
	if err != nil || k == nil {
		t.Fatalf("stale key: %v", err)
	}
	revoked := writeE2EManifest(t, dir, "revoked.yaml", users+server+rule+"\nrevoked:\n  - {fingerprint: "+k.Fingerprint+", date: 2026-11-10}\n")
	if code, out, stderr := runBin(t, bin, "audit", "--config", revoked, "--known-hosts", kh); code != 2 || !strings.Contains(out, "REVOKED") {
		t.Fatalf("revoked kept key: audit exit = %d, want 2 (stderr: %s)\n%s", code, stderr, out)
	}
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", revoked, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply over the tombstone exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if got := e2eRemoteCat(t, host, port, kh, "presv"); strings.Contains(got, strings.Fields(stale)[1]) || strings.Contains(got, authkeys.PreserveMarker) {
		t.Errorf("the revoked line or an empty marker survived:\n%s", got)
	}
}
