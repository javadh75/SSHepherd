//go:build integration

package main

import (
	"strings"
	"testing"
)

// TestE2EProtected drives a protected user through the design's semantics
// against real sshd: its key is written after the fleet-wide operator's and
// granted only where its access says, a trim needs --operator, a key missing
// where it is granted is critical (exit 2), and an operator's except: that
// would leave this run no key is refused by the lockout guard with the new
// hint.
func TestE2EProtected(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	dir := t.TempDir()
	base := `
users:
  - {name: op, operator: true, keys: ["` + pub + `"]}
  - {name: ci, protected: true, keys: ["` + stale + `"]}
servers:
  - {name: prot-a, host: ` + host + `, port: ` + port + `, user: prota}
  - {name: prot-b, host: ` + host + `, port: ` + port + `, user: protb}
access:
  - {user: ci, servers: [prot-a, prot-b]}
`
	m := writeE2EManifest(t, dir, "protected.yaml", base)
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	opBlob, ciBlob := strings.Fields(pub)[1], strings.Fields(stale)[1]
	for _, user := range []string{"prota", "protb"} {
		got := e2eRemoteCat(t, host, port, kh, user)
		if i, j := strings.Index(got, opBlob), strings.Index(got, ciBlob); i < 0 || j < 0 || i > j {
			t.Errorf("%s: want the operator's key, then ci's:\n%s", user, got)
		}
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
	before := readFile(t, m)
	code, out, stderr := runBin(t, bin, "revoke", "ci", "--from-server", "prot-a", "--yes", "--config", m, "--known-hosts", kh)
	if code != 3 || !strings.Contains(stderr, "ci is protected; pass --operator to confirm") {
		t.Fatalf("revoke without --operator exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if readFile(t, m) != before {
		t.Error("the refused trim changed the manifest")
	}
	code, out, stderr = runBin(t, bin, "revoke", "ci", "--from-server", "prot-a", "--operator", "--yes", "--config", m, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "PROTECTED: ci is protected; --operator given") {
		t.Fatalf("revoke --operator exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if got := e2eRemoteCat(t, host, port, kh, "prota"); strings.Contains(got, ciBlob) {
		t.Errorf("prota still holds ci's key:\n%s", got)
	}
	if got := e2eRemoteCat(t, host, port, kh, "protb"); !strings.Contains(got, ciBlob) {
		t.Errorf("protb lost ci's key:\n%s", got)
	}
	// The original manifest grants ci prot-a again, where its key is now
	// missing: the same emergency as a missing operator key.
	regranted := writeE2EManifest(t, dir, "regranted.yaml", base)
	code, out, stderr = runBin(t, bin, "audit", "--config", regranted, "--known-hosts", kh)
	if code != 2 || !strings.Contains(out, "(CRITICAL: protected key)") {
		t.Fatalf("audit exit = %d, want 2 (stderr: %s)\n%s", code, stderr, out)
	}
	// An operator's own except: takes the only key this run holds off
	// prot-b, so the guard refuses, and the hint no longer says operator: true.
	scoped := writeE2EManifest(t, dir, "scoped.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
  - {name: ci, protected: true, keys: ["`+stale+`"]}
servers:
  - {name: prot-a, host: `+host+`, port: `+port+`, user: prota}
  - {name: prot-b, host: `+host+`, port: `+port+`, user: protb}
access:
  - {user: op, servers: ["*"], except: [prot-b]}
  - {user: ci, servers: [prot-b]}
`)
	code, out, stderr = runBin(t, bin, "apply", "--dry-run", "--config", scoped, "--known-hosts", kh)
	if code != 1 || !strings.Contains(out, "(or grant its user this server)") {
		t.Fatalf("apply --dry-run exit = %d, want 1 (stderr: %s)\n%s", code, stderr, out)
	}
}
