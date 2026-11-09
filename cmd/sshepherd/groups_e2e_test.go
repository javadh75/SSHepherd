//go:build integration

package main

import (
	"strings"
	"testing"
)

// TestE2EGroupGrant drives one group grant through the design's loop: adopt
// carries the group through, apply installs the member's key on both
// servers, audit is clean, a per-server revoke of the member is refused, a
// full revoke removes the member and the key, and audit is clean again with
// the empty group's warning.
func TestE2EGroupGrant(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	member := itPubLine(t, itKeys(t), "stale")
	dir := t.TempDir()
	m := writeE2EManifest(t, dir, "group.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
  - {name: tmp, keys: ["`+member+`"]}
groups:
  - {name: team, members: [tmp]}
servers:
  - {name: grp-a, host: `+host+`, port: `+port+`, user: grpa, tags: [grp]}
  - {name: grp-b, host: `+host+`, port: `+port+`, user: grpb, tags: [grp]}
access:
  - {group: team, servers: ["@grp"]}
`)
	code, out, stderr := runBin(t, bin, "adopt", "--config", m, "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("adopt exit = %d (stderr: %s)", code, stderr)
	}
	for _, want := range []string{"groups:", "group: team"} {
		if !strings.Contains(out, want) {
			t.Errorf("adopt output lacks %q:\n%s", want, out)
		}
	}
	adopted := writeE2EManifest(t, dir, "adopted.yaml", out)
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", adopted, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	blob := strings.Fields(member)[1]
	for _, user := range []string{"grpa", "grpb"} {
		if got := e2eRemoteCat(t, host, port, kh, user); !strings.Contains(got, blob) {
			t.Errorf("%s lacks the member's key:\n%s", user, got)
		}
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", adopted, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
	before := readFile(t, adopted)
	code, out, stderr = runBin(t, bin, "revoke", "tmp", "--from-server", "grp-a", "--yes", "--config", adopted, "--known-hosts", kh)
	if code != 3 || !strings.Contains(stderr, "tmp's access to grp-a comes from group team") {
		t.Fatalf("revoke --from-server exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if readFile(t, adopted) != before {
		t.Error("the refused trim changed the manifest")
	}
	code, out, stderr = runBin(t, bin, "revoke", "tmp", "--yes", "--config", adopted, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "manifest edit: remove user tmp (1 key, 0 access grants, 1 group)") {
		t.Fatalf("revoke exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	for _, user := range []string{"grpa", "grpb"} {
		if got := e2eRemoteCat(t, host, port, kh, user); strings.Contains(got, blob) {
			t.Errorf("%s still holds the member's key:\n%s", user, got)
		}
	}
	code, out, stderr = runBin(t, bin, "audit", "--config", adopted, "--known-hosts", kh)
	if code != 0 || !strings.Contains(stderr, `group "team" has no members`) {
		t.Fatalf("final audit exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
}
