package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRotateGroupMemberReachesGroupServers: a member's rotation pushes to the
// servers the group reaches, and the group is untouched. carol is the second
// member, so a grant that expanded only the first would affect no server.
func TestRotateGroupMemberReachesGroupServers(t *testing.T) {
	hosts, kh, cfg := groupFleetManifest(t, "", "", "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "carol", "--old", fpOf(t, 3), "--new", writePub(t, "id_new.pub", testkeys.Line(t, 6)), "--yes",
		"--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), " — 2 servers affected\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
	gone, added := strings.Fields(testkeys.Line(t, 3))[1], strings.Fields(testkeys.Line(t, 6))[1]
	for _, name := range []string{"web-1", "web-2"} {
		if file := hosts[name].keys(t); strings.Contains(file, gone) || !strings.Contains(file, added) {
			t.Errorf("%s:\n%s", name, file)
		}
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Groups[0].Members, []string{"bob", "carol"}) {
		t.Errorf("members = %v", saved.Groups[0].Members)
	}
	if _, revoked := saved.Revoked(fpOf(t, 3)); !revoked {
		t.Error("the old key was not tombstoned")
	}
}

// TestAdoptMergeHonoursBlockedGroupMember: bob's key is still on web-2, a
// tombstone blocks his group grant there, and adopt --merge must not extend
// him: the plan is empty, so the file is untouched byte for byte.
func TestAdoptMergeHonoursBlockedGroupMember(t *testing.T) {
	_, kh, cfg := groupFleetManifest(t, "", "", "revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n")
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--merge", "--config", cfg, "-o", cfg, "--force", "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("the manifest changed:\n%s", fileBytes(t, cfg))
	}
	if readCfg(t, cfg).Covers("bob", "web-2") {
		t.Errorf("adopt --merge re-granted web-2:\n%s", fileBytes(t, cfg))
	}
	if !strings.Contains(errBuf.String(), "whose access was revoked") {
		t.Errorf("stderr lacks the not-re-granted warning:\n%s", errBuf.String())
	}
}

// TestAdoptMergeAppendKeepsGroups: an unknown key makes the plan non-empty, so
// the merge goes through Append and Encode. A new user is appended, and the
// groups: section, its comment included, is byte for byte what it was: adopt
// never creates or rewrites a group.
func TestAdoptMergeAppendKeepsGroups(t *testing.T) {
	const kept = "groups:\n  - {name: web-team, members: [bob, carol]}\n  # kept group comment\n  - name: solo\n    members: [bob]\nservers:\n"
	hosts, kh, cfg := groupFleetManifest(t, "  # kept group comment\n  - name: solo\n    members: [bob]\n", "", "")
	hosts["web-1"].install(t, []byte{1, 2, 3, 5})
	want := readCfg(t, cfg).Groups
	if !strings.Contains(string(fileBytes(t, cfg)), kept) {
		t.Fatalf("the fixture lacks the groups block:\n%s", fileBytes(t, cfg))
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--merge", "--config", cfg, "-o", cfg, "--force", "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(string(fileBytes(t, cfg)), kept) {
		t.Errorf("groups: changed:\n%s", fileBytes(t, cfg))
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Groups, want) {
		t.Errorf("Groups = %+v\nwant %+v", saved.Groups, want)
	}
	if owner, ok := saved.OwnerOf(fpOf(t, 5)); !ok || !saved.Covers(owner.Name, "web-1") {
		t.Errorf("the unknown key was not adopted on web-1:\n%s", fileBytes(t, cfg))
	}
}

// TestImportMergeHonoursBlockedGroupMember: the same for import --merge, on a
// group "*" entry. A conflict-only plan returns the file unchanged.
func TestImportMergeHonoursBlockedGroupMember(t *testing.T) {
	home := hermeticHome(t)
	bobKey := filepath.Join(home, "bob")
	if err := os.WriteFile(bobKey+".pub", []byte(testkeys.Line(t, 4)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := writeConfig(t, "users:\n  - {name: bob, keys: ["+qk(t, 4)+"]}\n"+
		"groups:\n  - {name: team, members: [bob]}\n"+
		"servers:\n  - {name: db-1, host: 10.0.0.3, user: deploy}\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"+
		"access:\n  - {group: team, servers: [\"*\"]}\n"+
		"revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n")
	before := fileBytes(t, m)
	path := writeSSHConfig(t, "Host db-1\n  HostName 10.0.0.3\n  User deploy\n  IdentityFile "+bobKey+"\n"+
		"Host web-1\n  HostName 10.0.0.1\n  User deploy\n  IdentityFile "+bobKey+"\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--merge", m, "-o", m, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, m), before) {
		t.Errorf("the manifest changed:\n%s", fileBytes(t, m))
	}
	saved := readCfg(t, m)
	if saved.Covers("bob", "db-1") || !saved.Covers("bob", "web-1") {
		t.Errorf("covers db-1 %v, web-1 %v", saved.Covers("bob", "db-1"), saved.Covers("bob", "web-1"))
	}
	if !strings.Contains(errBuf.String(), "whose access was revoked") {
		t.Errorf("stderr lacks the not-re-granted warning:\n%s", errBuf.String())
	}
}
