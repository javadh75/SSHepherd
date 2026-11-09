package main

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// groupFleetManifest: alice (k1, held) holds web-1 and web-2 by name; bob (k2)
// and carol (k3) are in web-team, which holds @web; all three keys are
// installed on both servers. groups, access and extra are spliced in.
func groupFleetManifest(t *testing.T, groups, access, extra string) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1, 2, 3})
	}
	tagged := func(name string) string {
		return strings.TrimSuffix(hosts[name].line(name), "}\n") + ", tags: [web]}\n"
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n  - {name: carol, keys: ["+qk(t, 3)+"]}\n"+
		"groups:\n  - {name: web-team, members: [bob, carol]}\n"+groups+
		"servers:\n"+tagged("web-1")+tagged("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {group: web-team, servers: [\"@web\"]}\n"+access+extra)
	return hosts, kh, cfg
}

// TestRevokeServerRefusedThroughGroup: any group grant reaching the pair
// refuses the trim, with a direct grant or without (trimming the direct one
// would leave the access). Exit 3, nothing saved, and the date is the run's.
// Under --json stdout stays empty: the document is written exactly on exit
// 0, 1 or 2.
func TestRevokeServerRefusedThroughGroup(t *testing.T) {
	fixedEditClock(t)
	const want = "bob's access to web-1 comes from group web-team; remove the user from the group, trim the group's grant, or add revoked: [{user: bob, servers: [web-1], date: 2026-11-09}] to block only this member"
	for _, tc := range []struct {
		name, access string
		flags        []string
	}{
		{"group only", "", nil},
		{"a direct grant too", "  - {user: bob, servers: [web-1]}\n", nil},
		{"--json writes no document", "", []string{"--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, kh, cfg := groupFleetManifest(t, "", tc.access, "")
			before := fileBytes(t, cfg)
			var out, errBuf bytes.Buffer
			args := append([]string{"revoke", "bob", "--from-server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, tc.flags...)
			code := run(args, &out, &errBuf)
			if code != 3 || out.Len() != 0 || !strings.Contains(errBuf.String(), want) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q\nwant stderr to contain %q", code, out.String(), errBuf.String(), want)
			}
			if !bytes.Equal(fileBytes(t, cfg), before) {
				t.Errorf("the manifest changed:\n%s", fileBytes(t, cfg))
			}
		})
	}
}

// TestRevokeServerRefusalNamesEveryGroup: two groups reaching the pair are
// named together.
func TestRevokeServerRefusalNamesEveryGroup(t *testing.T) {
	fixedEditClock(t)
	const want = "bob's access to web-1 comes from groups web-team, solo; remove the user from the groups, trim the groups' grants, or add revoked: [{user: bob, servers: [web-1], date: 2026-11-09}] to block only this member"
	_, kh, cfg := groupFleetManifest(t, "  - {name: solo, members: [bob]}\n", "  - {group: solo, servers: [web-1]}\n", "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), want) {
		t.Errorf("exit = %d, stderr = %q\nwant %q", code, errBuf.String(), want)
	}
}

// TestRevokeServerBlockedGroupMemberIsAlreadyRevoked (D1c): GroupGrantsReaching
// ignores a blocked pair, so a member the tombstone blocks gets the note, not
// the refusal: exit 0, nothing saved.
func TestRevokeServerBlockedGroupMemberIsAlreadyRevoked(t *testing.T) {
	_, kh, cfg := groupFleetManifest(t, "", "", "revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n")
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if !strings.HasPrefix(out.String(), "bob's access to web-2 was already revoked (2026-11-08); run 'sshepherd apply") {
		t.Errorf("stdout = %q", out.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("the manifest changed:\n%s", fileBytes(t, cfg))
	}
	if !strings.Contains(errBuf.String(), `is not granted "web-2" through group web-team`) {
		t.Errorf("stderr lacks the load warning:\n%s", errBuf.String())
	}
}

// TestRevokeServerKeepsCountIgnoresBlockedGroupPair: bob is in a group whose
// "*" entry excepts web-2, with a direct grant of web-2 and a tombstone
// blocking db-1. The trim of web-2 is not refused, because the group does not
// reach it, and it records a tombstone: the group's except: stops applying
// when bob leaves the group, so it is no memory for this trim (D1a). db-1 does
// not count as kept: without Covers' c.blocked check it would read 2 other
// servers. The header never says no access is left: he keeps web-1 through
// the group (the design's HasAccessEntry goal, met by the S3a count).
func TestRevokeServerKeepsCountIgnoresBlockedGroupPair(t *testing.T) {
	hosts, _, _ := editFleet(t, []byte{1}, "web-1", "web-2", "db-1")
	body := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n" +
		"groups:\n  - {name: team, members: [bob]}\n" +
		"servers:\n" + hosts["web-1"].line("web-1") + hosts["web-2"].line("web-2") + hosts["db-1"].line("db-1") +
		"access:\n  - {user: alice, servers: [web-1, web-2, db-1]}\n  - {group: team, servers: [\"*\"], except: [web-2]}\n  - {user: bob, servers: [web-2]}\n" +
		"revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n"
	t.Run("trim keeps the honest count", func(t *testing.T) {
		cfg := writeConfig(t, body)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--from-server", "web-2", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), "manifest edit: remove bob's access to web-2 (1 access entry removed); bob keeps access to 1 other server") {
			t.Errorf("stdout:\n%s", out.String())
		}
		if strings.Contains(out.String(), "no access left") {
			t.Errorf("bob keeps web-1 through the group:\n%s", out.String())
		}
		saved := readCfg(t, cfg)
		if len(saved.Access) != 2 || !saved.ExceptCarveOut("bob", "web-2") {
			t.Errorf("access = %+v", saved.Access)
		}
		if _, ok := saved.AccessRevoked("bob", "web-2"); !ok {
			t.Errorf("no tombstone for the trimmed direct grant:\n%s", fileBytes(t, cfg))
		}
		if len(saved.Conflicts()) != 0 {
			t.Errorf("Conflicts = %+v, want none: the group excepts web-2", saved.Conflicts())
		}
		if len(saved.Warnings) != 1 || !strings.Contains(saved.Warnings[0], `"db-1"`) {
			t.Errorf("Warnings = %q, want only the fixture's blocked db-1", saved.Warnings)
		}
	})
	t.Run("the blocked pair is a note", func(t *testing.T) {
		cfg := writeConfig(t, body)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--from-server", "db-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(out.String(), "bob's access to db-1 was already revoked (2026-11-08)") {
			t.Errorf("stdout = %q", out.String())
		}
	})
}

// TestRevokeServerLeavesGroupExceptsAlone: trimming db-1 records db-1 and
// nothing else. The group's except: of web-2 was never bob's own and did not
// change, so it must not turn into a tombstone (forgottenCarveOut reads the
// user's own except: on both sides).
func TestRevokeServerLeavesGroupExceptsAlone(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"groups:\n  - {name: team, members: [bob]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [web]}\n  - {name: db-1, host: 10.0.2.1, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {group: team, servers: [\"@web\"], except: [web-2]}\n  - {user: bob, servers: [db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "db-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	if _, ok := saved.AccessRevoked("bob", "db-1"); !ok {
		t.Errorf("no tombstone for db-1:\n%s", fileBytes(t, cfg))
	}
	if _, ok := saved.AccessRevoked("bob", "web-2"); ok {
		t.Errorf("the group's except: became a tombstone:\n%s", fileBytes(t, cfg))
	}
}

// TestRevokeUserDropsGroupMembership: bob leaves web-team, his key leaves
// both servers, carol's stays, and the header says a group was changed.
func TestRevokeUserDropsGroupMembership(t *testing.T) {
	hosts, kh, cfg := groupFleetManifest(t, "", "", "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "manifest edit: remove user bob (1 key, 0 access grants, 1 group) — 2 servers affected\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Groups[0].Members, []string{"carol"}) {
		t.Errorf("members = %v", saved.Groups[0].Members)
	}
	gone, kept := strings.Fields(testkeys.Line(t, 2))[1], strings.Fields(testkeys.Line(t, 3))[1]
	for _, name := range []string{"web-1", "web-2"} {
		if file := hosts[name].keys(t); strings.Contains(file, gone) || !strings.Contains(file, kept) {
			t.Errorf("%s:\n%s", name, file)
		}
	}
}

// TestRevokeLastGroupMemberLeavesGroupWarning: the group keeps its entry and
// its access: entry, and the manifest still loads. The run that empties the
// group prints the warning itself, and the next load carries it.
func TestRevokeLastGroupMemberLeavesGroupWarning(t *testing.T) {
	const want = `group "web-team" has no members; its grants add nothing`
	_, _, cfg := groupFleetManifest(t, "", "", "")
	for _, user := range []string{"bob", "carol"} {
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", user, "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("%s: exit = %d\n%s\n%s", user, code, out.String(), errBuf.String())
		}
		if user == "carol" && !strings.Contains(errBuf.String(), want) {
			t.Errorf("the run that empties the group did not warn:\n%s", errBuf.String())
		}
	}
	saved := readCfg(t, cfg)
	if len(saved.Groups) != 1 || len(saved.Groups[0].Members) != 0 || len(saved.Access) != 2 {
		t.Errorf("groups = %+v, access = %+v", saved.Groups, saved.Access)
	}
	if len(saved.ManifestWarnings) != 1 || saved.ManifestWarnings[0].Message != want {
		t.Errorf("ManifestWarnings = %+v", saved.ManifestWarnings)
	}
}

// TestRevokeLastGroupMemberJSONWarns: the run that empties the group carries
// the warning in its own document, not only on a later load.
func TestRevokeLastGroupMemberJSONWarns(t *testing.T) {
	_, _, cfg := groupFleetManifest(t, "", "", "")
	doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "carol", "--json", "--no-apply", "--yes", "--config", cfg)
	ws, _ := doc["manifest_warnings"].([]any)
	want := map[string]any{"kind": "empty_group", "message": `group "web-team" has no members; its grants add nothing`}
	if len(ws) != 1 || !reflect.DeepEqual(ws[0], want) {
		t.Errorf("manifest_warnings = %v\nwant one %v", ws, want)
	}
}

func TestRevokeUserGroupsJSON(t *testing.T) {
	_, kh, cfg := groupFleetManifest(t, "", "", "")
	doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh)
	e := doc["edit"].(map[string]any)["edits"].([]any)[0].(map[string]any)
	if e["kind"] != "remove-user" || e["grants"] != float64(0) || !reflect.DeepEqual(e["groups"], []any{"web-team"}) {
		t.Errorf("edit entry = %v", e)
	}
}

// TestRevokeServerGroupExceptIsNotMemory: deleting bob's own wildcard forgets
// his except: of web-2. A group's except: of web-2 that survives the edit is
// not memory for it, so web-2 still gets a tombstone (D1a, both sides of
// forgottenCarveOut read the user's own except:).
func TestRevokeServerGroupExceptIsNotMemory(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"groups:\n  - {name: team, members: [bob]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.1.1, user: deploy}\n  - {name: web-2, host: 10.0.1.2, user: deploy}\n  - {name: db-1, host: 10.0.2.1, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [\"*\"], except: [web-2, db-1]}\n  - {group: team, servers: [\"*\"], except: [web-1, web-2]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	for _, server := range []string{"web-1", "web-2"} {
		if _, ok := saved.AccessRevoked("bob", server); !ok {
			t.Errorf("%s was not tombstoned:\n%s", server, fileBytes(t, cfg))
		}
	}
}
