package main

import (
	"bytes"
	"context"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagFleetManifest: alice (k1, held) holds web-1 and web-2 by name, bob (k2)
// holds @web, and both keys are installed on both servers.
func tagFleetManifest(t *testing.T) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1, 2})
	}
	tagged := func(name string) string {
		return strings.TrimSuffix(hosts[name].line(name), "}\n") + ", tags: [web]}\n"
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+tagged("web-1")+tagged("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [\"@web\"]}\n")
	return hosts, kh, cfg
}

// normalizedManifest is the saved manifest with what varies per run replaced:
// the date of this run's tombstone and each server's port.
func normalizedManifest(t *testing.T, path string) []byte {
	t.Helper()
	out := regexp.MustCompile(`date: "?\d{4}-\d{2}-\d{2}"?`).ReplaceAll(fileBytes(t, path), []byte("date: DATE"))
	return regexp.MustCompile(`port: \d+`).ReplaceAll(out, []byte("port: PORT"))
}

// TestRevokeServerTrimsTagGrant: the tag entry gains except: (no tombstone,
// the except: remembers), bob's key leaves web-1 only and web-2 is untouched.
func TestRevokeServerTrimsTagGrant(t *testing.T) {
	hosts, kh, cfg := tagFleetManifest(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "manifest edit: remove bob's access to web-1 (1 access entry changed, 1 server excepted); bob keeps access to 1 other server — 1 server affected\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Access[1], config.Access{User: "bob", Servers: []string{"@web"}, Except: []string{"web-1"}}) {
		t.Errorf("access[1] = %+v", saved.Access[1])
	}
	if len(saved.Tombstones) != 0 || saved.Serial() != 1 {
		t.Errorf("tombstones = %+v, serial = %d", saved.Tombstones, saved.Serial())
	}
	k2 := strings.Fields(testkeys.Line(t, 2))[1]
	if strings.Contains(hosts["web-1"].keys(t), k2) {
		t.Errorf("bob's key survives on web-1:\n%s", hosts["web-1"].keys(t))
	}
	if !strings.Contains(hosts["web-2"].keys(t), k2) {
		t.Errorf("web-2 must keep bob's key:\n%s", hosts["web-2"].keys(t))
	}
}

// TestRevokeServerTwoTrimsTombstoneBothServers (D1a through an @tag entry):
// the second trim deletes the entry and its except:, so both servers get
// tombstones; the saved manifest is a golden, and adopt --merge does not
// re-grant either.
func TestRevokeServerTwoTrimsTombstoneBothServers(t *testing.T) {
	_, kh, cfg := tagFleetManifest(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("first trim: exit %d\n%s", code, errBuf.String())
	}
	if len(readCfg(t, cfg).Tombstones) != 0 || !readCfg(t, cfg).ExceptCarveOut("bob", "web-1") {
		t.Fatal("the first trim should record web-1 in except: only")
	}
	if code := run([]string{"revoke", "bob", "--from-server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("second trim: exit %d\n%s", code, errBuf.String())
	}
	saved := readCfg(t, cfg)
	if len(saved.Access) != 1 {
		t.Errorf("bob's entry survived: %+v", saved.Access)
	}
	for _, s := range []string{"web-1", "web-2"} {
		if _, ok := saved.AccessRevoked("bob", s); !ok {
			t.Errorf("no access tombstone for %s: %+v", s, saved.Tombstones)
		}
	}
	checkGolden(t, "revoke_tag_two_trims.golden", normalizedManifest(t, cfg))
	errBuf.Reset()
	if code := run([]string{"adopt", "--merge", "--config", cfg, "-o", cfg, "--force", "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("adopt --merge: exit %d\n%s", code, errBuf.String())
	}
	if readCfg(t, cfg).Covers("bob", "web-1") {
		t.Errorf("adopt --merge re-granted web-1:\n%s", fileBytes(t, cfg))
	}
}

func TestRevokeFromServerRefusesSelectors(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, sel := range []string{"@prod", "*"} {
		var out, errBuf bytes.Buffer
		code := run([]string{"revoke", "bob", "--from-server", sel, "--config", "/nonexistent"}, &out, &errBuf)
		if code != 3 || out.Len() != 0 || !strings.Contains(errBuf.String(), "--from-server takes server names") {
			t.Errorf("%s: exit = %d, stdout = %q, stderr = %q", sel, code, out.String(), errBuf.String())
		}
	}
}

// TestRevokeServerBlockedPairIsAlreadyRevoked (D1c): the pair a tombstone
// blocks is already revoked: a note, exit 0, nothing saved.
func TestRevokeServerBlockedPairIsAlreadyRevoked(t *testing.T) {
	_, kh, cfg := tagFleetManifest(t)
	raw := string(fileBytes(t, cfg)) + "revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n"
	cfg = writeConfig(t, raw)
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
	if !strings.Contains(errBuf.String(), `is not granted "web-2" through @web`) {
		t.Errorf("stderr lacks the load warning:\n%s", errBuf.String())
	}
}

// TestRevokeServerLastUnblockedServerNoGrantsLeft: a tombstone blocks bob on
// web-2 and the trim takes web-1, the last server he reaches. The entry stays
// (its except: names only web-1) but reaches nothing he can use, so every
// report says no access is left (spec "every report then see no access").
func TestRevokeServerLastUnblockedServerNoGrantsLeft(t *testing.T) {
	blocked := func(t *testing.T) string {
		t.Helper()
		_, _, cfg := tagFleetManifest(t)
		return writeConfig(t, string(fileBytes(t, cfg))+"revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n")
	}
	t.Run("text", func(t *testing.T) {
		cfg := blocked(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(out.String(), "note: bob has no access left — 'sshepherd revoke bob") {
			t.Errorf("stdout:\n%s", out.String())
		}
		if got := readCfg(t, cfg).Access[1]; !reflect.DeepEqual(got, config.Access{User: "bob", Servers: []string{"@web"}, Except: []string{"web-1"}}) {
			t.Errorf("access[1] = %+v, want the entry kept", got)
		}
	})
	t.Run("json", func(t *testing.T) {
		cfg := blocked(t)
		doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--from-server", "web-1", "--json", "--no-apply", "--yes", "--config", cfg)
		e := doc["edit"].(map[string]any)["edits"].([]any)[0].(map[string]any)
		if e["no_grants_left"] != true {
			t.Errorf("edit entry = %v", e)
		}
	})
}

// TestRevokeServerTagJSON: the counts of a selector trim, and of a deleted
// @tag entry, which is not a wildcard removal.
func TestRevokeServerTagJSON(t *testing.T) {
	entry := func(doc map[string]any) map[string]any {
		return doc["edit"].(map[string]any)["edits"].([]any)[0].(map[string]any)
	}
	t.Run("selector trim", func(t *testing.T) {
		_, kh, cfg := tagFleetManifest(t)
		e := entry(runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--from-server", "web-1", "--json", "--yes", "--config", cfg, "--known-hosts", kh))
		if e["kind"] != "remove-access" || e["entries_changed"] != float64(1) || e["servers_excepted"] != float64(1) ||
			e["entries_removed"] != float64(0) || e["wildcards_removed"] != float64(0) || e["no_grants_left"] != false {
			t.Errorf("edit entry = %v", e)
		}
	})
	t.Run("deleted @tag entry", func(t *testing.T) {
		_, kh, cfg := tagFleetManifest(t)
		e := entry(runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--from-server", "web-1", "--from-server", "web-2", "--json", "--yes", "--config", cfg, "--known-hosts", kh))
		if e["entries_removed"] != float64(1) || e["wildcards_removed"] != float64(0) || e["no_grants_left"] != true {
			t.Errorf("edit entry = %v", e)
		}
	})
	t.Run("deleted @tag entry warns of no wildcard", func(t *testing.T) {
		_, _, cfg := tagFleetManifest(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--from-server", "web-2", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if strings.Contains(out.String(), "wildcard grant is removed") || !strings.Contains(out.String(), "note: bob has no access left") {
			t.Errorf("stdout:\n%s", out.String())
		}
	})
}

// TestRevokeServerLiteralBesideTagIsTombstoned: a name removed from a mixed
// list gains no except: (the tag does not reach it), so a tombstone is what
// remembers it (accessTombstones, D1a).
func TestRevokeServerLiteralBesideTagIsTombstoned(t *testing.T) {
	hosts, _, _ := editFleet(t, []byte{1}, "web-1", "db-1")
	tagged := strings.TrimSuffix(hosts["web-1"].line("web-1"), "}\n") + ", tags: [web]}\n"
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+tagged+hosts["db-1"].line("db-1")+
		"access:\n  - {user: alice, servers: [web-1, db-1]}\n  - {user: bob, servers: [\"@web\", db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "db-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	saved := readCfg(t, cfg)
	if !reflect.DeepEqual(saved.Access[1], config.Access{User: "bob", Servers: []string{"@web"}}) {
		t.Errorf("access[1] = %+v", saved.Access[1])
	}
	if _, ok := saved.AccessRevoked("bob", "db-1"); !ok {
		t.Errorf("no access tombstone for db-1: %+v", saved.Tombstones)
	}
}
