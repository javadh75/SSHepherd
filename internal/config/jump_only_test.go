package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// jumpFleet: alice (k1), op (k2, operator); edge is a jump_only bastion on
// a root account tagged prod and edge, and web-1 (prod) and db-1 (root) sit
// behind it.
func jumpFleet(t *testing.T, access string) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"  - {name: op, operator: true, keys: [\"" + testkeys.Line(t, 2) + "\"]}\n" +
		"servers:\n  - {name: edge, host: edge.example.com, user: root, jump_only: true, tags: [prod, edge]}\n" +
		"  - {name: web-1, host: 10.0.1.5, user: deploy, via: edge, tags: [prod]}\n" +
		"  - {name: db-1, host: 10.0.2.1, user: root, via: edge}\n" +
		"access:\n" + access
}

// TestJumpOnlyReach: "*", @tag and the operator's implicit grant skip a
// jump_only server; Covers is false for it; it renders nothing, so
// GrantCount does not count it and wildcard_root does not name it.
func TestJumpOnlyReach(t *testing.T) {
	cfg := mustParse(t, jumpFleet(t, "  - {user: alice, servers: [\"*\"]}\n  - {user: alice, servers: [\"@prod\"]}\n"))
	if got := cfg.DesiredFor("edge"); len(got) != 0 {
		t.Errorf("DesiredFor(edge) = %d keys, want none", len(got))
	}
	for _, user := range []string{"alice", "op"} {
		if cfg.Covers(user, "edge") {
			t.Errorf("Covers(%s, edge) = true, want false", user)
		}
	}
	if !hasKey(t, cfg, 1, "web-1") || !hasKey(t, cfg, 2, "db-1") {
		t.Error("the bastion's dependents lost their grants")
	}
	if got := cfg.GrantCount(); got != 4 {
		t.Errorf("GrantCount = %d, want 4 (alice and op on web-1 and db-1)", got)
	}
	for _, w := range cfg.ManifestWarnings {
		if w.Kind == WarnWildcardRoot && strings.Contains(w.Message, "edge") {
			t.Errorf("wildcard_root names the jump_only server: %s", w.Message)
		}
	}
}

// TestJumpOnlyGroupWildcard: a group's "*" skips a jump_only server too,
// so a tombstone naming the server blocks no group grant there and warns
// nothing about it.
func TestJumpOnlyGroupWildcard(t *testing.T) {
	y := strings.Replace(jumpFleet(t, "  - {group: team, servers: [\"*\"]}\n"), "servers:\n", "groups:\n  - {name: team, members: [alice]}\nservers:\n", 1) +
		"revoked:\n  - {user: alice, servers: [edge], date: 2026-11-10}\n"
	cfg := mustParse(t, y)
	if got := cfg.DesiredFor("edge"); len(got) != 0 {
		t.Errorf("DesiredFor(edge) = %d keys, want none", len(got))
	}
	if !hasKey(t, cfg, 1, "web-1") {
		t.Error("the group lost web-1")
	}
	for _, w := range cfg.ManifestWarnings {
		if w.Kind == WarnTombstoneBlocksGrant && w.Server == "edge" {
			t.Errorf("tombstone_blocks_grant names the jump_only server: %s", w.Message)
		}
	}
}

// TestJumpOnlyNotInConflictServers: a revoked operator key's conflict lists
// the servers whose render holds it; the implicit grant skips the bastion.
func TestJumpOnlyNotInConflictServers(t *testing.T) {
	cfg := mustParse(t, jumpFleet(t, "  - {user: alice, servers: [web-1]}\n")+
		"revoked:\n  - {fingerprint: "+fpOf(t, 2)+", date: 2026-11-10}\n")
	cs := cfg.Conflicts()
	if len(cs) != 1 || !slices.Equal(cs[0].Servers, []string{"web-1", "db-1"}) {
		t.Errorf("Conflicts = %+v, want one naming web-1 and db-1 only", cs)
	}
}

func TestJumpOnlyAccessErrors(t *testing.T) {
	for _, tt := range []struct {
		name, access, want string
	}{
		{"named in servers", "  - {user: alice, servers: [edge]}\n",
			`access for "alice": server "edge" is jump_only; access cannot name it`},
		{"named in except", "  - {user: alice, servers: [\"*\"], except: [edge]}\n",
			`access for "alice": server "edge" is jump_only; access cannot name it`},
		{"a tag only it carries", "  - {user: alice, servers: [\"@edge\"]}\n",
			`access for "alice": "@edge" matches only jump_only servers`},
		{"a tag nobody carries", "  - {user: alice, servers: [\"@nope\"]}\n",
			`access for "alice": unknown tag "@nope"`},
		{"a group names it", "  - {group: team, servers: [edge]}\n",
			`access for group "team": server "edge" is jump_only; access cannot name it`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			y := strings.Replace(jumpFleet(t, tt.access), "servers:\n", "groups:\n  - {name: team, members: [alice]}\nservers:\n", 1)
			if got := loadErr(t, y); !strings.Contains(got, tt.want) {
				t.Errorf("error = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

func TestJumpOnlyWithAuthorizedKeysFile(t *testing.T) {
	y := "users: []\nservers:\n  - {name: edge, host: e, user: jump, jump_only: true, authorized_keys_file: /etc/k}\n" +
		"  - {name: web-1, host: w, user: deploy, via: edge}\n"
	if got := loadErr(t, y); !strings.Contains(got, `server "edge": jump_only has no managed file; remove authorized_keys_file`) {
		t.Errorf("error = %q", got)
	}
}

func TestJumpOnlyUnusedWarns(t *testing.T) {
	cfg := mustParse(t, "users: []\nservers:\n  - {name: bastion-eu, host: bastion.example.com, user: jump, jump_only: true}\n")
	want := ManifestWarning{Kind: WarnJumpOnlyUnused, Server: "bastion-eu",
		Message: `server "bastion-eu": jump_only but no server has via: bastion-eu; nothing connects through it and nothing checks it`}
	if len(cfg.ManifestWarnings) != 1 || !reflect.DeepEqual(cfg.ManifestWarnings[0], want) {
		t.Errorf("ManifestWarnings = %+v, want exactly %+v", cfg.ManifestWarnings, want)
	}
	used := mustParse(t, jumpFleet(t, "  - {user: alice, servers: [web-1]}\n"))
	for _, w := range used.ManifestWarnings {
		if w.Kind == WarnJumpOnlyUnused {
			t.Errorf("a bastion web-1 goes through warned: %s", w.Message)
		}
	}
}

// TestJumpOnlyTombstoneLoadsAndDoesNothing: a tombstone naming a jump_only
// server loads and has no effect while the flag is set; without the flag it
// applies again.
func TestJumpOnlyTombstoneLoadsAndDoesNothing(t *testing.T) {
	y := jumpFleet(t, "  - {user: alice, servers: [\"*\"]}\n") + "revoked:\n  - {user: alice, servers: [edge], date: 2026-11-10}\n"
	cfg := mustParse(t, y)
	if cs := cfg.Conflicts(); len(cs) != 0 {
		t.Errorf("Conflicts = %+v, want none", cs)
	}
	for _, w := range cfg.ManifestWarnings {
		if w.Kind == WarnTombstoneBlocksGrant {
			t.Errorf("a tombstone on a jump_only server blocked a grant: %s", w.Message)
		}
	}
	if !hasKey(t, cfg, 1, "web-1") {
		t.Error("alice lost web-1")
	}
	if cs := mustParse(t, strings.Replace(y, ", jump_only: true", "", 1)).Conflicts(); len(cs) != 1 {
		t.Errorf("without the flag: Conflicts = %+v, want alice's * over the tombstone", cs)
	}
}

// TestWildcardOverJumpOnlyAlone: a * entry over a fleet of jump_only
// servers grants nothing, the existing load error.
func TestWildcardOverJumpOnlyAlone(t *testing.T) {
	y := "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: edge, host: e, user: jump, jump_only: true}\naccess:\n  - {user: alice, servers: [\"*\"]}\n"
	if got := loadErr(t, y); !strings.Contains(got, `access for "alice": wildcard grants no servers`) {
		t.Errorf("error = %q", got)
	}
}
