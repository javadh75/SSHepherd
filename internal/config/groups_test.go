package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// webTeam is a groups: entry; alice and bob are its members.
const webTeam = "  - {name: web-team, members: [alice, bob]}\n"

// groupFleet: alice (k1), bob (k2), carol (k3), op (k4, operator); web-1 and
// web-2 tagged web, web-3 tagged web on root, db-1 tagged db. groups, access
// and extra are spliced in verbatim.
func groupFleet(t *testing.T, groups, access, extra string) string {
	t.Helper()
	return `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
groups:
` + groups + `servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [web]}
  - {name: web-3, host: 10.0.1.3, user: root, tags: [web]}
  - {name: db-1, host: 10.0.2.1, user: deploy, tags: [db]}
access:
` + access + extra
}

func TestGroupValidation(t *testing.T) {
	long := strings.Repeat("a", 64)
	for _, tc := range []struct{ name, groups, want string }{
		{"uppercase", "  - {name: Web, members: [alice]}\n",
			`group "Web": name is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters`},
		{"empty name", `  - {name: "", members: [alice]}` + "\n", `group "": name is not valid`},
		{"64 characters", "  - {name: " + long + ", members: [alice]}\n", `group "` + long + `": name is not valid`},
		{"leading dash", "  - {name: -x, members: [alice]}\n", `group "-x": name is not valid`},
		{"repeated name", webTeam + webTeam, `duplicate group "web-team"`},
		{"unknown member", "  - {name: g, members: [zed]}\n", `group "g": unknown member "zed"`},
		{"repeated member", "  - {name: g, members: [alice, alice]}\n", `group "g": member "alice" is repeated`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(groupFleet(t, tc.groups, "", "")))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	valid := mustParse(t, groupFleet(t, "  - {name: a.b_c-d, description: docs only, members: [alice]}\n  - {name: 9lives, members: [bob, alice]}\n", "", ""))
	if len(valid.Groups) != 2 || valid.Groups[0].Description != "docs only" || !reflect.DeepEqual(valid.Groups[1].Members, []string{"bob", "alice"}) {
		t.Errorf("Groups = %+v", valid.Groups)
	}
	if len(valid.Warnings) != 0 {
		t.Errorf("Warnings = %q, want none", valid.Warnings)
	}
}

// TestEmptyGroupWarns: an empty group loads, so revoking the last member
// never breaks the manifest; a missing members: key is the same as [].
func TestEmptyGroupWarns(t *testing.T) {
	const want = `group "web-team" has no members; its grants add nothing`
	for _, groups := range []string{"  - {name: web-team, members: []}\n", "  - {name: web-team}\n"} {
		cfg := mustParse(t, groupFleet(t, groups, "", ""))
		if !reflect.DeepEqual(cfg.Warnings, []string{want}) {
			t.Errorf("Warnings = %q, want [%q]", cfg.Warnings, want)
		}
		if len(cfg.ManifestWarnings) != 1 || cfg.ManifestWarnings[0].Kind != WarnEmptyGroup || cfg.ManifestWarnings[0].Message != want {
			t.Errorf("ManifestWarnings = %+v", cfg.ManifestWarnings)
		}
	}
}

func TestAccessEntrySubject(t *testing.T) {
	for _, tc := range []struct{ name, access, want string }{
		{"neither", "  - {servers: [web-1]}\n", "access[0]: set exactly one of user or group"},
		{"both", "  - {user: alice, group: web-team, servers: [web-1]}\n", "access[0]: set exactly one of user or group"},
		{"second entry index", "  - {user: alice, servers: [web-1]}\n  - {servers: [web-1]}\n", "access[1]: set exactly one of user or group"},
		{"unknown group", "  - {group: nope, servers: [web-1]}\n", `access: unknown group "nope"`},
		{"unknown user unchanged", "  - {user: zed, servers: [web-1]}\n", `access: unknown user "zed"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(groupFleet(t, webTeam, tc.access, "")))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestGroupEntryErrorsNameTheGroup: every access-entry message prints the
// group, never `access for ""` (spec S3b, "Error text").
func TestGroupEntryErrorsNameTheGroup(t *testing.T) {
	for _, tc := range []struct{ name, entry, want string }{
		{"unknown server", `servers: [web-9]`, `access for group "web-team": unknown server "web-9"`},
		{"unknown tag", `servers: ["@nope"]`, `access for group "web-team": unknown tag "@nope"`},
		{"wildcard not alone", `servers: ["*", web-1]`, `access for group "web-team": "*" must be the only servers entry`},
		{"except needs a selector", `servers: [web-1], except: [web-2]`, `access for group "web-team": except requires servers ["*"] or an @tag`},
		{"empty servers", `servers: []`, `access for group "web-team": servers is empty (grants no servers)`},
		{"selector in except", `servers: ["@web"], except: ["@db"]`, `access for group "web-team": except takes server names, not the selector "@db"`},
		{"unknown except", `servers: ["@web"], except: [web-9]`, `access for group "web-team": unknown except server "web-9"`},
		{"in both lists", `servers: ["@web", web-1], except: [web-1]`, `access for group "web-team": "web-1" is in both servers and except`},
		{"wildcard grants nothing", `servers: ["*"], except: [web-1, web-2, web-3, db-1]`, `access for group "web-team": wildcard grants no servers`},
		{"selectors grant nothing", `servers: ["@db"], except: [db-1]`, `access for group "web-team": selectors grant no servers after except`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(groupFleet(t, webTeam, "  - {group: web-team, "+tc.entry+"}\n", "")))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func desiredFPs(cfg *Config, server string) []string {
	var out []string
	for _, k := range cfg.DesiredFor(server) {
		out = append(out, k.Fingerprint)
	}
	return out
}

func TestGroupEntryGrantsEveryMember(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"], except: [web-2]}\n", ""))
	for seed, want := range map[byte][]string{1: {"web-1", "web-3"}, 2: {"web-1", "web-3"}, 3: nil} {
		if got := grantedOn(t, cfg, seed); !reflect.DeepEqual(got, want) {
			t.Errorf("key %d granted on %v, want %v", seed, got, want)
		}
	}
}

// TestGroupGrantRenderOrder: access order, then member order inside an
// entry; a user reached twice is emitted once, at the first reach.
func TestGroupGrantRenderOrder(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, "  - {name: rev, members: [bob, alice]}\n",
		"  - {user: carol, servers: [web-1]}\n  - {group: rev, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", ""))
	want := []string{fpOf(t, 4), fpOf(t, 3), fpOf(t, 2), fpOf(t, 1)}
	if got := desiredFPs(cfg, "web-1"); !reflect.DeepEqual(got, want) {
		t.Errorf("DesiredFor = %v\nwant %v", got, want)
	}
}

// TestGroupOperatorMemberRenderedOnce: the existing redundant-grant skip
// applies to an operator member.
func TestGroupOperatorMemberRenderedOnce(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, "  - {name: ops, members: [op, alice]}\n", "  - {group: ops, servers: [web-1]}\n", ""))
	if got, want := desiredFPs(cfg, "web-1"), []string{fpOf(t, 4), fpOf(t, 1)}; !reflect.DeepEqual(got, want) {
		t.Errorf("DesiredFor = %v\nwant %v", got, want)
	}
	if got := cfg.GrantCount(); got != 5 { // op on 4 servers, alice on 1
		t.Errorf("GrantCount = %d, want 5", got)
	}
}

func TestEmptyGroupEntryGrantsNothing(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, "  - {name: none, members: []}\n", "  - {group: none, servers: [web-1]}\n", ""))
	if got, want := desiredFPs(cfg, "web-1"), []string{fpOf(t, 4)}; !reflect.DeepEqual(got, want) {
		t.Errorf("DesiredFor = %v\nwant %v (the operator only)", got, want)
	}
}

func TestGroupCoversAndCarveOut(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"*\"], except: [web-2]}\n", ""))
	for _, tc := range []struct {
		user, server string
		want         bool
	}{
		{"alice", "web-1", true},
		{"bob", "db-1", true},
		{"alice", "web-2", false},
		{"alice", "future", true}, // a member gets every wildcard, future servers included
		{"carol", "web-1", false},
	} {
		if got := cfg.Covers(tc.user, tc.server); got != tc.want {
			t.Errorf("Covers(%s, %s) = %v, want %v", tc.user, tc.server, got, tc.want)
		}
	}
	if !cfg.ExceptCarveOut("alice", "web-2") || !cfg.ExceptCarveOut("bob", "web-2") {
		t.Error("a group entry's except: must carve out for every member")
	}
	if cfg.ExceptCarveOut("carol", "web-2") {
		t.Error("carol is no member; the group's except: is not hers")
	}
	tagged := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n", ""))
	if tagged.Covers("alice", "future") {
		t.Error("an @tag never covers a server not in the manifest yet")
	}
}

const aliceOffWeb1 = "revoked:\n  - {user: alice, servers: [web-1], date: 2026-11-08}\n"

const blockedAlice = `access[0]: "alice" is not granted "web-1" through group web-team: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`

func TestTombstoneBlocksOneGroupMember(t *testing.T) {
	for _, tc := range []struct{ name, servers string }{
		{"tag", `["@web"]`},
		{"wildcard", `["*"]`},         // kills Covers without its c.blocked check
		{"literal", `[web-1, web-2]`}, // same, and proves a group name is not direct
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: "+tc.servers+"}\n", aliceOffWeb1))
			if hasKey(t, cfg, 1, "web-1") {
				t.Error("alice's key is still rendered on web-1")
			}
			if !hasKey(t, cfg, 2, "web-1") || !hasKey(t, cfg, 1, "web-2") {
				t.Errorf("other members and servers lost the grant: web-1 %v, alice %v", desiredFPs(cfg, "web-1"), grantedOn(t, cfg, 1))
			}
			if cfg.Covers("alice", "web-1") {
				t.Error("Covers(alice, web-1) = true: c.blocked must win over the raw scan")
			}
			if !cfg.Covers("bob", "web-1") {
				t.Error("Covers(bob, web-1) = false: only alice is blocked")
			}
			if _, ok := cfg.AccessRevoked("alice", "web-1"); !ok {
				t.Error("AccessRevoked must still answer for a blocked pair")
			}
			if len(cfg.Conflicts()) != 0 {
				t.Errorf("Conflicts = %+v, want none: a blocked grant is not a conflict", cfg.Conflicts())
			}
			if !slices.Contains(cfg.Warnings, blockedAlice) {
				t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, blockedAlice)
			}
			i := slices.IndexFunc(cfg.ManifestWarnings, func(w ManifestWarning) bool { return w.Message == blockedAlice })
			if i < 0 {
				t.Fatalf("ManifestWarnings = %+v", cfg.ManifestWarnings)
			}
			w := cfg.ManifestWarnings[i]
			if w.Kind != WarnTombstoneBlocksGrant || w.RevokedIndex == nil || *w.RevokedIndex != 0 || w.User != "alice" || w.Server != "web-1" {
				t.Errorf("warning = %+v", w)
			}
		})
	}
}

// TestGroupDirectGrantStaysConflict: a user: entry naming the server is a W4
// conflict even beside a group entry, the pair is not blocked, and only the
// user: entry is named.
func TestGroupDirectGrantStaysConflict(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", aliceOffWeb1))
	if !hasKey(t, cfg, 1, "web-1") {
		t.Error("a direct grant over a tombstone is a conflict, not a block")
	}
	cs := cfg.Conflicts()
	if len(cs) != 1 || cs[0].Kind != ConflictRevokedAccess || !strings.Contains(cs[0].Message, `is granted "web-1" by access[1]`) {
		t.Errorf("Conflicts = %+v, want one naming access[1]", cs)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("Warnings = %q, want none", cfg.Warnings)
	}
}

// TestGroupAndTagEntriesEachWarn: one warning per (entry, user, server).
func TestGroupAndTagEntriesEachWarn(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n  - {user: alice, servers: [\"@web\"]}\n", aliceOffWeb1))
	want := []string{blockedAlice, `access[1]: "alice" is not granted "web-1" through @web: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`}
	if !reflect.DeepEqual(cfg.Warnings, want) {
		t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, want)
	}
	if hasKey(t, cfg, 1, "web-1") || len(cfg.Conflicts()) != 0 {
		t.Errorf("web-1 = %v, conflicts = %+v", desiredFPs(cfg, "web-1"), cfg.Conflicts())
	}
}

func TestOperatorGroupMemberBlockedNoWarning(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, "  - {name: ops, members: [op]}\n", "  - {group: ops, servers: [web-1]}\n",
		"revoked:\n  - {user: op, servers: [web-1], date: 2026-11-08}\n"))
	if !hasKey(t, cfg, 4, "web-1") {
		t.Error("the implicit operator grant must still install the key")
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("Warnings = %q, want none: 'is not granted' would be false", cfg.Warnings)
	}
}

// TestKeyTombstoneCoversGroupGrant: serversRendering reads c.grants, so a key
// tombstone's conflict names the servers a group grant renders the key on.
func TestKeyTombstoneCoversGroupGrant(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n",
		"revoked:\n  - {fingerprint: "+fpOf(t, 1)+", user: alice, date: 2026-11-08}\n"))
	cs := cfg.Conflicts()
	if len(cs) != 1 || cs[0].Kind != ConflictRevokedKey || !reflect.DeepEqual(cs[0].Servers, []string{"web-1", "web-2", "web-3"}) {
		t.Errorf("Conflicts = %+v", cs)
	}
}

func TestBlockedGroupPairLeavesConflictsOfOthersAlone(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n  - {user: bob, servers: [web-1]}\n",
		"revoked:\n  - {user: bob, servers: [web-1], date: 2026-11-08}\n  - {user: alice, servers: [web-2], date: 2026-11-08}\n"))
	if !hasKey(t, cfg, 2, "web-1") || hasKey(t, cfg, 1, "web-2") {
		t.Errorf("bob on web-1 is a conflict (kept), alice on web-2 is blocked: web-1 %v, web-2 %v", desiredFPs(cfg, "web-1"), desiredFPs(cfg, "web-2"))
	}
	if cs := cfg.Conflicts(); len(cs) != 1 || cs[0].User != "bob" {
		t.Errorf("Conflicts = %+v", cs)
	}
}

// TestWildcardRootNamesTheGroup: a group "*" entry reaching a root account
// warns once per entry (spec S3b), an @tag does not.
func TestWildcardRootNamesTheGroup(t *testing.T) {
	const want = `access for group "web-team": servers ["*"] includes the root account on web-3; list the servers or use an @tag that excludes root accounts`
	cfg := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"*\"]}\n", ""))
	if !reflect.DeepEqual(cfg.Warnings, []string{want}) {
		t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, want)
	}
	if cfg.ManifestWarnings[0].Kind != WarnWildcardRoot || cfg.ManifestWarnings[0].User != "" {
		t.Errorf("warning = %+v", cfg.ManifestWarnings[0])
	}
	if tagged := mustParse(t, groupFleet(t, webTeam, "  - {group: web-team, servers: [\"@web\"]}\n", "")); len(tagged.Warnings) != 0 {
		t.Errorf("an @tag warned: %q", tagged.Warnings)
	}
	// Four root accounts: the design's literal text, which the README sample
	// copies.
	rootFleet := `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
groups:
  - {name: web-team, members: [alice]}
servers:
  - {name: web-1, host: 10.0.1.1, user: root}
  - {name: web-2, host: 10.0.1.2, user: root}
  - {name: web-3, host: 10.0.1.3, user: root}
  - {name: web-4, host: 10.0.1.4, user: root}
access:
  - {group: web-team, servers: ["*"]}
`
	const wantMore = `access for group "web-team": servers ["*"] includes the root account on web-1 and 3 more; list the servers or use an @tag that excludes root accounts`
	if got := mustParse(t, rootFleet).Warnings; !reflect.DeepEqual(got, []string{wantMore}) {
		t.Errorf("Warnings = %q\nwant %q", got, wantMore)
	}
	// An empty or all-operator group warns too: the grant stands for whoever
	// joins later (design gap 6). The empty group's own warning is another
	// kind, so only wildcard_root is compared.
	for _, tc := range []struct{ name, groups, group string }{
		{"empty group", "  - {name: none, members: []}\n", "none"},
		{"all-operator group", "  - {name: ops, members: [op]}\n", "ops"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grouped := mustParse(t, groupFleet(t, tc.groups, "  - {group: "+tc.group+", servers: [\"*\"]}\n", ""))
			var gotRoot []string
			for _, w := range grouped.ManifestWarnings {
				if w.Kind == WarnWildcardRoot {
					gotRoot = append(gotRoot, w.Message)
				}
			}
			wantRoot := `access for group "` + tc.group + `": servers ["*"] includes the root account on web-3; list the servers or use an @tag that excludes root accounts`
			if !reflect.DeepEqual(gotRoot, []string{wantRoot}) {
				t.Errorf("wildcard_root warnings = %q\nwant one %q", gotRoot, wantRoot)
			}
		})
	}
}
