package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// protectedFleet: alice (k1) is a plain user, op (k2) an operator; web-1 and
// web-2 carry the web tag, db-1 carries none. users, access and extra are
// spliced in (extra is any further top-level section, e.g. groups: or
// revoked:).
func protectedFleet(t *testing.T, users, access, extra string) string {
	t.Helper()
	return `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 2) + `"]}
` + users + `servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [web]}
  - {name: db-1, host: 10.0.2.1, user: deploy}
access:
` + access + extra
}

// ciUser is a users: entry for ci (k3), protected.
func ciUser(t *testing.T) string {
	t.Helper()
	return `  - {name: ci, protected: true, keys: ["` + testkeys.Line(t, 3) + `"]}` + "\n"
}

// seedFPs are the fingerprints of the given key seeds, in order.
func seedFPs(t *testing.T, seeds ...byte) []string {
	t.Helper()
	var out []string
	for _, s := range seeds {
		out = append(out, fpOf(t, s))
	}
	return out
}

func TestIsProtected(t *testing.T) {
	for _, tc := range []struct {
		name string
		u    User
		want bool
	}{
		{"plain", User{}, false},
		{"operator", User{Operator: true}, true},
		{"protected", User{Protected: true}, true},
		{"both", User{Operator: true, Protected: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.u.IsProtected(); got != tc.want {
				t.Errorf("IsProtected = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestProtectedNeedsNoKey: a protected user with no keys has nothing to
// protect (spec S4), unlike an operator.
func TestProtectedNeedsNoKey(t *testing.T) {
	cfg := mustParse(t, protectedFleet(t, "  - {name: ci, protected: true, keys: []}\n", "  - {user: ci, servers: [web-1]}\n", ""))
	if !cfg.Users[2].Protected {
		t.Fatalf("Users[2] = %+v, want protected", cfg.Users[2])
	}
	if got, want := desiredFPs(cfg, "web-1"), seedFPs(t, 2); !slices.Equal(got, want) {
		t.Errorf("DesiredFor(web-1) = %v, want %v (only the operator)", got, want)
	}
	if _, err := Parse([]byte(protectedFleet(t, "  - {name: bad, operator: true, keys: []}\n", "", ""))); err == nil || !strings.Contains(err.Error(), `user "bad": operator requires at least one valid key`) {
		t.Errorf("err = %v, want the operator key requirement", err)
	}
}

func TestFleetWide(t *testing.T) {
	const team = "groups:\n  - {name: team, members: [op, alice]}\n"
	for _, tc := range []struct {
		name, access, extra string
		want                bool
	}{
		{"no entry", "", "", true},
		{"own wildcard", `  - {user: op, servers: ["*"]}` + "\n", "", false},
		{"own wildcard with except", `  - {user: op, servers: ["*"], except: [db-1]}` + "\n", "", false},
		{"@tag entry stays fleet-wide", `  - {user: op, servers: ["@web"]}` + "\n", "", true},
		{"literal entry stays fleet-wide", "  - {user: op, servers: [web-1]}\n", "", true},
		{"a group's wildcard does not count", `  - {group: team, servers: ["*"]}` + "\n", team, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, protectedFleet(t, "", tc.access, tc.extra))
			if got := cfg.FleetWide("op"); got != tc.want {
				t.Errorf("FleetWide(op) = %v, want %v", got, tc.want)
			}
		})
	}
	cfg := mustParse(t, protectedFleet(t, ciUser(t), "  - {user: ci, servers: [web-1]}\n", ""))
	for _, name := range []string{"alice", "ci", "nobody"} {
		if cfg.FleetWide(name) {
			t.Errorf("FleetWide(%s) = true", name)
		}
	}
}

// TestDesiredForProtectedAndScoped: protected-and-granted keys first in users
// order, then the rest in access order; an operator's own "*" and except:
// replace the implicit grant.
func TestDesiredForProtectedAndScoped(t *testing.T) {
	ci := ciUser(t)
	both := `  - {name: both, operator: true, protected: true, keys: ["` + testkeys.Line(t, 3) + `"]}` + "\n"
	const team = "groups:\n  - {name: team, members: [ci]}\n"
	for _, tc := range []struct {
		name, users, access, extra string
		web1, web2, db1            []byte
	}{
		{"operator with no entry is everywhere", "", "  - {user: alice, servers: [web-1]}\n", "",
			[]byte{2, 1}, []byte{2}, []byte{2}},
		{"own wildcard with except narrows", "", `  - {user: op, servers: ["*"], except: [db-1]}` + "\n", "",
			[]byte{2}, []byte{2}, nil},
		{"@tag entry leaves the operator fleet-wide", "", `  - {user: op, servers: ["@web"]}` + "\n", "",
			[]byte{2}, []byte{2}, []byte{2}},
		{"protected written first, users order", ci, "  - {user: alice, servers: [web-1]}\n  - {user: ci, servers: [web-1]}\n", "",
			[]byte{2, 3, 1}, []byte{2}, []byte{2}},
		{"protected not granted is not desired", ci, "  - {user: alice, servers: [web-1]}\n", "",
			[]byte{2, 1}, []byte{2}, []byte{2}},
		{"protected through a group is first", ci, "  - {user: alice, servers: [web-1]}\n  - {group: team, servers: [web-1]}\n", team,
			[]byte{2, 3, 1}, []byte{2}, []byte{2}},
		{"a blocked protected grant is not desired", ci, `  - {user: ci, servers: ["@web"]}` + "\n",
			"revoked:\n  - {user: ci, servers: [web-1], date: 2026-11-08}\n", []byte{2}, []byte{2, 3}, []byte{2}},
		{"both flags emit once", both, "  - {user: both, servers: [web-1]}\n", "",
			[]byte{2, 3}, []byte{2, 3}, []byte{2, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, protectedFleet(t, tc.users, tc.access, tc.extra))
			for _, s := range []struct {
				server string
				want   []byte
			}{{"web-1", tc.web1}, {"web-2", tc.web2}, {"db-1", tc.db1}} {
				if got, want := desiredFPs(cfg, s.server), seedFPs(t, s.want...); !slices.Equal(got, want) {
					t.Errorf("DesiredFor(%s) = %v, want %v", s.server, got, want)
				}
			}
		})
	}
}

// TestDesiredForUsersOrderAcrossProtectedKinds: written-first order is users
// order over every protected user, so a protected non-operator listed before
// an operator comes first, and it is not by access order either.
func TestDesiredForUsersOrderAcrossProtectedKinds(t *testing.T) {
	cfg := mustParse(t, `users:
  - {name: ci, protected: true, keys: ["`+testkeys.Line(t, 3)+`"]}
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 2)+`"]}
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.1.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: ci, servers: [web-1]}
`)
	if got, want := desiredFPs(cfg, "web-1"), seedFPs(t, 3, 2, 1); !slices.Equal(got, want) {
		t.Errorf("DesiredFor(web-1) = %v, want %v (ci, op, alice)", got, want)
	}
}

// TestCoversScopedOperator: a scoped operator goes through ordinary coverage,
// including its except:.
func TestCoversScopedOperator(t *testing.T) {
	cfg := mustParse(t, protectedFleet(t, "", `  - {user: op, servers: ["*"], except: [db-1]}`+"\n", ""))
	if !cfg.Covers("op", "web-1") || !cfg.Covers("op", "new-9") || cfg.Covers("op", "db-1") {
		t.Errorf("Covers: web-1 %v, new-9 %v, db-1 %v", cfg.Covers("op", "web-1"), cfg.Covers("op", "new-9"), cfg.Covers("op", "db-1"))
	}
	if !cfg.ExceptCarveOut("op", "db-1") {
		t.Error("ExceptCarveOut(op, db-1) = false")
	}
}

func TestGrantCountScopedOperator(t *testing.T) {
	for _, tc := range []struct {
		name, users, access string
		want                int
	}{
		{"fleet-wide operator on every server", "", "", 3},
		{"own wildcard with except counts its servers", "", `  - {user: op, servers: ["*"], except: [db-1]}` + "\n", 2},
		{"a redundant literal is not counted twice", "", "  - {user: op, servers: [web-1]}\n", 3},
		{"protected counts where granted", ciUser(t), "  - {user: ci, servers: [web-1]}\n", 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, protectedFleet(t, tc.users, tc.access, ""))
			if got := cfg.GrantCount(); got != tc.want {
				t.Errorf("GrantCount = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestWeakScopedOperatorNamesItsServers: a conflict names every server the key
// renders on, which for a scoped operator excludes its except:.
func TestWeakScopedOperatorNamesItsServers(t *testing.T) {
	users := `  - {name: weak, operator: true, keys: ["` + testkeys.DSALine(t, 1) + `"]}` + "\n"
	cfg := mustParse(t, protectedFleet(t, users, `  - {user: weak, servers: ["*"], except: [db-1]}`+"\n", ""))
	var servers []string
	for _, c := range cfg.Conflicts() {
		if c.User == "weak" {
			servers = c.Servers
		}
	}
	if want := []string{"web-1", "web-2"}; !slices.Equal(servers, want) {
		t.Errorf("conflict servers = %v, want %v", servers, want)
	}
}

// TestScopedOperatorTombstoneIsConflict: an operator's own "*" is a direct
// grant, so a tombstone over it is a W4 conflict and the key stays desired.
func TestScopedOperatorTombstoneIsConflict(t *testing.T) {
	cfg := mustParse(t, protectedFleet(t, "", `  - {user: op, servers: ["*"]}`+"\n", "revoked:\n  - {user: op, servers: [db-1], date: 2026-11-08}\n"))
	if cs := cfg.Conflicts(); len(cs) != 1 || cs[0].Kind != ConflictRevokedAccess {
		t.Fatalf("Conflicts = %+v, want one revoked-access conflict", cs)
	}
	if !hasKey(t, cfg, 2, "db-1") {
		t.Error("a conflict does not block: the key must stay desired")
	}
}

// TestScopedOperatorBlockedPairWarns: the skip in blockEntry is for an
// implicit grant that still installs the key. A scoped operator has none, so
// its blocked @tag pair warns like anyone's.
func TestScopedOperatorBlockedPairWarns(t *testing.T) {
	access := `  - {user: op, servers: ["*"], except: [web-1]}` + "\n" + `  - {user: op, servers: ["@web"]}` + "\n"
	cfg := mustParse(t, protectedFleet(t, "", access, "revoked:\n  - {user: op, servers: [web-1], date: 2026-11-08}\n"))
	if hasKey(t, cfg, 2, "web-1") {
		t.Error("the blocked pair must not render")
	}
	if !slices.ContainsFunc(cfg.ManifestWarnings, func(w ManifestWarning) bool { return w.Kind == WarnTombstoneBlocksGrant && w.User == "op" }) {
		t.Errorf("ManifestWarnings = %+v, want a tombstone_blocks_grant for op", cfg.ManifestWarnings)
	}
}

// TestOperatorGrantRedundantWarning: an entry warns when it cannot narrow a
// fleet-wide operator. An operator's own "*" replaces the grant and a group
// entry still grants its other members, so neither warns.
func TestOperatorGrantRedundantWarning(t *testing.T) {
	const want = `operator "op": this access entry adds nothing; operator: true still grants every server`
	const team = "groups:\n  - {name: team, members: [op, alice]}\n"
	for _, tc := range []struct {
		name, access, extra string
		count               int
	}{
		{"@tag", `  - {user: op, servers: ["@web"]}` + "\n", "", 1},
		{"literal", "  - {user: op, servers: [web-1]}\n", "", 1},
		{"each entry warns", "  - {user: op, servers: [web-1]}\n  - {user: op, servers: [web-2]}\n", "", 2},
		{"own wildcard", `  - {user: op, servers: ["*"]}` + "\n", "", 0},
		{"own wildcard with an @tag entry", `  - {user: op, servers: ["*"], except: [db-1]}` + "\n" + `  - {user: op, servers: ["@web"]}` + "\n", "", 0},
		{"group entry", "  - {group: team, servers: [web-1]}\n", team, 0},
		{"no entry", "", "", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, protectedFleet(t, "", tc.access, tc.extra))
			got := 0
			for _, w := range cfg.ManifestWarnings {
				if w.Kind == WarnOperatorGrantRedundant {
					got++
					if w.Message != want || w.User != "op" {
						t.Errorf("warning = %+v", w)
					}
				}
			}
			if got != tc.count {
				t.Errorf("redundant warnings = %d, want %d: %+v", got, tc.count, cfg.ManifestWarnings)
			}
		})
	}
	cfg := mustParse(t, protectedFleet(t, ciUser(t), "  - {user: ci, servers: [web-1]}\n", ""))
	if len(cfg.ManifestWarnings) != 0 {
		t.Errorf("a protected non-operator's entry warned: %+v", cfg.ManifestWarnings)
	}
}
