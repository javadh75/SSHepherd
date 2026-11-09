package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagFleet: alice (k1), bob (k2), carol (k3), op (k4, operator); web-1 and
// web-2 are prod+web, web-3 prod+web on root, db-1 prod+db, db-2 db, and ci
// carries no tag. access and extra are appended verbatim.
func tagFleet(t *testing.T, access, extra string) string {
	t.Helper()
	return `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [prod, web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [prod, web]}
  - {name: web-3, host: 10.0.1.3, user: root, tags: [prod, web]}
  - {name: db-1, host: 10.0.2.1, user: deploy, tags: [prod, db]}
  - {name: db-2, host: 10.0.2.2, user: deploy, tags: [db]}
  - {name: ci, host: 10.0.3.1, user: git}
access:
` + access + extra
}

func mustParse(t *testing.T, y string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, y)
	}
	return cfg
}

// hasKey reports whether user's key is rendered on server.
func hasKey(t *testing.T, cfg *Config, seed byte, server string) bool {
	t.Helper()
	fp := fpOf(t, seed)
	return slices.ContainsFunc(cfg.DesiredFor(server), func(k authkeys.Key) bool { return k.Fingerprint == fp })
}

func grantedOn(t *testing.T, cfg *Config, seed byte) []string {
	t.Helper()
	var out []string
	for _, s := range cfg.Servers {
		if hasKey(t, cfg, seed, s.Name) {
			out = append(out, s.Name)
		}
	}
	return out
}

func TestTagValidation(t *testing.T) {
	long := strings.Repeat("a", 63)
	const web1 = "  - {name: web-1, host: 10.0.1.1, user: deploy, "
	for _, tc := range []struct{ name, servers, want string }{
		{"uppercase tag", web1 + "tags: [Prod]}\n", `server "web-1": tag "Prod" is not valid`},
		{"uppercase after the first character", web1 + "tags: [pRod]}\n", `server "web-1": tag "pRod" is not valid`},
		{"leading dash", web1 + "tags: [-prod]}\n", `server "web-1": tag "-prod" is not valid`},
		{"empty tag", web1 + `tags: [""]}` + "\n", `server "web-1": tag "" is not valid`},
		{"tag of 64 characters", web1 + "tags: [" + long + "a]}\n", `tag "` + long + `a" is not valid`},
		{"repeated tag", web1 + "tags: [prod, prod]}\n", `server "web-1": tag "prod" is repeated`},
		{"at-name reserved", "  - {name: web-1, host: 10.0.1.1, user: deploy}\n  - {name: \"@x\", host: 10.0.1.2, user: deploy}\n",
			`servers[1]: name "@x" is reserved for tag selectors`},
		{"wildcard name reserved", "  - {name: \"*\", host: 10.0.1.1, user: deploy}\n",
			`servers[0]: name "*" is reserved for wildcard grants`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte("users: []\nservers:\n" + tc.servers))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
	valid := mustParse(t, "users: []\nservers:\n"+web1+"tags: [a.b_c-d, 9lives, "+long+"]}\n")
	if got := valid.Servers[0].Tags; len(got) != 3 {
		t.Errorf("Tags = %v", got)
	}
}

func TestServerNameIssue(t *testing.T) {
	for name, want := range map[string]string{
		"web-1": "",
		"*":     "is reserved for wildcard grants",
		"@prod": "is reserved for tag selectors",
		"a b":   "contains whitespace",
		"a@b":   "",
	} {
		if got := ServerNameIssue(name); got != want {
			t.Errorf("ServerNameIssue(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestTagSelectorExpansion(t *testing.T) {
	for _, tc := range []struct {
		name, access string
		want         []string
	}{
		{"one tag, manifest order", `  - {user: carol, servers: ["@web"]}`, []string{"web-1", "web-2", "web-3"}},
		{"two tags union", `  - {user: carol, servers: ["@web", "@db"]}`, []string{"web-1", "web-2", "web-3", "db-1", "db-2"}},
		{"selector and name mix", `  - {user: carol, servers: ["@db", ci]}`, []string{"db-1", "db-2", "ci"}},
		{"name repeated by a tag", `  - {user: carol, servers: ["@db", db-1]}`, []string{"db-1", "db-2"}},
		{"except removes selector-derived", `  - {user: carol, servers: ["@web", ci], except: [web-2]}`, []string{"web-1", "web-3", "ci"}},
		{"except naming a server outside the tag", `  - {user: carol, servers: ["@db"], except: [ci]}`, []string{"db-1", "db-2"}},
		{"entries union", "  - {user: carol, servers: [\"@db\"]}\n  - {user: carol, servers: [web-1]}", []string{"web-1", "db-1", "db-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, tagFleet(t, tc.access+"\n", ""))
			if got := grantedOn(t, cfg, 3); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("granted on %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSelectorEntryValidation(t *testing.T) {
	for _, tc := range []struct{ name, access, want string }{
		{"unknown tag", `  - {user: carol, servers: ["@prd"]}`, `access for "carol": unknown tag "@prd"`},
		{"empty tag selector", `  - {user: carol, servers: ["@"]}`, `access for "carol": unknown tag "@"`},
		{"malformed tag selector", `  - {user: carol, servers: ["@Prod"]}`, `access for "carol": unknown tag "@Prod"`},
		{"wildcard not alone", `  - {user: carol, servers: ["*", "@prod"]}`, `access for "carol": "*" must be the only servers entry`},
		{"except with names only", `  - {user: carol, servers: [web-1], except: [web-2]}`, `access for "carol": except requires servers ["*"] or an @tag`},
		{"except names an unknown server", `  - {user: carol, servers: ["@prod"], except: [nope]}`, `access for "carol": unknown except server "nope"`},
		{"tag in except", `  - {user: carol, servers: ["@prod"], except: ["@web"]}`, `access for "carol": except takes server names, not the selector "@web"`},
		{"tag in a wildcard's except", `  - {user: carol, servers: ["*"], except: ["@web"]}`, `access for "carol": except takes server names, not the selector "@web"`},
		{"name in servers and except", `  - {user: carol, servers: ["@db", ci], except: [ci]}`, `access for "carol": "ci" is in both servers and except`},
		{"selector grants nothing", `  - {user: carol, servers: ["@db"], except: [db-1, db-2]}`, `access for "carol": selectors grant no servers after except`},
		{"wildcard grants nothing", `  - {user: carol, servers: ["*"], except: [web-1, web-2, web-3, db-1, db-2, ci]}`, `access for "carol": wildcard grants no servers`},
		{"unknown literal beside a tag", `  - {user: carol, servers: ["@db", nope]}`, `access for "carol": unknown server "nope"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tagFleet(t, tc.access+"\n", "")))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestCoversSelectors(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, `  - {user: alice, servers: ["*"], except: [ci]}
  - {user: carol, servers: ["@db", web-1], except: [db-2]}
`, ""))
	for _, tc := range []struct {
		name, user, server string
		want               bool
	}{
		{"tag member", "carol", "db-1", true},
		{"literal beside a tag", "carol", "web-1", true},
		{"excepted tag member", "carol", "db-2", false},
		{"not in the tag", "carol", "web-2", false},
		{"future server, @tag", "carol", "db-9", false},
		{"future server, wildcard", "alice", "db-9", true},
		{"wildcard's except", "alice", "ci", false},
	} {
		if got := cfg.Covers(tc.user, tc.server); got != tc.want {
			t.Errorf("%s: Covers(%s, %s) = %v, want %v", tc.name, tc.user, tc.server, got, tc.want)
		}
	}
	if !cfg.ExceptCarveOut("carol", "db-2") {
		t.Error("ExceptCarveOut must answer for an @tag entry")
	}
	if cfg.ExceptCarveOut("carol", "web-2") {
		t.Error("a server the except: does not name is no carve-out")
	}
}

func TestWildcardRootWarning(t *testing.T) {
	roots := "  - {name: r-1, host: 10.0.9.1, user: root}\n  - {name: r-2, host: 10.0.9.2, user: root}\n  - {name: r-3, host: 10.0.9.3, user: root}\n"
	withRoots := func(t *testing.T, access string) string {
		return strings.Replace(tagFleet(t, access, ""), "access:\n", roots+"access:\n", 1)
	}
	const tail = `; list the servers or use an @tag that excludes root accounts`
	for _, tc := range []struct {
		name, y string
		want    []string
	}{
		{"three more", withRoots(t, "  - {user: alice, servers: [\"*\"]}\n"),
			[]string{`access for "alice": servers ["*"] includes the root account on web-3 and 3 more` + tail}},
		{"one root left, no count", tagFleet(t, "  - {user: alice, servers: [\"*\"]}\n", ""),
			[]string{`access for "alice": servers ["*"] includes the root account on web-3` + tail}},
		{"once per entry", tagFleet(t, "  - {user: alice, servers: [\"*\"]}\n  - {user: bob, servers: [\"*\"], except: [ci]}\n", ""),
			[]string{
				`access for "alice": servers ["*"] includes the root account on web-3` + tail,
				`access for "bob": servers ["*"] includes the root account on web-3` + tail,
			}},
		{"except removes the root account", tagFleet(t, "  - {user: alice, servers: [\"*\"], except: [web-3]}\n", ""), nil},
		{"an operator does not warn", tagFleet(t, "  - {user: op, servers: [\"*\"]}\n", ""), nil},
		{"an @tag reaching root does not warn", tagFleet(t, "  - {user: alice, servers: [\"@web\"]}\n", ""), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, tc.y)
			if !reflect.DeepEqual(cfg.Warnings, tc.want) {
				t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, tc.want)
			}
			for _, w := range cfg.ManifestWarnings {
				if w.Kind != WarnWildcardRoot || w.User != "" || w.RevokedIndex != nil || w.Server != "" {
					t.Errorf("warning = %+v", w)
				}
			}
		})
	}
}

// memoryOnDB is a tombstone removing bob from db-1.
const memoryOnDB = "revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n"

const blockedDB1 = `access[0]: "bob" is not granted "db-1" through @db: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`

func TestTombstoneBlocksTagGrant(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@db\"]}\n", memoryOnDB))
	if c := cfg.Conflicts(); len(c) != 0 {
		t.Errorf("Conflicts = %+v, want none: a blocked grant is not a conflict", c)
	}
	if !reflect.DeepEqual(cfg.Warnings, []string{blockedDB1}) {
		t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, blockedDB1)
	}
	w := cfg.ManifestWarnings[0]
	if w.Kind != WarnTombstoneBlocksGrant || w.RevokedIndex == nil || *w.RevokedIndex != 0 || w.User != "bob" || w.Server != "db-1" {
		t.Errorf("warning = %+v", w)
	}
	if got := grantedOn(t, cfg, 2); !reflect.DeepEqual(got, []string{"db-2"}) {
		t.Errorf("granted on %v, want [db-2]", got)
	}
	if cfg.Covers("bob", "db-1") {
		t.Error("Covers must be false for a blocked pair")
	}
	if _, ok := cfg.AccessRevoked("bob", "db-1"); !ok {
		t.Error("AccessRevoked must still answer")
	}
	if cfg.GrantCount() != 1+6 { // bob on db-2, op everywhere
		t.Errorf("GrantCount = %d", cfg.GrantCount())
	}
}

// TestBlockedWarningNamesTheGrantingSelector: in a mixed list the warning names
// the first selector that reaches the server, not a literal beside it.
func TestBlockedWarningNamesTheGrantingSelector(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [ci, \"@db\", \"@prod\"]}\n", memoryOnDB))
	if !reflect.DeepEqual(cfg.Warnings, []string{blockedDB1}) {
		t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, blockedDB1)
	}
}

// TestInvalidTagIsNotAlsoRepeated: a tag that fails the shape check is reported
// once per occurrence and never as repeated.
func TestInvalidTagIsNotAlsoRepeated(t *testing.T) {
	_, err := Parse([]byte("users: []\nservers:\n  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [Prod, Prod]}\n"))
	if err == nil || strings.Count(err.Error(), `tag "Prod" is not valid`) != 2 || strings.Contains(err.Error(), "is repeated") {
		t.Errorf("err = %v, want two shape errors and no repeat error", err)
	}
}

func TestBlockedPairsPerEntryAndLatestTombstone(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@db\"]}\n  - {user: bob, servers: [\"@prod\"]}\n",
		"revoked:\n  - {user: bob, servers: [db-1], date: 2026-01-01}\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n"))
	want := []string{
		`access[0]: "bob" is not granted "db-1" through @db: revoked[1] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
		`access[1]: "bob" is not granted "db-1" through @prod: revoked[1] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
	}
	if !reflect.DeepEqual(cfg.Warnings, want) {
		t.Errorf("Warnings = %q\nwant %q", cfg.Warnings, want)
	}
	if got, _ := cfg.AccessRevoked("bob", "db-1"); got.Date != "2026-11-08" {
		t.Errorf("AccessRevoked = %+v; the warning must name the same tombstone", got)
	}
}

func TestLiteralInSameEntryStaysConflict(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@db\", db-1]}\n", memoryOnDB))
	if len(cfg.Warnings) != 0 {
		t.Errorf("Warnings = %q, want none: a literal is direct", cfg.Warnings)
	}
	want := Conflict{Kind: ConflictRevokedAccess, User: "bob", Servers: []string{"db-1", "db-2"},
		Message: `user "bob" is granted "db-1" by access[0], but revoked[0] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately`}
	if got := cfg.Conflicts(); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Errorf("Conflicts = %+v\nwant [%+v]", got, want)
	}
	if !cfg.Covers("bob", "db-1") {
		t.Error("a conflicted pair stays granted")
	}
}

func TestLiteralAndTagInTwoEntriesNamesOnlyLiteralEntry(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [db-1]}\n  - {user: bob, servers: [\"@db\"]}\n", memoryOnDB))
	got := cfg.Conflicts()
	if len(got) != 1 || !strings.Contains(got[0].Message, "by access[0],") || !reflect.DeepEqual(got[0].Servers, []string{"db-1"}) {
		t.Errorf("Conflicts = %+v, want only access[0], servers [db-1]", got)
	}
	if len(cfg.Warnings) != 0 {
		t.Errorf("Warnings = %q: the pair is not blocked", cfg.Warnings)
	}
}

func TestBlockedPairLeavesConflictServersAlone(t *testing.T) {
	// web-1 is blocked (through @web), db-1 is a W4 conflict (literal): the
	// conflict's Servers is what the entry renders on, without web-1.
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@web\", db-1]}\n",
		"revoked:\n  - {user: bob, servers: [db-1, web-1], date: 2026-11-08}\n"))
	got := cfg.Conflicts()
	if len(got) != 1 || !reflect.DeepEqual(got[0].Servers, []string{"web-2", "web-3", "db-1"}) {
		t.Errorf("Conflicts = %+v, want Servers [web-2 web-3 db-1]", got)
	}
}

func TestWildcardOverTombstoneStaysConflict(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"*\"]}\n", memoryOnDB))
	if len(cfg.Conflicts()) != 1 {
		t.Errorf("Conflicts = %+v, want the W4 conflict", cfg.Conflicts())
	}
}

// TestWildcardExceptIsNotDirect: a server a wildcard excepts is not reached
// directly, so an @tag entry reaching it is blocked, not a conflict.
func TestWildcardExceptIsNotDirect(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"*\"], except: [db-1, web-3]}\n  - {user: bob, servers: [\"@db\"]}\n", memoryOnDB))
	if len(cfg.Conflicts()) != 0 || cfg.Covers("bob", "db-1") {
		t.Errorf("Conflicts = %+v, Covers = %v; want blocked", cfg.Conflicts(), cfg.Covers("bob", "db-1"))
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], `access[1]: "bob" is not granted "db-1" through @db`) {
		t.Errorf("Warnings = %q", cfg.Warnings)
	}
}

func TestOperatorBlockedPairNoWarning(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: op, servers: [\"@db\"]}\n", "revoked:\n  - {user: op, servers: [db-1], date: 2026-11-08}\n"))
	if len(cfg.Warnings) != 0 || len(cfg.Conflicts()) != 0 {
		t.Errorf("Warnings = %q, Conflicts = %+v, want neither", cfg.Warnings, cfg.Conflicts())
	}
	if !hasKey(t, cfg, 4, "db-1") {
		t.Error("the implicit operator grant must still install the key")
	}
}

func TestTombstoneIgnoredServerDoesNotBlock(t *testing.T) {
	cfg := mustParse(t, tagFleet(t, "  - {user: bob, servers: [\"@db\"]}\n", "revoked:\n  - {user: bob, servers: [db-9], date: 2026-11-08}\n"))
	if got := grantedOn(t, cfg, 2); !reflect.DeepEqual(got, []string{"db-1", "db-2"}) {
		t.Errorf("granted on %v", got)
	}
	if len(cfg.Warnings) != 1 || !strings.Contains(cfg.Warnings[0], "unknown server") {
		t.Errorf("Warnings = %q, want only the D1e warning", cfg.Warnings)
	}
}

func TestTombstoneSelectorIsLoadError(t *testing.T) {
	_, err := Parse([]byte(tagFleet(t, "  - {user: bob, servers: [db-1]}\n", "revoked:\n  - {user: bob, servers: [\"@db\"], date: 2026-11-08}\n")))
	if err == nil || !strings.Contains(err.Error(), "revoked[0]: servers cannot hold a selector; list the servers by name") {
		t.Errorf("err = %v", err)
	}
}
