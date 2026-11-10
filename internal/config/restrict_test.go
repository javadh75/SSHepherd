package config

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// grantFleet (spec S7): alice (k1, her key line prefixed by aliceOpts,
// verbatim, may be ""), bob (k2), carol (k3), op (k4, operator); web-1 and
// web-2 tagged web, db-1 tagged db, no root account. groups and access are
// spliced in verbatim.
func grantFleet(t *testing.T, aliceOpts, groups, access string) string {
	t.Helper()
	return `users:
  - {name: alice, keys: ['` + aliceOpts + testkeys.Line(t, 1) + `']}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
groups:
` + groups + `servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [web]}
  - {name: db-1, host: 10.0.2.1, user: deploy, tags: [db]}
access:
` + access
}

// grantOpts returns the options the key of seed renders with on server, and
// whether it renders there at all.
func grantOpts(t *testing.T, cfg *Config, seed byte, server string) ([]string, bool) {
	t.Helper()
	want := fpOfLine(t, testkeys.Line(t, seed))
	for _, k := range cfg.DesiredFor(server) {
		if k.Fingerprint == want {
			return k.Options, true
		}
	}
	return nil, false
}

// TestGrantOptionValidation (spec S7 Validation): each row is a load error.
func TestGrantOptionValidation(t *testing.T) {
	team := "  - {name: team, members: [bob, alice]}\n"
	for _, tc := range []struct{ name, aliceOpts, groups, access, want string }{
		{"an unknown option", "", "", "  - {user: bob, servers: [web-1], options: [no-ptty]}\n",
			`access[0]: option "no-ptty" is not a recognized authorized_keys option`},
		{"an unquoted value", "", "", "  - {user: bob, servers: [web-1], options: [from=10.0.0.1]}\n",
			`access[0]: option "from=10.0.0.1" requires a quoted value (name="...")`},
		{"a bad expiry", "", "", `  - {user: bob, servers: [web-1], options: ['expiry-time="2027"']}` + "\n",
			`access[0]: option "expiry-time=\"2027\"" has an invalid value (want YYYYMMDD[HHMM[SS]][Z])`},
		{"a widening option", "", "", "  - {user: bob, servers: [web-1], options: [pty]}\n",
			`access[0]: option "pty" does not restrict access; a grant can only add restrictions`},
		{"a neutral option", "", "", `  - {user: bob, servers: [web-1], options: ['environment="A=b"']}` + "\n",
			`access[0]: option "environment=\"A=b\"" does not restrict access; a grant can only add restrictions`},
		{"cert-authority", "", "", "  - {user: bob, servers: [web-1], options: [cert-authority]}\n",
			`access[0]: option "cert-authority" makes the key accept certificates only; a grant cannot turn a key into a certificate authority`},
		{"principals", "", "", `  - {user: bob, servers: [web-1], options: ['principals="ops"']}` + "\n",
			`access[0]: option "principals=\"ops\"" makes the key accept certificates only; a grant cannot turn a key into a certificate authority`},
		{"a repeated from= in one grant", "", "", `  - {user: bob, servers: [web-1], options: ['from="10.0.0.0/8"', 'from="10.1.0.0/16"']}` + "\n",
			`access[0]: option "from=\"10.1.0.0/16\"" repeats from=, which sshd allows once per line`},
		{"a name already on the key line", `from="10.0.0.0/8" `, "", `  - {user: alice, servers: [web-1], options: ['from="10.1.0.0/16"']}` + "\n",
			`access[0]: option "from=\"10.1.0.0/16\"": user "alice" key 1 already carries "from=\"10.0.0.0/8\""; restrict a key on its key line or on its grants, not both`},
		{"the same name in another case", `FROM="10.0.0.0/8" `, "", `  - {user: alice, servers: [web-1], options: ['from="10.0.0.0/8"']}` + "\n",
			`access[0]: option "from=\"10.0.0.0/8\"": user "alice" key 1 already carries "FROM=\"10.0.0.0/8\""`},
		{"a permitopen= union", `permitopen="db:5432" `, "", `  - {user: alice, servers: [web-1], options: ['permitopen="cache:6379"']}` + "\n",
			`access[0]: option "permitopen=\"cache:6379\"": user "alice" key 1 already carries "permitopen=\"db:5432\""`},
		{"a member's key line through a group", "no-pty ", team, "  - {group: team, servers: [web-1], options: [NO-PTY]}\n",
			`access[0]: option "NO-PTY": user "alice" key 1 already carries "no-pty"`},
		{"the entry's own index", "", "", "  - {user: bob, servers: [web-1]}\n  - {user: carol, servers: [web-2], options: [pty]}\n",
			`access[1]: option "pty" does not restrict access`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(grantFleet(t, tc.aliceOpts, tc.groups, tc.access)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestGrantOptionsAccepted: every restricting option loads in one grant, on
// a key line that already carries an option the grant does not name.
func TestGrantOptionsAccepted(t *testing.T) {
	all := `['command="backup"', 'expiry-time="20990101"', 'from="10.0.0.0/8"', no-agent-forwarding, no-port-forwarding, no-pty, no-user-rc, no-x11-forwarding, 'permitlisten="8080"', 'permitopen="db:5432"', restrict, verify-required]`
	cfg := mustParse(t, grantFleet(t, "no-touch-required ", "", "  - {user: alice, servers: [web-1], options: "+all+"}\n"))
	if len(cfg.Access[0].Options) != 12 {
		t.Errorf("Options = %q, want all 12", cfg.Access[0].Options)
	}
}

// TestGrantOptionsRenderPerServer (spec S7 Meaning): one key, restricted on
// the servers one entry grants and plain where another grants it; except:
// carves web-2 out of the restricted entry. The key line's own option comes
// first.
func TestGrantOptionsRenderPerServer(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "no-agent-forwarding ", "",
		`  - {user: alice, servers: ["@web"], except: [web-2], options: ['from="10.0.0.0/8"', no-pty]}
  - {user: alice, servers: [web-2]}
`))
	for server, want := range map[string][]string{
		"web-1": {"no-agent-forwarding", `from="10.0.0.0/8"`, "no-pty"},
		"web-2": {"no-agent-forwarding"},
	} {
		if got, ok := grantOpts(t, cfg, 1, server); !ok || !slices.Equal(got, want) {
			t.Errorf("%s: options = %q (rendered %v), want %q", server, got, ok, want)
		}
	}
	if _, ok := grantOpts(t, cfg, 1, "db-1"); ok {
		t.Error("alice renders on db-1, which no entry grants")
	}
	// keysOn copies: the manifest's parsed key line never changes.
	if got := cfg.keysByUser["alice"][0].Options; !slices.Equal(got, []string{"no-agent-forwarding"}) {
		t.Errorf("alice's parsed key line changed to %q", got)
	}
}

// TestKeysOnNeverSharesOptions: each server's render owns its options, so
// rendering web-2 cannot rewrite web-1's earlier result. The parsed key line
// is given spare capacity first: an in-place append (mutant G13) would then
// write both renders into one backing array, which the parsed-line check
// above cannot see (its length never changes).
func TestKeysOnNeverSharesOptions(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "no-agent-forwarding ", "",
		"  - {user: alice, servers: [web-1], options: [no-pty]}\n  - {user: alice, servers: [web-2], options: [restrict]}\n"))
	line := &cfg.keysByUser["alice"][0]
	line.Options = slices.Grow(line.Options, 4) // spare capacity, whatever the parser left
	web1, _ := grantOpts(t, cfg, 1, "web-1")
	_ = cfg.DesiredFor("web-2") // under G13 this overwrites web1's last option
	if want := []string{"no-agent-forwarding", "no-pty"}; !slices.Equal(web1, want) {
		t.Errorf("web-1 renders %q after web-2 was rendered, want %q", web1, want)
	}
}

// TestGroupGrantOptionsMatchFlatTwin (spec S7 composition with S3b): a group
// entry's options reach every member, exactly as one user: entry per member
// with the same options would.
func TestGroupGrantOptionsMatchFlatTwin(t *testing.T) {
	group := mustParse(t, grantFleet(t, "", "  - {name: team, members: [alice, bob]}\n",
		"  - {group: team, servers: [\"@web\"], options: [no-pty, no-x11-forwarding]}\n"))
	flat := mustParse(t, grantFleet(t, "", "",
		"  - {user: alice, servers: [\"@web\"], options: [no-pty, no-x11-forwarding]}\n"+
			"  - {user: bob, servers: [\"@web\"], options: [no-pty, no-x11-forwarding]}\n"))
	for _, s := range []string{"web-1", "web-2", "db-1"} {
		if g, f := group.DesiredFor(s), flat.DesiredFor(s); !reflect.DeepEqual(g, f) {
			t.Errorf("%s: the group renders %+v, its flat twin %+v", s, g, f)
		}
	}
	if got, _ := grantOpts(t, group, 2, "web-2"); !slices.Equal(got, []string{"no-pty", "no-x11-forwarding"}) {
		t.Errorf("bob on web-2 = %q", got)
	}
}

// TestOperatorOwnGrantOptions (spec S7 with S4): an operator's own "*" entry
// replaces the implicit grant, so its options reach every server and its key
// is still written first.
func TestOperatorOwnGrantOptions(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "", "  - {user: bob, servers: [web-1]}\n  - {user: op, servers: [\"*\"], options: [no-pty]}\n"))
	desired := cfg.DesiredFor("web-1")
	if len(desired) != 2 || desired[0].Fingerprint != fpOfLine(t, testkeys.Line(t, 4)) || !slices.Equal(desired[0].Options, []string{"no-pty"}) {
		t.Errorf("web-1 = %+v, want op first with no-pty, then bob", desired)
	}
}

// TestOfferOrderSeesGrantOptions (spec S7 Render): a grant's command= makes
// its key a forced-command line on that server only, so every connection
// offers the plain key first there and keeps grant order elsewhere.
func TestOfferOrderSeesGrantOptions(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "", `  - {user: alice, servers: [web-1], options: ['command="backup"']}
  - {user: alice, servers: [web-2]}
  - {user: bob, servers: [web-1, web-2]}
`))
	a, b, op := fpOfLine(t, testkeys.Line(t, 1)), fpOfLine(t, testkeys.Line(t, 2)), fpOfLine(t, testkeys.Line(t, 4))
	if got := authkeys.OfferOrder(cfg.DesiredFor("web-1")); !slices.Equal(got, []string{op, b, a}) {
		t.Errorf("web-1 offer order = %q, want op, bob, then alice's forced-command line", got)
	}
	if got := authkeys.OfferOrder(cfg.DesiredFor("web-2")); !slices.Equal(got, []string{op, a, b}) {
		t.Errorf("web-2 offer order = %q, want op, alice, bob", got)
	}
}

// clashTail ends every restriction conflict's message.
const clashTail = "; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user"

// clashesOf is the manifest's restriction conflicts.
func clashesOf(cfg *Config) []Conflict {
	var out []Conflict
	for _, c := range cfg.Conflicts() {
		if c.Kind == ConflictRestriction {
			out = append(out, c)
		}
	}
	return out
}

// TestRestrictionConflict (spec S7, OP6): a clash loads (a policy conflict,
// not a load error), one conflict per user and pair of grant sources, every
// server where the pair disagrees, no fingerprint.
func TestRestrictionConflict(t *testing.T) {
	team := "  - {name: team, members: [alice, bob]}\n"
	clash := func(user string, servers []string, msg string) Conflict {
		return Conflict{Kind: ConflictRestriction, User: user, Servers: servers, Message: msg + clashTail}
	}
	for _, tc := range []struct {
		name, groups, access string
		want                 []Conflict
	}{
		{"a tag and a name", "", `  - {user: alice, servers: ["@web"], options: ['from="10.0.0.0/8"', no-pty]}
  - {user: alice, servers: [web-1]}
`, []Conflict{clash("alice", []string{"web-1"},
			`user "alice": server "web-1" is granted by access[0] with [from="10.0.0.0/8" no-pty] and by access[1] with no options`)}},
		{"several servers", "", `  - {user: alice, servers: ["*"], options: [no-pty]}
  - {user: alice, servers: ["@web"]}
`, []Conflict{clash("alice", []string{"web-1", "web-2"},
			`user "alice": servers "web-1" and 1 more are granted by access[0] with [no-pty] and by access[1] with no options`)}},
		{"a group and a member's own entry", team, `  - {group: team, servers: ["@web"], options: [no-pty]}
  - {user: bob, servers: [web-2]}
`, []Conflict{clash("bob", []string{"web-2"},
			`user "bob": server "web-2" is granted by access[0] with [no-pty] and by access[1] with no options`)}},
		{"an operator's implicit grant", "", "  - {user: op, servers: [db-1], options: [no-pty]}\n",
			[]Conflict{clash("op", []string{"db-1"},
				`user "op": server "db-1" is granted by its operator grant with no options and by access[0] with [no-pty]`)}},
		{"an operator in a restricted group", "  - {name: ops, members: [op]}\n", "  - {group: ops, servers: [\"@web\"], options: [restrict]}\n",
			[]Conflict{clash("op", []string{"web-1", "web-2"},
				`user "op": servers "web-1" and 1 more are granted by its operator grant with no options and by access[0] with [restrict]`)}},
		{"three sets: the first two that differ", "", `  - {user: alice, servers: [web-1], options: [no-pty]}
  - {user: alice, servers: [web-1], options: [NO-PTY]}
  - {user: alice, servers: [web-1], options: [restrict]}
  - {user: alice, servers: [web-1], options: [no-x11-forwarding]}
`, []Conflict{clash("alice", []string{"web-1"},
			`user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[2] with [restrict]`)}},
		{"two pairs, two conflicts", "", `  - {user: alice, servers: [web-1, web-2], options: [no-pty]}
  - {user: alice, servers: [web-1]}
  - {user: alice, servers: [web-2], options: [restrict]}
`, []Conflict{
			clash("alice", []string{"web-1"}, `user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[1] with no options`),
			clash("alice", []string{"web-2"}, `user "alice": server "web-2" is granted by access[0] with [no-pty] and by access[2] with [restrict]`),
		}},
		// plan gap 4: access[0] and access[2] also disagree on web-1, but
		// there the first disagreement is with access[1].
		{"a pair is named only where it is the first disagreement", "", `  - {user: alice, servers: [web-1, web-2], options: [no-pty]}
  - {user: alice, servers: [web-1], options: [restrict]}
  - {user: alice, servers: [web-1, web-2], options: [no-x11-forwarding]}
`, []Conflict{
			clash("alice", []string{"web-1"}, `user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[1] with [restrict]`),
			clash("alice", []string{"web-2"}, `user "alice": server "web-2" is granted by access[0] with [no-pty] and by access[2] with [no-x11-forwarding]`),
		}},
		{"an empty list is no options", "", "  - {user: alice, servers: [web-1], options: []}\n  - {user: alice, servers: [web-1]}\n", nil},
		{"order and name case do not matter", "", `  - {user: alice, servers: ["@web"], options: [no-pty, 'from="10.0.0.0/8"']}
  - {user: alice, servers: [web-1], options: ['FROM="10.0.0.0/8"', NO-PTY]}
`, nil},
		{"a group and a tag with the same set", team, `  - {group: team, servers: [web-1], options: [no-pty]}
  - {user: alice, servers: ["@web"], options: [no-pty]}
`, nil},
		{"no options anywhere", "", "  - {user: alice, servers: [\"@web\"]}\n  - {user: alice, servers: [web-1]}\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, grantFleet(t, "", tc.groups, tc.access))
			if got := clashesOf(cfg); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("restriction conflicts:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// TestBlockedGrantCannotClash (spec S7 Tombstones): the access tombstone
// blocks alice's tag and group grants of web-1 (neither names her there
// directly), so they take no part in the clash check; web-2 still clashes.
func TestBlockedGrantCannotClash(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "  - {name: team, members: [alice, bob]}\n", `  - {group: team, servers: ["@web"]}
  - {user: alice, servers: ["@web"], options: [no-pty]}
revoked:
  - {user: alice, servers: [web-1], date: 2026-11-10}
`))
	if got := clashesOf(cfg); len(got) != 1 || !slices.Equal(got[0].Servers, []string{"web-2"}) {
		t.Errorf("clashes = %+v, want alice on web-2 only", got)
	}
	if _, ok := grantOpts(t, cfg, 1, "web-1"); ok {
		t.Error("the blocked pair still renders alice on web-1")
	}
}

// TestBlockedOperatorStillRenders: a tombstone blocks an operator's group
// grant of web-1, but the implicit grant still installs the key there, with
// no options and no clash; web-2 still clashes.
func TestBlockedOperatorStillRenders(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "  - {name: ops, members: [op]}\n", `  - {group: ops, servers: ["@web"], options: [restrict]}
revoked:
  - {user: op, servers: [web-1], date: 2026-11-10}
`))
	if got, ok := grantOpts(t, cfg, 4, "web-1"); !ok || len(got) != 0 {
		t.Errorf("op on web-1 = %q (rendered %v), want the implicit grant's key with no options", got, ok)
	}
	// The blocked pair keeps the implicit grant as its one source (G10b:
	// DesiredFor would still emit op, so only the sources show it).
	if src := cfg.grantSources("op", cfg.Servers[0]); len(src) != 1 || src[0].entry != implicitGrant {
		t.Errorf("op's sources on web-1 = %+v, want the implicit grant alone", src)
	}
	if got := clashesOf(cfg); len(got) != 1 || !slices.Equal(got[0].Servers, []string{"web-2"}) {
		t.Errorf("clashes = %+v, want op on web-2 only", got)
	}
}

// TestEmptyGrantOptions (spec S7 Go shape: "An empty list means no
// restrictions"): options: [] loads, renders the key line alone and never
// clashes with an entry without options:.
func TestEmptyGrantOptions(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "no-agent-forwarding ", "",
		"  - {user: alice, servers: [web-1], options: []}\n  - {user: alice, servers: [web-1]}\n"))
	if got, ok := grantOpts(t, cfg, 1, "web-1"); !ok || !slices.Equal(got, []string{"no-agent-forwarding"}) {
		t.Errorf("alice on web-1 = %q (rendered %v), want the key line's option alone", got, ok)
	}
	if got := clashesOf(cfg); len(got) != 0 {
		t.Errorf("clashes = %+v, want none", got)
	}
}

// TestKeylessUserNeverClashes (plan gap 5): a protected user with no keys
// renders nothing, so two grants cannot disagree about a key.
func TestKeylessUserNeverClashes(t *testing.T) {
	y := strings.Replace(grantFleet(t, "", "", "  - {user: ci, servers: [web-1], options: [no-pty]}\n  - {user: ci, servers: [web-1]}\n"),
		"users:\n", "users:\n  - {name: ci, protected: true, keys: []}\n", 1)
	if got := clashesOf(mustParse(t, y)); len(got) != 0 {
		t.Errorf("clashes = %+v, want none", got)
	}
}

// TestClashedPairRendersFirstSource (spec S7 Render, plan gap 3): a clashed
// pair still renders, with the first source's options; an operator's
// implicit grant comes first and adds none.
func TestClashedPairRendersFirstSource(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "", `  - {user: alice, servers: ["@web"], options: [no-pty]}
  - {user: alice, servers: [web-1], options: [restrict]}
  - {user: op, servers: [web-1], options: [no-pty]}
`))
	if got, _ := grantOpts(t, cfg, 1, "web-1"); !slices.Equal(got, []string{"no-pty"}) {
		t.Errorf("alice on web-1 = %q, want access[0]'s [no-pty]", got)
	}
	if got, ok := grantOpts(t, cfg, 4, "web-1"); !ok || len(got) != 0 {
		t.Errorf("op on web-1 = %q (rendered %v), want the implicit grant's none", got, ok)
	}
	if n := len(clashesOf(cfg)); n != 2 {
		t.Errorf("clashes = %d, want 2 (alice, op)", n)
	}
}

// TestGrantExpiryWarns (P09's passed-expiry warning, plan gap 9): a grant's
// expiry-time= that has passed warns like a key line's, kind key_expired.
func TestGrantExpiryWarns(t *testing.T) {
	pinNow(t, time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))
	cfg := mustParse(t, grantFleet(t, "", "", `  - {user: bob, servers: [web-1], options: ['expiry-time="20990101"']}
  - {user: alice, servers: [web-1], options: ['expiry-time="20200101"']}
`))
	want := ManifestWarning{Kind: WarnKeyExpired, Message: `access[1]: expiry-time="20200101" has passed; sshd no longer accepts the keys this entry grants`}
	if !slices.Contains(cfg.ManifestWarnings, want) || len(cfg.ManifestWarnings) != 1 {
		t.Errorf("warnings = %+v, want exactly %+v", cfg.ManifestWarnings, want)
	}
}
