package apply

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// clashText is the restriction conflict clashCfg holds (spec S7 wording).
const clashText = `user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[1] with no options; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user`

// clashCfg (spec S7): op (k1, operator, held); alice (k2) is granted @web
// with no-pty and web-1 again with none, a restriction conflict on web-1
// only. extra is appended verbatim (a revoked: section).
func clashCfg(t *testing.T, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
access:
  - {user: alice, servers: ["@web"], options: [no-pty]}
  - {user: alice, servers: [web-1]}
` + extra))
	if err != nil {
		t.Fatalf("clashCfg: %v", err)
	}
	return cfg
}

// opOnly serves the operator's key alone on both servers.
func opOnly(t *testing.T) *fakeReader {
	t.Helper()
	body := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n")}
	return &fakeReader{byName: map[string]fleet.ReadResult{"web-1": body, "web-2": body}}
}

// TestClashRefusesOnlyItsServers (spec S7 apply row, OP6): web-1 is refused
// with the conflict text and is save-neutral; web-2 is planned.
func TestClashRefusesOnlyItsServers(t *testing.T) {
	plans := buildPlans(t, clashCfg(t, ""), opOnly(t), []string{fp(t, 1)})
	p := planFor(t, plans, "web-1")
	if p.Class != ClassRefused || p.Refusal != clashText || !p.ClashRefused || p.WeakRefused {
		t.Errorf("web-1 = %s %q clash=%v weak=%v", p.Class, p.Refusal, p.ClashRefused, p.WeakRefused)
	}
	if q := planFor(t, plans, "web-2"); q.Class != ClassChange {
		t.Errorf("web-2 = %s %q, want a change", q.Class, q.Refusal)
	}
	if NothingCanLand([]ServerPlan{p}) {
		t.Error("a clash alone withholds an edit's save; OP6 says revoke and rotate still save")
	}
}

// TestRevokedKindOutranksClash: a server that a revoked-kind conflict and a
// clash both name is refused by the revoked kind, which still withholds a
// save, exactly as before S7. It pins today's precedence and bites only
// under mutant W3.
func TestRevokedKindOutranksClash(t *testing.T) {
	cfg := clashCfg(t, "revoked:\n  - {user: alice, servers: [web-1], date: 2026-11-10}\n")
	p := planFor(t, buildPlans(t, cfg, opOnly(t), []string{fp(t, 1)}), "web-1")
	if p.Class != ClassRefused || p.ClashRefused || !strings.Contains(p.Refusal, "revoked[0] removed that access") {
		t.Errorf("web-1 = %s %q clash=%v", p.Class, p.Refusal, p.ClashRefused)
	}
}

// TestRenderGrantOptionsGolden (spec S7 Render): a group grant restricts its
// members on web-1, alice's own web-2 grant adds nothing to her key line's
// option, and bob's db-1 grant restricts him there; the operator's implicit
// grant adds none.
func TestRenderGrantOptionsGolden(t *testing.T) {
	got := renderFleet(t, `users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: alice, keys: ['no-agent-forwarding `+testkeys.Line(t, 2)+`']}
  - {name: bob, keys: ["`+testkeys.Line(t, 3)+`"]}
groups:
  - {name: team, members: [alice, bob]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  - {group: team, servers: ["@web"], except: [web-2], options: ['from="10.0.0.0/8"', no-pty]}
  - {user: alice, servers: [web-2]}
  - {user: bob, servers: [db-1], options: [restrict, 'permitopen="db:5432"']}
`)
	for server, line := range map[string]string{
		"web-1": `no-agent-forwarding,from="10.0.0.0/8",no-pty ` + testkeys.Line(t, 2) + " alice",
		"web-2": "no-agent-forwarding " + testkeys.Line(t, 2) + " alice",
		"db-1":  `restrict,permitopen="db:5432" ` + testkeys.Line(t, 3) + " bob",
	} {
		if block := fleetBlock(t, got, server); !strings.Contains(block, line+"\n") {
			t.Errorf("%s lacks %q:\n%s", server, line, block)
		}
	}
	checkGolden(t, "render_grant_options.golden", got)
}

// TestGrantOptionsForwardGuard (spec S7 Tests, with S5's guard): a grant
// restriction on the held operator key at a managed bastion is judged like
// a key-line one; a restriction on the dependents is not.
func TestGrantOptionsForwardGuard(t *testing.T) {
	const refusal = "none of the surviving keys you hold may forward through bastion-eu (no-port-forwarding, restrict or permitopen=); this write would cut off web-1 and 1 more"
	for _, tt := range []struct {
		name, opts string
		refused    bool
	}{
		{"no-port-forwarding", "no-port-forwarding", true},
		{"restrict", "restrict", true},
		{"permitopen for one dependent only", `'permitopen="10.0.1.5:22"'`, true},
		{"no-pty", "no-pty", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			y := bastionYAML(t, "") + "access:\n  - {user: op, servers: [\"*\"], except: [bastion-eu]}\n" +
				"  - {user: op, servers: [bastion-eu], options: [" + tt.opts + "]}\n"
			_, plans := bastionPlans(t, y)
			p := planNamed(t, plans, "bastion-eu")
			switch {
			case tt.refused && (p.Class != ClassRefused || p.Refusal != refusal):
				t.Errorf("bastion plan = %s %q, want refused with %q", p.Class, p.Refusal, refusal)
			case !tt.refused && p.Class != ClassChange:
				t.Errorf("bastion plan = %s %q, want a change", p.Class, p.Refusal)
			}
			if w := planNamed(t, plans, "web-1"); w.Class != ClassChange {
				t.Errorf("web-1 = %s %q", w.Class, w.Refusal)
			}
		})
	}
}

// TestGrantRestrictionKeepsGuardSurvivor (plan gap 12): a grant cannot add
// cert-authority, so a restricted held key still survives the lockout guard;
// the guard warns that every surviving key is restricted, and the rewrite
// narrows (no Loosens).
func TestGrantRestrictionKeepsGuardSurvivor(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: op, servers: ["*"], options: [restrict]}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(testkeys.Line(t, 1) + " op\n")}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassChange || !strings.HasPrefix(p.Warning, "every remaining key you hold carries a restrictive option") {
		t.Errorf("plan = %s %q warning %q", p.Class, p.Refusal, p.Warning)
	}
	if len(p.Rewrites) != 1 || !p.Rewrites[0].OptionsDiffer || len(p.Rewrites[0].Loosens)+len(p.Rewrites[0].Widens) != 0 {
		t.Errorf("rewrites = %+v, want one narrowing options row", p.Rewrites)
	}
}

// TestAffectedFollowsGrantOptions (spec S7 Tests): an edit that changes only
// a grant's options affects exactly the servers that grant reaches.
func TestAffectedFollowsGrantOptions(t *testing.T) {
	manifest := func(opts string) *config.Config {
		cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]` + opts + `}
  - {user: alice, servers: [web-2]}
`))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	if got := Affected(manifest(", options: [no-pty]"), manifest("")); !slices.Equal(got.Servers, []string{"web-1"}) {
		t.Errorf("Affected = %v, want [web-1]", got.Servers)
	}
}

// TestRewriteFlagsDroppedGrantOption (spec S7 Render): dropping a grant's
// restriction on one server is a loosening rewrite there and nowhere else.
func TestRewriteFlagsDroppedGrantOption(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: alice, servers: [web-2], options: [no-pty]}
`))
	if err != nil {
		t.Fatal(err)
	}
	body := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + " op\nno-pty " + testkeys.Line(t, 2) + " alice\n")}
	plans := buildPlans(t, cfg, &fakeReader{byName: map[string]fleet.ReadResult{"web-1": body, "web-2": body}}, []string{fp(t, 1)})
	if rows := planFor(t, plans, "web-1").Rewrites; len(rows) != 1 || !slices.Equal(rows[0].Loosens, []string{"no-pty"}) {
		t.Errorf("web-1 rewrites = %+v, want alice losing no-pty", rows)
	}
	if rows := planFor(t, plans, "web-2").Rewrites; len(rows) != 0 {
		t.Errorf("web-2 rewrites = %+v, want none (its grant keeps no-pty)", rows)
	}
}

// TestGrantOptionsNeverTouchKeptLines (spec S7 with S6): a restricted grant
// on a preserve: server changes the desired line only; the kept line is
// written back verbatim under the marker.
func TestGrantOptionsNeverTouchKeptLines(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: gitea, host: g.example.com, user: git, preserve: [{command: 'gitea serv key-[0-9]+'}]}
access:
  - {user: alice, servers: [gitea], options: [no-pty]}
`))
	if err != nil {
		t.Fatal(err)
	}
	kept := `command="gitea serv key-7" ` + testkeys.Line(t, 9) + " git@laptop"
	r := &fakeReader{byName: map[string]fleet.ReadResult{"gitea": {Content: []byte(testkeys.Line(t, 2) + "\n" + kept + "\n")}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 2)}), "gitea")
	want := authkeys.ManagedHeader + "\nno-pty " + testkeys.Line(t, 2) + " alice\n" + authkeys.PreserveMarker + "\n" + kept + "\n"
	if p.Class != ClassChange || string(p.Rendered) != want {
		t.Errorf("plan = %s %q, rendered:\n%s\nwant:\n%s", p.Class, p.Refusal, p.Rendered, want)
	}
}

// TestPlanRestrictionConflictGolden (spec S7 apply row): the plan report's
// REFUSED row carries the conflict text; web-2 is planned.
func TestPlanRestrictionConflictGolden(t *testing.T) {
	cfg := clashCfg(t, "")
	plans := buildPlans(t, cfg, opOnly(t), []string{fp(t, 1)})
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	if !strings.Contains(buf.String(), "REFUSED: "+clashText) {
		t.Errorf("no REFUSED row with the conflict:\n%s", buf.String())
	}
	checkGolden(t, "plan_restriction_conflict.golden", buf.Bytes())
}
