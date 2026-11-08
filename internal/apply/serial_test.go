package apply

import (
	"context"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// serialCfg: serial 7; op (k1, operator) everywhere; alice (k2) -> web-1.
func serialCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`))
	if err != nil {
		t.Fatalf("serialCfg: %v", err)
	}
	return cfg
}

// web1Body is web-1's rendered body (everything after the header line).
func web1Body(t *testing.T, cfg *config.Config) string {
	t.Helper()
	return string(bodyOf(renderedFor(t, cfg, "web-1")))
}

// planWeb1 plans web-1 holding content, with op's key held by the agent.
func planWeb1(t *testing.T, cfg *config.Config, content string, keys2, bumped bool) ServerPlan {
	t.Helper()
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(content), AuthorizedKeys2: keys2}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{Bumped: bumped})
	if err != nil {
		t.Fatalf("BuildWith: %v", err)
	}
	return planFor(t, plans, "web-1")
}

func TestMaxSerialBoundsAgree(t *testing.T) {
	if config.MaxSerial != authkeys.MaxHeaderSerial {
		t.Fatalf("config.MaxSerial %d != authkeys.MaxHeaderSerial %d", uint64(config.MaxSerial), uint64(authkeys.MaxHeaderSerial))
	}
}

func TestPlanEqualSerialConverged(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg), false, true)
	if p.Class != ClassConverged || p.Serial != (SerialPlan{Header: 7, Manifest: 7, Writes: 7, Case: SerialEqual}) || p.SerialNote != "" {
		t.Fatalf("plan = %+v", p)
	}
}

// TestBuildWithZeroOptionsIsPlainApply: BuildOptions{} is a plain apply —
// an older equal-body server stays converged (no header-only write).
func TestBuildWithZeroOptionsIsPlainApply(t *testing.T) {
	cfg := serialCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(authkeys.Header(6) + "\n" + web1Body(t, cfg))}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{})
	if err != nil || plans[0].Class != ClassConverged || !strings.Contains(string(plans[0].Serial.Case), "older") {
		t.Fatalf("BuildWith(…, BuildOptions{}) = %+v, %v; want the plain-apply (not bumped) verdict", plans, err)
	}
}

func TestPlanRefusesNewerServerSerial(t *testing.T) {
	cfg := serialCfg(t)
	// alice's key is not on the server: this manifest's render would add it.
	p := planWeb1(t, cfg, authkeys.Header(8)+"\n"+testkeys.Line(t, 1)+" op\n", false, false)
	want := "written by manifest serial 8, this manifest is 7 — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: 8 in your manifest (this is the only override)"
	if p.Class != ClassRefused || p.Refusal != want || p.Serial.Case != SerialNewerRefused {
		t.Fatalf("plan = %+v\nwant refusal %q", p, want)
	}
}

// TestPlanRemovalOnlyProceedsOnNewerSerial: removing a stranger's key from
// a server a newer manifest wrote proceeds, and the header keeps S (8), so
// the write never lowers the server's serial.
func TestPlanRemovalOnlyProceedsOnNewerSerial(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(8)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	if p.Class != ClassChange || p.Serial.Case != SerialNewerRemovalOnly || p.Serial.Writes != 8 || len(p.Remove) != 1 {
		t.Fatalf("plan = %+v", p)
	}
	if want := authkeys.Header(8) + "\n" + web1Body(t, cfg); string(p.Rendered) != want {
		t.Errorf("Rendered = %q\nwant %q (header keeps serial 8)", p.Rendered, want)
	}
	if p.SerialNote != "written by newer manifest serial 8; this write only removes keys, so it proceeds" {
		t.Errorf("SerialNote = %q", p.SerialNote)
	}
	// A comment-only difference is still removal-only.
	c := authkeys.Header(8) + "\n" + testkeys.Line(t, 1) + " op\n" + testkeys.Line(t, 2) + " alice@laptop\n"
	if p := planWeb1(t, cfg, c, false, false); p.Class != ClassChange || p.Serial.Case != SerialNewerRemovalOnly {
		t.Errorf("comment rewrite on a newer server = %+v, want removal-only", p)
	}
}

func TestPlanRemovalOnlyRejectsLoosenedOptions(t *testing.T) {
	cfg := serialCfg(t)
	// The server restricts alice's key; this manifest's line has no from=:
	// writing it would loosen access, which is a grant.
	c := authkeys.Header(8) + "\n" + testkeys.Line(t, 1) + " op\n" + `from="10.0.0.0/8" ` + testkeys.Line(t, 2) + " alice\n"
	if p := planWeb1(t, cfg, c, false, false); p.Class != ClassRefused || p.Serial.Case != SerialNewerRefused {
		t.Fatalf("plan = %+v, want the stale-serial refusal", p)
	}
}

func TestPlanNewerSerialSameBodyConvergedWithNote(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(8)+"\n"+web1Body(t, cfg), false, false)
	if p.Class != ClassConverged || p.Serial.Case != SerialNewerConverged ||
		p.SerialNote != "written by newer manifest serial 8 (yours is 7): pull the latest manifest" {
		t.Fatalf("plan = %+v", p)
	}
	// A non-empty authorized_keys2 to move aside turns row 2 into row 3.
	k2 := planWeb1(t, cfg, authkeys.Header(8)+"\n"+web1Body(t, cfg), true, false)
	if k2.Class != ClassChange || !k2.DisableKeys2() || k2.Serial.Case != SerialNewerRemovalOnly || k2.Serial.Writes != 8 {
		t.Fatalf("with authorized_keys2: %+v", k2)
	}
}

// TestPlanForgedSerialTreatedAsNone: S > M+1000 is forged, in any run: a
// header-only write carrying M when the bodies match, an ordinary change
// otherwise. A forged header never blocks a write.
func TestPlanForgedSerialTreatedAsNone(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(1008)+"\n"+web1Body(t, cfg), false, false)
	if p.Class != ClassChange || !p.HeaderOnly || p.Serial.Case != SerialForged || p.Serial.Writes != 7 ||
		p.SerialNote != "header claims serial 1008, far above this manifest's 7 — treated as no serial" {
		t.Fatalf("plan = %+v", p)
	}
	q := planWeb1(t, cfg, authkeys.Header(1008)+"\n"+testkeys.Line(t, 1)+" op\n", false, false)
	if q.Class != ClassChange || q.HeaderOnly || len(q.Add) != 1 || !strings.HasPrefix(string(q.Rendered), authkeys.Header(7)+"\n") {
		t.Fatalf("forged with a missing key = %+v", q)
	}
	if b := planWeb1(t, cfg, authkeys.Header(1007)+"\n"+web1Body(t, cfg), false, false); b.Class != ClassConverged || b.Serial.Case != SerialNewerConverged {
		t.Errorf("M+1000 is still a real newer serial: %+v", b)
	}
}

// TestPlanHeaderOnlyWriteOnAffectedOlderSerial (replaces
// TestPlanConvergedOnOlderSerialSameBody — the W0 verifier's PRD-2 hole):
// in a bumped run, an affected server whose keys already match and whose
// header is older (a (serial S) or the legacy header) gets a header-only
// write carrying M.
func TestPlanHeaderOnlyWriteOnAffectedOlderSerial(t *testing.T) {
	cfg := serialCfg(t)
	for _, first := range []string{authkeys.Header(6), authkeys.ManagedHeader} {
		p := planWeb1(t, cfg, first+"\n"+web1Body(t, cfg), false, true)
		if p.Class != ClassChange || !p.HeaderOnly || p.Serial.Case != SerialHeaderOnly || p.Serial.Writes != 7 {
			t.Fatalf("%q: plan = %+v", first, p)
		}
		if len(p.Add)+len(p.Remove)+len(p.Rewrites) != 0 || p.Normalize.Any() {
			t.Errorf("%q: a header-only plan has key rows: %+v", first, p)
		}
		if want := authkeys.Header(7) + "\n" + web1Body(t, cfg); string(p.Rendered) != want {
			t.Errorf("%q: Rendered = %q\nwant the server's bytes with line 1 replaced: %q", first, p.Rendered, want)
		}
	}
}

func TestPlanOlderSerialSameBodyConvergedWithoutBump(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.Header(6)+"\n"+web1Body(t, cfg), false, false)
	if p.Class != ClassConverged || p.HeaderOnly || p.Serial.Case != SerialOlder {
		t.Fatalf("plain apply over an older equal-body server = %+v, want converged", p)
	}
}

// TestPlanHeaderOnlyRefusedByGuard: the lockout guard judges a header-only
// write like any write.
func TestPlanHeaderOnlyRefusedByGuard(t *testing.T) {
	cfg := serialCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(authkeys.Header(6) + "\n" + web1Body(t, cfg))}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 9)), BuildOptions{Bumped: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := plans[0]; p.Class != ClassRefused || !strings.Contains(p.Refusal, "lock this session out") {
		t.Fatalf("plan = %+v, want the guard's refusal", p)
	}
}

// TestPlanRefusesConflictServers: a revoked key still listed refuses every
// server it would render on, with the conflict message; the rest of the
// fleet is planned normally.
func TestPlanRefusesConflictServers(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
revoked:
  - {fingerprint: ` + fp(t, 2) + `, user: alice, date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	plans := buildPlans(t, cfg, r, []string{fp(t, 1)})
	w1, w2 := planFor(t, plans, "web-1"), planFor(t, plans, "web-2")
	if w1.Class != ClassRefused || w1.Refusal != cfg.Conflicts()[0].Message {
		t.Errorf("web-1 = %+v, want the conflict refusal %q", w1, cfg.Conflicts()[0].Message)
	}
	if w2.Class != ClassChange {
		t.Errorf("web-2 = %+v, want an ordinary change", w2)
	}
}
