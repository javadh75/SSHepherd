package apply

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// filesReader serves every server the same file content; nobody is
// unreachable.
type filesReader map[string]string

func (f filesReader) ReadAuthorizedKeys(_ context.Context, s config.Server) (fleet.ReadResult, error) {
	return fleet.ReadResult{Content: []byte(f[s.Name])}, nil
}

// bastionPlans plans manifest y with every server's file empty, holding
// key 1 (agent).
func bastionPlans(t *testing.T, y string) (*config.Config, []ServerPlan) {
	t.Helper()
	return bastionPlansHolding(t, y, 1)
}

// bastionPlansHolding plans manifest y with every server's file empty,
// holding the numbered keys (agent).
func bastionPlansHolding(t *testing.T, y string, keys ...byte) (*config.Config, []ServerPlan) {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v\n%s", err, y)
	}
	results := audit.Run(context.Background(), cfg, filesReader{}, audit.Options{Parallel: 4})
	held := make([]fleet.HeldKey, 0, len(keys))
	for _, n := range keys {
		held = append(held, fleet.HeldKey{Fingerprint: testKey(t, n).Fingerprint, Source: fleet.SourceAgent})
	}
	plans, err := BuildWith(cfg, results, held, BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, plans
}

func planNamed(t *testing.T, plans []ServerPlan, name string) ServerPlan {
	t.Helper()
	for _, p := range plans {
		if p.Server.Name == name {
			return p
		}
	}
	t.Fatalf("no plan for %s", name)
	return ServerPlan{}
}

// bastionYAML: op (key 1, operator) with opts on its key line; a managed
// bastion-eu with web-1 and web-2 behind it.
func bastionYAML(t *testing.T, opts string) string {
	t.Helper()
	return "users:\n  - {name: op, operator: true, keys: ['" + opts + testkeys.Line(t, 1) + "']}\n" +
		"servers:\n  - {name: bastion-eu, host: bastion.example.com, user: jump}\n" +
		"  - {name: web-1, host: 10.0.1.5, user: deploy, via: bastion-eu}\n" +
		"  - {name: web-2, host: 10.0.1.6, user: deploy, via: bastion-eu}\n"
}

// onlyWeb2Refusal is the refusal for op's line when its permitopen= names
// web-1 alone: op's key is the first offered, and only web-2 is cut off.
func onlyWeb2Refusal(t *testing.T) string {
	t.Helper()
	return "the first key offered to bastion-eu (op, " + testKey(t, 1).Fingerprint + ") may not forward to every server behind it " +
		"(no-port-forwarding, restrict or permitopen=), and the login stops at that key; this write would cut off web-2" +
		" \u2014 lift its restriction or grant a key that may forward ahead of it"
}

// TestForwardGuard (spec S5 Guard): a managed bastion must keep forwarding
// to every dependent for a key this run holds.
func TestForwardGuard(t *testing.T) {
	const refusal = "none of the surviving keys you hold may forward through bastion-eu (no-port-forwarding, restrict or permitopen=); this write would cut off web-1 and 1 more"
	for _, tt := range []struct {
		name, opts string
		refused    bool
	}{
		{"a plain line", "", false},
		{"no-port-forwarding", "no-port-forwarding ", true},
		{"restrict", "restrict ", true},
		{"restrict with port-forwarding", "restrict,port-forwarding ", false},
		{"port-forwarding before restrict", "port-forwarding,restrict ", true}, // sshd applies options in order
		{"permitopen for one dependent only", `permitopen="10.0.1.5:22" `, true},
		{"permitopen for both", `permitopen="10.0.1.5:22",permitopen="10.0.1.6:22" `, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, plans := bastionPlans(t, bastionYAML(t, tt.opts))
			p := planNamed(t, plans, "bastion-eu")
			want := refusal
			if strings.HasPrefix(tt.opts, "permitopen") { // op may still reach web-1: only web-2 is cut off
				want = onlyWeb2Refusal(t)
			}
			switch {
			case tt.refused && (p.Class != ClassRefused || p.Refusal != want):
				t.Errorf("bastion plan = %s %q, want refused with %q", p.Class, p.Refusal, want)
			case !tt.refused && p.Class != ClassChange:
				t.Errorf("bastion plan = %s %q, want a change", p.Class, p.Refusal)
			}
			if w := planNamed(t, plans, "web-1"); w.Class != ClassChange {
				t.Errorf("web-1 = %s %q: a dependent has no forwarding guard", w.Class, w.Refusal)
			}
		})
	}
}

// TestForwardGuardJudgesOnlyHeldKeys: a forwarding key this run does not
// hold cannot carry its writes through the bastion, so it does not satisfy
// the guard next to a held key that cannot forward.
func TestForwardGuardJudgesOnlyHeldKeys(t *testing.T) {
	const refusal = "none of the surviving keys you hold may forward through bastion-eu (no-port-forwarding, restrict or permitopen=); this write would cut off web-1 and 1 more"
	y := strings.Replace(bastionYAML(t, "restrict "), "users:\n",
		"users:\n  - {name: ci, operator: true, keys: ['"+testkeys.Line(t, 2)+"']}\n", 1)
	_, plans := bastionPlans(t, y) // holds key 1 only
	if p := planNamed(t, plans, "bastion-eu"); p.Class != ClassRefused || p.Refusal != refusal {
		t.Errorf("bastion plan = %s %q, want refused with %q", p.Class, p.Refusal, refusal)
	}
}

// twoOperators: op (key 1) and ci (key 2), both operators, each with its own
// options, on a managed bastion-eu with web-1 and web-2 behind it. op's key
// comes first in manifest order.
func twoOperators(t *testing.T, opOpts, ciOpts string) string {
	t.Helper()
	return "users:\n  - {name: op, operator: true, keys: ['" + opOpts + testkeys.Line(t, 1) + "']}\n" +
		"  - {name: ci, operator: true, keys: ['" + ciOpts + testkeys.Line(t, 2) + "']}\n" +
		"servers:\n  - {name: bastion-eu, host: bastion.example.com, user: jump}\n" +
		"  - {name: web-1, host: 10.0.1.5, user: deploy, via: bastion-eu}\n" +
		"  - {name: web-2, host: 10.0.1.6, user: deploy, via: bastion-eu}\n"
}

// TestForwardGuardJudgesFirstOfferedKey (F007, owner answer a): sshd stops
// at the first key that verifies, so the hop logs in with the first surviving
// key in authkeys.OfferOrder and a later key that may forward cannot help.
func TestForwardGuardJudgesFirstOfferedKey(t *testing.T) {
	const onlyWeb1 = `permitopen="10.0.1.5:22" `
	firstKeyRefusal := func(owner string, key byte, cut string) string {
		return "the first key offered to bastion-eu (" + owner + ", " + testKey(t, key).Fingerprint + ") may not forward to every server behind it " +
			"(no-port-forwarding, restrict or permitopen=), and the login stops at that key; this write would cut off " + cut +
			" \u2014 lift its restriction or grant a key that may forward ahead of it"
	}
	const noneRefusal = "none of the surviving keys you hold may forward through bastion-eu (no-port-forwarding, restrict or permitopen=); this write would cut off web-1 and 1 more"
	for _, tt := range []struct {
		name, op, ci string
		held         []byte
		want         string // "" = a change
	}{
		{name: "the report's repro: the first key reaches web-1 only, the second is plain", op: onlyWeb1, held: []byte{1, 2}, want: firstKeyRefusal("op", 1, "web-2")},
		{name: "the first key may not forward at all", op: "no-port-forwarding ", held: []byte{1, 2}, want: firstKeyRefusal("op", 1, "web-1 and 1 more")},
		{name: "a first key that forwards to both passes, whatever the second may do", ci: "no-port-forwarding ", held: []byte{1, 2}},
		{name: "a first key whose permitopen names both passes", op: `permitopen="10.0.1.5:22",permitopen="10.0.1.6:22" `, held: []byte{1, 2}},
		{name: "offer order, not manifest order: a plain key outranks an earlier from= line", op: `from="10.0.0.1",permitopen="10.0.1.5:22" `, held: []byte{1, 2}},
		{name: "offer order, not manifest order: a from= line loses to the restricted plain one", op: `from="10.0.0.1" `, ci: onlyWeb1, held: []byte{1, 2}, want: firstKeyRefusal("ci", 2, "web-2")},
		{name: "a key this run does not hold is not the first offered", op: "no-port-forwarding ", held: []byte{2}},
		// The general text is kept for when it is true: op may forward to
		// web-1, so only web-2 is cut off, and the first key is named.
		{name: "no survivor forwards to both: the first key's refusal names what it cuts off", op: onlyWeb1, ci: "restrict ", held: []byte{1, 2}, want: firstKeyRefusal("op", 1, "web-2")},
		{name: "no survivor forwards anywhere: the general refusal", op: "no-port-forwarding ", ci: "restrict ", held: []byte{1, 2}, want: noneRefusal},
		{name: "a later key that forwards to one dependent: the first key's refusal", op: "no-port-forwarding ", ci: onlyWeb1, held: []byte{1, 2}, want: firstKeyRefusal("op", 1, "web-1 and 1 more")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, plans := bastionPlansHolding(t, twoOperators(t, tt.op, tt.ci), tt.held...)
			p := planNamed(t, plans, "bastion-eu")
			if tt.want == "" {
				if p.Class != ClassChange {
					t.Fatalf("bastion plan = %s %q, want a change", p.Class, p.Refusal)
				}
				return
			}
			if p.Class != ClassRefused || p.Refusal != tt.want {
				t.Fatalf("bastion plan = %s\n got %q\nwant %q", p.Class, p.Refusal, tt.want)
			}
		})
	}
}

// TestPlanSetsProbeForward: a bastion's write probes a forward to every
// dependent, in manifest order; a server nothing goes through probes none.
func TestPlanSetsProbeForward(t *testing.T) {
	_, plans := bastionPlans(t, bastionYAML(t, ""))
	want := []string{"10.0.1.5:22", "10.0.1.6:22"}
	if got := planNamed(t, plans, "bastion-eu").ProbeForward; !slices.Equal(got, want) {
		t.Errorf("bastion ProbeForward = %q, want %q", got, want)
	}
	if got := planNamed(t, plans, "web-1").ProbeForward; len(got) != 0 {
		t.Errorf("web-1 ProbeForward = %q, want none", got)
	}
}

// TestPlanProbeForwardCarriesPorts: the probe forwards to each dependent's
// own port, and brackets an IPv6 host, as the bastion will be asked for it.
func TestPlanProbeForwardCarriesPorts(t *testing.T) {
	y := strings.Replace(bastionYAML(t, ""), "{name: web-2, host: 10.0.1.6, user: deploy, via: bastion-eu}",
		"{name: web-2, host: 10.0.1.6, port: 2222, user: deploy, via: bastion-eu}", 1)
	y += "  - {name: web-3, host: \"fd00::5\", port: 2200, user: deploy, via: bastion-eu}\n"
	_, plans := bastionPlans(t, y)
	want := []string{"10.0.1.5:22", "10.0.1.6:2222", "[fd00::5]:2200"}
	if got := planNamed(t, plans, "bastion-eu").ProbeForward; !slices.Equal(got, want) {
		t.Errorf("bastion ProbeForward = %q, want %q", got, want)
	}
}

// TestPlanJumpOnly: a jump_only server is its own class, never guarded,
// never probed, and never changes the exit code.
func TestPlanJumpOnly(t *testing.T) {
	y := strings.Replace(bastionYAML(t, "no-port-forwarding "), "user: jump}", "user: jump, jump_only: true}", 1)
	_, plans := bastionPlans(t, y)
	p := planNamed(t, plans, "bastion-eu")
	if p.Class != ClassJumpOnly || p.Refusal != "" || len(p.ProbeForward) != 0 {
		t.Errorf("bastion plan = %+v, want class jump_only with nothing else", p)
	}
	for i := range plans {
		if plans[i].Class == ClassChange {
			plans[i].Outcome = OutcomeApplied
		}
	}
	if code := ExitCode(plans); code != 0 {
		t.Errorf("ExitCode = %d, want 0 with the dependents applied", code)
	}
}

// hopAlarm is a host-key alarm at a bastion (apply cannot import sshconn).
type hopAlarm struct{ hop string }

func (e hopAlarm) Error() string              { return "via " + e.hop + ": host key changed" }
func (e hopAlarm) ErrorKind() fleet.ErrorKind { return fleet.ErrorKindHostKeyChanged }
func (e hopAlarm) FailedHop() string          { return e.hop }

// TestNeedsHumanIgnoresBastionHostKey: an UNPROVEN login check stopped by
// a bastion's host-key alarm is exit 1; the server's own is still 2 (D10b).
func TestNeedsHumanIgnoresBastionHostKey(t *testing.T) {
	unproven := func(last error) []ServerPlan {
		return []ServerPlan{{Class: ClassChange, Outcome: OutcomeUnproven, OutcomeErr: &fleet.UnprovenError{Attempts: 1, HostKey: true, Last: last}}}
	}
	if code := ExitCode(unproven(hopAlarm{"bastion-eu"})); code != 1 {
		t.Errorf("bastion alarm: ExitCode = %d, want 1", code)
	}
	if code := ExitCode(unproven(hopAlarm{""})); code != 2 {
		t.Errorf("the server's own alarm: ExitCode = %d, want 2", code)
	}
}

// hopDown is a bastion that stopped answering during the login check.
type hopDown struct{ hop string }

func (e hopDown) Error() string              { return "via " + e.hop + ": connection refused" }
func (e hopDown) ErrorKind() fleet.ErrorKind { return fleet.ErrorKindDial }
func (e hopDown) FailedHop() string          { return e.hop }

// TestHopDeathInProbeIsExit1 (spec S5: "no restore, exit 1, never
// lockout_unrestored"): an UNPROVEN login check whose last failure was the
// bastion going away is exit 1. It pins P08 behaviour the S5 change must
// keep; sshwrite's TestProbeHopDeathIsUnproven proves the writer returns
// exactly this shape (UNPROVEN, no LockoutError, file kept).
func TestHopDeathInProbeIsExit1(t *testing.T) {
	plans := []ServerPlan{{Class: ClassChange, Outcome: OutcomeUnproven,
		OutcomeErr: &fleet.UnprovenError{Attempts: 4, Last: hopDown{"b"}}}}
	if code := ExitCode(plans); code != 1 {
		t.Errorf("ExitCode = %d, want 1", code)
	}
}

// TestRenderBastionGoldens: the jump only row and summary segment, the via
// head, JSON class jump_only with outcome null, via, summary.jump_only; and
// the forwarding refusal.
func TestRenderBastionGoldens(t *testing.T) {
	y := strings.Replace(bastionYAML(t, ""), "user: jump}", "user: jump, jump_only: true}", 1)
	cfg, plans := bastionPlans(t, y)
	var text, js bytes.Buffer
	Render(&text, cfg, plans, RenderOptions{})
	RenderSummary(&text, cfg, plans, RenderOptions{})
	checkGolden(t, "plan_jump_only.golden", text.Bytes())
	if err := RenderJSON(&js, cfg, plans, JSONOptions{Command: "apply", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_jump_only.golden.json", js.Bytes())

	cfg, plans = bastionPlans(t, bastionYAML(t, "no-port-forwarding "))
	text.Reset()
	Render(&text, cfg, plans, RenderOptions{})
	RenderSummary(&text, cfg, plans, RenderOptions{})
	checkGolden(t, "plan_forward_refused.golden", text.Bytes())

	// via_failed: an unreachable server's phase-1 read and a change whose
	// login check stopped at the bastion both name it.
	cfg, _ = bastionPlans(t, y)
	web1, _ := cfg.ServerNamed("web-1")
	web2, _ := cfg.ServerNamed("web-2")
	failed := []ServerPlan{
		{Server: web1, Class: ClassUnreachable, Err: hopAlarm{"bastion-eu"}},
		{Server: web2, Class: ClassChange, Outcome: OutcomeUnproven,
			OutcomeErr: &fleet.UnprovenError{Attempts: 4, Last: fmt.Errorf("login check: %w", hopDown{"bastion-eu"})}},
	}
	js.Reset()
	if err := RenderJSON(&js, cfg, failed, JSONOptions{Command: "apply"}); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_via_failed.golden.json", js.Bytes())
	if n := strings.Count(js.String(), `"via_failed": "bastion-eu"`); n != 2 {
		t.Errorf("via_failed appears %d times, want on both servers:\n%s", n, js.String())
	}
}
