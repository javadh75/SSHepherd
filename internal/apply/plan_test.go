package apply

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeReader returns canned phase-1 results per server name.
type fakeReader struct {
	byName map[string]audit.ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (audit.ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return audit.ReadResult{}, err
	}
	return f.byName[srv.Name], nil
}

// buildPlans runs the real pipeline (audit.Run + Build) over a fake fleet —
// exactly what the command does, minus SSH.
func buildPlans(t *testing.T, cfg *config.Config, r audit.KeyReader, agentFPs []string) []ServerPlan {
	t.Helper()
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 4})
	plans, err := Build(cfg, results, agentFPs)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return plans
}

// planFor pulls one server's plan out by name.
func planFor(t *testing.T, plans []ServerPlan, name string) ServerPlan {
	t.Helper()
	for _, p := range plans {
		if p.Server.Name == name {
			return p
		}
	}
	t.Fatalf("no plan for %s", name)
	return ServerPlan{}
}

// fp is shorthand for a test key's fingerprint.
func fp(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("fp(%d): %v", seed, err)
	}
	return k.Fingerprint
}

// planCfg: op (operator, k1, comment op@sshepherd) everywhere; alice (k2,
// comment alice@work) -> web-1; bob (k3, no comment -> name floor) -> web-1.
func planCfg(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: op, operator: true, comment: "op@sshepherd", keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, comment: "alice@work", keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("planCfg: %v", err)
	}
	return cfg
}

// renderedFor renders a server's desired file exactly as Build does.
func renderedFor(t *testing.T, cfg *config.Config, name string) []byte {
	t.Helper()
	out, err := authkeys.Render(desiredEntries(cfg, name))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

func TestPlanConvergedIsByteExact(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: renderedFor(t, cfg, "web-1")},
	}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassConverged {
		t.Fatalf("Class = %s, want converged (bytes equal the render)", p.Class)
	}
}

func TestPlanAuditCleanIsNotApplyConverged(t *testing.T) {
	// Fingerprint-set equality is NOT convergence: same keys, but no managed
	// header and audit-style comments — the first apply normalizes it.
	cfg := planCfg(t)
	content := testkeys.Line(t, 1) + " op@sshepherd\n" + testkeys.Line(t, 2) + " alice@work\n" + testkeys.Line(t, 3) + " bob\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassChange {
		t.Fatalf("Class = %s, want change (byte drift: missing header)", p.Class)
	}
	if len(p.Add)+len(p.Remove)+len(p.Rewrites) != 0 {
		t.Errorf("rows = %d/%d/%d, want none (keys/comments/options all match)",
			len(p.Add), len(p.Remove), len(p.Rewrites))
	}
	if !p.Normalize.Whitespace {
		t.Errorf("Normalize = %+v, want the whitespace/format residual", p.Normalize)
	}
}

func TestPlanAddRemoveRewriteNormalize(t *testing.T) {
	cfg := planCfg(t)
	// On web-1: op present with the desired comment, bob present with a
	// stale comment (rewrite), alice missing (add), a stranger key
	// (remove), plus one hand comment and one blank line (normalize), and
	// bob listed before op (reorder).
	content := "# hand-written note\n" +
		testkeys.Line(t, 3) + " bob@old\n" +
		testkeys.Line(t, 1) + " op@sshepherd\n" +
		"\n" +
		testkeys.Line(t, 9) + " stray@laptop\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")

	if p.Class != ClassChange {
		t.Fatalf("Class = %s, want change", p.Class)
	}
	if len(p.Add) != 1 || p.Add[0].Fingerprint != fp(t, 2) {
		t.Errorf("Add = %+v, want exactly alice's key", p.Add)
	}
	if len(p.Remove) != 1 || p.Remove[0].Fingerprint != fp(t, 9) {
		t.Errorf("Remove = %+v, want exactly the stray key", p.Remove)
	}
	if len(p.Rewrites) != 1 {
		t.Fatalf("Rewrites = %+v, want one (bob's comment)", p.Rewrites)
	}
	rw := p.Rewrites[0]
	if !rw.CommentDiffers || rw.OptionsDiffer || rw.ActualComment != "bob@old" || rw.DesiredComment != "bob" {
		t.Errorf("rewrite = %+v, want comment bob@old -> bob (name floor)", rw)
	}
	if !p.Normalize.Reorder {
		t.Error("Normalize.Reorder = false, want true (bob before op on the server)")
	}
	if p.Normalize.NonKeyLines != 2 {
		t.Errorf("NonKeyLines = %d, want 2 (one comment + one blank)", p.Normalize.NonKeyLines)
	}
	if string(p.Rendered) != string(renderedFor(t, cfg, "web-1")) {
		t.Error("Rendered must be exactly the desired render — it is what phase 2 writes")
	}
}

func TestPlanRewriteOptions(t *testing.T) {
	cfg := planCfg(t)
	content := string(renderedFor(t, cfg, "web-1"))
	// Same file, but bob's line grew a no-pty option on the server.
	content = strings.Replace(content, testkeys.Line(t, 3), "no-pty "+testkeys.Line(t, 3), 1)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if len(p.Rewrites) != 1 || !p.Rewrites[0].OptionsDiffer || p.Rewrites[0].CommentDiffers {
		t.Fatalf("Rewrites = %+v, want exactly one options-only rewrite", p.Rewrites)
	}
}

func TestPlanFileAbsentIsAdditiveChange(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassChange || !p.FileAbsent {
		t.Fatalf("plan = %+v, want an additive change carrying the file-absent diagnostic", p)
	}
	if len(p.Add) != 3 || len(p.Remove) != 0 {
		t.Errorf("Add/Remove = %d/%d, want 3/0", len(p.Add), len(p.Remove))
	}
}

func TestPlanParseErrorRefused(t *testing.T) {
	cfg := planCfg(t)
	content := testkeys.Line(t, 1) + " op@sshepherd\nthis is not a key\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "unparseable") {
		t.Fatalf("plan = %+v, want refusal over the unparseable line", p)
	}
}

func TestPlanUnreachable(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{errs: map[string]error{"web-1": errors.New("dial tcp: connection refused")}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassUnreachable || p.Err == nil {
		t.Fatalf("plan = %+v, want unreachable with the error retained", p)
	}
}

// emptyDesiredCfg: a fleet with no operators and a grantless server.
func emptyDesiredCfg(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: bare, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("emptyDesiredCfg: %v", err)
	}
	return cfg
}

func TestPlanEmptyDesiredSplit(t *testing.T) {
	cfg := emptyDesiredCfg(t)
	web1 := renderedFor(t, cfg, "web-1")
	tests := []struct {
		name        string
		read        audit.ReadResult
		wantClass   Class
		wantRefusal string
	}{
		{"file absent is converged", audit.ReadResult{FileAbsent: true}, ClassConverged, ""},
		{"empty file is converged", audit.ReadResult{Content: []byte("")}, ClassConverged, ""},
		{"comments-only file is converged", audit.ReadResult{Content: []byte("# just notes\n")}, ClassConverged, ""},
		{"installed keys refuse the wipe", audit.ReadResult{Content: []byte(testkeys.Line(t, 9) + "\n" + testkeys.Line(t, 8) + "\n" + testkeys.Line(t, 7) + "\n")},
			ClassRefused, "3 keys installed but manifest grants none — refusing to wipe"},
		{"unparseable content refuses too", audit.ReadResult{Content: []byte("garbage\n")},
			ClassRefused, "unparseable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: web1}, "bare": tt.read}}
			p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 2)}), "bare")
			if p.Class != tt.wantClass {
				t.Fatalf("Class = %s, want %s", p.Class, tt.wantClass)
			}
			if tt.wantRefusal != "" && !strings.Contains(p.Refusal, tt.wantRefusal) {
				t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, tt.wantRefusal)
			}
		})
	}
}

func TestGuardRefusesLockout(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	// The agent holds only keys the manifest never grants to web-1. One
	// fingerprint is listed twice: the refusal must count distinct keys,
	// not raw listing entries.
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 9), fp(t, 8), fp(t, 9)}), "web-1")
	if p.Class != ClassRefused {
		t.Fatalf("Class = %s, want refused (predicted lockout)", p.Class)
	}
	for _, want := range []string{"none of the 2 keys in this agent", "lock this session out", "operator: true"} {
		if !strings.Contains(p.Refusal, want) {
			t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, want)
		}
	}
}

func TestGuardOperatorAlwaysPasses(t *testing.T) {
	// An operator key is in every desired set, so holding it passes the
	// guard on every server — the structural operator contract.
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassChange {
		t.Fatalf("Class = %s, want change (operator key held)", p.Class)
	}
}

func TestGuardRotateNoteSessionKeyRemoved(t *testing.T) {
	cfg := planCfg(t)
	// The session authenticated with stray key 9 (installed, not desired);
	// the agent also holds op's key, which survives — rotate is allowed,
	// loudly.
	content := testkeys.Line(t, 9) + " old@key\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(content), SessionKeyFP: fp(t, 9)},
	}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 9), fp(t, 1)}), "web-1")
	if p.Class != ClassChange {
		t.Fatalf("Class = %s, want change (op key survives)", p.Class)
	}
	if !strings.Contains(p.Note, "removes the key this session logged in with") ||
		!strings.Contains(p.Note, "op remains") {
		t.Errorf("Note = %q, want the rotate note naming the survivor", p.Note)
	}
}

func TestGuardNoNoteWhenSessionKeySurvives(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {FileAbsent: true, SessionKeyFP: fp(t, 1)},
	}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Note != "" {
		t.Errorf("Note = %q, want none (the session key stays desired)", p.Note)
	}
}

func TestGuardEmptyAgentFallback(t *testing.T) {
	cfg := planCfg(t)
	t.Run("additive-only write proceeds", func(t *testing.T) {
		r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
		p := planFor(t, buildPlans(t, cfg, r, nil), "web-1")
		if p.Class != ClassChange {
			t.Fatalf("Class = %s, want change (nothing removed)", p.Class)
		}
	})
	t.Run("removal is refused", func(t *testing.T) {
		r := &fakeReader{byName: map[string]audit.ReadResult{
			"web-1": {Content: []byte(testkeys.Line(t, 9) + "\n")},
		}}
		p := planFor(t, buildPlans(t, cfg, r, nil), "web-1")
		if p.Class != ClassRefused || !strings.Contains(p.Refusal, "agent key listing is unavailable") {
			t.Fatalf("plan = %+v, want the empty-listing refusal", p)
		}
	})
}

func TestGuardRestrictiveOptionsWarning(t *testing.T) {
	y := `
users:
  - {name: op, operator: true, keys: ["restrict,command=\"/usr/bin/false\" ` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	t.Run("all surviving keys restricted warns", func(t *testing.T) {
		p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
		if p.Class != ClassChange {
			t.Fatalf("Class = %s, want change (warning, not refusal)", p.Class)
		}
		if !strings.Contains(p.Warning, "restrictive option") {
			t.Errorf("Warning = %q, want the restrictive-options warning", p.Warning)
		}
	})
	t.Run("an unrestricted survivor clears the warning", func(t *testing.T) {
		p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1), fp(t, 2)}), "web-1")
		if p.Warning != "" {
			t.Errorf("Warning = %q, want none (alice's plain key survives too)", p.Warning)
		}
	})
}

func TestHasRestrictiveOption(t *testing.T) {
	tests := []struct {
		name    string
		options []string
		want    bool
	}{
		{"none", nil, false},
		{"benign", []string{"no-pty", "no-agent-forwarding"}, false},
		{"restrict", []string{"restrict"}, true},
		{"from", []string{`from="10.0.0.0/8"`}, true},
		{"command", []string{`command="/bin/true"`}, true},
		{"expiry", []string{`expiry-time="20270101"`}, true},
		{"case-insensitive", []string{`FROM="10.0.0.1"`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRestrictiveOption(tt.options); got != tt.want {
				t.Errorf("hasRestrictiveOption(%v) = %v, want %v", tt.options, got, tt.want)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	ch := func(o Outcome) ServerPlan { return ServerPlan{Class: ClassChange, Outcome: o} }
	tests := []struct {
		name  string
		plans []ServerPlan
		want  int
	}{
		{"empty fleet", nil, 0},
		{"all converged", []ServerPlan{{Class: ClassConverged}}, 0},
		{"applied counts as converged", []ServerPlan{{Class: ClassConverged}, ch(OutcomeApplied)}, 0},
		{"pending (dry-run/declined)", []ServerPlan{ch(OutcomePending)}, 1},
		{"failed", []ServerPlan{ch(OutcomeFailed)}, 1},
		{"refused late (symlink)", []ServerPlan{ch(OutcomeRefused)}, 1},
		{"refused in plan", []ServerPlan{{Class: ClassRefused}}, 1},
		{"unreachable", []ServerPlan{{Class: ClassUnreachable}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.plans); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}
