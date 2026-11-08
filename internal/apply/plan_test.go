package apply

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeReader returns canned phase-1 results per server name.
type fakeReader struct {
	byName map[string]fleet.ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (fleet.ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return fleet.ReadResult{}, err
	}
	return f.byName[srv.Name], nil
}

// buildPlans runs the real pipeline (audit.Run + Build) over a fake fleet —
// exactly what the command does, minus SSH — with agentFPs held by the
// agent.
func buildPlans(t *testing.T, cfg *config.Config, r audit.KeyReader, agentFPs []string) []ServerPlan {
	t.Helper()
	return buildPlansHeld(t, cfg, r, agentHeld(agentFPs...))
}

// buildPlansHeld is buildPlans with an explicit held set (any sources).
func buildPlansHeld(t *testing.T, cfg *config.Config, r audit.KeyReader, held []fleet.HeldKey) []ServerPlan {
	t.Helper()
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 4})
	plans, err := BuildWith(cfg, results, held, BuildOptions{})
	if err != nil {
		t.Fatalf("BuildWith: %v", err)
	}
	return plans
}

// agentHeld labels fingerprints as agent-held keys.
func agentHeld(fps ...string) []fleet.HeldKey {
	held := make([]fleet.HeldKey, 0, len(fps))
	for _, fp := range fps {
		held = append(held, fleet.HeldKey{Fingerprint: fp, Source: fleet.SourceAgent})
	}
	return held
}

// fileHeld labels a fingerprint as held through an --identity file.
func fileHeld(fp, path string) fleet.HeldKey {
	return fleet.HeldKey{Fingerprint: fp, Source: path}
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(content)}}}
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(content)}}}
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(content)}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if len(p.Rewrites) != 1 || !p.Rewrites[0].OptionsDiffer || p.Rewrites[0].CommentDiffers {
		t.Fatalf("Rewrites = %+v, want exactly one options-only rewrite", p.Rewrites)
	}
	if rw := p.Rewrites[0]; strings.Join(rw.ActualOptions, ",") != "no-pty" || len(rw.Loosens) != 1 || rw.Loosens[0] != "no-pty" {
		t.Errorf("rewrite = %+v, want the on-server options kept and no-pty flagged as a dropped restriction", rw)
	}
}

func TestPlanFileAbsentIsAdditiveChange(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(content)}}}
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
		read        fleet.ReadResult
		wantClass   Class
		wantRefusal string
	}{
		{"file absent is converged", fleet.ReadResult{FileAbsent: true}, ClassConverged, ""},
		{"empty file is converged", fleet.ReadResult{Content: []byte("")}, ClassConverged, ""},
		{"comments-only file is converged", fleet.ReadResult{Content: []byte("# just notes\n")}, ClassConverged, ""},
		{"installed keys refuse the wipe", fleet.ReadResult{Content: []byte(testkeys.Line(t, 9) + "\n" + testkeys.Line(t, 8) + "\n" + testkeys.Line(t, 7) + "\n")},
			ClassRefused, "3 keys installed but manifest grants none — refusing to wipe"},
		{"unparseable content refuses too", fleet.ReadResult{Content: []byte("garbage\n")},
			ClassRefused, "unparseable"},
		{"no keys but authorized_keys2 refuses (audit calls it drift)", fleet.ReadResult{FileAbsent: true, AuthorizedKeys2: true},
			ClassRefused, "authorized_keys2 holds keys but the manifest grants none — refusing to wipe; remove it by hand"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: web1}, "bare": tt.read}}
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

// TestApplyAuditAgreeOnKeys2WithoutGrants (COR-2): apply's exit code and
// audit's verdict agree for a no-grant server whose authorized_keys2 holds
// keys — both non-zero, and apply writes nothing (no wipe mode exists).
func TestApplyAuditAgreeOnKeys2WithoutGrants(t *testing.T) {
	cfg := emptyDesiredCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: renderedFor(t, cfg, "web-1")}, "bare": {FileAbsent: true, AuthorizedKeys2: true}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 2)), BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	p := planFor(t, plans, "bare")
	if p.Class != ClassRefused || p.DisableKeys2() || p.Rendered != nil {
		t.Fatalf("plan = %s (disable=%v), want a refusal that writes nothing", p.Class, p.DisableKeys2())
	}
	if ExitCode(plans) != 1 || audit.ExitCode(cfg, results) != 1 {
		t.Errorf("apply exit %d, audit exit %d; want both 1", ExitCode(plans), audit.ExitCode(cfg, results))
	}
}

func TestGuardRefusesLockout(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
	// The agent holds only keys the manifest never grants to web-1. One
	// fingerprint is listed twice: the refusal must count distinct keys,
	// not raw listing entries.
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 9), fp(t, 8), fp(t, 9)}), "web-1")
	if p.Class != ClassRefused {
		t.Fatalf("Class = %s, want refused (predicted lockout)", p.Class)
	}
	for _, want := range []string{"none of the 2 keys you hold (identity files + agent)", "lock this session out", "operator: true"} {
		if !strings.Contains(p.Refusal, want) {
			t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, want)
		}
	}
}

func TestGuardOperatorAlwaysPasses(t *testing.T) {
	// An operator key is in every desired set, so holding it passes the
	// guard on every server — the structural operator contract.
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {FileAbsent: true, SessionKeyFP: fp(t, 1)},
	}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Note != "" {
		t.Errorf("Note = %q, want none (the session key stays desired)", p.Note)
	}
}

func TestGuardEmptyAgentRefuses(t *testing.T) {
	// No agent keys: nothing could prove access survives (and the login
	// probe would have nothing to offer), so even an additive write is
	// refused — the old "additive writes may proceed" fallback is gone.
	cfg := planCfg(t)
	for name, read := range map[string]fleet.ReadResult{
		"additive-only": {FileAbsent: true},
		"removes a key": {Content: []byte(testkeys.Line(t, 9) + "\n")},
	} {
		t.Run(name, func(t *testing.T) {
			r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": read}}
			p := planFor(t, buildPlans(t, cfg, r, nil), "web-1")
			if p.Class != ClassRefused || !strings.Contains(p.Refusal, "you hold no plain keys") {
				t.Fatalf("plan = %s/%q, want the empty-agent refusal", p.Class, p.Refusal)
			}
		})
	}
}

func TestGuardCertAuthorityIsNotASurvivor(t *testing.T) {
	// The operator's only agent-held key is granted as a cert-authority
	// line: sshd accepts certificates it signed, never the bare key, so
	// this write would lock the session out.
	y := `
users:
  - {name: op, operator: true, keys: ["cert-authority,principals=\"ops\" ` + testkeys.Line(t, 1) + `"]}
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "cert-authority") {
		t.Fatalf("plan = %s/%q, want a lockout refusal naming the cert-authority line", p.Class, p.Refusal)
	}
	if got := Survivors(p.Desired, heldSet(agentHeld(fp(t, 1), fp(t, 2)))); len(got) != 1 || got[0].Fingerprint != fp(t, 2) {
		t.Errorf("Survivors = %v, want only alice's bare key", got)
	}
}

func TestPlanRefusesUnverifiableRenderSize(t *testing.T) {
	cfg := planCfg(t)
	saved := maxRender
	maxRender = 100 // the real cap is fleet.MaxRemoteOutput (1 MiB)
	t.Cleanup(func() { maxRender = saved })
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "could never be verified") {
		t.Fatalf("plan = %s/%q, want the size refusal", p.Class, p.Refusal)
	}
}

func TestPlanCarriesSnapshotAndKeys2(t *testing.T) {
	cfg := planCfg(t)
	content := []byte(testkeys.Line(t, 1) + "\n")
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: content, AuthorizedKeys2: true}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Expect != fleet.SnapshotOf(false, content) {
		t.Errorf("Expect = %+v, want the snapshot of the phase-1 bytes", p.Expect)
	}
	if !p.AuthorizedKeys2 {
		t.Error("AuthorizedKeys2 must carry the phase-1 finding into the plan")
	}
	r = &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
	if p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1"); !p.Expect.Absent {
		t.Errorf("Expect = %+v, want absent for a file-absent server", p.Expect)
	}
}

func TestPlanDuplicatesAreNamed(t *testing.T) {
	cfg := planCfg(t)
	base := string(renderedFor(t, cfg, "web-1"))
	tests := []struct {
		name        string
		extra       string
		wantDiffers bool
	}{
		{"identical copy", testkeys.Line(t, 3) + " bob\n", false},
		{"copy with its own options", `command="/bin/sh" ` + testkeys.Line(t, 3) + " bob\n", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(base + tt.extra)}}}
			p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
			if p.Class != ClassChange {
				t.Fatalf("Class = %s, want change", p.Class)
			}
			if p.Normalize.Duplicates != 1 || p.Normalize.DuplicateOptionsDiffer != tt.wantDiffers {
				t.Errorf("Normalize = %+v, want 1 duplicate (options differ: %v)", p.Normalize, tt.wantDiffers)
			}
			if p.Normalize.Whitespace {
				t.Error("a removed duplicate key line must not be reported as whitespace/format")
			}
		})
	}
}

// COR-4: FIDO options are classified by meaning, and added relaxations are seen.
func TestPlanRewriteLooseningByMeaning(t *testing.T) {
	tests := []struct {
		name, manifestOpts, serverOpts string
		wantLoosens, wantWidens        []string
	}{
		{"verify-required dropped", "", "verify-required ", []string{"verify-required"}, nil},
		{"no-touch-required dropped is tightening", "", "no-touch-required ", nil, nil},
		{"no-touch-required added", "no-touch-required ", "", nil, []string{"no-touch-required"}},
		{"port-forwarding added under restrict", "restrict,port-forwarding ", "restrict ", nil, []string{"port-forwarding"}},
		{"pty added without restrict is a no-op", "pty ", "", nil, nil},
		// A server line sshd ignores grants nothing today; the rewrite makes it live.
		{"server line sshd ignores (typo)", "", "no-ptty ", []string{"no-ptty"}, nil},
		{"server line sshd ignores (unknown)", "", "zzz ", []string{"zzz"}, nil},
		// permitopen= is a union: one more destination widens access.
		{"permitopen added beside existing", `permitopen=\"db:5432\",permitopen=\"*:*\" `, `permitopen="db:5432" `, nil, []string{`permitopen="*:*"`}},
		{"permitopen first one narrows", `permitopen=\"db:5432\" `, "", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.Parse([]byte(`
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + tt.manifestOpts + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
`))
			if err != nil {
				t.Fatalf("config: %v", err)
			}
			// Comments match the render, so bob's options are the only drift.
			content := testkeys.Line(t, 1) + " op\n" + tt.serverOpts + testkeys.Line(t, 3) + " bob\n"
			r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(content)}}}
			p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
			if len(p.Rewrites) != 1 {
				t.Fatalf("Rewrites = %+v, want bob's options rewrite", p.Rewrites)
			}
			rw := p.Rewrites[0]
			if strings.Join(rw.Loosens, "|") != strings.Join(tt.wantLoosens, "|") ||
				strings.Join(rw.Widens, "|") != strings.Join(tt.wantWidens, "|") {
				t.Errorf("Loosens=%q Widens=%q, want %q / %q", rw.Loosens, rw.Widens, tt.wantLoosens, tt.wantWidens)
			}
		})
	}
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
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
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
	unproven := func(kind fleet.ErrorKind) ServerPlan {
		return ServerPlan{Class: ClassChange, Outcome: OutcomeUnproven,
			OutcomeErr: &fleet.UnprovenError{Attempts: 1, Last: &hintedErr{kind: kind, err: errors.New("x")}}}
	}
	rolled := func(revoked ...string) ServerPlan {
		return ServerPlan{Class: ClassChange, Outcome: OutcomeFailed, RolledBack: true, RevokedRemovals: revoked}
	}
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
		{"lockout not restored", []ServerPlan{ch(OutcomeLockoutUnrestored)}, 2},
		{"applied plus lockout", []ServerPlan{ch(OutcomeApplied), ch(OutcomeLockoutUnrestored)}, 2},
		{"unproven (dial)", []ServerPlan{unproven(fleet.ErrorKindDial)}, 1},
		{"unproven, host key changed", []ServerPlan{unproven(fleet.ErrorKindHostKeyChanged)}, 2},
		{"unproven, host key revoked", []ServerPlan{unproven(fleet.ErrorKindHostKeyRevoked)}, 2},
		{"unproven, host key unknown", []ServerPlan{unproven(fleet.ErrorKindHostKeyUnknown)}, 1},
		{"unproven, key type unrecorded", []ServerPlan{unproven(fleet.ErrorKindHostKeyTypeUnrecorded)}, 1},
		{"rollback put back a revoked key", []ServerPlan{rolled("SHA256:x")}, 2},
		{"rollback, no revoked key among the removals", []ServerPlan{rolled()}, 1},
		{"revoked removals but no rollback", []ServerPlan{{Class: ClassChange, Outcome: OutcomeFailed, RevokedRemovals: []string{"SHA256:x"}}}, 1},
		{"a refused plan never exits 2", []ServerPlan{{Class: ClassRefused, Outcome: OutcomeLockoutUnrestored}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.plans); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPlanSnapshotCarriesManaged(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(authkeys.Header(3) + "\n" + testkeys.Line(t, 9) + "\n")},
	}}
	content := []byte(authkeys.Header(3) + "\n" + testkeys.Line(t, 9) + "\n")
	if p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1"); !p.Expect.Managed || p.Expect != authkeys.ManagedSnapshot(false, content) {
		t.Errorf("Expect = %+v, want authkeys.ManagedSnapshot's (Managed for a (serial 3) file)", p.Expect)
	}
	r.byName["web-1"] = fleet.ReadResult{Content: []byte(testkeys.Line(t, 9) + "\n")}
	if p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1"); p.Expect.Managed {
		t.Error("Expect.Managed = true for a hand-written file")
	}
}

// A serial header is a managed header: never counted as a removed
// hand-written comment line.
func TestNormalizeSkipsSerialHeader(t *testing.T) {
	cfg := planCfg(t)
	body := strings.TrimPrefix(string(renderedFor(t, cfg, "web-1")), authkeys.ManagedHeader+"\n")
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(authkeys.Header(5) + "\n" + testkeys.Line(t, 9) + "\n" + body)},
	}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Normalize.NonKeyLines != 0 {
		t.Errorf("NonKeyLines = %d, want 0 (the serial header is not a hand comment)", p.Normalize.NonKeyLines)
	}
}

// TestPlanRevokedRemovals (D10a): only key tombstones count, in Remove
// order; an access tombstone removed nothing that sshd would still honour.
func TestPlanRevokedRemovals(t *testing.T) {
	const accessOnly = `  - {user: bob, servers: [web-1], date: "2026-11-01"}
`
	parse := func(t *testing.T, revoked string) *config.Config {
		t.Helper()
		cfg, err := config.Parse([]byte(`serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 10) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
revoked:
` + revoked))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return cfg
	}
	bobLine := testkeys.Line(t, 10) + "\n"
	t.Run("key tombstones in Remove order; an access tombstone does not count", func(t *testing.T) {
		// The tombstones are listed opposite to the file: the result must
		// follow Remove, which follows the file.
		cfg := parse(t, `  - {fingerprint: "`+fp(t, 9)+`", date: "2026-11-01"}
  - {fingerprint: "`+fp(t, 8)+`", date: "2026-11-01"}
`+accessOnly)
		stale := testkeys.Line(t, 8) + "\n" + bobLine + testkeys.Line(t, 9) + "\n"
		p := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg)+stale, false, false)
		if len(p.Remove) != 3 {
			t.Fatalf("Remove = %+v, want all three stale keys", p.Remove)
		}
		if want := []string{fp(t, 8), fp(t, 9)}; !slices.Equal(p.RevokedRemovals, want) {
			t.Errorf("RevokedRemovals = %v, want %v (Remove order, no access-tombstoned key)", p.RevokedRemovals, want)
		}
	})
	t.Run("only an access-tombstoned key removed: a rollback is exit 1", func(t *testing.T) {
		cfg := parse(t, accessOnly)
		p := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg)+bobLine, false, false)
		if len(p.Remove) != 1 || len(p.RevokedRemovals) != 0 {
			t.Fatalf("Remove = %+v, RevokedRemovals = %v", p.Remove, p.RevokedRemovals)
		}
		p.Outcome, p.RolledBack = OutcomeFailed, true
		if got := ExitCode([]ServerPlan{p}); got != 1 {
			t.Errorf("ExitCode = %d, want 1", got)
		}
	})
}
