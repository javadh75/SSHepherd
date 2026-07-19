package apply

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

// mixedCfg: alice (k2, comment) -> web-1+web-2; bob (k3) -> web-1; db-1 has
// no grants (wipe refusal); web-3 will be unreachable. No operators, so the
// empty-desired path is reachable.
func mixedCfg(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, comment: "alice@work", keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: db-1, host: 10.0.0.9, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: web-3, host: 10.0.0.3, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("mixedCfg: %v", err)
	}
	return cfg
}

// mixedPlans builds the full four-class scenario: web-1 change (add bob,
// remove stray, rewrite alice's comment, normalize a hand comment),
// web-2 converged, db-1 refused (wipe), web-3 unreachable.
func mixedPlans(t *testing.T) (*config.Config, []ServerPlan) {
	t.Helper()
	cfg := mixedCfg(t)
	web1 := "# legacy note\n" +
		testkeys.Line(t, 2) + " alice@old\n" +
		testkeys.Line(t, 9) + " stray@laptop\n"
	r := &fakeReader{
		byName: map[string]audit.ReadResult{
			"web-1": {Content: []byte(web1), SessionKeyFP: fp(t, 2)},
			"web-2": {Content: renderedFor(t, cfg, "web-2")},
			"db-1":  {Content: []byte(testkeys.Line(t, 8) + "\n")},
		},
		errs: map[string]error{"web-3": errors.New("dial tcp 10.0.0.3:22: connection refused")},
	}
	return cfg, buildPlans(t, cfg, r, []string{fp(t, 2)})
}

func TestRenderPlanMixedGolden(t *testing.T) {
	cfg, plans := mixedPlans(t)
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		"add (authorized, missing)",
		"remove (unauthorized)",
		`rewrite comment: "alice@old" → "alice@work"`,
		"normalize: removing 1 non-key lines (comments/blank)",
		"→ 2 keys desired · 1 add · 1 remove · 1 rewrite",
		"web-2 (deploy@10.0.0.2:22)  converged (no changes)",
		"db-1 (deploy@10.0.0.9:22)  REFUSED: 1 keys installed but manifest grants none — refusing to wipe",
		"web-3 (deploy@10.0.0.3:22)  ERROR:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	checkGolden(t, "plan_mixed.golden", buf.Bytes())
}

func TestRenderPlanMixedColorGolden(t *testing.T) {
	cfg, plans := mixedPlans(t)
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{Color: true})
	if !strings.Contains(buf.String(), "\x1b[0;32m+\x1b[0m") {
		t.Errorf("color output lacks the painted add glyph:\n%q", buf.String())
	}
	checkGolden(t, "plan_mixed_color.golden", buf.Bytes())
}

func TestRenderColorStrippedEqualsPlain(t *testing.T) {
	cfg, plans := mixedPlans(t)
	var plain, color bytes.Buffer
	Render(&plain, cfg, plans, RenderOptions{})
	Render(&color, cfg, plans, RenderOptions{Color: true})
	stripped := color.String()
	for _, code := range []string{codeGreen, codeRed, codeBoldRed, codeYellow} {
		stripped = strings.ReplaceAll(stripped, "\x1b["+code+"m", "")
	}
	stripped = strings.ReplaceAll(stripped, "\x1b[0m", "")
	if stripped != plain.String() {
		t.Error("color output with SGR stripped must be byte-identical to plain")
	}
}

func TestRenderSummaryAppliedGolden(t *testing.T) {
	_, plans := mixedPlans(t)
	for i := range plans {
		if plans[i].Class == ClassChange {
			plans[i].Outcome = OutcomeApplied
		}
	}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		"web-1: applied · verified",
		"Summary: 2/4 servers converged (1 applied) · 1 refused · 1 unreachable  → exit 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	checkGolden(t, "summary_applied.golden", buf.Bytes())
}

func TestRenderSummaryPendingGolden(t *testing.T) {
	_, plans := mixedPlans(t)
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	want := "Summary: 1/4 servers converged · 1 pending · 1 refused · 1 unreachable  → exit 1\n"
	if buf.String() != want {
		t.Errorf("dry-run summary = %q, want %q (no outcome lines for pending)", buf.String(), want)
	}
	checkGolden(t, "summary_pending.golden", buf.Bytes())
}

func TestRenderSummaryFailedAndSymlink(t *testing.T) {
	plans := []ServerPlan{
		{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: errors.New("verify on a: file bytes differ from the rendered desired state")},
		{Server: config.Server{Name: "b"}, Class: ClassChange, Outcome: OutcomeRefused,
			OutcomeErr: errors.New("/etc/keys is a symlink — refusing to replace it with a regular file (point authorized_keys_file at the real target if intended)")},
	}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		"a: FAILED: verify on a",
		"b: REFUSED: /etc/keys is a symlink",
		"Summary: 0/2 servers converged · 1 failed · 1 refused  → exit 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
}

func TestRenderAllConvergedSummary(t *testing.T) {
	plans := []ServerPlan{{Server: config.Server{Name: "a"}, Class: ClassConverged}}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	if got, want := buf.String(), "Summary: 1/1 servers converged  → exit 0\n"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}

func TestRenderEmptyPlans(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, mixedCfg(t), nil, RenderOptions{})
	if got, want := buf.String(), "Summary: 0 servers targeted — nothing to apply\n"; got != want {
		t.Errorf("empty render = %q, want %q", got, want)
	}
	buf.Reset()
	RenderSummary(&buf, nil, RenderOptions{})
	if buf.Len() != 0 {
		t.Errorf("RenderSummary(nil) = %q, want no output", buf.String())
	}
}

func TestRenderGuardNoteAndWarning(t *testing.T) {
	plans := []ServerPlan{{
		Server: config.Server{Name: "w", User: "u", Host: "h", Port: 22},
		Class:  ClassChange, Outcome: OutcomePending,
		Note:    "removes the key this session logged in with; op remains",
		Warning: "every remaining agent-held key carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked",
	}}
	var buf bytes.Buffer
	Render(&buf, mixedCfg(t), plans, RenderOptions{})
	if !strings.Contains(buf.String(), "note: removes the key this session logged in with") {
		t.Errorf("report lacks the rotate note:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "warning: every remaining agent-held key") {
		t.Errorf("report lacks the restrictive-options warning:\n%s", buf.String())
	}
}
