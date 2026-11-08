package apply

import (
	"bytes"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
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
		byName: map[string]fleet.ReadResult{
			"web-1": {Content: []byte(web1), SessionKeyFP: fp(t, 2)},
			"web-2": {Content: renderedFor(t, cfg, "web-2")},
			"db-1":  {Content: []byte(testkeys.Line(t, 8) + "\n")},
		},
		errs: map[string]error{"web-3": dialRefused("10.0.0.3")},
	}
	return cfg, buildPlans(t, cfg, r, []string{fp(t, 2)})
}

// dialRefused is exactly what sshconn returns for a refused TCP connect.
func dialRefused(ip string) error {
	return &sshconn.Error{Kind: fleet.ErrorKindDial, Hint: sshconn.DialHint, Err: &net.OpError{Op: "dial", Net: "tcp",
		Addr: &net.TCPAddr{IP: net.ParseIP(ip), Port: 22}, Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}}
}

// TestRenderRemoveRowShowsOptions: an unowned key's on-server options ride
// in the remove row's detail cell.
func TestRenderRemoveRowShowsOptions(t *testing.T) {
	cfg := mixedCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 2) + " alice@work\n" + testkeys.Line(t, 3) + " bob\n" +
			`command="/bin/backup" ` + testkeys.Line(t, 9) + " backup@nas\n"), SessionKeyFP: fp(t, 2)},
	}}
	plans := buildPlans(t, cfg, r, []string{fp(t, 2)})
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	if !strings.Contains(buf.String(), `(unknown) "backup@nas"`) ||
		!strings.Contains(buf.String(), `remove (unauthorized) · options: "command=\"/bin/backup\""`) {
		t.Errorf("remove row lacks comment/options:\n%s", buf.String())
	}
}

// TestRenderRewriteWidens: a rewrite that adds a relaxing option is
// flagged on its own warning line, painted like the loosening warning.
func TestRenderRewriteWidens(t *testing.T) {
	cfg := planCfg(t)
	plans := []ServerPlan{{
		Server: config.Server{Name: "web-1", Host: "10.0.0.1", Port: 22, User: "deploy"}, Class: ClassChange,
		Rewrites: []RewriteRow{{Key: testKey(t, 1), Widens: []string{"no-touch-required"}}},
	}}
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	if !strings.Contains(buf.String(), `adds relaxing option(s) "no-touch-required"`) {
		t.Errorf("report lacks the widening warning:\n%s", buf.String())
	}
	var color bytes.Buffer
	Render(&color, cfg, plans, RenderOptions{Color: true})
	if !strings.Contains(color.String(), "\x1b["+codeBoldRed+"mrewrite comment") {
		t.Errorf("a widening rewrite row must be painted bold red:\n%q", color.String())
	}
}

// TestRenderSummaryFailedHint: a phase-2 failure that carries a hint prints
// it once under the first FAILED row.
func TestRenderSummaryFailedHint(t *testing.T) {
	plans := []ServerPlan{
		{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: dialRefused("10.0.0.1")},
		{Server: config.Server{Name: "b"}, Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: dialRefused("10.0.0.2")},
	}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	if n := strings.Count(buf.String(), "  hint: "+sshconn.DialHint+"\n"); n != 1 {
		t.Errorf("hint printed %d times, want 1:\n%s", n, buf.String())
	}
	checkGolden(t, "summary_failed_hint.golden", buf.Bytes())
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
		"normalize: removing 1 non-key line (comments/blank)",
		"→ 2 keys desired · 1 add · 1 remove · 1 rewrite",
		"web-2 (deploy@10.0.0.2:22)  converged (no changes)",
		"db-1 (deploy@10.0.0.9:22)  REFUSED: 1 key installed but manifest grants none — refusing to wipe",
		"web-3 (deploy@10.0.0.3:22)  ERROR [dial]: dial tcp 10.0.0.3:22: connect: connection refused\n  hint: " + sshconn.DialHint + "\n",
		`-  (unknown) "stray@laptop"`,
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
		Warning: "every remaining key you hold carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked",
	}}
	var buf bytes.Buffer
	Render(&buf, mixedCfg(t), plans, RenderOptions{})
	if !strings.Contains(buf.String(), "note: removes the key this session logged in with") {
		t.Errorf("report lacks the rotate note:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "warning: every remaining key you hold") {
		t.Errorf("report lacks the restrictive-options warning:\n%s", buf.String())
	}
}

// securityPlans: web-1 where the manifest would strip alice's restrictive
// options, bob's key is installed twice (the copy with its own options),
// and an unmanaged authorized_keys2 is present.
func securityPlans(t *testing.T) (*config.Config, []ServerPlan) {
	t.Helper()
	cfg := planCfg(t)
	content := testkeys.Line(t, 1) + " op@sshepherd\n" +
		`from="10.0.0.5",command="/usr/bin/pg_dump-wrapper" ` + testkeys.Line(t, 2) + " alice@work\n" +
		testkeys.Line(t, 3) + " bob\n" +
		"no-pty " + testkeys.Line(t, 3) + " bob\n"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(content), AuthorizedKeys2: true},
	}}
	return cfg, buildPlans(t, cfg, r, []string{fp(t, 1)})
}

func TestRenderPlanSecurityGolden(t *testing.T) {
	cfg, plans := securityPlans(t)
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		`rewrite options: "from=\"10.0.0.5\",command=\"/usr/bin/pg_dump-wrapper\"" → (none)`,
		`warning: the rewrite of alice (alice@work)'s key drops restrictive option(s) "from=\"10.0.0.5\"", "command=\"/usr/bin/pg_dump-wrapper\""`,
		"removing 1 duplicate key line (some carry options different from the first copy",
		"disable ~/.ssh/authorized_keys2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	checkGolden(t, "plan_security.golden", buf.Bytes())

	buf.Reset()
	Render(&buf, cfg, plans, RenderOptions{Color: true})
	if !strings.Contains(buf.String(), "\x1b[1;31mrewrite options:") {
		t.Errorf("a loosening rewrite must be painted red:\n%q", buf.String())
	}
	checkGolden(t, "plan_security_color.golden", buf.Bytes())
}

// TestPlanKeys2ForcesDisable: a server whose authorized_keys already
// matches the render is not converged while a non-empty authorized_keys2
// (which sshd also reads) exists — a revoked key there still logs in. The
// plan is a change whose only row disables the file.
func TestPlanKeys2ForcesDisable(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: renderedFor(t, cfg, "web-1"), AuthorizedKeys2: true},
	}}
	plans := buildPlans(t, cfg, r, []string{fp(t, 1)})
	p := planFor(t, plans, "web-1")
	if p.Class != ClassChange || !p.DisableKeys2() {
		t.Fatalf("plan = %s (disable=%v), want a change that disables authorized_keys2", p.Class, p.DisableKeys2())
	}
	if len(p.Add)+len(p.Remove)+len(p.Rewrites) != 0 || p.Normalize.Any() {
		t.Errorf("plan = %+v, want no key or formatting rows (the bytes already match)", p)
	}
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	if !strings.Contains(buf.String(), "disable ~/.ssh/authorized_keys2") || strings.Contains(buf.String(), "warning: ~/.ssh/authorized_keys2") {
		t.Errorf("report = %q, want the disable row instead of the hand-removal warning", buf.String())
	}
}

// TestRenderKeys2WarningOnRefused: a server apply will not write keeps the
// hand-removal warning — nothing disables the file there.
func TestRenderKeys2WarningOnRefused(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\ngarbage line\n"), AuthorizedKeys2: true},
	}}
	plans := buildPlans(t, cfg, r, []string{fp(t, 1)})
	if p := planFor(t, plans, "web-1"); p.Class != ClassRefused || p.DisableKeys2() {
		t.Fatalf("plan = %s (disable=%v), want refused without a disable", p.Class, p.DisableKeys2())
	}
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	if !strings.Contains(buf.String(), "warning: ~/.ssh/authorized_keys2 exists and is non-empty") {
		t.Errorf("report = %q, want the authorized_keys2 warning", buf.String())
	}
}

func TestRenderSummaryInterruptedGolden(t *testing.T) {
	plans := []ServerPlan{
		{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeApplied},
		{Server: config.Server{Name: "b"}, Class: ClassChange, Outcome: OutcomePending, OutcomeErr: errInterrupted},
		{Server: config.Server{Name: "c"}, Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: errors.New("lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate)")},
	}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	for _, want := range []string{
		"b: NOT STARTED: interrupted before the write started",
		"c: FAILED: lockout prevented — restored previous file",
		"Summary: 1/3 servers converged (1 applied) · 1 pending · 1 failed  → exit 1",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "summary_interrupted.golden", buf.Bytes())
}

// TestCountSummaryMatchesRenderSummary pins that the JSON summary and the
// text summary line count from one helper and cannot disagree.
func TestCountSummaryMatchesRenderSummary(t *testing.T) {
	plans := []ServerPlan{
		{Server: config.Server{Name: "a"}, Class: ClassConverged},
		{Server: config.Server{Name: "b"}, Class: ClassChange, Outcome: OutcomeApplied},
		{Server: config.Server{Name: "c"}, Class: ClassChange, Outcome: OutcomePending, OutcomeErr: errInterrupted},
		{Server: config.Server{Name: "d"}, Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: errors.New("boom")},
		{Server: config.Server{Name: "e"}, Class: ClassChange, Outcome: OutcomeRefused, OutcomeErr: errors.New("symlink")},
		{Server: config.Server{Name: "f"}, Class: ClassRefused, Refusal: "wipe"},
		{Server: config.Server{Name: "g"}, Class: ClassUnreachable, Err: errors.New("dial")},
	}
	got := countSummary(plans)
	want := summaryCounts{converged: 2, applied: 1, pending: 1, failed: 1, refused: 2, unreachable: 1}
	if got != want {
		t.Fatalf("countSummary = %+v, want %+v", got, want)
	}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	if !strings.Contains(buf.String(), "Summary: 2/7 servers converged (1 applied) · 1 pending · 1 failed · 2 refused · 1 unreachable  → exit 1") {
		t.Errorf("summary line disagrees with countSummary:\n%s", buf.String())
	}
}
