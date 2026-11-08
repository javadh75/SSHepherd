package apply

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
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

// testDialHint mirrors sshconn.DialHint (apply cannot import sshconn,
// ARC-8); internal/sshconn's TestAuditGoldenCarriesDialHint pins the two
// equal through summary_failed_hint.golden.
const testDialHint = "check the host, port, and firewall; hosts reachable only through a bastion (ProxyJump/ProxyCommand) are dialed directly — jump hosts are not supported yet"

// hintedErr is a classified transport error with its remediation kept out
// of the message (the fleet.KindedError and fleet.Hinted pair that
// sshconn.Error implements), built here so apply's tests need no transport
// import.
type hintedErr struct {
	kind fleet.ErrorKind
	hint string
	err  error
}

func (e *hintedErr) Error() string              { return e.err.Error() }
func (e *hintedErr) Unwrap() error              { return e.err }
func (e *hintedErr) ErrorKind() fleet.ErrorKind { return e.kind }
func (e *hintedErr) ErrorHint() string          { return e.hint }

// dialRefused is what sshconn returns for a refused TCP connect.
func dialRefused(ip string) error {
	return &hintedErr{kind: fleet.ErrorKindDial, hint: testDialHint, err: &net.OpError{Op: "dial", Net: "tcp",
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
	RenderSummary(&buf, nil, plans, RenderOptions{})
	if n := strings.Count(buf.String(), "  hint: "+testDialHint+"\n"); n != 1 {
		t.Errorf("hint printed %d times, want 1:\n%s", n, buf.String())
	}
	checkGolden(t, "summary_failed_hint.golden", buf.Bytes())
}

// TestRenderSummaryRefusedHint: a phase-2 refusal that carries a hint
// prints it once under the first REFUSED row, like a failure's.
func TestRenderSummaryRefusedHint(t *testing.T) {
	const hint = "remove the stale lock by hand once no other run is writing"
	refused := func(name string) error {
		return fleet.Refused(&hintedErr{kind: fleet.ErrorKindDial, hint: hint, err: errors.New(name + " is locked by another run")})
	}
	plans := []ServerPlan{
		{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeRefused, OutcomeErr: refused("a")},
		{Server: config.Server{Name: "b"}, Class: ClassChange, Outcome: OutcomeRefused, OutcomeErr: refused("b")},
	}
	var buf bytes.Buffer
	RenderSummary(&buf, nil, plans, RenderOptions{})
	want := "a: REFUSED: a is locked by another run\n  hint: " + hint + "\nb: REFUSED: b is locked by another run\n"
	if !strings.HasPrefix(buf.String(), want) {
		t.Errorf("summary =\n%s\nwant it to start with\n%s", buf.String(), want)
	}
}

// TestRenderRemoveOptionsOnlyForUnknownKeys: the remove row's " · options:"
// suffix is for keys neither config owns. A key the manifest owns (bob's,
// on a server he is not granted) and a key only the pre-edit config owns
// (carol's, revoked) keep the plain "remove (unauthorized)" cell, even
// with on-server options.
func TestRenderRemoveOptionsOnlyForUnknownKeys(t *testing.T) {
	cfg := planCfg(t)
	former, err := config.Parse([]byte("users:\n  - {name: carol, keys: [\"" + testkeys.Line(t, 4) + "\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	withOpts := func(seed byte) authkeys.Key {
		k, err := authkeys.ParseLine("no-pty " + testkeys.Line(t, seed))
		if err != nil || k == nil {
			t.Fatalf("key %d: %v", seed, err)
		}
		return *k
	}
	plans := []ServerPlan{{
		Server: config.Server{Name: "web-1", Host: "10.0.0.1", Port: 22, User: "deploy"}, Class: ClassChange,
		Remove: []authkeys.Key{withOpts(3), withOpts(4), withOpts(9)},
	}}
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{Former: former})
	rows := map[string]string{"bob": "", "carol (revoked)": "", "(unknown)": ""}
	for line := range strings.Lines(buf.String()) {
		for label := range rows {
			if strings.Contains(line, " "+label+" ") {
				rows[label] = line
			}
		}
	}
	for label, want := range map[string]string{
		"bob":             "remove (unauthorized)\n",
		"carol (revoked)": "remove (unauthorized)\n",
		"(unknown)":       `remove (unauthorized) · options: "no-pty"` + "\n",
	} {
		if !strings.HasSuffix(rows[label], want) {
			t.Errorf("%s row = %q, want it to end %q\nreport:\n%s", label, rows[label], want, buf.String())
		}
	}
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
		"web-3 (deploy@10.0.0.3:22)  ERROR [dial]: dial tcp 10.0.0.3:22: connect: connection refused\n  hint: " + testDialHint + "\n",
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
	RenderSummary(&buf, nil, plans, RenderOptions{})
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
	RenderSummary(&buf, nil, plans, RenderOptions{})
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
	RenderSummary(&buf, nil, plans, RenderOptions{})
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
	RenderSummary(&buf, nil, plans, RenderOptions{})
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
	RenderSummary(&buf, nil, nil, RenderOptions{})
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
	RenderSummary(&buf, nil, plans, RenderOptions{})
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
	RenderSummary(&buf, nil, plans, RenderOptions{})
	if !strings.Contains(buf.String(), "Summary: 2/7 servers converged (1 applied) · 1 pending · 1 failed · 2 refused · 1 unreachable  → exit 1") {
		t.Errorf("summary line disagrees with countSummary:\n%s", buf.String())
	}
}

// serialFleet: serial 7, op (k1) operator, alice (k2) on every server; one
// server per row of the §3 table, planned in a bumped (revoke) run.
func serialFleet(t *testing.T) (*config.Config, []ServerPlan) {
	t.Helper()
	cfg, err := config.Parse([]byte(`serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: s-forged, host: 10.0.0.1, user: deploy}
  - {name: s-headeronly, host: 10.0.0.2, user: deploy}
  - {name: s-newer, host: 10.0.0.3, user: deploy}
  - {name: s-older, host: 10.0.0.4, user: deploy}
  - {name: s-refused, host: 10.0.0.5, user: deploy}
  - {name: s-removal, host: 10.0.0.6, user: deploy}
access:
  - {user: alice, servers: ["*"]}
`))
	if err != nil {
		t.Fatal(err)
	}
	body := string(bodyOf(renderedFor(t, cfg, "s-forged")))
	opOnly := testkeys.Line(t, 1) + " op\n"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"s-forged":     {Content: []byte(authkeys.Header(5000) + "\n" + body)},
		"s-headeronly": {Content: []byte(authkeys.Header(6) + "\n" + body)},
		"s-newer":      {Content: []byte(authkeys.Header(8) + "\n" + body)},
		"s-older":      {Content: []byte(authkeys.ManagedHeader + "\n" + opOnly)},
		"s-refused":    {Content: []byte(authkeys.Header(8) + "\n" + opOnly)},
		"s-removal":    {Content: []byte(authkeys.Header(8) + "\n" + body + testkeys.Line(t, 9) + " stray\n")},
	}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 2})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{Bumped: true})
	if err != nil {
		t.Fatal(err)
	}
	return cfg, plans
}

func TestRenderPlanSerialGolden(t *testing.T) {
	cfg, plans := serialFleet(t)
	var b bytes.Buffer
	Render(&b, cfg, plans, RenderOptions{})
	checkGolden(t, "plan_serial.golden", b.Bytes())
	for _, want := range []string{
		"(header)", // the label column; tabwriter pads the row, so match its cells separately
		"update header: forged serial 5000 → 7 (keys unchanged)\n",
		"update header: serial 6 → 7 (keys unchanged)\n",
		"  → 2 keys desired · header only",
		"s-newer (deploy@10.0.0.3:22)  converged (no changes)\n  note: written by newer manifest serial 8 (yours is 7): pull the latest manifest\n",
		"  warning: written by newer manifest serial 8; this write only removes keys, so it proceeds",
		"  warning: header claims serial 5000, far above this manifest's 7 — treated as no serial",
		"REFUSED: written by manifest serial 8, this manifest is 7",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, b.String())
		}
	}
}

func TestRenderHeaderOnlyFromNoSerial(t *testing.T) {
	cfg := serialCfg(t)
	p := planWeb1(t, cfg, authkeys.ManagedHeader+"\n"+web1Body(t, cfg), false, true)
	var b bytes.Buffer
	Render(&b, cfg, []ServerPlan{p}, RenderOptions{})
	if !strings.Contains(b.String(), "update header: no serial → 7 (keys unchanged)") {
		t.Errorf("report:\n%s", b.String())
	}
}

func appliedPlan(name string) ServerPlan {
	return ServerPlan{Server: config.Server{Name: name}, Class: ClassChange, Outcome: OutcomeApplied}
}

func unprovenPlan(name string, attempts int, hostKey bool, last error) ServerPlan {
	return ServerPlan{Server: config.Server{Name: name}, Class: ClassChange, Outcome: OutcomeUnproven,
		OutcomeErr: &fleet.UnprovenError{Path: "~/.ssh/authorized_keys", Attempts: attempts, HostKey: hostKey, Last: last}}
}

func TestRenderSummaryUnprovenGolden(t *testing.T) {
	plans := []ServerPlan{appliedPlan("web-1"), unprovenPlan("web-2", 4, false,
		&hintedErr{kind: fleet.ErrorKindDial, hint: testDialHint, err: errors.New("dial tcp 10.0.0.2:22: i/o timeout")})}
	var buf bytes.Buffer
	RenderSummary(&buf, nil, plans, RenderOptions{})
	for _, want := range []string{
		"web-2: UNPROVEN: written and verified, but the login check could not reach the server after 4 attempts (dial tcp 10.0.0.2:22: i/o timeout) — kept the new file; run sshepherd audit to confirm\n",
		"Summary: 1/2 servers converged (1 applied) · 1 unproven  → exit 1\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "summary_unproven.golden", buf.Bytes())
}

func TestRenderSummaryUnprovenHostKeyGolden(t *testing.T) {
	plans := []ServerPlan{unprovenPlan("web-1", 1, true, &hintedErr{kind: fleet.ErrorKindHostKeyChanged, err: errors.New("host key changed")})}
	var buf bytes.Buffer
	RenderSummary(&buf, nil, plans, RenderOptions{})
	for _, want := range []string{
		"web-1: UNPROVEN: written and verified, but the login check stopped at a host-key alarm (host key changed) — kept the new file; check known_hosts, then run sshepherd audit\n",
		"→ exit 2\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "summary_unproven_hostkey.golden", buf.Bytes())
}

func TestRenderSummaryLockoutGolden(t *testing.T) {
	plans := []ServerPlan{
		appliedPlan("web-1"),
		unprovenPlan("web-2", 2, false, &hintedErr{kind: fleet.ErrorKindAgent, err: errors.New("none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)")}),
		{Server: config.Server{Name: "web-3"}, Class: ClassChange, Outcome: OutcomeLockoutUnrestored,
			OutcomeErr: &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("ssh: unable to authenticate"), Restore: errors.New("restore on web-3 failed (exit 1): mv: denied")}},
	}
	var buf bytes.Buffer
	RenderSummary(&buf, nil, plans, RenderOptions{})
	for _, want := range []string{
		"web-3: LOCKOUT — NOT RESTORED: post-write login offering only the surviving keys you hold failed (ssh: unable to authenticate) AND restoring the previous file failed (restore on web-3 failed (exit 1): mv: denied) — the previous version is at ~/.ssh/authorized_keys.sshepherd.bak; repair it over a session that is still open\n",
		"Summary: 1/3 servers converged (1 applied) · 1 unproven · 1 lockout not restored  → exit 2\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "summary_lockout.golden", buf.Bytes())
}

// rolledBackPlans: a rollback that put back alice (on the revoked: list)
// and bob, beside two applied servers.
func rolledBackPlans(t *testing.T) []ServerPlan {
	t.Helper()
	alice, bob := testKey(t, 2), testKey(t, 3)
	return []ServerPlan{appliedPlan("a"), appliedPlan("b"), {
		Server: config.Server{Name: "web-1"}, Class: ClassChange, Outcome: OutcomeFailed, RolledBack: true,
		Remove: []authkeys.Key{alice, bob}, RevokedRemovals: []string{alice.Fingerprint},
		OutcomeErr: &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("ssh: unable to authenticate")},
	}}
}

func TestRenderSummaryRestoredRevokedGolden(t *testing.T) {
	var buf bytes.Buffer
	RenderSummary(&buf, &config.Config{}, rolledBackPlans(t), RenderOptions{Former: planCfg(t)})
	for _, want := range []string{
		"web-1: FAILED: lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate); it still grants alice (" + fp(t, 2) + ", on the revoked: list) and bob (" + fp(t, 3) + "), which the manifest removed — fix the surviving key and re-run\n",
		"Summary: 2/3 servers converged (2 applied) · 1 failed  → exit 2\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "summary_restored_revoked.golden", buf.Bytes())
}

func TestRollbackDetail(t *testing.T) {
	k1, k2, k3 := testKey(t, 1), testKey(t, 2), testKey(t, 3)
	k9 := testKey(t, 9)
	k9.Comment = "stray"
	cfg := planCfg(t) // op owns k1, alice k2, bob k3
	for _, tt := range []struct {
		name string
		p    ServerPlan
		want string
	}{
		{"no rollback", ServerPlan{Remove: []authkeys.Key{k1}}, ""},
		{"nothing removed", ServerPlan{RolledBack: true}, ""},
		{"one key", ServerPlan{RolledBack: true, Remove: []authkeys.Key{k2}},
			"; it still grants alice (" + k2.Fingerprint + "), which the manifest removed — fix the surviving key and re-run"},
		{"three keys, a former owner by name", ServerPlan{RolledBack: true, Remove: []authkeys.Key{k1, k2, k3}, RevokedRemovals: []string{k3.Fingerprint}},
			"; it still grants op (" + k1.Fingerprint + "), alice (" + k2.Fingerprint + ") and bob (" + k3.Fingerprint + ", on the revoked: list), which the manifest removed — fix the surviving key and re-run"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := rollbackDetail(cfg, nil, tt.p); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
	t.Run("a key neither config owns", func(t *testing.T) {
		p := ServerPlan{RolledBack: true, Remove: []authkeys.Key{k9}}
		if got := rollbackDetail(cfg, nil, p); !strings.Contains(got, audit.UnknownLabel(k9)+" (") {
			t.Errorf("got %s", got)
		}
	})
	t.Run("the former owner, when only former has it", func(t *testing.T) {
		p := ServerPlan{RolledBack: true, Remove: []authkeys.Key{k2}}
		if got := rollbackDetail(&config.Config{}, cfg, p); !strings.Contains(got, "alice (") {
			t.Errorf("got %s", got)
		}
	})
}

func TestRenderSummaryExitTwoLinesAreBoldRed(t *testing.T) {
	boldRed := "\x1b[" + codeBoldRed + "m"
	for _, tt := range []struct {
		name  string
		plan  ServerPlan
		label string
		red   bool
	}{
		{"revoked rollback", ServerPlan{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeFailed, RolledBack: true, RevokedRemovals: []string{"x"}, OutcomeErr: errors.New("e")}, "FAILED:", true},
		{"plain failure", ServerPlan{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: errors.New("e")}, "FAILED:", false},
		{"host-key unproven", unprovenPlan("a", 1, true, &hintedErr{kind: fleet.ErrorKindHostKeyRevoked, err: errors.New("e")}), "UNPROVEN:", true},
		{"dial unproven", unprovenPlan("a", 1, false, &hintedErr{kind: fleet.ErrorKindDial, err: errors.New("e")}), "UNPROVEN:", false},
		{"lockout", ServerPlan{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeLockoutUnrestored, OutcomeErr: errors.New("e")}, "LOCKOUT — NOT RESTORED:", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			RenderSummary(&buf, &config.Config{}, []ServerPlan{tt.plan}, RenderOptions{Color: true})
			if got := strings.Contains(buf.String(), boldRed+tt.label); got != tt.red {
				t.Errorf("bold red = %v, want %v:\n%q", got, tt.red, buf.String())
			}
		})
	}
}
