package apply

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

const preserveRuleYAML = `[{command: '/usr/local/bin/gitea serv key-[0-9]+'}]`

// preserveCfg: op (k1, operator, comment op@sshepherd) on every server;
// alice (k2) owns a key granted nowhere; dave (k4) owns a key whose access
// to gitea an access tombstone removed; k5 is revoked; gitea keeps gitea's
// command= lines. serial > 0 sets serial:.
func preserveCfg(t *testing.T, serial int) *config.Config {
	t.Helper()
	head := ""
	if serial > 0 {
		head = fmt.Sprintf("serial: %d\n", serial)
	}
	y := head + `
users:
  - {name: op, operator: true, comment: op@sshepherd, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: dave, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: gitea, host: 10.0.4.1, user: git, preserve: ` + preserveRuleYAML + `}
revoked:
  - {fingerprint: ` + fp(t, 5) + `, date: 2026-11-10}
  - {user: dave, servers: [gitea], date: 2026-11-10}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("preserveCfg: %v", err)
	}
	return cfg
}

// giteaLine is a Gitea-style forced-command line for key seed.
func giteaLine(t *testing.T, seed byte, n int) string {
	t.Helper()
	return fmt.Sprintf(`command="/usr/local/bin/gitea serv key-%d",no-port-forwarding,no-pty %s git@laptop`, n, testkeys.Line(t, seed))
}

// opLine is op's line exactly as the render writes it.
func opLine(t *testing.T) string { t.Helper(); return testkeys.Line(t, 1) + " op@sshepherd" }

// giteaPlan plans gitea over content with op's key held.
func giteaPlan(t *testing.T, cfg *config.Config, res fleet.ReadResult, held ...string) ServerPlan {
	t.Helper()
	if len(held) == 0 {
		held = []string{fp(t, 1)}
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"gitea": res}}
	return planFor(t, buildPlans(t, cfg, r, held), "gitea")
}

// TestPlanKeepsPreservedLines (spec S6 "Render"): the write renders the kept
// line and its comment after the desired keys, under the marker; nothing is
// removed; the kept comment is not counted as a removed non-key line; and
// the written bytes, read back, are converged.
func TestPlanKeepsPreservedLines(t *testing.T) {
	cfg := preserveCfg(t, 0)
	gitea := "# gitea public key\n" + giteaLine(t, 7, 1) + "\n"
	p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(opLine(t) + "\n" + gitea)})
	want, err := authkeys.RenderKept(desiredEntries(cfg, "gitea"), 0, authkeys.ScanFile([]byte(gitea)))
	if err != nil {
		t.Fatal(err)
	}
	if p.Class != ClassChange || string(p.Rendered) != string(want) || len(p.Remove) != 0 || p.Kept != 1 || p.Normalize.NonKeyLines != 0 {
		t.Fatalf("plan = %s, kept %d, remove %d, normalize %+v, rendered:\n%s", p.Class, p.Kept, len(p.Remove), p.Normalize, p.Rendered)
	}
	again := giteaPlan(t, cfg, fleet.ReadResult{Content: p.Rendered})
	if again.Class != ClassConverged || again.Kept != 1 {
		t.Errorf("re-apply: Class = %s, Kept = %d; want converged, 1 (byte-exact convergence)", again.Class, again.Kept)
	}
}

// TestPlanPreservedIsNotARemoval (spec S6, P04 serial rows): a kept line is
// never in Remove, so it neither triggers the D4b bump nor makes a newer
// server's write "removal-only"; a newer server whose body already holds it
// is converged.
func TestPlanPreservedIsNotARemoval(t *testing.T) {
	cfg := preserveCfg(t, 7)
	body := opLine(t) + "\n" + giteaLine(t, 7, 1) + "\n" // no marker yet: a write
	p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(authkeys.Header(7) + "\n" + body)})
	if p.Class != ClassChange || len(p.Remove) != 0 || NeedsSerialBump([]ServerPlan{p}, 7) {
		t.Errorf("S == M: Class = %s, Remove = %d, bump = %v; want change, 0, false", p.Class, len(p.Remove), NeedsSerialBump([]ServerPlan{p}, 7))
	}
	stray := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(authkeys.Header(7) + "\n" + body + testkeys.Line(t, 8) + " stray\n")})
	if !NeedsSerialBump([]ServerPlan{stray}, 7) {
		t.Error("a real removal beside a kept line must still bump")
	}
	newer := append([]byte(authkeys.Header(9)+"\n"), bodyOf(p.Rendered)...)
	if q := giteaPlan(t, cfg, fleet.ReadResult{Content: newer}); q.Class != ClassConverged || q.Serial.Case != SerialNewerConverged {
		t.Errorf("newer header, equal body: Class = %s, case %s; want converged, newer_converged", q.Class, q.Serial.Case)
	}
}

// TestPlanPreservedNewerRemovalOnly (spec S6 "P04's serial row", §3 row 3):
// a newer server (S 9 > M 7) whose write only removes a stray key proceeds
// at S, and that second render (planWrite's row-3 re-render) still writes
// the kept line under the marker: a removal-only write never drops it.
func TestPlanPreservedNewerRemovalOnly(t *testing.T) {
	cfg := preserveCfg(t, 7)
	kept := "# gitea public key\n" + giteaLine(t, 7, 1) + "\n"
	content := authkeys.Header(9) + "\n" + opLine(t) + "\n" + kept + testkeys.Line(t, 8) + " stray\n"
	p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(content)})
	if p.Class != ClassChange || p.Serial.Case != SerialNewerRemovalOnly || p.Serial.Writes != 9 || p.Kept != 1 || len(p.Remove) != 1 {
		t.Fatalf("Class = %s, case %s, writes %d, Kept = %d, Remove = %d; want change, newer_removal_only, 9, 1, 1",
			p.Class, p.Serial.Case, p.Serial.Writes, p.Kept, len(p.Remove))
	}
	want, err := authkeys.RenderKept(desiredEntries(cfg, "gitea"), 9, authkeys.ScanFile([]byte(kept)))
	if err != nil {
		t.Fatal(err)
	}
	if string(p.Rendered) != string(want) {
		t.Errorf("row-3 render dropped the kept section:\n%s\nwant\n%s", p.Rendered, want)
	}
}

// TestPlanNeverPreserves (spec S6 "Lines that are never preserved",
// "Tombstones"): an owned key, a revoked key, a cert-authority line and an
// owned key whose access an access tombstone removed are removed even on a
// line the rule matches.
func TestPlanNeverPreserves(t *testing.T) {
	cfg := preserveCfg(t, 0)
	content := opLine(t) + "\n" + giteaLine(t, 2, 1) + "\n" + giteaLine(t, 5, 2) + "\ncert-authority," + giteaLine(t, 9, 3) + "\n" + giteaLine(t, 4, 4) + "\n"
	p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(content)})
	if p.Kept != 0 || len(p.Remove) != 4 || len(p.RevokedRemovals) != 1 || p.RevokedRemovals[0] != fp(t, 5) {
		t.Errorf("Kept = %d, Remove = %d, RevokedRemovals = %v; want 0, 4, [k5]", p.Kept, len(p.Remove), p.RevokedRemovals)
	}
}

// TestPlanUnparseableStillRefuses (spec S6 "Lines that are never
// preserved"): a kept line does not hide an unparseable one; the write is
// refused as today.
func TestPlanUnparseableStillRefuses(t *testing.T) {
	cfg := preserveCfg(t, 0)
	content := opLine(t) + "\n" + giteaLine(t, 7, 1) + "\nnot a key\n"
	p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(content)})
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "1 unparseable line — refusing to rewrite") {
		t.Errorf("Class = %s, Refusal = %q; want the unparseable-line refusal", p.Class, p.Refusal)
	}
}

// TestPlanMixedLinesNotPreserved (spec S6): a rule-matching line beside a
// plain copy of the same key, in either order, is removed with it.
func TestPlanMixedLinesNotPreserved(t *testing.T) {
	cfg := preserveCfg(t, 0)
	plain, forced := testkeys.Line(t, 7), giteaLine(t, 7, 1)
	for name, content := range map[string]string{
		"plain first":  opLine(t) + "\n" + plain + "\n" + forced + "\n",
		"forced first": opLine(t) + "\n" + forced + "\n" + plain + "\n",
	} {
		p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(content)})
		if p.Kept != 0 || len(p.Remove) != 1 || p.Normalize.Duplicates != 1 {
			t.Errorf("%s: Kept = %d, Remove = %d, duplicates %d; want 0, 1, 1", name, p.Kept, len(p.Remove), p.Normalize.Duplicates)
		}
	}
}

// TestPlanAllMatchingDuplicatesKept: two lines of one key that both match
// are both kept, and neither counts as a removed duplicate.
func TestPlanAllMatchingDuplicatesKept(t *testing.T) {
	cfg := preserveCfg(t, 0)
	p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(opLine(t) + "\n" + giteaLine(t, 7, 1) + "\n" + giteaLine(t, 7, 2) + "\n")})
	if p.Kept != 2 || len(p.Remove) != 0 || p.Normalize.Duplicates != 0 || strings.Count(string(p.Rendered), "gitea serv") != 2 {
		t.Errorf("Kept = %d, Remove = %d, duplicates %d, rendered:\n%s", p.Kept, len(p.Remove), p.Normalize.Duplicates, p.Rendered)
	}
}

// TestPlanEmptyExternalSection (spec S6): a marker with nothing left under
// it is its own normalize finding (not whitespace, not a non-key line); an
// extra marker beside kept lines is a removed non-key line.
func TestPlanEmptyExternalSection(t *testing.T) {
	cfg := preserveCfg(t, 0)
	p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(authkeys.ManagedHeader + "\n" + opLine(t) + "\n" + authkeys.PreserveMarker + "\n")})
	if p.Class != ClassChange || !p.Normalize.EmptyExternalSection || p.Normalize.NonKeyLines != 0 || p.Normalize.Whitespace {
		t.Errorf("empty section: Class = %s, normalize %+v", p.Class, p.Normalize)
	}
	two := authkeys.ManagedHeader + "\n" + opLine(t) + "\n" + authkeys.PreserveMarker + "\n" + authkeys.PreserveMarker + "\n" + giteaLine(t, 7, 1) + "\n"
	q := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(two)})
	if q.Normalize.EmptyExternalSection || q.Normalize.NonKeyLines != 1 || q.Kept != 1 {
		t.Errorf("two markers: normalize %+v, kept %d", q.Normalize, q.Kept)
	}
}

// TestPlanPreservedOnlyNoGrantServer (spec S6 "Empty-server rule stays"): a
// server the manifest grants nothing, holding only kept lines, is converged
// (never written); any other unauthorized key, an unparseable line or a
// non-empty authorized_keys2 still refuses. The last three rows pin
// planNoGrants' existing branches with a kept line beside them.
func TestPlanPreservedOnlyNoGrantServer(t *testing.T) {
	cfg, err := config.Parse([]byte("users: []\nservers:\n  - {name: bare, host: 10.0.4.2, user: git, preserve: " + preserveRuleYAML + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	content := []byte(giteaLine(t, 7, 1) + "\n")
	plan := func(res fleet.ReadResult) ServerPlan {
		r := &fakeReader{byName: map[string]fleet.ReadResult{"bare": res}}
		return planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "bare")
	}
	if p := plan(fleet.ReadResult{Content: content}); p.Class != ClassConverged || p.Kept != 1 {
		t.Errorf("Class = %s, Kept = %d; want converged, 1", p.Class, p.Kept)
	}
	for _, tc := range []struct{ name, extra, want string }{
		{"stray key", testkeys.Line(t, 8) + " stray\n", "1 key installed but manifest grants none — refusing to wipe"},
		{"unparseable line", "not a key\n", "0 keys and 1 unparseable line installed but manifest grants none — refusing to wipe"},
	} {
		if p := plan(fleet.ReadResult{Content: append(slices.Clone(content), tc.extra...)}); p.Class != ClassRefused || p.Refusal != tc.want {
			t.Errorf("%s: Class = %s, Refusal = %q; want refused, %q", tc.name, p.Class, p.Refusal, tc.want)
		}
	}
	p := plan(fleet.ReadResult{Content: content, AuthorizedKeys2: true})
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "authorized_keys2 holds keys but the manifest grants none") {
		t.Errorf("with keys2: Class = %s, Refusal = %q", p.Class, p.Refusal)
	}
}

// TestGuardPreservedKeyIsNoSurvivor (spec S6 "Guard"): a held key that sits
// only on a kept line does not keep this session's access. This pins
// existing behaviour (Survivors reads only the desired keys; before S6 the
// key was simply unauthorized): see Step 1's bite note.
func TestGuardPreservedKeyIsNoSurvivor(t *testing.T) {
	cfg := preserveCfg(t, 0)
	p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(giteaLine(t, 7, 1) + "\n")}, fp(t, 7))
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "would lock this session out") {
		t.Errorf("Class = %s, Refusal = %q; want the lockout refusal", p.Class, p.Refusal)
	}
}

// TestGuardSessionNoteSkipsPreserved (gap 4): a session that logged in with
// a key on a kept line does not get "removes the key this session logged in
// with": that line stays.
func TestGuardSessionNoteSkipsPreserved(t *testing.T) {
	cfg := preserveCfg(t, 0)
	content := testkeys.Line(t, 1) + "\n" + giteaLine(t, 7, 1) + "\n" // op's comment differs: a write
	p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(content), SessionKeyFP: fp(t, 7)}, fp(t, 1), fp(t, 7))
	if p.Class != ClassChange || p.Note != "" {
		t.Errorf("Class = %s, Note = %q; want change and no note", p.Class, p.Note)
	}
}

// TestPlanExternalSection (F1 Q3): a write that adds the preserve: marker
// the file lacks is its own normalize finding (never whitespace, never a
// non-key line); it is not set when the marker is already there, when
// nothing is kept, or for a marker with nothing under it.
func TestPlanExternalSection(t *testing.T) {
	cfg := preserveCfg(t, 0)
	head := authkeys.ManagedHeader + "\n" + opLine(t) + "\n"
	for _, tt := range []struct {
		name, content            string
		section, empty, residual bool
	}{
		{"kept line, no marker", head + giteaLine(t, 7, 1) + "\n", true, false, false},
		{"kept line and its comment, no marker", head + "# gitea public key\n" + giteaLine(t, 7, 1) + "\n", true, false, false},
		{"marker there, a stray removed", head + testkeys.Line(t, 9) + " stray@laptop\n" + authkeys.PreserveMarker + "\n" + giteaLine(t, 7, 1) + "\n", false, false, false},
		{"nothing kept, no marker", authkeys.ManagedHeader + "\n  " + opLine(t) + "\n", false, false, true},
		{"marker with nothing under it", head + authkeys.PreserveMarker + "\n", false, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(tt.content)})
			n := p.Normalize
			if p.Class != ClassChange || n.ExternalSection != tt.section || n.EmptyExternalSection != tt.empty || n.Whitespace != tt.residual || n.NonKeyLines != 0 {
				t.Errorf("Class = %s, normalize %+v; want section %v, empty %v, whitespace %v, no non-key lines", p.Class, n, tt.section, tt.empty, tt.residual)
			}
		})
	}
}
