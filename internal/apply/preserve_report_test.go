package apply

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// preservedPlans: alice (k2, comment alice@work) on empty, gitea, gitea-2,
// gitea-3 and session; bob (k3, not held) on locked; bare and bare-k2 grant
// nothing. The run holds k2 and k7 (k7 is the gitea key). gitea: a write
// that keeps a gitea line and removes a stray; gitea-2: already converged
// with a kept line; gitea-3: a managed file whose kept line has no marker
// yet (the first write after adding preserve:, gap 17); bare: only a kept
// line (converged); bare-k2: the same with authorized_keys2 (refused);
// empty: a marker with nothing under it; locked: the only held key on the
// server sits on a kept line, so the guard refuses (spec S6 Guard);
// session: the session logged in with the kept key, so no "removes the key
// this session logged in with" note (gap 4).
func preservedPlans(t *testing.T) (*config.Config, []ServerPlan) {
	t.Helper()
	y := `
users:
  - {name: alice, comment: alice@work, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, comment: bob@work, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: bare, host: 10.0.4.4, user: git, preserve: ` + preserveRuleYAML + `}
  - {name: bare-k2, host: 10.0.4.5, user: git, preserve: ` + preserveRuleYAML + `}
  - {name: empty, host: 10.0.4.3, user: git}
  - {name: gitea, host: 10.0.4.1, user: git, preserve: ` + preserveRuleYAML + `}
  - {name: gitea-2, host: 10.0.4.2, user: git, preserve: ` + preserveRuleYAML + `}
  - {name: gitea-3, host: 10.0.4.6, user: git, preserve: ` + preserveRuleYAML + `}
  - {name: locked, host: 10.0.4.7, user: git, preserve: ` + preserveRuleYAML + `}
  - {name: session, host: 10.0.4.8, user: git, preserve: ` + preserveRuleYAML + `}
access:
  - {user: alice, servers: [empty, gitea, gitea-2, gitea-3, session]}
  - {user: bob, servers: [locked]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("preservedPlans: %v", err)
	}
	alice := testkeys.Line(t, 2) + " alice@work"
	kept := "# gitea public key\n" + giteaLine(t, 7, 1) + "\n"
	converged, err := authkeys.RenderKept(desiredEntries(cfg, "gitea-2"), 0, authkeys.ScanFile([]byte(kept)))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"bare":    {Content: []byte(giteaLine(t, 7, 1) + "\n")},
		"bare-k2": {Content: []byte(giteaLine(t, 7, 1) + "\n"), AuthorizedKeys2: true},
		"empty":   {Content: []byte(authkeys.ManagedHeader + "\n" + alice + "\n" + authkeys.PreserveMarker + "\n")},
		"gitea":   {Content: []byte(alice + "\n" + kept + testkeys.Line(t, 9) + " stray@laptop\n")},
		"gitea-2": {Content: converged},
		"gitea-3": {Content: []byte(authkeys.ManagedHeader + "\n" + alice + "\n" + kept)},
		"locked":  {Content: []byte(kept)},
		"session": {Content: []byte(testkeys.Line(t, 2) + "\n" + kept), SessionKeyFP: fp(t, 7)}, // alice's comment differs: a write
	}}
	return cfg, buildPlans(t, cfg, r, []string{fp(t, 2), fp(t, 7)})
}

// TestRenderPreservedGoldens (spec S6 "Render", "Empty-server rule stays",
// "Guard", Tests "plan goldens"): the kept-lines note on a write and on a
// converged server, the empty section's row, a refused no-grant server with
// authorized_keys2 (no note), the guard ignoring a kept key, the session-key
// note skipped, the first write that only adds the marker, and JSON
// external_kept on exactly the converged and change servers.
func TestRenderPreservedGoldens(t *testing.T) {
	cfg, plans := preservedPlans(t)
	if p := planFor(t, plans, "gitea-3"); p.Class != ClassChange || !p.Normalize.Whitespace || p.Kept != 1 || len(p.Remove) != 0 {
		t.Errorf("gitea-3: Class = %s, normalize %+v, Kept = %d, Remove = %d; want change, whitespace, 1, 0 (gap 17)", p.Class, p.Normalize, p.Kept, len(p.Remove))
	}
	if p := planFor(t, plans, "locked"); p.Class != ClassRefused || !strings.Contains(p.Refusal, "would lock this session out") {
		t.Errorf("locked: Class = %s, Refusal = %q; want the lockout refusal", p.Class, p.Refusal)
	}
	if p := planFor(t, plans, "session"); p.Class != ClassChange || p.Note != "" {
		t.Errorf("session: Class = %s, Note = %q; want change and no note", p.Class, p.Note)
	}
	var text bytes.Buffer
	Render(&text, cfg, plans, RenderOptions{})
	checkGolden(t, "plan_preserved.golden", text.Bytes())
	out := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply", DryRun: true})
	checkGolden(t, "json_preserved.golden.json", out)

	var doc struct {
		Servers []struct {
			Name         string `json:"name"`
			ExternalKept int    `json:"external_kept"`
			Changes      struct {
				Normalize map[string]any `json:"normalize"`
			} `json:"changes"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string]int{"bare": 1, "bare-k2": 0, "empty": 0, "gitea": 1, "gitea-2": 1, "gitea-3": 1, "locked": 0, "session": 1}
	if len(doc.Servers) != len(want) {
		t.Fatalf("JSON has %d servers, want %d", len(doc.Servers), len(want))
	}
	for _, s := range doc.Servers {
		if s.ExternalKept != want[s.Name] {
			t.Errorf("%s: external_kept = %d, want %d", s.Name, s.ExternalKept, want[s.Name])
		}
		if _, ok := s.Changes.Normalize["empty_external_section"]; ok != (s.Name == "empty") {
			t.Errorf("%s: empty_external_section present = %v", s.Name, ok)
		}
	}
}
