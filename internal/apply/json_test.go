package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// renderJSONCfg renders and asserts the output is one valid JSON value.
func renderJSONCfg(t *testing.T, cfg *config.Config, plans []ServerPlan, opts JSONOptions) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderJSON(&buf, cfg, plans, opts); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatalf("not valid JSON:\n%s", buf.String())
	}
	return buf.Bytes()
}

// TestRenderJSONEmptyFleet: nil plans still produce the full stable shape:
// servers [], every count 0, exit_code 0, skipped carried, edit null.
func TestRenderJSONEmptyFleet(t *testing.T) {
	out := renderJSONCfg(t, mixedCfg(t), nil, JSONOptions{Command: "apply", Skipped: 2})
	checkGolden(t, "json_empty.golden.json", out)

	var doc struct {
		Schema  int             `json:"schema"`
		Command string          `json:"command"`
		Edit    json.RawMessage `json:"edit"`
		Summary map[string]int  `json:"summary"`
		Servers []any           `json:"servers"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != 1 || doc.Command != "apply" || string(doc.Edit) != "null" || doc.Servers == nil ||
		len(doc.Servers) != 0 || doc.Summary["skipped"] != 2 || doc.Summary["exit_code"] != 0 {
		t.Errorf("empty doc = %+v", doc)
	}
}

// jsonDocT is the round-trip view the tests assert on.
type jsonDocT struct {
	Schema  int    `json:"schema"`
	Command string `json:"command"`
	DryRun  bool   `json:"dry_run"`
	Edit    *struct {
		Saved bool `json:"saved"`
	} `json:"edit"`
	Summary map[string]int `json:"summary"`
	Servers []struct {
		Name      string  `json:"name"`
		Class     string  `json:"class"`
		Outcome   *string `json:"outcome"`
		Error     *string `json:"error"`
		ErrorKind string  `json:"error_kind"`
		Changes   struct {
			Add       []map[string]any `json:"add"`
			Remove    []map[string]any `json:"remove"`
			Rewrite   []map[string]any `json:"rewrite"`
			Normalize map[string]any   `json:"normalize"`
		} `json:"changes"`
		Disables bool              `json:"disables_authorized_keys2"`
		Notes    map[string]string `json:"notes"`
	} `json:"servers"`
}

func decodeDoc(t *testing.T, b []byte) jsonDocT {
	t.Helper()
	var d jsonDocT
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("decode: %v\n%s", err, b)
	}
	return d
}

func serverNamed(t *testing.T, d jsonDocT, name string) int {
	t.Helper()
	for i, s := range d.Servers {
		if s.Name == name {
			return i
		}
	}
	t.Fatalf("no server %q in document", name)
	return -1
}

// TestRenderJSONMixed: all four classes; outcome null off change; stable
// shape on non-change servers; add comment is the decided write-time
// comment; remove comment is the on-server one.
func TestRenderJSONMixed(t *testing.T) {
	cfg, plans := mixedPlans(t)
	out := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply", DryRun: true})
	checkGolden(t, "json_mixed.golden.json", out)
	d := decodeDoc(t, out)
	if !d.DryRun || d.Edit != nil || d.Summary["exit_code"] != 1 {
		t.Errorf("top level = %+v", d)
	}
	classes := map[string]string{"web-1": "change", "web-2": "converged", "db-1": "refused", "web-3": "unreachable"}
	for name, class := range classes {
		s := d.Servers[serverNamed(t, d, name)]
		if s.Class != class {
			t.Errorf("%s class = %q, want %q", name, s.Class, class)
		}
		if (class == "change") != (s.Outcome != nil) {
			t.Errorf("%s outcome = %v: must be set exactly on change servers", name, s.Outcome)
		}
		if s.Changes.Add == nil || s.Changes.Remove == nil || s.Changes.Rewrite == nil || s.Changes.Normalize == nil {
			t.Errorf("%s changes not fully present: %+v", name, s.Changes)
		}
	}
	w1 := d.Servers[serverNamed(t, d, "web-1")]
	if *w1.Outcome != "pending" {
		t.Errorf("dry-run outcome = %q, want pending", *w1.Outcome)
	}
	if got := w1.Changes.Remove[0]["comment"]; got != "stray@laptop" {
		t.Errorf("remove comment = %v, want the on-server comment", got)
	}
	if got := w1.Changes.Add[0]["comment"]; got != "bob" {
		t.Errorf("add comment = %v, want the decided write-time comment (bob's name floor)", got)
	}
	w3 := d.Servers[serverNamed(t, d, "web-3")]
	if w3.Error == nil || w3.ErrorKind == "" {
		t.Errorf("unreachable server lacks error/error_kind: %+v", w3)
	}
	db1 := d.Servers[serverNamed(t, d, "db-1")]
	if db1.Error == nil || !strings.Contains(*db1.Error, "refusing to wipe") || db1.ErrorKind != "" {
		t.Errorf("refused server error = %v kind %q", db1.Error, db1.ErrorKind)
	}
}

// TestRenderJSONSecurity: options rewrite with verbatim loosens, operator
// marker, keys2 disable, restrictive-options note.
func TestRenderJSONSecurity(t *testing.T) {
	cfg, plans := securityPlans(t)
	out := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply", DryRun: true})
	checkGolden(t, "json_security.golden.json", out)
	d := decodeDoc(t, out)
	s := d.Servers[serverNamed(t, d, "web-1")]
	if !s.Disables {
		t.Error("disables_authorized_keys2 = false, want true (keys2 found on a change plan)")
	}
	var found bool
	for _, rw := range s.Changes.Rewrite {
		ls, _ := rw["loosens"].([]any)
		for _, l := range ls {
			if l == `from="10.0.0.5"` {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no rewrite loosens the verbatim from=\"10.0.0.5\":\n%s", out)
	}
}

// TestRenderJSONOutcomes: applied/refused/failed/pending, and a pending
// server that never started carries error_kind "canceled".
func TestRenderJSONOutcomes(t *testing.T) {
	srv := func(n string) config.Server {
		return config.Server{Name: n, Host: "10.0.0.1", Port: 22, User: "deploy"}
	}
	plans := []ServerPlan{
		{Server: srv("a"), Class: ClassChange, Outcome: OutcomeApplied},
		{Server: srv("b"), Class: ClassChange, Outcome: OutcomePending, OutcomeErr: errInterrupted},
		{Server: srv("c"), Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: errors.New("verify\nfailed")},
		{Server: srv("d"), Class: ClassChange, Outcome: OutcomeRefused, OutcomeErr: errors.New("target is a symlink")},
	}
	out := renderJSONCfg(t, mixedCfg(t), plans, JSONOptions{Command: "apply"})
	checkGolden(t, "json_outcomes.golden.json", out)
	d := decodeDoc(t, out)
	want := map[string][2]string{"a": {"applied", ""}, "b": {"pending", "canceled"}, "c": {"failed", ""}, "d": {"refused", ""}}
	for name, w := range want {
		s := d.Servers[serverNamed(t, d, name)]
		if s.Outcome == nil || *s.Outcome != w[0] || s.ErrorKind != w[1] {
			t.Errorf("%s = outcome %v kind %q, want %v", name, s.Outcome, s.ErrorKind, w)
		}
	}
	if c := d.Servers[serverNamed(t, d, "c")]; c.Error == nil || *c.Error != "verify failed" {
		t.Errorf("error text not collapsed to one line: %v", c.Error)
	}
	if a := d.Servers[serverNamed(t, d, "a")]; a.Error != nil {
		t.Errorf("applied server error = %v, want null", *a.Error)
	}
	if d.Summary["converged"] != 1 || d.Summary["applied"] != 1 || d.Summary["pending"] != 1 ||
		d.Summary["failed"] != 1 || d.Summary["refused"] != 1 || d.Summary["exit_code"] != 1 {
		t.Errorf("summary = %v", d.Summary)
	}
}

// TestRenderJSONDetails covers what the fleet fixtures do not reach: the
// authorized_keys_file override, file_absent, every note, operator markers
// on add/remove/rewrite, and a rewrite changing options and comment at once.
func TestRenderJSONDetails(t *testing.T) {
	cfg := planCfg(t) // op (operator, k1), alice (k2), bob (k3)
	key := func(seed byte, comment string, options ...string) authkeys.Key {
		return authkeys.Key{Fingerprint: fp(t, seed), Type: "ssh-ed25519", Comment: comment, Options: options}
	}
	plans := []ServerPlan{{
		Server: config.Server{Name: "web-9", Host: "10.0.0.9", Port: 2222, User: "deploy",
			AuthorizedKeysFile: "/etc/ssh/keys/deploy"},
		Class: ClassChange, Outcome: OutcomePending, FileAbsent: true,
		Add:    []authkeys.Key{key(1, "")},
		Remove: []authkeys.Key{key(3, "bob@old-laptop")},
		Rewrites: []RewriteRow{{
			Key:            key(1, "", "no-pty"),
			ActualComment:  "op@old",
			DesiredComment: "op@sshepherd",
			ActualOptions:  []string{`expiry-time="20270101"`, "no-pty"},
			CommentDiffers: true,
			OptionsDiffer:  true,
			Loosens:        []string{`expiry-time="20270101"`},
		}},
		Normalize: Normalize{Reorder: true, Whitespace: true},
		Note:      "removes the key this session logged in with; op remains",
		Warning:   "every remaining key you hold carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked",
		AgentOnly: "only SHA256:x (agent) keeps access; none of your --identity keys survives — a run without this agent will be locked out",
	}}
	out := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply", DryRun: true})
	checkGolden(t, "json_details.golden.json", out)

	var doc struct {
		Servers []struct {
			AuthorizedKeysFile string            `json:"authorized_keys_file"`
			FileAbsent         bool              `json:"file_absent"`
			Notes              map[string]string `json:"notes"`
			Changes            struct {
				Add     []map[string]any `json:"add"`
				Remove  []map[string]any `json:"remove"`
				Rewrite []map[string]any `json:"rewrite"`
			} `json:"changes"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	s := doc.Servers[0]
	if s.AuthorizedKeysFile != "/etc/ssh/keys/deploy" || !s.FileAbsent {
		t.Errorf("override/file_absent = %q/%v", s.AuthorizedKeysFile, s.FileAbsent)
	}
	for _, n := range []string{"guard", "restrictive_options", "agent_only_survivors"} {
		if s.Notes[n] == "" {
			t.Errorf("notes.%s missing: %v", n, s.Notes)
		}
	}
	if s.Changes.Add[0]["operator"] != true || s.Changes.Rewrite[0]["operator"] != true {
		t.Errorf("operator key lacks the operator marker on add/rewrite:\n%s", out)
	}
	if s.Changes.Add[0]["comment"] != "op@sshepherd" {
		t.Errorf("add comment = %v, want the decided comment op@sshepherd", s.Changes.Add[0]["comment"])
	}
	if _, has := s.Changes.Remove[0]["operator"]; has {
		t.Errorf("non-operator key carries operator: %v", s.Changes.Remove[0])
	}
	rw := s.Changes.Rewrite[0]
	if rw["options_change"] == nil || rw["comment_change"] == nil {
		t.Errorf("rewrite lacks options_change or comment_change: %v", rw)
	}
}

// TestRenderJSONRevoke: former_owner on keys the edit removed, the edit
// section with emptied servers, saved carried.
func TestRenderJSONRevoke(t *testing.T) {
	former := planCfg(t) // op k1 operator, alice k2, bob k3 on web-1
	edited, err := config.Parse([]byte(`
users:
  - {name: op, operator: true, comment: "op@sshepherd", keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
`))
	if err != nil {
		t.Fatal(err)
	}
	content := testkeys.Line(t, 1) + " op@sshepherd\n" + testkeys.Line(t, 2) + " alice@work\n" +
		testkeys.Line(t, 3) + " bob\n" + testkeys.Line(t, 9) + " stray\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	plans := buildPlans(t, edited, r, []string{fp(t, 1)})
	sum := EditSummary{
		Edits:    []Edit{{Kind: EditRemoveUser, User: "alice", Keys: 1, Grants: 1}},
		Affected: 1,
		Emptied:  []EmptiedServer{{Server: "db-1", Users: []string{"carol"}, Keys: 1}},
	}
	out := renderJSONCfg(t, edited, plans, JSONOptions{Command: "revoke", Former: former, Edit: &sum, Saved: true})
	checkGolden(t, "json_revoke.golden.json", out)

	var doc struct {
		Edit struct {
			Saved     bool             `json:"saved"`
			Edits     []map[string]any `json:"edits"`
			Operators []string         `json:"operators"`
			Emptied   []map[string]any `json:"emptied"`
		} `json:"edit"`
		Servers []struct {
			Changes struct {
				Remove []map[string]any `json:"remove"`
			} `json:"changes"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Edit.Saved || doc.Edit.Operators == nil || len(doc.Edit.Emptied) != 1 {
		t.Errorf("edit = %+v", doc.Edit)
	}
	e := doc.Edit.Edits[0]
	if e["kind"] != "remove-user" || e["keys"] != float64(1) || e["grants"] != float64(1) {
		t.Errorf("edit entry = %v", e)
	}
	for _, f := range []string{"no_keys_left", "clears_operator", "fingerprint", "new_fingerprint", "keeps_expiry"} {
		if _, has := e[f]; has {
			t.Errorf("remove-user carries %q: %v", f, e)
		}
	}
	formers := map[string]bool{}
	var stray bool
	for _, k := range doc.Servers[0].Changes.Remove {
		if fo, ok := k["former_owner"].(string); ok {
			formers[fo] = true
			if k["owner"] != nil {
				t.Errorf("former-owned key has owner %v", k["owner"])
			}
		} else if k["comment"] == "stray" {
			stray = true // a key neither config owns: no former_owner
		}
	}
	if !formers["alice"] || !formers["bob"] || !stray {
		t.Errorf("former_owner set = %v (stray without former_owner: %v), want alice and bob", formers, stray)
	}
}

// TestRenderJSONEditOnly: rotate --no-apply — edit section, no servers,
// counts 0, exit 0; field presence per kind (keeps_expiry, zero-valued
// remove-key flags still present).
func TestRenderJSONEditOnly(t *testing.T) {
	sum := EditSummary{
		Edits: []Edit{
			{Kind: EditRotate, User: "deploy", Fingerprint: fp(t, 4), NewFingerprint: fp(t, 5), KeepsExpiry: `expiry-time="20270101"`},
			{Kind: EditRemoveKey, User: "bob", Fingerprint: fp(t, 3)},
		},
		Affected: 2,
	}
	out := renderJSONCfg(t, planCfg(t), nil, JSONOptions{Command: "rotate", Edit: &sum, Saved: true})
	checkGolden(t, "json_rotate_edit_only.golden.json", out)
	if !strings.Contains(string(out), `"no_keys_left": false`) || !strings.Contains(string(out), `"clears_operator": false`) {
		t.Errorf("remove-key flags must be present even when false:\n%s", out)
	}
	if !strings.Contains(string(out), `"emptied": []`) || !strings.Contains(string(out), `"operators": []`) {
		t.Errorf("empty edit lists must encode as []:\n%s", out)
	}
	d := decodeDoc(t, out)
	if len(d.Servers) != 0 || d.Summary["exit_code"] != 0 || d.Summary["servers"] != 0 || d.Edit == nil || !d.Edit.Saved {
		t.Errorf("edit-only doc = %+v", d)
	}
}

// TestRenderJSONWithheld: the nothing-can-land / save-withheld document —
// saved false, change servers pending.
func TestRenderJSONWithheld(t *testing.T) {
	cfg, plans := mixedPlans(t)
	sum := EditSummary{
		Edits:     []Edit{{Kind: EditRemoveUser, User: "carol", Keys: 1, Grants: 1}},
		Affected:  4,
		Operators: []string{"carol"},
	}
	out := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "revoke", Edit: &sum, Saved: false})
	checkGolden(t, "json_withheld.golden.json", out)
	d := decodeDoc(t, out)
	if d.Edit == nil || d.Edit.Saved {
		t.Errorf("edit.saved must be false: %+v", d.Edit)
	}
	for _, s := range d.Servers {
		if s.Class == "change" && (s.Outcome == nil || *s.Outcome != "pending") {
			t.Errorf("%s outcome = %v on a withheld run, want pending", s.Name, s.Outcome)
		}
	}
}

// TestRenderJSONSanitizes: ESC, C1 CSI and a bidi override in an on-server
// comment, an option and an error string never reach the document raw.
func TestRenderJSONSanitizes(t *testing.T) {
	const hostile = "x" + string(rune(0x1b)) + "[31m" + string(rune(0x9b)) + "2J" + string(rune(0x202e)) + "y" // ESC, C1 CSI, RLO
	cfg := planCfg(t)
	content := testkeys.Line(t, 1) + " op@sshepherd\n" +
		`from="10.0.0.5` + hostile + `" ` + testkeys.Line(t, 2) + " alice@work\n" +
		testkeys.Line(t, 9) + " " + hostile + "\n" +
		`command="/bin/` + hostile + `" ` + testkeys.Line(t, 8) + " backup@nas\n"
	r := &fakeReader{
		byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}},
	}
	plans := buildPlans(t, cfg, r, []string{fp(t, 1)})
	plans = append(plans, ServerPlan{
		Server: config.Server{Name: "evil"}, Class: ClassUnreachable,
		Err: errors.New("banner " + hostile),
	})
	out := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply", DryRun: true})
	d := decodeDoc(t, out)
	w1 := d.Servers[serverNamed(t, d, "web-1")]
	if w1.Class != "change" || len(w1.Changes.Rewrite) == 0 || len(w1.Changes.Remove) == 0 {
		t.Fatalf("fixture must reach the option rewrite and the hostile remove comment:\n%s", out)
	}
	var decoded any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	var walk func(any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			for _, r := range x {
				if r == 0x1b || r == 0x9b || r == 0x202e {
					t.Errorf("hostile rune %U survived in %q", r, x)
				}
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(decoded)
	// The unowned remove key's on-server options arrive sanitized.
	var doc jsonDoc
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, k := range doc.Servers[serverNamed(t, d, "web-1")].Changes.Remove {
		if k.Fingerprint == fp(t, 8) {
			found = true
			if want := []string{`command="/bin/x[31m2Jy"`}; !slices.Equal(k.Options, want) {
				t.Errorf("remove options = %q, want %q", k.Options, want)
			}
		}
	}
	if !found {
		t.Errorf("fixture lacks the optioned remove key:\n%s", out)
	}
}

// TestRenderJSONHintAndRemoveOptions: unreachable and failed servers carry
// the hint beside, never inside, error; remove keys carry on-server options.
func TestRenderJSONHintAndRemoveOptions(t *testing.T) {
	cfg, plans := mixedPlans(t)
	plans = append(plans, ServerPlan{Server: config.Server{Name: "w"}, Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: dialRefused("10.0.0.7")})
	var buf bytes.Buffer
	if err := RenderJSON(&buf, cfg, plans, JSONOptions{Command: "apply", DryRun: true}); err != nil {
		t.Fatal(err)
	}
	var doc jsonDoc
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, s := range doc.Servers {
		if s.Name != "web-3" && s.Name != "w" {
			if s.Hint != "" {
				t.Errorf("%s: unexpected hint %q", s.Name, s.Hint)
			}
			continue
		}
		if s.ErrorKind != "dial" || s.Hint != sshconn.DialHint || strings.Contains(*s.Error, "hint") {
			t.Errorf("%s: error %q kind %q hint %q", s.Name, *s.Error, s.ErrorKind, s.Hint)
		}
	}
}

// TestRenderJSONRemoveOptionsOnlyUnowned: changes.remove[].options is only
// for a key neither the manifest nor the pre-edit manifest owns. A key the
// rendered manifest owns (bob's key, removed here) and one the edit removed
// (former_owner carol) carry no options even when the on-server line has
// them.
func TestRenderJSONRemoveOptionsOnlyUnowned(t *testing.T) {
	cfg := planCfg(t) // op (operator, k1), alice (k2), bob (k3)
	former, err := config.Parse([]byte(`
users:
  - {name: carol, keys: ["` + testkeys.Line(t, 6) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: carol, servers: [web-1]}
`))
	if err != nil {
		t.Fatal(err)
	}
	key := func(seed byte) authkeys.Key {
		return authkeys.Key{Fingerprint: fp(t, seed), Type: "ssh-ed25519", Options: []string{"no-pty"}}
	}
	plans := []ServerPlan{{
		Server: config.Server{Name: "web-1", Host: "10.0.0.1", Port: 22, User: "deploy"},
		Class:  ClassChange, Outcome: OutcomePending,
		Remove: []authkeys.Key{key(3), key(6), key(9)},
	}}
	var doc jsonDoc
	if err := json.Unmarshal(renderJSONCfg(t, cfg, plans, JSONOptions{Command: "revoke", Former: former}), &doc); err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{fp(t, 3): nil, fp(t, 6): nil, fp(t, 9): {"no-pty"}}
	rm := doc.Servers[0].Changes.Remove
	if len(rm) != len(want) {
		t.Fatalf("remove = %+v, want 3 keys", rm)
	}
	for _, k := range rm {
		if w, ok := want[k.Fingerprint]; !ok || !slices.Equal(k.Options, w) {
			t.Errorf("remove %s options = %q, want %q", k.Fingerprint, k.Options, w)
		}
	}
}

func TestRenderJSONDryRunAllPending(t *testing.T) {
	cfg, plans := mixedPlans(t)
	d := decodeDoc(t, renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply", DryRun: true}))
	for _, s := range d.Servers {
		if s.Class == "change" && *s.Outcome != "pending" {
			t.Errorf("%s outcome = %q under --dry-run", s.Name, *s.Outcome)
		}
	}
}

// TestRenderJSONRemoveAccess: a remove-access entry carries exactly its
// fields — access_servers ([] never null), the four counts and
// no_grants_left, zero/false included — and no other kind's.
func TestRenderJSONRemoveAccess(t *testing.T) {
	sum := EditSummary{
		Edits: []Edit{
			{Kind: EditRemoveAccess, User: "bob", AccessServers: []string{"web-1", "db-1"}, EntriesChanged: 1, EntriesRemoved: 1, ServersExcepted: 1},
			{Kind: EditRemoveAccess, User: "carol", EntriesRemoved: 1, WildcardsRemoved: 1, NoGrantsLeft: true},
		},
		Affected: 2,
	}
	out := renderJSONCfg(t, planCfg(t), nil, JSONOptions{Command: "revoke", Edit: &sum, Saved: true})
	checkGolden(t, "json_remove_access.golden.json", out)
	var doc struct {
		Edit struct {
			Edits []map[string]any `json:"edits"`
		} `json:"edit"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	bob, carol := doc.Edit.Edits[0], doc.Edit.Edits[1]
	for _, k := range []string{"access_servers", "entries_changed", "entries_removed", "servers_excepted", "wildcards_removed", "no_grants_left"} {
		if _, ok := bob[k]; !ok {
			t.Errorf("remove-access entry lacks %q: %v", k, bob)
		}
	}
	for _, k := range []string{"keys", "grants", "fingerprint", "no_keys_left", "clears_operator", "keep_old"} {
		if _, ok := bob[k]; ok {
			t.Errorf("remove-access entry carries another kind's %q: %v", k, bob)
		}
	}
	if bob["wildcards_removed"] != float64(0) || bob["no_grants_left"] != false {
		t.Errorf("zero values must be present: %v", bob)
	}
	if s, ok := carol["access_servers"].([]any); !ok || len(s) != 0 {
		t.Errorf("empty access_servers = %v, want []", carol["access_servers"])
	}
	if carol["no_grants_left"] != true || carol["wildcards_removed"] != float64(1) {
		t.Errorf("carol = %v", carol)
	}
}

// TestRenderJSONKeepOld: keep_old is present on every rotate entry — true
// for --keep-old, false for a plain rotate — and on no other kind.
func TestRenderJSONKeepOld(t *testing.T) {
	sum := EditSummary{
		Edits:    []Edit{{Kind: EditRotate, User: "bob", Fingerprint: fp(t, 4), NewFingerprint: fp(t, 5), KeepOld: true}},
		Affected: 3,
	}
	out := renderJSONCfg(t, planCfg(t), nil, JSONOptions{Command: "rotate", Edit: &sum, Saved: true})
	checkGolden(t, "json_rotate_keep_old.golden.json", out)
	if !strings.Contains(string(out), `"keep_old": true`) {
		t.Errorf("keep_old missing:\n%s", out)
	}
	plain := EditSummary{Edits: []Edit{
		{Kind: EditRotate, User: "bob", Fingerprint: fp(t, 4), NewFingerprint: fp(t, 5)},
		{Kind: EditRemoveKey, User: "bob", Fingerprint: fp(t, 3)},
	}}
	out = renderJSONCfg(t, planCfg(t), nil, JSONOptions{Command: "rotate", Edit: &plain})
	if strings.Count(string(out), `"keep_old"`) != 1 || !strings.Contains(string(out), `"keep_old": false`) {
		t.Errorf("want keep_old: false on the rotate entry only:\n%s", out)
	}
}

// TestRenderJSONRewriteWidens: a rewrite that adds relaxing options carries
// them as widens; one that adds none carries widens: [] (always present,
// like loosens).
func TestRenderJSONRewriteWidens(t *testing.T) {
	plans := []ServerPlan{{
		Server: srv("web-1"), Class: ClassChange, Outcome: OutcomePending,
		Rewrites: []RewriteRow{
			{Key: testKey(t, 1), Widens: []string{"no-touch-required"}},
			{Key: testKey(t, 2), CommentDiffers: true, ActualComment: "a", DesiredComment: "b"},
		},
	}}
	out := renderJSONCfg(t, planCfg(t), plans, JSONOptions{Command: "apply", DryRun: true})
	d := decodeDoc(t, out)
	rw := d.Servers[0].Changes.Rewrite
	if len(rw) != 2 {
		t.Fatalf("rewrite = %v, want 2 rows", rw)
	}
	if got := fmt.Sprint(rw[0]["widens"]); got != "[no-touch-required]" {
		t.Errorf("widens = %s, want [no-touch-required]:\n%s", got, out)
	}
	if w, ok := rw[1]["widens"].([]any); !ok || len(w) != 0 {
		t.Errorf("a rewrite without widening must carry widens: [], got %v:\n%s", rw[1]["widens"], out)
	}
}

// srv is a bare server named name, enough for jsonErrorFor.
func srv(name string) config.Server { return config.Server{Name: name} }

// writeKindErr stands in for a classified transport error (sshconn.Error)
// that reaches a plan's OutcomeErr through sshwrite's wrappers.
type writeKindErr struct{ kind audit.ErrorKind }

func (e writeKindErr) Error() string              { return "ssh deploy@10.0.0.1:22: knownhosts: key mismatch" }
func (e writeKindErr) ErrorKind() audit.ErrorKind { return e.kind }

// TestJSONErrorKindWritePhase: a write-phase failure keeps the kind the
// transport attached (ARC-3), so a host key that changed between plan and
// write is distinguishable from an ordinary verify failure. Unclassified
// write errors and refusals keep no kind, so existing documents are unchanged.
func TestJSONErrorKindWritePhase(t *testing.T) {
	tests := []struct {
		name string
		p    ServerPlan
		want string
	}{
		{"host key changed at write connect", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: fmt.Errorf("write on a: %w", writeKindErr{audit.ErrorKindHostKeyChanged})}, "host_key_changed"},
		{"dial at write connect", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: writeKindErr{audit.ErrorKindDial}}, "dial"},
		{"unclassified verify failure", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: errors.New("verify failed")}, ""},
		{"refusal", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomeRefused,
			OutcomeErr: errors.New("target is a symlink")}, ""},
		{"interrupted pending", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomePending,
			OutcomeErr: errInterrupted}, "canceled"},
		{"per-server deadline at write connect", ServerPlan{Server: srv("a"), Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: writeKindErr{audit.ErrorKindCanceled}}, "timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, kind, _ := jsonErrorFor(tt.p)
			if msg == nil || kind != tt.want {
				t.Errorf("jsonErrorFor = (%v, %q), want kind %q", msg, kind, tt.want)
			}
		})
	}
}

// TestJSONWriteConnectTimeoutIsTimeout: the per-server timeout firing
// during the write connect is a started server that failed — "timeout",
// never "canceled", which the document reserves for a pending server that
// never started. The write connect's AfterFunc cancels its detached ctx
// when the per-server deadline expires, so the transport sees a plain
// cancellation and classifies it "canceled" (ARC-3 repair).
func TestJSONWriteConnectTimeoutIsTimeout(t *testing.T) {
	hostKey := sshtest.Signer(t, sshtest.Key(200))
	s := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{hostKey}, Stall: true})
	w := &sshwrite.FleetWriter{Dialer: &sshconn.Dialer{
		KnownHostsPath: sshtest.KnownHostsFile(t, s.KnownHostsLine(hostKey.PublicKey())),
		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))},
		DialTimeout:    5 * time.Second,
	}}
	held := testKey(t, 1)
	p := changePlan("web-1", held)
	p.Server = config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
	plans := []ServerPlan{p}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, PerServerTimeout: 200 * time.Millisecond, Held: agentHeld(held.Fingerprint)})

	if plans[0].Outcome != OutcomeFailed {
		t.Fatalf("Outcome = %s (err %v), want failed", plans[0].Outcome, plans[0].OutcomeErr)
	}
	if msg, kind, _ := jsonErrorFor(plans[0]); msg == nil || kind != string(audit.ErrorKindTimeout) {
		t.Errorf("jsonErrorFor = (%v, %q), want kind timeout", msg, kind)
	}
}
