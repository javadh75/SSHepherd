package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func renderJSON(t *testing.T, cfg *config.Config, results []ServerResult) []byte {
	t.Helper()
	return renderJSONOpts(t, cfg, results, JSONOptions{})
}

func renderJSONOpts(t *testing.T, cfg *config.Config, results []ServerResult, opts JSONOptions) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderJSON(&buf, cfg, results, opts); err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatalf("RenderJSON produced invalid JSON:\n%s", buf.String())
	}
	return buf.Bytes()
}

func TestRenderJSONDriftGolden(t *testing.T) {
	cfg := reportConfig(t)
	got := renderJSON(t, cfg, driftResults(t, cfg))
	checkGolden(t, "report_drift.golden.json", got)
}

func TestRenderJSONRevokedGolden(t *testing.T) {
	// revoked[2]: an access conflict; [3] an unknown server (D1e); [4] an
	// unknown server with a control rune (plan decision 3: a warning, and
	// sanitized here); [5] key 8, unlabelled, installed on web-2.
	cfg := memoryConfig(t, "  - {user: alice, servers: [web-1], date: 2026-11-08}\n  - {user: alice, servers: [db-9], date: 2026-11-08}\n"+
		"  - {user: alice, servers: [\"db\\e9\"], date: 2026-11-08}\n  - {fingerprint: "+fpOf(t, 8)+", date: 2026-11-08}\n")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3, 9}, []byte{1, 2, 3, 8}))
	got := renderJSON(t, cfg, res)
	checkGolden(t, "report_revoked.golden.json", got)
	for _, want := range []string{
		`"manifest_serial": 7`, `"policy_conflicts": [`, `"kind": "revoked_access"`, `"manifest_warnings": [`,
		`"kind": "tombstone_unknown_server"`, `"revoked_keys": 2`, `"policy_conflicts": 1`,
		`"revoked": {`, `"user": "carol"`, `"reason": "offboarded"`, `"access_revoked": {`, `"status": "critical"`,
	} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("document lacks %s", want)
		}
	}
	if bytes.ContainsRune(got, 0x1b) || bytes.Contains(got, []byte(`\u001b`)) {
		t.Errorf("a control rune from the manifest reached the document:\n%s", got)
	}
	// spec §9: an unlabelled tombstone's revoked object has no "user".
	var doc struct {
		Servers []struct {
			Keys struct {
				Unauthorized []struct {
					Fingerprint string         `json:"fingerprint"`
					Revoked     map[string]any `json:"revoked"`
				} `json:"unauthorized"`
			} `json:"keys"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range doc.Servers {
		for _, k := range s.Keys.Unauthorized {
			if k.Fingerprint == fpOf(t, 8) {
				_, hasUser := k.Revoked["user"]
				found = k.Revoked["date"] == "2026-11-08" && !hasUser
			}
		}
	}
	if !found {
		t.Errorf("key 8's revoked object must be {date} with no user:\n%s", got)
	}
}

func TestRenderJSONSerialAheadGolden(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(8), []byte{1, 2, 3}, []byte{1, 2}))
	res[1].HeaderSerial = 9999
	got := renderJSON(t, cfg, res)
	checkGolden(t, "report_serial_ahead.golden.json", got)
	for _, want := range []string{`"header_serial": 8`, `"manifest_serial_ahead": 8`, `"forged_header_serial": 9999`} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("document lacks %s", want)
		}
	}
}

func TestRenderJSONCriticalGolden(t *testing.T) {
	cfg := operatorConfig(t)
	got := renderJSON(t, cfg, criticalResults(t, cfg))
	checkGolden(t, "report_critical.golden.json", got)
}

func TestRenderJSONEmptyFleet(t *testing.T) {
	got := renderJSON(t, &config.Config{}, nil)
	var rep struct {
		Schema  int `json:"schema"`
		Summary struct {
			Servers  int `json:"servers"`
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
		Servers []json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(got, &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Schema != 1 || rep.Summary.Servers != 0 || rep.Summary.ExitCode != 0 {
		t.Errorf("empty fleet = schema %d, servers %d, exit %d; want 1, 0, 0",
			rep.Schema, rep.Summary.Servers, rep.Summary.ExitCode)
	}
	if rep.Servers == nil || len(rep.Servers) != 0 {
		t.Errorf("servers must be an empty array, not null: %s", got)
	}
}

// jsonReportView mirrors the load-bearing shape for round-trip assertions.
type jsonReportView struct {
	Schema  int `json:"schema"`
	Summary struct {
		Servers, Compliant, Drift, Critical, Unreachable int
		ExitCode                                         int `json:"exit_code"`
	} `json:"summary"`
	Servers []struct {
		Name   string  `json:"name"`
		Status string  `json:"status"`
		Error  *string `json:"error"`
		Keys   struct {
			Present, Missing, Unauthorized []struct {
				Owner       *string `json:"owner"`
				Comment     string  `json:"comment"`
				Fingerprint string  `json:"fingerprint"`
				Type        string  `json:"type"`
				Operator    bool    `json:"operator"`
			}
		} `json:"keys"`
		ParseErrors []struct {
			Line  int    `json:"line"`
			Error string `json:"error"`
		} `json:"parse_errors"`
		FileAbsent bool `json:"file_absent"`
	} `json:"servers"`
}

// TestRenderJSONRoundTrip pins field semantics on the drift fixture:
// web-1 has alice present, bob missing, one unknown unauthorized key and one
// parse error; web-2 is unreachable.
func TestRenderJSONRoundTrip(t *testing.T) {
	cfg := reportConfig(t)
	var rep jsonReportView
	if err := json.Unmarshal(renderJSON(t, cfg, driftResults(t, cfg)), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Summary.ExitCode != 1 || rep.Summary.Drift != 1 || rep.Summary.Unreachable != 1 {
		t.Errorf("summary = %+v, want drift 1, unreachable 1, exit 1", rep.Summary)
	}
	if len(rep.Servers) != 2 {
		t.Fatalf("servers = %d, want 2", len(rep.Servers))
	}
	web1, web2 := rep.Servers[0], rep.Servers[1]
	if web1.Status != "drift" || web2.Status != "unreachable" {
		t.Errorf("statuses = %q, %q; want drift, unreachable", web1.Status, web2.Status)
	}
	if web2.Error == nil || *web2.Error == "" {
		t.Error("unreachable server must carry its error string")
	}
	if len(web1.Keys.Unauthorized) != 1 || web1.Keys.Unauthorized[0].Owner != nil {
		t.Errorf("unauthorized = %+v, want one entry with null owner", web1.Keys.Unauthorized)
	}
	if got := web1.Keys.Unauthorized[0].Comment; got != "who@is-this" {
		t.Errorf("unauthorized comment = %q, want the inline comment as identity hint", got)
	}
	if len(web1.ParseErrors) != 1 || web1.ParseErrors[0].Line != 3 {
		t.Errorf("parse_errors = %+v, want line 3", web1.ParseErrors)
	}
	if len(web1.Keys.Missing) != 1 || web1.Keys.Missing[0].Operator {
		t.Errorf("missing = %+v, want bob without operator marker", web1.Keys.Missing)
	}
}

// TestRenderJSONOperatorMarker: only missing operator-owned keys carry
// operator: true — the JSON twin of the CRITICAL rendering.
func TestRenderJSONOperatorMarker(t *testing.T) {
	cfg := operatorConfig(t)
	var rep jsonReportView
	if err := json.Unmarshal(renderJSON(t, cfg, criticalResults(t, cfg)), &rep); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if rep.Summary.ExitCode != 2 || rep.Summary.Critical != 2 {
		t.Errorf("summary = %+v, want critical 2, exit 2", rep.Summary)
	}
	var operatorMarks int
	for _, s := range rep.Servers {
		if s.Status != "critical" {
			t.Errorf("server %s status = %q, want critical", s.Name, s.Status)
		}
		for _, k := range s.Keys.Missing {
			if k.Operator {
				operatorMarks++
				if k.Owner == nil || *k.Owner != "op" {
					t.Errorf("operator-marked key owner = %v, want op", k.Owner)
				}
			}
		}
		if s.Name == "web-2" && !s.FileAbsent {
			t.Error("web-2 must carry file_absent: true")
		}
	}
	if operatorMarks != 2 {
		t.Errorf("operator-marked missing keys = %d, want 2 (one per server)", operatorMarks)
	}
}

// TestRenderJSONAuthorizedKeysFile pins the additive optional field
// (schema stays 1): servers[].authorized_keys_file appears exactly when the
// manifest sets the override — omitempty keeps override-free reports (and
// every existing JSON golden) byte-identical.
func TestRenderJSONAuthorizedKeysFile(t *testing.T) {
	t.Run("set: field emitted", func(t *testing.T) {
		cfg := overrideConfig(t, "/etc/ssh/keys/deploy")
		reader := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {FileAbsent: true}}}
		results := Run(context.Background(), cfg, reader, Options{Parallel: 1})
		var rep struct {
			Servers []map[string]json.RawMessage `json:"servers"`
		}
		if err := json.Unmarshal(renderJSON(t, cfg, results), &rep); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		raw, ok := rep.Servers[0]["authorized_keys_file"]
		if !ok {
			t.Fatal("authorized_keys_file missing from server record with an override set")
		}
		if got := string(raw); got != `"/etc/ssh/keys/deploy"` {
			t.Errorf("authorized_keys_file = %s, want \"/etc/ssh/keys/deploy\"", got)
		}
	})
	t.Run("unset: field omitted", func(t *testing.T) {
		cfg := reportConfig(t)
		var rep struct {
			Servers []map[string]json.RawMessage `json:"servers"`
		}
		if err := json.Unmarshal(renderJSON(t, cfg, driftResults(t, cfg)), &rep); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		for _, s := range rep.Servers {
			if _, ok := s["authorized_keys_file"]; ok {
				t.Errorf("authorized_keys_file emitted for a server without an override: %s", s["name"])
			}
		}
	})
}

// commentDriftView decodes present keys as raw maps so key presence/absence
// of comment_drift is assertable, not just its value.
type commentDriftView struct {
	Summary struct {
		ExitCode int `json:"exit_code"`
	} `json:"summary"`
	Servers []struct {
		Name string `json:"name"`
		Keys struct {
			Present []map[string]json.RawMessage `json:"present"`
		} `json:"keys"`
	} `json:"servers"`
}

// TestRenderJSONCommentDrift pins the opt-in additive field (schema stays 1):
// with Comments on, a present key whose actual comment differs from the
// desired one gains comment_drift{actual, desired}; matching keys and
// flag-off runs never emit the field. Exit code stays 0 throughout.
func TestRenderJSONCommentDrift(t *testing.T) {
	cfg := reportConfig(t)
	results := commentDriftResults(t, cfg)

	t.Run("flag on: set exactly where drifting", func(t *testing.T) {
		var rep commentDriftView
		if err := json.Unmarshal(renderJSONOpts(t, cfg, results, JSONOptions{Comments: true}), &rep); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if rep.Summary.ExitCode != 0 {
			t.Errorf("exit_code = %d, want 0 (comment drift is informational)", rep.Summary.ExitCode)
		}
		web1 := rep.Servers[0]
		if len(web1.Keys.Present) != 2 {
			t.Fatalf("web-1 present = %d keys, want 2", len(web1.Keys.Present))
		}
		raw, ok := web1.Keys.Present[0]["comment_drift"] // alice: drifting
		if !ok {
			t.Fatal("alice's drifting key lacks comment_drift")
		}
		var d struct{ Actual, Desired string }
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("unmarshal comment_drift: %v", err)
		}
		if d.Actual != "alice@laptop" || d.Desired != "alice@sshepherd" {
			t.Errorf("comment_drift = %+v, want alice@laptop → alice@sshepherd", d)
		}
		if _, ok := web1.Keys.Present[1]["comment_drift"]; ok {
			t.Error("bob's matching key must not carry comment_drift")
		}
		if _, ok := rep.Servers[1].Keys.Present[0]["comment_drift"]; ok {
			t.Error("web-2's matching key must not carry comment_drift")
		}
	})
	t.Run("flag off: never emitted", func(t *testing.T) {
		got := renderJSONOpts(t, cfg, results, JSONOptions{})
		if strings.Contains(string(got), "comment_drift") {
			t.Errorf("comment_drift emitted without the flag:\n%s", got)
		}
	})
}

// TestRenderJSONHostileErrorEscaped: even if a raw control byte reaches the
// renderer, it never reaches the output — not raw, and (since the
// 2026-11-07 sanitizing fix) not as a JSON \u001b escape either, so a
// consumer decoding the document cannot get it back. Newlines collapse.
func TestRenderJSONHostileErrorEscaped(t *testing.T) {
	cfg := reportConfig(t)
	results := []ServerResult{{
		Server: cfg.Servers[0],
		Err:    errors.New("dial failed\nSummary: 99/99 compliant \x1b[31mred"),
	}}
	got := renderJSON(t, cfg, results)
	if bytes.ContainsRune(got, 0x1b) {
		t.Errorf("raw ESC byte survived into JSON output:\n%s", got)
	}
	if strings.Contains(string(got), `\u001b`) {
		t.Errorf("ESC must be stripped, not JSON-escaped as \\u001b, got:\n%s", got)
	}
	if !strings.Contains(string(got), `"error": "dial failed Summary: 99/99 compliant [31mred"`) {
		t.Errorf("error not collapsed and stripped as expected:\n%s", got)
	}
}

// TestRenderJSONSanitizesHostileText: on-server comments, options (drift
// actual) and error strings carrying ESC / C1 CSI / bidi-override runes
// never reach audit --json — not raw, and not JSON-escaped either (a
// consumer decoding the document must not get them back).
func TestRenderJSONSanitizesHostileText(t *testing.T) {
	const hostile = "x\x1b[31m\u009b2J\u202ey"
	cfg := reportConfig(t)
	content := `environment="A=` + hostile + `" ` + testkeys.Line(t, 1) + " " + hostile + "\n" +
		testkeys.Line(t, 2) + "\n" +
		testkeys.Line(t, 9) + " " + hostile + "\n"
	reader := &fakeReader{
		byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(content)}},
		errs:   map[string]error{"web-2": errors.New("banner " + hostile)},
	}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 1})
	if len(results[0].Diff.Unauthorized) != 1 || len(results[0].Diff.OK) != 2 {
		t.Fatalf("fixture did not parse as intended: %+v", results[0])
	}
	got := renderJSONOpts(t, cfg, results, JSONOptions{Comments: true})
	for _, want := range []string{`"options_drift"`, `"comment_drift"`, `"error": "banner x[31m2Jy"`} {
		if !strings.Contains(string(got), want) {
			t.Errorf("output lacks %s:\n%s", want, got)
		}
	}
	var decoded any
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
	flat := fmt.Sprint(decoded)
	for _, r := range []rune{0x1b, 0x9b, 0x202e} {
		if strings.ContainsRune(flat, r) {
			t.Errorf("hostile rune %U survived:\n%s", r, got)
		}
	}
}

// TestRenderJSONHintField: hint is additive and separate — error holds only
// the error, hint the sanitized remediation, absent when there is none.
func TestRenderJSONHintField(t *testing.T) {
	cfg := reportConfig(t)
	hostile := hintedErr{kindedErr{fleet.ErrorKindDial, "dial tcp 10.0.0.2:22: connect: connection refused"}, "fix\nit \x1b[31mnow\u202e"}
	var rep jsonReport
	raw := renderJSON(t, cfg, []ServerResult{{Server: cfg.Servers[0], Err: hostile}, {Server: cfg.Servers[1], Err: errors.New("boom")}})
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	s0, s1 := rep.Servers[0], rep.Servers[1]
	if *s0.Error != "dial tcp 10.0.0.2:22: connect: connection refused" || s0.ErrorKind != "dial" || s0.Hint != "fix it [31mnow" {
		t.Errorf("server 0 = error %q kind %q hint %q", *s0.Error, s0.ErrorKind, s0.Hint)
	}
	if s1.Hint != "" || bytes.Count(raw, []byte(`"hint"`)) != 1 {
		t.Errorf("hint must be omitted when the error carries none:\n%s", raw)
	}
}

// TestRenderJSONUnauthorizedOptions: on-server options of an unowned key are
// additive `options` (sanitized), absent when the key has none \u2014 and absent
// on a key the manifest owns (bob's on web-2, where he has no grant) even
// when it carries options: `options` is only for a key nobody owns.
func TestRenderJSONUnauthorizedOptions(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(`no-pty,command="x` + "\u202e" + `" ` + testkeys.Line(t, 9) + " a@b\n" + testkeys.Line(t, 8) + "\n")},
		"web-2": {Content: []byte("no-pty " + testkeys.Line(t, 2) + " bob@laptop\n")},
	}}
	var rep jsonReport
	if err := json.Unmarshal(renderJSON(t, cfg, Run(context.Background(), cfg, reader, Options{Parallel: 1})), &rep); err != nil {
		t.Fatal(err)
	}
	u := rep.Servers[0].Keys.Unauthorized
	if len(u) != 2 || !slices.Equal(u[0].Options, []string{"no-pty", `command="x"`}) || u[1].Options != nil {
		t.Errorf("unauthorized = %+v, want options on the first key only, U+202E stripped", u)
	}
	owned := rep.Servers[1].Keys.Unauthorized
	if len(owned) != 1 || owned[0].Owner == nil || *owned[0].Owner != "bob" || owned[0].Options != nil {
		t.Errorf("web-2 unauthorized = %+v, want bob's owned key without options", owned)
	}
}
