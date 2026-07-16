package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
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
		reader := &fakeReader{byName: map[string]ReadResult{"web-1": {FileAbsent: true}}}
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
// renderer, the JSON encoding must escape it — no raw ESC in the output.
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
	if !strings.Contains(string(got), `\u001b`) {
		t.Errorf("ESC should be JSON-escaped as \\u001b, got:\n%s", got)
	}
}
