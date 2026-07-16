package audit

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
)

func renderJSON(t *testing.T, cfg *config.Config, results []ServerResult) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := RenderJSON(&buf, cfg, results); err != nil {
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
