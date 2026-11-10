package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// restrictCfg (spec S7): alice (k1) is granted @web with no-pty and web-1
// again with none, a restriction conflict on web-1 only; bob (k2) is granted
// both servers, carol (k3) web-1. web-2 renders alice's key with no-pty.
func restrictCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
access:
  - {user: alice, servers: ["@web"], options: [no-pty]}
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: [web-1, web-2]}
  - {user: carol, servers: [web-1]}
`))
	if err != nil {
		t.Fatalf("restrictCfg: %v", err)
	}
	return cfg
}

// restrictReader: web-1 holds alice with restrict (neither grant's set), bob
// with no-pty (drift: no grant gives bob options) and an unknown key k9;
// carol is missing. web-2 holds alice plain (drift: the manifest wants
// no-pty there) and bob.
func restrictReader(t *testing.T) *fakeReader {
	t.Helper()
	return &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: content("restrict "+testkeys.Line(t, 1), "no-pty "+testkeys.Line(t, 2), testkeys.Line(t, 9))},
		"web-2": {Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2))},
	}}
}

// TestRestrictionConflictAudit (spec S7 audit row): the conflict prints as
// critical and makes web-1 critical (exit 2); on web-1 the options
// comparison is skipped for alice only, while bob's drift, carol's missing
// key and the unknown key are still reported; web-2 compares alice against
// its own grant (no-pty).
func TestRestrictionConflictAudit(t *testing.T) {
	cfg := restrictCfg(t)
	results := Run(context.Background(), cfg, restrictReader(t), Options{Parallel: 2})
	if code := ExitCode(cfg, results); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
	if got, want := criticalReasons(cfg, results[0]), []string{"policy_conflict"}; !reflect.DeepEqual(got, want) {
		t.Errorf("web-1 criticalReasons = %v, want %v", got, want)
	}
	if s := statusOf(cfg, results[1]); s != statusDrift {
		t.Errorf("web-2 status = %s, want drift (alice lacks no-pty)", s)
	}
	for _, k := range results[0].Diff.OK { // the desired form; fpOf: internal/audit/audit_test.go
		if _, _, drifted := results[0].optionsDrift(k); drifted && k.Fingerprint == fpOf(t, 1) {
			t.Error("web-1: alice's options were compared despite the clash")
		}
	}
	if len(results[0].Diff.Missing) != 1 || len(results[0].Diff.Unauthorized) != 1 {
		t.Errorf("web-1 missing %d, unauthorized %d; want 1 and 1", len(results[0].Diff.Missing), len(results[0].Diff.Unauthorized))
	}

	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	if strings.Count(out, "OPTIONS DIFFER") != 2 { // bob on web-1, alice on web-2
		t.Errorf("want two OPTIONS DIFFER rows:\n%s", out)
	}
	if !strings.Contains(out, `manifest: user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[1] with no options`) {
		t.Errorf("the conflict is not printed:\n%s", out)
	}
	checkGolden(t, "report_restriction_conflict.golden", buf.Bytes())

	got := renderJSON(t, cfg, results)
	checkGolden(t, "report_restriction_conflict.golden.json", got)
	var doc struct {
		PolicyConflicts []map[string]any `json:"policy_conflicts"`
		Servers         []struct {
			Name string `json:"name"`
			Keys struct {
				Present []struct {
					Owner        *string         `json:"owner"`
					OptionsDrift json.RawMessage `json:"options_drift"`
				} `json:"present"`
			} `json:"keys"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.PolicyConflicts) != 1 || doc.PolicyConflicts[0]["kind"] != "restriction_conflict" ||
		doc.PolicyConflicts[0]["user"] != "alice" || doc.PolicyConflicts[0]["fingerprint"] != nil {
		t.Errorf("policy_conflicts = %+v", doc.PolicyConflicts)
	}
	drift := map[string]bool{}
	for _, s := range doc.Servers {
		for _, k := range s.Keys.Present {
			if k.Owner != nil && k.OptionsDrift != nil {
				drift[s.Name+"/"+*k.Owner] = true
			}
		}
	}
	if want := map[string]bool{"web-1/bob": true, "web-2/alice": true}; !reflect.DeepEqual(drift, want) {
		t.Errorf("options_drift on %v, want %v", drift, want)
	}
}

// TestRestrictionConflictUnderServer (OP4): an audit restricted to web-2
// still prints the conflict about web-1 and still exits 2.
func TestRestrictionConflictUnderServer(t *testing.T) {
	cfg := restrictCfg(t)
	results := Run(context.Background(), cfg, restrictReader(t), Options{Parallel: 1, Servers: []config.Server{cfg.Servers[1]}})
	if len(results) != 1 || ExitCode(cfg, results) != 2 {
		t.Fatalf("results = %d, ExitCode = %d; want 1 and 2", len(results), ExitCode(cfg, results))
	}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	if !strings.Contains(buf.String(), `user "alice": server "web-1" is granted by`) {
		t.Errorf("the conflict about web-1 is missing:\n%s", buf.String())
	}
}

// TestGrantOptionsDriftPerServer (spec S7 Tests): with no clash, audit
// compares each server against its own grant's options.
func TestGrantOptionsDriftPerServer(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1], options: ['from="10.0.0.0/8"']}
  - {user: alice, servers: [web-2]}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: content(`from="10.0.0.0/8" ` + testkeys.Line(t, 1))},
		"web-2": {Content: content(`from="10.0.0.0/8" ` + testkeys.Line(t, 1))},
	}}
	results := Run(context.Background(), cfg, r, Options{Parallel: 2})
	if !results[0].Compliant() || results[1].Compliant() {
		t.Errorf("compliant = %v, %v; want web-1 only (web-2 grants alice no options)", results[0].Compliant(), results[1].Compliant())
	}
}
