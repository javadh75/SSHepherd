# audit --json & Monitoring-Style Exit Codes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sshepherd audit --json` emits one machine-readable report on stdout, and exit codes become 0 compliant / 1 drift-or-unreachable / 2 critical drift / 3 tool error (tool-wide).

**Architecture:** `internal/audit` gains a JSON renderer (`json.go`) beside the human one and a cfg-aware `ExitCode` returning 0/1/2; `cmd/sshepherd` gains the `--json` flag, an `errCriticalDrift` sentinel, and an `exitCodeFor` mapping in `run()` that renumbers generic errors 2 → 3. Spec: `docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md`.

**Tech Stack:** Go 1.26, stdlib `encoding/json`, existing golden-file harness (`checkGolden` + `-update` flag), table-driven tests. Run tests through `rtk proxy` when exact output matters.

**Conventions that apply to every task:** every test package already has a goleak `TestMain` — do not add another. `gofmt` + `gitleaks` run on pre-commit; the full gate is `make check`.

---

### Task 1: `audit.ExitCode` gains cfg and returns 2 for critical drift

**Files:**
- Modify: `internal/audit/report.go` (ExitCode at top of file, `renderSummary` at bottom)
- Test: `internal/audit/report_test.go`
- Regenerate: `internal/audit/testdata/report_critical.golden`, `internal/audit/testdata/report_critical_color.golden`

- [ ] **Step 1: Update the existing ExitCode assertions and add the table test**

In `internal/audit/report_test.go`, change every `ExitCode(results)` / `ExitCode(nil)` call — the signature becomes `ExitCode(cfg, results)`:

- `TestRenderDrift`: `if ExitCode(cfg, results) != 1 { t.Errorf("ExitCode = %d, want 1", ExitCode(cfg, results)) }`
- `TestRenderCompliant`: same shape, want 0.
- `TestRenderEmptyFleet`: `if ExitCode(&config.Config{}, nil) != 0 { t.Errorf("ExitCode(empty) = %d, want 0", ExitCode(&config.Config{}, nil)) }`
- `TestRenderUnauthorizedKnownOwnerIsNamed`: same shape, want 1.
- `TestRenderCriticalOperatorMissing`: the expectation flips from 1 to 2 —
  ```go
  if ExitCode(cfg, results) != 2 {
  	t.Errorf("ExitCode = %d, want 2 (critical drift)", ExitCode(cfg, results))
  }
  ```

Then add the table test after `TestRenderEmptyFleet`:

```go
// TestExitCodeSeverity pins the monitoring-style scheme from the 2026-07-16
// spec: 0 compliant, 1 drift/unreachable, 2 critical — critical wins over
// everything, unreachable alone is only 1 (nothing knowable about its keys).
func TestExitCodeSeverity(t *testing.T) {
	driftCfg := reportConfig(t)
	critCfg := operatorConfig(t)
	tests := []struct {
		name    string
		cfg     *config.Config
		results []ServerResult
		want    int
	}{
		{"empty fleet", &config.Config{}, nil, 0},
		{"drift plus unreachable, no critical", driftCfg, driftResults(t, driftCfg), 1},
		{"critical present", critCfg, criticalResults(t, critCfg), 2},
		{"unreachable only", critCfg, []ServerResult{
			{Server: critCfg.Servers[0], Err: errors.New("dial tcp: connection refused")},
		}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.cfg, tt.results); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run to verify it fails to compile**

Run: `rtk proxy go test ./internal/audit/ -run 'TestExitCodeSeverity|TestRender' 2>&1 | tail -5`
Expected: `too many arguments in call to ExitCode` build failure.

- [ ] **Step 3: Implement the new ExitCode**

In `internal/audit/report.go`, replace the `ExitCode` function:

```go
// ExitCode maps audit results to the process exit code (monitoring-style,
// see docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md):
// 0 every server compliant (an empty fleet is trivially compliant);
// 1 drift and/or unreachable servers — compliance not proven;
// 2 critical drift — at least one server is missing an operator key.
// Tool errors (exit 3) are the caller's domain; this function never sees them.
func ExitCode(cfg *config.Config, results []ServerResult) int {
	code := 0
	for _, r := range results {
		if criticalDrift(cfg, r) {
			return 2
		}
		if !r.Compliant() {
			code = 1
		}
	}
	return code
}
```

And in `renderSummary`, the last line's `ExitCode(results)` becomes `ExitCode(cfg, results)`.

- [ ] **Step 4: Regenerate the two critical goldens (summary tail changes 1 → 2)**

Run: `rtk proxy go test ./internal/audit/ -run 'TestRenderCriticalOperatorMissing|TestRenderCriticalColorGolden' -update`
Then: `git diff internal/audit/testdata/` — the ONLY change in each file must be `→ exit 1` becoming `→ exit 2` on the Summary line. Any other diff means Step 3 broke rendering; stop and fix.

- [ ] **Step 5: Run the package to verify green**

Run: `rtk proxy go test ./internal/audit/ 2>&1 | tail -3`
Expected: `ok`. (The `cmd/sshepherd` package will NOT compile until Task 3 — that is expected mid-flight; do not run `./...` yet.)

- [ ] **Step 6: Commit**

```bash
git add internal/audit/report.go internal/audit/report_test.go internal/audit/testdata/report_critical.golden internal/audit/testdata/report_critical_color.golden
git commit -m "feat(audit): ExitCode distinguishes critical drift (0/1/2)

Supersedes the operator spec's render-only decision per the 2026-07-16
audit-json spec. cmd/sshepherd catches up in the next commits.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

Note: the pre-push hook would fail right now (cmd doesn't compile); that's fine for local commits — Tasks 2–3 restore the build before any push.

---

### Task 2: `run()` maps errors via `exitCodeFor`; tool errors become 3

**Files:**
- Modify: `cmd/sshepherd/run.go` (sentinels near top, mapping in `run()`)
- Test: `cmd/sshepherd/run_test.go`
- Modify (pin updates): `cmd/sshepherd/audit_test.go`, `cmd/sshepherd/adopt_test.go`, `cmd/sshepherd/import_test.go`

- [ ] **Step 1: Renumber every usage-error exit pin from 2 to 3**

```bash
perl -pi -e 's/code != 2\b/code != 3/g; s/(exit(?: code)? = %d, want) 2/$1 3/g' \
  cmd/sshepherd/run_test.go cmd/sshepherd/audit_test.go \
  cmd/sshepherd/adopt_test.go cmd/sshepherd/import_test.go
```

Verify nothing was missed and nothing extra was touched:

```bash
rtk proxy grep -rn 'want 2' cmd/sshepherd/run_test.go cmd/sshepherd/audit_test.go cmd/sshepherd/adopt_test.go cmd/sshepherd/import_test.go
```

Expected leftovers are key-count assertions only (`DesiredFor(...) ... want 2`, `Warnings ... want 2` — around `import_test.go:80,114,398` and `adopt_test.go:110`). No `exit ... want 2` line may remain.

- [ ] **Step 2: Write the failing mapping test**

Append to `cmd/sshepherd/run_test.go` (the file already imports `testing`; add `"errors"` and `"fmt"` to its imports if absent):

```go
// TestExitCodeFor pins the tool-wide exit contract from the 2026-07-16 spec:
// 0 ok, 1 drift/unreadable, 2 critical drift, 3 everything else.
func TestExitCodeFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"non-compliant", errNonCompliant, 1},
		{"fleet unreadable", errFleetUnreadable, 1},
		{"critical drift", errCriticalDrift, 2},
		{"wrapped critical", fmt.Errorf("audit: %w", errCriticalDrift), 2},
		{"generic error", errors.New("boom"), 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeFor(tt.err); got != tt.want {
				t.Errorf("exitCodeFor(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `rtk proxy go vet ./cmd/sshepherd/ 2>&1 | head -5`
Expected: `undefined: errCriticalDrift` / `undefined: exitCodeFor` (plus, until Task 3, the `audit.ExitCode` arity error from Task 1 — both are the red we want).

- [ ] **Step 4: Implement sentinel + mapping**

In `cmd/sshepherd/run.go`, below `errFleetUnreadable`:

```go
// errCriticalDrift signals exit code 2: the audit ran and at least one
// server is missing an operator key — the drift class that threatens fleet
// access itself.
var errCriticalDrift = errors.New("fleet has critical drift")
```

Replace the `switch` at the end of `run()`:

```go
	err := root.Execute()
	code := exitCodeFor(err)
	if code == 3 {
		a.log(stderr).Error(err.Error())
	}
	return code
```

And add below `run()`:

```go
// exitCodeFor maps Execute's error to the monitoring-style process exit code
// (see docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md).
// Sentinel-mapped outcomes have already rendered their report; only the
// tool-error case (3) still needs the error logged.
func exitCodeFor(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errNonCompliant), errors.Is(err, errFleetUnreadable):
		return 1
	case errors.Is(err, errCriticalDrift):
		return 2
	default:
		return 3
	}
}
```

- [ ] **Step 5: Proceed to Task 3 before running cmd tests**

`cmd/sshepherd` still doesn't compile (audit.go calls the old `ExitCode`). Task 3 fixes that; the two tasks commit together as one working tree state — do NOT commit yet.

---

### Task 3: audit command returns the right sentinel (`auditVerdict`)

**Files:**
- Modify: `cmd/sshepherd/audit.go`
- Test: `cmd/sshepherd/audit_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cmd/sshepherd/audit_test.go`. Add imports `"errors"`, `"github.com/javadh75/SSHepherd/internal/audit"`, `"github.com/javadh75/SSHepherd/internal/authkeys"`, `"github.com/javadh75/SSHepherd/internal/config"` if absent (check the file's import block first).

```go
// verdictConfig: op (operator, key 1) desired everywhere; alice (key 2) -> web-1.
func verdictConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("verdictConfig: %v", err)
	}
	return cfg
}

func mustParseKey(t *testing.T, line string) authkeys.Key {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("mustParseKey(%q): %v", line, err)
	}
	return *k
}

// TestAuditVerdict pins the sentinel choice: ExitCode 2 -> errCriticalDrift,
// 1 -> errNonCompliant, 0 -> nil.
func TestAuditVerdict(t *testing.T) {
	cfg := verdictConfig(t)
	opKey := mustParseKey(t, testkeys.Line(t, 1))
	aliceKey := mustParseKey(t, testkeys.Line(t, 2))

	compliant := []audit.ServerResult{{Server: cfg.Servers[0]}}
	drift := []audit.ServerResult{{Server: cfg.Servers[0],
		Diff: authkeys.Result{Missing: []authkeys.Key{aliceKey}}}}
	critical := []audit.ServerResult{{Server: cfg.Servers[0],
		Diff: authkeys.Result{Missing: []authkeys.Key{opKey}}}}

	if err := auditVerdict(cfg, compliant); err != nil {
		t.Errorf("compliant verdict = %v, want nil", err)
	}
	if err := auditVerdict(cfg, drift); !errors.Is(err, errNonCompliant) {
		t.Errorf("drift verdict = %v, want errNonCompliant", err)
	}
	if err := auditVerdict(cfg, critical); !errors.Is(err, errCriticalDrift) {
		t.Errorf("critical verdict = %v, want errCriticalDrift", err)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `rtk proxy go test ./cmd/sshepherd/ -run TestAuditVerdict 2>&1 | tail -5`
Expected: build failure — `undefined: auditVerdict` and the pre-existing `audit.ExitCode` arity error.

- [ ] **Step 3: Implement**

In `cmd/sshepherd/audit.go`, replace the tail of `RunE` —

```go
			audit.Render(stdout, cfg, results, audit.RenderOptions{Color: a.reportColor})
			if audit.ExitCode(results) != 0 {
				return errNonCompliant
			}
			return nil
```

with:

```go
			audit.Render(stdout, cfg, results, audit.RenderOptions{Color: a.reportColor})
			return auditVerdict(cfg, results)
```

and add at the bottom of the file:

```go
// auditVerdict converts the fleet's ExitCode into run()'s sentinel errors so
// the process exits 0 (compliant), 1 (drift/unreachable), or 2 (critical).
func auditVerdict(cfg *config.Config, results []audit.ServerResult) error {
	switch audit.ExitCode(cfg, results) {
	case 2:
		return errCriticalDrift
	case 1:
		return errNonCompliant
	default:
		return nil
	}
}
```

- [ ] **Step 4: Run the whole module to verify green**

Run: `rtk proxy go test ./... 2>&1 | tail -12`
Expected: all packages `ok` — the Task 2 renumbering and this wiring must both hold.

- [ ] **Step 5: Commit Tasks 2+3 together**

```bash
git add cmd/sshepherd/run.go cmd/sshepherd/run_test.go cmd/sshepherd/audit.go cmd/sshepherd/audit_test.go cmd/sshepherd/adopt_test.go cmd/sshepherd/import_test.go
git commit -m "feat(cmd): monitoring-style exit codes — 0/1/2/3

audit exits 2 on critical drift via the new errCriticalDrift sentinel;
generic tool/usage errors move from 2 to 3, tool-wide, per the
2026-07-16 audit-json spec.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: JSON renderer in `internal/audit`

**Files:**
- Create: `internal/audit/json.go`
- Create: `internal/audit/json_test.go`
- Create (via `-update`): `internal/audit/testdata/report_drift.golden.json`, `internal/audit/testdata/report_critical.golden.json`
- Modify: `internal/audit/report.go` (extract `tallyResults` from `renderSummary`)

- [ ] **Step 1: Write the failing tests**

Create `internal/audit/json_test.go`:

```go
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
```

Note the deliberate detail in `TestRenderJSONRoundTrip`: `driftResults` feeds web-1 three lines (alice, unknown key with comment `who@is-this`, `garbage entry`) so the parse error is line 3.

- [ ] **Step 2: Run to verify it fails**

Run: `rtk proxy go test ./internal/audit/ -run TestRenderJSON 2>&1 | tail -5`
Expected: build failure — `undefined: RenderJSON`.

- [ ] **Step 3: Extract `tallyResults` and implement `RenderJSON`**

In `internal/audit/report.go`, replace `renderSummary` with:

```go
// tallyCounts aggregates fleet outcomes for the summary line and the JSON
// report. A critical server counts in both drift and critical.
type tallyCounts struct {
	compliant, drift, critical, unreachable int
}

func tallyResults(cfg *config.Config, results []ServerResult) tallyCounts {
	var c tallyCounts
	for _, r := range results {
		switch {
		case r.Err != nil:
			c.unreachable++
		case r.Compliant():
			c.compliant++
		default:
			c.drift++
			if criticalDrift(cfg, r) {
				c.critical++
			}
		}
	}
	return c
}

func renderSummary(w io.Writer, cfg *config.Config, results []ServerResult) {
	c := tallyResults(cfg, results)
	fmt.Fprintf(w, "Summary: %d/%d servers compliant · %d with drift (%d critical) · %d unreachable  → exit %d\n",
		c.compliant, len(results), c.drift, c.critical, c.unreachable, ExitCode(cfg, results))
}
```

Create `internal/audit/json.go`:

```go
package audit

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// schemaVersion marks the JSON report shape. Bump only on breaking changes
// so consumers can hard-fail instead of misparsing.
const schemaVersion = 1

// The json* types are the wire shape of --json output, pinned by the
// 2026-07-16 spec and the report_*.golden.json fixtures. Field names are
// part of the public contract — change them only with a schema bump.
type jsonReport struct {
	Schema  int          `json:"schema"`
	Summary jsonSummary  `json:"summary"`
	Servers []jsonServer `json:"servers"`
}

type jsonSummary struct {
	Servers     int `json:"servers"`
	Compliant   int `json:"compliant"`
	Drift       int `json:"drift"`
	Critical    int `json:"critical"`
	Unreachable int `json:"unreachable"`
	ExitCode    int `json:"exit_code"`
}

type jsonServer struct {
	Name           string           `json:"name"`
	Host           string           `json:"host"`
	Port           int              `json:"port"`
	User           string           `json:"user"`
	Status         string           `json:"status"`
	Error          *string          `json:"error"`
	Keys           jsonKeySets      `json:"keys"`
	ParseErrors    []jsonParseError `json:"parse_errors"`
	FileAbsent     bool             `json:"file_absent"`
	NoUsersGranted bool             `json:"no_users_granted"`
}

type jsonKeySets struct {
	Present      []jsonKey `json:"present"`
	Missing      []jsonKey `json:"missing"`
	Unauthorized []jsonKey `json:"unauthorized"`
}

type jsonKey struct {
	Owner       *string `json:"owner"`
	Comment     string  `json:"comment,omitempty"`
	Fingerprint string  `json:"fingerprint"`
	Type        string  `json:"type"`
	Operator    bool    `json:"operator,omitempty"`
}

type jsonParseError struct {
	Line  int    `json:"line"`
	Error string `json:"error"`
}

// RenderJSON writes the machine-readable audit report: one indented JSON
// document with a trailing newline. It is the --json twin of Render and
// takes the same inputs.
func RenderJSON(w io.Writer, cfg *config.Config, results []ServerResult) error {
	rep := jsonReport{Schema: schemaVersion, Servers: make([]jsonServer, 0, len(results))}
	for _, r := range results {
		rep.Servers = append(rep.Servers, jsonServerFor(cfg, r))
	}
	c := tallyResults(cfg, results)
	rep.Summary = jsonSummary{
		Servers:     len(results),
		Compliant:   c.compliant,
		Drift:       c.drift,
		Critical:    c.critical,
		Unreachable: c.unreachable,
		ExitCode:    ExitCode(cfg, results),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("encode audit report: %w", err)
	}
	return nil
}

// statusOf derives the per-server status, in spec order: unreachable
// (nothing knowable) > compliant > critical > drift.
func statusOf(cfg *config.Config, r ServerResult) string {
	switch {
	case r.Err != nil:
		return "unreachable"
	case r.Compliant():
		return "compliant"
	case criticalDrift(cfg, r):
		return "critical"
	default:
		return "drift"
	}
}

func jsonServerFor(cfg *config.Config, r ServerResult) jsonServer {
	s := jsonServer{
		Name:   r.Server.Name,
		Host:   r.Server.Host,
		Port:   r.Server.Port,
		User:   r.Server.User,
		Status: statusOf(cfg, r),
		Keys: jsonKeySets{
			Present:      []jsonKey{},
			Missing:      []jsonKey{},
			Unauthorized: []jsonKey{},
		},
		ParseErrors:    []jsonParseError{},
		FileAbsent:     r.FileAbsent,
		NoUsersGranted: r.NoUsersGranted,
	}
	if r.Err != nil {
		// oneLine collapses newlines (same defense as the human head line);
		// encoding/json escapes any remaining control bytes.
		msg := oneLine(r.Err)
		s.Error = &msg
		return s
	}
	for _, k := range r.Diff.OK {
		s.Keys.Present = append(s.Keys.Present, jsonKeyFor(cfg, k, false))
	}
	for _, k := range r.Diff.Missing {
		s.Keys.Missing = append(s.Keys.Missing, jsonKeyFor(cfg, k, true))
	}
	for _, k := range r.Diff.Unauthorized {
		s.Keys.Unauthorized = append(s.Keys.Unauthorized, jsonKeyFor(cfg, k, false))
	}
	for _, pe := range r.ParseErrs {
		// pe.Error() is the control-stripped rendering; the line prefix is
		// redundant with Line but keeps the string self-contained.
		s.ParseErrors = append(s.ParseErrors, jsonParseError{Line: pe.Line, Error: pe.Error()})
	}
	return s
}

// jsonKeyFor renders one key. markOperator is true only for missing keys:
// operator: true is the JSON twin of the CRITICAL rendering and appears
// nowhere else.
func jsonKeyFor(cfg *config.Config, k authkeys.Key, markOperator bool) jsonKey {
	jk := jsonKey{Comment: k.Comment, Fingerprint: k.Fingerprint, Type: k.Type}
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		name := u.Name
		jk.Owner = &name
		if markOperator && u.Operator {
			jk.Operator = true
		}
	}
	return jk
}
```

- [ ] **Step 4: Generate the goldens, inspect, then verify green**

Run: `rtk proxy go test ./internal/audit/ -run 'TestRenderJSON.*Golden' -update`
Inspect both new files (`internal/audit/testdata/report_drift.golden.json`, `report_critical.golden.json`) by reading them: field names snake_case, `"schema": 1`, statuses correct, unauthorized key's `owner` is `null`, exactly the shape in the spec's example. Fix the renderer if anything is off, regenerate, re-inspect.
Then run: `rtk proxy go test ./internal/audit/ 2>&1 | tail -3`
Expected: `ok` — goldens, round-trip, marker, hostile-escape, and all pre-existing report tests.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/json.go internal/audit/json_test.go internal/audit/report.go internal/audit/testdata/report_drift.golden.json internal/audit/testdata/report_critical.golden.json
git commit -m "feat(audit): RenderJSON — machine-readable report (schema 1)

Fingerprint/identity only, operator marker on missing keys, summary
with exit_code; shares tallyResults with the human summary line.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: wire `--json` into the audit command

**Files:**
- Modify: `cmd/sshepherd/audit.go`
- Test: `cmd/sshepherd/audit_test.go`

- [ ] **Step 1: Write the failing test**

Append to `cmd/sshepherd/audit_test.go` (uses the same empty-fleet pattern as the existing `TestAuditEmptyFleet` around line 39 — a manifest with `servers: []` needs no agent and completes offline; add `"encoding/json"` to imports):

```go
// TestAuditJSONEmptyFleet: --json must emit exactly one valid JSON document
// on stdout — nothing else — with logs on stderr, and exit 0.
func TestAuditJSONEmptyFleet(t *testing.T) {
	path := writeConfig(t, `
users: []
servers: []
access: []
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path, "--json"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	var rep struct {
		Schema  int               `json:"schema"`
		Servers []json.RawMessage `json:"servers"`
		Summary struct {
			Servers  int `json:"servers"`
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
	}
	// Unmarshal the WHOLE stdout: any human-report text before or after the
	// document (or a second document) fails here.
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatalf("stdout is not exactly one JSON document: %v\n%s", err, out.String())
	}
	if rep.Schema != 1 || rep.Summary.Servers != 0 || rep.Summary.ExitCode != 0 {
		t.Errorf("report = %+v, want schema 1, 0 servers, exit 0", rep)
	}
	if rep.Servers == nil {
		t.Errorf("servers must be [], not null:\n%s", out.String())
	}
	if strings.Contains(out.String(), "Summary:") {
		t.Errorf("human summary leaked into --json stdout:\n%s", out.String())
	}
}
```

If `audit_test.go` has no `writeConfig` helper, reuse whatever helper the existing empty-fleet test uses to write a manifest to a temp file (check around `cmd/sshepherd/audit_test.go:39`) and adapt the call — do not duplicate a second helper.

- [ ] **Step 2: Run to verify it fails**

Run: `rtk proxy go test ./cmd/sshepherd/ -run TestAuditJSONEmptyFleet 2>&1 | tail -5`
Expected: FAIL — `unknown flag: --json`.

- [ ] **Step 3: Implement the flag**

In `cmd/sshepherd/audit.go`:

1. Add `jsonOut bool` to the `var (...)` block at the top of `newAuditCmd`.
2. Register the flag next to the others at the bottom:
   ```go
   cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the report as machine-readable JSON on stdout")
   ```
3. Introduce one render closure so the empty-fleet early return and the main
   path cannot drift apart. Inside `RunE`, right after the manifest loads:
   ```go
   			render := func(results []audit.ServerResult) error {
   				if jsonOut {
   					return audit.RenderJSON(stdout, cfg, results)
   				}
   				audit.Render(stdout, cfg, results, audit.RenderOptions{Color: a.reportColor})
   				return nil
   			}
   ```
4. The empty-fleet branch becomes:
   ```go
   			if len(cfg.Servers) == 0 {
   				return render(nil)
   			}
   ```
5. The tail (from Task 3) becomes:
   ```go
   			if err := render(results); err != nil {
   				return err
   			}
   			return auditVerdict(cfg, results)
   ```

- [ ] **Step 4: Run to verify green**

Run: `rtk proxy go test ./cmd/sshepherd/ 2>&1 | tail -3`
Expected: `ok`.

- [ ] **Step 5: Smoke-test the real binary**

```bash
rtk proxy go run ./cmd/sshepherd audit --help | grep -A1 json
printf 'users: []\nservers: []\naccess: []\n' > /tmp/empty.yaml
rtk proxy go run ./cmd/sshepherd audit --config /tmp/empty.yaml --json; echo "exit=$?"
rm /tmp/empty.yaml
```
Expected: help shows the flag; the run prints an indented JSON document with `"schema": 1` and `exit=0`.

- [ ] **Step 6: Commit**

```bash
git add cmd/sshepherd/audit.go cmd/sshepherd/audit_test.go
git commit -m "feat(cmd): audit --json emits the machine-readable report

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: docs, spec cross-references, full gate

**Files:**
- Modify: `CLAUDE.md` (Status section, last paragraph)
- Modify: `docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md` (Status line)
- Modify: `docs/superpowers/specs/2026-07-06-audit-slice-design.md` (open-questions list)
- Modify: `docs/superpowers/specs/2026-07-10-operator-users-wildcard-access-design.md` (decisions table)

- [ ] **Step 1: Update the docs**

1. `CLAUDE.md` Status section — append after the logging sentence:
   ```
   Audit is scriptable: `--json` emits a machine-readable report (schema 1)
   and exit codes are monitoring-style — 0 compliant, 1 drift/unreachable,
   2 critical drift, 3 tool error (specced in
   docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md).
   ```
2. New spec: change `- **Status:** Approved, awaiting implementation` to `- **Status:** Implemented (2026-07-16) — see docs/superpowers/plans/2026-07-16-audit-json-exit-codes.md`.
3. `2026-07-06-audit-slice-design.md`: in "Deliberately deferred", annotate the `--json` bullet with `(implemented 2026-07-16 — see the audit-json spec)`; there is no exit-code bullet there, but scan "Open questions" for related lines and annotate the same way if present.
4. `2026-07-10-operator-users-wildcard-access-design.md`: in the Decisions table, edit the "Critical severity" row's Notes cell — append ` **Superseded 2026-07-16:** audit now exits 2 on critical drift (see the audit-json spec).`

- [ ] **Step 2: Run the full gate**

Run: `make check 2>&1 | tail -15`
Expected: everything green — fmt, vet, lint (0 issues), gosec, govulncheck, gitleaks, race suite. Fix anything it flags before committing.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md docs/superpowers/specs/2026-07-06-audit-slice-design.md docs/superpowers/specs/2026-07-10-operator-users-wildcard-access-design.md
git commit -m "docs: mark audit --json + exit-code slice implemented

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```
