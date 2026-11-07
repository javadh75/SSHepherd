# `--json` for apply, revoke and rotate — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `apply`, `revoke` and `rotate` emit one machine-readable JSON document (plan + per-server outcome + manifest edit) on stdout under `--json`, plus two small hardening fixes (truncation wording, C1/Cf sanitizing in `audit --json`).

**Architecture:** A new renderer `internal/apply/json.go` maps `[]ServerPlan` (+ optional `EditSummary`) onto unexported wire structs, mirroring `internal/audit/json.go`. `cmd/sshepherd` gains `--json` on the shared `runFlags`, enforces "needs `--dry-run` or `--yes`", suppresses every text stdout site, and routes the two early `errNonCompliant` exits through `finish` via a new `stageWithheld` so a document is written on every exit-0/1 path. A new leaf package `internal/sanitize` holds the remote-text sanitizer so `internal/audit` can use it without an import cycle.

**Tech Stack:** Go 1.26, `encoding/json`, Cobra, existing hermetic `sshtest` server, golden files (`-update`), goleak.

**Spec:** `docs/superpowers/specs/2026-11-07-apply-json-design.md` — read it first; it is the contract. This plan never overrides it.

---

## Execution model (read before starting)

This plan is executed by a Workflow, split by **disjoint file ownership**:

| Owner | Tasks | Files (exclusive) |
|---|---|---|
| **Agent A** | A1–A6 | `internal/apply/json.go` (new), `internal/apply/json_test.go` (new), `internal/apply/testdata/*.golden.json` (new), `internal/apply/report.go` (summary helper only), `internal/apply/report_test.go` (parity test only) |
| **Agent B** | B1–B7 | `internal/sanitize/**` (new), `internal/sshconn/sshconn.go`, `internal/sshconn/sshconn_test.go`, `internal/audit/json.go`, `internal/audit/json_test.go`, `cmd/sshepherd/edit.go`, `cmd/sshepherd/apply.go`, `cmd/sshepherd/editrun.go`, `cmd/sshepherd/*_test.go` (new `json_cmd_test.go`; no edits to other test files except where stated), `README.md` **flag-table rows only** |
| **Integrator** | I1–I4 | `cmd/sshepherd/e2e_test.go`, rest of `README.md`, `CLAUDE.md`, plus merge fixes |

Rules for every agent:
- **No commits.** Leave changes in the working tree; the integrator commits once.
- Agent B codes against the `RenderJSON`/`JSONOptions` signature in Task A2. To compile before A lands, B may add a **temporary** stub `internal/apply/json_stub.go` in its own worktree only and must delete it before handing back (the integrator verifies it is absent).
- Toolchain trap: run Go with `GOTOOLCHAIN=go1.26.9` (Homebrew go1.27 breaks the pinned golangci-lint). Example: `GOTOOLCHAIN=go1.26.9 go test ./internal/apply/...`.
- The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- Golden files are written with `-update` and then **read back and checked by eye** against the spec's shape before being accepted.

---

## Agent A — `internal/apply` renderer

### Task A1: Extract summary counting into one helper

**Files:**
- Modify: `internal/apply/report.go` (`RenderSummary`, ~lines 233–280)
- Test: `internal/apply/report_test.go` (append one test)

- [ ] **Step 1: Write the failing test** — append to `internal/apply/report_test.go`:

```go
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
```

- [ ] **Step 2: Run it — expect FAIL** (`undefined: countSummary`):
`GOTOOLCHAIN=go1.26.9 go test ./internal/apply/ -run TestCountSummaryMatchesRenderSummary`

- [ ] **Step 3: Implement.** In `report.go`, add above `RenderSummary`:

```go
// summaryCounts is the outcome tally behind the text Summary line and the
// JSON summary object — one helper so the two can never disagree.
// converged includes servers applied this run.
type summaryCounts struct {
	converged, applied, pending, refused, failed, unreachable int
}

func countSummary(plans []ServerPlan) summaryCounts {
	var c summaryCounts
	for _, p := range plans {
		switch p.Class {
		case ClassConverged:
			c.converged++
		case ClassRefused:
			c.refused++
		case ClassUnreachable:
			c.unreachable++
		case ClassChange:
			switch p.Outcome {
			case OutcomeApplied:
				c.converged++
				c.applied++
			case OutcomeRefused:
				c.refused++
			case OutcomeFailed:
				c.failed++
			default:
				c.pending++
			}
		}
	}
	return c
}
```

Then rewrite `RenderSummary` so its loop only prints the per-server lines and the counts come from the helper:

```go
func RenderSummary(w io.Writer, plans []ServerPlan, opts RenderOptions) {
	if len(plans) == 0 {
		return // Render already printed the 0-servers summary
	}
	pal := palette{on: opts.Color}
	for _, p := range plans {
		if p.Class != ClassChange {
			continue
		}
		switch p.Outcome {
		case OutcomeApplied:
			fmt.Fprintf(w, "%s: %s\n", p.Server.Name, pal.paint(codeGreen, "applied · verified"))
		case OutcomeRefused:
			fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeBoldRed, "REFUSED:"), oneLine(p.OutcomeErr))
		case OutcomeFailed:
			fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeRed, "FAILED:"), oneLine(p.OutcomeErr))
		default:
			if p.OutcomeErr != nil {
				fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeYellow, "NOT STARTED:"), oneLine(p.OutcomeErr))
			}
		}
	}
	c := countSummary(plans)
	line := fmt.Sprintf("Summary: %d/%d servers converged", c.converged, len(plans))
	if c.applied > 0 {
		line += fmt.Sprintf(" (%d applied)", c.applied)
	}
	for _, seg := range []struct {
		n     int
		label string
	}{{c.pending, "pending"}, {c.failed, "failed"}, {c.refused, "refused"}, {c.unreachable, "unreachable"}} {
		if seg.n > 0 {
			line += fmt.Sprintf(" · %d %s", seg.n, seg.label)
		}
	}
	fmt.Fprintf(w, "%s  → exit %d\n", line, ExitCode(plans))
}
```

- [ ] **Step 4: Run the whole package — expect PASS, goldens unchanged** (proves the refactor is behavior-neutral):
`GOTOOLCHAIN=go1.26.9 go test ./internal/apply/`

### Task A2: `json.go` skeleton — options, wire types, empty document

**Files:**
- Create: `internal/apply/json.go`
- Create: `internal/apply/json_test.go`
- Create: `internal/apply/testdata/json_empty.golden.json`

- [ ] **Step 1: Write the failing test** — `internal/apply/json_test.go`:

```go
package apply

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
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
```

- [ ] **Step 2: Run — expect FAIL** (`undefined: RenderJSON`).

- [ ] **Step 3: Implement** `internal/apply/json.go`:

```go
package apply

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// jsonSchemaVersion marks the write-path document shape. Bump only on
// breaking changes; additive optional fields keep 1.
const jsonSchemaVersion = 1

// JSONOptions selects the document kind and the revoke/rotate extras.
type JSONOptions struct {
	Command string         // "apply" | "revoke" | "rotate"
	DryRun  bool           // --dry-run was given
	Skipped int            // servers excluded by --server (apply only)
	Former  *config.Config // as-loaded config before the edit; nil for apply
	Edit    *EditSummary   // nil for apply
	Saved   bool           // the manifest was written (revoke/rotate)
}

// The json* types are the wire shape of --json on apply/revoke/rotate,
// pinned by docs/superpowers/specs/2026-11-07-apply-json-design.md and the
// json_*.golden.json fixtures. Field names are public contract.
type jsonDoc struct {
	Schema  int          `json:"schema"`
	Command string       `json:"command"`
	DryRun  bool         `json:"dry_run"`
	Edit    *jsonEdit    `json:"edit"`
	Summary jsonSummary  `json:"summary"`
	Servers []jsonServer `json:"servers"`
}

type jsonSummary struct {
	Servers     int `json:"servers"`
	Skipped     int `json:"skipped"`
	Converged   int `json:"converged"`
	Applied     int `json:"applied"`
	Pending     int `json:"pending"`
	Failed      int `json:"failed"`
	Refused     int `json:"refused"`
	Unreachable int `json:"unreachable"`
	ExitCode    int `json:"exit_code"`
}

type jsonEdit struct {
	Saved     bool            `json:"saved"`
	Edits     []jsonEditEntry `json:"edits"`
	Affected  int             `json:"affected"`
	Operators []string        `json:"operators"`
	Emptied   []jsonEmptied   `json:"emptied"`
}

// jsonEditEntry: pointer fields are present exactly for their kind, so a
// zero count or false flag is still emitted where it belongs.
type jsonEditEntry struct {
	Kind           string `json:"kind"`
	User           string `json:"user"`
	Keys           *int   `json:"keys,omitempty"`
	Grants         *int   `json:"grants,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	NewFingerprint string `json:"new_fingerprint,omitempty"`
	KeepsExpiry    string `json:"keeps_expiry,omitempty"`
	NoKeysLeft     *bool  `json:"no_keys_left,omitempty"`
	ClearsOperator *bool  `json:"clears_operator,omitempty"`
}

type jsonEmptied struct {
	Server string   `json:"server"`
	Users  []string `json:"users"`
	Keys   int      `json:"keys"`
}

type jsonServer struct {
	Name                    string      `json:"name"`
	Host                    string      `json:"host"`
	Port                    int         `json:"port"`
	User                    string      `json:"user"`
	AuthorizedKeysFile      string      `json:"authorized_keys_file,omitempty"`
	Class                   string      `json:"class"`
	Outcome                 *string     `json:"outcome"`
	Error                   *string     `json:"error"`
	ErrorKind               string      `json:"error_kind,omitempty"`
	Changes                 jsonChanges `json:"changes"`
	FileAbsent              bool        `json:"file_absent"`
	AuthorizedKeys2Present  bool        `json:"authorized_keys2_present"`
	DisablesAuthorizedKeys2 bool        `json:"disables_authorized_keys2"`
	Notes                   jsonNotes   `json:"notes"`
}

type jsonChanges struct {
	Add       []jsonKey     `json:"add"`
	Remove    []jsonKey     `json:"remove"`
	Rewrite   []jsonRewrite `json:"rewrite"`
	Normalize jsonNormalize `json:"normalize"`
}

// jsonKey: owner always present (null = the rendered manifest does not own
// it); former_owner only for a key only JSONOptions.Former owns.
type jsonKey struct {
	Owner       *string `json:"owner"`
	FormerOwner string  `json:"former_owner,omitempty"`
	Fingerprint string  `json:"fingerprint"`
	Type        string  `json:"type"`
	Comment     string  `json:"comment,omitempty"`
	Operator    bool    `json:"operator,omitempty"`
}

// jsonRewrite is not a key object: only what changes is present.
type jsonRewrite struct {
	Owner         *string            `json:"owner"`
	Fingerprint   string             `json:"fingerprint"`
	Type          string             `json:"type"`
	Operator      bool               `json:"operator,omitempty"`
	OptionsChange *jsonOptionsChange `json:"options_change,omitempty"`
	CommentChange *jsonCommentChange `json:"comment_change,omitempty"`
	Loosens       []string           `json:"loosens"`
}

type jsonOptionsChange struct {
	From []string `json:"from"`
	To   []string `json:"to"`
}

type jsonCommentChange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type jsonNormalize struct {
	Reorder                bool `json:"reorder"`
	NonKeyLines            int  `json:"non_key_lines"`
	Duplicates             int  `json:"duplicates"`
	DuplicateOptionsDiffer bool `json:"duplicate_options_differ"`
	Whitespace             bool `json:"whitespace"`
}

type jsonNotes struct {
	Guard              string `json:"guard,omitempty"`
	RestrictiveOptions string `json:"restrictive_options,omitempty"`
	AgentOnlySurvivors string `json:"agent_only_survivors,omitempty"`
}

// RenderJSON writes the write-path report as one indented JSON document
// with a trailing newline. plans may be nil (empty fleet, edit-only run).
func RenderJSON(w io.Writer, cfg *config.Config, plans []ServerPlan, opts JSONOptions) error {
	c := countSummary(plans)
	doc := jsonDoc{
		Schema:  jsonSchemaVersion,
		Command: opts.Command,
		DryRun:  opts.DryRun,
		Summary: jsonSummary{
			Servers: len(plans), Skipped: opts.Skipped,
			Converged: c.converged, Applied: c.applied, Pending: c.pending,
			Failed: c.failed, Refused: c.refused, Unreachable: c.unreachable,
			ExitCode: ExitCode(plans),
		},
		Servers: make([]jsonServer, 0, len(plans)),
	}
	if opts.Edit != nil {
		doc.Edit = jsonEditFor(*opts.Edit, opts.Saved)
	}
	for _, p := range plans {
		doc.Servers = append(doc.Servers, jsonServerFor(cfg, p, opts))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("render json: %w", err)
	}
	return nil
}

// clean strips terminal-hostile runes (C0/DEL/C1, Cf) that encoding/json
// would emit raw; idempotent on already-sanitized text.
func clean(s string) string { return sshconn.SanitizeRemote(s) }

// cleanLine is clean plus oneLine's whitespace collapse, for error text.
func cleanLine(s string) string { return clean(strings.Join(strings.Fields(s), " ")) }

func cleanAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, clean(s))
	}
	return out
}
```

Leave `jsonEditFor` and `jsonServerFor` as minimal stubs for now so the empty test compiles:

```go
func jsonEditFor(s EditSummary, saved bool) *jsonEdit { return &jsonEdit{Saved: saved} }

func jsonServerFor(cfg *config.Config, p ServerPlan, opts JSONOptions) jsonServer {
	return jsonServer{Name: p.Server.Name}
}
```

(`errors`, `audit`, `authkeys` imports become used in A3/A4; until then, omit them to compile, and re-add in A3.)

- [ ] **Step 4: Generate and inspect the golden:**
`GOTOOLCHAIN=go1.26.9 go test ./internal/apply/ -run TestRenderJSONEmptyFleet -update` then read `internal/apply/testdata/json_empty.golden.json`. It must be exactly:

```json
{
  "schema": 1,
  "command": "apply",
  "dry_run": false,
  "edit": null,
  "summary": {
    "servers": 0,
    "skipped": 2,
    "converged": 0,
    "applied": 0,
    "pending": 0,
    "failed": 0,
    "refused": 0,
    "unreachable": 0,
    "exit_code": 0
  },
  "servers": []
}
```

- [ ] **Step 5: Run without `-update` — expect PASS.**

### Task A3: Per-server mapping

**Files:**
- Modify: `internal/apply/json.go` (replace the `jsonServerFor` stub; add key helpers)
- Modify: `internal/apply/json_test.go`
- Create: `internal/apply/testdata/json_mixed.golden.json`, `json_security.golden.json`, `json_outcomes.golden.json`

- [ ] **Step 1: Write the failing tests** — append to `json_test.go`:

```go
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
			Add     []map[string]any `json:"add"`
			Remove  []map[string]any `json:"remove"`
			Rewrite []map[string]any `json:"rewrite"`
			Normalize map[string]any `json:"normalize"`
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
	srv := func(n string) config.Server { return config.Server{Name: n, Host: "10.0.0.1", Port: 22, User: "deploy"} }
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
	if d.Summary["converged"] != 1 || d.Summary["applied"] != 1 || d.Summary["pending"] != 1 ||
		d.Summary["failed"] != 1 || d.Summary["refused"] != 1 || d.Summary["exit_code"] != 1 {
		t.Errorf("summary = %v", d.Summary)
	}
}
```

Add `"errors"`, `"strings"` and `config` imports to `json_test.go`.

- [ ] **Step 2: Run — expect FAIL** (stub returns only names; class asserts fail).

- [ ] **Step 3: Implement** — replace the `jsonServerFor` stub in `json.go`:

```go
func jsonServerFor(cfg *config.Config, p ServerPlan, opts JSONOptions) jsonServer {
	s := jsonServer{
		Name:               p.Server.Name,
		Host:               p.Server.Host,
		Port:               p.Server.Port,
		User:               p.Server.User,
		AuthorizedKeysFile: p.Server.AuthorizedKeysFile,
		Class:              string(p.Class),
		Changes: jsonChanges{
			Add:     []jsonKey{},
			Remove:  []jsonKey{},
			Rewrite: []jsonRewrite{},
			Normalize: jsonNormalize{
				Reorder:                p.Normalize.Reorder,
				NonKeyLines:            p.Normalize.NonKeyLines,
				Duplicates:             p.Normalize.Duplicates,
				DuplicateOptionsDiffer: p.Normalize.DuplicateOptionsDiffer,
				Whitespace:             p.Normalize.Whitespace,
			},
		},
		FileAbsent:              p.FileAbsent,
		AuthorizedKeys2Present:  p.AuthorizedKeys2,
		DisablesAuthorizedKeys2: p.DisableKeys2(),
		Notes: jsonNotes{
			Guard:              clean(p.Note),
			RestrictiveOptions: clean(p.Warning),
			AgentOnlySurvivors: clean(p.AgentOnly),
		},
	}
	switch p.Class {
	case ClassUnreachable:
		if p.Err != nil {
			msg := cleanLine(p.Err.Error())
			s.Error = &msg
			s.ErrorKind = string(audit.ErrorKindOf(p.Err))
		}
	case ClassRefused:
		msg := cleanLine(p.Refusal)
		s.Error = &msg
	case ClassChange:
		outcome := string(p.Outcome)
		s.Outcome = &outcome
		if p.OutcomeErr != nil {
			msg := cleanLine(p.OutcomeErr.Error())
			s.Error = &msg
			if p.Outcome == OutcomePending && errors.Is(p.OutcomeErr, errInterrupted) {
				s.ErrorKind = string(audit.ErrorKindCanceled)
			}
		}
	}
	for _, k := range p.Add {
		jk := jsonKeyFor(cfg, opts.Former, k)
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
			jk.Comment = clean(config.DesiredComment(u, k)) // what the write installs
		}
		s.Changes.Add = append(s.Changes.Add, jk)
	}
	for _, k := range p.Remove {
		s.Changes.Remove = append(s.Changes.Remove, jsonKeyFor(cfg, opts.Former, k))
	}
	for _, rw := range p.Rewrites {
		s.Changes.Rewrite = append(s.Changes.Rewrite, jsonRewriteFor(cfg, rw))
	}
	return s
}

// jsonKeyFor renders a key object: the comment is the key's own (on-server
// for remove; add overrides it with the decided comment).
func jsonKeyFor(cfg *config.Config, former *config.Config, k authkeys.Key) jsonKey {
	jk := jsonKey{Fingerprint: k.Fingerprint, Type: k.Type, Comment: clean(k.Comment)}
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		name := u.Name
		jk.Owner = &name
		jk.Operator = u.Operator
		return jk
	}
	if former != nil {
		if fu, ok := former.OwnerOf(k.Fingerprint); ok {
			jk.FormerOwner = fu.Name
		}
	}
	return jk
}

func jsonRewriteFor(cfg *config.Config, rw RewriteRow) jsonRewrite {
	jr := jsonRewrite{Fingerprint: rw.Key.Fingerprint, Type: rw.Key.Type, Loosens: cleanAll(rw.Loosens)}
	if u, ok := cfg.OwnerOf(rw.Key.Fingerprint); ok {
		name := u.Name
		jr.Owner = &name
		jr.Operator = u.Operator
	}
	if rw.OptionsDiffer {
		jr.OptionsChange = &jsonOptionsChange{From: cleanAll(rw.ActualOptions), To: cleanAll(rw.Key.Options)}
	}
	if rw.CommentDiffers {
		jr.CommentChange = &jsonCommentChange{From: clean(rw.ActualComment), To: clean(rw.DesiredComment)}
	}
	return jr
}
```

Re-add the `errors`, `audit`, `authkeys` imports. (`cleanAll` returns a non-nil empty slice, so `loosens` and option lists are `[]`, never `null`.)

- [ ] **Step 4: Generate goldens** with `-update`, then **read each file** and check against the spec: `outcome` null on web-2/db-1/web-3; web-1 `add` has bob, `remove` the stray key with `"comment": "stray@laptop"` and `"owner": null`, `rewrite` alice with only `comment_change` (`alice@old` → `alice@work`) and `"loosens": []`; normalize `non_key_lines: 1`; `notes: {}` where empty. Security golden: `options_change.from` contains `from="10.0.0.5"` and `command="/usr/bin/pg_dump-wrapper"` verbatim, `loosens` lists both, op's key carries `"operator": true` wherever it appears, `disables_authorized_keys2: true`.

- [ ] **Step 5: Add the dry-run golden** — append:

```go
func TestRenderJSONDryRunAllPending(t *testing.T) {
	cfg, plans := mixedPlans(t)
	d := decodeDoc(t, renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply", DryRun: true}))
	for _, s := range d.Servers {
		if s.Class == "change" && *s.Outcome != "pending" {
			t.Errorf("%s outcome = %q under --dry-run", s.Name, *s.Outcome)
		}
	}
}
```

(No separate golden: `json_mixed.golden.json` is already a dry-run document.)

- [ ] **Step 6: Run the package — expect PASS.**

### Task A4: Edit section + revoke/rotate documents

**Files:**
- Modify: `internal/apply/json.go` (replace the `jsonEditFor` stub)
- Modify: `internal/apply/json_test.go`
- Create: `internal/apply/testdata/json_revoke.golden.json`, `json_rotate_edit_only.golden.json`, `json_withheld.golden.json`

- [ ] **Step 1: Write the failing tests:**

```go
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
	if _, has := e["no_keys_left"]; has {
		t.Errorf("remove-user carries a remove-key field: %v", e)
	}
	formers := map[string]bool{}
	for _, k := range doc.Servers[0].Changes.Remove {
		if fo, ok := k["former_owner"].(string); ok {
			formers[fo] = true
			if k["owner"] != nil {
				t.Errorf("former-owned key has owner %v", k["owner"])
			}
		}
	}
	if !formers["alice"] || !formers["bob"] {
		t.Errorf("former_owner set = %v, want alice and bob", formers)
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
	d := decodeDoc(t, out)
	if len(d.Servers) != 0 || d.Summary["exit_code"] != 0 || d.Summary["servers"] != 0 {
		t.Errorf("edit-only doc = %+v", d)
	}
}

// TestRenderJSONWithheld: the nothing-can-land / save-withheld document —
// saved false, change servers pending.
func TestRenderJSONWithheld(t *testing.T) {
	cfg, plans := mixedPlans(t)
	sum := EditSummary{Edits: []Edit{{Kind: EditRemoveUser, User: "carol", Keys: 1, Grants: 1}}, Affected: 4}
	out := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "revoke", Edit: &sum, Saved: false})
	checkGolden(t, "json_withheld.golden.json", out)
	d := decodeDoc(t, out)
	if d.Edit == nil || d.Edit.Saved {
		t.Errorf("edit.saved must be false: %+v", d.Edit)
	}
}
```

Add `"github.com/javadh75/SSHepherd/internal/audit"` and `"github.com/javadh75/SSHepherd/internal/testkeys"` imports.

- [ ] **Step 2: Run — expect FAIL** (stub edit lacks entries).

- [ ] **Step 3: Implement** — replace the `jsonEditFor` stub:

```go
func jsonEditFor(s EditSummary, saved bool) *jsonEdit {
	e := &jsonEdit{
		Saved:     saved,
		Edits:     make([]jsonEditEntry, 0, len(s.Edits)),
		Affected:  s.Affected,
		Operators: append([]string{}, s.Operators...),
		Emptied:   make([]jsonEmptied, 0, len(s.Emptied)),
	}
	for _, ed := range s.Edits {
		je := jsonEditEntry{Kind: string(ed.Kind), User: ed.User}
		switch ed.Kind {
		case EditRemoveUser:
			keys, grants := ed.Keys, ed.Grants
			je.Keys, je.Grants = &keys, &grants
		case EditRemoveKey:
			noKeys, clears := ed.NoKeysLeft, ed.ClearsOperator
			je.Fingerprint = ed.Fingerprint
			je.NoKeysLeft, je.ClearsOperator = &noKeys, &clears
		case EditRotate:
			je.Fingerprint, je.NewFingerprint, je.KeepsExpiry = ed.Fingerprint, ed.NewFingerprint, ed.KeepsExpiry
		}
		e.Edits = append(e.Edits, je)
	}
	for _, em := range s.Emptied {
		e.Emptied = append(e.Emptied, jsonEmptied{Server: em.Server, Users: append([]string{}, em.Users...), Keys: em.Keys})
	}
	return e
}
```

- [ ] **Step 4: Generate goldens with `-update`, read each one** (check: `keeps_expiry` verbatim `expiry-time="20270101"`; remove-user has `keys`/`grants` and no fingerprint; `operators: []`; `emptied: []` in the rotate one).

- [ ] **Step 5: Run the package — expect PASS.**

### Task A5: Sanitization pin

**Files:** Modify `internal/apply/json_test.go`

- [ ] **Step 1: Write the test:**

```go
// TestRenderJSONSanitizes: ESC, C1 CSI and a bidi override in an on-server
// comment, an option and an error string never reach the document raw.
func TestRenderJSONSanitizes(t *testing.T) {
	const hostile = "x\x1b[31m\u009b2J‮y"
	cfg := planCfg(t)
	content := testkeys.Line(t, 1) + " op@sshepherd\n" +
		`from="10.0.0.5` + hostile + `" ` + testkeys.Line(t, 2) + " alice@work\n" +
		testkeys.Line(t, 9) + " " + hostile + "\n"
	r := &fakeReader{
		byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}},
	}
	plans := buildPlans(t, cfg, r, []string{fp(t, 1)})
	plans = append(plans, ServerPlan{
		Server: config.Server{Name: "evil"}, Class: ClassUnreachable,
		Err: errors.New("banner " + hostile),
	})
	out := renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply", DryRun: true})
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
}
```

(If `authkeys.ParseLine` rejects the hostile option line as unparseable — making web-1 `refused` — keep the hostile comment on the stray key line, which is always parseable, and move the option case to a hand-built `RewriteRow` appended to a `ClassChange` plan: `ServerPlan{Server: config.Server{Name: "opt"}, Class: ClassChange, Outcome: OutcomePending, Rewrites: []RewriteRow{{Key: authkeys.Key{Fingerprint: fp(t, 2), Type: "ssh-ed25519"}, ActualOptions: []string{"command=\"" + hostile + "\""}, OptionsDiffer: true, Loosens: []string{"command=\"" + hostile + "\""}}}}`. The walk must still find zero hostile runes. Run first; pick the variant that exercises all three sources.)

- [ ] **Step 2: Run — expect PASS** (the renderer already sanitizes). If it fails, the failure names the unsanitized field; fix that field in `json.go`.

### Task A6: Package gates

- [ ] `GOTOOLCHAIN=go1.26.9 go test -race ./internal/apply/` — PASS.
- [ ] `GOTOOLCHAIN=go1.26.9 golangci-lint run ./internal/apply/...` — clean (watch `gocyclo` on `jsonServerFor`; if flagged, split the `switch p.Class` block into `jsonErrorFor(p ServerPlan) (*string, string)`).
- [ ] `GOTOOLCHAIN=go1.26.9 go test -cover ./internal/apply/` — coverage not below its pre-change value.
- [ ] Hand back: list of files changed, golden files created, any deviation from this plan and why.

---

## Agent B — sanitize leaf, wording, audit fix, CLI plumbing

### Task B1: `internal/sanitize` leaf package

**Files:**
- Create: `internal/sanitize/sanitize.go`, `internal/sanitize/sanitize_test.go`, `internal/sanitize/leak_test.go`
- Modify: `internal/sshconn/sshconn.go` (`SanitizeRemote` → delegate)

- [ ] **Step 1: Write the failing test** — `internal/sanitize/sanitize_test.go`:

```go
package sanitize

import "testing"

func TestRemote(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"plain", "plain"},
		{"keep\nnewline\tand tab", "keep\nnewline\tand tab"},
		{"esc\x1b[31mred", "esc[31mred"},
		{"c1\u009bcsi", "c1csi"},
		{"del\x7f", "del"},
		{"bidi‮evil", "bidievil"},
		{"zwj‍", "zwj"},
		{"ünïcode ok", "ünïcode ok"},
	} {
		if got := Remote(tt.in); got != tt.want {
			t.Errorf("Remote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func FuzzRemote(f *testing.F) {
	f.Add("a\x1b\u009b‮b")
	f.Fuzz(func(t *testing.T, s string) {
		out := Remote(s)
		if Remote(out) != out {
			t.Errorf("not idempotent on %q", s)
		}
	})
}
```

`internal/sanitize/leak_test.go`:

```go
package sanitize

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
```

- [ ] **Step 2: Run — expect FAIL** (`undefined: Remote`).

- [ ] **Step 3: Implement** — `internal/sanitize/sanitize.go`:

```go
// Package sanitize strips terminal-hostile runes from remote-controlled
// text. It is a stdlib-only leaf so every package that renders server
// output (sshconn, audit, apply) can share one rule without import cycles.
package sanitize

import (
	"strings"
	"unicode"
)

// Remote strips control characters (except newline and tab) and Unicode
// format (Cf) runes. unicode.IsControl covers C0, DEL and C1 — C1 CSI
// (U+009B) acts like ESC [ in some terminals; Cf covers bidi overrides
// such as U+202E that visually reorder text. encoding/json does not
// escape C1 or Cf, so JSON renderers need this too. internal/clog's
// sanitize applies the same class of defense on the log path.
func Remote(s string) string {
	return strings.Map(func(r rune) rune {
		if (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}
```

In `internal/sshconn/sshconn.go`, replace the body of `SanitizeRemote` (keep its doc comment, add one line pointing to the leaf) and drop the now-unused `unicode` import if nothing else uses it:

```go
// SanitizeRemote … (existing comment) … The rule lives in internal/sanitize.
func SanitizeRemote(s string) string { return sanitize.Remote(s) }
```

- [ ] **Step 4: Run** `GOTOOLCHAIN=go1.26.9 go test ./internal/sanitize/ ./internal/sshconn/` — PASS. Check `.golangci.yml` `depguard` rules allow `internal/sanitize` from `internal/sshconn` and `internal/audit` (they allow module-internal imports today; confirm by running lint in B7).

### Task B2: Truncation wording

**Files:** `internal/sshconn/sshconn.go:194`, `internal/sshconn/sshconn_test.go:373`

- [ ] **Step 1: Update the test first** — at `sshconn_test.go:373` change `"refusing to audit"` to `"refusing to trust a truncated authorized_keys"`.
- [ ] **Step 2: Run** `GOTOOLCHAIN=go1.26.9 go test ./internal/sshconn/ -run Truncat` — FAIL.
- [ ] **Step 3: Change** the message in `FinishRead` to:
  `"remote read on %s: remote output exceeded 1MiB — refusing to trust a truncated authorized_keys"`.
- [ ] **Step 4: Run** — PASS. Then `rtk proxy grep -rn "refusing to audit" .` must print nothing.

### Task B3: Sanitize `audit --json`

**Files:** `internal/audit/json.go`, `internal/audit/json_test.go`

- [ ] **Step 1: Write the failing test** — append to `internal/audit/json_test.go` (reuse that file's existing fixture helpers for building a `ServerResult`; the shape below uses the public types directly):

```go
// TestRenderJSONSanitizesHostileText: on-server comments, option drift and
// error strings with ESC / C1 / bidi runes never reach audit --json raw.
func TestRenderJSONSanitizesHostileText(t *testing.T) {
	const hostile = "x\x1b[31m\u009b2J‮y"
	cfg, err := config.Parse([]byte(`
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
`))
	if err != nil {
		t.Fatal(err)
	}
	stray, err := authkeys.ParseLine(testkeys.Line(t, 9) + " " + hostile)
	if err != nil {
		t.Fatal(err)
	}
	results := []ServerResult{
		{Server: cfg.Servers[0], Diff: Diff{Unauthorized: []authkeys.Key{stray}}},
		{Server: cfg.Servers[1], Err: errors.New("banner " + hostile)},
	}
	var buf bytes.Buffer
	if err := RenderJSON(&buf, cfg, results, JSONOptions{}); err != nil {
		t.Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	for _, r := range []rune{0x1b, 0x9b, 0x202e} {
		if strings.ContainsRune(fmt.Sprint(decoded), r) {
			t.Errorf("hostile rune %U survived:\n%s", r, buf.String())
		}
	}
}
```

Adapt field names (`Diff`, `Unauthorized`, `ServerResult`, `JSONOptions`) to the actual ones in `internal/audit` — read `audit.go` and the existing `json_test.go` fixtures first; the assertion (no hostile rune anywhere in the decoded document) is what matters.

- [ ] **Step 2: Run — expect FAIL** (comment passes through raw today).

- [ ] **Step 3: Implement** in `internal/audit/json.go` (import `github.com/javadh75/SSHepherd/internal/sanitize`):
  - `jsonKeyFor`: `Comment: sanitize.Remote(k.Comment)`.
  - error: `msg := sanitize.Remote(oneLine(r.Err))`.
  - parse errors: `Error: sanitize.Remote(pe.Error())`.
  - options drift: sanitize each element of `actual` and `desired` before `nonNil(...)`.
  - comment drift: `Actual: sanitize.Remote(actual), Desired: sanitize.Remote(desired)`.
  - Update the comment at the error site: "oneLine collapses newlines; sanitize.Remote strips C0/C1/Cf, which encoding/json leaves raw."

- [ ] **Step 4: Run** `GOTOOLCHAIN=go1.26.9 go test ./internal/audit/` — PASS, and **existing audit goldens unchanged** (fixtures contain no hostile runes).

### Task B4: `--json` flag and the prompt rule

**Files:** `cmd/sshepherd/edit.go`, `cmd/sshepherd/apply.go`, `cmd/sshepherd/editrun.go`, `README.md` (three rows), new `cmd/sshepherd/json_cmd_test.go`

- [ ] **Step 1: Write the failing tests** — create `cmd/sshepherd/json_cmd_test.go`:

```go
package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestJSONNeedsDryRunOrYes: every write command refuses --json without
// --dry-run/--yes, exit 3, before the manifest is read (a missing manifest
// would otherwise be the error) and with nothing on stdout.
func TestJSONNeedsDryRunOrYes(t *testing.T) {
	for _, args := range [][]string{
		{"apply", "--json", "--config", "/nonexistent.yaml"},
		{"revoke", "bob", "--json", "--config", "/nonexistent.yaml"},
		{"revoke", "bob", "--json", "--no-apply", "--config", "/nonexistent.yaml"},
		{"rotate", "bob", "--old", "SHA256:x", "--new", "/x.pub", "--json", "--config", "/nonexistent.yaml"},
	} {
		var out, errBuf bytes.Buffer
		if code := run(args, &out, &errBuf); code != 3 {
			t.Errorf("%v: exit = %d, want 3", args, code)
		}
		if !strings.Contains(errBuf.String(), "--json needs --dry-run or --yes") {
			t.Errorf("%v: stderr = %q", args, errBuf.String())
		}
		if out.Len() != 0 {
			t.Errorf("%v: stdout = %q, want empty", args, out.String())
		}
	}
}

// oneJSONDoc asserts stdout is exactly one JSON value and returns it.
func oneJSONDoc(t *testing.T, stdout string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if dec.More() {
		t.Fatalf("stdout carries more than one JSON value:\n%s", stdout)
	}
	if rest := strings.TrimSpace(stdout[dec.InputOffset():]); rest != "" {
		t.Fatalf("trailing text after the document: %q", rest)
	}
	return doc
}

func TestApplyJSONEmptyFleet(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--json", "--dry-run", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	if doc["command"] != "apply" || len(doc["servers"].([]any)) != 0 {
		t.Errorf("doc = %v", doc)
	}
}
```

- [ ] **Step 2: Run** `GOTOOLCHAIN=go1.26.9 go test ./cmd/sshepherd/ -run 'TestJSON|TestApplyJSON'` — FAIL (unknown flag `--json`).

- [ ] **Step 3: Implement.**

`cmd/sshepherd/edit.go` — add the field, flag, and check:

```go
type runFlags struct {
	cfgPath    string
	knownHosts string
	parallel   int
	dryRun     bool
	yes        bool
	json       bool
	idf        identityFlags
}
```

In `register`, after the `--yes` line:

```go
	cmd.Flags().BoolVar(&f.json, "json", false,
		"emit the plan and outcome as machine-readable JSON on stdout (needs --dry-run or --yes)")
```

And add:

```go
// errJSONNeedsMode: a script cannot answer the [y/N] prompt, so --json
// must say up front whether this run previews or writes.
var errJSONNeedsMode = errors.New("--json needs --dry-run or --yes (a script cannot answer the confirmation prompt)")

// checkJSON enforces errJSONNeedsMode; it runs with the other flag checks,
// before the manifest is read or anything is printed.
func (f *runFlags) checkJSON() error {
	if f.json && !f.dryRun && !f.yes {
		return errJSONNeedsMode
	}
	return nil
}
```

`cmd/sshepherd/apply.go` `RunE` — right after `validateFlags`:

```go
			if err := rf.checkJSON(); err != nil {
				return err
			}
```

and the zero-targets branch:

```go
			if len(targets) == 0 {
				if rf.json {
					return apply.RenderJSON(stdout, cfg, nil, apply.JSONOptions{Command: "apply", DryRun: rf.dryRun, Skipped: skipped})
				}
				apply.Render(stdout, cfg, nil, ropts)
				return nil
			}
```

(`RenderJSON` already wraps its error, satisfying `wrapcheck`.)

`cmd/sshepherd/editrun.go` `editFlags.validate` — first statement:

```go
	if err := f.run.checkJSON(); err != nil {
		return identities{}, err
	}
```

`README.md` — add one row to each of the three flag tables, directly under the `--yes` row:

- apply: ``| `--json` | off | Emit the plan and outcome as machine-readable JSON on stdout (needs `--dry-run` or `--yes`) |``
- revoke and rotate: the same row.

- [ ] **Step 4: Run** the new tests plus `TestHelpMatchesREADMETables` — PASS.

### Task B5: `runApply` / apply finish — JSON render, `stageWithheld`

**Files:** `cmd/sshepherd/apply.go`, `cmd/sshepherd/json_cmd_test.go`

- [ ] **Step 1: Write the failing test** — append (uses the hermetic fleet from `audit_hermetic_test.go`):

```go
func TestApplyJSONHermetic(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtestKnownHosts(t, srv, hostKey)

	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	servers := doc["servers"].([]any)
	s0 := servers[0].(map[string]any)
	if s0["class"] != "change" || s0["outcome"] != "applied" {
		t.Errorf("server = %v", s0)
	}
	if doc["summary"].(map[string]any)["exit_code"] != float64(0) {
		t.Errorf("summary = %v", doc["summary"])
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"apply", "--json", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("re-run exit = %d\n%s", code, errBuf.String())
	}
	doc = oneJSONDoc(t, out.String())
	if doc["dry_run"] != true || doc["servers"].([]any)[0].(map[string]any)["class"] != "converged" {
		t.Errorf("dry-run doc = %v", doc)
	}
}

// TestApplyJSONSkipped: --server exclusions land in summary.skipped, the
// text "(N skipped by --server)" line is not printed, and the skipped
// server is not in the document. web-1 is unreachable (closed port), so
// the run exits 1 with a document.
func TestApplyJSONSkipped(t *testing.T) {
	fakeAgent(t)
	kh := writeEmptyKnownHosts(t)
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
  - {name: web-2, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--json", "--dry-run", "--config", path, "--known-hosts", kh, "--server", "web-1"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	summary := doc["summary"].(map[string]any)
	if summary["skipped"] != float64(1) || summary["servers"] != float64(1) || summary["unreachable"] != float64(1) {
		t.Errorf("summary = %v", summary)
	}
	if strings.Contains(out.String(), "skipped by --server") || strings.Contains(out.String(), "web-2") {
		t.Errorf("text leaked into the document:\n%s", out.String())
	}
}
```

`sshtestKnownHosts(t, srv, hostKey)` above stands for `sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))` — write that expression inline (import `github.com/javadh75/SSHepherd/internal/sshconn/sshtest`); `fakeAgent`, `writeEmptyKnownHosts`, `closedPort`, `strconvItoa`, `writeConfig`, `shortHome` and `hermeticFleet` already exist in the package's test files.

- [ ] **Step 2: Run — expect FAIL** (text is printed).

- [ ] **Step 3: Implement** in `apply.go`.

Add the stage:

```go
const (
	stagePlanned   applyStage = iota // plan shown, nothing confirmed: --dry-run, or nothing to confirm
	stageDeclined                    // the confirmation prompt was declined
	stageConfirmed                   // confirmed: beforeWrite passed and the writes (if any) ran
	stageWithheld                    // planned, but the prompt hook or beforeWrite withheld the run (errNonCompliant): nothing saved or written
)
```

In `runApply`:

```go
	ctx, log := cmd.Context(), a.logger
	if run.header != nil && !rf.json {
		run.header(stdout)
	}
	…
	if !rf.json {
		apply.Render(stdout, run.cfg, plans, apply.RenderOptions{Color: a.reportColor, Former: run.former, FormerNote: run.formerNote})
	}

	toWrite := countChanges(plans)
	if rf.dryRun || (toWrite == 0 && !run.alwaysConfirm) {
		return run.finish(plans, stagePlanned)
	}
	question, err := run.prompt(plans, toWrite)
	if err != nil {
		return run.withheld(plans, err)
	}
	…
	if toWrite == 0 {
		if err := run.beforeWrite(ctx, plans, nil); err != nil {
			return run.withheld(plans, err)
		}
		return run.finish(plans, stageConfirmed)
	}
	log.Info(…)
	if err := writePhase(ctx, log, pre, run.preferKeys, plans, rf.parallel, run.beforeWrite); err != nil {
		return run.withheld(plans, err)
	}
	return run.finish(plans, stageConfirmed)
```

and the helper:

```go
// withheld routes a hook's errNonCompliant (nothing can land, no held key
// survives) through finish so the run still reports — under --json that
// is the document; any other error is a tool error and passes through.
// writePhase returns beforeWrite's error before any worker starts, so the
// plans are untouched.
func (run applyRun) withheld(plans []apply.ServerPlan, err error) error {
	if errors.Is(err, errNonCompliant) {
		return run.finish(plans, stageWithheld)
	}
	return err
}
```

Apply's own `finish` closure:

```go
				finish: func(plans []apply.ServerPlan, stage applyStage) error {
					if stage == stageDeclined {
						log.Error("aborted; no changes made")
					}
					if rf.json {
						if err := apply.RenderJSON(stdout, cfg, plans, apply.JSONOptions{Command: "apply", DryRun: rf.dryRun, Skipped: skipped}); err != nil {
							return err
						}
					} else {
						apply.RenderSummary(stdout, plans, ropts)
						if skipped > 0 {
							fmt.Fprintf(stdout, "(%s skipped by --server)\n", apply.Plural(skipped, "server", "servers"))
						}
					}
					if stage == stageWithheld || apply.ExitCode(plans) != 0 {
						return errNonCompliant
					}
					return nil
				},
```

Update the `finish` field comment in `applyRun`: "finish renders the tail of the report (or, under --json, the whole document) and maps the run to its exit; stageWithheld always maps to exit 1."

- [ ] **Step 4: Run** `GOTOOLCHAIN=go1.26.9 go test ./cmd/sshepherd/` — all PASS (text-mode tests unchanged).

### Task B6: revoke/rotate — JSON on every exit-0/1 path

**Files:** `cmd/sshepherd/editrun.go`, `cmd/sshepherd/json_cmd_test.go`

- [ ] **Step 1: Write the failing tests** — append (fixtures from `revoke_test.go`, same package):

```go
func TestRevokeJSONHermetic(t *testing.T) {
	_, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	edit := doc["edit"].(map[string]any)
	if doc["command"] != "revoke" || edit["saved"] != true {
		t.Errorf("doc = %v", doc)
	}
	for _, s := range doc["servers"].([]any) {
		sm := s.(map[string]any)
		if sm["outcome"] != "applied" {
			t.Errorf("%v outcome = %v", sm["name"], sm["outcome"])
		}
		removed := sm["changes"].(map[string]any)["remove"].([]any)
		if len(removed) != 1 || removed[0].(map[string]any)["former_owner"] != "bob" {
			t.Errorf("%v remove = %v", sm["name"], removed)
		}
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
}

func TestRevokeJSONDryRun(t *testing.T) {
	_, kh, cfg := twoUserFleet(t)
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--json", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (pending changes)\n%s", code, errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	if doc["dry_run"] != true || doc["edit"].(map[string]any)["saved"] != false {
		t.Errorf("doc = %v", doc)
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("--dry-run saved")
	}
}

func TestRevokeJSONNothingCanLand(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	for _, h := range hosts {
		h.install(t, []byte{1, 2}, "this line is not a key")
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	if doc["edit"].(map[string]any)["saved"] != false {
		t.Errorf("edit = %v", doc["edit"])
	}
	for _, s := range doc["servers"].([]any) {
		if s.(map[string]any)["class"] != "refused" {
			t.Errorf("server = %v, want refused", s)
		}
	}
}

func TestRevokeJSONNoApply(t *testing.T) {
	for _, dry := range []bool{false, true} {
		_, _, cfg := twoUserFleet(t)
		args := []string{"revoke", "bob", "--json", "--no-apply", "--config", cfg}
		if dry {
			args = append(args, "--dry-run")
		} else {
			args = append(args, "--yes")
		}
		var out, errBuf bytes.Buffer
		if code := run(args, &out, &errBuf); code != 0 {
			t.Fatalf("dry=%v exit = %d\n%s", dry, code, errBuf.String())
		}
		doc := oneJSONDoc(t, out.String())
		edit := doc["edit"].(map[string]any)
		if edit["saved"] != !dry || edit["affected"] != float64(2) || len(doc["servers"].([]any)) != 0 {
			t.Errorf("dry=%v doc = %v", dry, doc)
		}
	}
}
```

Also add a save-withheld test by copying `TestRevokeHeldKeysGoneAfterPrompt` (`revoke_test.go:408`) — it needs the interactive prompt to remove the agent socket between plan and write, which `--json` forbids. Instead, trigger the same path with `--yes` by installing a `beforeManifestSave`-independent seam: **skip this case at cmd level** and rely on (a) the `stageWithheld` routing already exercised by `TestRevokeJSONNothingCanLand` (prompt-hook path) and (b) a unit test of `applyRun.withheld`:

```go
func TestApplyRunWithheldRoutesNonCompliant(t *testing.T) {
	var got applyStage = -1
	run := applyRun{finish: func(_ []apply.ServerPlan, s applyStage) error { got = s; return errNonCompliant }}
	if err := run.withheld(nil, errNonCompliant); !errors.Is(err, errNonCompliant) || got != stageWithheld {
		t.Errorf("errNonCompliant: err=%v stage=%v", err, got)
	}
	got = -1
	boom := errors.New("boom")
	if err := run.withheld(nil, boom); err != boom || got != -1 {
		t.Errorf("tool error must pass through without finish: err=%v stage=%v", err, got)
	}
}
```

(imports: `errors`, `internal/apply`.)

- [ ] **Step 2: Run — expect FAIL.**

- [ ] **Step 3: Implement** in `editrun.go` `runEdit`:

```go
	aff := apply.Affected(ep.former, ep.edited)
	ep.summary.Affected = len(aff.Servers)
	ep.summary.Emptied = emptiedServers(ep.former, aff.Emptied)
	ropts := apply.RenderOptions{Color: a.reportColor, Former: ep.former, FormerNote: ep.formerNote}
	header := func(w io.Writer) { apply.RenderEditHeader(w, ep.summary, ropts) }
	// doc renders the --json document (nil in text mode). saved is read at
	// call time: finish runs after beforeWrite's save.
	var doc func(plans []apply.ServerPlan, saved bool) error
	if f.run.json {
		doc = func(plans []apply.ServerPlan, saved bool) error {
			return apply.RenderJSON(stdout, ep.edited, plans, apply.JSONOptions{
				Command: cmd.Name(), DryRun: f.run.dryRun, Former: ep.former, Edit: &ep.summary, Saved: saved,
			})
		}
	}
	saved := false
	if f.noApply || len(aff.Servers) == 0 {
		if doc == nil {
			header(stdout)
		}
		return saveOnly(cmd, log, stdout, f, ep, aff.Servers, doc)
	}
	return runApply(cmd, a, stdout, &f.run, ids, applyRun{
		…unchanged fields…
		beforeWrite: func(ctx context.Context, plans []apply.ServerPlan, fresh []sshconn.HeldKey) error {
			…existing interrupt check and no-survivor check unchanged…
			if err := saveEdit(stdout, ep, doc != nil); err != nil {
				return err
			}
			saved = true
			return nil
		},
		finish: func(plans []apply.ServerPlan, stage applyStage) error {
			return finishEdit(stdout, log, ep, aff, f.run.cfgPath, plans, stage, ropts, doc, saved)
		},
	})
```

`saveEdit` gains `quiet bool` and skips its reminder when set:

```go
func saveEdit(stdout io.Writer, ep editPlan, quiet bool) error {
	if err := ep.target.Save(ep.encoded); err != nil {
		return err
	}
	if !quiet {
		fmt.Fprintf(stdout, "manifest %s updated — commit and push it: an apply from a copy without this edit re-grants the removed key\n", ep.target.Path)
	}
	return nil
}
```

`saveOnly` gains the `doc` parameter:

```go
func saveOnly(cmd *cobra.Command, log *slog.Logger, stdout io.Writer, f *editFlags, ep editPlan, affected []string,
	doc func([]apply.ServerPlan, bool) error,
) error {
	if f.run.dryRun {
		log.Info("dry run — manifest not changed")
		if doc != nil {
			return doc(nil, false)
		}
		return nil
	}
	ok, err := confirmGate(cmd, f.run.yes, apply.EditPrompt(ep.summary.Operators, 0, len(affected), f.noApply))
	…unchanged…
	if err := saveEdit(stdout, ep, doc != nil); err != nil {
		return err
	}
	if doc != nil {
		return doc(nil, true)
	}
	switch { …unchanged text lines… }
	return nil
}
```

`finishEdit` gains `doc` and `saved`:

```go
func finishEdit(stdout io.Writer, log *slog.Logger, ep editPlan, aff apply.AffectedSet, cfgPath string,
	plans []apply.ServerPlan, stage applyStage, ropts apply.RenderOptions,
	doc func([]apply.ServerPlan, bool) error, saved bool,
) error {
	if stage == stageDeclined {
		log.Error("aborted; manifest not changed, nothing written")
		return errNonCompliant
	}
	if doc != nil {
		if err := doc(plans, saved); err != nil {
			return err
		}
		if stage == stageWithheld || apply.ExitCode(plans) != 0 {
			return errNonCompliant
		}
		return nil
	}
	if stage == stageWithheld {
		return errNonCompliant // text mode: the hook already logged why; plan already shown
	}
	…existing text body unchanged…
}
```

`saved` is true only after a successful save, so `stagePlanned` (dry run) and `stageWithheld` report `false` automatically.

- [ ] **Step 4: Run** `GOTOOLCHAIN=go1.26.9 go test ./cmd/sshepherd/` — all PASS, including every pre-existing revoke/rotate text test.

- [ ] **Step 5: stdout audit** — `rtk proxy grep -n "Fprint.*stdout\|Fprintln(stdout\|header(stdout)\|Render(stdout\|RenderSummary(stdout" cmd/sshepherd/apply.go cmd/sshepherd/editrun.go`. For each hit, confirm it is unreachable under `--json` (guarded by `rf.json`/`doc != nil`, or in a path that returns before it). List them in the hand-back.

### Task B7: Package gates

- [ ] `GOTOOLCHAIN=go1.26.9 go test -race ./internal/sanitize/ ./internal/sshconn/... ./internal/audit/ ./cmd/sshepherd/` — PASS.
- [ ] `GOTOOLCHAIN=go1.26.9 golangci-lint run ./...` — clean (stub file, if any, deleted first).
- [ ] Hand back: files changed, the stdout-site list from B6 Step 5, any deviation and why.

---

## Integrator

### Task I1: Merge and full gates

- [ ] Merge A and B into one tree; confirm `internal/apply/json_stub.go` does not exist.
- [ ] `GOTOOLCHAIN=go1.26.9 make check` — PASS (fmt, vet, lint, deadcode, gosec, govulncheck, gitleaks, coverage ≥ 80%).
- [ ] Re-run the B6 Step 5 stdout grep on the merged tree.

### Task I2: Integration + E2E

**Files:** `cmd/sshepherd/e2e_test.go`

- [ ] In `TestE2EApplyLoop`, change the "first apply normalizes and verifies" step to run
  `apply --json --yes --config adopted --known-hosts kh` and assert on the parsed document:

```go
	t.Run("first apply normalizes and verifies (--json)", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "apply", "--json", "--yes", "--config", adopted, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		var doc struct {
			Summary struct {
				Applied  int `json:"applied"`
				ExitCode int `json:"exit_code"`
			} `json:"summary"`
			Servers []struct {
				Outcome *string `json:"outcome"`
			} `json:"servers"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
		}
		if doc.Summary.Applied != 1 || doc.Summary.ExitCode != 0 || doc.Servers[0].Outcome == nil || *doc.Servers[0].Outcome != "applied" {
			t.Errorf("apply document = %+v\n%s", doc, out)
		}
	})
```

- [ ] Change the "revoke --key saves the manifest and converges" step to `revoke --key stalePub --json --yes …` and assert `edit.saved == true`, `edit.edits[0].kind == "remove-key"`, every server `outcome == "applied"`, `summary.exit_code == 0`. Keep the "re-apply is a byte-stable no-op" step in text mode (text coverage of the binary stays).
- [ ] Add `"encoding/json"` to the imports.
- [ ] `GOTOOLCHAIN=go1.26.9 make integration` — PASS.

### Task I3: README + CLAUDE.md

- [ ] README `### sshepherd apply`: after the flag table's note on `--dry-run`/`--yes`, add a **JSON** paragraph: `--json` prints one indented JSON document on stdout at the end of the run (schema 1, `command` names the kind), never the text report; it needs `--dry-run` or `--yes`; exit-3 tool errors print no document; comments and options are sanitized (control and Unicode format characters removed), so they may not byte-match the server line. Then a fenced ```json sample **copied verbatim** from `internal/apply/testdata/json_mixed.golden.json` (never hand-edited), and "See `internal/apply/testdata/json_*.golden.json` for every shape."
- [ ] README `### sshepherd revoke` / `rotate`: one sentence each — under `--json` the document adds an `edit` section (`saved`, `edits`, `affected`, `operators`, `emptied`); `--no-apply` prints the edit section with `servers: []`; sample copied from `json_revoke.golden.json`.
- [ ] README `audit --json` section: one sentence that comments and error text are sanitized the same way.
- [ ] README Status table: `apply` row → "… (text + `--json`)"; `revoke`/`rotate` row likewise.
- [ ] `CLAUDE.md` Status: append one sentence — "`apply`, `revoke` and `rotate` take `--json` (needs `--dry-run` or `--yes`): one schema-1 document with plan, per-server outcome and the manifest edit, written exactly when the run exits 0 or 1 (specced in `docs/superpowers/specs/2026-11-07-apply-json-design.md`); remote text in both JSON reports passes through the new `internal/sanitize` leaf."
- [ ] Re-run `GOTOOLCHAIN=go1.26.9 go test ./cmd/sshepherd/ -run TestHelpMatchesREADMETables`.

### Task I4: Commit

- [ ] `git add -A` (review `git status` first — only the files listed in this plan), then:

```bash
git commit -m "feat: --json for apply, revoke and rotate

One schema-1 document on stdout with the plan, per-server outcome and
the manifest edit; needs --dry-run or --yes; written exactly when the
run exits 0 or 1. Shared summary counting with the text report;
stageWithheld routes nothing-can-land and save-withheld through finish.
New internal/sanitize leaf; audit --json now strips C1/Cf runes too;
truncation error says 'refusing to trust'.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

## Verifier (independent) and repair pass

The verifier gets the spec, this plan and the commit — not the agents' hand-backs. It checks:
1. Every row of the spec's **Document rule** table: run (or read the test for) each path; stdout is exactly one JSON value on exit 0/1 and empty on exit 3.
2. Every row of the spec's **Text stdout suppressed** table is unreachable under `--json`.
3. Golden shapes match the spec field-by-field (presence rules: `outcome` null off change; `[]` never `null`; `former_owner`/`operator`/`error_kind` presence; per-kind edit fields).
4. The sanitization pins exist for both apply and audit and cover ESC, U+009B, U+202E.
5. README samples are byte-identical to the goldens they cite; help/README test green.
6. `make check` and `make integration` green.

Findings go to a repair pass that fixes only confirmed findings, re-runs the gates and amends nothing — it commits a follow-up `fix:` commit.
