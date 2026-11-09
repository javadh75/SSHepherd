# `validate` and `audit --server` (P10 S1, PRD-11) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step, not a commit.

**Commits at:** `docs/superpowers/plans/2026-11-09-p10-s1-validate-audit-server.md`

**Goal:** Build slice S1 of the approved access-model design (`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, decisions D25, D25a, OP1, OP4; finding PRD-11): an offline `sshepherd validate` with `--strict` and `--json`, a repeatable `audit --server NAME`, and the shared `Config.ManifestWarnings` rule that carries every load warning in JSON.

**Architecture:** `internal/config` gains one structured warning type (`ManifestWarning`, recorded through one `Config.warn`, so `Warnings` and `ManifestWarnings` can never disagree) and `GrantCount`. `cmd/sshepherd/validate.go` is a new command that reuses `readManifest`, `config.Parse`, `manifest.Load` and `sshread.LoadKnownHosts` and never dials. `audit --server` reuses `selectServers` (moved to `fleet.go`), `audit.Options.Servers` and the `(N servers skipped by --server)` line apply already prints; `summary.skipped` is additive.

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), Cobra, `gopkg.in/yaml.v3`, `golang.org/x/crypto/ssh/knownhosts` through `sshread`, the hermetic `internal/sshconn/sshtest` server, goleak, golden files (`-update`), golangci-lint (depguard layering, gocyclo 15, wrapcheck, errorlint, revive), `deadcode ./cmd/sshepherd`.

**Base:** `master` at `aff7bf0`, after P08 and P09. Every `file:line` below was read there. Where the design predates P08 and P09 the landed code wins; the place that matters is plan decision 2. Three questions need the owner's answer; see "Owner decisions".

**Not compiled.** This plan was drafted read-only: the code below was read against `aff7bf0` and syntax-checked with `gofmt`, but it was never built or run, and no test here has been seen to pass. A lane that finds a build error fixes it to the text's intent and says so in its hand-back.

---

## Owner decisions (hand-off to the main session)

The design is approved, and this plan builds its text wherever it speaks. In three places the design and the landed code, or two design sentences, cannot both stand. The main session asks the owner before the round named and passes the answers to the integrator in the wave's `handoffs`. The plan as written builds option (a) of each.

- **O1 (before round 2): a default-path known_hosts that exists but cannot be loaded.** A real contradiction with the draft of this plan, and a gap in the design. Design step 5 covers an explicit bad file (exit 3) and a missing default file (a warning), and is silent on a default file that exists but cannot be loaded (malformed, `EACCES`, `ENOTDIR` on `~/.ssh`, or `expandHome` failing with `HOME` unset). The exit table makes it a tool error, so exit 3. Design lines 283-284 say "Only an unreadable manifest, a bad flag or a bad explicit `--known-hosts` writes no document", so a document is written.
  - **(a) Built here, the design's text:** exit 3, with the document written: `valid: true` (design: `valid` is false only on a load error or a policy conflict), `host_keys_checked: false`, `summary.exit_code: 3`, the message in `errors`, and the message on stderr.
  - **(b) Fail closed, as `openFleet` does (what the draft did):** exit 3, no document. If the owner picks this: in Task 9's `run()` drop `&& v.explicitKnownHosts` and the `knownErr` handling in `finish`, delete `TestValidateJSONDefaultKnownHostsLoadFailure` and `TestValidateConflictAndDefaultKnownHostsFailure`, assert `out == ""` in `TestValidateBadKnownHosts`'s default subtest under `--json`, make the README's "no document" sentence say "a bad known_hosts file", and in Task 11 Step 2 change design lines 283-284 to "a bad `--known-hosts` file".
- **O2 (before round 1): `manifest_warnings` and P09's two load warnings.** A real contradiction inside the design: lines 158-159 say the field "carries every warning" and lines 181-183 say existing goldens stay byte-identical, and P09 landed two more `Config.Warnings` after that was written (`policy.go:47` ungranted weak key, `policy.go:72` passed expiry). Line 166 also says each slice names the kinds it adds, and `weak_key_ungranted` and `key_expired` are new names S1 never lists.
  - **(a) Built here:** every warning is carried, the two warnings get those two kinds, and `internal/audit/testdata/report_key_issues.golden.json` gains one additive entry.
  - **(b) The alternative:** those two warnings stay out of JSON and every golden holds. Then either `validate`'s `summary.warnings` no longer equals the length of `manifest_warnings` (line 318), or `--strict` stops counting those two warnings.
  - The spec amendment for (a) is in Task 11 Step 1 and is applied **only once the owner has answered**.
- **O3 (before round 2's commit): the README half that waits for S8.** Design line 343 asks S1's README to say that validate writes a document on some exit 3s "while `import` and `adopt` almost never do". Those commands have no `--json` until S8, so the second half describes behaviour S1 does not have.
  - **(a) Built here:** S1's README states validate's half, and Task 11 Step 2 adds the other half to S8's **README** paragraph in the design, so the requirement has an owner. That edit is bookkeeping and is applied unless the owner picks (b).
  - **(b)** Write the whole sentence in S1's README now.

Without an answer, the code is still built as (a). The integrator leaves O2's spec amendment out and reports it, so a parked question blocks no round.

---

## How this plan is cut (read first)

### Why the lanes look the way they do

1. **Two rounds, not two parallel lanes.** The design's lane row (S1: A `validate.go`, `validate_test.go`, `run.go` · B `audit.go`, `fleet.go`, `apply.go`, the JSON files) lists two lanes, but `validate.go` needs `config.ManifestWarning` and `audit.ManifestFindings`, which lane B produces, and a lane must compile on earlier rounds alone. So B runs first as round 1 (`audit-server`) and A as round 2 (`validate`). Design lane B also takes `internal/config`'s `ManifestWarning`, because the rename and its consumers must land atomically.
2. **`deadcode ./cmd/sshepherd` is part of `make check`.** `GrantCount` has no caller until `validate` exists, so it lands in round 2 with its caller. `printSkipped` lands with its two callers. Constants, types and struct fields are exempt.
3. **`TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` read `README.md`.** Round 1 adds a flag row and round 2 adds a whole section and a footer. Each lane applies its own `docsDelta` to its worktree's `README.md` before `make check`; the ownership filter drops that change from the patch, and **the integrator re-applies the `docsDelta` before running `make check`**.

### Rounds

| Round | Lane | Builds on |
|---|---|---|
| 1 | `audit-server` (Tasks 1-5, `needsIntegration`): `ManifestWarning`, audit and apply JSON, `selectServers` move, `audit --server` | `aff7bf0` |
| 2 | `validate` (Tasks 6-10): `GrantCount`, the command, known_hosts, JSON, hermetic proof | round 1 |

The integrator runs Task 11 Step 1 for round 1's commit and Step 2 for round 2's. An independent verifier runs Task 12 after round 2. No lane owns either.

### Files S2 also edits

S1 needs no manifest change and runs in the same wave as S2. These files are in both plans. S1 round 1 merges before S2 round 1 (`import`, for `adopt.go`) and S1 round 2 merges before S2 round 2 (`identity`, for `help_readme_test.go` and `audit.golden`); never run an S1 and an S2 round in parallel. The rounds cannot be zipped by index: zipped, rounds 1 and 2 would each have a file with two owners.

| File | S1 edit | S2 edit | Resolution |
|---|---|---|---|
| `cmd/sshepherd/adopt.go` | one argument at `:288` (`readFleet` call) | `--merge` help at `:338` (S2 `import`) | Separate hunks |
| `cmd/sshepherd/help_readme_test.go` | one table row after `:118` | `TestHelpShowsIdentityVarnames` at `:168` (S2 `identity`) | Separate hunks |
| `cmd/sshepherd/testdata/help/audit.golden` | new `--server` line and example | `--identity-passphrase` line (`KEY=FILE` to `PATH=FILE`, S2 `identity`) | On a conflict, regenerate with `-update` and read the diff |
| `README.md` | integrator-only | integrator-only | Integrator applies both deltas |

`adopt.go` is outside the design's S1 lane row, but the design's S1 text requires it ("`readFleet` gains a `targets` argument; adopt passes the whole fleet").

### Plan decisions (not in the spec; none changes a decided exit code, refusal or load)

1. **Round order** as above: the design's row reads as parallel; it cannot be, because of the type dependency.
2. **`manifest_warnings` also carries P09's two warnings, and one golden changes (owner decision O2).** The design's "carries every warning" and its "existing goldens stay byte-identical" cannot both hold now that P09 has landed two more `Config.Warnings`. `validate`'s warning count and `--strict` need those warnings, so they get kinds `weak_key_ungranted` and `key_expired`, and `internal/audit/testdata/report_key_issues.golden.json` gains one additive `manifest_warnings` entry, because its manifest has a passed `expiry-time`. It is the only golden expected to change. The owner has not ruled on this; see O2.
3. **Only `tombstone_unknown_server` and `host_key_not_recorded` carry extra fields.** The design says the tombstone fields stay omitted for other kinds, and its own sample gives `host_key_not_recorded` a `server`. `comment_on_multi_key`, `weak_key_ungranted`, `key_expired`, `manifest_not_editable` and `known_hosts_missing` are `kind` and `message` only.
4. **A default-path known_hosts that exists but cannot be loaded is exit 3, and `--json` still writes its document (owner decision O1).** Design lines 283-284 list what writes no document, and this case is not on the list; the draft of this plan wrongly said the design did not cover it. The rule applies to any non-`ErrNotExist` failure of the default path, and to `expandHome` failing. See O1 for the alternative.
5. **`memoryJSON` is exported as `audit.ManifestFindings`** so `validate` sanitizes manifest text through the same code as audit. apply's `cleanMemory` keeps its name and only changes its type.
6. **A JSON run that exits 3 also prints its error on stderr.** The document goes to stdout, and the same message the text mode prints goes to stderr.
7. **`manifest OK` always shows the count**, including `(0 warnings)`.
8. **README: the "import and adopt almost never do" half of the design's sentence waits for S8 (owner decision O3).** Those commands have no `--json` yet, so S1's README states only validate's half, and Task 11 Step 2 records the other half in S8's README paragraph so the requirement keeps an owner.
9. **README has no command list under Commands**, so the design's "Command list" means the Status table row plus the new section.
10. **`validate --json` goldens replace the temporary known_hosts path with `~/.ssh/known_hosts`**, so the golden matches the design's text and the README can copy it.

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted.
- **Before hand-back:** apply this lane's `docsDelta` to the worktree's `README.md` (gate only), run `make check`, then `git add -A`, unstage every path outside the lane's globs (`README.md` and `CLAUDE.md` always), and write the patch. Sample output in docs comes from the golden named beside it, never from this plan.
- The lane's `README.md` edit is the gate-only `docsDelta`, which the unstage step above removes. **Do not list `README.md` in `foreignBreaks`**; the integrator treats that list as merge fixes.
- gofmt realigns a struct or `var` block when a field's width changes; a single-line edit can leave the file not gofmt-clean. Run `gofmt -w` on what you edited before `make check` (the tasks name the files that need it).
- Coverage: `make coverage` gates production packages at `COVERAGE_MIN := 93`.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests exists.
- gocyclo 15 applies to production code, and function literals count toward their enclosing function. errorlint applies to tests too. New test variables must not shadow builtins (revive).

---

## File structure

| File | Round/lane | Responsibility |
|---|---|---|
| `internal/config/warnings.go` (new), `warnings_test.go` (new) | 1 `audit-server` | `ManifestWarning`, the kinds, `Config.warn` |
| `internal/config/config.go`, `revoked.go`, `policy.go`, `revoked_test.go` | 1 `audit-server` | every warning goes through `warn`; `TombstoneWarning` removed |
| `internal/audit/json.go`, `json_test.go`, `testdata/report_key_issues.golden.json` | 1 `audit-server` | `ManifestFindings`, `summary.skipped` |
| `internal/apply/json.go`, `json_test.go` | 1 `audit-server` | the type rename |
| `cmd/sshepherd/fleet.go`, `apply.go`, `adopt.go` | 1 `audit-server` | `selectServers` moved, `printSkipped`, `readFleet` takes targets |
| `cmd/sshepherd/audit.go`, `audit_test.go`, `testdata/help/audit.golden` | 1 `audit-server` | `--server` |
| `internal/config/grants.go` (new), `grants_test.go` (new) | 2 `validate` | `GrantCount` |
| `cmd/sshepherd/validate.go` (new), `validate_test.go` (new), `validate_pipe_test.go` (new) | 2 `validate` | the command |
| `cmd/sshepherd/run.go`, `run_test.go`, `usage_test.go`, `help_readme_test.go` | 2 `validate` | `AddCommand`, `exitCodesValidate`, help and README tests |
| `cmd/sshepherd/testdata/help/root.golden`, `validate.golden` (new), `testdata/validate_*.golden.json` (new) | 2 `validate` | snapshots |

## Design coverage

| Design requirement | Task |
|---|---|
| Shared rule: `ManifestWarning`, `revoked_index` pointer, reset moved, `comment_on_multi_key` | 1, 2 |
| `audit --server`, `selectServers` moved, `readFleet` targets, `summary.skipped`, skip line, OP4 | 3, 4 |
| `validate` steps 1-4, 6, 7, text for a conflict, exits, `GrantCount` | 6, 7 |
| Step 5 known_hosts, OP1, cert-authority | 8 |
| A bad default known_hosts still writes the document (lines 283-284, O1) | 8, 9 |
| `--json` shape, each exit, `errors` split | 9 |
| Hermetic no-socket proof, piped manifest, help goldens, README flag test | 7, 10 |
| Repeatable `--server` at the audit level (line 324), `host_keys_checked`, a bad flag writes no document | 4, 9 |
| P09 plan decision 14: `validate` exit 3 on `weak_key`, exit 0 for an ungranted weak key | 7, 9 |

---

## Round 1 — lane `audit-server` (Tasks 1-5)

Owns the files in the last JSON block. Finding: PRD-11.

### Task 1: `config.ManifestWarning`

**Files:** Create `internal/config/warnings.go`, `internal/config/warnings_test.go`. Modify `internal/config/config.go:72-74,136,161-163`, `internal/config/revoked.go:90-99,133,231-234`, `internal/config/policy.go:47,72`, `internal/config/revoked_test.go:145-149`.

- [ ] **Step 1: Write the failing test** (`internal/config/warnings_test.go`):

```go
package config

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestManifestWarningsMirrorWarnings: every load warning is recorded twice,
// as text for stderr and as a structured object for JSON, in the same order,
// each with its kind.
func TestManifestWarningsMirrorWarnings(t *testing.T) {
	pinNow(t, time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))
	cfg, err := Parse([]byte(`users:
  - {name: multi, comment: "c", keys: ["` + testkeys.Line(t, 1) + `", "` + testkeys.Line(t, 2) + `"]}
  - {name: old, keys: ["` + testkeys.DSALine(t, 7) + `"]}
  - {name: gone, keys: ["expiry-time=\"20200101\" ` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: gone, servers: [web-1]}
revoked:
  - {user: gone, servers: [db-9], date: 2026-11-08}
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var kinds, messages []string
	for _, w := range cfg.ManifestWarnings {
		kinds = append(kinds, w.Kind)
		messages = append(messages, w.Message)
	}
	want := []string{WarnCommentOnMultiKey, WarnTombstoneUnknownServer, WarnWeakKeyUngranted, WarnKeyExpired}
	if !slices.Equal(kinds, want) {
		t.Errorf("kinds = %v, want %v", kinds, want)
	}
	if !slices.Equal(messages, cfg.Warnings) {
		t.Errorf("messages = %q\nWarnings = %q", messages, cfg.Warnings)
	}
	for _, w := range cfg.ManifestWarnings {
		if w.Kind == WarnTombstoneUnknownServer {
			if w.RevokedIndex == nil || *w.RevokedIndex != 0 || w.User != "gone" || w.Server != "db-9" {
				t.Errorf("tombstone warning = %+v", w)
			}
			continue
		}
		if w.RevokedIndex != nil || w.User != "" || w.Server != "" {
			t.Errorf("%s carries tombstone fields: %+v", w.Kind, w)
		}
	}
}

// TestManifestWarningWireShape: revoked[0] still prints its index, and the
// tombstone fields vanish for every other kind.
func TestManifestWarningWireShape(t *testing.T) {
	zero := 0
	for _, tc := range []struct {
		w    ManifestWarning
		want string
	}{
		{ManifestWarning{Kind: WarnTombstoneUnknownServer, RevokedIndex: &zero, User: "bob", Server: "db-9", Message: "m"},
			`{"kind":"tombstone_unknown_server","revoked_index":0,"user":"bob","server":"db-9","message":"m"}`},
		{ManifestWarning{Kind: WarnCommentOnMultiKey, Message: "m"}, `{"kind":"comment_on_multi_key","message":"m"}`},
	} {
		got, err := json.Marshal(tc.w)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("got %s\nwant %s", got, tc.want)
		}
	}
}
```

- [ ] **Step 2: See it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'TestManifestWarning'`
Expected: build failure, `undefined: WarnCommentOnMultiKey`.

- [ ] **Step 3: Add the type** (`internal/config/warnings.go`):

```go
package config

// The manifest_warnings kinds config records. Consumers ignore kinds they do
// not know; validate adds its own in cmd/sshepherd.
const (
	WarnTombstoneUnknownServer = "tombstone_unknown_server"
	WarnCommentOnMultiKey      = "comment_on_multi_key"
	WarnWeakKeyUngranted       = "weak_key_ungranted"
	WarnKeyExpired             = "key_expired"
)

// ManifestWarning is one load warning in structured form: an object of
// manifest_warnings in the audit, apply and validate JSON. RevokedIndex and
// User belong to tombstone_unknown_server; Server also to validate's
// host_key_not_recorded. RevokedIndex is a pointer so revoked[0] still prints.
type ManifestWarning struct {
	Kind         string `json:"kind"`
	RevokedIndex *int   `json:"revoked_index,omitempty"`
	User         string `json:"user,omitempty"`
	Server       string `json:"server,omitempty"`
	Message      string `json:"message"`
}

// warn records one load warning in both forms, so Warnings (stderr) and
// ManifestWarnings (JSON) can never disagree.
func (c *Config) warn(w ManifestWarning) {
	c.Warnings = append(c.Warnings, w.Message)
	c.ManifestWarnings = append(c.ManifestWarnings, w)
}
```

- [ ] **Step 4: Route every warning through `warn`.**

`internal/config/config.go:72-74`, replace the `TombstoneWarnings` field and its comment:

```go
	// ManifestWarnings are Warnings in structured form (the JSON
	// manifest_warnings objects), one per entry, in the same order.
	ManifestWarnings []ManifestWarning `yaml:"-"`
```

`internal/config/config.go:136`, reset both next to each other:

```go
	c.Warnings = nil
	c.ManifestWarnings = nil
```

`internal/config/config.go:161-163`:

```go
			c.warn(ManifestWarning{Kind: WarnCommentOnMultiKey, Message: fmt.Sprintf(
				"user %q: comment is set on a user with %d keys; apply will write the same comment on every key",
				u.Name, len(u.Keys))})
```

`internal/config/revoked.go`: delete the `TombstoneWarning` type (`:90-99`) and the `c.TombstoneWarnings = nil` line (`:133`). The reset moved to `validateUsers` because `validateRevoked` runs after `validateAccess` and would erase that step's warnings. Replace `:231-234`:

```go
		c.warn(ManifestWarning{Kind: WarnTombstoneUnknownServer, RevokedIndex: &i, User: t.User, Server: s, Message: msg})
```

`internal/config/policy.go:47`:

```go
				c.warn(ManifestWarning{Kind: WarnWeakKeyUngranted, Message: fmt.Sprintf("user %q key %d (%s): %s key, granted on no server", u.Name, i+1, k.Fingerprint, k.Weak)})
```

`internal/config/policy.go:72`:

```go
				c.warn(ManifestWarning{Kind: WarnKeyExpired, Message: fmt.Sprintf("user %q key %d: %s has passed; sshd no longer accepts this key", u.Name, i+1, opt)})
```

- [ ] **Step 5: Update the existing assertion** (`internal/config/revoked_test.go:145-149`):

```go
	if len(cfg.ManifestWarnings) != 1 {
		t.Fatalf("ManifestWarnings = %+v, want one", cfg.ManifestWarnings)
	}
	if w := cfg.ManifestWarnings[0]; w.Kind != WarnTombstoneUnknownServer || w.RevokedIndex == nil || *w.RevokedIndex != 0 ||
		w.User != "bob" || w.Server != "db-9" || w.Message != want {
		t.Errorf("ManifestWarnings[0] = %+v", w)
	}
```

- [ ] **Step 6: See it pass.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS. (`internal/audit` and `internal/apply` do not build until Task 2.)

### Task 2: audit and apply JSON carry every warning

**Files:** Modify `internal/audit/json.go:29,181,339-353`, `internal/apply/json.go:60,289-304`, `internal/audit/json_test.go`, `internal/apply/json_test.go:711,775-776,784`, `internal/audit/testdata/report_key_issues.golden.json`.

- [ ] **Step 1: Write the failing tests.** Add to `internal/audit/json_test.go`:

```go
// TestRenderJSONCarriesEveryManifestWarning: a non-tombstone warning reaches
// manifest_warnings with kind and message only.
func TestRenderJSONCarriesEveryManifestWarning(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, comment: "a", keys: ["` + testkeys.Line(t, 1) + `", "` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Warnings []map[string]any `json:"manifest_warnings"`
	}
	if err := json.Unmarshal(renderJSON(t, cfg, nil), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Warnings) != 1 || doc.Warnings[0]["kind"] != config.WarnCommentOnMultiKey {
		t.Fatalf("manifest_warnings = %v", doc.Warnings)
	}
	for _, absent := range []string{"revoked_index", "user", "server"} {
		if _, ok := doc.Warnings[0][absent]; ok {
			t.Errorf("%s must be omitted: %v", absent, doc.Warnings[0])
		}
	}
}
```

Add to `internal/apply/json_test.go`, and change `:711` and `:784` to `[]config.ManifestWarning`, and `:775-776` to `cfg.ManifestWarnings`:

```go
// TestRenderJSONCarriesEveryManifestWarning: apply's document carries a
// non-tombstone warning too.
func TestRenderJSONCarriesEveryManifestWarning(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, comment: "a", keys: ["` + testkeys.Line(t, 2) + `", "` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`))
	if err != nil {
		t.Fatal(err)
	}
	got := renderJSONCfg(t, cfg, nil, JSONOptions{Command: "apply", DryRun: true})
	if !bytes.Contains(got, []byte(`"kind": "comment_on_multi_key"`)) {
		t.Errorf("document lacks the warning:\n%s", got)
	}
}
```

- [ ] **Step 2: See it fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit ./internal/apply -run 'TestRenderJSONCarriesEveryManifestWarning'`
Expected: build failure, `undefined: config.TombstoneWarning`.

- [ ] **Step 3: Change the types.**

`internal/audit/json.go:29`:

```go
	ManifestWarnings []config.ManifestWarning `json:"manifest_warnings,omitempty"`
```

`internal/audit/json.go:181`:

```go
	rep.PolicyConflicts, rep.ManifestWarnings = ManifestFindings(cfg)
```

`internal/audit/json.go:339-353`:

```go
// ManifestFindings is the manifest's policy conflicts and load warnings with
// every manifest-derived text through sanitize.Remote (spec §9). A D1e
// warning's server may hold control runes. Each list stays nil when empty
// (omitted). validate's document uses it too.
func ManifestFindings(cfg *config.Config) ([]config.Conflict, []config.ManifestWarning) {
	cs := cfg.Conflicts() // a copy
	for i := range cs {
		cs[i].Message, cs[i].User = sanitize.Remote(cs[i].Message), sanitize.Remote(cs[i].User)
	}
	ws := slices.Clone(cfg.ManifestWarnings)
	for i := range ws {
		ws[i].User, ws[i].Server, ws[i].Message = sanitize.Remote(ws[i].User), sanitize.Remote(ws[i].Server), sanitize.Remote(ws[i].Message)
	}
	return cs, ws
}
```

`internal/apply/json.go:60`:

```go
	ManifestWarnings []config.ManifestWarning `json:"manifest_warnings,omitempty"`
```

`internal/apply/json.go:294` and `:299`:

```go
func cleanMemory(cfg *config.Config) ([]config.Conflict, []config.ManifestWarning) {
```

```go
	ws := slices.Clone(cfg.ManifestWarnings)
```

`internal/apply/json.go:289-293`, the comment is stale once the function carries every load warning:

```go
// cleanMemory is the manifest's policy conflicts and load warnings with
// every manifest-derived text passed through clean (spec §9: "sanitized
// like today's text fields"). A D1e warning's server can be any string —
// even one with control runes (plan decision 3) — so this is not
// cosmetic. Each list stays nil when empty (omitted).
```

- [ ] **Step 4: Realign.** `ManifestWarning` is one character shorter than `TombstoneWarning`, so the blocks at `internal/audit/json.go:27-31`, `internal/apply/json.go:59-61` and `internal/apply/json_test.go:710-712` move.

Run: `gofmt -w internal/config/config.go internal/audit/json.go internal/apply/json.go internal/apply/json_test.go`

- [ ] **Step 5: See them pass, and find the golden diff.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config ./internal/audit ./internal/apply`
Expected: only `TestReportKeyIssuesGolden` fails. Any other failing golden stops the lane: report it, because plan decision 2 assumed one.

- [ ] **Step 6: Accept the one golden.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit -run TestReportKeyIssuesGolden -update`

Read back `git diff internal/audit/testdata/report_key_issues.golden.json`. The diff must be exactly this insertion after `"schema": 1,`:

```json
  "manifest_warnings": [
    {
      "kind": "key_expired",
      "message": "user \"op\" key 1: expiry-time=\"20260101\" has passed; sshd no longer accepts this key"
    }
  ],
```

Run: `GOTOOLCHAIN=go1.27.3 go build ./... && GOTOOLCHAIN=go1.27.3 go test ./internal/config ./internal/audit ./internal/apply`
Expected: PASS.

### Task 3: `selectServers` to `fleet.go`, `readFleet` takes targets

**Files:** Modify `cmd/sshepherd/fleet.go:212-224`, `cmd/sshepherd/apply.go:209-211,436-462`, `cmd/sshepherd/audit.go:69`, `cmd/sshepherd/adopt.go:288`.

This task is a pure move; the existing `TestSelectServers`-style subtests in `apply_test.go:326-344` and `TestApply*` pin it.

- [ ] **Step 1: Move and widen.** Delete `selectServers` and its comment from `apply.go:436-462`. In `fleet.go`, add `"io"` to the imports and replace `readFleet` (`:212-224`) with:

```go
// readFleet is audit's and adopt's whole read over targets: an empty list
// needs no credentials (never reads a key, never prompts) and returns nil.
func readFleet(ctx context.Context, log *slog.Logger, cfg *config.Config, targets []config.Server, f *connFlags, ids identities, verb string) ([]audit.ServerResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	s, err := openFleet(ctx, log, f, ids, false)
	if err != nil {
		return nil, err
	}
	s.warnNoGrantedKeys(ctx, targets, grantedOn(cfg))
	return s.Read(ctx, verb, cfg, targets, grantedOn(cfg))
}

// selectServers resolves --server names to manifest servers, preserving
// manifest order and deduplicating; no names selects the whole fleet. An
// unknown name is a usage error: a canary typo must not silently apply or
// audit nothing.
func selectServers(cfg *config.Config, names []string) ([]config.Server, error) {
	if len(names) == 0 {
		return cfg.Servers, nil
	}
	known := make(map[string]bool, len(cfg.Servers))
	for _, s := range cfg.Servers {
		known[s.Name] = true
	}
	wanted := make(map[string]bool, len(names))
	for _, n := range names {
		if !known[n] {
			return nil, fmt.Errorf("--server: unknown server %q", n)
		}
		wanted[n] = true
	}
	var targets []config.Server
	for _, s := range cfg.Servers {
		if wanted[s.Name] {
			targets = append(targets, s)
		}
	}
	return targets, nil
}

// printSkipped is the report's closing line when --server left servers out.
func printSkipped(w io.Writer, skipped int) {
	if skipped > 0 {
		fmt.Fprintf(w, "(%s skipped by --server)\n", apply.Plural(skipped, "server", "servers"))
	}
}
```

`apply.go:209-211`, in `finish`:

```go
	printSkipped(pa.stdout, pa.skipped)
```

`adopt.go:288`:

```go
			results, err := readFleet(cmd.Context(), log, cfg, cfg.Servers, &cf, ids, "reading")
```

`audit.go:69`:

```go
			results, err := readFleet(cmd.Context(), log, cfg, cfg.Servers, &cf, ids, "auditing")
```

- [ ] **Step 2: See the suite stay green.**

Run: `GOTOOLCHAIN=go1.27.3 go build ./... && GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd`
Expected: PASS, no golden change.

### Task 4: `audit --server`

**Files:** Modify `cmd/sshepherd/audit.go`, `cmd/sshepherd/audit_test.go`, `internal/audit/json.go:34-49,172-196`, `cmd/sshepherd/testdata/help/audit.golden`.

- [ ] **Step 1: Write the failing tests.** Add `"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"` to `cmd/sshepherd/audit_test.go`'s imports and append:

```go
// auditSubsetFleet is hermeticFleet plus web-2 on a closed port (any read of
// it is unreachable, exit 1), with extra appended to the manifest.
func auditSubsetFleet(t *testing.T, extra string) (cfg, kh string) {
	t.Helper()
	srv, hostKey, base := hermeticFleet(t, shortHome(t))
	raw, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	web2 := "  - {name: web-2, host: 127.0.0.1, port: " + strconvItoa(closedPort(t)) + ", user: deploy}\n"
	return writeConfig(t, strings.Replace(string(raw), "access:\n", web2+"access:\n", 1)+extra),
		sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
}

// TestAuditWithoutServerReadsEveryServer is the control for the subset
// tests: with no --server, the closed web-2 is dialed.
func TestAuditWithoutServerReadsEveryServer(t *testing.T) {
	cfg, kh := auditSubsetFleet(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "web-2") || strings.Contains(out.String(), "skipped by --server") {
		t.Errorf("stdout = %q", out.String())
	}
}

func TestAuditServerSubset(t *testing.T) {
	cfg, kh := auditSubsetFleet(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--server", "web-1"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.HasSuffix(out.String(), "(1 server skipped by --server)\n") || strings.Contains(out.String(), "web-2") {
		t.Errorf("stdout = %q", out.String())
	}
}

// TestAuditServerRepeatable: --server repeats, and a run that selects every
// server skips none.
func TestAuditServerRepeatable(t *testing.T) {
	cfg, kh := auditSubsetFleet(t, "")
	var out, errBuf bytes.Buffer
	args := []string{"audit", "--config", cfg, "--known-hosts", kh, "--server", "web-1", "--server", "web-2"}
	if code := run(args, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "web-1") || !strings.Contains(out.String(), "web-2") || strings.Contains(out.String(), "skipped by --server") {
		t.Errorf("stdout = %q", out.String())
	}
	out.Reset()
	if code := run(append([]string{"audit", "--json"}, args[1:]...), &out, &errBuf); code != 1 {
		t.Fatalf("json exit = %d, want 1", code)
	}
	doc := oneJSONDoc(t, out.String())
	if _, ok := doc["summary"].(map[string]any)["skipped"]; ok {
		t.Errorf("skipped must be omitted when nothing was skipped:\n%s", out.String())
	}
	if got := len(docServers(doc)); got != 2 {
		t.Errorf("servers = %d, want 2", got)
	}
}

func TestAuditServerUnknownName(t *testing.T) {
	cfg, kh := auditSubsetFleet(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--server", "nope"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), `--server: unknown server "nope"`) || out.Len() != 0 {
		t.Errorf("stdout %q, stderr %q", out.String(), errBuf.String())
	}
}

// TestAuditServerJSONSkipped: summary.skipped appears under --server and is
// omitted otherwise.
func TestAuditServerJSONSkipped(t *testing.T) {
	cfg, kh := auditSubsetFleet(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--json", "--config", cfg, "--known-hosts", kh, "--server", "web-1"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	summary := doc["summary"].(map[string]any)
	if summary["skipped"] != float64(1) || summary["servers"] != float64(1) || len(docServers(doc)) != 1 {
		t.Errorf("summary = %v", summary)
	}
	if strings.Contains(out.String(), "skipped by --server") {
		t.Errorf("text leaked into the document:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"audit", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("whole-fleet exit = %d, want 1", code)
	}
	if _, ok := oneJSONDoc(t, out.String())["summary"].(map[string]any)["skipped"]; ok {
		t.Errorf("skipped must be omitted when 0:\n%s", out.String())
	}
}

// TestAuditServerConflictOutsideSubsetExits2 (OP4): a policy conflict is about
// the manifest, so it is printed and exits 2 even when --server excludes the
// server it names.
func TestAuditServerConflictOutsideSubsetExits2(t *testing.T) {
	cfg, kh := auditSubsetFleet(t, "  - {user: alice, servers: [web-2]}\nrevoked:\n  - {user: alice, servers: [web-2], date: 2026-11-08}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--server", "web-1"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "(CRITICAL: policy conflict)") {
		t.Errorf("stdout = %q", out.String())
	}
	out.Reset()
	if code := run([]string{"audit", "--json", "--config", cfg, "--known-hosts", kh, "--server", "web-1"}, &out, &errBuf); code != 2 {
		t.Fatalf("json exit = %d, want 2", code)
	}
	doc := oneJSONDoc(t, out.String())
	if conflicts, ok := doc["policy_conflicts"].([]any); !ok || len(conflicts) != 1 {
		t.Errorf("policy_conflicts = %v", doc["policy_conflicts"])
	}
}
```

- [ ] **Step 2: See them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestAuditServer|TestAuditWithoutServer'`
Expected: `TestAuditWithoutServerReadsEveryServer` passes (it is the control and pins behaviour already present); the rest fail with `unknown flag: --server`.

- [ ] **Step 3: Add `summary.skipped`.** In `internal/audit/json.go`, in `jsonSummary` after `Servers int`:

```go
	// Skipped is additive-optional (schema stays 1): servers --server left
	// out. Omitted when zero.
	Skipped int `json:"skipped,omitempty"`
```

Set it in `RenderJSON`'s `jsonSummary` literal (`:187`):

```go
		Servers:         len(results),
		Skipped:         opts.Skipped,
```

and extend `JSONOptions` (`:172`):

```go
type JSONOptions struct {
	Comments bool
	// Skipped is the number of manifest servers --server left out.
	Skipped int
}
```

- [ ] **Step 4: Wire the flag** (`cmd/sshepherd/audit.go`). Declare `serverSel []string` in the `var` block. Append to `Example`:

```go
			"  # Monitoring: JSON report on stdout, alert on the exit code\n" +
			"  sshepherd audit --json --config fleet.yaml\n\n" +
			"  # One server after a change; a policy conflict anywhere still exits 2\n" +
			"  sshepherd audit --server web-1 --config fleet.yaml",
```

After `logManifest(log, cfg)` (`:53`), replacing the render closure and the two branches that follow it through `:76`:

```go
			targets, err := selectServers(cfg, serverSel)
			if err != nil {
				return err
			}
			skipped := len(cfg.Servers) - len(targets)
			// One render path for the empty-fleet early return and the main
			// flow, so the two cannot drift apart.
			render := func(results []audit.ServerResult) error {
				if jsonOut {
					return audit.RenderJSON(stdout, cfg, results, audit.JSONOptions{Comments: comments, Skipped: skipped})
				}
				audit.Render(stdout, cfg, results, audit.RenderOptions{Color: a.reportColor, Comments: comments})
				printSkipped(stdout, skipped)
				return nil
			}
			if len(targets) == 0 {
				if err := render(nil); err != nil {
					return err
				}
				return auditVerdict(cfg, nil) // a policy conflict is critical with no server read
			}
			results, err := readFleet(cmd.Context(), log, cfg, targets, &cf, ids, "auditing")
			if err != nil {
				return err
			}
			if err := render(results); err != nil {
				return err
			}
			return auditVerdict(cfg, results)
```

After the `--comments` flag registration (`:81-82`):

```go
	cmd.Flags().StringArrayVar(&serverSel, "server", nil,
		"audit only this server (repeatable); a policy conflict anywhere in the manifest still exits 2")
```

- [ ] **Step 5: Realign.** `serverSel` is the longest name in the `var` block at `audit.go:29-33`, and the `JSONOptions` and `jsonSummary` edits move their blocks.

Run: `gofmt -w cmd/sshepherd/audit.go internal/audit/json.go`

- [ ] **Step 6: Accept the help golden.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestHelpGolden/audit' -update`

Read back `git diff cmd/sshepherd/testdata/help/audit.golden`. It must add only the new example and one `--server stringArray` line.

- [ ] **Step 7: See them pass.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestAudit|TestHelpGolden'`
Expected: PASS.

### Task 5: hand back `audit-server`

- [ ] **Step 1: Apply the docsDelta to the worktree's `README.md` (gate only).**

**docsDelta (`README.md`, audit-server):**

In the `### sshepherd audit` flag table, after the `--parallel` row:

```markdown
| `--server` | all | Audit only this server (repeatable). An unknown name exits `3` before anything connects. A policy conflict anywhere in the manifest still exits `2` |
```

After the flag table, before `**Drift classes.**`:

```markdown
With `--server`, the report ends with `(N servers skipped by --server)` and the JSON
summary gains `skipped`. The manifest's policy conflicts are about the manifest, not one
server, so they are still printed and still exit `2`.
```

As its own paragraph **after the closing fence of the JSON sample** that opens at `README.md:748` (the fence is line 881 at `aff7bf0`). The paragraph at `:741-746` ends with `remote text:` and leads into that sample, so nothing may go between them:

```markdown
`manifest_warnings` carries every load warning, in the `audit` document and in the `apply`
document. Each object has `kind` and `message`. `revoked_index`, `user` and `server` appear
only on `tombstone_unknown_server`. The kinds are `tombstone_unknown_server`,
`comment_on_multi_key`, `weak_key_ungranted` and `key_expired`; ignore kinds you do not know.
```

Round 2's docsDelta rewords the `server` sentence, because `validate` adds a kind that carries it.

- [ ] **Step 2: Gate.** Run: `make check`, then `make integration` under the runner's lock. Expected: both pass. `TestHelpMatchesREADMETables` needs Step 1.

- [ ] **Step 3: Hand back** the patch for this lane's globs. `README.md` is not in the patch.

---

## Round 2 — lane `validate` (Tasks 6-10)

Owns the files in the last JSON block. Finding: PRD-11. Requires round 1.

### Task 6: `Config.GrantCount`

**Files:** Create `internal/config/grants.go`, `internal/config/grants_test.go`.

- [ ] **Step 1: Write the failing test** (`internal/config/grants_test.go`):

```go
package config

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestGrantCount: a grant is one (user, server) pair the render would write,
// operators included.
func TestGrantCount(t *testing.T) {
	k1, k2 := testkeys.Line(t, 1), testkeys.Line(t, 2)
	servers := "servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: web-2, host: 10.0.0.2, user: deploy}\n"
	for _, tc := range []struct {
		name, manifest string
		want           int
	}{
		{"operator on every server", "users:\n  - {name: op, operator: true, keys: [\"" + k1 + "\"]}\n" + servers, 2},
		{"operator named in access is not counted twice", "users:\n  - {name: op, operator: true, keys: [\"" + k1 + "\"]}\n" + servers + "access:\n  - {user: op, servers: [web-1]}\n", 2},
		{"operator plus one grant", "users:\n  - {name: op, operator: true, keys: [\"" + k1 + "\"]}\n  - {name: alice, keys: [\"" + k2 + "\"]}\n" + servers + "access:\n  - {user: alice, servers: [web-1]}\n", 3},
		{"wildcard with except", "users:\n  - {name: alice, keys: [\"" + k2 + "\"]}\n" + servers + "access:\n  - {user: alice, servers: [\"*\"], except: [web-2]}\n", 1},
		{"repeated entries union", "users:\n  - {name: alice, keys: [\"" + k2 + "\"]}\n" + servers + "access:\n  - {user: alice, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", 1},
		{"a user with no keys renders nothing", "users:\n  - {name: alice, keys: []}\n" + servers + "access:\n  - {user: alice, servers: [web-1]}\n", 0},
		{"no servers", "users:\n  - {name: op, operator: true, keys: [\"" + k1 + "\"]}\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tc.manifest))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := cfg.GrantCount(); got != tc.want {
				t.Errorf("GrantCount = %d, want %d", got, tc.want)
			}
		})
	}
}
```

- [ ] **Step 2: See it fail.** Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run TestGrantCount`. Expected: build failure, `cfg.GrantCount undefined`.

- [ ] **Step 3: Implement** (`internal/config/grants.go`):

```go
package config

import "slices"

// GrantCount is the number of (user, server) pairs the render would write:
// every operator on every server, plus each granted user with at least one
// key. An operator also named in access: is counted once.
func (c *Config) GrantCount() int {
	n := 0
	for _, s := range c.Servers {
		n += len(c.operators)
		for _, user := range c.grants[s.Name] {
			if !slices.Contains(c.operators, user) && len(c.keysByUser[user]) > 0 {
				n++
			}
		}
	}
	return n
}
```

- [ ] **Step 4: See it pass.** Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`. Expected: PASS.

### Task 7: the command, text path

**Files:** Create `cmd/sshepherd/validate.go`, `cmd/sshepherd/validate_test.go`, `cmd/sshepherd/testdata/help/validate.golden`. Modify `cmd/sshepherd/run.go` (footer, `AddCommand`), `cmd/sshepherd/usage_test.go:68`, `cmd/sshepherd/testdata/help/root.golden`.

- [ ] **Step 1: Write the failing tests** (`cmd/sshepherd/validate_test.go`):

```go
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// validateCLI runs validate and returns its exit code, stdout and stderr.
func validateCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(append([]string{"validate"}, args...), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func validateManifest(t *testing.T) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n" +
		"access:\n  - {user: alice, servers: [web-1]}\n"
}

// recordedKnownHosts is a known_hosts file holding a key for each host.
func recordedKnownHosts(t *testing.T, hosts ...string) string {
	t.Helper()
	var lines []string
	for _, h := range hosts {
		lines = append(lines, h+" "+testkeys.Line(t, 40))
	}
	return sshtest.KnownHostsFile(t, lines...)
}

func TestValidateValid(t *testing.T) {
	code, out, stderr := validateCLI(t, "--config", writeConfig(t, validateManifest(t)), "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if want := "manifest OK: 1 user, 1 server, 1 grant (0 warnings)\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestValidateInvalid(t *testing.T) {
	path := writeConfig(t, "users: []\nservers: []\naccess:\n  - {user: ghost, servers: [web-9]}\n")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if !strings.Contains(stderr, "invalid manifest "+path+":") || !strings.Contains(stderr, `access: unknown user "ghost"`) {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestValidateUnreadableManifest(t *testing.T) {
	code, out, stderr := validateCLI(t, "--config", "/nonexistent.yaml", "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" || !strings.Contains(stderr, "no manifest at /nonexistent.yaml") {
		t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
}

func TestValidateWarningsAndStrict(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: alice, comment: c, keys: [\""+testkeys.Line(t, 1)+"\", \""+testkeys.Line(t, 2)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n")
	kh := recordedKnownHosts(t, "10.0.1.5")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "(1 warning)") {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if !strings.Contains(stderr, `user "alice": comment is set on a user with 2 keys`) {
		t.Errorf("stderr = %q", stderr)
	}
	if code, out, _ := validateCLI(t, "--strict", "--config", path, "--known-hosts", kh); code != 1 || !strings.HasPrefix(out, "manifest OK:") {
		t.Errorf("--strict: exit = %d, stdout = %q; want 1 with the summary", code, out)
	}
}

func TestValidateAnchorsWarn(t *testing.T) {
	code, out, stderr := validateCLI(t, "--config", writeConfig(t, "users: &u []\nservers: []\naccess: []\n"), "--known-hosts", recordedKnownHosts(t))
	if code != 0 || out != "manifest OK: 0 users, 0 servers, 0 grants (1 warning)\n" {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	want := "revoke, rotate and --merge cannot edit this manifest: manifest contains a YAML anchor or alias (line 1); comment-preserving edits do not support them"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}

func TestValidateConflictExit3(t *testing.T) {
	k, err := authkeys.ParseLine(testkeys.Line(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\nrevoked:\n  - {fingerprint: "+k.Fingerprint+", date: 2026-11-08}\n")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if !strings.Contains(stderr, "manifest has 1 policy conflict: key "+k.Fingerprint) {
		t.Errorf("stderr = %q", stderr)
	}
}

// TestValidateWeakKeys: a granted weak key is a policy conflict (exit 3) and
// an ungranted one is a warning (exit 0); P09 plan decision 14 assigned these
// two cases to this command.
func TestValidateWeakKeys(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	base := "users:\n  - {name: old, keys: [\"" + dsa + "\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n"
	kh := recordedKnownHosts(t, "10.0.1.5")
	t.Run("granted", func(t *testing.T) {
		code, out, stderr := validateCLI(t, "--config", writeConfig(t, base+"access:\n  - {user: old, servers: [web-1]}\n"), "--known-hosts", kh)
		if code != 3 || out != "" || !strings.Contains(stderr, `manifest has 1 policy conflict: user "old" key 1 (`) {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
	t.Run("ungranted", func(t *testing.T) {
		code, out, stderr := validateCLI(t, "--config", writeConfig(t, base), "--known-hosts", kh)
		if code != 0 || !strings.Contains(out, "(1 warning)") || !strings.Contains(stderr, "dsa key, granted on no server") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
}

// TestValidateConflictsPlural: several conflicts are counted and joined.
func TestValidateConflictsPlural(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(dsa)
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, "users:\n  - {name: old, keys: [\""+dsa+"\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n"+
		"access:\n  - {user: old, servers: [web-1]}\nrevoked:\n  - {fingerprint: "+k.Fingerprint+", user: old, date: 2026-11-08}\n")
	code, _, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 3 || !strings.Contains(stderr, "manifest has 2 policy conflicts: ") || !strings.Contains(stderr, "; ") {
		t.Errorf("exit = %d, stderr = %q", code, stderr)
	}
}
```

- [ ] **Step 2: See them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestValidate'`
Expected: exit 3 with `unknown flag: --config` (`validate` is not a subcommand yet, the root takes arbitrary arguments, and it has no `--config`); the assertions on exit 0 or 1, or on stderr text, fail.

- [ ] **Step 3: Implement** (`cmd/sshepherd/validate.go`):

```go
package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
)

// warnManifestNotEditable is the kind for a valid manifest the comment-preserving
// editor refuses. Consumers ignore kinds they do not know.
const warnManifestNotEditable = "manifest_not_editable"

type validateOpts struct {
	cfgPath    string
	knownHosts string
	strict     bool
	json       bool
}

func newValidateCmd(a *app, stdout io.Writer) *cobra.Command {
	var o validateOpts
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check the manifest offline: schema, policy conflicts and host-key coverage (never connects)",
		Long: "Checks the manifest offline: parses and validates it, reports policy\n" +
			"conflicts, says whether revoke, rotate and --merge can edit it and, when a\n" +
			"known_hosts file loads, which servers have no recorded host key. Never\n" +
			"opens a socket or reads a key.\n\n" + exitCodesValidate,
		Example: "  # Check the default manifest\n" +
			"  sshepherd validate\n\n" +
			"  # GitOps PR check: any warning fails the job\n" +
			"  sshepherd validate --strict --json --known-hosts ci/known_hosts --config fleet.yaml",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := &validation{log: a.logger, stdout: stdout, opts: o, explicitKnownHosts: cmd.Flags().Changed("known-hosts")}
			return v.run()
		},
	}
	cmd.Flags().StringVar(&o.cfgPath, "config", defaultConfigPath, "path to the manifest")
	cmd.Flags().StringVar(&o.knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (checks that every server has a recorded host key)")
	cmd.Flags().BoolVar(&o.strict, "strict", false, "exit 1 when the manifest is valid but has warnings")
	cmd.Flags().BoolVar(&o.json, "json", false, "emit the result as machine-readable JSON on stdout")
	return cmd
}

// validation is one validate run.
type validation struct {
	log                *slog.Logger
	stdout             io.Writer
	opts               validateOpts
	explicitKnownHosts bool
}

func (v *validation) run() error {
	m, err := readManifest(v.opts.cfgPath)
	if err != nil {
		return manifestError("--config", v.opts.cfgPath, err)
	}
	cfg, err := config.Parse(m.Loaded)
	if err != nil {
		return manifestError("--config", v.opts.cfgPath, err)
	}
	logManifest(v.log, cfg)
	own, err := notEditable(m.Loaded)
	if err != nil {
		return err
	}
	for _, w := range own {
		v.log.Warn(w.Message)
	}
	return v.finish(cfg, own)
}

// notEditable reports a valid manifest the comment-preserving editor refuses.
func notEditable(data []byte) ([]config.ManifestWarning, error) {
	_, err := manifest.Load(data)
	var ue *manifest.UnsupportedError
	if errors.As(err, &ue) {
		return []config.ManifestWarning{{Kind: warnManifestNotEditable,
			Message: "revoke, rotate and --merge cannot edit this manifest: " + ue.Reason}}, nil
	}
	return nil, err //nolint:wrapcheck // nil, or config.Parse's verdict on bytes it already accepted
}

// finish reports the verdict: own is what validate found beyond the
// manifest's load warnings.
func (v *validation) finish(cfg *config.Config, own []config.ManifestWarning) error {
	conflicts := cfg.Conflicts()
	warnings := len(cfg.ManifestWarnings) + len(own)
	code := validateExit(len(conflicts), warnings, v.opts.strict)
	if code == 3 {
		return conflictsError(conflicts)
	}
	fmt.Fprintf(v.stdout, "manifest OK: %s, %s, %s (%s)\n",
		apply.Plural(len(cfg.Users), "user", "users"), apply.Plural(len(cfg.Servers), "server", "servers"),
		apply.Plural(cfg.GrantCount(), "grant", "grants"), apply.Plural(warnings, "warning", "warnings"))
	return exitFor(code)
}

// validateExit is the command's exit code once the manifest has parsed.
func validateExit(conflicts, warnings int, strict bool) int {
	switch {
	case conflicts > 0:
		return 3
	case strict && warnings > 0:
		return 1
	default:
		return 0
	}
}

// conflictsError is validate's own wording: conflictRefusal talks about
// writing, and validate writes nothing.
func conflictsError(cs []config.Conflict) error {
	msgs := make([]string, 0, len(cs))
	for _, c := range cs {
		msgs = append(msgs, c.Message)
	}
	return fmt.Errorf("manifest has %s: %s", apply.Plural(len(cs), "policy conflict", "policy conflicts"), strings.Join(msgs, "; "))
}
```

`cmd/sshepherd/run.go`, after `exitCodesImport` (`:241`):

```go
const exitCodesValidate = `Exit codes:
  0  valid (warnings may be present)
  1  valid, with warnings, under --strict
  3  invalid, a policy conflict, or a tool error: bad flags, unreadable
     manifest, a bad --known-hosts file`
```

`cmd/sshepherd/run.go:327`, after `root.AddCommand(newRotateCmd(a, stdout))`:

```go
	root.AddCommand(newValidateCmd(a, stdout))
```

`cmd/sshepherd/usage_test.go:68`:

```go
var helpCommands = []string{"", "audit", "import", "adopt", "apply", "revoke", "rotate", "validate"}
```

- [ ] **Step 4: Accept the help goldens.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestHelpGolden' -update`

Read back `git diff cmd/sshepherd/testdata/help/root.golden` (one `validate` line under Available Commands) and `cmd/sshepherd/testdata/help/validate.golden` (Long text, the footer, two examples, the four flags and the Global Flags section).

- [ ] **Step 5: See them pass.** Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestValidate|TestHelpGolden|TestHelpHasNoBoolValueSuffix'`. Expected: PASS.

### Task 8: known_hosts coverage (step 5, OP1)

**Files:** Modify `cmd/sshepherd/validate.go`, `cmd/sshepherd/validate_test.go`.

- [ ] **Step 1: Write the failing tests** (append to `validate_test.go`; add `"os"` and `"path/filepath"` to its imports):

```go
func TestValidateKnownHostsGap(t *testing.T) {
	manifest := "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n  - {name: web-2, host: 10.0.1.6, port: 2222, user: deploy}\n"
	path := writeConfig(t, manifest)
	kh := recordedKnownHosts(t, "10.0.1.5")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "(1 warning)") {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if want := `server "web-2": no host key recorded for 10.0.1.6:2222 in ` + kh; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if strings.Contains(stderr, `server "web-1"`) {
		t.Errorf("recorded host reported as a gap: %q", stderr)
	}
	if code, _, _ := validateCLI(t, "--strict", "--config", path, "--known-hosts", kh); code != 1 {
		t.Errorf("--strict exit = %d, want 1", code)
	}
}

// TestValidateKnownHostsNonDefaultPortAndCA: a [host]:port entry and a host
// matched only by @cert-authority both count as recorded; a port-22 entry does
// not record the same host on another port.
func TestValidateKnownHostsNonDefaultPortAndCA(t *testing.T) {
	path := writeConfig(t, "users: []\nservers:\n  - {name: web-1, host: 10.0.1.5, port: 2222, user: deploy}\n  - {name: web-2, host: 10.0.1.6, user: deploy}\n  - {name: web-3, host: 10.0.1.7, port: 2222, user: deploy}\n")
	kh := sshtest.KnownHostsFile(t, "[10.0.1.5]:2222 "+testkeys.Line(t, 40), "@cert-authority 10.0.1.6 "+testkeys.Line(t, 41), "10.0.1.7 "+testkeys.Line(t, 42))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "(1 warning)") {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	if want := `server "web-3": no host key recorded for 10.0.1.7:2222`; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	for _, recorded := range []string{`server "web-1"`, `server "web-2"`} {
		if strings.Contains(stderr, recorded) {
			t.Errorf("%s reported as a gap: %q", recorded, stderr)
		}
	}
}

// TestValidateMissingDefaultKnownHosts (OP1): a warning that fails --strict.
func TestValidateMissingDefaultKnownHosts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := writeConfig(t, validateManifest(t))
	code, out, stderr := validateCLI(t, "--config", path)
	if code != 0 || !strings.Contains(out, "(1 warning)") {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if want := "no known_hosts at ~/.ssh/known_hosts; host keys were not checked"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if code, _, _ := validateCLI(t, "--strict", "--config", path); code != 1 {
		t.Errorf("--strict exit = %d, want 1", code)
	}
}

func TestValidateBadKnownHosts(t *testing.T) {
	path := writeConfig(t, validateManifest(t))
	bad := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(bad, []byte("not a known hosts line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte("not a known hosts line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("explicit path missing", func(t *testing.T) {
		code, out, stderr := validateCLI(t, "--json", "--config", path, "--known-hosts", filepath.Join(t.TempDir(), "missing"))
		if code != 3 || out != "" || !strings.Contains(stderr, "known_hosts preflight:") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
	t.Run("explicit file malformed", func(t *testing.T) {
		code, out, stderr := validateCLI(t, "--json", "--config", path, "--known-hosts", bad)
		if code != 3 || out != "" || !strings.Contains(stderr, "known_hosts preflight:") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
	// Text mode: exit 3 and nothing on stdout. Task 9 pins the --json document.
	t.Run("default file malformed", func(t *testing.T) {
		t.Setenv("HOME", home)
		code, out, stderr := validateCLI(t, "--config", path)
		if code != 3 || out != "" || !strings.Contains(stderr, "known_hosts preflight:") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
}
```

- [ ] **Step 2: See them fail.** Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestValidateKnownHosts|TestValidateMissingDefault|TestValidateBadKnownHosts'`. Expected: assertion failures (no gap warning, exit 0 for a bad file).

- [ ] **Step 3: Implement.** In `validate.go`, add `"io/fs"`, `"net"`, `"strconv"` and `"github.com/javadh75/SSHepherd/internal/sshread"` to the imports. Replace the kind constant:

```go
// The manifest_warnings kinds validate adds. Consumers ignore kinds they do
// not know.
const (
	warnManifestNotEditable = "manifest_not_editable"
	warnKnownHostsMissing   = "known_hosts_missing"
	warnHostKeyNotRecorded  = "host_key_not_recorded"
)
```

Add a field to `validation`:

```go
	hostKeysChecked    bool // a known_hosts file loaded
```

In `run()`, replacing the `for _, w := range own` loop:

```go
	known, err := v.knownHostsWarnings(cfg)
	if err != nil {
		return err
	}
	own = append(own, known...)
	for _, w := range own {
		v.log.Warn(w.Message)
	}
```

Add the method:

```go
// knownHostsWarnings is step 5: a missing default file is a warning (OP1), a
// bad file is a tool error, and each server with no recorded host key is a
// warning. A host matched only by @cert-authority counts as recorded.
func (v *validation) knownHostsWarnings(cfg *config.Config) ([]config.ManifestWarning, error) {
	path := v.opts.knownHosts
	resolved, err := expandHome(path)
	if err != nil {
		return nil, fmt.Errorf("known_hosts preflight: %w", err)
	}
	kh, err := sshread.LoadKnownHosts(resolved)
	if errors.Is(err, fs.ErrNotExist) && !v.explicitKnownHosts {
		return []config.ManifestWarning{{Kind: warnKnownHostsMissing,
			Message: "no known_hosts at " + path + "; host keys were not checked"}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("known_hosts preflight: %w", err)
	}
	v.hostKeysChecked = true
	var out []config.ManifestWarning
	for _, s := range cfg.Servers {
		addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
		if kh.HostKeyAlgorithms(addr) == nil {
			out = append(out, config.ManifestWarning{Kind: warnHostKeyNotRecorded, Server: s.Name,
				Message: fmt.Sprintf("server %q: no host key recorded for %s in %s", s.Name, addr, path)})
		}
	}
	return out, nil
}
```

- [ ] **Step 4: See them pass.** Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestValidate'`. Expected: PASS.

### Task 9: `--json` (D25a)

**Files:** Modify `cmd/sshepherd/validate.go`, `cmd/sshepherd/validate_test.go`. Create `cmd/sshepherd/testdata/validate_warning.golden.json`, `cmd/sshepherd/testdata/validate_invalid.golden.json`.

- [ ] **Step 1: Write the failing tests** (append to `validate_test.go`; add `"errors"` and `"reflect"` to its imports):

```go
func TestValidateJSONValid(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--config", writeConfig(t, validateManifest(t)), "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	doc := oneJSONDoc(t, out)
	wantSummary(t, doc, map[string]int{"users": 1, "servers": 1, "grants": 1, "warnings": 0, "exit_code": 0})
	if doc["valid"] != true || doc["host_keys_checked"] != true {
		t.Errorf("doc = %v", doc)
	}
	if errs, ok := doc["errors"].([]any); !ok || len(errs) != 0 {
		t.Errorf("errors must be present and empty: %v", doc["errors"])
	}
	for _, absent := range []string{"policy_conflicts", "manifest_warnings"} {
		if _, ok := doc[absent]; ok {
			t.Errorf("%s must be omitted when empty: %v", absent, doc)
		}
	}
}

// TestValidateJSONWarningGolden pins the design's "valid with one warning"
// document. The temporary path is rewritten so the README can copy it.
func TestValidateJSONWarningGolden(t *testing.T) {
	kh := writeEmptyKnownHosts(t)
	code, out, _ := validateCLI(t, "--json", "--config", writeConfig(t, validateManifest(t)), "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	checkGolden(t, "validate_warning.golden.json", []byte(strings.ReplaceAll(out, kh, "~/.ssh/known_hosts")))
}

func TestValidateJSONInvalidGolden(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-9]}\n")
	code, out, stderr := validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || !strings.Contains(stderr, `access for "alice": unknown server "web-9"`) {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	checkGolden(t, "validate_invalid.golden.json", []byte(out))
}

func TestValidateJSONStrict(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: alice, comment: c, keys: [\""+testkeys.Line(t, 1)+"\", \""+testkeys.Line(t, 2)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n")
	code, out, _ := validateCLI(t, "--json", "--strict", "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	doc := oneJSONDoc(t, out)
	if doc["valid"] != true {
		t.Errorf("valid = %v: a run failing only under --strict is valid", doc["valid"])
	}
	wantSummary(t, doc, map[string]int{"warnings": 1, "exit_code": 1})
	ws := doc["manifest_warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["kind"] != "comment_on_multi_key" {
		t.Errorf("manifest_warnings = %v", ws)
	}
}

func TestValidateJSONConflict(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	path := writeConfig(t, "users:\n  - {name: old, keys: [\""+dsa+"\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\naccess:\n  - {user: old, servers: [web-1]}\n")
	code, out, stderr := validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 3 || !strings.Contains(stderr, "manifest has 1 policy conflict:") {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	doc := oneJSONDoc(t, out)
	wantSummary(t, doc, map[string]int{"users": 1, "servers": 1, "grants": 1, "warnings": 0, "exit_code": 3})
	if doc["valid"] != false || doc["host_keys_checked"] != true {
		t.Errorf("doc = %v", doc)
	}
	cs := doc["policy_conflicts"].([]any)
	if len(cs) != 1 || cs[0].(map[string]any)["kind"] != "weak_key" {
		t.Errorf("policy_conflicts = %v", cs)
	}
	if errs, ok := doc["errors"].([]any); !ok || len(errs) != 0 {
		t.Errorf("errors = %v, want []", doc["errors"])
	}
}

func TestValidateJSONUngrantedWeakKey(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: old, keys: [\""+testkeys.DSALine(t, 7)+"\"]}\n")
	code, out, _ := validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	ws := oneJSONDoc(t, out)["manifest_warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["kind"] != "weak_key_ungranted" {
		t.Errorf("manifest_warnings = %v", ws)
	}
}

// TestValidateJSONParseFailure: a syntax error is one errors entry, and
// counts stay zero.
func TestValidateJSONParseFailure(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--config", writeConfig(t, "users: [\n"), "--known-hosts", recordedKnownHosts(t))
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	doc := oneJSONDoc(t, out)
	if errs := doc["errors"].([]any); len(errs) != 1 || doc["valid"] != false || doc["host_keys_checked"] != false {
		t.Errorf("doc = %v", doc)
	}
	wantSummary(t, doc, map[string]int{"users": 0, "servers": 0, "grants": 0, "warnings": 0, "exit_code": 3})
}

// TestValidateJSONMissingDefaultKnownHosts (OP1): no known_hosts was loaded,
// so host_keys_checked is false on a parsed manifest.
func TestValidateJSONMissingDefaultKnownHosts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := writeConfig(t, validateManifest(t))
	code, out, _ := validateCLI(t, "--json", "--config", path)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	doc := oneJSONDoc(t, out)
	wantSummary(t, doc, map[string]int{"users": 1, "servers": 1, "grants": 1, "warnings": 1, "exit_code": 0})
	if doc["valid"] != true || doc["host_keys_checked"] != false {
		t.Errorf("doc = %v", doc)
	}
	ws := doc["manifest_warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["kind"] != "known_hosts_missing" {
		t.Errorf("manifest_warnings = %v", ws)
	}
	code, out, _ = validateCLI(t, "--json", "--strict", "--config", path)
	if code != 1 {
		t.Fatalf("--strict exit = %d, want 1", code)
	}
	if strict := oneJSONDoc(t, out); strict["valid"] != true {
		t.Errorf("--strict valid = %v, want true", strict["valid"])
	}
}

// TestValidateJSONDefaultKnownHostsLoadFailure (O1): a default-path file that
// exists but cannot be loaded is exit 3, and unlike a bad explicit file it
// still writes the document, with the reason in errors.
func TestValidateJSONDefaultKnownHostsLoadFailure(t *testing.T) {
	path := writeConfig(t, validateManifest(t))
	for _, tc := range []struct {
		name string
		home func(t *testing.T) string
	}{
		{"malformed", func(t *testing.T) string {
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte("not a known hosts line\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return home
		}},
		{"~/.ssh is a file", func(t *testing.T) string {
			home := t.TempDir()
			if err := os.WriteFile(filepath.Join(home, ".ssh"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return home
		}},
		{"HOME unset", func(_ *testing.T) string { return "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", tc.home(t))
			code, out, stderr := validateCLI(t, "--json", "--config", path)
			if code != 3 || !strings.Contains(stderr, "known_hosts preflight:") {
				t.Fatalf("exit = %d, stderr = %q", code, stderr)
			}
			doc := oneJSONDoc(t, out)
			wantSummary(t, doc, map[string]int{"users": 1, "servers": 1, "grants": 1, "warnings": 0, "exit_code": 3})
			if doc["valid"] != true || doc["host_keys_checked"] != false {
				t.Errorf("doc = %v", doc)
			}
			errs, ok := doc["errors"].([]any)
			if !ok || len(errs) != 1 || !strings.Contains(errs[0].(string), "known_hosts preflight:") {
				t.Errorf("errors = %v", doc["errors"])
			}
		})
	}
}

// TestValidateConflictAndDefaultKnownHostsFailure: both are reported, and the
// conflict decides valid.
func TestValidateConflictAndDefaultKnownHostsFailure(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".ssh"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	path := writeConfig(t, "users:\n  - {name: old, keys: [\""+testkeys.DSALine(t, 7)+"\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\naccess:\n  - {user: old, servers: [web-1]}\n")
	code, out, stderr := validateCLI(t, "--config", path)
	if code != 3 || out != "" || !strings.Contains(stderr, "manifest has 1 policy conflict:") || !strings.Contains(stderr, "known_hosts preflight:") {
		t.Errorf("text: exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	code, out, _ = validateCLI(t, "--json", "--config", path)
	if code != 3 {
		t.Fatalf("json exit = %d, want 3", code)
	}
	doc := oneJSONDoc(t, out)
	if doc["valid"] != false || doc["host_keys_checked"] != false {
		t.Errorf("doc = %v", doc)
	}
	if errs := doc["errors"].([]any); len(errs) != 1 {
		t.Errorf("errors = %v", errs)
	}
	if cs := doc["policy_conflicts"].([]any); len(cs) != 1 {
		t.Errorf("policy_conflicts = %v", cs)
	}
}

func TestValidateJSONAnchors(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--config", writeConfig(t, "users: &u []\nservers: []\naccess: []\n"), "--known-hosts", recordedKnownHosts(t))
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	doc := oneJSONDoc(t, out)
	wantSummary(t, doc, map[string]int{"warnings": 1, "exit_code": 0})
	if doc["valid"] != true {
		t.Errorf("doc = %v", doc)
	}
	ws := doc["manifest_warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["kind"] != "manifest_not_editable" {
		t.Errorf("manifest_warnings = %v", ws)
	}
}

// TestValidateJSONBadFlagWritesNoDocument: a bad flag never reaches the run.
func TestValidateJSONBadFlagWritesNoDocument(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--nope")
	if code != 3 || out != "" {
		t.Errorf("exit = %d, stdout = %q", code, out)
	}
}

func TestValidateJSONUnreadableManifestWritesNoDocument(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--config", "/nonexistent.yaml", "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" {
		t.Errorf("exit = %d, stdout = %q", code, out)
	}
}

// TestValidateJSONSanitizesManifestText: a D1e warning can name a server with
// control runes, and they must not reach the document.
func TestValidateJSONSanitizesManifestText(t *testing.T) {
	path := writeConfig(t, "users: []\nservers: []\nrevoked:\n  - {user: bob, servers: [\"db\\e9\"], date: 2026-11-08}\n")
	code, out, _ := validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.ContainsRune(out, 0x1b) || strings.Contains(out, `\u001b`) {
		t.Errorf("a control rune reached the document:\n%s", out)
	}
}

func TestSplitErrors(t *testing.T) {
	joined := errors.Join(errors.New("first"), errors.New("sec\x1bond"))
	if got, want := splitErrors(joined), []string{"first", "second"}; !reflect.DeepEqual(got, want) {
		t.Errorf("joined: got %q, want %q", got, want)
	}
	if got, want := splitErrors(errors.New("one")), []string{"one"}; !reflect.DeepEqual(got, want) {
		t.Errorf("single: got %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: See them fail.** Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestValidateJSON|TestSplitErrors'`. Expected: build failure, `undefined: splitErrors`. `TestValidateJSONUnreadableManifestWritesNoDocument` and `TestValidateJSONBadFlagWritesNoDocument` are pins: Tasks 7-8 write no document at all, so they cannot fail before this task. Task 12's mutation proves the first one bites.

- [ ] **Step 3: Implement.** In `validate.go`, add `"encoding/json"`, `"github.com/javadh75/SSHepherd/internal/audit"` and `"github.com/javadh75/SSHepherd/internal/sanitize"` to the imports. Add the types:

```go
// validateSchema marks the JSON document's shape; it stays 1, with additive
// fields.
const validateSchema = 1

type validateSummary struct {
	Users    int `json:"users"`
	Servers  int `json:"servers"`
	Grants   int `json:"grants"`
	Warnings int `json:"warnings"`
	ExitCode int `json:"exit_code"`
}

// validateDoc is the --json document. Errors is always present;
// PolicyConflicts and ManifestWarnings follow audit's shapes and are omitted
// when empty.
type validateDoc struct {
	Schema           int                      `json:"schema"`
	Valid            bool                     `json:"valid"`
	Summary          validateSummary          `json:"summary"`
	HostKeysChecked  bool                     `json:"host_keys_checked"`
	Errors           []string                 `json:"errors"`
	PolicyConflicts  []config.Conflict        `json:"policy_conflicts,omitempty"`
	ManifestWarnings []config.ManifestWarning `json:"manifest_warnings,omitempty"`
}
```

In `run()`, replace the `config.Parse` error return:

```go
	cfg, err := config.Parse(m.Loaded)
	if err != nil {
		return v.invalid(err)
	}
```

and the known_hosts step, and hand the failure to `finish`:

```go
	known, knownErr := v.knownHostsWarnings(cfg)
	if knownErr != nil && v.explicitKnownHosts {
		return knownErr // design: a bad explicit --known-hosts writes no document
	}
	own = append(own, known...)
	for _, w := range own {
		v.log.Warn(w.Message)
	}
	return v.finish(cfg, own, knownErr)
```

Replace `finish` and add the helpers:

```go
// finish reports the verdict: own is what validate found beyond the
// manifest's load warnings, and knownErr a default known_hosts file that
// exists but could not be loaded (exit 3; the document still says why). Under
// --json the document is written on every exit here, 3 included (a conflict is
// validate's finding, not a tool failure).
func (v *validation) finish(cfg *config.Config, own []config.ManifestWarning, knownErr error) error {
	conflicts, warnings := audit.ManifestFindings(cfg)
	for _, w := range own {
		w.Server, w.Message = sanitize.Remote(w.Server), sanitize.Remote(w.Message)
		warnings = append(warnings, w)
	}
	code := validateExit(len(conflicts), len(warnings), v.opts.strict)
	if knownErr != nil {
		code = 3
	}
	if v.opts.json {
		errs := []string{}
		if knownErr != nil {
			errs = splitErrors(knownErr)
		}
		err := v.writeDoc(validateDoc{
			Schema: validateSchema, Valid: len(conflicts) == 0,
			Summary: validateSummary{Users: len(cfg.Users), Servers: len(cfg.Servers), Grants: cfg.GrantCount(),
				Warnings: len(warnings), ExitCode: code},
			HostKeysChecked: v.hostKeysChecked, Errors: errs,
			PolicyConflicts: conflicts, ManifestWarnings: warnings,
		})
		if err != nil {
			return err
		}
	} else if code != 3 {
		fmt.Fprintf(v.stdout, "manifest OK: %s, %s, %s (%s)\n",
			apply.Plural(len(cfg.Users), "user", "users"), apply.Plural(len(cfg.Servers), "server", "servers"),
			apply.Plural(cfg.GrantCount(), "grant", "grants"), apply.Plural(len(warnings), "warning", "warnings"))
	}
	switch {
	case len(conflicts) > 0:
		return errors.Join(conflictsError(conflicts), knownErr) // Join drops a nil knownErr
	case knownErr != nil:
		return knownErr
	default:
		return exitFor(code)
	}
}

// invalid reports a manifest config.Parse refused: exit 3, and under --json
// a document whose counts are 0.
func (v *validation) invalid(err error) error {
	verdict := manifestError("--config", v.opts.cfgPath, err)
	if v.opts.json {
		if werr := v.writeDoc(validateDoc{Schema: validateSchema, Summary: validateSummary{ExitCode: 3}, Errors: splitErrors(err)}); werr != nil {
			return werr
		}
	}
	return verdict
}

func (v *validation) writeDoc(doc validateDoc) error {
	enc := json.NewEncoder(v.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode validate report: %w", err)
	}
	return nil
}

// splitErrors lists each validation error of errors.Join, sanitized; a parse
// failure is one entry. Never nil.
func splitErrors(err error) []string {
	list := []error{err}
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		list = joined.Unwrap()
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, sanitize.Remote(e.Error()))
	}
	return out
}
```

- [ ] **Step 4: Accept the goldens.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestValidateJSON(Warning|Invalid)Golden' -update`

Read back both files. `validate_warning.golden.json` must be:

```json
{
  "schema": 1,
  "valid": true,
  "summary": {
    "users": 1,
    "servers": 1,
    "grants": 1,
    "warnings": 1,
    "exit_code": 0
  },
  "host_keys_checked": true,
  "errors": [],
  "manifest_warnings": [
    {
      "kind": "host_key_not_recorded",
      "server": "web-1",
      "message": "server \"web-1\": no host key recorded for 10.0.1.5:22 in ~/.ssh/known_hosts"
    }
  ]
}
```

`validate_invalid.golden.json` must be:

```json
{
  "schema": 1,
  "valid": false,
  "summary": {
    "users": 0,
    "servers": 0,
    "grants": 0,
    "warnings": 0,
    "exit_code": 3
  },
  "host_keys_checked": false,
  "errors": [
    "access for \"alice\": unknown server \"web-9\""
  ]
}
```

- [ ] **Step 5: See them pass.** Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestValidate|TestSplitErrors'`. Expected: PASS.

### Task 10: hermetic proof, piped manifest, help tests, hand back

**Files:** Create `cmd/sshepherd/validate_pipe_test.go`. Modify `cmd/sshepherd/validate_test.go`, `cmd/sshepherd/run_test.go:122,133-134`, `cmd/sshepherd/help_readme_test.go:118`.

- [ ] **Step 1: Write the hermetic test** (append to `validate_test.go`; add `"context"`, `"net"` and `"sync/atomic"` to its imports):

```go
// TestValidateOpensNoSocket: a server in the manifest and SSH_AUTH_SOCK both
// point at counting listeners, and validate touches neither.
func TestValidateOpensNoSocket(t *testing.T) {
	var dials atomic.Int32
	serve := func(ln net.Listener) (stop func()) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				dials.Add(1)
				_ = c.Close()
			}
		}()
		return func() {
			_ = ln.Close()
			<-done
		}
	}
	tcp, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stopTCP := serve(tcp)
	sock, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", filepath.Join(shortHome(t), "a"))
	if err != nil {
		t.Fatal(err)
	}
	stopSock := serve(sock)
	t.Setenv("SSH_AUTH_SOCK", sock.Addr().String())
	path := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 127.0.0.1, port: "+strconvItoa(tcp.Addr().(*net.TCPAddr).Port)+", user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	code, _, stderr := validateCLI(t, "--config", path, "--known-hosts", writeEmptyKnownHosts(t))
	stopTCP()
	stopSock()
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("validate opened %d connections", n)
	}
}
```

- [ ] **Step 2: Write the piped test** (`cmd/sshepherd/validate_pipe_test.go`):

```go
//go:build linux || darwin

package main

import "testing"

// TestValidatePipedManifest: --config /dev/stdin or <(...) works, as on every
// command that reads the manifest once.
func TestValidatePipedManifest(t *testing.T) {
	code, out, stderr := validateCLI(t, "--config", pipeConfig(t, validateManifest(t)), "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 0 || out != "manifest OK: 1 user, 1 server, 1 grant (0 warnings)\n" {
		t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
}
```

- [ ] **Step 3: Run them.** Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestValidateOpensNoSocket|TestValidatePipedManifest'`. Expected: PASS. These pin behaviour built in Tasks 7-9. To see `TestValidateOpensNoSocket` bite, temporarily add `net.Dial("tcp", net.JoinHostPort(cfg.Servers[0].Host, strconv.Itoa(cfg.Servers[0].Port)))` in `run()`, see the test fail, and remove it.

- [ ] **Step 4: Add the help tests.**

`cmd/sshepherd/help_readme_test.go`, after the `rotate` row (`:118`):

```go
		{"validate", "### `sshepherd validate`", localFlags},
```

`cmd/sshepherd/run_test.go:122`:

```go
	for _, f := range []string{exitCodesAudit, exitCodesWrite, exitCodesAdopt, exitCodesImport, exitCodesValidate} {
```

`cmd/sshepherd/run_test.go:133-134`:

```go
		"audit": exitCodesAudit, "apply": exitCodesWrite, "revoke": exitCodesWrite, "rotate": exitCodesWrite,
		"adopt": exitCodesAdopt, "import": exitCodesImport, "validate": exitCodesValidate,
```

- [ ] **Step 5: See them fail for the README, then apply the docsDelta.** Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestHelpMatchesREADMETables|TestHelpExamplesAndExitCodes'`. Expected: `README has no "### `sshepherd validate`" heading`. Apply the block below to the worktree's `README.md` (gate only).

**docsDelta (`README.md`, validate):**

In the Status table, after the `audit` row:

```markdown
| `validate` | ✅ | Offline manifest check: schema, policy conflicts, host-key coverage (text + `--json`, `--strict`) |
```

Before `### \`sshepherd audit\``, a new section:

````markdown
### `sshepherd validate`

Check the manifest offline. It never opens a socket and never reads a key. It parses and validates the manifest, reports policy conflicts, says whether `revoke`, `rotate` and `--merge` can edit it, and, when a known_hosts file loads, warns about each server with no recorded host key.

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--config` | `sshepherd.yaml` | Path to the manifest (`/dev/stdin` and a pipe work) |
| `--known-hosts` | `~/.ssh/known_hosts` | `known_hosts` path. With the default path a missing file is a warning (it fails `--strict`). A file given explicitly that is missing or bad, or a default file that exists but cannot be loaded, exits `3` |
| `--strict` | off | Exit `1` when the manifest is valid but has warnings |
| `--json` | off | Machine-readable result on stdout (schema 1) |

A valid manifest prints one line on stdout, e.g. `manifest OK: 1 user, 1 server, 1 grant (0 warnings)`. A policy conflict prints `manifest has 1 policy conflict: MESSAGE` on stderr and exits `3`. A weak key granted on a server is a policy conflict; an ungranted one is a warning.

`--json` writes one document. It is written on exit `3` too, when the manifest is invalid or has a policy conflict, with `valid: false`, and when the default known_hosts exists but cannot be loaded (`valid: true`, the reason in `errors`). An unreadable manifest, a bad flag or a bad `--known-hosts` file given explicitly writes no document. A run that fails only under `--strict` has `valid: true` and exit `1`. `manifest_warnings` adds the kinds `manifest_not_editable`, `known_hosts_missing` and `host_key_not_recorded`; ignore kinds you do not know. `host_keys_checked` is `false` when no known_hosts file loaded.

```json
<copy cmd/sshepherd/testdata/validate_warning.golden.json verbatim>
```

An invalid manifest:

```json
<copy cmd/sshepherd/testdata/validate_invalid.golden.json verbatim>
```
````

In the `manifest_warnings` paragraph round 1 added to the `sshepherd audit` JSON section, replace the sentence ``"`revoked_index`, `user` and `server` appear only on `tombstone_unknown_server`."`` with ``"`revoked_index` and `user` appear only on `tombstone_unknown_server`; `server` appears there and on validate's `host_key_not_recorded`."``

In `### CI recipes`, before **GitHub Actions**:

````markdown
**GitOps PR check** — no fleet access needed. `--strict` fails on host-key gaps too, so commit a known_hosts file for the job:

```yaml
- name: validate the manifest
  run: sshepherd validate --strict --known-hosts ci/known_hosts --config sshepherd.yaml
```
````

In `## Exit codes`, change the sentence before the table to end `(`adopt`, `import` and `validate` use `0`, `1` and `3` as their own footers below say):`, and after the `import --help` block add:

````markdown
`validate --help`:

```console
Exit codes:
  0  valid (warnings may be present)
  1  valid, with warnings, under --strict
  3  invalid, a policy conflict, or a tool error: bad flags, unreadable
     manifest, a bad --known-hosts file
```
````

- [ ] **Step 6: Gate.** Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd`, then `make check`. Expected: PASS, deadcode green.

- [ ] **Step 7: Hand back** the patch for this lane's globs. `README.md` is not in the patch.

---

## Integration

### Task 11: integrator (no lane)

One commit per round. Each commit carries its own README, `CLAUDE.md` Status and spec text (design line 1278, the CLAUDE.md README rule). `make check` and `make integration` gate **that commit's tree, before it is committed**, so neither runs on a tree missing its docs: `TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` fail without the README delta. Run `make integration` in the foreground under the runner's lock.

- [ ] **Step 1: Round 1 commit.** After the `audit-server` patch applies:

1. Apply Task 5's `docsDelta` to `README.md`.
2. `CLAUDE.md` Status, append:

```markdown
**`audit --server`** (P10 S1, OP4, PRD-11; specced in
`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, planned in
`docs/superpowers/plans/2026-11-09-p10-s1-validate-audit-server.md`): `audit --server NAME`
(repeatable) restricts the read, adds `summary.skipped`, and still exits 2 on a policy
conflict about another server (OP4). `Config.ManifestWarnings` replaces `TombstoneWarnings`
and carries every load warning in JSON, each with a kind (`Config.warn` records both
forms). `selectServers` moved to `cmd/sshepherd/fleet.go` and `readFleet` takes its targets.
```

3. In `docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, S1's **Files** paragraph: add `adopt.go` (the `readFleet` call), which the S1 text already requires.
4. **Only if the owner has answered O2 with (a)**, add under **Shared rules → JSON** in the same spec (otherwise leave the spec sentence alone and report it):

```markdown
P09's load warnings landed after this rule was written. S1 gives them the kinds
`weak_key_ungranted` and `key_expired`, so `report_key_issues.golden.json` gains one
additive `manifest_warnings` entry. That is the only golden that changed.
```

5. Run `make check` and `make integration`. `audit-server` changes audit's read path, which the E2E loop drives.
6. Commit: `feat(audit): --server and every load warning in manifest_warnings (P10 S1, PRD-11)`.

- [ ] **Step 2: Round 2 commit.** After the `validate` patch applies:

1. Apply Task 10's `docsDelta` to `README.md`.
2. Copy the README JSON samples from `cmd/sshepherd/testdata/validate_warning.golden.json` and `validate_invalid.golden.json` over the two `<copy …>` placeholders. They are copied from goldens, never from this plan.
3. `CLAUDE.md` Status, append:

```markdown
**`validate`** (P10 S1, D25, D25a, PRD-11; same spec and plan as `audit --server` above):
an offline manifest check (`--known-hosts`, `--strict`, `--json`) that never dials. It
warns about a missing default known_hosts, each server with no recorded host key, and a
manifest the editor refuses, and exits 3 on a policy conflict, including a granted weak
key. `--json` writes a schema-1 document on every exit 3 except an unreadable manifest, a
bad flag or a bad explicit `--known-hosts`.
```

4. In the same spec, change line 4's `Not built:` clause to `S1 built (plan 2026-11-09-p10-s1-validate-audit-server); the other slices are not built:`.
5. Unless the owner picked O3 (b), add to S8's **README** paragraph: `` `sshepherd validate` gains the sentence that `import` and `adopt` write a document on almost no exit 3. ``
6. Only if the owner picked O1 (b): change design lines 283-284 to "a bad `--known-hosts` file" and apply the O1 (b) edits.
7. Run `make check` and `make integration`. `validate` touches no transport, so integration should pass unchanged.
8. Commit: `feat(validate): offline manifest check with --strict and --json (P10 S1, D25, D25a, PRD-11)`.

### Task 12: independent verifier (no lane)

- [ ] **Step 1:** Confirm `git grep -n 'TombstoneWarning' -- internal cmd` prints nothing and `git grep -n 'func selectServers' -- cmd` names only `fleet.go`.
- [ ] **Step 2:** Mutations, each expected to fail a named test and then reverted:
  - drop the `printSkipped` call in `audit.go` (`TestAuditServerSubset`);
  - in `audit.go`, replace the final `return auditVerdict(cfg, results)` with `if skipped > 0 { return nil }; return auditVerdict(cfg, results)` (`TestAuditServerConflictOutsideSubsetExits2`);
  - make `selectServers` skip the unknown-name error (`TestAuditServerUnknownName`);
  - remove `len(c.keysByUser[user]) > 0` (`TestGrantCount`);
  - drop `!v.explicitKnownHosts` (`TestValidateBadKnownHosts`);
  - make `validateExit` ignore `strict` (`TestValidateWarningsAndStrict`);
  - set `Valid: true` always (`TestValidateJSONConflict`);
  - drop the `sanitize.Remote` in `splitErrors` (`TestSplitErrors`);
  - move `v.hostKeysChecked = true` above the `sshread.LoadKnownHosts` call (`TestValidateJSONMissingDefaultKnownHosts`);
  - route the `readManifest` error through `v.invalid` (`TestValidateJSONUnreadableManifestWritesNoDocument`);
  - in `run()`, return `knownErr` whenever it is non-nil, explicit or not (`TestValidateJSONDefaultKnownHostsLoadFailure`);
  - delete the whole `if knownErr != nil && v.explicitKnownHosts` block, so a bad explicit file reaches `finish` and writes a document (`TestValidateBadKnownHosts`, explicit subtests).
- [ ] **Step 3:** Run the built binary against a real manifest with no flags, with `--strict` and with `--json`, and compare the output with the README section.

---

## Review log

Two independent reviews of the draft, 20 issues (18 distinct), each checked against `aff7bf0` and the design. None rejected.

| Issue | Outcome |
|---|---|
| R0.1 decision 4 contradicts design lines 283-284 | Applied: restated as O1. The plan builds the design's text (exit 3 with a document); the test, README row and "no document" sentence flipped; the fail-closed path is listed in O1. Exit 3 in design step 5 is silent, and comes from the exit table |
| R0.2 same-commit rule | Applied: Task 11 is per-commit, docs before the gates; Status split into halves |
| R0.3 no JSON test for OP1, `manifest_not_editable`, `host_keys_checked: false` | Applied: `TestValidateJSONMissingDefaultKnownHosts`, `TestValidateJSONAnchors`, new mutation |
| R0.4 decision 8 drops a README requirement | Applied: O3, and Task 11 Step 2 adds it to S8's README paragraph |
| R0.5 decision 2 changes the spec unflagged | Applied: O2, spec edit only after the answer |
| R0.6, R1.8 Task 5 docsDelta location | Applied: own paragraph after the sample's fence. The wording is two-step: round 1 is true of round 1, and round 2's delta rewords it, so each commit's README is true |
| R0.7 no bad-flag test | Applied |
| R0.8 no repeatable test at audit level | Applied |
| R0.9, R1.9 test name in the README | Applied |
| R1.1 `net.Listen` fails `noctx` | Applied; confirmed no bare `net.Listen` in the repo |
| R1.2 integrator order and `handoffs` | Applied: `handoffs` in the JSON (verified at skeleton lines 481, 568), Conventions line for `foreignBreaks` |
| R1.3 sequencing against S2 | Applied |
| R1.4 `NonDefaultPortAndCA` passes before Task 8 | Applied: web-3 must be flagged (`HostKeyAlgorithms` nil at `10.0.1.7:2222` because a plain entry matches port 22 only) |
| R1.5 unreadable-manifest test cannot fail | Applied: stated as a pin, plus a mutation |
| R1.6 wrong expected failure text | Applied: root `Args: cobra.ArbitraryArgs` confirmed |
| R1.7 gofmt realignment | Applied: Task 2 Step 4, Task 4 Step 5 |
| R1.10 stale `cleanMemory` comment | Applied |
| R1.11 inapplicable mutation | Applied |

Also added beyond the reviews: `TestValidateConflictAndDefaultKnownHostsFailure` and two O1 mutations, because O1's document path is new code; `expandHome`'s failure gets the `known_hosts preflight:` prefix so all default-path failures read alike; S1's **Files** paragraph gets `adopt.go`, which S2's plan also asked for.

---

## Wave lanes (for the runner)

```json
{
  "rounds": [
    [
      {
        "pkg": "P10-S1",
        "lane": "audit-server",
        "kind": "fix",
        "ids": ["PRD-11"],
        "tasks": "Tasks 1-5",
        "files": [
          "internal/config/warnings.go",
          "internal/config/warnings_test.go",
          "internal/config/config.go",
          "internal/config/revoked.go",
          "internal/config/policy.go",
          "internal/config/revoked_test.go",
          "internal/audit/json.go",
          "internal/audit/json_test.go",
          "internal/audit/testdata/report_key_issues.golden.json",
          "internal/apply/json.go",
          "internal/apply/json_test.go",
          "cmd/sshepherd/fleet.go",
          "cmd/sshepherd/apply.go",
          "cmd/sshepherd/adopt.go",
          "cmd/sshepherd/audit.go",
          "cmd/sshepherd/audit_test.go",
          "cmd/sshepherd/testdata/help/audit.golden"
        ],
        "needsIntegration": true
      }
    ],
    [
      {
        "pkg": "P10-S1",
        "lane": "validate",
        "kind": "fix",
        "ids": ["PRD-11"],
        "tasks": "Tasks 6-10",
        "files": [
          "internal/config/grants.go",
          "internal/config/grants_test.go",
          "cmd/sshepherd/validate.go",
          "cmd/sshepherd/validate_test.go",
          "cmd/sshepherd/validate_pipe_test.go",
          "cmd/sshepherd/run.go",
          "cmd/sshepherd/run_test.go",
          "cmd/sshepherd/usage_test.go",
          "cmd/sshepherd/help_readme_test.go",
          "cmd/sshepherd/testdata/help/root.golden",
          "cmd/sshepherd/testdata/help/validate.golden",
          "cmd/sshepherd/testdata/validate_*.golden.json"
        ],
        "needsIntegration": false
      }
    ]
  ],
  "mergeOrder": ["P10-S1"],
  "handoffs": [
    "P10-S1: apply each lane's docsDelta to README.md BEFORE that lane's make check (the help/README tests need it); fill the two <copy …> placeholders from the regenerated goldens; a README.md entry in foreignBreaks is the gate-only delta, not a break",
    "P10-S1: run Task 11's Step 1 for round 1 and Step 2 for round 2. Each commit carries its README, CLAUDE.md Status and spec text; make check and make integration run on that tree BEFORE it is committed. O2's spec amendment is applied only if the owner's answer is in this list; report it otherwise."
  ]
}
```
