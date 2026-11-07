# Design: `--json` for apply, revoke and rotate

- **Date:** 2026-11-07
- **Status:** Implemented (2026-11-07, commit 3080a57) — see docs/superpowers/plans/2026-11-07-apply-json.md
- **Scope:** `internal/apply` (a JSON renderer beside the text one),
  `cmd/sshepherd` (`--json` on the shared run flags of `apply`, `revoke`,
  `rotate`), plus two small fixes: the truncation wording in
  `internal/sshconn` and control/format-rune sanitizing in `audit --json`
  (`internal/audit/json.go`). Fulfils the `apply --json` item deferred by the
  apply slice (2026-07-19) and the revoke/rotate slice (2026-10-23).

## Context & goal

`audit --json` made drift machine-readable (schema 1, 2026-07-16). The write
path is still text-only, yet `--identity` (2026-10-16) exists precisely so
`apply --yes`, `revoke --yes` and `rotate --yes` can run headless in CI and
cron. Those runs need a record a script can read: what the plan was, what
each server's outcome was, and — for revoke/rotate — what the manifest edit
did. A plan-only document also serves a pre-apply policy gate ("block if any
rewrite loosens options").

## Decisions (locked, owner-approved 2026-11-07)

| Decision | Choice | Notes |
|---|---|---|
| Runs covered | **Plan and result**: `--json` works with `--dry-run` or `--yes` | One document at the end holds each server's plan and outcome. Rejected: plan-only (no record of headless writes). |
| Commands | **`apply`, `revoke`, `rotate`** | revoke/rotate add an `edit` section; they share `runApply`, so cost is one struct and tests. Offboarding is the most-scripted flow. |
| Detail level | **Everything the text report shows, as data** | Adds, removes, rewrites (options/comment from→to, `loosens`), normalize, notes. Never raw key blobs, never the rendered file bytes. |
| Implementation | **Separate renderer in `internal/apply`** | Mirrors `internal/audit/json.go`: unexported wire structs + `RenderJSON`. Internal types stay free to change. Rejected: json tags on `ServerPlan` (leaks `Rendered`, raw errors); a shared report package (premature). |
| Prompt rule | **`--json` requires `--dry-run` or `--yes`, always** | Even when nothing would change — predictable. Checked with the other flag validation, before the manifest is read. |
| Destination | **stdout, exactly one document, at the end** | All text stdout is suppressed (every site listed below); logs on stderr; `--color` has no effect. Passphrase prompts stay on `/dev/tty`. |
| When a document exists | **Exactly when the run ends without a tool error** (exit 0 or 1) | Exit 3 never writes one. See "Document rule". |
| Schema marker | **`"schema": 1`** plus **`"command"`** | `command` names the document kind; bump `schema` only on breaking changes. Same field-presence and additive-optional conventions as audit. |
| Formatting | **2-space indent, trailing newline** | As audit. |

## CLI behavior

### Flag and prompt rule

- `--json` (bool) is registered on the shared `runFlags` used by `apply`,
  `revoke` and `rotate`. Help text, pinned (the README table must match
  `--help` exactly):
  `emit the plan and outcome as machine-readable JSON on stdout (needs --dry-run or --yes)`.
- The prompt rule is checked in `apply`'s `RunE` right after
  `validateFlags`, and in `editFlags.validate` for revoke/rotate — before the
  manifest is read and before any branch that could print. Failure: exit 3,
  message
  `--json needs --dry-run or --yes (a script cannot answer the confirmation prompt)`.
  `--dry-run`/`--yes` are already mutually exclusive, and `--no-apply` still
  confirms, so `revoke --no-apply --json` needs `--yes` (or `--dry-run`).

### Document rule

A run writes **exactly one** document to stdout **iff it ends with exit 0 or
1**; exit 3 never writes one (the message goes to stderr, as today). Concretely
the document is rendered on every one of these paths, and they are the only
paths that return 0/1:

| Path (today's code) | Exit | Document |
|---|---|---|
| `apply` with zero targets (`apply.go` returns before `runApply`) | 0 | empty fleet: `servers: []`, counts 0, `summary.skipped` = servers excluded by `--server` |
| `runApply` → `finish` (`stagePlanned`, `stageConfirmed`) | 0/1 | full document |
| Ctrl-C after the plan, before/while `Execute` runs (apply: `beforeWrite` does not check the context, so `Execute` marks unstarted servers interrupted and `finish` runs) | 1 | full document; unstarted servers `pending` with `error_kind: "canceled"` |
| revoke/rotate **nothing can land** — the `prompt` hook returns `errNonCompliant` when every affected server is refused (`editrun.go` `nothingCanLand`) | 1 | full document, `edit.saved: false`, change servers `pending` |
| revoke/rotate **save withheld** — `beforeWrite` returns `errNonCompliant` when no held key survives anywhere | 1 | full document, `edit.saved: false`, change servers `pending` |
| revoke/rotate **edit-only** (`saveOnly`: `--no-apply`, or no server affected), with or without `--dry-run` | 0 | `edit` section, `servers: []`, counts 0, `exit_code` 0; `saved` false under `--dry-run` |

The two `errNonCompliant` paths that today bypass `finish` (nothing can land,
save withheld) need a render hook: `runApply` gains a `stageWithheld` and
calls `run.finish(plans, stageWithheld)` when the `prompt` hook or
`beforeWrite` returns `errNonCompliant`; `finish` renders (text or JSON) and
returns `errNonCompliant`. A declined prompt (`stageDeclined`) cannot occur
under `--json`.

Exit 3 (no document) covers, among the existing tool errors: bad flags and the
prompt rule, unloadable manifest, failed preflight, unreadable/refused
`--identity`, interrupt during phase 1 (`audit.Run`), `apply`'s manifest
changed since read, and revoke/rotate's own exit-3 refusals as listed in the
README exit-code table — unknown user or key, an operator target without
`--operator`, a manifest the edits cannot handle or that is not a regular file,
a concurrent save, a failed save, and an interrupt caught by their
`beforeWrite` (manifest not saved). **Exit codes are unchanged.**

### Text stdout suppressed under `--json`

Every current `Fprint*(stdout, …)` site on these commands is skipped under
`--json` (the facts move into the document):

| Site | Text | JSON carrier |
|---|---|---|
| `apply.go` zero-targets `apply.Render` | "Summary: 0 servers targeted…" | empty-fleet document |
| `apply.go` `finish` | `(N skipped by --server)` | `summary.skipped` |
| `runApply` `run.header` / `apply.Render` / `apply.RenderSummary` | edit header, plan, outcomes | `edit`, `servers`, `summary` |
| `editrun.go` `saveEdit` | `manifest … updated — commit and push it…` | `edit.saved` |
| `editrun.go` `saveOnly` | `no servers contacted — …` | `edit.affected` with `servers: []` |
| `editrun.go` `finishEdit` | `manifest updated; N servers not converged — finish with: …` | derivable: servers whose outcome is not `applied`/class not `converged`, minus `edit.emptied` |
| `editrun.go` `printScope` (saveOnly + finishEdit) | the scope line | `summary.servers` vs. manifest (informational; not carried) |

The integrator greps `Fprint.*stdout` over `cmd/sshepherd` to confirm no site
is missed; a cmd test asserts stdout is one JSON value and nothing else on
every path in the Document rule table.

## JSON shape

```json
{
  "schema": 1,
  "command": "revoke",
  "dry_run": false,
  "edit": {
    "saved": true,
    "edits": [
      {"kind": "remove-user", "user": "bob", "keys": 2, "grants": 3}
    ],
    "affected": 3,
    "operators": [],
    "emptied": [{"server": "db-1", "users": ["carol"], "keys": 1}]
  },
  "summary": {
    "servers": 3, "skipped": 0, "converged": 1, "applied": 1, "pending": 0,
    "failed": 0, "refused": 1, "unreachable": 1, "exit_code": 1
  },
  "servers": [
    {
      "name": "web-1", "host": "10.0.0.1", "port": 22, "user": "deploy",
      "class": "change",
      "outcome": "applied",
      "error": null,
      "changes": {
        "add": [],
        "remove": [
          {"owner": null, "former_owner": "bob", "fingerprint": "SHA256:…",
           "type": "ssh-ed25519", "comment": "bob@laptop"}
        ],
        "rewrite": [
          {"owner": "alice", "fingerprint": "SHA256:…", "type": "ssh-ed25519",
           "options_change": {"from": ["from=\"10.0.0.0/8\""], "to": []},
           "loosens": ["from=\"10.0.0.0/8\""]}
        ],
        "normalize": {"reorder": false, "non_key_lines": 2, "duplicates": 0,
                      "duplicate_options_differ": false, "whitespace": false}
      },
      "file_absent": false,
      "authorized_keys2_present": false,
      "disables_authorized_keys2": false,
      "notes": {}
    }
  ]
}
```

### Top level

- `command`: `"apply"`, `"revoke"` or `"rotate"`.
- `dry_run`: true exactly when `--dry-run` was given.
- `edit`: `null` for `apply`; an object for `revoke`/`rotate`.
- `summary` and `servers` always present (`servers: []` when empty).

### `edit`

- `saved`: the manifest was written to disk — `false` under `--dry-run` and
  on the nothing-can-land / save-withheld paths, `true` otherwise (including
  `--no-apply`).
- `edits[]`, one per `apply.Edit`, field presence by `kind`:
  - `remove-user`: `user`, `keys`, `grants`.
  - `remove-key`: `user`, `fingerprint`, `no_keys_left`, `clears_operator`.
  - `rotate`: `user`, `fingerprint` (old), `new_fingerprint`,
    `keeps_expiry` (omitted when empty).
- `affected`: `EditSummary.Affected`.
- `operators`: operator targets acknowledged with `--operator` (`[]` when none).
- `emptied[]`: `server`, `users` (owners whose keys stay installed), `keys`
  (`[]` when none).

### `summary`

Same counting as `apply.RenderSummary`, extracted into one unexported helper
so text and JSON cannot disagree: `servers` (planned), `skipped` (excluded by
`--server`; always present, 0 for revoke/rotate), `converged` (includes
servers applied this run — text: "2/3 converged (1 applied)"), `applied`,
`pending`, `failed`, `refused` (plan-refused + write-refused), `unreachable`;
`exit_code` = `apply.ExitCode(plans)` (0 for an empty plan list), which equals
the process exit on every document path.

### Per server

- `name`, `host`, `port`, `user`; `authorized_keys_file` only when the
  manifest sets the override (as audit).
- `class`: `converged` | `change` | `refused` | `unreachable`.
- `outcome`: `applied` | `refused` | `failed` | `pending` for `change`;
  `null` otherwise (mapped explicitly — `planOne` sets `Pending` on every
  plan). Always `pending` under `--dry-run`.
- `error`: string or `null` — the unreachable error, the plan refusal, or
  the outcome error (write/verify/probe failure, write refusal, "not
  started").
- `error_kind`: present only (a) on `unreachable` servers, from
  `audit.ErrorKindOf(Err)`, and (b) as `"canceled"` on `pending` servers
  whose `OutcomeErr` is apply's interrupted error (`errors.Is`) — so "not
  started" is detectable without parsing English.
- `changes`: always present with all four members; arrays `[]` when empty.
  - `add[]` — desired keys missing; key objects whose `comment` is the
    decided write-time comment, `config.DesiredComment` (what the write
    installs), not the manifest line's raw comment.
  - `remove[]` — installed keys not desired; key objects with the
    on-server comment.
  - `rewrite[]` — **not key objects**: `owner`, `fingerprint`, `type`,
    `operator` (as below), then only what changes: `options_change: {from,
    to}` when `OptionsDiffer`, `comment_change: {from, to}` when
    `CommentDiffers`; `loosens` (`[]` when none) always present. `loosens`
    entries are the dropped options **verbatim** as on the server
    (`droppedRestrictions`), e.g. `from="10.0.0.0/8"`, not bare names.
  - `normalize` — the five `apply.Normalize` fields.
- `file_absent`, `authorized_keys2_present` (phase-1 finding),
  `disables_authorized_keys2` (`ServerPlan.DisableKeys2()`): always present.
- `notes`: object; members omitted when empty — `guard` (`Note`),
  `restrictive_options` (`Warning`), `agent_only_survivors` (`AgentOnly`).

### Key objects (`add[]`, `remove[]`)

`owner` always present (`null` = the rendered manifest does not own it),
`fingerprint`, `type`, `comment` (string, omitted when empty), `operator:
true` when the current owner is an operator user (on `add`, `remove` and
`rewrite` entries — broader than audit, which marks only missing keys,
because a removed or rewritten operator key is equally consequential here).
New: `former_owner` (omitted unless set) — the owner in `JSONOptions.Former`
of a key the edited manifest no longer owns; the JSON twin of "bob (revoked)"
/ "(rotated out)".

### Safety

- Error text: `oneLine(...)` then `sshconn.SanitizeRemote` (SanitizeRemote
  keeps `\n`/`\t`; `oneLine` collapses them, matching the text report).
- Comments, options and `loosens` entries: `sshconn.SanitizeRemote` — strips
  C0/DEL/C1 (e.g. U+009B CSI) and Cf (e.g. U+202E) runes, which
  `encoding/json` would otherwise emit raw. Consequence, documented in the
  README: a comment or option containing such runes is not byte-identical to
  the server's line. Fingerprints and key types are derived values and need
  no sanitizing.
- **`audit --json` gets the same fix in this slice** (`internal/audit/json.go`):
  today it passes on-server comments raw (`ParseLine` does not filter them),
  so a hostile comment can carry C1/Cf runes into `audit --json` output.
- A test pins ESC, U+009B and U+202E in an on-server comment, an option and an
  error string, for both apply's and audit's JSON.

## Implementation shape

### `internal/apply/json.go` (new)

```go
// JSONOptions selects the document kind and the revoke/rotate extras.
type JSONOptions struct {
	Command string         // "apply" | "revoke" | "rotate"
	DryRun  bool
	Skipped int            // servers excluded by --server (apply only)
	Former  *config.Config // as-loaded config before the edit; nil for apply
	Edit    *EditSummary   // nil for apply
	Saved   bool           // manifest written (revoke/rotate)
}

// RenderJSON writes one indented JSON document (trailing newline).
// plans may be nil (empty fleet, edit-only runs).
func RenderJSON(w io.Writer, cfg *config.Config, plans []ServerPlan, opts JSONOptions) error
```

Unexported wire structs with json tags; field names are the public contract
(change only with a schema bump). The summary counting moves into an
unexported helper in `report.go` shared with `RenderSummary`.

### `cmd/sshepherd`

- `runFlags` gains `json bool`; `register` declares `--json` with the pinned
  help text; the prompt rule lives in `apply`'s `RunE` after `validateFlags`
  and in `editFlags.validate`.
- `apply.go`: the zero-targets branch renders the empty-fleet document under
  `--json`; `finish` passes `Skipped`.
- `runApply`: under `--json`, skip `run.header`, `apply.Render` and
  `apply.RenderSummary`; add `stageWithheld` and route the `prompt`-hook and
  `beforeWrite` `errNonCompliant` returns through `run.finish`.
- `editrun.go`: supply `Command`, `Former`, `Edit`, and `Saved` (set after a
  successful `saveEdit`; false under `--dry-run` and on withheld paths);
  `saveOnly` renders the edit-only document; `saveEdit`'s reminder, "no
  servers contacted", `finishEdit`'s "not converged" hint and `printScope`
  are skipped under `--json`.

### `internal/sshconn/sshconn.go`

`FinishRead`'s truncation error says "refusing to **trust** a truncated
authorized_keys" (was "audit") — it serves audit, adopt, apply's plan and
apply's verify. Only `sshconn.go` and the pinned assertion in
`sshconn_test.go` contain the old wording (no golden or README quotes it).

### `internal/audit/json.go`

Run on-server comments and error strings (after the existing `oneLine`)
through the same sanitizer, with a pin test. `internal/audit` cannot import
`internal/sshconn` (sshconn imports audit — a cycle), so the body moves to a
new leaf package **`internal/sanitize`** (`sanitize.Remote(s string) string`,
stdlib-only, with its own tests and goleak `TestMain`);
`sshconn.SanitizeRemote` becomes a one-line delegate so existing callers
(including `internal/apply`) are unchanged.

## Testing (per project policy — all kinds, coverage ≥ 80%)

- **Golden** (`internal/apply/testdata/*.golden.json`): mixed fleet (all four
  classes, all four outcomes, a `canceled` pending server, rewrite with
  options + comment + verbatim loosens, normalize, every note, keys2
  disable, override path, operator markers); dry run; revoke with
  `former_owner` and `emptied`; rotate with `keeps_expiry`; nothing-can-land
  (`saved: false`); edit-only; empty fleet with `skipped`.
- **Round-trip**: unmarshal each golden; assert schema, command, classes,
  outcomes, `exit_code`, `saved`, `skipped`.
- **Stable shape**: non-change servers still carry `changes` with `[]`
  arrays; `outcome` null off `change`.
- **Sanitization pin**: ESC, U+009B and U+202E in comment/option/error come
  out stripped, apply and audit both; no raw control or Cf runes in output.
- **Summary parity**: text and JSON summaries agree for a table of fleets.
- **cmd-level**: `--json` without `--yes`/`--dry-run` → exit 3 before the
  manifest is read (also with zero targets); every Document-rule path
  produces exactly one valid JSON value on stdout and nothing else (logs on
  stderr) with the expected exit; every exit-3 path leaves stdout empty;
  interrupt-after-plan document carries real + `pending`/`canceled`
  outcomes.
- **Help/README**: the existing `TestHelpMatchesREADMETables` enforces the new
  `--json` rows once registered.
- **Integration** (`//go:build integration`): `apply --json --yes` against
  the dockerized sshd; parse and assert `applied`.
- **E2E**: one step runs `revoke --json --yes` and asserts the parsed
  outcomes and `edit.saved`.
- goleak `TestMain` already present in the touched packages.

## Workflow split (disjoint file ownership)

1. **Agent A** — `internal/apply/json.go`, `json_test.go`, goldens, the
   summary-count helper in `report.go`.
2. **Agent B** — `cmd/sshepherd` plumbing and tests (against the signature
   above), the `--json` rows in the README flag tables for apply/revoke/rotate
   (so `TestHelpMatchesREADMETables` stays green), the `internal/sshconn`
   wording fix, the new `internal/sanitize` leaf (+ `SanitizeRemote`
   delegate), and the `internal/audit/json.go` sanitizing fix with tests.
3. **Integrator** — merges, the `Fprint.*stdout` grep, `make check` +
   `make integration`, the rest of the README ("JSON output" section for the
   write path with a sample copied from a golden, the prompt rule, the
   sanitizing note), CLAUDE.md Status.
4. **Verifier** (independent), then a **repair pass**.

## Deliberately deferred (NOT in this slice)

- `--json` for `import`/`adopt` (they emit manifests).
- A `command` field on audit's document.
- Streaming/NDJSON, `--format`, JSON logs.
- A plan-hash or rendered-bytes digest in the document.
- Carrying `finishEdit`'s "finish with: …" hint or the scope line as fields
  (derivable).
