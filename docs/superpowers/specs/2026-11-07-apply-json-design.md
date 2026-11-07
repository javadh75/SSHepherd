# Design: `--json` for apply, revoke and rotate

- **Date:** 2026-11-07
- **Status:** Approved design — awaiting plan
- **Scope:** `internal/apply` (a JSON renderer beside the text one),
  `cmd/sshepherd` (`--json` on the shared run flags of `apply`, `revoke`,
  `rotate`), plus one wording fix in `internal/sshconn`. Fulfils the
  `apply --json` item deferred by the apply slice (2026-07-19) and the
  revoke/rotate slice (2026-10-23).

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
| Prompt rule | **`--json` requires `--dry-run` or `--yes`, always** | Even when nothing would change — predictable. Checked before any connection. |
| Destination | **stdout, exactly one document, at the end** | Text header/plan/summary suppressed; logs on stderr; `--color` has no effect. Passphrase prompts stay on `/dev/tty`. |
| Tool errors | **No document; exit 3; message on stderr** | Same as `audit --json`. |
| Schema marker | **`"schema": 1`** plus **`"command"`** | `command` names the document kind; bump `schema` only on breaking changes. Same field-presence and additive-optional conventions as audit. |
| Formatting | **2-space indent, trailing newline** | As audit. |

## CLI behavior

- `--json` (bool) is registered on the shared `runFlags` used by `apply`,
  `revoke` and `rotate`.
- Without `--dry-run` or `--yes`: exit 3 before dialing, message
  `--json needs --dry-run or --yes (a script cannot answer the confirmation prompt)`.
- The document is written once, after phase 2 (or after the plan for
  `--dry-run`). The text edit header, plan report and outcome summary are
  not written.
- **Tool errors print no document** (exit 3): unloadable manifest, failed
  preflight, unreadable/refused `--identity`, interrupt before any write,
  manifest changed since read, any revoke/rotate refusal before save, a
  failed save.
- **Interrupt after writes started**: started writes finish (unchanged); the
  document is written with their real outcomes and `pending` (with the
  "not started" reason in `error`) for the rest.
- **Edit-only runs** — `revoke`/`rotate --no-apply`, or an edit that
  affects no server (both take `saveOnly`): document with the `edit`
  section, all `summary` counts 0, `exit_code` 0, `servers: []`; `saved` is
  `false` under `--dry-run`, else `true`. `edit.affected` > 0 with
  `servers: []` is how a consumer sees "saved, not yet pushed".
- **Save withheld after the plan** (the post-prompt re-list finds no held
  key surviving anywhere): not a tool error — the document is written with
  `"saved": false`, every change server `pending`, exit 1 (as today).
- The text-mode stdout lines from revoke/rotate ("manifest … updated —
  commit and push it", "no servers contacted — …", the scope line) are
  suppressed under `--json`; `edit.saved` and `edit.affected` carry the
  same facts.
- **Exit codes unchanged.** `summary.exit_code` repeats the process exit.
  Under `--json` a declined prompt cannot happen (`--yes` or no prompt).

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
    "servers": 3, "converged": 1, "applied": 1, "pending": 0,
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
           "options": {"from": ["from=\"10.0.0.0/8\""], "to": []},
           "loosens": ["from="]}
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

- `saved`: the manifest was written to disk — `false` under `--dry-run`,
  `true` otherwise (including `--no-apply`).
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

Same counting as `apply.RenderSummary`, extracted so text and JSON share
it: `converged` includes servers applied this run (text: "2/3 converged
(1 applied)"); `pending`, `failed`, `refused` (plan-refused + write-refused),
`unreachable`; `exit_code` = `apply.ExitCode(plans)`.

### Per server

- `name`, `host`, `port`, `user`; `authorized_keys_file` only when the
  manifest sets the override (as audit).
- `class`: `converged` | `change` | `refused` | `unreachable`.
- `outcome`: `applied` | `refused` | `failed` | `pending` for `change`;
  `null` otherwise. Always `pending` under `--dry-run`.
- `error`: string or `null` — the unreachable error, the plan refusal, or
  the outcome error (write/verify/probe failure, write refusal, "not
  started"). `error_kind` (an `audit.ErrorKind`, via `audit.ErrorKindOf`) is
  present only for `unreachable`.
- `changes`: always present with all four members; arrays `[]` when empty.
  - `add[]` — desired keys missing (manifest form; `comment` is the
    desired comment).
  - `remove[]` — installed keys not desired (on-server form and comment).
  - `rewrite[]` — `owner`, `fingerprint`, `type`, then only what changes:
    `options: {from, to}` when `OptionsDiffer`, `comment: {from, to}` when
    `CommentDiffers`; `loosens` (`[]` when none) always present.
  - `normalize` — the five `apply.Normalize` fields.
- `file_absent`, `authorized_keys2_present` (phase-1 finding),
  `disables_authorized_keys2` (`ServerPlan.DisableKeys2()`): always present.
- `notes`: object; members omitted when empty — `guard` (`Note`),
  `restrictive_options` (`Warning`), `agent_only_survivors` (`AgentOnly`).

### Key objects

As audit's: `owner` always present (`null` = the rendered manifest does not
own it), `fingerprint`, `type`, `comment` (omitted when empty), `operator:
true` only for keys owned by an operator user. New: `former_owner` (omitted
unless set) — the owner in `JSONOptions.Former` of a key the edited manifest
no longer owns; the JSON twin of "bob (revoked)" / "(rotated out)".

### Safety

Every server-derived string (comments, options, `loosens`, error text)
passes through `sshconn.SanitizeRemote` before encoding — idempotent on
already-sanitized input. This matters because `encoding/json` leaves C1
runes (e.g. U+009B, CSI) and Cf runes (bidi overrides) unescaped. A test
pins ESC, C1 and U+202E in an on-server comment, an option and an error.

## Implementation shape

### `internal/apply/json.go` (new)

```go
// JSONOptions selects the document kind and the revoke/rotate extras.
type JSONOptions struct {
	Command    string         // "apply" | "revoke" | "rotate"
	DryRun     bool
	Former     *config.Config // as-loaded config before the edit; nil for apply
	Edit       *EditSummary   // nil for apply
	Saved      bool           // manifest written (revoke/rotate)
}

// RenderJSON writes one indented JSON document (trailing newline).
func RenderJSON(w io.Writer, cfg *config.Config, plans []ServerPlan, opts JSONOptions) error
```

Unexported wire structs with json tags; field names are the public contract
(change only with a schema bump). The summary counting moves into an
unexported helper shared with `RenderSummary`.

### `cmd/sshepherd`

- `runFlags` gains `json bool`; `register` declares `--json`; a shared check
  enforces the prompt rule before preflight.
- `runApply`: under `--json`, skip `run.header`, `apply.Render` and
  `apply.RenderSummary`; `finish` calls `apply.RenderJSON` once.
- revoke/rotate (`editrun.go`) supply `Command`, `Former`, `Edit`, and
  `Saved` (set after a successful save; false under `--dry-run`);
  `saveOnly` renders the edit-only document, and the text-only stdout lines
  (`saveEdit`'s reminder, "no servers contacted", `printScope`) are skipped
  under `--json`.

### `internal/sshconn/sshconn.go`

`FinishRead`'s truncation error says "refusing to **trust** a truncated
authorized_keys" (was "audit") — it serves audit, adopt, apply's plan and
apply's verify. Update the pinned test in `sshconn_test.go` and any golden or
README text quoting the old wording.

## Testing (per project policy — all kinds, coverage ≥ 80%)

- **Golden** (`internal/apply/testdata/*.golden.json`): mixed fleet (all four
  classes, all four outcomes, rewrite with options + comment + loosens,
  normalize, every note, keys2 disable, override path); dry run; revoke with
  `former_owner` and `emptied`; rotate with `keeps_expiry`; `--no-apply`;
  empty fleet.
- **Round-trip**: unmarshal each golden; assert schema, command, statuses,
  outcomes, `exit_code`, `saved`.
- **Stable shape**: non-change servers still carry `changes` with `[]`
  arrays; `outcome` null off `change`.
- **Sanitization pin**: ESC, U+009B and U+202E in comment/option/error come
  out stripped; no raw control or Cf runes in output.
- **Summary parity**: text and JSON summaries agree for a table of fleets.
- **cmd-level**: `--json` without `--yes`/`--dry-run` → exit 3, no dial;
  stdout is exactly one valid document and nothing else (logs on stderr);
  tool error → empty stdout; edit-only documents (`--no-apply`, zero
  affected, each with and without `--dry-run`); save-withheld document
  (`saved: false`, exit 1); interrupt-after-write document carries real +
  `pending` outcomes.
- **Help/README test**: flag tables for apply/revoke/rotate include `--json`.
- **Integration** (`//go:build integration`): `apply --json --yes` against
  the dockerized sshd; parse and assert `applied`.
- **E2E**: one step runs `revoke --json --yes` and asserts the parsed
  outcomes and `edit.saved`.
- goleak `TestMain` already present in both packages.

## Workflow split (disjoint file ownership)

1. **Agent A** — `internal/apply/json.go`, `json_test.go`, goldens, the
   summary-count helper in `report.go`.
2. **Agent B** — `cmd/sshepherd` plumbing and tests (against the signature
   above) + the `internal/sshconn` wording fix and its test.
3. **Integrator** — merges, `make check` + `make integration`, README (flag
   tables, a "JSON output" section whose sample is copied from a golden,
   wording if quoted), CLAUDE.md Status.
4. **Verifier** (independent), then a **repair pass**.

## Deliberately deferred (NOT in this slice)

- `--json` for `import`/`adopt` (they emit manifests).
- A `command` field on audit's document.
- Streaming/NDJSON, `--format`, JSON logs.
- A plan-hash or rendered-bytes digest in the document.

## Docs to touch with the implementation

- `README.md`: `--json` row in the apply/revoke/rotate flag tables; a "JSON
  output" section for the write path (sample copied from a golden); the
  `--json` prompt rule; Status unchanged in shape.
- `CLAUDE.md` Status: one sentence on write-path `--json`.
