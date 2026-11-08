# Design: audit --json output & monitoring-style exit codes

- **Date:** 2026-07-16
- **Status:** Implemented (2026-07-16) — see docs/superpowers/plans/2026-07-16-audit-json-exit-codes.md
- **Scope:** `internal/audit` (a JSON renderer beside the human one, richer
  `ExitCode`), `cmd/sshepherd` (`audit --json` flag, exit-code mapping in
  `run()`). Settles two open questions recorded in the audit slice spec
  (2026-07-06): `--json` output and a critical-drift exit code. Supersedes the
  operator spec's (2026-07-10) "critical severity is render-only" decision —
  the "revisit if scripts need it" condition is now met: audit is headed for
  cron/CI use, and a plain shell consumer cannot distinguish critical without
  an exit code.

## Context & goal

`sshepherd audit` renders a human report and exits 0 (compliant) or 1
(anything else provable-or-not), with 2 for usage/config/tool errors. Scripts
cannot consume the result without scraping text, and a missing operator key —
the drift class that threatens fleet access itself — is indistinguishable
from ordinary drift outside the rendered report.

This slice makes audit automatable: a `--json` flag that emits one
machine-readable document on stdout, and an exit-code scheme that a
monitoring system can page on without parsing anything.

## Decisions (locked)

| Decision | Choice | Notes |
|---|---|---|
| Exit scheme | **0 compliant · 1 drift/unreachable · 2 critical drift · 3 tool error** | Monotonic severity, matches Nagios/Icinga convention (0 OK / 1 WARN / 2 CRIT). Breaking: tool errors move 2 → 3, tool-wide (import/adopt included — `run()` owns the mapping). Accepted now while nothing consumes the old codes. |
| Critical definition | **≥1 server whose drift includes a missing operator key** | Exactly the existing `criticalDrift` predicate; unreachable servers stay severity 1 (nothing knowable about their keys). Precedence: 2 beats 1 beats 0. |
| Flag shape | **`--json` boolean, local to `audit`** | Matches the audit spec's own wording; zero validation surface. A future `--format` can absorb it as an alias if a third format ever exists. |
| JSON destination | **stdout, exactly one document** | The report is the command's stdout product (unchanged principle). Logs stay on stderr; `--color` does not affect JSON; the human report is suppressed. |
| Key material | **Fingerprints + identity only, never raw key lines** | Audit is read-only; anything needing key material reads the manifest. Keeps output small and diff-friendly. |
| Schema marker | **`"schema": 1`** | Cheap insurance: consumers can hard-fail on a future shape change instead of misparsing. Bump only on breaking shape changes. |
| Formatting | **2-space indented, trailing newline** | Human-inspectable when redirected to a file; jq consumes either way. |

## Exit codes — semantics & plumbing

```
0  every server compliant (empty fleet is trivially compliant)
1  drift and/or unreachable servers — compliance not proven
2  critical drift — at least one server is missing an operator key
3  usage, config, or infrastructure error (bad manifest, agent/known_hosts
   preflight failure, unknown flag, …) — formerly 2
```

- `audit.ExitCode(cfg *config.Config, results []ServerResult) int` gains the
  `cfg` parameter (needed for the operator lookup) and returns 0/1/2. The
  summary line's `→ exit N` tail keeps telling the truth for free.
- `cmd/sshepherd`: the audit command returns `errCriticalDrift` (new
  sentinel) when `ExitCode` is 2, `errNonCompliant` when 1.
- `run()` maps: nil → 0; `errNonCompliant`/`errFleetUnreadable` → 1;
  `errCriticalDrift` → 2; anything else → 3 (logged, as today).
- `adopt --partial` semantics unchanged: `errFleetUnreadable` remains 1.
  import/adopt never exit 2; their failures are 1 or 3.

## JSON shape

Field names are snake_case. `owner` and `error` are `null` when absent;
`comment` and `operator` are omitted when empty/false; booleans and counts
are always present.

```json
{
  "schema": 1,
  "summary": {
    "servers": 3, "compliant": 1, "drift": 1, "critical": 1,
    "unreachable": 1, "exit_code": 2
  },
  "servers": [
    {
      "name": "web-1", "host": "10.0.0.1", "port": 22, "user": "deploy",
      "status": "critical",
      "error": null,
      "keys": {
        "present": [
          {"owner": "alice", "comment": "alice@laptop",
           "fingerprint": "SHA256:…", "type": "ssh-ed25519"}
        ],
        "missing": [
          {"owner": "javad-ops", "fingerprint": "SHA256:…",
           "type": "ssh-ed25519", "operator": true}
        ],
        "unauthorized": [
          {"owner": null, "comment": "bob@old-laptop",
           "fingerprint": "SHA256:…", "type": "ssh-rsa"}
        ]
      },
      "parse_errors": [{"line": 7, "error": "…"}],
      "file_absent": false,
      "no_users_granted": false
    }
  ]
}
```

- **`status`** derivation, in order: `Err != nil` → `"unreachable"`;
  `Compliant()` → `"compliant"`; `criticalDrift()` → `"critical"`; else
  `"drift"`. An unreachable server carries `error` (string) and empty key
  sets. The three `keys` arrays and `parse_errors` are always present
  (empty `[]`, never `null` or omitted) so consumers get a stable shape.
- **`summary`** counts mirror the human summary line exactly (a critical
  server counts in both `drift` and `critical`, as today); `exit_code`
  duplicates the process exit for consumers that only capture stdout.
- **Key objects**: `owner` is the manifest user name via `OwnerOf`, `null`
  for unknown keys. `comment` is the key's inline comment (`authkeys.Key`),
  the only identity hint an unauthorized key has; omitted when empty.
  `operator: true` appears only on `missing` entries owned by an operator —
  the JSON twin of the CRITICAL rendering.
- **Safety**: error strings and comments arrive pre-sanitized (sshread /
  authkeys sanitizers, which also strip Cf); `encoding/json` escapes any
  control bytes besides, so a hostile server cannot smuggle terminal escapes
  even through a `cat`-ed JSON file.
- **Empty fleet**: valid document, `servers: []`, all counts 0, exit 0. The
  current early-return path must also honor `--json`.

- **Amendment (2026-11-08, P07):** additive, schema stays 1. `servers[].hint`
  holds the failure's remediation (sanitized, one line). It is omitted when
  there is none and is never part of `error`, so `error` stays groupable.
  `keys.unauthorized[].options` lists the on-server options of a key the
  manifest does not own (sanitized). It is omitted when there are none. A
  refused dial's `error` names the address once
  (`dial tcp 10.0.0.2:22: connect: connection refused`, `error_kind` `dial`).

## Implementation shape

- `internal/audit/json.go`: unexported report/server/key structs with json
  tags + `RenderJSON(w io.Writer, cfg *config.Config, results []ServerResult)
  error`. Reuses `criticalDrift`, `label`-adjacent owner lookup, `ExitCode`.
- `cmd/sshepherd/audit.go`: `--json` flag; picks `RenderJSON` vs `Render`;
  returns the sentinel matching `ExitCode`.
- `cmd/sshepherd/run.go`: `errCriticalDrift` sentinel; default error path
  returns 3.

## Testing

- **Golden**: full-fleet JSON (compliant + drift + critical + unreachable +
  parse errors) against `testdata/report.golden.json`; empty-fleet golden.
- **Round-trip**: unmarshal the golden into anonymous structs and assert the
  load-bearing fields (schema, statuses, operator marker, exit_code).
- **ExitCode table**: all four statuses, precedence (critical beats drift
  beats unreachable-only fleets), empty fleet, unreachable-only → 1.
- **cmd-level** (`run_test.go` / `audit_test.go`): `--json` produces exactly
  one valid JSON document on stdout and nothing else (logs on stderr); exit
  mapping 0/1/2/3 including the 2 → 3 remap of usage errors; every existing
  test pinning exit 2 updated deliberately.
- **Sanitization pin**: a hostile error string / key comment renders as
  escaped JSON (no raw control bytes in output).

## Deliberately deferred (NOT in this slice)

- `--json` for import/adopt (they emit manifests, not reports).
- `--format` flag, YAML/table outputs, JSON logging (`--log-format`).
- Streaming/NDJSON output for very large fleets.
- Comment-drift reporting (still an open question in the audit spec).

## Docs to touch with the implementation

- CLAUDE.md Status section (mention `--json` + exit scheme).
- 2026-07-06 audit spec: mark the two open questions settled (pointer here).
- 2026-07-10 operator spec: annotate the "Critical severity: render-only"
  decision row as superseded by this spec.
