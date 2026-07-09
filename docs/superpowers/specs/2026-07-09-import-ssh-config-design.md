# Design: `sshepherd import` — convert an OpenSSH client config to a manifest

- **Date:** 2026-07-09
- **Status:** Approved, awaiting implementation plan.
- **Scope:** Second vertical slice — a converter that bootstraps a manifest's
  `servers:` section from an existing `~/.ssh/config`.

## Context & goal

Adopting SSHepherd today means hand-writing `sshepherd.yaml` from scratch, even
though most operators already describe their fleet in `~/.ssh/config`. This
slice adds `sshepherd import [path]`: it reads an OpenSSH client config and
emits a valid SSHepherd manifest with the `servers:` section filled in, ready
for the operator to add `users:` and `access:` and then run `audit`.

The conversion is **faithful, not inventive**: an SSH config describes how to
connect to machines, and only that is converted. It says nothing about who
should have access, so no users or grants are synthesized.

## Decisions (locked)

| Decision | Choice | Notes |
|---|---|---|
| Output scope | **Servers only** | `users: []`, `access: []` emitted empty. No reading of `IdentityFile`/`.pub` files, no invented grants. |
| Pattern blocks | **Resolve like OpenSSH** | Concrete aliases inherit from matching pattern blocks (`Host *`, `web-*`), first-obtained-wins. Pattern-only blocks produce no server entry. |
| Output destination | **Stdout, optional `-o`** | Default prints YAML to stdout; `-o <file>` writes it, refusing to overwrite unless `--force`. |
| `Include` | **Followed** | Globs expanded; relative paths resolved against `~/.ssh`; nesting capped at depth 16; missing targets warn, don't fail. |
| Command name | **`import [path]`** | Positional config path, default `~/.ssh/config`. Generalizes to future sources without renaming. |
| Parser | **Hand-rolled `internal/sshcfg`** | No new dependency (supply-chain stance: depguard, SBOM, go-licenses). Needed subset is small; degradation on `Match` is under our control; fuzz-tested like `internal/authkeys`. `kevinburke/ssh_config` was considered and rejected for dep cost + uncontrolled edge behavior. |

## In scope

- `sshepherd import [ssh-config-path]` subcommand (Cobra) in
  `cmd/sshepherd/import.go`, wired in `run.go` beside `audit`.
- `internal/sshcfg`: purpose-built OpenSSH client-config reader (parse +
  per-alias resolution of `HostName`, `Port`, `User`).
- Mapping resolved hosts to `config.Server` entries and marshaling a manifest.
- Tests: unit (table-driven), fuzz (+ seed corpus), golden, command-level.

## Deliberately deferred (NOT in this slice)

- Synthesizing `users:`/`access:` (e.g. from `IdentityFile` `.pub` files).
- Evaluating `Match` blocks (cannot be done statically; skipped with warning).
- Any other config keys (`ProxyJump`, `IdentityFile`, …) — no manifest
  equivalent; silently ignored.
- Merging into an existing manifest (import is generate-only; `-o` refuses to
  overwrite without `--force`).
- Importing from other sources (known_hosts, inventories) — the `import` name
  leaves room.

## Command surface

```
sshepherd import [path]      # path defaults to ~/.ssh/config
  -o, --output <file>        # write manifest to file instead of stdout
      --force                # allow -o to overwrite an existing file
```

- `~` in the positional path is expanded via the existing `expandHome`.
- Stdout carries **only** the generated YAML (clean for redirection); all
  warnings go to stderr.
- Exit codes: `0` success (including zero importable servers), `2` any error
  (unreadable config, unwritable output, `-o` target exists without `--force`),
  matching the existing `run()` mapping.

## `internal/sshcfg` — parsing & resolution semantics

**Line level.** Blank lines and `#` comments skipped. Both `Key value` and
`Key=value` accepted; double-quoted values supported; keywords
case-insensitive.

**Host blocks.** A `Host` line takes one or more whitespace-separated patterns
(`*`/`?` globs, `!` negation). Patterns match the host **alias**. A *concrete*
alias is a pattern with no wildcard and no negation; each becomes a candidate
server. Pattern-only blocks contribute defaults but emit no entry.

**Resolution (first-obtained-wins).** For each concrete alias, scan all blocks
in file order (includes inlined at their position); the first block whose
patterns match the alias (and isn't excluded by a `!` pattern) supplies each of
`HostName`, `Port`, `User` — the first value seen for a key sticks, later
matches never override. This mirrors `ssh -G` behavior for these keys.

**Include.** `Include <pattern...>`: glob-expanded; relative patterns resolve
against `~/.ssh` (OpenSSH user-config rule); nesting capped at depth 16;
a pattern matching nothing is a stderr warning, not an error. Included lines
are inlined at the `Include` position, so bare keywords inside a `Host` block
stay within that block and `Host` lines in the included file start new blocks —
matching OpenSSH behavior.

**Match blocks.** `Match` conditions (`exec`, `host`, `user`, …) cannot be
evaluated statically. The entire block (until the next `Host`/`Match`) is
skipped, with one stderr warning naming file and line.

**Everything else.** Unrecognized keywords are silently ignored. Malformed
lines (e.g. keyword with no value) produce a stderr warning naming file and
line; parsing continues.

## Mapping to the manifest

Each concrete alias → one `config.Server`:

| Manifest field | Source | Notes |
|---|---|---|
| `name` | the alias | |
| `host` | resolved `HostName` | falls back to the alias itself (ssh behavior) |
| `port` | resolved `Port` | omitted from YAML when 22 (loader defaults it) |
| `user` | resolved `User` | **required** — see below |
| `description` | — | left empty |

- An alias resolving with **no `User`** is skipped with a stderr warning (the
  manifest requires `user`; emitting it would produce an invalid manifest).
- Duplicate concrete aliases: first block wins (OpenSSH semantics); later
  duplicates are noted on stderr.
- Servers are emitted in order of first appearance (deterministic).
- Output: `users: []` / `servers: [...]` / `access: []` via `gopkg.in/yaml.v3`,
  preceded by a `# generated by sshepherd import from <path> — review before use`
  comment header.
- **Self-check:** before emitting, the generated YAML is round-tripped through
  `config.Parse`; the tool never outputs a manifest its own loader would
  reject. A self-check failure is a bug and exits 2 with the parse error.
- Zero importable servers is still success: an empty-but-valid manifest is
  emitted and the warnings on stderr explain what was skipped.

## Testing (per project policy — all kinds, coverage gated)

- **Unit** (`internal/sshcfg`): table-driven — quoting, `Key=value`, glob and
  negation matching, first-obtained-wins across blocks, `HostName` fallback,
  include glob/relative/depth-cap, `Match` skipping, malformed-line warnings.
- **Fuzz**: `go test -fuzz` target on the parser with a seed corpus of
  real-world-shaped configs committed to the repo (project rule: fuzz all
  parsers).
- **Golden**: snapshot the full emitted manifest for a representative fixture
  config (covers header, empty sections, port-22 omission, ordering).
- **Command-level** (`cmd/sshepherd`): default path expansion, positional
  path, `-o` write, `-o` refusing to overwrite, `--force`, exit codes,
  warnings-on-stderr vs YAML-on-stdout separation.
- Coverage flows through the existing `make coverage` gate (≥ 80%).
