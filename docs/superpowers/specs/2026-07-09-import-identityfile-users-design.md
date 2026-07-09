# Design: `sshepherd import` — derive `users:`/`access:` from `IdentityFile`

- **Date:** 2026-07-09
- **Status:** Implemented (2026-07-09) — see docs/superpowers/plans/2026-07-09-import-identityfile-users.md
- **Scope:** Extends the import slice
  (docs/superpowers/specs/2026-07-09-import-ssh-config-design.md), which
  deliberately deferred this. Import stops emitting `users: []` / `access: []`
  and instead derives both from the config's `IdentityFile` directives and
  OpenSSH's default identities.

## Context & goal

The import slice converts `~/.ssh/config` into a servers-only manifest, on the
grounds that an SSH config says how to connect, not who may log in. That is
true for grants in general — but the config *does* carry one authorization
fact: which key you actually use for each host (`IdentityFile`, or ssh's
default identities when none is set). Leaving `users:`/`access:` empty forces
the operator to restate by hand information the machine already has.

This extension makes import emit a **complete starter manifest**: servers, the
public keys behind the identities the config uses, and access entries mapping
each key to exactly the hosts that use it. The output remains a reviewed
draft, not gospel — the header comment still says "review before use", and
`audit` verifies it against fleet reality.

## Decisions (locked)

| Decision | Choice | Notes |
|---|---|---|
| Key→user mapping | **One manifest user per identity file** | Preserves the config's exact key→host mapping; never widens access (a merged single user would grant every key to every host via `DesiredFor`'s union). Operator merges entries by hand during review if desired. A "group by key set" hybrid is impossible: validation forbids one key under two users. |
| Hosts with no `IdentityFile` | **Fall back to default identities, all that exist** | Mirrors ssh: every default basename whose `.pub` exists in `~/.ssh` becomes a user granted those hosts. Stale spare keys may appear — named in warnings, caught in review/`audit`. |
| User naming | **`<local-user>-<key basename>`** | e.g. `javad-id_ed25519`, `javad-work`. One deterministic rule; numeric suffix (`-2`, `-3`) with a warning when different keys collide on a name. |
| Default vs flag | **New behavior is the default; `--servers-only` opts out** | The point of import is a usable manifest. `--servers-only` restores the previous output (e.g. importing a config on a machine whose keys aren't yours). |
| Logic placement | **New `internal/identity` package** | Hosts + injected home dir/username in, users + access out. `cmd/sshepherd/import.go` stays thin glue; matches how `sshcfg`/`authkeys` isolate parsing logic. Resolution inside `sshcfg` was rejected — the parser answers "what does the config say", not "what exists on disk". |
| Key material | **Read only `<path>.pub`** | Never open a private key, never `ssh-keygen -y`. Missing/unparseable `.pub` → warning, identity skipped. |

## In scope

- `internal/sshcfg`: parse the `identityfile` keyword; `Host` gains
  `Identities []string` (raw values, unexpanded).
- `internal/identity`: token expansion, default-identity scanning, `.pub`
  reading/validation (via `authkeys.ParseLine`), fingerprint dedup, user
  naming, access grouping.
- `cmd/sshepherd/import.go`: `userOut`/`accessOut` marshaling, `--servers-only`
  flag, help-text update.
- Tests: unit (both packages), fuzz corpus additions, new golden fixture,
  command-level.

## Deliberately deferred (NOT in this slice)

- `IdentitiesOnly`, `CertificateFile`, agent-held keys — none change which
  public keys belong in `authorized_keys` in a statically determinable way.
- Tokens beyond `~`, `%d`, `%u` (`%h`, `%r`, `%n`, …) — host-dependent or
  rarely used in `IdentityFile`; warn and skip that path.
- Merging derived users into an existing manifest.

## Command surface

```
sshepherd import [path]      # unchanged; users/access now populated
      --servers-only         # previous behavior: users: [], access: []
```

Stdout/`-o`/`--force`, warnings-to-stderr, and exit codes are unchanged.
Help text gains one caveat: default identities are scanned on the machine
running import, so run it where you actually ssh from.

## `internal/sshcfg` — `identityfile` semantics

Unlike `HostName`/`Port`/`User` (first-obtained-wins), OpenSSH **accumulates**
`IdentityFile` across all matching blocks. The parser mirrors that: for each
concrete alias, collect the values from every matching block in file order,
first argument per directive, deduping repeated paths. Values are stored raw —
no `~`/token expansion in the parser, keeping it a pure reader of the config.
`Match`-block skipping and `Include` inlining apply as for other keywords.

## `internal/identity` — resolution semantics

Inputs: `[]sshcfg.Host`, home directory, local username (both injected;
tests use `t.TempDir()` layouts). For each host, in appearance order:

1. **Identity list.** The host's raw `Identities`, expanded: leading `~/` and
   `%d` → home, `%u` → local username; any other `%` token → stderr warning,
   path skipped. If the host has no `IdentityFile` at all, use the **default
   scan**: OpenSSH's default basenames in ssh's try order — `id_rsa`,
   `id_ecdsa`, `id_ecdsa_sk`, `id_ed25519`, `id_ed25519_sk`, `id_xmss`,
   `id_dsa` — keeping each whose `.pub` exists in `<home>/.ssh`.
2. **Public key.** Read `<path>.pub`; parse with `authkeys.ParseLine`.
   Missing or invalid → warning, identity skipped. Two paths resolving to the
   same fingerprint dedupe to one user (first-seen path names it).
3. **User entry.** `name`: `<local-user>-<basename of key path>`; on collision
   between different keys, numeric suffix + warning. `description`:
   `imported from <raw path>` (raw as written — never the expanded form, which
   would leak the local home directory into a committed file); default-scanned
   keys use `imported from ~/.ssh/<name> (default identity)`. `comment`: the
   `.pub` trailing comment, when present. `keys`: the single public key line.
4. **Access entry.** One per user: the aliases (appearance order) whose
   identity list includes that key — restricted to aliases that became server
   entries, so a host skipped for missing `User` never appears in `access`.
   A host whose identities all failed to resolve keeps its server entry, with
   a `no access derived for host …` warning. A user whose every host was
   skipped as a server is dropped entirely, with a warning — import never
   emits a grantless user.

Users and access are emitted in first-appearance order — fully deterministic.

## Output & self-check

`import.go` adds `userOut` (`name`, `description,omitempty`,
`comment,omitempty`, `keys`) and `accessOut` (`user`, `servers`) mirrors.
The existing round-trip through `config.Parse` now genuinely validates key
lines, uniqueness, and access references; a failure is still a bug and exits 2.
Zero derivable users remains success — warnings on stderr explain what was
skipped, and `--servers-only` output is byte-identical to today's.

## Security notes

- Only `.pub` files are ever opened; private key material is never read.
- Generated `description` uses the path as written in the config, not the
  expanded absolute path.
- Committed test fixtures contain throwaway **public** keys only (gitleaks
  stays clean).

## Testing (per project policy — all kinds, coverage gated)

- **Unit** (`internal/identity`): table-driven over temp-dir layouts —
  explicit identity, default scan (0/1/many keys present), missing `.pub`,
  invalid `.pub`, `~`/`%d`/`%u` expansion, unsupported-token skip, name
  collision suffixing, fingerprint dedup, no-access-derived warning.
- **Unit** (`internal/sshcfg`): `identityfile` accumulation order across
  blocks, dedup, `Key=value` form, `Match`/`Include` interaction.
- **Fuzz**: existing parser target inherits the keyword; seed corpus gains
  `IdentityFile` lines.
- **Golden**: new fixture with two explicit identities + a default-scan host;
  snapshot the full manifest (header, users, servers, access, ordering).
- **Command-level** (`cmd/sshepherd`): `--servers-only`, missing-`.pub`
  warnings on stderr vs clean YAML on stdout, exit codes.
- Coverage flows through the existing `make coverage` gate (≥ 80%).
