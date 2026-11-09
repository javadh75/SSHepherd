# Design: access model and fleet reach

- **Date:** 2026-11-08
- **Status:** Approved (owner, 2026-11-08). S1 built (plan 2026-11-09-p10-s1-validate-audit-server), S2 built (plan 2026-11-09-p10-s2-flag-renames); the other slices are not built: each slice gets its own plan and the owner's go-ahead.
- **Implementation:** W5+, one slice at a time. Nothing here is built before approval.
- **Findings:** PRD-3, PRD-4, PRD-7, PRD-8 (MEDIUM) and PRD-5, PRD-6, PRD-11, UX-7 (LOW)
  from the 2026-11-07 whole-repo review.
- **Plan:** package P10 of `docs/superpowers/plans/2026-11-07-review-remediation.md`.
  Each slice below gets its own writing-plans plan.
- **Composes with:** `2026-11-08-revocation-memory-design.md` (P04: tombstones,
  serial, D29 policy conflicts, the D28 exit-code table),
  `2026-11-08-audit-trust-posture-design.md` (P09: granted-only key offering, weak-key
  rules) and `2026-11-08-write-failure-semantics-design.md` (P08: exit 2 for a failed
  undo). This spec adds rows to those tables and does not restate them.
- **Supersedes these earlier deferrals:** `2026-07-10-operator-users-wildcard-access-design.md`
  (no operator scope, no selectors), `2026-07-06-audit-slice-design.md` (no `audit
  --server`), `2026-10-16-review-hardening-design.md` (no bastions) and decision 3 of
  `2026-11-07-revoke-server-keep-old-design.md` (operators refused by `--server`; kept
  for operators, relaxed for protected non-operators by D21a).
- **Code anchors:** master after W4 (`a9c91ff`). The W4 repair pass may still move
  lines, so this spec names functions, not line numbers. P14's layering is enforced
  (`depguard`, `make layering`): `internal/fleet` is a standard-library leaf,
  `internal/workflow` and the domain packages import no transport, and the transport
  packages never import `internal/audit`, `internal/apply`, `internal/adopt` or
  `internal/workflow`.

Wording shown in `code` quotes is target text. It becomes a test expectation. After
implementation the README copies it from the goldens, never from this document.

## Goal and shape

The manifest today can only say "this user, these servers by name, or every server".
Every server must be directly reachable. Every line in a managed file belongs to
SSHepherd. `operator: true` joins two different ideas. There is no offline check, and
some flag names mean different things on different commands.

This spec fixes those as **independent slices**. Each slice can be planned, built,
reviewed and shipped alone, in the order below.

| Slice | What it adds | Decision | Must come after | Schema slice? |
|---|---|---|---|---|
| **S1** | `validate` (with `--json`) and `audit --server` | D25, D25a | W4 | no |
| **S2** | flag renames, no aliases | D26 | P01, P06, P12 | no |
| **S8** | `import --json` and `adopt --json` | owner rule | S2 | no |
| **S3a** | server tags and `@tag` selectors, root-wildcard warning | D20, D20a | S2, W4, P12 | yes |
| **S3b** | user groups | D20b | S3a | yes |
| **S4** | `protected: true` separate from fleet-wide reach | D21, D21a | S3b | yes |
| **S5** | bastions through `via:`, and `jump_only: true` for a bastion SSHepherd must not manage | D23, OP8 | S4, P03, P11, P13, P14 | yes |
| **S6** | co-managed accounts through `preserve:` | D24, D24a | S5, P05, P11 | yes |
| **S7** | optional per-grant restrictions | D22 = B | S3b, P05 | yes |

Schema slices each edit `internal/config/config.go`, the top-level key list in
`internal/manifest/manifest.go` and P12's encoder, so they run **one at a time**. S1
and S8 may run beside schema slices when their files do not overlap. S2 runs before the
schema slices: S3a, S3b and S4 use its `--from-server` name in messages and tests, and
no alias exists to cover the gap. S2 and S8 both edit `cmd/sshepherd/import.go`, so S8
follows S2.

## Findings covered

| ID | Sev | Finding | Slice | Decision |
|---|---|---|---|---|
| PRD-3 | MED | No bastion or `ProxyJump` support; every server is dialed directly | S5 | D23 |
| PRD-4 | MED | Access is flat; YAML anchors, the only reuse tool, make revoke and rotate refuse | S3b | D20b |
| PRD-5 | LOW | `servers: ["*"]` is the only selector and spans every account, root included | S3a | D20, D20a |
| PRD-6 | LOW | Restrictions belong to the key line, so one key cannot be restricted differently per server | S7 | D22 |
| PRD-7 | MED | `operator: true` ties "protected" to "on every server"; the operator grant ignores `except:` | S4 | D21, D21a |
| PRD-8 | MED | Full-file ownership fights cloud guest agents and app-managed accounts | S6 | D24, D24a |
| PRD-11 | LOW | No offline `validate`, no `audit --server`, no `grant` | S1 (`grant` later) | D25, D25a, D25b |
| UX-7 | LOW | `--operator`, `--merge` and `--server` mean different things on different commands | S2 | D26 |

UX-7's minimal fix, the `keeps access to N other servers` line, already landed in W1.

## Owner decisions (final)

Recorded answers from the plan's "Answers recorded" table, then the eight open points
the owner answered on 2026-11-08. They are not reopened here.

| ID | Question | Answer | Slice |
|---|---|---|---|
| **D25** | Add `validate` and `audit --server` now, `grant` later? | **Yes.** | S1 |
| **D25a** | `validate --json` in the first slice? | **B (owner override): `validate --json` from day one.** | S1 |
| **D25b** | `maintenance: true`, a `grant` command and a "what changed since HEAD" view? | **Yes to all three later ideas**, each with its own spec. | none here |
| **D23** | Bastion/`ProxyJump` support with strict host keys on both hops? | **Yes.** | S5 |
| **D24** | A per-server `preserve:` rule that keeps another tool's lines? | **Yes.** It never writes a no-grant server. | S6 |
| **D24a** | Allow matching by key comment? | **Yes, with a README warning.** | S6 |
| **D26** | Rename the confusing flags before the first release? | **Yes, no aliases.** | S2 |
| **D21** | "Protected" separate from "every server"? | **Yes.** | S4 |
| **D21a** | May `revoke --server` trim a protected non-operator? | **Yes, with `--operator`; operators stay refused.** | S4 |
| **D20** | Server tags (`@prod`)? | **Yes.** | S3a |
| **D20a** | Warn when `["*"]` reaches a root account? | **Yes.** | S3a |
| **D20b** | User groups, after tags? | **Yes.** | S3b |
| **D22** | One key with different restrictions on different servers? | **B (owner override after discussion): optional per-grant restrictions; two grants giving one key different restrictions on the same server are refused with an explanation.** | S7 |
| **Owner rule** (2026-11-07) | Every command offers `--json`, including `import`, `adopt` and `validate`. JSON stays schema 1 with additive fields. | **Rule.** | S1, S8 |
| **OP1** | `validate` with no `--known-hosts` and no default file? | **(1): a warning, kind `known_hosts_missing`, which fails `--strict`.** | S1 |
| **OP2** | A tunable bastion cap? | **(1): a constant 8, no flag.** | S5 |
| **OP3** | `--json` on `import` or `adopt` with no `-o`? | **(1): the YAML goes in a `manifest` field.** | S8 |
| **OP4** | `audit --server` and a policy conflict about another server? | **(1): still printed, still exit 2.** | S1 |
| **OP5** | Grant options: add to the key line, or replace it? | **(1): add only, restricting options only; a grant can never widen access.** | S7 |
| **OP6** | Which kind of refusal for a restriction clash? | **(2) (owner override): a D29 policy conflict, kind `restriction_conflict`. Audit is critical and skips the options comparison for that key, apply refuses those servers, validate and the saving commands that would add a clash refuse, revoke and rotate still save.** | S7 |
| **OP7** | One address reached through two bastions, or both directly and through a bastion? | **(2) (owner override): `target` stays host, port and user; a repeat is a load error until a future `host_key_alias:` exists.** | S5 |
| **OP8** | Is a bastion always a normal managed server? | **(2) (owner override): add `jump_only: true`. `*`, `@tag` and the operator implicit grant skip it, `access:` cannot name it, and audit and apply list it as `jump only` without reading or writing it. A bastion without it stays a normal managed server.** | S5 |

## Changes from the plan's sketch

The P10 section of the plan was written before W3 and W4. Reading the current code
forces these corrections. Each is explained in its slice.

1. **No hidden aliases (S2).** The plan's flag table kept old names through
   `MarkDeprecated`. D26 answered "no aliases", so the old names simply stop existing.
2. **The generated-manifest schema is now one encoder.** `manifestOut` is gone. Fields
   flow through `manifest.GenerateWith`/`entryNode` from the config types, guarded by
   `TestSchemaRoundTripAdopt`. But `requiredKeys["Access"]` lists `user` as always
   emitted, which would write a junk `user: ""` on every group entry. The loader
   accepts it (`""` equals absent in a struct decode), but it is wrong output. S3b
   fixes it.
3. **A tombstone is not always a conflict.** W4 made an explicit or wildcard grant over
   an access tombstone a D29 policy conflict. Tag- and group-derived access does not
   conflict, it is blocked. See "How selectors meet tombstones".
4. **`AddMember`/`RemoveMember` are not added.** `make check` runs `deadcode`, and they
   would have no caller until `grant` exists.
5. **Reconcile's `u.Operator` sites mean "fleet-wide", not "protected"** (S4). The
   plan grouped them with the protection sites. They need a different helper.
6. **`SetDeadline` does nothing on a tunnelled connection** (S5). `chanConn.SetDeadline`
   returns "deadline not supported", so only the hop's raw socket enforces the budget.
7. **The bastion cap sits at the fan-out, not in the dialer** (S5), so waiting for a
   slot does not eat the per-server timeout.
8. **Line 1 of a managed file does not change for `preserve:`** (S6). `ParseHeader` is
   a strict anchored match that P04's forged-serial check and `.orig` decision rely on.
   A separate marker line does the job.
9. **D22 became a slice** (S7). The plan listed it as deferred. The owner chose B. The
   sketch replaced the key line's options. S7 adds to them and allows restricting
   options only (OP5).
10. **D26's question named `--merge`.** The plan's per-flag table keeps both names, so
    S2 only clarifies help. The owner sees this at spec approval.
11. **S3b refuses whenever a group grant reaches the pair,** not only when it is the
    sole source, because trimming the direct grant would leave the access.
12. **The S3b refusal names a third way out,** a hand-written access tombstone, because
    the plan's two ways leave no revocation memory.
13. **A restriction clash is a policy conflict, not a load error** (S7, OP6). The plan's
    sketch stopped every command.
14. **`target` does not gain `via`** (S5, OP7). The plan's dedup rule is gone: one address
    is one manifest entry.
15. **`jump_only: true` is new** (S5, OP8). The plan had every bastion under full-file
    management.

## Shared rules

**Adding a manifest field.** A new top-level key goes in `Config`, in `topLevelKeys`
(`internal/manifest/manifest.go`), in `manifest.Draft`/`GenerateWith`, and gets its own
regenerate test (like `TestAdoptRegenerateKeepsRevokedAndSerial`), because `samples`
and `checkRoundTrip` see only `User`, `Server`, `Access` and `Tombstone` and compare
only the first entry of each. A new per-entry field of those types needs the struct
field and a sample; `entryNode` emits it, and `fill` fails until the sample exists.

**Manifest warnings in JSON.** `Config.TombstoneWarnings` becomes
`Config.ManifestWarnings []ManifestWarning` with `Kind`, `Message` and the existing
tombstone fields, which stay omitted for other kinds. `manifest_warnings` in audit,
apply and validate then carries every warning. The tombstone shape stays byte-identical
except for `omitempty` on the tombstone-only fields, and `revoked_index` becomes a
pointer so `0` still prints. `Config.Warnings []string` stays for stderr. The existing
multi-key `comment:` warning gets kind `comment_on_multi_key`; no JSON golden carries
it today (its tests check stderr). The reset of `ManifestWarnings` moves from
`validateRevoked` to `validateUsers`, next to `c.Warnings = nil`, because `validateRevoked`
runs after `validateAccess` and would erase that step's warnings. Consumers must ignore
kinds they do not know; each slice below names the ones it adds.

**Exit codes.** Exit 2 stays "a human must act now on security". The new rows of the
shared D28 table:

| Case | Exit |
|---|---|
| Unknown tag, group or `via`, a second entry for one address, an `access:` entry naming a `jump_only` server, or a bad `preserve:` rule (load error) | 3 on every command |
| Restriction clash (S7, a D29 policy conflict) | `audit` 2; `apply` 1, those servers refused; `validate` 3; a save that would add one 3; `revoke` and `rotate` still save, and their apply phase exits as `apply` does |
| Blocked grant, or a `jump_only` server nothing goes through | 0, with a warning (1 under `validate --strict`) |
| External line kept by `preserve:` | 0 |
| A `jump_only` server, listed as `jump only` | 0; it never changes an exit code |
| Forward refused by a bastion | 1 |
| Changed or `@revoked` host key on a bastion, `jump_only` or not | `audit` 2; `apply`, `revoke`, `rotate` and `adopt` 1 |

**JSON.** Schema stays 1. New fields are optional and omitted when empty, so existing
goldens stay byte-identical. Text that comes from a server passes through
`internal/sanitize`.

P09's load warnings landed after this rule was written. S1 gives them the kinds
`weak_key_ungranted` and `key_expired`, so `report_key_issues.golden.json` gains one
additive `manifest_warnings` entry. That is the only golden that changed.

## How selectors meet tombstones

W4 defined one behavior for a grant over a D1a access tombstone: it is a D29 policy
conflict, so audit marks it critical and apply refuses. That stays true for grants that
name the user directly. Selectors add a second behavior, **blocked**, because their
membership is decided somewhere else (a tag on a server entry, a member list), and one
tag edit must not make apply refuse every server of a grant.

The rule, for a tombstone `{user: U, servers: [S]}`:

| How U reaches S | Result | Why |
|---|---|---|
| `user: U` entry naming S literally | **Policy conflict** (W4, unchanged) | Direct contradiction in one place |
| `user: U` entry with `*`, S not in `except:` | **Policy conflict** (W4, unchanged) | Shipped behavior |
| `user: U` entry reaching S only through `@tag` | **Blocked** | S acts as an implicit `except:` for U |
| `group:` entry, any selector, U a member | **Blocked for U only** | Other members keep the grant |
| Operator's implicit fleet-wide grant | Not affected (no access entry exists) | Unchanged from W4 |
| A D1e-ignored tombstone (S not in `servers:`) | Nothing | Unchanged from W4 |
| S is `jump_only` (S5) | Nothing | `*`, `@tag` and the operator grant skip S and `access:` cannot name it, so no grant exists to block or contradict |

**What "blocked" means.** The grant is dropped for that (user, server) pair during
loading, and the pair is recorded in a new `c.blocked` set. `c.grants`, `DesiredFor`,
`apply.Affected` and every report then see no access. `Covers(U, S)` checks `c.blocked`
first and returns false. It has to, because its `*` scan would otherwise match a group
entry with `servers: ["*"]`. `AccessRevoked(U, S)` still returns the tombstone, so these
keep working with no change: adopt's `ownerSkip`, reconcile's tombstone branch, revoke's
D1c "already revoked" note and audit's D1d drift label. A manifest warning, kind
`tombstone_blocks_grant`, is printed for each (entry, user, server):

- `access[N]: "bob" is not granted "db-1" through @db: revoked[M] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`
- `access[N]: "alice" is not granted "web-1" through group web-team: revoked[M] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`

The warning is skipped when the implicit operator grant still installs the key
(`u.Operator` until S4, `FleetWide(U)` after), because "is not granted" would be false.
A warning never changes an exit code except under `validate --strict`. Save refusals
do not apply: a blocked grant is not a conflict.

**Order of work in `Config.validate`.** Today `validateAccess` runs before
`validateRevoked`, and blocking needs both. `validateAccess` records each grant's
sources; `validateRevoked` stays where it is; a new `blockTombstoned` step then drops
every pair where `AccessRevoked` is true and no source is direct. S7's
`restriction_conflict` check runs in `computeConflicts`, after blocking, so a blocked
grant cannot cause a clash.

`entryServers` gains tag expansion and skips blocked pairs, so `Servers` stays "every
server the entry renders on". `accessConflicts` adds one condition: the entry itself
must reach S directly (by literal name or `*`). Otherwise, with a literal S in entry 1
and an `@tag` covering S in entry 2, S is not blocked and entry 2 would also be named as
granting it.

A tombstone's own `servers:` lists server names only. A selector there is a load error,
as `*` already is, because the operator would believe the user is blocked when nothing
is: `revoked[N]: servers cannot hold a selector; list the servers by name`. Any other
unknown name stays a D1e warning. A tombstone naming a `jump_only` server still loads
and has no effect while the flag is set. If the flag is removed, it applies again.

---

## S1. `validate` and `audit --server` (D25, D25a; PRD-11)

### `sshepherd validate`

Offline. Never dials. Flags: `--config FILE`, `--known-hosts FILE`, `--strict`,
`--json`.

Steps, in order:

1. Read the manifest through `readManifest` (`/dev/stdin` and a pipe work). A file that
   cannot be read is a tool error: exit 3, stderr, no document.
2. `config.Parse`. Errors are the same as every command's, reported and exit 3.
3. Print `Config.Warnings` through `logManifest`.
4. `manifest.Load` on the same bytes. An `*UnsupportedError` becomes a warning, kind
   `manifest_not_editable`: `revoke, rotate and --merge cannot edit this manifest: REASON`.
5. Known hosts. With an explicit `--known-hosts`, a missing or bad file is exit 3. With
   the default path, a missing file is a warning, kind `known_hosts_missing`, so CI with
   no known_hosts fails under `--strict` (OP1):
   `no known_hosts at ~/.ssh/known_hosts; host keys were not checked`. When a file loads,
   each server with no recorded key is a warning, kind `host_key_not_recorded`:
   `server "web-1": no host key recorded for 10.0.1.5:22 in ~/.ssh/known_hosts`.
   `KnownHosts.HostKeyAlgorithms(addr)` returning nil means not recorded; a host matched
   only by `@cert-authority` counts as recorded.
6. Policy conflicts (`Conflicts()`, D29) are findings: exit 3, as P04 requires.
7. Print the summary on stdout:
   `manifest OK: 3 users, 12 servers, 40 grants (2 warnings)`. A grant is one
   (user, server) pair the render would write, operators included. A new
   `Config.GrantCount()` counts it.

| Exit | Meaning |
|---|---|
| 0 | Valid. Warnings may be present |
| 1 | Valid, with warnings, under `--strict` |
| 3 | Invalid, a policy conflict, or a tool error |

**Text for a conflict:** `manifest has 1 policy conflict: MESSAGE`, on stderr. The
save-refusal wording in `conflictRefusal` talks about writing, so validate has its own.

**`--json`** writes one schema-1 document on stdout. Per P04, a load error or conflict
is validate's finding, not a tool failure, so the document is written on those exit 3s
too. Only an unreadable manifest, a bad flag or a bad explicit `--known-hosts` writes no
document.

An invalid manifest:

```json
{
  "schema": 1,
  "valid": false,
  "summary": {"users": 0, "servers": 0, "grants": 0, "warnings": 0, "exit_code": 3},
  "host_keys_checked": false,
  "errors": ["access for \"alice\": unknown server \"web-9\""]
}
```

A valid manifest with one warning:

```json
{
  "schema": 1,
  "valid": true,
  "summary": {"users": 3, "servers": 12, "grants": 40, "warnings": 1, "exit_code": 0},
  "host_keys_checked": true,
  "errors": [],
  "manifest_warnings": [{"kind": "host_key_not_recorded", "server": "web-1", "message": "server \"web-1\": no host key recorded for 10.0.1.5:22 in ~/.ssh/known_hosts"}]
}
```

- `valid` is false on a load error or a policy conflict. A run that fails only under
  `--strict` has `valid: true` and exit 1.
- `errors` is always present. It lists each validation error, split from the
  `errors.Join` that `config.Parse` returns; a parse failure gives one entry.
- `policy_conflicts` and `manifest_warnings` follow audit's shapes and are omitted when
  empty.
- `summary` is always present, with `exit_code` where audit has it. Its counts are 0
  when the manifest did not parse, and `warnings` is the length of `manifest_warnings`.
- `host_keys_checked` is false when no known_hosts file was loaded, which includes every
  parse failure.

### `audit --server NAME`

Repeatable. Reuses `selectServers` (moved from `cmd/sshepherd/apply.go` to
`cmd/sshepherd/fleet.go`, so it can be shared) and `audit.Options.Servers`.
`readFleet` gains a `targets` argument; adopt passes the whole fleet. An unknown name
exits 3 with the existing message. The report ends with the existing wording
`(N servers skipped by --server)`.

JSON gains `summary.skipped` (additive, omitted when 0, so existing goldens hold). Audit
reads only the selected servers, but policy conflicts are about the manifest, so they
are still printed and still exit 2 (OP4).

**Tombstones.** `validate` reports them through the conflict and warning paths above;
it adds no new rule. `audit --server` does not change any tombstone rule.

**Files.** `cmd/sshepherd/validate.go` (new), `validate_test.go` (new), `run.go`
(`AddCommand`, `exitCodesValidate`), `fleet.go`, `audit.go`, `apply.go` (move),
`adopt.go` (the `readFleet` call), `internal/audit/json.go` and `internal/apply/json.go` (the `ManifestWarning` rename) with
their JSON tests, `internal/config` (`GrantCount`, `ManifestWarning`).

**README.** Command list under **Commands**; new **`sshepherd validate`** section,
including that validate writes a document on some exit 3s while `import` and `adopt`
almost never do; **CI recipes** (a GitOps PR check, which needs a known_hosts file to run
`--strict`); **`sshepherd audit`** flag table
and JSON; **Exit codes**.

**Tests.** `validate_test.go`: valid, invalid, warnings, `--strict`, anchors warning,
known_hosts gap, missing default known_hosts (a warning, exit 1 under `--strict`), bad
explicit known_hosts, conflict exit 3, JSON on each exit (`valid: true` with exit 1 under
`--strict`; `comment_on_multi_key` in `manifest_warnings`), piped manifest. `audit_test.go`: subset, unknown name, skipped count
in text and JSON, a conflict outside the subset still exits 2. Help goldens and the
README flag-table test. A hermetic test proves `validate` opens no socket.

---

## S2. Flag renames (D26; UX-7)

No release has shipped, so there are no aliases and no deprecation notices. The old
names become unknown flags. D26's "yes" covers `--merge` too, but the plan's table
keeps both names: `--merge` is fixed by help text only.

| Today | After | Mechanism |
|---|---|---|
| `import --operator PATH` | **`import --operator-key PATH`** | Flag, its usage text, the `--operator conflicts with --servers-only` error, the `(--operator)` description in generated manifests, and the reconcile message |
| `revoke --server NAME` | **`revoke --from-server NAME`** | Flag, `Use` line, `Long`, examples, every `revokeUsage` string and the `accessProblems` hint. `apply --server` and `audit --server` keep their name and meaning (they restrict the run) |
| `--identity-passphrase KEY=FILE` | Varname becomes **`PATH=FILE`** | The help varname, and the two runtime strings that quote it: `internal/keyfile/keyfile.go` (`use … --identity-passphrase PATH=FILE`) and `internal/keyfile/resolve.go` (`want PATH=FILE`), with their tests. `TestHelpShowsIdentityVarnames` and the README tables change |
| `adopt --merge` / `import --merge FILE` | **Keep both** names; clarify the help text | adopt: `merge into --config: preserve its text and append what is new`. import: `merge into FILE: preserve its text and append what is new` |
| `revoke/rotate --operator` (bool) | Keep. S4 rewords the help | Help text only |

Follow-up hints built by `followUp.command` are checked for the renamed flags.
`revoke`'s apply-phase `--server` hint (`editrun.go`) keeps its name: it is `apply`'s
flag. The W1 line `keeps access to N other servers` stays.

**Tombstones.** None. Messages that name the old flag change wording only.

**Files.** `cmd/sshepherd/{import,adopt,revoke,identity,editrun}.go`,
`internal/keyfile/{keyfile,resolve}.go`, `internal/reconcile` (message),
`internal/apply/edit.go` (comment), `testdata/help/*.golden`.
`editrun.go` and the `accessProblems` hint needed no change: `applyHint` builds `apply`'s
`--server`, and the hint builds `--operator`. The same section's lanes run in two rounds,
because `adopt.golden` and `revoke.golden` carry both a renamed flag and the `PATH=FILE`
varname.

**README.** Every touched flag table in **`sshepherd import`**, **`sshepherd adopt`**,
**`sshepherd audit`**, **`sshepherd apply`**, **`sshepherd revoke`**, **`sshepherd
rotate`** and **Authentication**, plus samples copied from the changed goldens.

**Tests.** The old flag fails with cobra's unknown-flag error. Help goldens. README flag
tables. `import --operator-key` conflict message. The `PATH=FILE` runtime strings
(`internal/keyfile`, `cmd/sshepherd/identity_test.go`).

---

## S8. `import --json` and `adopt --json` (owner rule)

Their normal output is the YAML manifest, so JSON is a **discovery and warnings
report**. Stdout is one document. The manifest goes where `-o` says, or into the
document's `manifest` field when there is no `-o` (OP3). Logs stay on stderr.

| Exit | `adopt --json` |
|---|---|
| 0 | Document, `emitted: true` |
| 1 | Document. `emitted` is true for `--partial` and false when unreadable servers stopped the run |
| 3 | No document, message on stderr. One exception: `--partial` with zero servers read writes a document with `"emitted": false`, because that is when a script most needs to see why |

| Exit | `import --json` |
|---|---|
| 0 | Document |
| 3 | No document, message on stderr |

`import` never exits 1 (`exitCodesImport`).

```json
{
  "schema": 1,
  "command": "adopt",
  "mode": "merge",
  "emitted": true,
  "output": {"path": "fleet.yaml", "written": true},
  "summary": {"servers": 12, "read": 11, "partly_read": 1, "new_users": 2, "extensions": 1, "warnings": 3, "exit_code": 1},
  "new_users": [{"name": "u-laptop", "fingerprint": "SHA256:…", "type": "ssh-ed25519", "found_on": ["web-1"]}],
  "extensions": [{"user": "bob", "servers": ["db-1"]}],
  "unreadable": [{"server": "db-3", "error_kind": "dial", "detail": "…", "hint": "…"}],
  "warnings": [{"kind": "revoked_key_skipped", "server": "web-2", "fingerprint": "SHA256:…", "user": "alice", "date": "2026-11-08", "message": "…"}]
}
```

`import` has `mode` (`generate` or `merge`), `summary` (`hosts`, `users`, `grants`,
`conflicts`, `warnings`, `exit_code`), `new_servers`, `new_users`, `extensions`,
`warnings`, the same `output`/`manifest` choice, and `notes`: a list of plain strings
from `reconcile.Plan.Notes`, not counted in `summary.warnings`, because they report
steady state and stderr logs them at info level.

With no `-o`, the document has `manifest` (the YAML) and no `output`, so
`… --json | jq -r .manifest` gives the same bytes a non-JSON run prints. A document with
`"emitted": false` has neither.

**Warning kinds** (`message` is the stderr text, unchanged). Consumers must ignore
kinds they do not know.

- adopt: `revoked_key_skipped`, `revoked_access_skipped` (shapes from P04),
  `except_skipped`, `key_differs`, `comment_dropped`.
- import: `revoked_pub_skipped`, `revoked_access_skipped` (shapes from P04),
  `ssh_config`, `identity`, `unsafe_host`, `collapsed_target`, `proxy_not_mapped`,
  `merge_conflict`.

**Mechanics.** `adopt.Plan.Warnings` and `reconcile.Plan.Warnings` become structured
(`Warning{Kind, Server, Fingerprint, User, Date, Message}`); stderr still prints
`Message`, so text output and goldens do not change. Import's other warnings log
directly or return strings today: `sshcfg.Load`, `resolveUsers`, `CollapseTargets`,
`warnProxies` and the host filter. Those functions return their warnings to one
collector in `import_json.go`, which assigns the kinds; the non-JSON path prints them
exactly as today. `--json` adds no behavior: the manifest bytes match a non-JSON run
exactly. Adopt's renderer is `internal/adopt/json.go`, which imports no CLI framework;
import's is `cmd/sshepherd/import_json.go`, because import's run lives in cmd.

**Tombstones.** Skips are reported through the P04 warning kinds. No rule changes.

**Files.** `internal/adopt/{adopt,json}.go`, `internal/reconcile/reconcile.go`,
`internal/sshcfg`, `cmd/sshepherd/{adopt,import,import_json}.go`.

**README.** **`sshepherd import`** and **`sshepherd adopt`** flag tables and a JSON
sample each; **Exit codes** note on when a document is written. `sshepherd validate`
gains the sentence that `import` and `adopt` write a document on almost no exit 3.

**Tests.** Goldens for each document, including the exit-1 strict abort and the
zero-read exit 3. The manifest bytes under `--json` match the non-JSON run, with and
without `-o`. `manifest` is present only without `-o`, and `output` only with it. Each
P04 skip kind appears with its fields. Each import warning kind comes
from the collector. `unreadable[]` carries `error_kind`. A hostile remote comment is
sanitized. Any other exit 3 writes no document.

---

## S3a. Server tags and `@tag` selectors (D20, D20a; PRD-5)

```yaml
servers:
  - name: web-1
    host: 10.0.1.5
    user: deploy
    tags: [prod, web]
access:
  - user: carol
    servers: ["@prod", db-1]   # selectors and names mix (union)
    except: [web-3]            # valid with "*" or any "@tag"
```

**Go shape.** `Server.Tags []string` (`yaml:"tags"`).

**Validation** (load errors, exit 3):

- A tag matches `^[a-z0-9][a-z0-9._-]{0,62}$`. A tag repeated on one server is an error.
- A server name starting with `@` is reserved, like `*`:
  `servers[N]: name "@x" is reserved for tag selectors`. A new `config.ServerNameIssue`
  is exported so `import` skips such an alias with a warning instead of generating a
  manifest that fails to load.
- An `@tag` matching no server is an error, like an unknown server name:
  `access for "carol": unknown tag "@prd"`.
- `*` must still be the only entry in `servers:`.
- `except:` needs `*` or at least one `@tag`. Without one:
  `access for "x": except requires servers ["*"] or an @tag`.
- Each `except:` name must be a known server. `@tag` is not allowed in `except:`.
- A name in both `servers:` and `except:` is an error (typo guard).
- An entry that grants nothing after `except:` is an error, the existing wildcard rule.

**Semantics.** Expansion stays inside `expandServers`, so `c.grants` and `DesiredFor`
do not change shape. `@tag` expands to every server carrying the tag, in manifest
order. Mixed lists union. `except:` removes from the selector-derived part.

**Raw-entry scanners move to one helper.** `Covers`, `ExceptCarveOut` and
`accessConflicts` read raw `Access` entries by `a.User`. They move to shared
`entryApplies(a, user)` and `entryCovers(a, server)`:

- A `@tag` never covers a server that is not in the manifest yet (it has no tags), so
  reconcile stays conservative. Only `*` covers future servers.
- `ExceptCarveOut` becomes true for any selector entry, not just `*`.

**Manifest editor.** `RemoveAccess` on a selector entry: remove a literal item when it
names the server, and append to `except:` when a selector still covers it. The entry
is deleted when no literal is left and every selector-covered server is excepted (the
existing wildcard rule). `revoke --from-server '@prod'` is refused:
`--from-server takes server names`. The `accessTombstones` logic is unchanged: a server
that gained an `except:` gets no tombstone, and when a later trim deletes the entry,
`forgottenCarveOut` tombstones its earlier `except:` names, because `ExceptCarveOut` now
answers for selector entries.

**Root warning (D20a).** A non-operator `servers: ["*"]` entry reaching a server with
`user: root` warns once per entry, kind `wildcard_root`:
`access for "alice": servers ["*"] includes the root account on web-1 and 3 more; list the servers or use an @tag that excludes root accounts`.
An `@tag` reaching root does not warn: D20a is about `*`.

**Tombstones.** A D1a tombstone blocks `@tag`-derived access, as an implicit `except:`
for that user (the rule above). A server named literally in the same entry stays a W4
conflict. A selector inside a tombstone's own `servers:` is a load error.

**Files.** `internal/config/{config,revoked}.go`, `internal/manifest/edit.go`,
`cmd/sshepherd/{revoke,import}.go`, `internal/reconcile` (through `Covers`).

**README.** **The manifest**: new "Tags and selectors" subsection; **Wildcard access**
(root warning); **Validation rules**; **`sshepherd revoke`** (trim on `@tag`);
**Revoked keys** (the blocked rule); **Exit codes**.

**Tests.**

- Unit: every validation row, valid and invalid.
- Equivalence property test: for each fixture, the tagged manifest and its hand-flattened
  twin give identical `DesiredFor` per server and identical `apply.Affected`.
- Tombstones: `@tag` grant over a tombstone is blocked with the warning; a literal in
  the same entry is still a conflict; a literal and an `@tag` in two entries names only
  the literal entry in the conflict; `Covers` false, `AccessRevoked` true; D1c note;
  adopt and reconcile do not re-extend; audit shows D1d drift when the key is installed;
  no warning for an operator's blocked pair; `@tag` in a tombstone's `servers:` is a load
  error.
- Manifest edit goldens: trim on `@tag`, mixed list, entry deleted when nothing is left,
  and two trims that delete the entry leave tombstones for both servers.
- `Covers` on a future server: `*` yes, `@tag` no.
- Fuzz seeds with `tags:` and `@tag` in the config and manifest corpora.
- Round-trip sample for `Tags`.

---

## S3b. User groups (D20b; PRD-4)

```yaml
groups:
  - name: web-team
    description: docs only
    members: [alice, bob]
access:
  - group: web-team      # exactly one of user: / group:
    servers: ["@web"]
```

**Go shape.** `type Group struct{ Name, Description string; Members []string }`,
`Config.Groups []Group` (`yaml:"groups"`), `Access.Group string` (`yaml:"group"`).
`groups:` is emitted after `users:`, and only when non-empty.

**Validation** (load errors unless noted):

- Exactly one of `user:` or `group:` per access entry. Unknown group is an error.
- Group names match the tag pattern and are unique.
- Every member is a known user. A repeated member is an error.
- An empty group is **valid, with a warning**, kind `empty_group`: `group "web-team" has no members; its grants add nothing`. So revoking the last member never breaks the manifest.

**Error text.** `validateAccess` and `expandServers` format every error with `a.User`,
so a group entry would print `access for ""`. An entry-label helper prints `"x"` for a
user entry, unchanged, and `group "web-team"` for a group entry: `access for group
"web-team": unknown server "web-9"`. An unknown group is `access: unknown group "x"`.

**Encoder.** `requiredKeys["Access"]` drops `user`, so a group entry is not written with
a junk `user: ""`. `servers` stays required, and the loader enforces "exactly one of".
`requiredKeys["Group"]` is `name` and `members`, so an empty group writes `members: []`.
`GenerateWith` omits `groups:` when empty, like `revoked:`; the other three sections
always emit, so existing goldens stay byte-identical.

**Semantics.** `validateAccess` expands a group entry to one grant per member, in member
order, then access order. Equivalent to the flattened manifest. Operator members are
already emitted; the existing "redundant grant" skip applies.

A group entry with `servers: ["*"]` reaching a `user: root` server warns once per entry,
kind `wildcard_root`:
`access for group "web-team": servers ["*"] includes the root account on web-1 and 3 more; list the servers or use an @tag that excludes root accounts`.

**Group access is not a personal grant.** `entryApplies(a, user)` is true when `a.User`
is the user or `a.Group` contains the user. `Covers` and `ExceptCarveOut` use it. A
group entry carries an `except:` for every member. `cmd/sshepherd` cannot call an
unexported helper, so `Config` exports `HasAccessEntry(user)` and
`GroupGrantsReaching(user, server) []string`.

**Editor.**

- `checkTopLevelKeys` accepts `groups`.
- `RemoveUser` also drops the name from every `groups[].members` and reports it in
  `UserRemoval.Groups`. A group left empty keeps its entry and gets the warning.
- `revoke USER --from-server S` is **refused** when any group grant reaches (USER, S),
  whether or not a direct grant also exists, because trimming the direct one would leave
  the access in place. `GroupGrantsReaching` ignores blocked pairs, so a blocked member
  gets the D1c note instead:
  `alice's access to web-1 comes from group web-team; remove the user from the group, trim the group's grant, or add revoked: [{user: alice, servers: [web-1], date: 2026-11-08}] to block only this member`
  (exit 3, nothing saved). The date printed is the run's date.
- `NoGrantsLeft` in `planRevokeAccess` scans `a.User` today. It moves to
  `HasAccessEntry`, so a user with group access is not told they have none left.
- `adopt` regenerate carries `Groups` through `Draft`. `adopt` and `import` never
  create groups.

**Tombstones.** A D1a tombstone blocks group-derived access **for that member only**.
Other members keep the grant. A key tombstone behaves as today: `serversRendering`
reads `c.grants`, so it covers group grants.

**Files.** `internal/config/{config,revoked}.go`, `internal/manifest/{manifest,edit}.go`,
`cmd/sshepherd/{adopt,revoke}.go`, `cmd/sshepherd/schema_roundtrip_test.go`.

**README.** **The manifest**: new "Groups" subsection; **Validation rules**;
**`sshepherd revoke`** (group refusal, removal from groups); **Revoked keys** (blocked for
one member); **Exit codes**.

**Tests.**

- Unit: every validation row, including the exactly-one-of rule, and the group wording of
  each message.
- Equivalence property test against the flattened twin.
- Tombstones: blocked for one member, others unaffected, with a group `servers: ["*"]`
  entry over a tombstone: `Covers` false, D1c note, `KeepsServers` not inflated; adopt and
  reconcile as in S3a.
- `wildcard_root` for a group `*` entry reaching a root server.
- Manifest edit goldens: remove a member; the refused trim; removing the last member.
- Round-trip: a group entry regenerates without `user:` (the `requiredKeys` fix). The
  `Group` sample in `samples["Access"]` is `""` with a comment: `fill` sets every field,
  and a user plus a group would fail exactly-one-of. `TestSchemaRoundTripAppend` cannot
  carry a group either, because `Append` has no groups parameter. A separate regenerate
  test asserts that `cfg.Groups` and a group entry survive `generateAdoptManifest`.
- E2E: one group grant through adopt → apply → revoke → audit.

---

## S4. `protected: true` (D21, D21a; PRD-7)

```yaml
users:
  - name: ci
    protected: true      # CRITICAL when missing, --operator to touch, written first
    keys: [...]
  - name: backup-root
    operator: true       # protected, plus every server
    keys: [...]
access:
  - user: backup-root
    servers: ["*"]       # replaces the implicit grant, so except: works
    except: [legacy-1]
```

**Semantics.**

- `protected: true` gives critical-when-missing, the `--operator` acknowledgement and
  written-first order, **only where the user's access entries grant it**. No key
  requirement: a protected user with no keys has nothing to protect.
- `operator: true` is protected plus an implicit `servers: ["*"]`.
- If an operator has its own `servers: ["*"]` entry (a `user:` entry, not a group), that
  entry and its `except:` replace the implicit grant. That one rule makes `except:` work
  for operators. Manifests without such an entry render byte-identically; a golden proves
  it.
- An operator with an `@tag` or literal entry stays fleet-wide. To limit scope, drop
  `operator: true` and use `protected: true`. A warning, kind `operator_grant_redundant`,
  says so: `operator "x": this access entry adds nothing; operator: true still grants every server`.

**Two helpers, not one.** The plan grouped every `u.Operator` site under "protected",
but they mean two things:

- `User.IsProtected()` is `Operator || Protected`. It replaces `u.Operator` in the
  audit critical tier and report (`criticalDrift`, the missing-key row,
  `audit/json.go`), `apply/json.go`, `operatorGate`, `apply/edit.go` and `planRotate`'s
  finish hint.
- `Config.FleetWide(user)` is "operator with no own wildcard entry". It replaces
  `u.Operator` in `DesiredFor`, `serversRendering` and reconcile's coverage branches.
  A scoped operator then goes through normal coverage, including `ExceptCarveOut`.

`DesiredFor` emits protected-and-granted keys first, in users order, then the rest in
access order. The `Covers` comment is updated.

**JSON and reports.** `protected: true` is additive next to `operator`, schema 1. The
missing-key row reads `(CRITICAL: protected key)` for a protected non-operator and
stays `(CRITICAL: operator key)` for an operator.

**`revoke --from-server` (D21a).** `revokeUsage`'s blanket "`--operator` cannot be
combined" goes. `planRevokeAccess` gains the `operator` argument and calls `operatorGate`
on the non-operator targets. A protected non-operator needs `--operator`. An operator
stays refused:
`x is an operator: --from-server cannot trim it; remove the user with 'revoke x --operator', or edit its access by hand`.
`--operator` with no protected target is refused, as today.

**Wording.** Today's text, `is an operator (fleet-wide, protected)`, is false for a
protected non-operator and for a scoped operator. `operatorGate` and `apply/edit.go`'s
header keep it, byte-identical, only for a fleet-wide operator. Anyone else prints `x is
protected; pass --operator to confirm` and `PROTECTED: x is protected; --operator
given`. A list mixing the two uses the second form. The edit summary carries which is
which.

**Lockout.** An `except:` can take the management key off a server. The guard refuses
any write that leaves this run no held key, but it sees only this run's keys, so a human
run could remove CI's protected key with no refusal. The plan therefore warns when an
`except:` removes a protected key from a server:
`removes protected key of "ci" (its except: excludes this server)`. `lockoutRefusal`'s
hint `or mark its user operator: true` becomes `or grant its user this server`, because
the flag does nothing for an excepted operator. Today's `DesiredFor` ignores an
operator's own `except:`, so a manifest that has one narrows when S4 lands; the README
says so.

**Tombstones.** A protected non-operator trim follows the normal rules: a literal gets
a tombstone, a selector gets `except:`. An operator's own `*` entry is a direct grant, so
a tombstone over it is a W4 conflict. The implicit grant is never blocked; it has no
entry and operators cannot be trimmed by the tool.

**Files.** `internal/config` (`IsProtected`, `FleetWide`, `DesiredFor`, field),
`internal/audit/{report,json}.go`, `internal/apply/{json,edit,plan}.go`,
`internal/reconcile/reconcile.go`, `cmd/sshepherd/{editrun,revoke,rotate}.go`.

**README.** **Operator users** (split into operator and protected, with the note that an
operator's own `except:` now takes effect); **`sshepherd revoke`**, **`sshepherd
rotate`** (`--operator` wording); **Exit codes** row 2 ("missing operator or protected
key"); **`sshepherd audit`** JSON.

**Tests.** Config: operator with and without own wildcard, with `except:`, protected
with explicit grant. Unchanged-render golden for today's operator manifests. Audit
critical goldens for a protected non-operator; missing where it is not granted is not
critical. JSON additive golden. `operatorGate` and `revokeUsage` tables: protected with
and without `--operator`, operator refused. The fleet-wide and protected wording goldens,
in the gate and the edit header. Plan golden: an `except:` removing a protected key warns.
`lockoutRefusal` golden. A render golden for an operator with its own `*` and `except:`.
Reconcile: a scoped operator's excepted server is not silently absorbed. Round-trip
sample.

---

## S5. Bastions through `via:` (D23; PRD-3)

```yaml
servers:
  - name: bastion-eu
    host: bastion.example.com
    user: jump
    jump_only: true      # optional: tunnel through it, never manage it
  - name: web-1
    host: 10.0.1.5
    user: deploy
    via: bastion-eu
```

**A bastion without `jump_only` is a normal managed server.** Its own `authorized_keys`
is audited and applied, so bastion access is access, and audit stays complete. That has
a cost the README must state: apply rewrites the bastion's whole file like any other
server's, a `servers: ["*"]` entry or an operator's implicit grant puts those users on
it, and a bastion that no grant reaches stays refused (exit 1) while its file holds keys.

**`jump_only: true` (OP8)** makes a server a tunnel and nothing else. It exists because a
shared jump account's file holds other people's keys, and because a `nologin` or
`ForceCommand` jump account can never be read, so audit could never reach exit 0. The
Go shape is `Server.JumpOnly bool` (`yaml:"jump_only"`).

- **No grant reaches it.** `*`, `@tag` and the operator implicit grant skip it:
  `expandServers`, `entryServers`, `entryCovers`, `DesiredFor` and `serversRendering`
  leave it out, and `Covers` is false for it. So it renders no keys, `GrantCount` does
  not count it and `wildcard_root` does not name it. `validate`'s server count includes
  it. `RemoveAccess`'s fleet list leaves it out, so a `*` entry left covering only
  `jump_only` servers is deleted.
- **`access:` cannot name it,** in `servers:` or in `except:`.
- **`audit` and `apply` list it as `jump only`.** `audit.Run` adds the row without taking
  a fan-out slot or connecting, and `apply`'s plan gets a new `ClassJumpOnly`. Neither
  reads or writes its file. It is never drift, critical or unreachable, and it never
  changes an exit code. The no-grant refusal, the forwarding guard, the forward probe and
  the write levels below do not apply to it.
- **Other commands.** `adopt` does not read it: it is not part of `read X of N` and is
  never `unreadable`. `revoke` and `rotate` never affect it, because its render is
  empty. `--sweep` does not read it and prints `not swept: bastion-eu (jump only)`. That
  line does not change the exit code; otherwise every sweep would exit 1.
- **Its host key is still verified strictly when tunneling.** The hop connection uses the
  same `known_hosts` callback as any other connection. An unrecorded, changed or
  `@revoked` key stops the tunnel, and the host-key exit codes below apply. `validate`
  still warns `host_key_not_recorded` for it. A run that selects no server behind it
  opens no connection to it, so that run checks nothing about it.
- **Manifest tooling.** `adopt` regenerate carries the flag through the encoder. `import`
  never sets it: an imported hop is a normal server until the operator adds the flag.
  `import --merge` adds no grant on a `jump_only` server and notes it:
  `server "bastion-eu" is jump_only in the manifest; no access added`. Reconcile's fleet
  set leaves it out, so a grant on every other server can still become `*`.

A `jump_only` server that no server's `via` names warns, kind `jump_only_unused`:
`server "bastion-eu": jump_only but no server has via: bastion-eu; nothing connects through it and nothing checks it`.

**Validation** (load errors):

- `via` names a known server, not itself. No cycles. Chain depth at most 3.
- **One address, one entry (OP7).** `target` does not change (host, port, user and file
  path) and does not include `via`. A second entry for one target is the existing load
  error, whether it is direct or behind any bastion. `known_hosts` is keyed by address, so two machines at one address
  could not be told apart, and recording both keys would let either key match either
  machine. An entry declared direct and another through a bastion could also name one
  real file: a tombstone on one name would not bind the other, and the two renders would
  fight. A future `host_key_alias:` lifts this rule. When the two entries differ in
  `via`, the message says so instead of `merge them into one entry`:
  `servers "a" and "b" both target deploy@10.0.0.5:22 ~/.ssh/authorized_keys through different hops; a manifest holds one entry per address, so remove one`.
- **One address, one route (OP7).** Two entries at the same `host:port` must have the same
  `via`, even when their user or file path differs, because `known_hosts` is keyed by
  address: `servers "a" and "b" reach 10.0.0.5:22 through different hops; every entry at one address must use the same route; if these are different machines, give each a hostname its own hop can resolve`.
  Different users or files at one address over the same route stay valid, as today.

**Known limitation (owner, 2026-11-08; keep it visible in the README's `via:` section).** Two different machines that
share a private address behind different hops, such as `10.0.0.5` in two networks, cannot both be
in one manifest by address. The workaround is a distinct hostname for each that its own hop
resolves. The refusal is safe and can be loosened later: the planned lift is an optional per-server
`host_key_alias:` (OpenSSH's `HostKeyAlias`), not built here because the owner's fleet has no
overlap today.
- An `access:` entry naming a `jump_only` server, in `servers:` or `except:`:
  `access for "alice": server "bastion-eu" is jump_only; access cannot name it`.
- A tag only `jump_only` servers carry grants nothing, so it fails like an unknown tag:
  `access for "alice": "@edge" matches only jump_only servers`.
- `jump_only` with `authorized_keys_file`, because there is no managed file:
  `server "bastion-eu": jump_only has no managed file; remove authorized_keys_file`.

**Transport.** All in `ConnectWith`, the one choke point for read, write and probe.
`sshconn` already imports `internal/config`. The dial step becomes
`dialTarget(ctx, srv, addr) (net.Conn, *Conn, error)`, which returns the hop too:

- No `via`: today's `net.Dialer`, and a nil hop.
- `via`: connect to the hop with `ConnectWith(ctx, hopSrv, ConnectOptions{})`, then
  `hop.Client.DialContext(ctx, "tcp", addr)`. The hop never inherits `Only` or `Prefer`.
  `sshconn.Dialer` and `sshread.Client` gain `Server func(string) (config.Server, bool)`,
  set from the validated config.
- A server with `via` on a `Dialer` with no `Server` lookup fails closed: the connect
  returns an error and never dials directly. The CLI always sets the lookup.
- `Conn` gains `hop *Conn`. `Close` closes the target, then always closes the hop, even
  when `Client` is nil. Every failure exit in `ConnectWith` after `dialTarget` closes the
  hop, and `goleak` proves it.

The hop offers keys under D17: those granted on the bastion plus operator keys, falling
back to all loaded keys with a warning. Until P09-impl lands it uses today's order
through `Dialer.PreferKeys(hopSrv)`: granted keys first, then every other held key. A
`jump_only` hop has no grants to filter by, so before and after P09-impl it is offered
every held key in today's order, with no warning, and D17b's preflight does not count it.

Four facts about the tunnel, confirmed in x/crypto v0.58.0:

1. **Deadlines.** `chanConn.SetDeadline` returns "deadline not supported", and the
   existing `_ = conn.SetDeadline(dl)` ignores it. Only the hop's raw socket enforces
   the budget. The hop is dialed with the same `ctx`, so its socket carries the same
   deadline. This is why there is **one hop connection per target**, no pooling: a shared
   hop would inherit one target's deadline.
2. **Host keys.** `knownhosts` prefers the hostname argument over the peer address, so
   the inner hop is verified as `srv.Host:port`, as OpenSSH does, despite the tunnel's
   zero address. Host keys are looked up by address, which is why the manifest allows
   one entry per address (see Validation). A `host_key_alias:` field is later work.
3. **DNS** for the target is resolved by the bastion.
4. **Cancellation.** `channel.Close` only sends a close message, and a blocked read waits
   for the peer's reply, so closing the tunnel alone does not stop a wedged handshake.
   The `AfterFunc` installed for the dial closes both the tunnel and the hop, and stops
   when the handshake ends, as it does today. After the handshake a tunnelled connection
   behaves like a direct one: cancellation closes the session, and a wedged peer is
   bounded by the socket deadline. The hop must not stay tied to the connect `ctx` past
   that point, because `connectForWrite` releases that `ctx` as soon as the connect
   returns.

**Concurrency cap.** At most 8 connections through one bastion, below sshd's default
`MaxStartups 10:30:100`. It is a constant with no flag (OP2).
The cap sits at the **fan-out**, not in the dialer: a
new `fleet.HopLimiter` (standard library only, per P14; it takes `[]string`) is acquired
in `audit.Run` and `apply.Execute` **before** the per-server budget starts, so waiting
for a slot cannot use up a server's timeout. It is taken before the `--parallel` slot,
so a queue behind one bastion does not idle the pool for other servers. Acquiring
selects on `ctx.Done()`. The sweep reuses `audit.Run`.

`ExecOptions` gains `Chain func(config.Server) []string`, backed by a `Config.Chain`
method over the whole fleet; `audit.Run` calls that method directly. Plans hold only some
servers, so slots and levels are computed from it, not from `ServerPlan.Server.Via`. A
chain acquires its slots root-first, always in the same order, so it cannot deadlock.
A read takes one slot per bastion in its chain. A write takes **two**, atomically,
because the login probe opens a second hop connection while the write's stays open. The
slots are held until the server's work is done.

**Apply write order.** `apply.Execute` runs in levels: servers that are nobody's `via`
first, then their bastions, deepest last. For A via B via C with B converged, C still
writes after A. A level finishes before the next starts. Bad bastion writes then cannot
strand pending target writes. With no `via:` there is one level and behavior is
unchanged. A `jump_only` bastion is in no level, because it is never written.

**Guard.** A managed bastion must keep forwarding, not only logins. For a server that is
another server's `via` and is not `jump_only`, at least one surviving held key must allow forwarding: its line has no
`no-port-forwarding`, no `restrict` without `port-forwarding`, and any `permitopen=`
clauses cover every dependent's `host:port`. Otherwise the plan is refused:
`none of the surviving keys you hold may forward through bastion-eu (no-port-forwarding, restrict or permitopen=); this write would cut off web-1 and 3 more`.
The post-write probe on a bastion also opens `direct-tcpip` to one dependent and closes
it at once (`fleet.WriteRequest.ProbeForward`). Only an `ssh.Prohibited` rejection fails
the probe and restores the file. A connection failure to the dependent is the
dependent's problem and does not.

**Errors.** One unreachable bastion makes each dependent `unreachable`, with the root
cause `via bastion-eu: …`. The error keeps its `fleet.ErrorKind`. `sshconn.Error` gains
`HopStage` (the hop's name), set on any failure reaching the hop or opening the forward;
domain code reads it through a new `fleet` interface, because P14 forbids it the
transport import. JSON adds `via_failed: "bastion-eu"` on each dependent, omitted when
empty.

A changed or `@revoked` host key on the hop is **exit 2 for audit only**. `apply`,
`revoke`, `rotate` and `adopt` exit 1, as `apply.ExitCode` does for any unreachable
server today. One changed bastion key would otherwise read as N impersonations, so
`host_key_alerts` counts one alert per distinct failing hop: a server with `via_failed`
adds none of its own.

A probe failure at the hop stage means "could not check". There is no restore, the
outcome is `failed`, exit 1, and it is never `lockout_unrestored`: restoring a good file
over a hop that may be gone can only do harm. After P08-impl that outcome becomes P08's
`unproven`.

A refused forward (`AllowTcpForwarding no`) is kind `dial` with `hint`:
`the bastion refused the forward; allow TCP forwarding for this account`; the remote
text is bounded through `remoteText`. `DialHint` becomes
`check the host, port, and firewall; a host reachable only through a bastion needs via: in the manifest`,
and its mirrored goldens change.

**Host-key hints.** For a `via` server, `keyscanCompareCmd` must not print a scan that
would run from the operator's machine. It prints the scan through the hop and labels it:
`ssh -p 22 jump@bastion.example.com ssh-keyscan -t ed25519 -p 22 10.0.5.5 | ssh-keygen -lf -`
(as seen by the bastion; still compare with the console).

**Import.** `Host.Proxy` of `ProxyJump a,b` means target `via: b` and `b` `via: a`. The
chain maps when every hop resolves to an imported or manifest server, by alias or by
host, port and user; an explicit `user@` on a hop must match that server's user. Depth
over 3, a hop that does not resolve, or a hop that would need two different parents:
warn as today, kind `proxy_not_mapped`, and leave `via` unset. `ProxyCommand` stays
unsupported and warned. Under `--merge`, the manifest wins: only new servers get `via`.

`reconcile`'s `target`/`targetOf`, used by `CollapseTargets` and `builder.servers`, stay
as they are, matching the loader. A later host with the target of a kept one is still
dropped. Today its grants move to the kept alias, because the two are one machine. When
the two reach the address by different resolved `ProxyJump` chains, or one direct and one
through a hop, they may be two machines, so **its grants do not move** and the warning
says so:
`server "web-b" in the ssh config has the same host, port and user as "web-a" but a different route — skipped, and its access is not moved to "web-a"; a manifest holds one entry per address`.
Under `--merge`, a host that matches a manifest server's target by a different route is
treated the same way. A user left with no servers gets no access entry. A hop that names
a host dropped this way is not mapped (`proxy_not_mapped`). `ServerAdd` gains `Via`, and
both `config.Server{...}` builders (`generateManifest`, `renderMergedImport`) carry it.

**JSON.** `via` is additive on audit's per-server object, omitted when empty. A
`jump_only` server has `status: "jump_only"` in audit and `class: "jump_only"` with
`outcome: null` in apply, with empty key lists. `summary.jump_only` (additive, omitted
when 0) counts them in both, and `summary.servers` includes them. No manifest has the
flag today, so existing goldens hold.

**Tombstones.** No new rule. `via` is reachability, not access, so a tombstone on a
bastion only affects that bastion's own `authorized_keys`. The hop offers keys under
D17, as above. A tombstone on the bastion removes that grant, so that key is no longer
offered there unless the fallback applies. A tombstone naming a `jump_only` bastion has
no effect while the flag is set: no grant exists there and nothing reads its file.

**Files.** `internal/config` (`Via`, `Chain`), `internal/fleet` (`HopLimiter`, the hop
interface, `WriteRequest.ProbeForward`),
`internal/sshconn/{connect.go,hostkey.go,errors.go,sshtest/sshtest.go}`,
`internal/sshread`, `internal/sshwrite` (hop-stage probe, forward probe),
`internal/audit/{audit,report,json}.go`, `internal/apply/{exec,plan,report,json}.go`,
`internal/manifest/edit.go`, `internal/sshcfg`, `internal/reconcile`,
`cmd/sshepherd/{import,fleet,adopt,sweep}.go`, `cmd/sshepherd/schema_roundtrip_test.go`,
`scripts/integration.sh`, README.

**README.** **Requirements** ("Direct reachability" rewritten, including how to record a
private host's key seen through the bastion); **The manifest**: new `via:` subsection,
including the full-rewrite consequence for a managed bastion, `jump_only: true` and what
it stops being checked, and the one-entry-per-address rule; **Validation rules**;
**`sshepherd import`** (ProxyJump, a route-differing duplicate, adding `jump_only` by
hand); **`sshepherd audit`** and **`sshepherd apply`** (`--parallel` note with the fixed
cap, write order, the `jump only` row and JSON); **`sshepherd adopt`** (`jump_only`
servers are not read); **`sshepherd revoke`** and **`sshepherd rotate`** (`--sweep` does
not read them); **Safety model**; **Exit codes**.

**Tests.**

- `sshtest` gains `direct-tcpip` (rejected today) with a hermetic hop-to-target test.
- Config: cycle, self, depth, unknown `via`, `Chain` over the whole fleet. One address
  through two different hops, or direct and through a hop, is a load error with the
  route wording; the same `via` keeps today's wording.
- `jump_only`: `*`, `@tag` and the operator grant skip it; `Covers` false; empty
  `DesiredFor`; naming it in `servers:` or `except:`, a tag only it carries and
  `authorized_keys_file` are load errors; `jump_only_unused`; a `*` entry left covering
  only `jump_only` servers is deleted; a tombstone naming it loads and does nothing.
- A hermetic test proves audit, apply, adopt and `--sweep` open no connection to a
  `jump_only` server for its own sake. Goldens: the `jump only` row, `status`, `class` and
  `summary.jump_only`; `read X of N`; the `not swept` line, with no exit change.
- Strict host key on a `jump_only` hop: an unrecorded key stops the tunnel; a changed key
  exits 2 for audit and 1 for apply, with `via_failed` on dependents; `validate` warns
  `host_key_not_recorded`.
- A `jump_only` hop is offered every held key with no warning.
- Round-trip: the `JumpOnly` sample in `samples["Server"]` is `false` with a comment:
  `fill` sets every field, and `true` would clash with the sampled `authorized_keys_file`
  and the sampled `except: [web-1]`. A separate regenerate test asserts that `jump_only`
  survives `generateAdoptManifest`.
- Hop host-key mismatch and target host-key mismatch: exit 2 for audit, 1 for apply.
  One changed bastion key counts one `host_key_alerts`, with `via_failed` on dependents.
- Deadline bounded by the hop socket: a stalled target through a hop times out.
- Ctrl-C during the handshake on a wedged hop returns at once. A connect through a hop
  whose context is released afterwards stays usable (the `connectForWrite` pattern).
- Failure paths close the hop (`goleak`). `Conn.Close` closes the hop with a nil `Client`.
- A `via` server with no `Server` lookup never dials directly.
- `HopLimiter`: the cap holds, chain order, no budget burned while waiting, the two-slot
  write, `ctx` cancellation while waiting.
- Write levels: dependents before bastions, a failed target does not stop the bastion's
  level, levels computed with a converged middle hop, and a `jump_only` bastion in no
  level.
- Guard: `no-port-forwarding`, `restrict` and a narrow `permitopen=` on a managed bastion
  are refused; a forward probe rejected with `Prohibited` restores; a connection failure
  does not; a `jump_only` bastion is neither guarded nor probed.
- A hermetic test kills the hop during the probe: no restore, exit 1, never
  `lockout_unrestored`.
- Hint golden: the `via` scan command and its label. `DialHint` goldens.
- Import mapping table (chains, `user@`, two parents) and an `ssh -G` differential case.
  The same IP behind two bastions, or direct and through one, through `CollapseTargets`
  and `--merge`: one entry kept, grants not moved, the output loads. `import --merge`
  adds no grant on a `jump_only` server.
- Integration: a docker bastion on two networks, the target on the internal one only.
- E2E: audit and apply through the bastion. Audit exits 0 through a `jump_only` bastion
  whose jump account has a `nologin` shell.

---

## S6. Co-managed accounts through `preserve:` (D24, D24a; PRD-8)

```yaml
servers:
  - name: gitea
    host: git.example.com
    user: git
    preserve:
      - command: '/usr/local/bin/gitea --config=/etc/gitea/app.ini serv key-[0-9]+'
      - comment: 'google-ssh .*'
```

**Go shape.** `type PreserveRule struct { Command string `yaml:"command,omitempty"`;
Comment string `yaml:"comment,omitempty"` }` and `Server.Preserve []PreserveRule`
(`yaml:"preserve"`). Without `omitempty`, `entryNode` would write `comment: ""` beside
`command:`. Compiled patterns live in a `Config` map behind an exported matcher; they
cannot sit on `Server` or the rule, because `checkRoundTrip` compares those types with
`reflect.DeepEqual`.

**Validation** (load errors):

- `preserve:` on a `jump_only` server, because its file is never rendered:
  `server "x": jump_only has no managed file; remove preserve`.
- Each rule has exactly one of `command:` or `comment:`.
- Go RE2, compiled as a full match `^(?:…)$`, at most 512 bytes. The anchors are added
  for you, so a pattern does not write `^` or `$`.
- The unanchored pattern must have a literal prefix of at least 4 bytes
  (`regexp.LiteralPrefix`). This rejects `.*`, `.+`, `.{10,}`, `.+@.+\..+` and `/.*`.
  A top-level alternation or `(?i)` has no literal prefix: write two rules.
- The pattern must not match the empty string, `x`, `user@host`, `alice@laptop.local`,
  `root@ip-10-0-0-1.ec2.internal`, `ed25519-key-20260101`, 64 `a` characters, `/bin/sh`
  or `/usr/bin/rrsync /srv`.

**What a line is.** A line matches when its `command="…"` value or its comment matches a
rule. Classification reads every line from `authkeys.ParseFile(r.Content)`, not `Diff`,
because `Diff` keeps only the first line per fingerprint.

A fingerprint is external only if **every** line holding it matches a rule. Otherwise
it stays in `Diff.Unauthorized`, none of its lines is kept, and duplicate drift applies
as today. A rule-matching line next to a plain copy of the same key, in either order,
is therefore never kept: `ServerResult.Duplicates` documents why an unrestricted copy
defeats a restricted one.

**Lines that are never preserved:**

- A line whose fingerprint the manifest owns. The manifest wins.
- A line whose fingerprint has a key tombstone. A revoked key never survives, so it
  stays critical and apply removes it.
- A line where `authkeys.CertOnly` is true. Keeping a `cert-authority` line would let
  every certificate that CA signs log in.
- Unparseable lines. They still refuse.

**Render.** Line 1 stays the normal managed header. Then the desired keys. Then, only
when at least one line is preserved, the fixed marker
`# Preserved by SSHepherd (externally managed):` and the preserved lines in on-server
order, each using `Key.Raw`. Comment lines directly above a preserved line, with no
blank line between, are kept with it, verbatim, because some tools mark their own lines
that way and treat a line without the mark as foreign. The managed header and the
marker are never captured as such a comment. Byte-exact convergence holds. The existing
compare-and-swap stops a race with the external tool. `normalize` does not count the
marker or those comment lines as removed.

A marker left with nothing under it (the tool removed its lines, or the rule was
dropped) gets its own plan text: `remove the empty externally-managed section`.

**Empty-server rule stays.** A server with no desired keys is **never written**.
Preserved lines are not unauthorized, so such a server becomes `converged` instead of
`refused`. Any other unauthorized key, or a non-empty `authorized_keys2` (D30), still
refuses. This is not a wipe mode.

**Guard.** Preserved keys never count as surviving held keys, because the external tool
may delete them. `Survivors` already reads only `p.Desired`, so no new code is needed
there. `guardCheck`'s `removes the key this session logged in with` note reads
`Diff.Actual`, which still lists preserved keys, so it must also skip a session key that
is external: that line stays.

**Audit.** `auditOne` builds a new `ServerResult.External` (one entry per line: the key,
the matching rule kind, and the comment lines above it) and removes those fingerprints
from `Diff.Unauthorized`. That alone makes adopt skip them and apply keep them. A
duplicate is exempt from drift only under the every-line condition above. Text row:
`~ externally managed (preserve: command)` or `(preserve: comment)`. JSON: `keys.external`,
additive, each with `rule` (`command` or `comment`) so comment-matched keys can be
reviewed. Not drift (exit 0). Every line is listed by fingerprint, so "who can log in"
stays answerable.

P04's serial row for removal-only writes must not treat a preserved line as a removal.
The plan report prints `N externally managed lines kept` when N is not zero.

**Security note.** Anyone who can write a `comment` can keep a key that matches a
comment rule. The README warns about this and prefers `command:` rules (D24a).

**Tombstones.** Key tombstones beat `preserve:`. Access tombstones do not interact: an
owned key is always managed, never preserved.

**Files.** `internal/config`, `internal/authkeys/render.go` (and a scan that returns each
key with the comment lines above it), `internal/audit`,
`internal/apply/{plan,serial,report,json}.go`, `internal/adopt` (through audit),
`cmd/sshepherd/schema_roundtrip_test.go`.

**README.** **Safety model** ("Full-file rewrite" gains the exception); **The manifest**:
new `preserve:` subsection with the warning; **Validation rules**; **`sshepherd audit`**;
**`sshepherd apply`**; a co-managed-accounts recipe; **Exit codes**.

**Tests.** Validation table (`preserve:` on a `jump_only` server, empty match, `.+`, both
fields, bad regex, too long, a pattern under 4 literal bytes, every probe). Classification: a rule-matching line and a
plain copy, in both orders, is never preserved; duplicates that all match are kept. Plan
goldens: preserved rows, converged-with-only-preserved, the guard ignoring preserved, a
preserved-only no-grant server with `authorized_keys2` refused, the session-key note
skipped, the empty-section plan text. An owned, tombstoned or cert-authority fingerprint
is never preserved. Render golden, marker absent when nothing is preserved, comments
above a line kept, the marker never captured as one. Byte-exact re-apply is a no-op.
Audit text and JSON goldens, including `rule`. Adopt skips them. Fuzz seed. Integration:
a gitlab-style `command=` line with a comment line above it survives apply.

---

## S7. Optional per-grant restrictions (D22 = B; PRD-6)

```yaml
users:
  - name: deploy
    keys: ["ssh-ed25519 AAAA… deploy"]
access:
  - user: deploy
    servers: ["@prod"]
    options: ['from="10.0.0.0/8"', no-pty]
  - user: deploy
    servers: [staging-1]      # no options: the key line alone
```

**Go shape.** `Access.Options []string` (`yaml:"options"`). Optional. An empty list means
no restrictions.

**Meaning.** The options are added to the key line for the servers this entry grants.
The rendered line is the key line's options, then the grant's. A grant can only narrow
access; to vary a restriction per server, leave it off the key line and put it on the
grants (OP5).

**Validation** (load errors):

- Each option passes `authkeys.CheckOption`, and the grant as a whole passes
  `authkeys.OptionIssue`, so `from="a"` and `from="b"` in one grant are refused before
  sshd can ignore the whole rendered line.
- Only restricting options are allowed: `command=`, `expiry-time=`, `from=`,
  `no-agent-forwarding`, `no-port-forwarding`, `no-pty`, `no-user-rc`,
  `no-x11-forwarding`, `permitlisten=`, `permitopen=`, `restrict`, `verify-required`. A
  new `authkeys.IsRestriction` reads the meaning table. `cert-authority` and
  `principals=` are refused: a grant must not turn a key into a certificate authority.
- An option name already on a key line this entry reaches is an error, checked per key
  (each member's keys for a group entry). Names compare through `authkeys.FindOption`,
  which ignores case, so `FROM=` clashes with `from=`. The clause would repeat a once-only
  option, or widen a `permitopen=`/`permitlisten=` union.
- `authkeys.OptionIssue` also runs on the combined key-line and grant options, per key,
  as a last check.

**Two grants, different restrictions: a policy conflict.** For each key on each server,
every grant reaching it (direct, group, tag, and an operator's implicit grant, which
counts as no options) must give the same set. Comparison ignores order and the case of
option names. Same-set grants union as today.

A clash is a **D29 policy conflict**, kind `restriction_conflict` (OP6), not a load
error. Adding a `tags:` value, or adding an operator to a group with restricted grants,
can cause a clash at a distance, and a load error would stop both the `revoke` of a
leaver and the scheduled audit. `computeConflicts` finds it, after tombstone blocking.
`config.Conflict` is unchanged. All of a user's keys get the same grants, so a clash
belongs to a user and a pair of entries. There is one conflict per pair: `user` is set,
`fingerprint` is omitted, and `Servers` lists every server where those two entries
disagree. With three different sets on a server, the first two in access order are named.

`user "deploy": server "web-1" is granted by access[2] with [from="10.0.0.0/8" no-pty] and by access[5] with no options; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user`

With several servers it starts `user "deploy": servers "web-1" and 3 more are granted by`.
An implicit grant reads `by its operator grant with no options`.

| Command | What a clash does |
|---|---|
| `audit` | Prints it as critical and marks each server in `Servers` critical: exit 2. Like any conflict, it still does under `--server` when it names only other servers (OP4). Presence is still compared, but the options comparison is skipped for that user's keys on those servers, because there is no one desired set |
| `apply` | Refuses the servers in `Servers` with the conflict text and plans the rest: exit 1 |
| `validate` | A finding: exit 3, `valid: false`, in `policy_conflicts` |
| `adopt` (both modes), `import --merge` | Refuse, exit 3, nothing saved, when the save **would add** a clash on a (user, server) pair the manifest they started from did not have. A clash already there does not stop the save |
| `revoke`, `rotate` | **Still save,** even when a clash remains: they never add a grant. Their apply phase refuses the clashed servers as `apply` does |

**Mechanics.** `auditOne` fills a new `ServerResult` set of fingerprints from
`Config.ClashedKeys(server)`, and `optionsDrift` reports no drift for those keys in text,
JSON and `Compliant`. `apply`'s refusal already reads `Conflict.Servers`, so it needs no
code. `conflictRefusal` in `cmd/sshepherd/conflicts.go` gains the manifest the command
started from: revoke and rotate skip this kind, and adopt and import count only a clash
that manifest did not have. Other conflict kinds are checked first, with today's wording.
An added clash reads
`refusing to write the manifest — it would add 1 restriction conflict: MESSAGE`.

**Render.** `DesiredFor` returns per-server `authkeys.Key` copies with the combined
`Options`. Everything downstream already consumes that: audit options drift,
`apply.Affected`, `Survivors`, `OfferOrder`, the `Loosens` highlight, the guard's
restrictive-options warning. `OwnerOf` and fingerprint uniqueness do not change. On a
clashed pair the key still renders, with the options of the first `access:` entry
reaching it, so `DesiredFor` stays deterministic. Nothing writes that line, because
apply refuses the server.

`rotate` and `rotate --keep-old` touch the key line only, so grant options carry over.
`adopt` and `import` never write `options:`. Regenerate carries it through the encoder.
P09's expiry-time warning must also read grant options; whichever of S7 and P09-impl
lands second adds that.

**Tombstones.** A blocked grant takes no part in the clash check.

**Files.** `internal/authkeys/options.go` (`IsRestriction`), `internal/config`
(`validateAccess`, `DesiredFor`, `computeConflicts`, `ClashedKeys`), `internal/audit`,
`cmd/sshepherd/{conflicts,editrun,adopt,import}.go`,
`cmd/sshepherd/schema_roundtrip_test.go`.

**README.** **The manifest**: new "Per-grant restrictions" subsection; **Validation
rules** (a clash is a policy conflict, not a shape error); **`sshepherd audit`** (options
drift per server, the conflict block, the skipped comparison and JSON `policy_conflicts`);
**`sshepherd apply`** (the refusal); **`sshepherd validate`**; **`sshepherd adopt`** and
**`sshepherd import`** (the save refusal); **`sshepherd revoke`** and **`sshepherd rotate`**
(they still save; grant options unaffected); **Exit codes**.

**Tests.** Validation table: bad option, a widening or cert option, a repeated `from=`
inside one grant, a name already on the key line (including `FROM=`).
`restriction_conflict` and no conflict across direct, group and tag grants, an operator
implicit grant, order-insensitive comparison, one conflict per pair with every server
listed, the several-servers and operator wording. A manifest with a clash loads. Audit:
critical, exit 2, also under `--server` for another server; options comparison skipped for
the clashed keys only, missing and unauthorized keys still reported; JSON shape. Apply
refuses only the clashed servers, exit 1. Validate exit 3 with `valid: false`. Adopt and
`import --merge` refuse a save that adds a clash (a new server reached by two `*` entries
with different `except:`), exit 3 and nothing saved, and save over a clash already there.
Revoke and rotate save over a remaining clash, and their apply phase refuses those servers.
A revoke that removes a clashing grant clears it. A blocked grant causes no clash. Render
golden with grant options; existing manifests byte-identical; a clashed pair renders the
first entry's options. Audit drift and `apply.Affected` follow the per-server options.
Offer order sees grant options. A `no-port-forwarding` grant reaching a managed bastion is
refused by S5's guard (whichever of S5 and S7 lands second adds this test). Round-trip
sample. Fuzz seed.

---

## Order and parallel lanes

Each slice follows the standard shape: scout, agents on disjoint files, one integrator
runs `make check` and `make integration` and updates README and CLAUDE.md Status in the
same commit, then an independent verifier, then repair.

| Slice | Lanes (disjoint files) |
|---|---|
| S1 | A: `validate.go`, `validate_test.go`, `run.go` · B: `audit.go`, `fleet.go`, `apply.go`, `internal/audit/json.go`, `internal/apply/json.go`, their JSON tests |
| S2 | A: `import.go`, `adopt.go`, `internal/reconcile` message · B: `revoke.go`, `editrun.go`, `internal/apply/edit.go` · C: `identity.go`, `internal/keyfile` |
| S8 | A: `internal/adopt`, `adopt.go` · B: `import_json.go`, `import.go`, `internal/reconcile`, `internal/sshcfg` |
| S3a | A: `internal/config` (types in the plan first) · B: `internal/manifest` · C: `revoke.go`, `import.go` |
| S3b | A: `internal/config` · B: `internal/manifest` · C: `revoke.go`, `adopt.go` |
| S4 | A: `internal/config` · B: `internal/audit` · C: `internal/apply`, `editrun.go`, `revoke.go`, `rotate.go`, `internal/reconcile` |
| S5 | A: `internal/config`, `internal/fleet`, `internal/manifest/edit.go` · B: `internal/sshconn`, `sshtest`, `internal/sshread`, `internal/sshwrite`, `internal/audit/{audit,report,json}.go` · C: `internal/sshcfg`, `internal/reconcile`, `import.go` · D: `internal/apply/{exec,plan,report,json}.go`, `adopt.go`, `sweep.go` · integrator: `scripts/integration.sh` |
| S6 | A: `internal/config` · B: `internal/authkeys/render.go`, `internal/apply` · C: `internal/audit`, `internal/adopt` |
| S7 | A: `internal/authkeys/options.go`, `internal/config` · B: `internal/audit`, `conflicts.go`, `editrun.go`, `adopt.go`, `import.go` · integrator: tests and README |

## Risks

- **Silent narrowing through a tombstone.** A blocked grant is a warning, not an error.
  An operator may not see why a member lacks access. The warning says exactly which
  tombstone did it.
- **A stale tag fails the whole manifest**, the same as a stale server name. `validate`
  in CI catches it first.
- **An unreachable bastion is slow.** Each dependent waits its dial timeout, 8 at a
  time. A per-run "bastion is down" memo is left for later if this bites.
- **Budget with long chains.** A three-hop chain can use most of the 30-second per-server
  timeout. Depth is capped at 3 and documented.
- **Bastion access is powerful.** The README says `via:` makes the bastion's account part
  of every dependent's reach.
- **`preserve:` weakens "who can log in".** The audit row lists every kept key with its
  rule, and `comment:` rules carry a README warning.
- **A hand edit around a group refusal leaves no memory.** Removing a member by hand, or
  trimming the group's grant, records no tombstone, so `adopt --merge` can re-extend the
  user while the key is still installed. The refusal's third way out avoids this.
- **Bastion accounts are shared.** A bastion without `jump_only: true` is under
  full-file management. The README says so before the `via:` example and shows the flag.
- **A `jump_only` server is outside every check.** Nothing reads its file, so a leaver's
  key on it survives `revoke` and `--sweep`, and the flag set on a real server would hide
  that server from audit. Every report lists each such server, and `jump_only_unused`
  catches one nothing goes through. Its host key is still verified.
- **A restriction clash holds up every write on its servers,** other users' revocations
  included, until it is fixed. Audit shows it as critical, and `revoke` still saves.
- **One address is one entry.** Two private machines at one IP behind different bastions
  cannot both be managed until `host_key_alias:` exists. The second is a load error, and
  `import` drops it with a warning.
- **Schema slices queue up.** They run one at a time and each regenerates fixtures.
- **W4's repair pass and P09-impl may land first.** P09-impl changes `criticalDrift` and
  offering; S4 and S5 re-anchor on the then-current function names.

## Out of scope

- **On hold (owner, 2026-11-07):** key generation, scheduled rotation, prune,
  `apply --force`, `import --prefer`, move-key, and apply wipe/empty-server mode. S6
  explicitly keeps the rule that a server with no desired keys is never written.
- **Later, each with its own spec (D25b):** `maintenance: true`, the `grant` command and
  its `AddMember`/`RemoveMember`, and validate's "what changed since HEAD" view.
- **Later, unspecced:** `host_key_alias:` (which would lift S5's one-entry-per-address
  rule), bastion connection pooling, a per-run
  bastion-down memo, `--server @tag` on `audit` and `apply`, and `@tag` inside `except:`.
- D1–D19 (P04, P08 and P09 own those).
