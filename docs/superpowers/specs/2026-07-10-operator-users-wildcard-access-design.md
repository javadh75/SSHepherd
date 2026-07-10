# Design: operator users, wildcard access grants, critical audit severity

- **Date:** 2026-07-10
- **Status:** Implemented (2026-07-10) — see docs/superpowers/plans/2026-07-10-operator-users-wildcard-access.md
- **Scope:** Extends the manifest schema (`internal/config`), the audit report
  (`internal/audit`), and the import command (`cmd/sshepherd`). Three features
  land together because they share one motivation: first-class support for the
  operator's own management keys — the keys SSHepherd itself logs in with.

## Context & goal

SSHepherd connects to servers with the operator's SSH agent; the manifest does
not know which keys those are. Today the operator's keys are ordinary users
whose `access` entries must list every server by hand. That has two failure
modes:

1. **Drift by omission** — add a server, forget to extend your own access
   list, and the desired state for that server excludes the very key the tool
   logs in with. Today's read-only `audit` merely misreports; the future
   `apply` would remove the key and lock the operator out.
2. **No severity signal** — a missing operator key is reported exactly like
   any other missing key, though it threatens fleet access itself.

This slice makes management keys a first-class manifest concept
(`operator: true`), adds wildcard grants with carve-outs for everyone else,
surfaces missing operator keys as CRITICAL in audit, and teaches
`sshepherd import` to mark operator keys instead of emitting a hand-listed
grant for every host.

## Decisions (locked)

| Decision | Choice | Notes |
|---|---|---|
| Marker meaning | **Fleet-wide grant + protected** | The operator's desired end state is both keys on every server (the current mixed layout is historical accident). A convenience-only wildcard cannot express "never remove"; protection alone cannot express "everywhere". |
| Marker shape | **Boolean flag on the user** (`users[].operator`) | The property belongs to the user, not to a grant. A separate `operators:` section splits one user's story across sections; wildcard+protected as two mechanisms allows states the operator explicitly does not want. |
| Flag name | **`operator`** | `admin` wrongly implies remote root/sudo; `break_glass` undersells the everyday fleet-wide meaning. |
| Wildcard shape | **`servers: ["*"]` + optional `except: [...]`** | For non-operator users who need broad access. `"*"` tracks servers added later; `except` expresses deliberate carve-outs. |
| Critical severity | **Render-only** | Distinct marker + summary count. Exit codes unchanged (0 compliant / 1 drift / 2 usage): CI treats non-zero as fail anyway, and a third code widens a public contract for little gain. |
| Import marking | **`--operator <key-path>`, repeatable, matched by fingerprint** | The operator references the key file they know, not an auto-generated user name (`<local-user>-<basename>` is not knowable before import runs). Auto-detection (key granted on every host) was rejected: on a mixed fleet it silently detects nothing. |
| Apply-slice protection | **Contract recorded now, implemented with apply** | Stripping an operator key requires removing the flag first plus explicit confirmation; apply also gets a runtime self-lockout guard (never remove the key the session authenticated with, even if the manifest says so). |

## In scope

- `internal/config`: `User.Operator`, `Access.Except`, validation rules,
  implicit operator grant in `DesiredFor`.
- `internal/audit`: CRITICAL rendering for missing operator keys, critical
  count in the summary line.
- `cmd/sshepherd`: `import --operator` flag, dropped/compacted access entries,
  `operator: true` in generated manifests.
- Tests for all of the above (see Testing).

## Deliberately deferred (NOT in this slice)

- Apply/revoke enforcement of the protection contract (no apply slice exists
  yet; the contract lives in this spec so it is not forgotten).
- Audit exit code distinguishing critical drift (revisit if scripts need it).
- `except` compaction in import output (emitting `"*"` + `except` for a user
  covering all-but-a-few hosts is too magical for a generated draft).
- Server groups/tags (the only grouping need expressed so far is "all").

## `internal/config` — schema & semantics

```yaml
users:
  - name: javad-work
    operator: true            # fleet-wide + protected
    keys: [ssh-ed25519 AAAA... work]

access:
  - user: alice
    servers: ["*"]            # every server, including future ones
    except: [db-1]            # only valid together with "*"
  - user: bob
    servers: [web-1, web-2]   # explicit lists unchanged
```

**Operator semantics.** Every operator user is implicitly granted every
server. `DesiredFor(server)` returns operator users' keys first (in `users:`
order), then access-granted users' keys (in `access:` order); a user already
included as an operator is skipped when it also appears in grants, so no key
is emitted twice. Ordering stays fully deterministic.

**Wildcard semantics.** A `servers: ["*"]` entry expands to every manifest
server (in `servers:` order) minus the `except` names. Expansion happens at
validation time into the existing grants map; downstream code sees no
difference between wildcard and explicit grants.

**Validation additions** (errors, in the existing "a manifest that parses is
safe to act on" spirit):

- An operator user must have at least one key.
- `"*"` must be the **only** element of `servers`.
- `except` is only legal when `servers` is `["*"]`.
- Every `except` name must be a known server; duplicate `except` names are
  tolerated (harmless, consistent with grants unioning silently).
- A wildcard entry whose effective grant is empty (empty fleet, or `except`
  covers every server) is an error — an entry granting nothing is a mistake.
- A server may not be named `"*"` (token reserved).

Unchanged: zero operators is valid (every existing manifest still parses);
redundant `access` entries for an operator user are allowed and union
silently.

## `internal/audit` — critical severity

A missing key whose owner (via `OwnerOf`) has `Operator: true` renders with
its own marker and label:

```
  ‼  javad-work  SHA256:...  ssh-ed25519  authorized but MISSING (CRITICAL: operator key)
```

The summary line counts servers whose drift includes at least one missing
operator key:

```
Summary: 3/5 servers compliant · 2 with drift (1 critical) · 0 unreachable  → exit 1
```

Nothing else changes: `Compliant()`, `ExitCode`, and the fan-out are
untouched. An operator key can never be *unauthorized* (it is desired
everywhere by construction), so MISSING is the only state that can be
critical. Unreachable servers stay plain ERROR — nothing is knowable about
their keys.

## `cmd/sshepherd import` — `--operator`

```
sshepherd import [path]
      --operator <key-path>   # repeatable; marks this key's user as operator
```

- Each path is home-expanded like an `IdentityFile`; the `.pub` is read
  (`<path>.pub`, or the path itself when it already ends in `.pub`). Only
  public keys are ever opened. Unreadable or invalid keys are **errors**
  (exit 2), not warnings — the operator named this key explicitly.
- The parsed key is matched **by fingerprint** against the derived users.
  Matched → the user gains `operator: true` and its access entry is dropped
  (the fleet-wide grant is implied). This also fixes today's noisiest output:
  default local identities no longer collect an explicit grant for every
  identity-less host.
- No match → the key is still emitted as a new operator user (operator means
  "everywhere" regardless of what the ssh config uses), named by the existing
  `<local-user>-<basename>` rule, description
  `imported from <path as typed> (--operator)`.
- Repeated `--operator` paths resolving to the same fingerprint dedupe
  silently.
- `--operator` with `--servers-only` is a flag conflict → error (exit 2).
- **Wildcard compaction:** a non-operator derived user whose grants cover
  every server is emitted as `servers: ["*"]`, with a stderr note — the
  wildcard deliberately opts that user into servers added later, which an
  explicit list would not. Compaction only applies when the fleet has ≥ 2
  servers (a single-server fleet says nothing about "everywhere").
- `userOut` gains `operator,omitempty`; `accessOut` is unchanged (import
  never emits `except`). The `config.Parse` self-check keeps guaranteeing
  import never emits an invalid manifest.

## Security notes

- Only `.pub` files are ever opened; private key material is never read.
- Generated descriptions use the path as typed, never the expanded absolute
  path (no home-directory leak into committed files).
- The protection contract (apply-slice) is the security payoff of the flag:
  operator keys become impossible to remove accidentally.

## Testing (per project policy — all kinds, coverage gated)

- **Unit** (`internal/config`, table-driven): operator flag parses; keyless
  operator rejected; `DesiredFor` ordering (operators first, users order,
  then access order) and dedup with redundant grants; wildcard expansion
  order; `"*"` not sole element rejected; `except` without wildcard rejected;
  unknown `except` name rejected; empty effective grant rejected; server
  named `"*"` rejected; zero-operator manifests unchanged.
- **Unit** (`internal/audit`): report golden-style assertions for the `‼`
  marker and label; summary critical count (0, 1, several); operator key
  missing on a `FileAbsent` server is critical; unreachable server stays
  plain ERROR.
- **Command-level** (`cmd/sshepherd`): `--operator` matched / unmatched /
  invalid path / conflict with `--servers-only`; golden manifest fixtures for
  operator marking, dropped access entries, and wildcard compaction (incl.
  the ≥ 2 servers guard and stderr note).
- **Coverage** flows through the existing `make coverage` gate (≥ 80%).

## Commit plan (trunk-based, each commit independently green)

1. `feat(config): operator users — fleet-wide protected keys in the manifest`
2. `feat(config): wildcard access grants with except lists`
3. `feat(audit): flag missing operator keys as CRITICAL` (depends on 1)
4. `feat(import): --operator marks management keys` (depends on 1 + 2)
5. `docs: mark operator/wildcard slice implemented` (CLAUDE.md status,
   spec status line)

The spec itself is committed before any implementation commit.
