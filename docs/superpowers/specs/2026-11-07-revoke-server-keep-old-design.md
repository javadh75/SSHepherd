# Design: `revoke USER --server` and `rotate --keep-old`

- **Date:** 2026-11-07
- **Status:** Implemented (plan: docs/superpowers/plans/2026-11-07-revoke-server-keep-old.md)
- **Scope:** `internal/manifest` (two new comment-preserving edits),
  `internal/apply` (edit-summary kinds, header text, JSON fields),
  `cmd/sshepherd` (`revoke.go`, `rotate.go`, `editrun.go`), README. Fulfils
  two items deferred by the revoke/rotate slice
  (`2026-10-23-revoke-rotate-design.md`, decisions 2 and 4).

## Context & goal

`revoke USER` offboards a user everywhere; there is no way to take away one
server without hand-editing `access:` — and hand-editing a wildcard grant is
exactly where mistakes happen. `rotate` swaps a key in one step, so the old
key dies fleet-wide in the same run: fine for a person's laptop key, an
outage for a key held by running systems (CI deploy keys, automation) that
cannot all switch at the same instant.

This slice adds per-server access trimming and an overlapping rotation, both
as thin manifest edits on top of the existing revoke/rotate pipeline (edit →
plan → confirm → save → apply over the affected servers).

## Decisions (owner-approved 2026-11-07)

| # | Decision | Choice | Rejected |
|---|---|---|---|
| 1 | Wildcard trim | **Append the server to `except:`** (created when absent); the grant keeps covering future servers | Expand `*` into an explicit list (silently stops future auto-grants); refuse wildcards |
| 1b | Wildcard left covering no current server | **Delete the entry and warn** that servers added later are no longer granted automatically — same rule as an emptied list | Refuse (exit 3) |
| 2 | Explicit-list trim | Remove the server (every occurrence) from every covering entry; an entry left with `servers: []` is **deleted** | — |
| 3 | Operators | `--server` on an operator target is **refused**; `--operator` with `--server` is a usage error — operators are fleet-wide by definition | Trimming an operator |
| 4 | Not-granted pairs | **Strict**: any USER × SERVER pair the user has no access to is exit 3 (all listed) | Skip silently |
| 5 | Overlap rotation | `rotate --keep-old` **adds** the new key right after the old one; the overlap is finished by hand with `revoke --key OLD`, whose exact command the run prints once the new key has landed | Dated overlap via `expiry-time=` on the old line; both |
| 6 | Overlap state | **None stored** — during the overlap the manifest lists both keys | A rotation-in-progress marker |
| 7 | Expiry under keep-old | The new key **carries the old line's options including `expiry-time=`**, exactly as plain `rotate`; the help text says so | Dropping expiry on the new key (silently extends a policy deadline) |
| 8 | Execution | One spec, **sequential** workflow (manifest → revoke → rotate → integrate) | Parallel agents (shared files) |

## `revoke USER... --server NAME...`

### Command surface

```
sshepherd revoke USER... --server NAME [--server NAME]... [usual flags]
```

- `--server` is repeatable, takes exact server names, and is valid only with
  the USER form. Help text: `remove the users' access to this server only
  (repeatable); the users and their keys stay`. (Unlike `apply --server`,
  which only restricts which servers a run touches, `revoke --server` edits
  the grants; the README says so in one line.)
- Every USER loses access to every named server; nothing else changes —
  the user entry, keys, other grants and the rest of the fleet stay.
- Duplicate `--server` values are de-duplicated silently.
- `Use` becomes `revoke {USER... [--server NAME...] | --key KEY...}` and the
  `Long` text gains one sentence on `--server`.

### Usage refusals (exit 3, before the manifest is read; first match wins)

1. USER and `--key` together — existing message
   (`revoke takes users or --key, not both`).
2. `--server` with `--key`: `access is granted per user, not per key — use
   'sshepherd revoke USER --server NAME'`.
3. `--server` with `--operator`: `--operator cannot be combined with
   --server: operators have access to every server by definition`.
4. `--server '*'`: `--server takes server names; to remove all of a user's
   access use 'sshepherd revoke USER'`.

### Refusals after the manifest is read (exit 3, nothing edited; all problems listed in one message)

The `--server` path does **not** call `operatorGate`. Instead, in order:

- Unknown USER (existing rule).
- Unknown server: `no server named "db-9" in the manifest`.
- Operator targets: `ops-bot is an operator (access to every server by
  definition); remove the user with 'sshepherd revoke ops-bot --operator',
  or clear operator: true by hand`.
- For non-operator targets only, a USER × SERVER pair with no access (by
  `config.Covers`, wildcard and `except:` included): `bob has no access to
  db-1`.

### Manifest edit — `(*manifest.File).RemoveAccess(user string, servers []string) (AccessRemoval, error)`

Uses the loaded config's server list (`f.Config()`) to resolve wildcards.
For each `access:` entry whose `user:` is `user`, and each server in
`servers` that the entry covers:

- **Explicit list:** remove **every** item equal to the server from
  `servers:`. When the list becomes empty, delete the whole entry (head
  comment rescued to the next sibling or the section footer, as
  `RemoveUser` does).
- **Wildcard (`servers: ["*"]`):** append the server to `except:`; when
  `except:` is absent, add it right after `servers:` using the same
  sequence style as that entry's `servers:` value (flow `["*"]` → flow
  `[web-1]`). If the wildcard would then cover **no current server**,
  delete the entry instead (decision 1b) and count it in
  `WildcardsRemoved`.
- An entry covering none of the servers is untouched; a server already in
  `except:` is not covered, so it is never appended twice.

```go
// AccessRemoval reports what RemoveAccess changed.
type AccessRemoval struct {
	EntriesChanged   int // entries edited in place (list shortened or except: extended)
	EntriesRemoved   int // entries deleted: list emptied, or wildcard left covering nothing
	ServersExcepted  int // servers appended to except: lists
	WildcardsRemoved int // of EntriesRemoved: wildcard entries deleted (decision 1b)
}
```

Node tree only; `Encode`'s built-in `config.Parse` self-check validates the
result. Comments on surviving items and entries are preserved; a removed
list item's line comment goes with it.

### What runs

- Affected servers = servers whose rendered desired file changes
  (`apply.Affected`) — for a trim, exactly the named servers where the user's
  keys were rendered. A server whose only grantee is trimmed gets the
  existing emptied warning and is never emptied.
- `editPlan` for the trim: `removesKey: false` (no scope line — servers that
  were not named are genuinely unaffected), `formerNote` unused (every
  removed key is still owned by the user, so plan labels show the owner),
  `stillHas: USER + " still has"` (the nothing-can-land message reads
  `bob still has access on 2 servers`), `saveNote` per the table below.
- Header line (one per user):
  `manifest edit: remove bob's access to web-1, db-1 (2 access entries changed, 1 removed, 1 server excepted)`
  — each count fragment pluralized and omitted when zero; the
  affected-servers tail follows the existing lone-edit / closing-line rule.
- Notes after the edit lines:
  - per wildcard deleted: `warning: bob's wildcard grant is removed — it
    would cover no current server; servers added later are no longer granted
    to bob automatically`;
  - when the user has no `access:` entry left in the edited config:
    `note: bob has no access left — 'sshepherd revoke bob' removes the user`.

## `rotate USER --old K1 --new K2 --keep-old`

### Rules

Identical to plain `rotate` (K1 belongs to USER; K2 not in the manifest and
≠ K1; no options on `--new`; a passed `expiry-time=` on K1 refused; the
operator gate with `--operator`). Only the edit differs. Help text:
`add the new key alongside the old one instead of replacing it (overlap; the
new key keeps the old line's options, expiry-time included); finish later
with 'sshepherd revoke --key OLD'`. The `Long` text's "the old key is dead
fleet-wide" sentence gains "(unless --keep-old)".

### Manifest edit — `(*manifest.File).AddKeyAfter(user, oldFP, newLine string) error`

Inserts `newLine` as a new `keys:` item **immediately after** the item whose
fingerprint is `oldFP`. It only inserts: the caller builds `newLine` with
the existing `rotatedLine` (rotate.go — option carry-over and the
inline-comment rule), exactly as plain rotate does before `ReplaceKey`. The
old item and `operator: true` are untouched.

### What runs

- Affected servers: wherever USER's render changes — every server USER is
  granted (all servers for an operator). The write is the usual **full-file
  render**: the lockout guard, the refusal classes and drift clean-up
  (`Remove` of unauthorized keys already on the server) apply unchanged.
  K1 stays in the desired set, so a run authenticated with K1 keeps a
  surviving held key.
- `editPlan` for keep-old: `removesKey: false`, `formerNote` unused,
  `stillHas: USER + "'s new key would get no"` (nothing-can-land reads
  `bob's new key would get no access on 3 servers`), `saveNote` per the
  table below.
- Header line: the existing rotate wording plus a fragment —
  `manifest edit: rotate bob key SHA256:old → SHA256:new (keeps the old key; keeps expiry-time="…")`
  — the `keeps expiry-time` fragment only when present, joined with `; `.

### Finish hint (text mode only; never under `--json` or `--dry-run`)

Built with `applyHint`'s quoting (`hintArg`); `CMD` = `sshepherd revoke
--key SHA256:old` + ` --config PATH` when not the default + ` --operator`
when USER is an operator.

| Path | Printed |
|---|---|
| Confirmed run, every affected server converged (applied or already converged) | `overlap started — every affected server accepts both keys; once every client uses the new key, finish with: CMD` |
| Confirmed run, some affected server not converged (failed, refused, unreachable, pending) | `overlap incomplete — N servers do not have the new key yet; push it first (see the apply hint above), then finish with: CMD` |
| `--no-apply` | `overlap recorded, not pushed — run the apply hint above, then, once every client uses the new key, finish with: CMD` |
| Zero affected servers (USER has no grants) | `new key recorded — bob has no grants yet, so no server was contacted; finish the overlap with: CMD` |
| Nothing-can-land / save withheld | none (nothing saved) |

When USER is an operator, every printed hint gets a second line:
`if the old key is how this machine logs in, run the finish with --identity
pointing at the new key's private key, or the lockout guard will refuse it`.

### Overlap lifecycle

- During the overlap the manifest lists both keys for USER; `audit` sees
  both as granted (correct), `apply` keeps both.
- The finish is plain `revoke --key K1`: K1 is not USER's last key (K2
  remains), so it never triggers "no keys left".
- `rotate --keep-old` again on the same K1 with a third key is allowed (K1 is
  still USER's); plain `rotate --old K1 --new K3` during an overlap replaces
  K1 as today.

## Save reminder per edit kind

`saveEdit`'s reminder (text mode) takes its tail from a new
`editPlan.saveNote`, defaulting to today's wording:

| Edit | Reminder tail after `manifest PATH updated — commit and push it:` |
|---|---|
| `revoke USER`, `revoke --key`, `rotate` (unchanged) | `an apply from a copy without this edit re-grants the removed key` |
| `revoke USER --server` | `an apply from a copy without this edit re-grants the removed access` |
| `rotate --keep-old` | `an apply from a copy without this edit removes the new key — clients that already switched would be locked out` |

## `apply.Edit` / JSON

- New `apply.EditKind` `EditRemoveAccess = "remove-access"`.
- `apply.Edit` gains `AccessServers []string`, `EntriesChanged`,
  `EntriesRemoved`, `ServersExcepted`, `WildcardsRemoved int`,
  `NoGrantsLeft bool` (remove-access only) and `KeepOld bool` (rotate only).
- JSON (additive; schema stays 1), following the existing per-kind presence
  rule (fields of a kind are always present for that kind, absent for
  others — `json.go`):
  - `remove-access`: `user`, `access_servers` (`[]`-safe), `entries_changed`,
    `entries_removed`, `servers_excepted`, `wildcards_removed`,
    `no_grants_left`.
  - `rotate`: gains `keep_old` (always present on rotate entries,
    `false` for plain rotate).

## Errors, exit codes

No new exit codes. All new refusals are exit 3 with nothing edited. `--json`
behaves as in `2026-11-07-apply-json-design.md`; only the edit fields above
are new.

## Testing (per project policy — all kinds, coverage ≥ 80%)

- **`internal/manifest` unit + golden:** `RemoveAccess` — explicit list
  (first / middle / last item; duplicate items all removed), list emptied →
  entry deleted with head comment rescued, wildcard without `except:`
  (created; flow and block `servers:` styles), wildcard with `except:`
  (appended), wildcard left covering nothing → entry deleted
  (`WildcardsRemoved`), two entries for one user both edited, entry covering
  none untouched, comment survival, every output re-parses. `AddKeyAfter` —
  position (first / middle / last key), unknown fingerprint error, operator
  flag untouched, comment survival.
- **`internal/apply`:** header goldens for `remove-access` (fragment
  pluralization and omission; wildcard-removed warning; no-access-left note)
  and keep-old rotate (with and without expiry); JSON goldens for the new
  fields (`keep_old: false` present on plain rotate).
- **`cmd/sshepherd` hermetic:**
  - revoke `--server`: every usage refusal and its precedence; unknown
    server; operator target (no gate loop); multiple users with one pair not
    granted (all listed); trim on an explicit list and on a wildcard
    (manifest bytes asserted); wildcard-to-nothing deletion warning;
    sole-grantee warning; no-access-left note; per-kind save reminder; no
    scope line; `--no-apply`, `--dry-run`, `--json`.
  - rotate `--keep-old`: both keys installed; expiry carried; every
    finish-hint row (including the operator `--identity` line); per-kind save
    reminder; the manifest's `comment:`-on-a-multi-key-user warning surfaces as it does for other
    edits; then `revoke --key OLD` leaves only the new key and `audit` is
    clean.
- **Integration / E2E:** extend the loop with `revoke USER --server` on a
  two-grant manifest (`audit` clean afterwards) and with `rotate --keep-old` →
  `audit` exit 0 (both keys) → `revoke --key OLD` → `audit` exit 0.
- No new parser → no new fuzz target.

## Workflow (sequential; shared files)

1. **Manifest agent** — `RemoveAccess`, `AddKeyAfter`, tests, goldens.
2. **Revoke agent** — `--server` in `revoke.go`/`editrun.go` (incl.
   `saveNote`), `apply.Edit` kind + header + JSON fields, help/`Use`/`Long`,
   the README flag-table row for `--server` (so the help/README test stays
   green), tests.
3. **Rotate agent** — `--keep-old` in `rotate.go`/`editrun.go`, header + JSON
   field, finish hint, help/`Long`, the README flag-table row for
   `--keep-old`, tests.
4. **Integrator** — `make check`, `make integration`, E2E, rest of README
   (revoke/rotate sections, samples copied from goldens, the
   `apply --server` vs `revoke --server` line), CLAUDE.md Status.
5. **Verifier**, then **repair**.

Each stage runs in the main tree after the previous one finishes; agents do
not commit; the integrator commits once.

## Deliberately deferred (NOT in this slice)

- Dated overlap (`--keep-old-until`, `expiry-time=` on the old line).
- `revoke --key K --server S` (access is per user).
- Trimming operators; moving a key between users; generating keys.
- Removing a key from an emptied server (apply "wipe" mode).
