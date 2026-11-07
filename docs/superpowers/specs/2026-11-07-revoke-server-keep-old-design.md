# Design: `revoke USER --server` and `rotate --keep-old`

- **Date:** 2026-11-07
- **Status:** Approved design — awaiting adversarial read and plan
- **Scope:** `internal/manifest` (two new comment-preserving edits),
  `internal/apply` (edit-summary kinds, header text, JSON fields),
  `cmd/sshepherd` (`revoke.go`, `rotate.go`, `editrun.go`). Fulfils two items
  deferred by the revoke/rotate slice
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
| 1 | Wildcard trim | **Append the server to `except:`** (created when absent); the grant keeps covering future servers | Expand `*` into an explicit list (silently stops future auto-grants); refuse wildcards (drops the most useful case) |
| 2 | Explicit-list trim | Remove the server from every covering entry; an entry left with `servers: []` is **deleted** (empty grants are invalid) | — |
| 3 | Operators | `--server` on an operator target is **refused even with `--operator`** — operators are fleet-wide by definition | Trimming an operator (contradicts `operator: true`) |
| 4 | Not-granted pairs | **Strict**: any USER × SERVER pair the user has no access to is exit 3 (all listed); a typo never becomes a silent no-op | Skip silently |
| 5 | Overlap rotation | `rotate --keep-old` **adds** the new key right after the old one; the overlap is finished by hand with the existing `revoke --key OLD`, whose exact command the run prints | Dated overlap via `expiry-time=` on the old line (silent scheduled outage risk, dead lines left behind); both |
| 6 | Overlap state | **None stored** — during the overlap the manifest simply lists both keys | A rotation-in-progress marker |
| 7 | Execution | One spec, **sequential** workflow (manifest → revoke → rotate → integrate) | Parallel agents (shared files) |

## `revoke USER... --server NAME...`

### Command surface

```
sshepherd revoke USER... --server NAME [--server NAME]... [usual flags]
```

- `--server` is repeatable, takes exact server names, and is valid only with
  the USER form. Help text: `remove the users' access to this server only
  (repeatable); the users and their keys stay`.
- Every USER loses access to every named server; nothing else changes —
  the user entry, keys, other grants and the rest of the fleet stay.
- Duplicate `--server` values are de-duplicated silently (as duplicate users
  are today).

### Usage refusals (exit 3, before the manifest is read)

- `--server` with `--key`: `access is granted per user, not per key — use
  'sshepherd revoke USER --server NAME'`.

### Refusals after the manifest is read (exit 3, nothing edited; every problem listed in one message)

- Unknown USER (existing rule).
- Unknown server: `no server named "db-9" in the manifest`.
- A USER × SERVER pair with no access (by `config.Covers`, i.e. the effective
  grant, wildcard and `except:` included): `bob has no access to db-1`.
- An operator target, with or without `--operator`: `ops-bot is an operator
  (access to every server by definition); remove the user with 'sshepherd
  revoke ops-bot --operator', or clear operator: true by hand`.

### Manifest edit — `(*manifest.File).RemoveAccess(user string, servers []string) (AccessRemoval, error)`

For each `access:` entry whose `user:` is `user`, and each server in
`servers` that the entry covers:

- **Explicit list:** remove the server's item from `servers:`. When the list
  becomes empty, delete the whole entry (head comment rescued to the next
  sibling or the section footer, as `RemoveUser` does).
- **Wildcard (`servers: ["*"]`):** append the server to `except:`, creating
  `except:` (in the entry's mapping style — flow entries get a flow
  sequence) after `servers:` when absent. A server already in `except:` is
  not covered, so it is never appended twice.
- An entry covering none of the servers is untouched.

```go
// AccessRemoval reports what RemoveAccess changed.
type AccessRemoval struct {
	EntriesChanged int // entries edited in place (list shortened or except: extended)
	EntriesRemoved int // entries deleted because their list became empty
	ExceptAdded    int // servers appended to an except: list
}
```

Node tree only, like the other edits; `Encode`'s built-in `config.Parse`
self-check validates the result. Comments on surviving items and entries
are preserved; a removed list item's line comment goes with it.

### What runs

- The existing pipeline: affected servers = servers whose rendered desired
  file changes (`apply.Affected`), which for a trim is exactly the named
  servers where the user had keys installed by the render. A server whose
  only grantee is trimmed gets the existing "emptied … stays" warning and is
  never emptied.
- When a user is left with no grants at all: a note in the header,
  `bob has no access left — 'sshepherd revoke bob' removes the user`.
  The user entry stays.
- Header line (one per user): `manifest edit: remove bob's access to web-1,
  db-1 (2 access entries changed, 1 removed, 1 except added) — 2 servers
  affected` (count fragments pluralized and omitted when zero; the
  affected-servers tail follows the existing lone-edit / closing-line rule).
- The scope line (`printScope`) is printed as for `revoke --key`: other
  servers were not contacted.

### `apply.Edit` / JSON

- New `apply.EditKind` `EditRemoveAccess = "remove-access"`.
- `apply.Edit` gains `Servers []string` and `EntriesChanged`,
  `EntriesRemoved`, `ExceptAdded int` (used by `remove-access` only) and
  `NoGrantsLeft bool`.
- JSON (additive; schema stays 1): a `remove-access` entry carries `user`,
  `servers`, `entries_changed`, `entries_removed`, `except_added`,
  `no_grants_left` — all present for that kind, absent for the others.

## `rotate USER --old K1 --new K2 --keep-old`

### Rules

Identical to plain `rotate` (K1 belongs to USER; K2 not in the manifest and
≠ K1; no options on `--new`; a passed `expiry-time=` on K1 refused; the
operator gate with `--operator`). Only the edit differs. `--keep-old` help
text: `add the new key alongside the old one instead of replacing it
(overlap); finish later with 'sshepherd revoke --key OLD'`.

### Manifest edit — `(*manifest.File).AddKeyAfter(user, oldFP, newLine string) error`

Insert `newLine` as a new `keys:` item **immediately after** the item whose
fingerprint is `oldFP`, carrying the old line's options verbatim (the same
option carry-over and inline-comment rule `ReplaceKey` applies: the new
key's comment if it has one, else the old line's, else none). The old item
is untouched. `operator: true` is untouched.

### What runs

- Affected servers: wherever USER's render changes — every server USER is
  granted (all servers for an operator). K2 is added; nothing is removed, so
  the lockout guard has nothing to refuse and `Remove` is empty.
- Header: `manifest edit: rotate bob's key SHA256:old → SHA256:new, keeping
  the old key (overlap) — 3 servers affected` (plus the existing `keeps
  expiry-time="…"` fragment when present).
- **Finish hint**, text mode only, printed after a successful save on every
  path that saves (confirmed run and `--no-apply`):
  `overlap started — once every client uses the new key, finish with:
  sshepherd revoke --key SHA256:old` + ` --config PATH` when not the default
  + ` --operator` when USER is an operator. Built with the existing
  `hintArg` quoting.
- JSON: the `rotate` entry gains `"keep_old": true` (omitted when false);
  the hint is suppressed under `--json` like the other text lines.

### Overlap lifecycle

- During the overlap the manifest lists both keys for USER; `audit` sees
  both as granted (correct), `apply` keeps both.
- The finish is plain `revoke --key K1`: K1 is not USER's last key (K2
  remains), so it never triggers "no keys left".
- `rotate --keep-old` again on the same K1 with a third key is allowed (K1 is
  still USER's); plain `rotate --old K1 --new K3` during an overlap replaces
  K1 as today.

## Errors, exit codes, JSON

No new exit codes. All new refusals are exit 3 with nothing edited. `--json`
behaves as specified in `2026-11-07-apply-json-design.md`; only the edit
entry fields above are new.

## Testing (per project policy — all kinds, coverage ≥ 80%)

- **`internal/manifest` unit + golden:** `RemoveAccess` — explicit list
  (first / middle / last item), list emptied → entry deleted with head
  comment rescued, wildcard with no `except:` (created; block and flow
  styles), wildcard with existing `except:` (appended), two entries for one
  user both edited, entry covering none untouched, comment survival, every
  output re-parses. `AddKeyAfter` — position (first / middle / last key),
  options carried, comment rule, operator flag untouched, comment survival.
- **`internal/apply`:** header goldens for `remove-access` (singular /
  plural fragments, no-grants-left note) and `rotate` keep-old; JSON goldens
  for both new fields.
- **`cmd/sshepherd` hermetic:** every refusal (key + server, unknown server,
  not-granted pair listed together, operator with and without `--operator`);
  a trim on an explicit list and on a wildcard (manifest bytes asserted);
  sole-grantee warning; no-grants-left note; `--no-apply`, `--dry-run`,
  `--json` for both; the full overlap: `rotate --keep-old` (both keys
  installed, finish hint exact) then `revoke --key OLD` (only the new key
  left, audit clean).
- **E2E (integration):** extend the loop with `rotate --keep-old` → `audit`
  exit 0 (both keys present) → `revoke --key OLD` → `audit` exit 0.
- No new parser → no new fuzz target.

## Workflow (sequential; shared files)

1. **Manifest agent** — `RemoveAccess`, `AddKeyAfter`, tests, goldens.
2. **Revoke agent** — `--server` in `revoke.go`/`editrun.go`, `apply.Edit`
   kind + header + JSON fields, tests.
3. **Rotate agent** — `--keep-old` in `rotate.go`/`editrun.go`, header + JSON
   field, finish hint, tests.
4. **Integrator** — `make check`, `make integration`, E2E, README (flag
   tables, revoke/rotate sections, samples from goldens), CLAUDE.md Status.
5. **Verifier**, then **repair**.

Each stage runs in the main tree after the previous one finishes; agents do
not commit; the integrator commits once.

## Deliberately deferred (NOT in this slice)

- Dated overlap (`--keep-old-until`, `expiry-time=` on the old line).
- `revoke --key K --server S` (access is per user).
- Trimming operators; moving a key between users; generating keys.
- Removing a key from an emptied server (apply "wipe" mode).
