# Design: `revoke` and `rotate`

- **Date:** 2026-10-23
- **Status:** Approved design (brainstorm 2026-10-23), pending adversarial
  critique and owner review of the written spec.
- **Amends:**
  [apply slice](2026-07-19-apply-slice-design.md) (fulfils the deferred
  "`revoke` / `rotate` UX"; apply's run becomes reusable),
  [operator users](2026-07-10-operator-users-wildcard-access-design.md)
  (implements the protection contract for revoke),
  [adopt `--merge`](2026-07-16-adopt-merge-design.md) (`internal/manifest`
  gains removal and replacement edits, not only appends).

## Context & goal

The apply slice reduced revocation and rotation to "edit the manifest, run
`apply`". That is correct but two steps, and the edit is error-prone by hand
(find the key by eye, remove the matching `access:` entries, keep the YAML
comments). This slice adds two verbs that perform the edit
comment-preservingly and then push it through apply's existing pipeline —
plan, confirm, guarded write, verify, probe — restricted to the servers the
edit actually changes. Offboarding becomes one command.

## Decisions (locked by prior specs — not open for relitigation)

- The manifest is the single source of truth; every fleet change goes
  through apply's safety model (full-file render, refusal gates, lockout
  guard over every held key, CAS remote write, verify, login probe with
  restore).
- Confirmation gate: TTY prompt, `--yes`, or `--dry-run`; non-TTY without
  `--yes` is exit 3.
- Exit codes: 0 converged, 1 a server failed/refused/unreachable, 3 tool or
  usage error. `revoke`/`rotate` never return 2.
- Operator protection contract (operator spec, 2026-07-10): stripping an
  operator key requires removing the flag first plus explicit
  confirmation.
- Manifest fidelity contract of `internal/manifest`: comments preserved;
  blank lines and quote styles may normalize.
- Credentials: agent and/or `--identity` key files, per the 2026-10-16
  spec, with its order of operations.

## New decisions this spec makes (owner-approved 2026-10-23)

| # | Decision | Choice | Rejected |
|---|---|---|---|
| 1 | Verb scope | **Edit, then apply** in one command; `--dry-run` leaves the manifest untouched; `--no-apply` only edits. | Edit-only (two-step offboarding remains); apply-only overlay (next `apply` reinstalls the revoked key). |
| 2 | Revoke forms | **User** (offboard: user + all their grants) and **key** (one key, by fingerprint/line/`.pub`). | Per-server access trimming (deferred: splitting grants, wildcard→`except:`, emptied grants are invalid). |
| 3 | Operators | **Refused by default** (exit 3 + hint); `--operator` acknowledges and performs the flag change in the same edit; loud `OPERATOR` plan line; `--yes` alone never covers it. | Always refuse (forces a hand edit); treat like anyone (weakens the contract). |
| 4 | Rotate shape | **One-step swap** in place; old key dead fleet-wide in that run. | Staged overlap / `--keep-old` (deferred). |
| 5 | Apply scope | **Affected servers only** — servers whose rendered desired file changes; on those, the full render still converges other drift (shown in the plan). Unaffected servers are not contacted. | Whole fleet (emergency revocation stalls on unrelated refusals); strict (trivial drift blocks an emergency). |
| 6 | Save point | Manifest saved **after confirmation, before the first remote write**, with a local compare-and-swap. | Save after writes (a crash leaves servers revoked but the manifest granting — the next `apply` reinstalls the key); save-then-rollback (fragile rollback of the source of truth). |

## Command surface

```
sshepherd revoke USER... [--operator]
sshepherd revoke --key KEY [--key KEY]... [--operator]
sshepherd rotate USER --old KEY --new KEY [--operator]
```

Both commands also take apply's flags with apply's defaults and help
text: `--config`, `--known-hosts`, `--parallel`, `--dry-run`, `--yes`, the
timeouts, and the three `--identity` flags. New: `--no-apply` (edit and
save after confirmation; no connections). There is no `--server`: the
scope is computed (decision 5).

**KEY forms.** For `--key` and `--old`: a `SHA256:` fingerprint, a full
public-key line (options and comment allowed), or a path to a `.pub`
file. For `--new`: a key line or a `.pub` path only — a fingerprint
carries no key. Disambiguation, in order: an argument starting with
`SHA256:` is a fingerprint; one that parses as an `authkeys` line is a
key line; otherwise it is a path (read with the 64 KiB cap; the file must
contain exactly one key line). A path that does not exist is exit 3 with
the three accepted forms listed.

**Usage rules (all exit 3, before the manifest is read):** users and
`--key` together; no target; `rotate` without exactly one `--old` and one
`--new`; `--new` given as a fingerprint; an unreadable or multi-key `.pub`;
`--dry-run` with `--yes` is allowed (dry-run wins, as in apply).

### `revoke USER...`

Deletes each user entry and every `access:` entry whose `user:` is that
user. Unknown user → exit 3 (all unknown names listed). Duplicated names
on the command line are de-duplicated silently.

### `revoke --key KEY...`

Removes each key line from its owner (keys are unique across users —
`config` rejects duplicates — so the owner is unambiguous). A key not in
the manifest → exit 3: "KEY is not in the manifest; `apply` already
removes keys the manifest does not grant — run `sshepherd audit` to find
where it is installed". If that was the owner's last key, the user stays
with `keys: []` (valid for non-operators) and the plan carries
`note: alice has no keys left — 'sshepherd revoke alice' removes the user`.
Two `--key` arguments naming the same fingerprint are de-duplicated.

### `rotate USER --old KEY --new KEY`

- `--old` must belong to `USER` (typo cross-check) — otherwise exit 3
  naming the actual owner, or "not in the manifest".
- `--new` must not already be in the manifest (exit 3 naming its owner).
- The new line replaces the old at the same index of `keys:`.
- **Options** of the old manifest line carry over (`from=`, `command=`,
  `restrict`, …); options written on `--new` itself are an error (exit 3:
  "rotate keeps the old line's options; edit them in the manifest").
- **Inline comment:** the new key's comment if it has one, else the old
  line's inline comment, else none (DesiredComment then falls back to
  `comment:`/`name` as always).
- `operator: true` is kept — a rotation is not a demotion.

### Operators

Any target that is, or belongs to, an `operator: true` user is refused
(exit 3) unless `--operator` is given:
`ops-bot is an operator (fleet-wide, protected); pass --operator to
confirm revoking it`. With `--operator`:

- `revoke USER` removes the user entry (flag included).
- `revoke --key` of an operator's **last** key also clears the flag
  (`operator: true` with no keys fails validation); the plan says so.
- `rotate` keeps the flag.
- The edit header carries a loud `OPERATOR` line per operator target.

`--yes` never substitutes for `--operator`. The lockout guard still
applies on top: revoking your own operator key with no other held key
surviving is refused per server as always.

## Order of operations

Nothing contacts the network before step 5; nothing writes the manifest
before step 7.

1. **Flags** (usage rules above; KEY arguments parsed, `.pub` files read).
2. **Load** the manifest with `manifest.Load`; keep the exact bytes read.
3. **Edit in memory.** Resolve targets against the config (unknown /
   ownership / duplicate checks, exit 3), apply the operator rule, edit the
   node tree, `Encode`, and re-parse the result with `config.Parse`. A
   re-parse failure is an internal error (exit 3, nothing saved). New
   manifest warnings are printed as for any load.
4. **Affected set.** `apply.Affected(old, new)` → servers whose rendered
   desired bytes differ, in manifest order. This includes servers where
   the key is already absent in reality (apply reports them converged).
   Zero affected, or `--no-apply`, skips to step 6 without credentials or
   connections.
5. **Fleet plan.** Apply's preflight and pipeline over the affected
   servers only — flag validation done, known_hosts, `keyfile.Load`,
   `CheckCredentials`, `Held`, audit read, `apply.Build` from the **edited**
   config — rendered under the edit header (below).
6. **Confirm.** Same gate as apply, with two differences:
   - revoke/rotate **always** ask (or need `--yes`), even when every
     affected server is already converged — the manifest edit is itself a
     change;
   - if **every** affected server is refused at plan time (guard, symlink,
     unparseable, …), there is no prompt: exit 1, nothing saved — the
     manifest never records a change that cannot land.
   `--dry-run` stops here: exit 0 (or 1 if every server is refused),
   nothing saved.
7. **Save the manifest** in apply's `beforeWrite` hook (after the guard
   re-run that follows the prompt, before the first remote write):
   - **CAS:** re-read the file; its bytes must equal step 2's. Otherwise
     exit 3, nothing saved or written: `manifest sshepherd.yaml changed
     since it was read; re-run`.
   - **Atomic:** write a temp file in the same directory (`O_EXCL`,
     same mode as the original), `fsync`, rename over the manifest,
     `fsync` the directory. A symlinked manifest path is resolved and its
     target replaced; the link is left intact.
   - A failed save is exit 3 with no remote writes.
8. **Writes** exactly as apply. If some servers fail, refuse or are
   unreachable: exit 1, and the summary ends with
   `manifest updated; 2 servers not converged — run 'sshepherd apply' to finish`.

**Why save before writing.** Saving after the writes leaves a crash
window where servers are revoked but the manifest still grants the key;
the next routine `apply` would reinstall it. Saving first makes the worst
case "manifest ahead of the fleet" — reported by `audit` as drift and
finished by any `apply`.

**Ctrl-C.** Before step 7: exit 3, nothing saved or written. After step 7:
apply's semantics (started writes finish, no new ones start); the manifest
stays saved.

**`--no-apply`:** steps 1–4, the edit header (with the affected-server
count, no fleet plan), confirm, save. No connections, no credentials.
`--dry-run --no-apply` prints the header only.

### Edit header

Printed above the per-server plan (and alone under `--no-apply`). Real
strings come from the golden `internal/apply/testdata/edit_header*.golden`;
shapes:

```
manifest edit: remove user alice (2 keys, 3 access grants) — 3 servers affected
manifest edit: remove key SHA256:… from bob — 2 servers affected
note: bob has no keys left — 'sshepherd revoke bob' removes the user
manifest edit: rotate deploy key SHA256:old… → SHA256:new… — 5 servers affected
OPERATOR: ops-bot is an operator (fleet-wide, protected); --operator given
```

## Packages

### `internal/manifest` — removal and replacement

New methods on `*File`, each editing the node tree in place and
re-validating via `Config()` refresh after `Encode` (callers re-parse):

- `RemoveUser(name string) (UserRemoval, error)` — `UserRemoval{Keys,
  Grants int}`; removes the `users:` item and every `access:` item whose
  `user:` scalar equals `name`.
- `RemoveKey(fp string) (owner string, lastKey bool, err error)` — finds
  the `keys:` item by **parsed fingerprint** (options, comments and
  spacing are irrelevant).
- `ReplaceKey(user, oldFP, newLine string) error` — replaces the scalar
  at the same index; the caller has already composed `newLine` (old
  options + new key + chosen comment).
- `SetOperator(user string, on bool) error` — removes the `operator:` key
  when `on` is false.

Rules shared by all edits:

- **Head-comment rescue.** yaml.v3 attaches a comment written above the
  first item of a list (`# --- contractors ---`) to that item. Removing an
  item moves its `HeadComment` to the next sibling (prepended to any it
  already has), or, when it was the last item, to the section key. Line
  and foot comments of the removed item go with it.
- Removing the only item leaves an empty flow sequence (`users: []`,
  `access: []`, `keys: []`).
- Flow- and block-style sequences are both supported.
- The package doc's "nothing existing is … removed" contract is rewritten
  to list the four edits.

### `internal/apply`

- `Affected(old, new *config.Config) []string` — pure; for every server in
  `new` (server lists are unchanged by these edits), compare the rendered
  desired bytes under `old` and `new`; return the names that differ in
  manifest order.
- `EditSummary` + `RenderEditHeader(w, EditSummary, RenderOptions)` with
  goldens (color via the existing palette; plain on non-TTY).
- **Cosmetic debt folded in** (roadmap item): pluralization in report and
  refusal strings ("1 keys installed", "1 non-key lines"); the affected
  goldens are regenerated and the README samples re-copied.

### `cmd/sshepherd`

- `apply.go`: the run body becomes `runApply(ctx, applyRun)` with
  `applyRun{cfg, servers, header, alwaysConfirm, beforeWrite, finishHint}`.
  Plain `apply` passes today's values; its goldens must not change
  (beyond the pluralization fix).
- `edit.go` (new): KEY-argument parsing, the CAS atomic manifest save,
  and shared flag registration with apply.
- `revoke.go`, `rotate.go` (new): steps 1–4 and the header, then
  `runApply`.

## Deliberately deferred (NOT in this slice)

- `revoke USER --server …` (per-server access trimming).
- Staged/overlapping rotation (`--keep-old`).
- Generating keys inside `rotate`; scheduled rotation.
- Moving a key between users.
- `apply --json` plan output.

## Testing (per project policy — all kinds, coverage ≥ 80%)

- **Unit (table-driven):**
  - manifest edits: block and flow sequences; first / last / only item;
    head-comment rescue (to next sibling, to section); last key → `keys:
    []`; operator last key clears the flag; `ReplaceKey` keeps options and
    applies the comment rule; output goldens prove comments survive;
    every edited output re-parses with `config.Parse`;
  - `Affected`: wildcard + `except`, operator fleet-wide grant, user with
    no grants (zero servers), rotation touching only that user's servers;
  - KEY parsing: fingerprint / line / `.pub` / missing path / multi-key
    `.pub` / options on `--new`.
- **Hermetic command tests** (`internal/sshconn/sshtest`): revoke user end
  to end; `--dry-run` and prompt abort save nothing; CAS conflict via a
  seam that rewrites the manifest before the save; every server refused →
  exit 1, nothing saved; partial failure → exit 1 with the finish hint and
  the manifest saved; `--no-apply` makes zero connections; operator
  refused without `--operator`, header line with it; rotating one's own
  key with the new key passed as `--identity`; Ctrl-C before the save →
  exit 3, nothing saved; plain `apply` goldens unchanged.
- **Integration / E2E** (Docker sshd): the E2E loop becomes **adopt →
  apply → revoke --key → audit (0) → rotate → audit (0)** — the
  "distribute → audit → revoke → rotate" flow the testing policy asks for;
  a headless `rotate` with old + new `--identity`.
- **Fuzz:** `FuzzManifestEdit` — RemoveKey / RemoveUser on fuzzed valid
  manifests; the output always re-parses and never contains the removed
  fingerprint. Seed corpus committed.
- goleak `TestMain` in every new test package; `-race`; coverage gate.

## Docs (same commit as the code)

- README: `revoke`/`rotate` rows replace "Not separate commands"; flag
  tables for both (enforced by the help ↔ README test); offboarding /
  lost-laptop and rotation recipes (including headless with
  `--identity`); safety-model note on save-before-write and the
  manifest-fidelity caveat (blank lines/quoting may normalize, visible in
  `git diff`); re-copied pluralization samples.
- CLAUDE.md Status; "Amended by" lines in the apply and operator specs;
  roadmap memory.
