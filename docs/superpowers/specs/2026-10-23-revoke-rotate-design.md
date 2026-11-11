# Design: `revoke` and `rotate`

- **Date:** 2026-10-23
- **Status:** Implemented (2026-10-23) — see
  `docs/superpowers/plans/2026-10-23-revoke-rotate.md`. Approved design
  (brainstorm 2026-10-23), revised after an adversarial three-lens critique
  (safety, feasibility against the code, operator UX), owner-approved.
  Deviations: none from this design. Found and fixed along the way:
  `manifest.Load` accepted an implicit null inside a flow mapping
  (`{name: a, operator, keys: [...]}`) that `Encode`'s self-check then
  rejected; such nulls now re-encode as `null` (also fixes `adopt`/`import
  --merge`).
- **Amends:**
  [apply slice](2026-07-19-apply-slice-design.md) (fulfils the deferred
  "`revoke` / `rotate` UX"; apply's run becomes reusable; plain `apply`
  re-checks the manifest before writing),
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
- **Apply never empties a server**: a server whose desired set is empty
  while keys are installed is refused ("refusing to wipe"), and the guard
  would refuse it anyway (no held key can survive an empty set).
- Confirmation gate: TTY prompt, `--yes`, or `--dry-run`; `--dry-run` and
  `--yes` are mutually exclusive; non-TTY without `--yes` is exit 3.
- Exit codes: 0 converged, 1 a server pending/failed/refused/unreachable,
  3 tool or usage error. `revoke`/`rotate` never return 2.
- Operator protection contract (operator spec, 2026-07-10): stripping an
  operator key requires removing the flag first plus explicit
  confirmation.
- Manifest fidelity contract of `internal/manifest`: comments preserved;
  blank lines and quote styles may normalize. Its structural gate (no
  anchors/aliases, no null entries) stands.
- Credentials: agent and/or `--identity` key files, per the 2026-10-16
  spec, with its order of operations.

## New decisions this spec makes (owner-approved 2026-10-23)

| # | Decision | Choice | Rejected |
|---|---|---|---|
| 1 | Verb scope | **Edit, then apply** in one command; `--dry-run` leaves the manifest untouched; `--no-apply` only edits. | Edit-only (two-step offboarding remains); apply-only overlay (next `apply` reinstalls the revoked key). |
| 2 | Revoke forms | **User** (offboard: user + all their grants) and **key** (one key). | Per-server access trimming (deferred: splitting grants, wildcard→`except:`, emptied grants are invalid). |
| 3 | Operators | **Refused by default** (exit 3 + hint); `--operator` acknowledges and performs the flag change in the same edit; loud `OPERATOR` lines; `--yes` alone never covers it. | Always refuse (forces a hand edit); treat like anyone (weakens the contract). |
| 4 | Rotate shape | **One-step swap** in place; old key dead fleet-wide in that run. | Staged overlap / `--keep-old` (deferred). |
| 5 | Apply scope | **Affected servers only** — servers whose rendered desired file changes; on those, the full render still converges other drift (shown in the plan). Unaffected servers are not contacted, and the output says so. **Amended by [revocation memory](2026-11-08-revocation-memory-design.md) (W4):** the scope stays affected-only, header-only writes stay inside it, and the audit command or `--sweep` replaces the `scope:` hint. | Whole fleet (emergency revocation stalls on unrelated refusals); strict (trivial drift blocks an emergency). |
| 6 | Save point | Manifest saved **once, after confirmation, before the first remote write**, under a local lock with a compare-and-swap. | Save after writes (a crash leaves servers revoked but the manifest granting — the next `apply` reinstalls the key); save-then-rollback (fragile rollback of the source of truth). |

## Command surface

```
sshepherd revoke USER... [--operator]
sshepherd revoke --key KEY [--key KEY]... [--operator]
sshepherd rotate USER --old KEY --new KEY [--operator]
```

Both commands also take these apply flags with apply's defaults and help
text: `--config`, `--known-hosts`, `--parallel`, `--dry-run`, `--yes`, and
the three `--identity` flags (timeouts are not flags). New: `--no-apply`
(edit and save after confirmation; no connections). There is no
`--server`: the scope is computed (decision 5).

### KEY arguments

Accepted forms: for `--key` and `--old`, a `SHA256:` fingerprint, a
public-key line, or a path to a `.pub` file; for `--new`, a key line or a
`.pub` path (a fingerprint carries no key). Classification, in order:

1. Starts with `SHA256:` → fingerprint. The value must be 43 characters of
   unpadded base64 (one trailing `=` is stripped); otherwise exit 3
   `malformed fingerprint`.
2. Matches the `ssh-keygen -l` shape `^\d+ SHA256:\S+( .*)? \([A-Z0-9-]+\)$` (trailing
   whitespace ignored) → the second field is the fingerprint, validated as above. A key
   line whose comment holds ` SHA256:…` is not this shape and falls to step 4 (G020).
3. Starts with `MD5:` or is hex-colon (`aa:bb:…`) → exit 3: `MD5
   fingerprints are not supported — use ssh-keygen -l -E sha256 -f FILE`.
4. Contains whitespace, or starts with a known key type or option →
   **key line**, parsed with `authkeys`. A parse failure reports the parse
   error (`not a valid public key line: …; quote the whole line`), never
   "file not found".
5. Otherwise → **path**. `~/` expands from `$HOME` (as `--identity`
   does); read with a 64 KiB cap; the file must hold exactly one key line
   (blank and `#` lines ignored).

Refusals (exit 3), all naming the argument but **never quoting file
contents**:

- a missing or unreadable path — lists the accepted forms;
- a file whose first non-blank line starts with `-----BEGIN` or
  `PuTTY-User-Key-File`, or contains `PRIVATE KEY`: `PATH is a private
  key — pass the public key (PATH.pub)`;
- a certificate (key type ending `-cert-v01@openssh.com`), as a line or in
  a file, for any of `--key`/`--old`/`--new`: `ARG is an SSH certificate,
  not a public key — pass the plain key (id_ed25519.pub, not
  id_ed25519-cert.pub)`;
- a `.pub` with zero or several key lines.

### Usage rules

All exit 3, before the manifest is read: users and `--key` together; no
target; `rotate` without exactly one USER, one `--old` and one `--new`
(a repeated `--old`/`--new` is refused — `rotate takes exactly one --old
(got 2)` — never resolved to the last value);
`--new` given as a fingerprint; `--dry-run` with `--yes` (mutually
exclusive, as in apply); `--no-apply` with `--identity*`, `--known-hosts`
or `--parallel` (they would be silently unused). `--dry-run --no-apply`
is allowed. A `revoke` USER argument that classifies as a fingerprint or
key line (steps 1–4 above) is exit 3: `ARG looks like a key — did you mean
--key?`.
Amended 2026-11 (P12): the looks-like-a-key check moved after the manifest
read and applies only to unknown names.

### `revoke USER...`

Deletes each user entry and every `access:` entry whose `user:` is that
user. Unknown users → exit 3, all listed. Duplicate names are
de-duplicated silently.

### `revoke --key KEY...`

Removes each key line from its owner (keys are unique across users —
`config` rejects duplicates — so the owner is unambiguous). A key not in
the manifest → exit 3: `KEY is not in the manifest; apply already removes
keys the manifest does not grant — run 'sshepherd audit' to find where it
is installed`. If an owner is left with no keys, the user stays with
`keys: []` (valid for non-operators) and the header says `note: bob has no
keys left — 'sshepherd revoke bob' removes the user`. Duplicate
fingerprints are de-duplicated.

### `rotate USER --old KEY --new KEY`

- `--old` must belong to `USER` — otherwise exit 3 naming the actual
  owner, or "not in the manifest".
- `--new` must not already be in the manifest (exit 3 naming its owner)
  and must differ from `--old`.
- The new line replaces the old at the same index of `keys:`.
- **Options** of the old manifest line carry over (`from=`, `command=`,
  `restrict`, …). Options written on `--new` are exit 3: `rotate keeps the
  old line's options; edit them in the manifest`.
- A carried-over `expiry-time=` that has already passed (at the run's
  start) is exit 3 before any edit: `the old line's expiry-time="…" has
  passed; the new key would be rejected by sshd — update or remove
  expiry-time in the manifest first`. A future one is listed in the
  header (`keeps expiry-time="…"`).
- **Inline comment:** the new key's comment if it has one, else the old
  line's inline comment, else none (`DesiredComment` then falls back to
  `comment:`/`name` as always).
- `operator: true` is kept — a rotation is not a demotion.

### Operators

The check runs over **all** resolved targets before any edit. Any target
that is, or belongs to, an `operator: true` user without `--operator` →
the whole command is refused (exit 3, nothing edited), naming every
operator target in one message: `ops-bot is an operator (fleet-wide,
protected); pass --operator to confirm`. `--operator` when no target is
or belongs to an operator → exit 3: `--operator given but no target is an
operator; drop the flag` (a habitually passed flag would empty the gate).

With `--operator`:

- `revoke USER` removes the user entry (flag included).
- `revoke --key` of an operator's **last** key also clears the flag
  (`operator: true` with no keys fails validation); the header says so.
- `rotate` keeps the flag.
- The header carries an `OPERATOR` line per operator target, and the
  confirmation prompt is prefixed `OPERATOR ops-bot: `.

`--yes` never substitutes for `--operator`. The lockout guard still
applies on top.

## Order of operations

Nothing contacts the network before step 5; nothing writes the manifest
before step 7.

1. **Flags** — usage rules; KEY arguments classified and `.pub` files read.
2. **Load** with `manifest.Load`; keep the exact bytes read and the
   resolved path (`filepath.EvalSymlinks`). A manifest that is not a
   regular file (a pipe: `--config /dev/stdin`, `<(...)`) cannot be saved in
   place → exit 3: `cannot edit PATH: not a regular file — revoke and
   rotate save the manifest in place; pass the manifest file's path`. A
   manifest `manifest.Load` cannot edit (anchors/aliases, null entries, unsupported shapes) → exit 3:
   `cannot edit PATH: REASON — edit the manifest by hand and run
   'sshepherd apply'`.
3. **Edit in memory.** Resolve every target once against the as-loaded
   config (unknown / ownership / duplicate / operator / expiry checks,
   exit 3). Apply all node edits (`SetOperator(user, false)` before
   removing an operator's last key), then `Encode` **once** — its built-in
   `config.Parse` check is the only validation (a failure is an internal
   error, exit 3, nothing saved). The plan, `Affected` and the save all
   use exactly those encoded bytes. New manifest warnings are printed.
4. **Affected set.** `apply.Affected(old, new)` returns:
   - `Servers` — servers whose rendered desired bytes differ, in manifest
     order (including servers where the key is already absent in reality;
     apply reports them converged);
   - `Emptied` — the subset whose desired set is empty under the new config
     but not the old (the revoked user was the server's only grantee).
     Apply never empties a server, so the key **cannot be removed there by
     SSHepherd**; each gets a header warning, before any credentials or
     connections: `warning: db-1 would have no granted keys — apply never
     empties a server, so alice's key stays installed there; grant another
     user (or an operator) on db-1 first, or remove the key by hand`.

   Zero affected, or `--no-apply`, skips to step 6 without credentials or
   connections.
5. **Fleet plan.** Apply's preflight and pipeline over the affected servers
   only — known_hosts, `keyfile.Load`, `CheckCredentials`, `Held`, audit
   read, `apply.Build` from the **edited** config — rendered under the edit
   header. Key preference for every dial (read and write) is the granted
   fingerprints under the **old** config, then under the new one,
   de-duplicated: sessions must authenticate with what is installed now.
   The post-write probe still offers only survivors under the new config.
   Plan rows label a key the edited config no longer owns from the old
   config: `alice (revoked)`, `deploy (rotated out)`.
6. **Confirm.** Apply's gate, with these rules:
   - revoke/rotate **always** ask (or need `--yes`), even when no affected
     server needs a write — the manifest edit is itself a change. Prompt:
     `save manifest edit and write N of M affected servers? [y/N]`;
     `save manifest edit (no servers need a write)? [y/N]` when N = 0;
     `save manifest edit? [y/N]` under `--no-apply`; prefixed with
     `OPERATOR NAME: ` per operator target. A golden pins each form.
   - **Nothing can land** — no affected server is change-planned or
     converged, and at least one is refused — means no prompt, nothing
     saved, exit 1: `nothing saved — alice still has access on N servers;
     fix the refusals and re-run, or record the change without touching
     servers with --no-apply`. Unreachable servers are not refusals: they
     can converge later, so an all-unreachable set still prompts and saves.
   - Declining prints `aborted; manifest not changed, nothing written` and
     exits 1, whatever the plan classes.
   - `--dry-run` stops here, nothing saved, and exits **exactly as `apply
     --dry-run`**: `apply.ExitCode` over the affected plans (0 only when
     every affected server is already converged; 1 when any is pending,
     refused or unreachable), matching the summary's `→ exit N`. Zero
     affected exits 0.
7. **Save the manifest — exactly once per confirmed run.** Where:
   - when at least one server will be written: in `runApply`'s
     `beforeWrite` hook, inside `writePhase` **after the post-prompt held-key
     re-list and before `apply.Execute` starts any worker**;
   - otherwise (zero change plans, zero affected, `--no-apply`): straight
     after confirmation.

   The hook, in order:
   1. ctx cancelled → exit 3, nothing saved or written;
   2. if no change-planned server has a surviving held key under the fresh
      listing (`apply.Survivors`) — e.g. the agent key expired at the
      prompt — and no affected server is converged: nothing saved, exit 1,
      `nothing saved — none of the keys you hold would survive on any
      server (did a key expire after the plan?)`;
   3. the save:
      - **Lock:** `flock(LOCK_EX|LOCK_NB)` on a persistent sidecar
        `DIR/.NAME.sshepherd-lock` (mode 0600, never deleted, so the lock
        survives the rename's inode change), next to the resolved path.
        Held → exit 3 `manifest is being updated by another sshepherd
        run; re-run`.
      - **CAS:** re-read the resolved file; bytes must equal step 2's,
        else exit 3 `manifest PATH changed since it was read; re-run`.
      - **Atomic:** temp file `O_EXCL` in the resolved file's directory,
        `fchmod` to the original's permission bits (not left to umask); if
        the original's uid/gid differ from the process's, `fchown`, and on
        failure exit 3 before the rename (`would change the manifest's
        owner`); write, `fsync`, rename over the resolved path, `fsync`
        the directory (reusing `writeSynced`/`syncDir` from
        `manifest_out.go`); release the lock. A symlink is followed; the
        link itself is left intact.
      - Any save failure → exit 3, `Execute` never called.

   After a successful save, always print: `manifest PATH updated — commit
   and push it: an apply from a copy without this edit re-grants the
   removed key`. The per-server guard re-check inside `Execute` stays
   authoritative. The save itself is not interruptible once the lock is
   taken. **Amended by [revocation memory](2026-11-08-revocation-memory-design.md) (W4):** the save note names the serial, and
   `revoke --key` of an unowned key records a tombstone (D1b).
8. **Writes** exactly as apply. The summary then ends with:
   - if any affected server that a later `apply` could converge is not
     converged (failed, refused for a fixable reason, unreachable, or not
     started after an interrupt): `manifest updated; 2 servers not
     converged — finish with: sshepherd apply --server web3 --server
     web7` (emptied servers are excluded — their warning stands);
   - on any run that removes a key (revoke; rotate's old key): `scope:
     only servers whose grants changed were contacted (N of M); the
     removed key may still be installed elsewhere as drift — run
     'sshepherd audit' to confirm, 'sshepherd apply' to sweep`.

**Why save before writing.** Saving after the writes leaves a crash window
where servers are revoked but the manifest still grants the key; the next
routine `apply` would reinstall it. Saving first makes the worst case
"manifest ahead of the fleet" — reported by `audit` as drift and finished
by any `apply`.

**Ctrl-C.** Before the save: exit 3, nothing saved or written. After it:
apply's semantics (started writes finish, no new ones start); the manifest
stays saved and the finish hint lists the servers not started.

**`--no-apply`:** steps 1–4, the edit header (with the affected-server
count, no fleet plan), confirm, save, then `manifest PATH updated; no
servers contacted — N affected servers still carry the old keys; run
'sshepherd apply --server …' to push`; exit 0. `--dry-run --no-apply`
prints the header only, exit 0.

### Plain `apply` change

A plain `apply` loaded the manifest minutes ago may plan against a version
a concurrent `revoke` has since replaced, and reinstall the revoked key.
`runApply` therefore keeps the bytes it loaded, and plain `apply`'s
`beforeWrite` re-reads the manifest: if it changed, exit 3 `manifest PATH
changed since it was read; re-run`, nothing written. (A residual window
between that check and the writes remains; the remote CAS bounds what a
stale write can overwrite.) A manifest piped in (`--config /dev/stdin`,
`<(...)`) is still accepted, as `audit` accepts it: its type comes from the
opened descriptor (on Linux `/dev/fd/N` links to an unresolvable
`pipe:[N]`, so the path is never resolved), and the re-check is skipped —
a drained pipe cannot be re-read, and nothing can replace it under the
run.

### Edit header

Printed above the per-server plan (and alone under `--no-apply`). Real
strings come from the goldens `internal/apply/testdata/edit_header*.golden`;
shapes:

```
manifest edit: remove user alice (2 keys, 3 access grants) — 3 servers affected
manifest edit: remove key SHA256:… from bob — 2 servers affected
note: bob has no keys left — 'sshepherd revoke bob' removes the user
manifest edit: rotate deploy key SHA256:old… → SHA256:new… (keeps expiry-time="20270101") — 5 servers affected
OPERATOR: ops-bot is an operator (fleet-wide, protected); --operator given
warning: db-1 would have no granted keys — apply never empties a server, …
```

## Packages

### `internal/manifest` — removal and replacement

New methods on `*File` read and edit **only the node tree**; none
validates, and `Config()` stays the as-loaded config (never refreshed).
Callers resolve targets against `Config()` first, apply every edit, then
`Encode` once.

- `RemoveUser(name string) (UserRemoval, error)` — `UserRemoval{Keys,
  Grants int}`; removes the `users:` item and every `access:` item whose
  `user:` scalar equals `name`.
- `RemoveKey(fp string) (owner string, lastKey bool, err error)` — finds
  the `keys:` item by **parsed fingerprint** (options, comments, spacing
  irrelevant); `lastKey` is computed from the `keys:` sequence after the
  removal.
- `ReplaceKey(user, oldFP, newLine string) error` — replaces the scalar at
  the same index; the caller composed `newLine` (old options + new key +
  chosen comment).
- `SetOperator(user string, on bool) error` — removes the `operator:` key
  when `on` is false.

Comment rules (verified against yaml.v3 with a probe):

- **`users:` / `access:` items:** yaml.v3 attaches a comment written above
  the first item of a list (`# --- contractors ---`) to that item's
  `HeadComment`. Removing an item moves its `HeadComment` to the next
  sibling (prepended to any it has); when no item follows, it is
  **appended to the section key's `FootComment`** (emitted right after the
  remaining items). Never prepend to the section key's `HeadComment`, which
  may hold the file header. Line and foot comments of the removed item go
  with it.
- **`keys:` items:** the removed key's head comment is dropped with it — it
  describes that key, and moving it would re-label a surviving key.
- Removing the only item leaves an empty flow sequence (`users: []`,
  `access: []`, `keys: []`); flow- and block-style sequences are both
  supported.
- Load's rejection texts become command-neutral (no "merge does not
  support them"); the package doc's "nothing existing is … removed"
  contract is rewritten to list the four edits.

### `internal/apply`

- `Affected(old, new *config.Config) AffectedSet` — pure;
  `AffectedSet{Servers, Emptied []string}` as in step 4 (server lists are
  unchanged by these edits; compares the rendered desired bytes per
  server).
- `EditSummary` + `RenderEditHeader(w, EditSummary, RenderOptions)` with
  goldens (existing palette; plain on non-TTY).
- `RenderOptions` gains `Former *config.Config`: `label` falls back to it
  for a key the current config does not own (`alice (revoked)`, `deploy
  (rotated out)`). Plain apply leaves it nil.
- **Cosmetic debt folded in** (roadmap item) — singular/plural for every
  count string: `N keys installed`, `N keys and N unparseable lines
  installed`, `N non-key lines`, `N duplicate key lines`, `N unparseable
  line(s)`, `→ N keys desired`. The `plan_mixed*`, `plan_identity` and
  `plan_security*` goldens, the `report_test`/`plan_test` assertions and
  the README samples are regenerated or re-copied.

### `cmd/sshepherd`

- `apply.go`: the run body becomes `runApply(ctx, applyRun)` with
  `applyRun{cfg, former, loadedBytes, servers, preferKeys, header,
  alwaysConfirm, prompt, beforeWrite, finish}`. Plain `apply` passes
  today's values plus the manifest re-check (above); its goldens change
  only by the pluralization fix.
- `edit.go` (new): KEY classification, the locked CAS atomic save, shared
  flag registration with apply.
- `revoke.go`, `rotate.go` (new): steps 1–4 and the header, then
  `runApply`.

## Deliberately deferred (NOT in this slice)

- `revoke USER --server …` (per-server access trimming).
- Staged/overlapping rotation (`--keep-old`).
- Generating keys inside `rotate`; scheduled rotation.
- Moving a key between users.
- Removing a key from an emptied server (would need an apply "wipe" mode,
  which the apply slice rejected).
- `apply --json` plan output.

## Testing (per project policy — all kinds, coverage ≥ 80%)

- **Unit (table-driven):**
  - manifest edits: block and flow sequences; first / last / only item;
    head-comment rescue to the next sibling and to the section footer
    (never above the file header); `keys:` head comments dropped; last key
    → `keys: []`; operator last key clears the flag; `ReplaceKey` keeps
    options and applies the comment rule; several edits then one `Encode`;
    output goldens prove comments survive; every edited output re-parses;
  - `Affected`: wildcard + `except`, operator fleet-wide grant, user with
    no grants (zero servers), rotation touching only that user's servers,
    sole-grantee server → `Emptied`;
  - KEY classification: fingerprint (valid / malformed / padded), pasted
    `ssh-keygen -lf` output, MD5, key line (valid / broken), `~/` path,
    missing path, multi-key `.pub`, certificate, private key (the error
    contains no byte of the file after the BEGIN line), options on
    `--new`, expired / future `expiry-time`;
  - edit header and prompt goldens; `(revoked)` / `(rotated out)` labels.
- **Hermetic command tests** (`internal/sshconn/sshtest`): revoke user end
  to end; every server already converged → prompt, saved, exit 0;
  `--dry-run` exit codes and nothing saved; declined prompt → exit 1,
  nothing saved; CAS conflict via a seam that rewrites the manifest
  before the save; two racing saves → exactly one succeeds; symlinked
  manifest into another directory; 0640 manifest under umask 077 keeps
  its mode; nothing can land → exit 1, nothing saved; sole-grantee server
  → warning, excluded from the hint; partial failure → exit 1, manifest
  saved, `apply --server …` hint; empty held set after the prompt →
  nothing saved, exit 1; Ctrl-C before the save → exit 3, nothing saved;
  `--no-apply` makes zero connections; operator: refused without
  `--operator` (mixed targets: whole command refused, all named),
  `--operator` without an operator target refused, header and prompt
  prefix with it; rotating one's own key with the new key as
  `--identity`; key installed on an ungranted server survives revoke and
  the scope line is printed; plain `apply` refuses when the manifest
  changed before its write; plain `apply` goldens unchanged beyond
  pluralization.
- **Integration / E2E** (Docker sshd): the E2E loop becomes **adopt →
  apply → revoke --key → audit (0) → rotate → audit (0)** — the
  "distribute → audit → revoke → rotate" flow the testing policy asks for;
  a headless `rotate` with old + new `--identity`.
- **Fuzz:** `FuzzManifestEdit` — RemoveKey / RemoveUser on fuzzed valid
  manifests; the output always re-parses and never contains the removed
  fingerprint. `FuzzKeyArg` — classification never panics and never echoes
  file content. Seed corpora committed.
- goleak `TestMain` in every new test package; `-race`; coverage gate.

## Docs (same commit as the code)

- README: `revoke`/`rotate` rows replace "Not separate commands"; flag
  tables for both (`revoke` and `rotate` added to the command lists in
  `TestHelpMatchesREADMETables` and `TestHelpShowsIdentityVarnames`);
  offboarding / lost-laptop and rotation recipes (including headless with
  `--identity`), each ending with **commit and push the manifest** and
  `sshepherd audit`; the emptied-server limitation; the anchors/aliases
  limitation; safety-model notes on save-before-write and plain apply's
  manifest re-check; the manifest-fidelity caveat (blank lines/quoting may
  normalize, visible in `git diff`); re-copied pluralization samples.
- CLAUDE.md Status; "Amended by" lines in the apply, operator and adopt
  `--merge` specs; roadmap memory.
