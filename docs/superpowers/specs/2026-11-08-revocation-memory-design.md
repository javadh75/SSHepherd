# Design: revocation memory and manifest authority

- **Date:** 2026-11-08 (drafted 2026-11-07 in wave W0 of the review-remediation plan)
- **Status:** Draft — awaiting owner decisions (Block 1: D28, D1, D29, D2, D3, D4,
  D4b, D5, D1a, D1b, D1c, D2a, D4a, D4c, D1d, D1e). Nothing here is built until the owner has
  answered every one of them and approved this spec. The W4 plan is written after
  that, against the tree P14 (W3) leaves.
- **Findings:** PRD-1 (HIGH), PRD-2 (MEDIUM), SEC-2 (LOW), SEC-3 (LOW) from the
  2026-11-07 whole-repo review.
- **Plan:** package P04 of `docs/superpowers/plans/2026-11-07-review-remediation.md`
  (spec in W0, implementation in W4).
- **Scope of the implementation (W4):** `internal/config` (schema, validation,
  policy conflicts), `internal/manifest` (top-level gate, two new edits),
  `internal/authkeys` (header with serial, `ParseHeader`), `internal/sshwrite`
  (`.orig` prefix test), `internal/apply` (convergence, serial refusal, scope),
  `internal/adopt`, `internal/reconcile`, `internal/audit` (REVOKED and serial
  rows, JSON), `cmd/sshepherd` (revoke, rotate, apply, adopt, sweep), README,
  CLAUDE.md. File paths below are as of `adee207`; W4 re-targets them to P14's
  layout. README line numbers are as of `85bf49e` (the plan's README line refs are
  older and stale); W4 finds each section by its heading.
- **Amends:** `2026-07-19-apply-slice-design.md` (managed header decision),
  `2026-10-23-revoke-rotate-design.md` (decision 5 and the save note),
  `2026-07-10-adopt-fleet-discovery-design.md` (wildcard compaction),
  `2026-07-16-adopt-merge-design.md` (merge must honour tombstones).

How to read this draft: every design section assumes the **recommended** answer to
each Block 1 question. The decisions table says, for each one, what changes if the
owner picks something else. Wording in `code` quotes is the target text; it becomes
a test expectation and, after W4, README sample output copied from the goldens.

## Context and goal

SSHepherd's promise is "revoke a key everywhere in one command". Today that
promise has no memory:

- **PRD-1 (HIGH).** After `revoke`, nothing records the fingerprint. If a copy of the
  key is still on a server the revoke could not reach (unreachable, refused, a
  sole-grantee server that is never emptied), the next `adopt --merge` adopts it
  again as a new user or extends its former owner, and `audit` shows it only as a
  generic `(unknown) … UNAUTHORIZED` at exit 1.
- **SEC-2.** `revoke` exits 0 while the revoked key may still be installed on
  servers outside the affected set. The only safeguard is the `scope:` hint.
- **PRD-2.** The managed header is a fixed string, so a server cannot tell which
  manifest generation wrote it. `apply --yes` from a stale checkout silently
  re-grants revoked keys. The code says so itself (`editrun.go:168`,
  `defaultSaveNote`).
- **SEC-3.** adopt turns an unknown key found on every server of a 2+ server fleet
  into `servers: ["*"]`, which grants a possibly planted key on every future server.

The goal: a revoke is remembered in the manifest, every tool honours that memory,
monitoring pages while a revoked key still works, an old copy of the manifest
cannot undo a newer revoke, and adopt never widens an unknown key to the future
fleet. All of this stays agentless and never adds a delete path (`prune`), an
override flag (`apply --force`) or a wipe mode, which are on hold.

## What the code does today (grounding, `adee207`)

- **The manifest top level is closed.** `config.Config` has only `users`,
  `servers` and `access` (`internal/config/config.go:56-70`, `KnownFields(true)` at
  `:86`). `manifest.checkTopLevelKeys` also refuses any other top-level key with an
  `UnsupportedError` (`internal/manifest/manifest.go:143-159`). `revoked:` and
  `serial:` need a change in **both** gates, or `revoke` cannot edit a manifest
  that has them.
- **Ownership is the only identity.** `validateUsers` builds `owners` by
  fingerprint (`config.go:146-158`); `OwnerOf` (`:511-514`) is what adopt
  (`adopt.go:77`), reconcile (`reconcile.go:192`), audit labels
  (`report.go:229-238`) and revoke (`revoke.go:174-177`) consult. A removed key is
  indistinguishable from a stranger's key.
- **Revoke never rejects a save because of the fleet.** It saves before the first
  write (`editrun.go:239-251`); unreachable or refused servers "can converge later".
  A sole-grantee server is refused and the key **stays** there
  (`internal/apply/plan.go:170-187`, README "Limitations" under revoke).
- **`revoke --key` of an unowned fingerprint is refused** (`revoke.go:174-177`).
- **The header is used in three places.** `authkeys.Render` writes it
  (`render.go:53-57`); `apply.normalize` skips it when counting non-key lines
  (`plan.go:296`); the remote write script takes the one-time `.orig` backup unless
  the first line **exactly** equals `authkeys.ManagedHeader`
  (`internal/sshwrite/sshwrite.go:205-206`). A variable header breaks that compare.
- **Affected scope is a rendered-bytes diff** (`apply/affected.go:27-51`). A serial
  inside that diff would make every server "affected" by every revoke.
- **Convergence is byte-exact** over the whole file, header included
  (`plan.go:213-221`).
- **adopt has two write paths.** Regenerate mode rebuilds the manifest from structs
  through `manifestOut` (`cmd/sshepherd/manifest_out.go:27-45`), which would
  silently drop `revoked:` and `serial:`; `--merge` appends through
  `internal/manifest`.
- **adopt's wildcard** is `adopt.go:180-184` (the `Wildcard` field at `:24`),
  rendered at `cmd/sshepherd/adopt.go:57-60` and `:100-103`.
- **audit reads `authorized_keys2` only with `[ -s ]`** (`sshconn.go:80-85`); it
  never reads the contents.
- **Exit 2 is audit-only.** README "Exit codes": "`apply`, `revoke` and `rotate`
  never return `2`"; `apply.ExitCode` (`plan.go:590-603`) keeps 2 reserved.

## Owner decisions

Asked one at a time, in this order: **D28 → D1 → D29 → D2 → D3 → D4 → D4b → D5 →
D1a → D1b → D1c → D2a → D4a → D4c → D1d → D1e.** Each answer is recorded here with
its date. Until all are answered, W4 waits; no fix wave depends on them. D4c, D1d and
D1e were open points in the first draft; each changes an exit code or whether a
manifest loads, so under the plan's rule ("Technical sub-choices that do not change
what a user sees are decided by the spec author") they are owner questions, asked
after the plan's thirteen.

The **README sections it changes** column names each section by its heading, with
its line at `85bf49e`, for the recommended answer; the alternative column says what
changes instead. The W4 integrator updates exactly these sections in the same
commit, with sample output copied from the goldens.

| # | Question | Recommendation | If the owner says otherwise | README sections it changes | Answer (date) |
|---|---|---|---|---|---|
| **D28** | What should exit 2 mean for apply, revoke and rotate? | **The same as audit: a human must act now on security** (a revoked key is still installed and was seen; a lockout could not be undone). One exit-code table for every command. | Exit 2 stays audit-only: `--sweep` findings become exit 1 with a loud line, and the shared table keeps the "never return 2" sentence. README: Exit codes keeps that sentence; `sshepherd revoke` documents the loud line at exit 1. | **Exit codes** (l.1362): rewritten from the section 8 table, dropping "(code `2` is `audit`-only)" (l.1364-1365) and "`apply`, `revoke` and `rotate` never return `2`" (l.1371). **`sshepherd apply`** JSON paragraph (l.585): "a document is written exactly when the run exits `0` or `1`" widens to 0, 1 or 2 (revoke and rotate share it). | pending |
| **D1** | Should the manifest remember keys you revoked? | **(1) A `revoked:` list in the manifest** (fingerprint, user, date, reason). | (2) a separate file: same entries in `sshepherd.revoked.yaml` next to the manifest, loaded and saved under the same lock (README: the same sections, with `### Revoked keys` describing the side file); (3) docs only: this spec shrinks to D4, D5 and D3 (README: only `sshepherd revoke` **Limitations**, l.1004, warn that a later adopt or import can re-adopt the key). | **The manifest** (l.196): new `### Revoked keys` after `### Comment policy` (l.305); **Validation rules** (l.274): the section 2 shape rules; **Quick start §4. Offboard someone** (l.182): the revoke is remembered; **`sshepherd revoke`** (l.778) and **`sshepherd rotate`** (l.1042): tombstones and `--reason`; **`sshepherd adopt`** (l.526) and **`sshepherd import`** `--merge` (l.469): revoked keys are skipped. | pending |
| **D29** | When the manifest breaks a rule (a revoked key still listed, a hand grant over a revoked server), stop every command or let audit report it? | **audit loads it and reports each conflict as critical (exit 2); apply refuses only the servers involved; `validate` and the commands that save the manifest refuse (exit 3)** — only when the manifest *as saved* still has a conflict, so `revoke --key` of the conflicting key is the fix and saves (was open point 5). | Every command fails to load (exit 3), including scheduled audits. README: Validation rules lists each conflict as a load error; Exit codes' "unloadable manifest" (3) already covers it. | **Validation rules** (l.274): shape errors vs policy conflicts; **`sshepherd audit`** (l.334): the `manifest:` conflict block and JSON `policy_conflicts`; **`sshepherd apply`** (l.558): the conflict refusal; **`sshepherd revoke`** (l.778), **`sshepherd rotate`** (l.1042), **`sshepherd adopt`** (l.526), **`sshepherd import`** (l.469): the save refusal; **Exit codes** (l.1362): audit 2, apply 1, saves 3. | pending |
| **D2** | A revoked key is still on a server: how loud is audit? | **Critical, exit 2.** | Exit 1 with a `REVOKED` label. README: the same audit row at exit 1; Exit codes row 1. | **`sshepherd audit`** (l.334): the `REVOKED` row, JSON `revoked` and `summary.revoked_keys`, copied from the new goldens; **Exit codes** (l.1362): the audit row for 2. | pending |
| **D3** | After a revoke, log in to every server to check the key is gone? Cost of a sweep: every revoke contacts the whole fleet; one unreachable server makes it exit 1; it can't run with `--no-apply`. | **(2) Only with `--sweep`** (that cost is paid only when asked; with D2 a scheduled audit already pages on a revoked key); **otherwise print the exact `sshepherd audit` command.** | (1) always sweep: no flag, every revoke pays the cost above (README: revoke and rotate say every run contacts the fleet, and `--no-apply` cannot prove removal); (3) keep today's `scope:` hint (README: the `scope:` lines stay). | **`sshepherd revoke`** (l.778): the `--sweep` flag row, the `scope:` lines (l.832, l.862) replaced by the printed audit command, JSON `sweep`; **`sshepherd rotate`** (l.1042): the same flag and line; **Quick start §4. Offboard someone** (l.182): the follow-up audit is the printed command; **Exit codes** (l.1362): revoke/rotate 2 (with D28) and 1 for an unreachable sweep. | pending |
| **D4** | Should the manifest carry a serial so an old copy cannot undo newer revokes? | **(1) Yes: apply refuses a server written by a newer serial, except for plans that only remove keys; absurd serials count as forged**, and a forged header is rewritten even when the body matches, a header-only write (was open point 3). | (2) warn only, never refuse (README: apply and audit document a warning; Exit codes unchanged); (3) no serial (rely on git): the header section and D4b, D4a, D4c drop out (README: none of these sections change; Safety model keeps the fixed header). | **`sshepherd apply`** (l.558): the header serial, the stale-serial refusal and its only override (`serial: S`); **Safety model** (l.1374): the quoted header (l.1379) gains the `(serial N)` form; **The manifest**: new `### Serial` after `### Comment policy` (l.305); **`sshepherd audit`** (l.334): the forged-header row and JSON `forged_header_serial`; **Exit codes** (l.1362): apply 1 for a stale serial, audit 2 for a forged header; **Quick start §4. Offboard someone** (l.182): save, push, then apply. | pending |
| **D4b** | A hand edit that removes a key does not bump the serial. Should apply bump it when a confirmed write removes keys? | **Yes, saved through the manifest store**, when the run writes a removal on a server whose header serial is not below the manifest's (M ≤ S). | No: the README says to bump `serial:` by hand after removing a key (in `### Serial` and Quick start §4). Stricter: bump on every confirmed removal not covered by a key tombstone, which closes the known limitation but saves the manifest on more applies (was open point 2). | **`sshepherd apply`** (l.558): the `would bump serial: N → N+1` dry-run line, the save point, and the piped `--config` warning; **The manifest** `### Serial`: when apply bumps it, and the limitation. | pending |
| **D5** | adopt finds an unknown key on every server: write `["*"]`? | **No: always list the servers by name.** | Keep the wildcard, with a louder warning. README: `sshepherd adopt` (l.528-532) must be rewritten to describe the wildcard and its warning, since its current sentence stays false. | **`sshepherd adopt`** (l.526): its text already says unknown keys become new users "with access to exactly the servers where they were found" (l.528-532), which today's code contradicts (`internal/adopt/adopt.go:180-183` emits `["*"]` with a warning). The recommendation makes that sentence true; W4 adds a "never a wildcard" note. | pending |
| **D1a** | `revoke bob --server db-1` leaves no trace. Remember that too? | **Yes: an access tombstone (`user` + `servers`, no fingerprint).** | adopt/import may re-extend bob to db-1. README: `sshepherd revoke` **Limitations** (l.1004) say so. | **`sshepherd revoke`** (l.778): `--server` records an access tombstone; **The manifest** `### Revoked keys`: access entries; **Validation rules** (l.274): their shape rules; **`sshepherd adopt`** (l.526) and **`sshepherd import`** `--merge` (l.469): a revoked (user, server) pair is never re-extended. | pending |
| **D1b** | `revoke --key` of a key no user has: record it instead of refusing? | **Yes: record a tombstone; it writes no server.** | Keep today's refusal (exit 3). README unchanged. | **`sshepherd revoke`** (l.778): an unowned `--key` records a tombstone and writes no server; **Exit codes** (l.1362): "unknown user or key" (3) no longer covers an unowned key. | pending |
| **D1c** | Re-running a revoke for someone already revoked: exit 0 with the apply hint? | **Yes, using the `revoked:` list.** | Keep today's exit 3. README unchanged. | **`sshepherd revoke`** (l.778): the already-revoked note and its exit 0; **Exit codes** (l.1362): "unknown user" (3) excludes an already-revoked user. | pending |
| **D2a** | adopt finds a revoked key: what happens? | **Skip it with a loud warning; adopt's exit code is unchanged** (D8 owns it). | adopt exits 1 when it skipped a revoked key. README: `sshepherd adopt` documents that exit 1. | **`sshepherd adopt`** (l.526): the skipped-revoked warning, exit-code text unchanged; **`sshepherd import`** `--merge` (l.469): the same skip for a tombstoned `.pub`. | pending |
| **D4a** | audit sees a server written by a newer manifest than yours. | **A note on that server, counted as drift (exit 1), naming both serials.** | No note. README: audit and Exit codes unchanged. | **`sshepherd audit`** (l.334): the serial-ahead note and JSON `manifest_serial_ahead`; **Exit codes** (l.1362): the audit row for 1. | pending |
| **D4c** | apply meets a server written by a newer manifest whose body already equals yours: exit 0 or 1? (was open point 4) | **Converged, exit 0, with the note** `written by newer manifest serial S (yours is M): pull the latest manifest`. Nothing would change, and audit still counts it as drift (D4a). | Exit 1 (refused, nothing written), so apply and audit agree as D30 does for `authorized_keys2`. README: the same sections, with exit 1. | **`sshepherd apply`** (l.558): the note and its exit code; **Exit codes** (l.1362): the apply row for 0 (or 1). | pending |
| **D1d** | audit finds bob's key on db-1 after `revoke bob --server db-1` (an access tombstone): drift or critical? (was open point 6) | **Drift, exit 1**, labelled `bob (access revoked 2026-11-08)`. D2 covers key tombstones only; bob is still a trusted user on his other servers. | Critical, exit 2, since the intent was a revocation. README: the same row at exit 2. | **`sshepherd audit`** (l.334): the label row and JSON `access_revoked`; **Exit codes** (l.1362): the audit row for 1 (or 2). | pending |
| **D1e** | A server named in an access tombstone is removed from `servers:`: does the manifest still load? (was open point 7) | **No: a load error** (`revoked[N]: unknown server "NAME"`, exit 3 on every command), so a typo in a tombstone never silently protects nothing. Decommissioning a server means editing the tombstones that name it. | A warning, and the entry is ignored for that server, so decommissioning never breaks a load (D29's reasoning: one stale line should not stop a scheduled audit). README: Validation rules lists it as a warning. | **Validation rules** (l.274): the unknown-server rule; **The manifest** `### Revoked keys`: decommissioning a server; **Exit codes** (l.1362): already covered by "unloadable manifest" (3). | pending |

**Answers already recorded that this design relies on** (plan, "Answers recorded
(2026-11-07)"): **D8** — `adopt --partial` exits 1 when some servers were unreadable;
**D8a** — adopt exits 3 and writes nothing when no server was read; **D30** — apply
refuses (exit 1) a no-grant server whose `authorized_keys2` holds keys; **D31** —
the login probe offers keys in the order later runs use; **D27** — a malformed
`expiry-time` fails the manifest load. D2a leaves D8/D8a's exit codes as they are.

## Design

### 1. Schema (D1, D1a, D4)

```yaml
serial: 7                    # optional; absent = 0. Integer 0..9007199254740991.
users: [...]
servers: [...]
access: [...]
revoked:                     # optional; appended to by tooling; deleting an entry by hand = deliberate un-revoke
  - fingerprint: SHA256:abc…       # key tombstone (D1)
    user: alice                    # optional label: the former owner; need not exist
    date: 2026-11-08               # YYYY-MM-DD, required
    reason: offboarded             # optional free text
  - user: bob                      # access tombstone (D1a): no fingerprint
    servers: [db-1]
    date: 2026-11-08
```

- **Placement.** When a file lacks them, `serial:` is inserted as the **first**
  top-level key and `revoked:` is appended as the **last** top-level key. Existing
  keys keep their order. Every comment in the file is preserved (the edits go
  through `internal/manifest`'s comment-preserving node edits and the one `Encode`
  per run, `editrun.go:170-182`).
- **`internal/config`.** `Config` gains `Serial` (a custom type that accepts only a
  plain `!!int` scalar) and `Revoked []Tombstone`. Validation lives in a new
  `internal/config/revoked.go`, called from `validate()` (`config.go:104-110`).
- **`internal/manifest`.** `checkTopLevelKeys` also allows `serial` and `revoked`
  (`manifest.go:153-154`). If P12's `manifest.Store` adds its own schema gate, it
  allows them too. Two new edits, both comment-preserving:
  - `AddTombstones([]TombstoneEntry) (added int)`: appends entries, creating the
    section at the end. A key entry whose fingerprint is already tombstoned is
    skipped (the earliest entry wins), so a retry never produces a duplicate-
    fingerprint load error.
  - `BumpSerial() (uint64, error)`: `serial: 1` as the first top-level key when
    absent, otherwise N+1. Fails (exit 3, nothing saved) at the upper bound.
- **New accessors:** `(*Config).Revoked(fp string) (Tombstone, bool)`,
  `(*Config).AccessRevoked(user, server string) (Tombstone, bool)`,
  `(*Config).Serial() uint64`, `(*Config).Conflicts() []Conflict`.

### 2. Validation (load errors) and policy conflicts (D29)

**Shape errors stay load errors** (exit 3 everywhere, like any malformed manifest).
Messages, verbatim (`N` is the zero-based index in `revoked:`; `Parse` prefixes
`parse manifest: ` for decode errors as today):

| Rule | Message |
|---|---|
| `serial` is not a plain integer in range | `serial: want an integer from 0 to 9007199254740991, got "VALUE"` |
| fingerprint shape (`SHA256:` + 43 unpadded base64) | `revoked[N]: fingerprint "VALUE" is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)` |
| `servers` on a key entry | `revoked[N]: servers is not allowed on a key entry (SHA256:…); record access with a separate entry that has user and servers` |
| duplicate fingerprint | `revoked[N]: SHA256:… is already revoked by revoked[M]` |
| access entry without `user` | `revoked[N]: an entry without fingerprint needs user and servers` |
| access entry with empty `servers` | `revoked[N]: servers must not be empty` |
| `*` in `servers` | `revoked[N]: servers cannot be "*"; list the servers by name` |
| unknown server (D1e) | `revoked[N]: unknown server "NAME"` |
| missing or bad `date` | `revoked[N]: date "VALUE" is not a YYYY-MM-DD date` (missing: `revoked[N]: date is required`) |
| `user` / `reason` fail `authkeys.RenderTextIssue` (they are printed) | `revoked[N]: user ISSUE` / `revoked[N]: reason ISSUE` |
| `user` / `reason` over 256 bytes | `revoked[N]: reason is B bytes, over the 256-byte limit` (same for `user`) |

**Policy conflicts are not load errors.** `config.Parse` collects them in
`Conflicts()` and returns a usable `*Config`:

- **Revoked key still listed** (any user, operators included):
  `key SHA256:… of user "alice2" is revoked (2026-11-08, alice): remove it from users, or delete the revoked: entry to un-revoke it deliberately`.
  Without a `user` label the parenthesis is `(2026-11-08)`.
- **Explicit grant over an access tombstone** (a non-wildcard `access:` entry that
  names a server in a tombstone for the same user):
  `user "bob" is granted "db-1" by access[N], but revoked[M] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately`.
  A wildcard grant over a tombstoned server is not a conflict when `except:` lists
  that server (what `revoke --server` writes, `internal/manifest/edit.go:346-377`);
  a wildcard without that `except:` **is** a conflict with the same wording.

`Conflict` carries `{Kind: "revoked_key" | "revoked_access", Message, User,
Fingerprint, Servers []string}`; `Servers` is every server the conflicting key or
grant would render on.

How each command treats conflicts:

- **`audit`** loads the manifest, prints every conflict as critical, marks each
  server in `Servers` critical, and exits 2. A conflict with no servers (a user
  with no grants) is still printed and still exits 2.
- **`apply`** (and the apply phase of revoke/rotate) refuses every server in a
  conflict's `Servers`: nothing is written there, the refusal text is the conflict
  message, and the rest is planned normally. A revoked key is never installed.
  Exit 1 (an ordinary refused plan).
- **`validate`** (D25, when it lands) and every command that **saves** the manifest
  (revoke, rotate, `adopt --merge`, `import --merge`, regenerate-mode `adopt`)
  refuse with the conflict text, exit 3, when the manifest **as it would be saved**
  still has a conflict. An edit that resolves every conflict is allowed, so
  `revoke --key SHA256:…` of the conflicting key is the natural fix and saves. A
  `rotate --new` of a tombstoned key is refused by the same rule.
- D4b's serial-only save (section 6) is exempt: it changes nothing but `serial:`,
  and the conflicting servers are refused anyway.

### 3. The managed header carries the serial (D4, D4c)

- **Render.** `authkeys.Render(entries, serial uint64)`.
  - `serial == 0`: the existing header, **byte for byte**:
    `# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.`
    Fleets that never revoke see no churn on upgrade, and the apply goldens do not
    change.
  - `serial > 0`:
    `# Managed by SSHepherd (serial 7). Manual edits will be overwritten by 'sshepherd apply'.`
- **Parse.** `authkeys.ParseHeader(firstLine string) (serial uint64, managed bool)`,
  in a new `internal/authkeys/header.go`. The first line is remote-controlled input,
  so the match is strict:

  ```
  ^# Managed by SSHepherd(?: \(serial ([1-9][0-9]{0,15})\))?\. Manual edits will be overwritten by 'sshepherd apply'\.$
  ```

  The captured digits must also be ≤ 9007199254740991, or the result is `(0,
  false)`. Legacy header → `(0, true)`; `(serial 7)` → `(7, true)`; `(serial 07)`,
  `(serial 0)`, `(serial -1)`, a trailing space or `\r`, 17 digits → `(0, false)`.
  A `FuzzParseHeader` target pins "never panics" and
  `ParseHeader(firstLine(Render(nil, n))) == (n, true)`.
- **Body.** A file's *body* is everything after its first line when that line is a
  managed header (`managed == true`), otherwise the whole content.
- **Scope ignores the header.** `apply.Affected` renders both sides with serial 0,
  so a serial bump never widens the affected set.
- **Non-key line count ignores any managed header** (`plan.go:296` uses
  `ParseHeader` instead of the exact compare).
- **`.orig` backup.** The remote script's exact first-line compare
  (`sshwrite.go:205-206`) becomes a prefix test, so a serial-headed file never
  takes a fresh `.orig`:
  `case "$(head -n 1 "$p")" in '# Managed by SSHepherd'*) ;; *) take .orig ;; esac`.
  (P11 rewrites this script in W2; W4 applies the prefix test to P11's version.)

**Convergence and refusal.** `S` is the server's header serial (from
`ParseHeader`; a non-managed or legacy first line gives "no serial"), `M` is the
manifest's serial. Apply plans each server by the first matching row:

| Server serial S vs manifest serial M | Bodies | Plan |
|---|---|---|
| S > M + 1000 | any | **Forged header.** audit: critical (exit 2), `header claims serial S, far above this manifest's M — someone edited this file`. apply: treats the server as having no serial, warns `header claims serial S, far above this manifest's M — treated as no serial`, and always plans a write (a header-only write when the bodies are equal), rendered with M. A forged header can never block a write. |
| M < S ≤ M + 1000 | equal | Converged (exit 0, D4c), with the note `written by newer manifest serial S (yours is M): pull the latest manifest`. |
| M < S ≤ M + 1000 | the render **only removes** (below) | **Proceeds** with the warning `written by newer manifest serial S; this write only removes keys, so it proceeds`. The header keeps **S** (the written file says `serial S`), so the write never lowers the server's serial. |
| M < S ≤ M + 1000 | otherwise | **Refused**: `written by manifest serial S, this manifest is M — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: S in your manifest (this is the only override)` |
| S == M | equal | Converged. |
| S < M, or no serial | equal | Converged. No header-only write; the next real change carries M. |
| S ≤ M, or no serial | differ | Change, rendered with M. |

*Only removes* means: every key in the render is installed on the server with the
same fingerprint **and** the same option list, and no key is added. Comments, order
and non-key lines may differ, and moving aside `authorized_keys2` counts as a
removal. Loosening a kept key's options (dropping `from=`, `command=`, `restrict`)
is a grant, so it is not removal-only.

Only servers that a bump actually changes (the affected set) carry the new serial,
and those are exactly the servers a stale copy would re-grant on. An unaffected
server keeps its older header; a stale copy renders the same body there, so it
cannot re-grant anything.

### 4. revoke and rotate write memory and bump the serial (D1, D1a, D1b, D1c, D4)

- **`revoke USER...`** (`planRevokeUsers`, `revoke.go:133-162`): one key tombstone
  per removed key, `{fingerprint, user: USER, date, reason}`.
- **`revoke --key KEY...`** (`planRevokeKeys`, `:168-218`): one key tombstone per
  key, labelled with its owner.
- **`revoke USER... --server NAME...`** (`planRevokeAccess`, `:224-252`, D1a): one
  access tombstone per user, `{user, servers: [the servers removed from an explicit
  list], date, reason}`. A server that only gained an `except:` entry needs none
  (the `except:` already remembers it), so a user trimmed only from a wildcard gets
  no access tombstone.
- **Plain `rotate`** (`rotate.go:144-146`): tombstones the old key with
  `reason: rotated out` unless `--reason` is given. **`rotate --keep-old`**
  tombstones nothing; the finishing `revoke --key OLD` does.
- **Serial.** Every revoke and rotate run that saves calls `BumpSerial` once
  (keep-old too: a stale copy would otherwise remove the new key on the affected
  servers, which the keep-old save note already warns about).
- **`--reason TEXT`** on revoke and rotate: optional, default empty; must pass
  `RenderTextIssue` and the 256-byte cap (usage error, exit 3, before the manifest
  is read). The date is the run's clock in UTC (`now.UTC().Format("2006-01-02")`),
  read through the injected clock (the `rotateNow` seam, `rotate.go:17-18`), so
  goldens stay stable.
- **D1b — unowned `--key`.** Instead of the error at `revoke.go:176`,
  `planRevokeKeys` appends a key tombstone without a `user` label. The affected set
  is empty, so the run takes `saveOnly` (`editrun.go:209-213`) and then prints the
  audit command (or runs the sweep with `--sweep`). A fingerprint that is already
  tombstoned and owned by nobody is a no-op: `SHA256:… was already revoked (DATE)`,
  nothing saved, exit 0.
- **D1c — repeated revoke.** `revoke USER` where USER is not in `users:` but a key
  tombstone carries `user: USER` exits 0 with
  `USER was already revoked (DATE); run 'sshepherd apply' to converge any server that still has the key`
  (DATE is the latest such tombstone; the apply command carries the run's own flags
  through P06's hint helper). With several users, the already-revoked ones get the
  note and the rest are revoked as usual; a name that was never revoked keeps
  today's exit 3. The same applies to `revoke USER --server NAME` when the pair is
  not granted but an access tombstone records it.
- **Save note.** `defaultSaveNote` (`editrun.go:168`) becomes
  `an apply from a copy without this edit is refused on the servers this edit wrote (serial N)`.
- **Conflicts.** The edited manifest's `Conflicts()` must be empty before saving
  (section 2).

### 5. Consumers honour tombstones (D1, D1a, D1d, D2, D2a, D4a, D5)

- **adopt** (`adopt.Build`, `adopt.go:76-104`). Before `OwnerOf`:
  `key SHA256:… on web-2 is REVOKED (2026-11-08, alice) — not adopted; run 'sshepherd apply --server web-2' to remove it`
  and the key is skipped. Before an extension, an access tombstone for that
  (owner, server) skips it with
  `key SHA256:… of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`,
  mirroring the `ExceptCarveOut` branch at `:78-83`. adopt's exit code is unchanged
  (D2a; D8/D8a own it).
- **adopt regenerate mode** round-trips `serial` and `revoked` through
  `manifestOut` (`manifest_out.go:41-45`). Without this, a plain `adopt` erases all
  revocation memory; it gets a dedicated test.
- **reconcile** (`import --merge`, `reconcile.go:183-251`): the same two checks. A
  tombstoned incoming `.pub` is skipped with a warning, and a tombstoned
  (user, server) pair is never extended. Fresh `import` (no `--merge`) has no
  manifest and is unchanged.
- **audit, text.** `criticalDrift` (`report.go:257-268`) is also true for any
  `Diff.Unauthorized` key with `cfg.Revoked`. The row becomes
  `‼ alice (REVOKED 2026-11-08)  SHA256:…  ssh-ed25519  installed but REVOKED (CRITICAL: revoked key)`;
  an unlabelled tombstone shows `(REVOKED 2026-11-08)`. A key of a user found on a
  server that an access tombstone removed from that user (D1d) keeps today's
  unauthorized row and severity (drift, exit 1), with the owner label widened to
  `bob (access revoked 2026-11-08)`:
  `⚠  bob (access revoked 2026-11-08)  SHA256:…  ssh-ed25519  installed but UNAUTHORIZED`.
  Policy conflicts print in a
  block before the per-server sections, one
  `‼ manifest: MESSAGE (CRITICAL: policy conflict)` line each. The D4a note is
  `written by manifest serial 8, yours is 7 — pull the latest manifest` (drift).
  A forged header prints the section 3 line as critical.
- **audit, JSON** (schema stays 1, every field additive and omitted when unset):
  - `jsonKey.revoked: {"user": "alice", "date": "2026-11-08", "reason": "offboarded"}`
    on an unauthorized key that is tombstoned (`user`/`reason` omitted when empty);
  - the server's `status` is `critical`;
  - `jsonKey.access_revoked: {"date": "2026-11-08", "reason": "…"}` on an
    unauthorized key whose owner's access to that server is tombstoned (D1d;
    `reason` omitted when empty); the server's `status` stays `drift`;
  - `summary.revoked_keys`: installed tombstoned keys across servers;
  - `summary.policy_conflicts` and a top-level
    `policy_conflicts: [{"kind", "message", "servers"}]`;
  - per server `manifest_serial_ahead: S` (D4a, drift) and
    `forged_header_serial: S` (critical).
- **D5.** Delete the wildcard compaction (`adopt.go:180-184`), the `Wildcard`
  field (`:24`) and both renderer branches (`cmd/sshepherd/adopt.go:57-60`,
  `:100-103`). An unknown key found on every server is granted those servers by
  name. No `--wildcard` flag.

### 6. apply bumps the serial after a hand removal (D4b)

When a confirmed `apply` will write, on some server, a body that removes keys
compared with that server's current body, and the manifest's serial is not above
that server's header serial (M ≤ S), apply bumps `serial:` once for the run:

- through P12's `manifest.Store` (its lock and compare-and-swap), saved after the
  prompt and before the first write, the same point revoke saves; a failed save is
  exit 3 with nothing written;
- every server written in that run is rendered with the new serial;
- `--dry-run` prints `would bump serial: N → N+1 (this apply removes keys)` and
  saves nothing;
- a piped `--config` cannot be saved: apply warns
  `removing keys without a serial bump: an older copy could re-grant them` and
  proceeds.

### 7. Post-revoke sweep (D3: opt-in `--sweep`)

- **Without `--sweep`**, revoke and rotate replace the `scope:` line
  (`printScope`, `editrun.go:383-386`) with the exact follow-up, carrying the run's
  own flags (P06 helper):
  `check every server: sshepherd audit --config PATH [--known-hosts …] [--identity …]`.
  With D2, that audit exits 2 while the key is installed anywhere.
- **With `--sweep`** (new flag on revoke and rotate; new `cmd/sshepherd/sweep.go`):
  - runs after `finishEdit` on a confirmed run, and after a `saveOnly` that added a
    tombstone (D1b); skipped under `--dry-run` and `--no-apply` (they contact no
    server by contract), where the audit command above is printed instead;
  - reuses the run's known_hosts, credentials and `--parallel`, and calls
    `audit.Run` over **every manifest server except affected servers this run
    applied and verified or found converged**;
  - keeps only `Diff.Unauthorized` keys whose fingerprint is in **this run's** new
    key tombstones (an access tombstone only names servers the run already wrote,
    so it adds no extra servers);
  - **also reads `authorized_keys2`** on servers whose managed path is the default
    (the same condition as `SecondaryKeysCmd`): `cat` with the managed read's size
    cap, parsed, matched against the new tombstones, and reported as
    `REVOKED KEY STILL INSTALLED (authorized_keys2)`. A keys2 that exists but
    cannot be read or parsed gives `cannot prove removal on db-2 (authorized_keys2 unreadable)`,
    exit 1, never 0.
- **Output.**
  `REVOKED KEY STILL INSTALLED: alice SHA256:… on db-2, db-7 — run 'sshepherd apply --server db-2 --server db-7'`.
  A sole-grantee (emptied) server gets
  `REVOKED KEY STILL INSTALLED: alice SHA256:… on db-9 — remove it by hand or grant another user there first`
  (no wipe mode). The run ends with `swept N of M servers: K still have a revoked key, U unreachable`.
- **JSON.** The revoke/rotate document gains a top-level
  `sweep: {"checked": N, "still_installed": [{"server", "fingerprint", "user", "file"}], "unreachable": [..], "unprovable": [..]}`
  (present only with `--sweep`), and `edit` gains `serial` (the new value) and
  `revoked` (the tombstones this run added). Additive; schema stays 1.
- **Exit precedence with `--sweep`:** tool error 3 > sweep found a revoked key 2 >
  not converged, sweep unreachable or unprovable 1 > 0.
- The sweep only reads. It is not `prune`.

### 8. Exit codes (one shared table, D28)

The first wave that lands an exit-2 row (W4, together with P08/D10 when that lands)
rewrites README "Exit codes" from this table and drops "apply, revoke and rotate
never return 2". The revoke/rotate `--json` contract ("a document only on exit 0 or
1") widens to 0, 1 or 2, as P08 widens apply's.

| Code | audit | apply | revoke / rotate |
|---|---|---|---|
| 0 | compliant | converged (including a newer-serial server with an equal body, with a note: **D4c**) | converged (with `--sweep`: no revoked key found); D1c repeated revoke; D1b no-op |
| 1 | drift; unreachable; **server serial ahead of the manifest (D4a)**; **a key installed where an access tombstone removed it (D1d)** | pending, refused (**stale serial**, **policy conflict**, D30), failed, unreachable | not converged; **sweep unreachable or unprovable** |
| 2 | critical: missing operator key; host key changed or `@revoked`; **revoked key installed (D2)**; **policy conflict (D29)**; **forged header serial** | (P08/D10: lockout not restored — not this spec) | **`--sweep` found a revoked key still installed** |
| 3 | tool error | tool error | tool error; **a save that would keep a policy conflict**; `validate` with a conflict |

## Interactions with on-hold items

- **No `apply --force`.** The serial has no override flag. The only override is
  editing `serial:` in the manifest, which the refusal message names.
- **No `prune`.** The sweep only reads; D1b writes no server; nothing removes an
  unowned key fleet-wide.
- **No wipe/empty-server mode.** A sole-grantee server stays a by-hand fix and the
  sweep says so.
- **No scheduled rotation, key generation, `move-key`, `import --prefer`.** Untouched.

## Threat notes

- **A hostile server can claim any serial.** Above M + 1000 it counts as forged:
  audit exits 2 and apply ignores it and rewrites the header. Within the bound it can
  only refuse writes that **add** or loosen access on that same server; a
  removal-only write still proceeds, so no header can stop an emergency revoke of
  the attacker's own key.
- **The header is parsed with an anchored regexp and a range check**, never
  evaluated; it gets a fuzz target.
- **Tombstone `user` and `reason` are printed**, so they pass `RenderTextIssue` and
  a 256-byte cap at load and at `--reason`.
- **Remote content never writes manifest authority.** adopt and import never copy a
  server's header serial into the manifest.

## Known limitations (said plainly in the README in W4)

- A hand edit does not bump the serial by itself; D4b covers it only when apply
  writes a removal on a server whose header serial is not below the manifest's. A
  server still at an older header when the hand removal is applied gets the
  current serial, so a copy taken at that same serial (after the last bump, before
  the hand edit) can still re-grant there. See D4b (open point 2).
- Two branches that each bumped to the same serial cannot be told apart; git
  discipline stays the control for that case. A content hash was rejected as noise.
- The sweep reads `authorized_keys2` only on the default path.
- Deleting a `revoked:` entry by hand is a deliberate un-revoke and is not audited
  beyond git history.

## Amendments to earlier specs (applied when this spec is approved)

- **`2026-07-19-apply-slice-design.md`, "Managed header" row (line 76):** the header
  is fixed only at serial 0; above 0 it names the serial, and convergence compares
  bodies plus the serial table in section 3.
- **`2026-10-23-revoke-rotate-design.md`, decision 5 and the save note
  (lines 62, 280-295):** the affected-only scope stays; the `scope:` hint is replaced
  by the audit command or `--sweep`; the save note names the serial; `revoke --key`
  of an unowned key records a tombstone (D1b).
- **`2026-07-10-adopt-fleet-discovery-design.md`, "Access" (line 124):** no wildcard
  compaction; revoked keys are skipped with a warning.
- **`2026-07-16-adopt-merge-design.md`:** merge honours key and access tombstones,
  and regenerate mode round-trips `serial`/`revoked`.

## Dependencies on other packages

| Package | What this design uses |
|---|---|
| P05 (W1) | the authkeys option table (removal-only test compares option lists); `config.go`, `adopt.go`, `plan.go` change first |
| P06 (W1) | the hint helper that carries the run's flags; `Example:` blocks; the "keeps access to N other servers" line |
| P07 (W1) | audit's `(unknown)` comment column and renderer changes; follow-up: label former owners `alice (revoked)` |
| P08 (spec, W1) | apply exit 2 for `lockout_unrestored` shares this table; the apply `--json` widening |
| P11 (W2) | the rewritten write script that gets the `.orig` prefix test |
| P12 (W2) | `manifest.Store` (lock + compare-and-swap) for D4b; its schema gate must allow `serial`/`revoked` |
| P13 (W2) | `make fuzz` discovers `FuzzParseHeader`; no Makefile edit |
| P14 (W3) | `internal/fleet` / `internal/workflow` layout the W4 plan targets |

## Testing (W4, failing first)

- **Schema (config, manifest):** `TestRevokedRejectsOwnedKey` is replaced by
  `TestConflictsAreReportedNotFatal` (a listed tombstoned fingerprint parses and
  `Conflicts()` names it with the verbatim message), `TestRevokedFingerprintShape`,
  `TestAccessTombstoneConflictsExplicitGrant`, `TestSerialNegativeRejected`,
  `TestLoadAllowsSerialAndRevoked`, `TestBumpSerialCreatesFirstKey` (golden),
  `TestAddTombstonesPreservesComments`, `TestAddTombstonesSkipsKnownFingerprint`,
  fuzz seeds with tombstones and serials.
- **Header:** `TestRenderSerialZeroIsLegacyBytes`, `TestRenderSerialHeader`,
  `TestParseHeader` (the table in section 3), `FuzzParseHeader`, and an sshwrite
  script test that a `(serial 9)` file takes no `.orig`.
- **Pure consumers:** `TestBuildSkipsRevokedKey`, `TestBuildHonoursAccessTombstone`,
  `TestBuildNeverWildcards`, `TestReconcileSkipsRevokedPub`,
  `TestPlanRefusesNewerServerSerial`, `TestPlanRemovalOnlyProceedsOnNewerSerial`
  (header keeps S), `TestPlanRemovalOnlyRejectsLoosenedOptions`,
  `TestPlanForgedSerialTreatedAsNone` (header-only write),
  `TestPlanConvergedOnOlderSerialSameBody`, `TestAffectedIgnoresSerialBump`,
  `TestPlanRefusesConflictServers`.
- **audit:** `TestExitCodeRevokedKeyIsCritical` (2), `TestStatusSerialAheadIsDrift`
  (1), `TestForgedSerialIsCritical` (2), `TestPolicyConflictIsCritical` (2),
  `TestStatusAccessTombstoneIsDrift` (1, D1d label), and
  `report_revoked*` / `report_serial_ahead*` goldens (text and JSON).
- **cmd:** `TestRevokeWritesTombstoneAndBumpsSerial`,
  `TestRevokeUnownedKeyRecordsTombstone`, `TestRotateTombstonesOldKey`,
  `TestRevokeSweepFindsStrayExit2`, `TestRevokeSweepFindsKeyInKeys2`,
  `TestRevokeWithoutSweepPrintsAuditCommand`, `TestRevokeAlreadyRevokedExits0`,
  `TestApplyBumpsSerialOnHandRemoval`, `TestSweepSkippedOnDryRunAndNoApply`,
  `TestAdoptRegenerateKeepsRevokedAndSerial`, `TestAdoptMergeNoWildcard`,
  `TestSaveRefusedWhileConflictRemains`, `TestRevokeKeyResolvesConflict`.
- **E2E (written first against the post-W3 tree, where they must FAIL):**
  `TestE2ERevokeNoResurrect` (adopt → apply → `revoke alice` with one server pointed
  at a closed port → `adopt --merge` on the real port → alice's fingerprint absent
  from `users:` and the warning names it → audit exits 2 → `apply --server` → audit
  exits 0), `TestE2EStaleManifestRefused` (old copy → revoke → `apply --yes --config
  <old copy>` → exit 1 with the serial refusal, server bytes unchanged),
  `TestE2EStaleManifestAfterHandEdit` (D4b).
- **Integration:** a serial-header `.orig` case in the sshwrite matrix.

Acceptance after W4: `make check`, `make integration`,
`make fuzz-list | grep -q FuzzParseHeader`, `make fuzz`, and the three E2E tests
pass. The implementation outline (W4a schema + header + failing E2E lane; W4b
consumers, audit, cmd) is in the plan, P04 "Implementation outline".

## Open points for spec approval

Technical choices the author made where the plan's sketch was silent or, on a
close read, unsafe. A point that changes an exit code, whether a manifest loads, or
when a command refuses or saves is not an author choice (plan: "Technical
sub-choices that do not change what a user sees are decided by the spec author"),
so points 2–7 now sit in the owner decisions above: 2, 3 and 5 inside the rows of
the decision they refine, and 4, 6 and 7 as decisions of their own. Points 1 and 8
change no exit code, refusal or load; the owner may still change them at spec
approval. Numbering is kept so earlier references stay valid.

1. **A removal-only write on a newer-serial server keeps the server's serial S**
   (the sketch said "proceeds with M"). Writing M would lower the header, and a
   second stale copy at M with the revoked key would then pass `S == M` and re-grant.
2. **D4b condition** — part of owner decision **D4b** (its row names the stricter
   alternative). Default: the plan's rule (bump when a removal is written and
   M ≤ S). Stricter alternative: bump whenever a confirmed write removes a key that
   is not covered by a key tombstone, closing the limitation above at the cost of a
   manifest save on more applies (including plain drift clean-ups).
3. **A forged header with an equal body gets a header-only write** — part of owner
   decision **D4** (its recommendation states it). The sketch's "treated as no
   serial" would leave it converged, and audit would page forever with no tool-side
   fix.
4. **A newer-serial server with an equal body** — now owner decision **D4c**
   (apply exit 0 with a note, or exit 1; README `sshepherd apply` and Exit codes).
5. **Saving commands refuse only if the manifest as saved still has a conflict** —
   part of owner decision **D29** (its recommendation states it), so `revoke --key`
   can fix a conflict (refusing on the loaded manifest would block the natural fix).
6. **Access tombstones in audit** — now owner decision **D1d** (drift exit 1 with
   the `bob (access revoked 2026-11-08)` label, or critical exit 2; README
   `sshepherd audit` and Exit codes; the label is specified in section 5).
7. **An unknown server in an access tombstone** — now owner decision **D1e** (load
   error, or a warning; README Validation rules, The manifest `### Revoked keys` and
   Exit codes).
8. **Tombstone dates are UTC**, and `--reason` is capped at 256 bytes.

## Out of scope

- `prune`, `apply --force` (or any serial override flag), wipe/empty-server mode,
  key generation and scheduled rotation, `move-key`, `import --prefer` (on hold).
- Import's wildcard compaction (`import.go:100-106`, `reconcile.go:307-311`), which
  comes from the operator's own ssh config, not remote content. Not covered by D5.
- Content hashes or signatures for the manifest, and any server-side enforcement
  (agentless design).
- Labelling plain `apply` remove rows `(REVOKED)` in `internal/apply/report.go`
  (follow-up after P07), and audit's "former owner" label for keys a standalone
  audit sees (follow-up candidate after D1).
