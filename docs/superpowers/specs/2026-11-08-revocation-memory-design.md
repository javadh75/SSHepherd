# Design: revocation memory and manifest authority

- **Date:** 2026-11-08 (drafted 2026-11-07 in wave W0 of the review-remediation plan;
  revised 2026-11-08 with the owner's answers and the W0 verifier's PRD-2 fix)
- **Status:** Implemented (W4, commits eb8d9da schema, 2dbb35f header, 1c337cc apply,
  0e2246a audit, 55791e5 writecmds, 7abd8fa sweep, and the e2e lane commit that records
  this status). Approved by the owner on 2026-11-08 via recorded answers. Every Block 1
  decision (D28, D1, D29, D2, D3, D4, D4b, D5, D1a, D1b, D1c,
  D2a, D4a, D4c, D1d, D1e) is answered and recorded below as final.
- **Findings:** PRD-1 (HIGH), PRD-2 (MEDIUM), SEC-2 (LOW), SEC-3 (LOW) from the
  2026-11-07 whole-repo review.
- **Plan:** package P04 of `docs/superpowers/plans/2026-11-07-review-remediation.md`
  (spec in W0, implementation in W4).
- **Anchors after W2:** line anchors below were refreshed against `cfe22dc`. W2 (P12)
  then replaced `manifestOut` with one encoder from the config types
  (`manifest.Generate`, `internal/manifest/manifest.go`, guarded by a reflection
  round-trip test) and moved every manifest write onto `manifest.Store`. Read
  "round-trips through `manifestOut`" as "`serial`/`revoked` are fields of the config
  types that `manifest.Generate` encodes"; the W4 plan re-anchors everything against
  the tree W3 leaves.
- **Scope of the implementation (W4):** `internal/config` (schema, validation,
  policy conflicts, tombstone warnings), `internal/manifest` (top-level gate, two
  new edits), `internal/authkeys` (header with serial, `ParseHeader`),
  `internal/sshwrite` (`.orig` decision from the plan snapshot), `internal/apply`
  (convergence, header-only writes, serial refusal, scope, JSON), `internal/adopt`,
  `internal/reconcile`, `internal/audit` (REVOKED and serial rows, JSON),
  `cmd/sshepherd` (revoke, rotate, apply, adopt, sweep), README, CLAUDE.md.
- **Code anchors** are as of `cfe22dc` (after W1: P05 moved option logic into
  `internal/authkeys/options.go`, P06 added the `followUp` hint helper in
  `cmd/sshepherd/fleet.go`, P07 changed the audit and apply renderers). W2 (P11's
  write script, P12's `manifest.Store`) and W3 (P14's `internal/fleet` /
  `internal/workflow` layout) still move code; the W4 plan re-targets every anchor
  to that layout. **README line numbers** are as of `cfe22dc`; W4 finds each section
  by its heading.
- **Amends:** `2026-07-19-apply-slice-design.md` (managed header decision),
  `2026-10-23-revoke-rotate-design.md` (decision 5 and the save note),
  `2026-07-10-adopt-fleet-discovery-design.md` (wildcard compaction),
  `2026-07-16-adopt-merge-design.md` (merge must honour tombstones).

Wording in `code` quotes is the target text; it becomes a test expectation and,
after W4, README sample output copied from the goldens.

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
  re-grants revoked keys. The code says so itself (`defaultSaveNote`,
  `cmd/sshepherd/editrun.go:164-166`; the access save note at
  `cmd/sshepherd/revoke.go:249`).
- **SEC-3.** adopt turns an unknown key found on every server of a 2+ server fleet
  into `servers: ["*"]`, which grants a possibly planted key on every future server.

The goal: a revoke is remembered in the manifest, every tool honours that memory,
monitoring pages while a revoked key still works, an old copy of the manifest
cannot undo a newer revoke, and adopt never widens an unknown key to the future
fleet. All of this stays agentless and never adds a delete path (`prune`), an
override flag (`apply --force`) or a wipe mode, which are on hold.

## What the code does today (grounding, `cfe22dc`)

- **The manifest top level is closed.** `config.Config` has only `users`,
  `servers` and `access` (`internal/config/config.go:56-71`, `KnownFields(true)` at
  `:86`). `manifest.checkTopLevelKeys` also refuses any other top-level key with an
  `UnsupportedError` (`internal/manifest/manifest.go:143-159`, the key test at
  `:153-154`). `revoked:` and `serial:` need a change in **both** gates, or
  `revoke` cannot edit a manifest that has them.
- **Ownership is the only identity.** `validateUsers` builds `owners` by
  fingerprint (`config.go:112-158`, the map writes at `:152-157`); `OwnerOf`
  (`:470-473`) is what adopt (`internal/adopt/adopt.go:96`), reconcile
  (`internal/reconcile/reconcile.go:192`), audit labels
  (`internal/audit/report.go:301-310`) and revoke (`cmd/sshepherd/revoke.go:190-195`)
  consult. A removed key is indistinguishable from a stranger's key.
- **Revoke never rejects a save because of the fleet.** It saves after the prompt,
  before the first write (`beforeWrite`, `cmd/sshepherd/editrun.go:241-255`);
  unreachable or refused servers "can converge later". A server left with no grant is
  refused and the key **stays** there (`internal/apply/plan.go:176-193`, README
  `sshepherd revoke` **Limitations**).
- **`revoke --key` of an unowned fingerprint is refused** (`revoke.go:190-195`).
- **The header is used in three places.** `authkeys.Render` writes it
  (`internal/authkeys/render.go:54-56`, the constant at `:11-14`);
  `apply.normalize` skips it when counting non-key lines (`plan.go:303`, a trimmed
  exact compare); the remote write script takes the one-time `.orig` backup unless
  the first line **exactly** equals `authkeys.ManagedHeader`
  (`internal/sshwrite/sshwrite.go:205-206`). A variable header breaks that compare.
- **Affected scope is a rendered-bytes diff** (`internal/apply/affected.go:27-51`).
  A serial inside that diff would make every server "affected" by every revoke. Its
  contract (`:13-15`) says the set includes servers "where reality already matches
  the new render (apply reports them converged)" — the servers the PRD-2 fix below
  must not leave behind.
- **Convergence is byte-exact** over the whole file, header included
  (`plan.go:216-228`).
- **adopt has two write paths.** Regenerate mode rebuilds the manifest from structs
  (`generateAdoptManifest`, `cmd/sshepherd/adopt.go:22-66`) through `manifestOut`
  (`cmd/sshepherd/manifest_out.go:17-45`), which would silently drop `revoked:` and
  `serial:`; `--merge` appends through `internal/manifest`
  (`renderMergedManifest`, `cmd/sshepherd/adopt.go:76-111`).
- **adopt's wildcard** is in `nameUsers` (`internal/adopt/adopt.go:249-253`, the
  `Wildcard` field at `:24`), rendered at `cmd/sshepherd/adopt.go:55-57` and
  `:98-100`.
- **audit reads `authorized_keys2` only with `[ -s ]`**
  (`internal/sshconn/sshconn.go:80-85`); it never reads the contents.
- **Exit 2 is audit-only.** README "Exit codes": "`apply`, `revoke` and `rotate`
  never return `2`"; `apply.ExitCode` (`plan.go:550-565`) keeps 2 reserved.
- **audit's `statusOf`** (`internal/audit/report.go:354-366`) returns `compliant`
  before it checks `criticalDrift` (`:327-339`), so today a key-compliant server
  can never be critical.

## Owner decisions (final)

Asked one at a time, in this order: **D28 → D1 → D29 → D2 → D3 → D4 → D4b → D5 →
D1a → D1b → D1c → D2a → D4a → D4c → D1d → D1e**, and answered on 2026-11-07 (plan,
"Answered 2026-11-07 (second sitting)" and the D4c/D1d/D1e rows after it). Every
answer below is final; agents implement it and do not re-ask. D1e is an **owner
override** of the planner's recommendation.

The **Safe default** column records what would have happened had a question stayed
open (the plan's rule: "W4 waits", i.e. today's behaviour); it is kept so the
decision trail is complete. The **README sections it changes** column names each
section by its heading with its line at `cfe22dc`. The W4 integrator updates exactly
these sections in the same commit, with sample output copied from the goldens.

| # | Question | Answer (final) | Safe default (had it stayed open) | README sections it changes |
|---|---|---|---|---|
| **D28** | What should exit 2 mean for apply, revoke and rotate? | **The same as audit: a human must act now on security** (a revoked key is still installed and was seen; a lockout could not be undone), for every command. One exit-code table in the README. | Exit 2 stays audit-only. | **Exit codes** (l.1481): rewritten from the section 8 table, dropping "(code `2` is `audit`-only …)" (l.1483-1485) and "`apply`, `revoke` and `rotate` never return `2`" (l.1491). **`sshepherd apply`** JSON paragraph (l.659): "a document is written exactly when the run exits `0` or `1`" widens to 0, 1 or 2 (revoke and rotate share it). |
| **D1** | Should the manifest remember keys you revoked? | **A `revoked:` list in the manifest** (fingerprint, user, date, reason). | No memory (today). | **The manifest** (l.211): new `### Revoked keys` after `### Comment policy` (l.330); **Validation rules** (l.292): the section 2 shape rules; **Quick start §4. Offboard someone** (l.194): the revoke is remembered; **`sshepherd revoke`** (l.880) and **`sshepherd rotate`** (l.1157): tombstones and `--reason`; **`sshepherd adopt`** (l.574) and **`sshepherd import`** `--merge` (l.513): revoked keys are skipped. |
| **D29** | When the manifest breaks a rule (a revoked key still listed, a hand grant over a revoked server), should every command stop, or should audit report it? | **audit loads it and reports each conflict as critical (exit 2); apply refuses only the servers involved (exit 1); `validate` and the commands that save the manifest refuse (exit 3)** — only when the manifest *as saved* still has a conflict, so `revoke --key` of the conflicting key is the fix and saves. | No conflicts can exist without D1. | **Validation rules** (l.292): shape errors vs policy conflicts; **`sshepherd audit`** (l.367): the `manifest:` conflict block and JSON `policy_conflicts`; **`sshepherd apply`** (l.632): the conflict refusal; **`sshepherd revoke`** (l.880), **`sshepherd rotate`** (l.1157), **`sshepherd adopt`** (l.574), **`sshepherd import`** (l.513): the save refusal; **Exit codes** (l.1481): audit 2, apply 1, saves 3. |
| **D2** | A revoked key is still on a server: how loud is audit? | **Critical, exit 2.** | No tombstones (today: exit 1, `(unknown)`). | **`sshepherd audit`** (l.367): the `REVOKED` row, JSON `revoked` and `summary.revoked_keys`, copied from the new goldens; **Exit codes** (l.1481): the audit row for 2. |
| **D3** | After a revoke, should SSHepherd log in to every server to check the key is gone? | **Only with `--sweep`; otherwise print the exact `sshepherd audit` command** (with D2, a scheduled audit already pages on a revoked key). | Today's `scope:` hint. | **`sshepherd revoke`** (l.880): the `--sweep` flag row, the `scope:` sentences (l.937, l.970-973) replaced by the printed audit command, JSON `sweep` and `check_command`; **`sshepherd rotate`** (l.1157): the same flag, and the scope sentence at l.1193-1194; **Quick start §4. Offboard someone** (l.194): the follow-up audit is the printed command; **Exit codes** (l.1481): revoke/rotate 2 and 1 for an unreachable sweep. |
| **D4** | Should the manifest carry a serial so an old copy cannot undo newer revokes? | **Yes: apply refuses a server written by a newer serial, except for writes that only remove keys (never blocked); absurd serials count as forged**, and a forged header is rewritten even when the body matches (a header-only write). | Fixed header (today). | **`sshepherd apply`** (l.632): the header serial, the stale-serial refusal and its only override (`serial: S`), header-only writes; **Safety model** (l.1535): the quoted header (l.1540) gains the `(serial N)` form; **The manifest**: new `### Serial` after `### Comment policy` (l.330); **`sshepherd audit`** (l.367): the forged-header row and JSON `forged_header_serial`; **Exit codes** (l.1481): apply 1 for a stale serial, audit 2 for a forged header; **Quick start §4. Offboard someone** (l.194): `revoke` (with its apply phase), then commit and push, then the printed audit (section 3, "Bump scope"). |
| **D4b** | A hand edit that removes a key does not bump the serial. Should apply bump it when a confirmed write removes keys? | **Yes: a confirmed apply that removes keys bumps the serial once and saves the manifest through the locked store**, when the run writes a removal on a server whose header serial is not below the manifest's (M ≤ S) and no planned server is a newer-serial row (2-4). | No bump (today). | **`sshepherd apply`** (l.632): the `would bump serial: N → N+1` dry-run line, the save point, and the piped `--config` warning; **The manifest** `### Serial`: when apply bumps it, and the limitation. |
| **D5** | adopt finds an unknown key on every server: should it write `["*"]`? | **No: always list the servers by name.** | Today's wildcard with a warning. | **`sshepherd adopt`** (l.574): its text already says unknown keys become new users "with access to exactly the servers where they were found" (l.576-580), which today's code contradicts (`internal/adopt/adopt.go:249-253` emits `["*"]` with a warning). The answer makes that sentence true; W4 adds a "never a wildcard" note. |
| **D1a** | Should `revoke bob --server db-1` also be remembered, so a later adopt or import never gives db-1 back? | **Yes: an access tombstone (`user` + `servers`, no fingerprint).** | No trace (today). | **`sshepherd revoke`** (l.880): `--server` records an access tombstone; **The manifest** `### Revoked keys`: access entries; **Validation rules** (l.292): their shape rules; **`sshepherd adopt`** (l.574) and **`sshepherd import`** `--merge` (l.513): a revoked (user, server) pair is never re-extended. |
| **D1b** | `revoke --key` of a key no user has: record it instead of refusing? | **Yes: record a tombstone; it writes no server.** | Refused, exit 3 (today). | **`sshepherd revoke`** (l.880): an unowned `--key` records a tombstone and writes no server; **Exit codes** (l.1481): "unknown user or key" (3) no longer covers an unowned key. |
| **D1c** | Re-running a revoke for someone already revoked: exit 0 with the apply hint? | **Yes (idempotent), using the `revoked:` list.** | Exit 3 (today). | **`sshepherd revoke`** (l.880): the already-revoked note and its exit 0; **Exit codes** (l.1481): "unknown user" (3) excludes an already-revoked user. |
| **D2a** | adopt finds a revoked key: what happens? | **Skip it with a loud warning; adopt's exit code is unchanged** (D8/D8a own it). | No tombstones. | **`sshepherd adopt`** (l.574): the skipped-revoked warning, exit-code text unchanged; **`sshepherd import`** `--merge` (l.513): the same skip for a tombstoned `.pub`. |
| **D4a** | When audit sees a server written by a newer manifest than yours, should it say so, and how loud? | **Yes: a note on that server naming both serials, counted as drift (exit 1).** | No serial. | **`sshepherd audit`** (l.367): the serial-ahead note and JSON `manifest_serial_ahead`; **Exit codes** (l.1481): the audit row for 1. |
| **D4c** | apply meets a server written by a newer manifest whose body already equals yours: exit 0 or 1? | **Converged, exit 0, with the note** `written by newer manifest serial S (yours is M): pull the latest manifest`; audit still counts it as drift (D4a). | No serial. | **`sshepherd apply`** (l.632): the note and its exit 0; **Exit codes** (l.1481): the apply row for 0. |
| **D1d** | audit finds bob's key on db-1 after `revoke bob --server db-1` (an access tombstone): drift or critical? | **Drift, exit 1**, labelled `bob (access revoked 2026-11-08)`. Critical stays for revoked keys (D2). | No access tombstones. | **`sshepherd audit`** (l.367): the label row and JSON `access_revoked`; **Exit codes** (l.1481): the audit row for 1. |
| **D1e** | A server named in an access tombstone is removed from `servers:`: does the manifest still load? | **Yes (owner override, for consistency with D29): a warning, and that entry is ignored for that server — not a load error.** One stale line never stops a scheduled audit. | No access tombstones. | **Validation rules** (l.292): the unknown-server warning; **The manifest** `### Revoked keys`: decommissioning a server leaves a warning until the entry is edited; **Exit codes**: unchanged. |

**Answers already recorded that this design relies on** (plan, "Answers recorded
(2026-11-07)"): **D8** — `adopt --partial` exits 1 when some servers were unreadable;
**D8a** — adopt exits 3 and writes nothing when no server was read; **D30** — apply
refuses (exit 1) a no-grant server whose `authorized_keys2` holds keys; **D31** —
the login probe offers keys in the order later runs use; **D27** — a malformed
`expiry-time` fails the manifest load. D2a leaves D8/D8a's exit codes as they are.
**Owner rule (2026-11-07): every command offers `--json`** — section 9 specifies the
JSON shape of every output this design adds.

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
  per run, `encodeEdit`, `cmd/sshepherd/editrun.go:168-180`).
- **`internal/config`.** `Config` gains `Serial` (a custom type that accepts only a
  plain `!!int` scalar) and `Revoked []Tombstone`. Validation lives in a new
  `internal/config/revoked.go`, called from `validate()` (`config.go:104-110`).
- **`internal/manifest`.** `checkTopLevelKeys` also allows `serial` and `revoked`
  (`manifest.go:153-154`). P12's `manifest.Store` (W2), if it adds its own schema
  gate, allows them too. Two new edits, both comment-preserving:
  - `AddTombstones([]TombstoneEntry) (added int)`: appends entries, creating the
    section at the end. A key entry whose fingerprint is already tombstoned is
    skipped (the earliest entry wins), so a retry never produces a duplicate-
    fingerprint load error.
  - `BumpSerial() (uint64, error)`: `serial: 1` as the first top-level key when
    absent, otherwise N+1. Fails (exit 3, nothing saved) at the upper bound.
- **New accessors:** `(*Config).Revoked(fp string) (Tombstone, bool)`,
  `(*Config).AccessRevoked(user, server string) (Tombstone, bool)` (ignores servers
  the D1e warning names), `(*Config).Serial() uint64`,
  `(*Config).Conflicts() []Conflict`.

### 2. Validation: load errors, warnings, policy conflicts (D29, D1e)

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
| missing or bad `date` | `revoked[N]: date "VALUE" is not a YYYY-MM-DD date` (missing: `revoked[N]: date is required`) |
| `user` / `reason` fail `authkeys.RenderTextIssue` (they are printed) | `revoked[N]: user ISSUE` / `revoked[N]: reason ISSUE` |
| `user` / `reason` over 256 bytes | `revoked[N]: reason is B bytes, over the 256-byte limit` (same for `user`) |

**Warnings (D1e).** A server in an access tombstone that is not in `servers:` is
**not** a load error. It is appended to `config.Warnings` (surfaced on stderr by
every command that loads the manifest, as today, `cmd/sshepherd/fleet.go:132`), and
that entry is ignored for that server — `AccessRevoked` never matches it, and no
conflict is computed for it:

`revoked[N]: unknown server "NAME" — this entry is ignored for it; remove NAME from the entry once the server is gone for good`

An entry whose servers are all unknown is ignored entirely and still loads. If a
server with that name is added back, the entry applies to it again and the warning
disappears. A warning never changes an exit code, never makes a saving command
refuse, and is not a policy conflict.

**Policy conflicts are not load errors.** `config.Parse` collects them in
`Conflicts()` and returns a usable `*Config`:

- **Revoked key still listed** (any user, operators included):
  `key SHA256:… of user "alice2" is revoked (2026-11-08, alice): remove it from users, or delete the revoked: entry to un-revoke it deliberately`.
  Without a `user` label the parenthesis is `(2026-11-08)`.
- **Explicit grant over an access tombstone** (a non-wildcard `access:` entry that
  names a server in a tombstone for the same user):
  `user "bob" is granted "db-1" by access[N], but revoked[M] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately`.
  A wildcard grant over a tombstoned server is not a conflict when `except:` lists
  that server (what `revoke --server` writes, `exceptServers`,
  `internal/manifest/edit.go:346-377`); a wildcard without that `except:` **is** a
  conflict with the same wording.

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
- **`validate`** (D25, a P10 slice after W4) and every command that **saves** the
  manifest (revoke, rotate, `adopt --merge`, `import --merge`, regenerate-mode
  `adopt`) refuse with the conflict text, exit 3, when the manifest **as it would be
  saved** still has a conflict. An edit that resolves every conflict is allowed, so
  `revoke --key SHA256:…` of the conflicting key is the natural fix and saves. A
  `rotate --new` of a tombstoned key is refused by the same rule. Saving commands
  print the refusal on stderr and, under `--json`, no document (the exit-3 rule of
  the apply JSON contract).
- D4b's serial-only save (section 6) is exempt: it changes nothing but `serial:`,
  and the conflicting servers are refused anyway.

See `2026-11-08-audit-trust-posture-design.md` for the `weak_key` conflict kind and its save rule: a save is refused only when it adds a weak key.

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
  so the match is strict and anchored:

  ```
  ^# Managed by SSHepherd(?: \(serial ([1-9][0-9]{0,15})\))?\. Manual edits will be overwritten by 'sshepherd apply'\.$
  ```

  The captured digits must also be ≤ 9007199254740991, or the result is `(0,
  false)`. Legacy header → `(0, true)`; `(serial 7)` → `(7, true)`; `(serial 07)`,
  `(serial 0)`, `(serial -1)`, a trailing space or `\r`, 17 digits → `(0, false)`.
  A `FuzzParseHeader` target pins "never panics" and
  `ParseHeader(firstLine(Render(nil, n))) == (n, true)`.
- **Body.** A file's *body* is everything after its first line when that line is a
  managed header (`managed == true`), otherwise the whole content. Two files have
  *equal bodies* only when the server's first line is a managed header **and** the
  bodies are byte-identical; a file without a managed header never has an equal
  body, so it is written exactly as today.
- **Scope ignores the header.** `apply.Affected` renders both sides with serial 0
  (`renderFor`, `affected.go:45-51`), so a serial bump never widens the affected
  set.
- **Non-key line count ignores any managed header.** `normalize` (`plan.go:303`)
  replaces `t == authkeys.ManagedHeader` with `ParseHeader(t)`'s `managed`, on the
  same trimmed line as today, so a serial header is never reported as a removed
  non-key line.
- **`.orig` backup, decided by `ParseHeader` itself.** The remote script's exact
  shell compare (`sshwrite.go:205-206`) is removed. `sshwrite.Snapshot` gains
  `Managed bool`, set by `SnapshotOf` from `ParseHeader` on the snapshot content's
  first line (the text before the first `\n`). `writeCmdFor` emits the one-time
  `.orig` copy only when `!expect.Managed`. The script's compare-and-swap (exit 46,
  length + POSIX `cksum`) runs **before** the backup step, so the file the script
  backs up is the snapshot the decision was made on: the `.orig` decision is exactly
  `ParseHeader`'s anchored definition, with no shell pattern that could drift from
  it (a prefix glob such as `'# Managed by SSHepherd'*` would treat
  `# Managed by SSHepherd-ish …` or `(serial 07)` as managed and skip the backup of
  a hand-written file). A legacy or `(serial N)` file takes no `.orig`; any other
  first line does. (P11 rewrites this script in W2; W4 applies the snapshot-driven
  decision to P11's version.)

**Convergence and refusal.** `S` is the server's header serial from `ParseHeader`;
a legacy header, a non-managed first line, or an absent file count as **S = 0 (no
serial)**. `M` is the manifest's serial (absent = 0). A run **bumped** when it saves
a higher `serial:` (every revoke and rotate that saves, section 4; an apply that
triggers D4b, section 6). Apply plans each server by the first matching row:

| # | Server serial S vs manifest serial M | Bodies | Plan |
|---|---|---|---|
| 1 | S > M + 1000 | any | **Forged header.** audit: critical (exit 2), `header claims serial S, far above this manifest's M — someone edited this file`. apply: warns `header claims serial S, far above this manifest's M — treated as no serial`, treats S as 0, and always plans a write rendered with M — a header-only write (below) when the bodies are equal, in any run. A forged header can never block a write. |
| 2 | M < S ≤ M + 1000 | equal | **Converged** (exit 0, D4c), with the note `written by newer manifest serial S (yours is M): pull the latest manifest`. |
| 3 | M < S ≤ M + 1000 | the render **only removes** (below) | **Proceeds** with the warning `written by newer manifest serial S; this write only removes keys, so it proceeds`. The header keeps **S** (the written file says `serial S`), so the write never lowers the server's serial. |
| 4 | M < S ≤ M + 1000 | otherwise | **Refused**: `written by manifest serial S, this manifest is M — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: S in your manifest (this is the only override)` |
| 5 | S == M | equal | **Converged** (the files are byte-identical, today's rule). |
| 6 | S < M | equal, the run bumped, and the server is in the bump scope | **Header-only write** carrying M (below). |
| 7 | S < M | equal, otherwise | **Converged**, no write. |
| 8 | S ≤ M | differ | **Change**, rendered with M. |

*Only removes* means: every key in the render is installed on the server with the
same fingerprint **and** the same option list, and no key is added. Comments, order
and non-key lines may differ, and moving aside `authorized_keys2` counts as a
removal. Any change to a kept key's option list is not removal-only — in
particular loosening (dropping `from=`, `command=`, `restrict`; the cases
`authkeys.Loosening` reports, `internal/authkeys/options.go:157`) is a grant. A
non-empty `authorized_keys2` to move aside turns an equal-body row 2 into row 3, and
rows 5 and 7 into today's change (a write rendered with M), exactly as it makes an
otherwise converged server a change today (`plan.go:220-228`).

**Header-only write (the PRD-2 fix).** On an equal-body server, the rendered file
differs from the server's file only in line 1: the old header (legacy, an older
`(serial S)`, or a forged one) becomes the header carrying M. It is planned as an
ordinary change (`ClassChange`, `HeaderOnly: true`, no add, remove, rewrite or
normalize rows) and goes through apply's existing guarded write unchanged — the
lock, the compare-and-swap against the plan snapshot, `.bak`, the in-session verify
and the login probe; the lockout guard sees the same survivors as for any write, and
refuses it on the same terms. It cannot loosen anything:

- every byte after line 1 — each key line, its options, its comment, each non-key
  line — is the server's own, so who can log in, with which key and under which
  restrictions, is unchanged;
- line 1 is a `#` comment, which sshd ignores;
- the only effect is a higher serial in that comment (S < M, or a forged value
  replaced by M), which only narrows what an apply from an older copy may do there
  (rows 2-4); it never lowers a serial, because row 6 requires S < M and row 3 keeps
  S;
- it is not a new write path, an override or a wipe: the bump scope is a subset of
  servers the run already plans, and the file is never emptied.

**Bump scope.** For a revoke or rotate run, the bump scope is exactly its affected
set, `apply.Affected(former, edited)` — the servers its apply phase already plans.
That set includes, by its own contract (`affected.go:13-15`), servers whose reality
already matches the new render. Without row 6 those servers would keep an older
header, and a copy taken before the revoke would pass row 5 or 8 there and re-grant
the revoked key (the hole the W0 verifier found). With row 6, every affected server
the bumping run reaches carries M afterwards — changed servers through their write,
already-converged ones through the header-only write. Those are exactly the servers
where a copy older than M renders a different body. An unaffected server keeps its
older header; a copy one step older renders the same body there, and any server an
earlier bump affected already carries that bump's serial, because serials on a
server never go down (rows 3 and 6). For a D4b apply, the bump scope is the servers
the run writes anyway (section 6); apply has no former manifest to compute an
affected set from, which is D4b's known limitation. A plain apply that did not bump
never plans a header-only write, except to replace a forged header (row 1).

**Report.** A header-only server shows one row in place of key rows:
`  ~  (header)  update header: serial 6 → 7 (keys unchanged)` (`no serial → 7` when
S was 0; `forged serial 9999 → 7` for row 1), and its summary line
`  → N keys desired · header only`. It counts as a change: pending under
`--dry-run`, applied after the write, and in revoke's prompt count. JSON: section 9.

### 4. revoke and rotate write memory and bump the serial (D1, D1a, D1b, D1c, D4)

- **`revoke USER...`** (`planRevokeUsers`, `cmd/sshepherd/revoke.go:146-177`): one
  key tombstone per removed key, `{fingerprint, user: USER, date, reason}`.
- **`revoke --key KEY...`** (`planRevokeKeys`, `:184-235`): one key tombstone per
  key, labelled with its owner.
- **`revoke USER... --server NAME...`** (`planRevokeAccess`, `:241-277`, D1a): one
  access tombstone per user, `{user, servers: [the servers removed from an explicit
  list], date, reason}`. A server that only gained an `except:` entry needs none
  (the `except:` already remembers it), so a user trimmed only from a wildcard gets
  no access tombstone. A wildcard deleted by a trim takes its `except:` with it, so
  every server only that `except:` remembered gets an access tombstone too, with
  this run's date.
- **Plain `rotate`** (`planRotate`, `cmd/sshepherd/rotate.go:107-161`; the
  `ReplaceKey` branch at `:150-152`): tombstones the old key with
  `reason: rotated out` unless `--reason` is given. **`rotate --keep-old`**
  tombstones nothing; the finishing `revoke --key OLD` does.
- **Serial.** Every revoke and rotate run that saves calls `BumpSerial` once
  (keep-old too: a stale copy would otherwise remove the new key on the affected
  servers, which the keep-old save note at `rotate.go:148` already warns about). Its
  apply phase renders with the new serial and plans header-only writes on the
  affected servers that already match (section 3, row 6).
- **`--reason TEXT`** on revoke and rotate: optional, default empty; must pass
  `RenderTextIssue` and the 256-byte cap (usage error, exit 3, before the manifest
  is read). The date is the run's clock in UTC (`now.UTC().Format("2006-01-02")`),
  read through an injected clock (the `rotateNow` seam, `rotate.go:17-18`), so
  goldens stay stable.
- **D1b — unowned `--key`.** Instead of the refusal at `revoke.go:190-195`,
  `planRevokeKeys` appends a key tombstone without a `user` label. The affected set
  is empty, so the run takes `saveOnly` (`editrun.go:211-216`, `:269-296`) and then
  prints the audit command (or runs the sweep with `--sweep`). A fingerprint that is
  already tombstoned and owned by nobody is a no-op:
  `SHA256:… was already revoked (DATE)`, nothing saved, exit 0.
- **D1c — repeated revoke.** `revoke USER` where USER is not in `users:` but a key
  tombstone carries `user: USER` exits 0 with
  `USER was already revoked (DATE); run 'sshepherd apply' to converge any server that still has the key`
  (DATE is the latest such tombstone; the apply command carries the run's own
  non-default flags through `followUp.command`, `cmd/sshepherd/fleet.go:47-81`).
  With several users, the already-revoked ones get the note and the rest are revoked
  as usual; a name that was never revoked keeps today's exit 3. The same applies to
  `revoke USER --server NAME` when the pair is not granted but an access tombstone
  records it. A run in which every target was already revoked saves nothing and
  does not bump.
- **Save note.** `defaultSaveNote` (`editrun.go:164-166`) and the access save note
  (`revoke.go:249`) become
  `an apply from a copy without this edit is refused on the servers this run writes (serial N)`;
  under `--no-apply` the note is
  `servers learn serial N only when an apply writes them; until then a copy without this edit can re-grant there`.
- **Conflicts.** The edited manifest's `Conflicts()` must be empty before saving
  (section 2).

### 5. Consumers honour tombstones (D1, D1a, D1d, D2, D2a, D4a, D5)

- **adopt** (`adopt.Build`, `internal/adopt/adopt.go:69-146`, the unauthorized-key
  loop at `:82-139`). Before `OwnerOf` (`:96`):
  `key SHA256:… on web-2 is REVOKED (2026-11-08, alice) — not adopted; run 'sshepherd apply --server web-2' to remove it`
  and the key is skipped. Before an extension, an access tombstone for that
  (owner, server) skips it with
  `key SHA256:… of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`,
  mirroring the `ExceptCarveOut` branch at `:97-102`. adopt's exit code is unchanged
  (D2a; D8/D8a own it).
- **adopt regenerate mode** round-trips `serial` and `revoked` through
  `manifestOut` (`manifest_out.go:41-45`, built in `generateAdoptManifest`,
  `cmd/sshepherd/adopt.go:22-66`). Without this, a plain `adopt` erases all
  revocation memory; it gets a dedicated test. adopt never copies a server's header
  serial into the manifest.
- **reconcile** (`import --merge`, `builder.users` / `knownKey` / `extend`,
  `internal/reconcile/reconcile.go:183-269`): the same two checks. A tombstoned
  incoming `.pub` is skipped with
  `key SHA256:… from IDENTITY is REVOKED (2026-11-08, alice) — not imported`, and a
  tombstoned (user, server) pair is never extended (the adopt wording). Fresh
  `import` (no `--merge`) reads no manifest and is unchanged, except that
  `import -o FILE --force` over an existing manifest holding memory warns that it
  drops it and proceeds.
- **Name claims.** Generated user names (adopt's `nameUsers` and
  `reconcile.Build`) avoid names kept only by an access tombstone: a new grant under
  one would be a policy conflict, refused at save.
- **audit, classification.** `statusOf` (`internal/audit/report.go:354-366`)
  checks, in this order: unreachable; **critical** — `criticalDrift`
  (`:327-339`, extended: a missing operator key, any `Diff.Unauthorized` key with
  `cfg.Revoked`, a forged header, membership in a policy conflict's `Servers`);
  **drift** — not `ServerResult.Compliant()` (`internal/audit/audit.go:76-84`), or a
  serial-ahead header (D4a); then compliant. The compliant short-circuit therefore
  moves below the new critical and drift checks, so a key-compliant server with a
  forged header, a newer serial or a policy conflict is never reported compliant.
  A header serial below M is not drift (a plain apply leaves it, row 7).
- **audit, text.** The revoked row is
  `‼ alice (REVOKED 2026-11-08)  SHA256:…  ssh-ed25519  installed but REVOKED (CRITICAL: revoked key)`;
  an unlabelled tombstone shows `(REVOKED 2026-11-08)`. A key of a user found on a
  server that an access tombstone removed from that user (D1d) keeps today's
  unauthorized row and severity (drift, exit 1), with the owner label widened to
  `bob (access revoked 2026-11-08)`:
  `⚠  bob (access revoked 2026-11-08)  SHA256:…  ssh-ed25519  installed but UNAUTHORIZED`.
  Policy conflicts print in a block before the per-server sections, one
  `‼ manifest: MESSAGE (CRITICAL: policy conflict)` line each. The D4a note is the
  D4c wording, `written by newer manifest serial 8 (yours is 7): pull the latest manifest`
  (drift). A forged header prints the section 3 line as critical. The D1e warnings
  print on stderr like every manifest warning.
- **audit, JSON:** section 9.
- **D5.** Delete the wildcard compaction (`internal/adopt/adopt.go:249-253`), the
  `Wildcard` field (`:24`), the compaction sentence in `nameUsers`' comment
  (`:227-228`) and both renderer branches (`cmd/sshepherd/adopt.go:55-57`,
  `:98-100`). An unknown key found on every server is granted those servers by
  name. No `--wildcard` flag.

### 6. apply bumps the serial after a hand removal (D4b)

When a confirmed `apply` will write, on some server, a body that removes keys
compared with that server's current body, and the manifest's serial is not above
that server's header serial (M ≤ S), and no planned server is a newer-serial row
(2-4), apply bumps `serial:` once for the run:

- through P12's `manifest.Store` (its lock and compare-and-swap), saved after the
  prompt and before the first write, the same point revoke saves; a failed save is
  exit 3 with nothing written;
- the plan is computed against M; after the save, every server written in that run
  is rendered with M+1 (a row-3 removal-only write keeps S when S > M+1, so a
  serial never goes down) and no plan changes class (the bump scope;
  no header-only writes are added for servers whose body already matches);
- text: `manifest serial: 7 → 8 (saved; this apply removes keys)` after the save;
  `--dry-run` prints `would bump serial: 7 → 8 (this apply removes keys)` and saves
  nothing;
- a piped `--config` cannot be saved: apply warns
  `removing keys without a serial bump: an older copy could re-grant them` and
  proceeds;
- JSON: `serial_bump` (section 9).

### 7. Post-revoke sweep (D3: opt-in `--sweep`)

- **Without `--sweep`**, revoke and rotate replace the `scope:` line
  (`printScope`, `editrun.go:392-398`) with the exact follow-up, carrying the run's
  own non-default flags (`followUp.command("audit", nil)`):
  `check every server: sshepherd audit [--config PATH] [--known-hosts …] [--identity …]`.
  With D2, that audit exits 2 while the key is installed anywhere. It is printed on
  every run that removes a key, including `--dry-run` and `--no-apply`.
- **With `--sweep`** (new flag on revoke and rotate; new `cmd/sshepherd/sweep.go`,
  re-targeted to `internal/workflow` by the W4 plan if P14 moves the edit flow there):
  - runs after `finishEdit` (`editrun.go:353-390`) on a confirmed run, and after a
    `saveOnly` that added a tombstone (D1b); skipped under `--dry-run` and
    `--no-apply` (they contact no server by contract), where the audit command above
    is printed instead;
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
  - **a no-op run (D1b/D1c) sweeps too**: a run in which every target was already
    revoked saves nothing and sweeps every server for the key tombstones already
    recorded for those targets (exit 2 if one is found); `--dry-run` and
    `--no-apply` still skip;
  - **parse errors in `authorized_keys` are unprovable**:
    `cannot prove removal on db-2 (authorized_keys has unparseable lines)`, exit 1;
  - **an interrupted sweep is unprovable, not exit 3**: unread servers report
    `cannot prove removal on db-2 (sweep interrupted)` and are not counted as
    checked, so the run keeps its report or JSON document and exits 1, or 2 if a
    key was found;
  - **the save-only preflight precedes the save**: a `saveOnly` run opens the sweep
    session (known_hosts, credentials) before the confirm and save, so a failed
    preflight is exit 3 with nothing saved.
- **Output.**
  `REVOKED KEY STILL INSTALLED: alice SHA256:… on db-2, db-7 — run 'sshepherd apply --server db-2 --server db-7'`.
  A sole-grantee (emptied) server gets
  `REVOKED KEY STILL INSTALLED: alice SHA256:… on db-9 — remove it by hand or grant another user there first`
  (no wipe mode). The run ends with `swept N of M servers: K still have a revoked key, U unreachable`.
- **JSON:** `sweep` (section 9).
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
| 0 | compliant (a header serial below the manifest's is not drift) | converged, including a header-only write applied, and a newer-serial server with an equal body, with a note (**D4c**) | converged (with `--sweep`: no revoked key found); **D1c** repeated revoke; **D1b** no-op |
| 1 | drift; unreachable; **server serial ahead of the manifest (D4a)**; **a key installed where an access tombstone removed it (D1d)** | pending (including a header-only write under `--dry-run`), refused (**stale serial**, **policy conflict**, D30, a header-only write the guard refuses), failed, unreachable | not converged; **sweep unreachable or unprovable** |
| 2 | critical: missing operator key; host key changed or `@revoked`; **revoked key installed (D2)**; **policy conflict (D29)**; **forged header serial** | (P08/D10: lockout not restored — not this spec) | **`--sweep` found a revoked key still installed** |
| 3 | tool error | tool error; **a D4b serial save that failed** | tool error; **a save that would keep a policy conflict** |

`validate` (P10, D25/D25a) exits 3 on a policy conflict and 0 on warnings only (D1e).
`adopt` and `import` keep their own codes (D8/D8a); a skipped revoked key (D2a) does
not change them.

### 9. JSON (owner rule: every command offers `--json`)

Every field is additive and optional; schema stays **1** for each document. Field
values that come from the manifest or a server are sanitized like today's text
fields (`clean`, `internal/apply/json.go`).

**Shared objects.**

- Policy conflict: `{"kind": "revoked_key" | "revoked_access", "message": "…",
  "user": "alice2", "fingerprint": "SHA256:…", "servers": ["web-1"]}`
  (`fingerprint` omitted for `revoked_access`; `servers` always present, `[]` when
  empty).
- Manifest warning (D1e): `{"kind": "tombstone_unknown_server", "revoked_index": N,
  "user": "bob", "server": "db-9", "message": "…"}`.

**audit** (`internal/audit/json.go`):

- top level: `manifest_serial: M` (omitted when 0), `policy_conflicts: [..]` and
  `manifest_warnings: [..]` (each omitted when empty);
- `summary.revoked_keys` (installed tombstoned keys across servers) and
  `summary.policy_conflicts` (each omitted when 0);
- `jsonKey.revoked: {"user": "alice", "date": "2026-11-08", "reason": "offboarded"}`
  on an unauthorized key that is tombstoned (`user`/`reason` omitted when empty); the
  server's `status` is `critical`;
- `jsonKey.access_revoked: {"date": "2026-11-08", "reason": "…"}` on an
  unauthorized key whose owner's access to that server is tombstoned (D1d; `reason`
  omitted when empty); the server's `status` stays `drift`;
- per server `header_serial: S` (omitted when 0), `manifest_serial_ahead: S` (D4a,
  drift) and `forged_header_serial: S` (critical), each omitted when unset.

**apply, revoke, rotate** (`internal/apply/json.go`, one document shape):

- top level: `policy_conflicts: [..]` and `manifest_warnings: [..]` (each omitted
  when empty);
- top level `serial_bump` (apply only, D4b; omitted unless the run would bump):
  `{"from": 7, "to": 8, "saved": true}`; under `--dry-run` `"saved": false`; with a
  piped `--config` `{"from": 7, "to": null, "saved": false, "warning": "removing keys without a serial bump: an older copy could re-grant them"}`;
- per server `serial` (omitted when M and S are both 0):
  `{"header": S, "manifest": M, "writes": W, "case": "…"}` — `header` is `null` for
  no serial, `writes` is the serial the planned write's header carries (`null` when
  nothing is written; S for a removal-only write on a newer server), and `case` is
  one of `"forged"`, `"newer_converged"`, `"newer_removal_only"`, `"newer_refused"`,
  `"equal"`, `"header_only"`, `"older"` (rows 1-7 of section 3; a row-8 change on an
  older or equal serial reports `"older"` or `"equal"`);
- `notes.serial`: the human note of rows 1-3 (the forged warning, the D4c note, the
  removal-only warning), omitted otherwise; a stale-serial or policy-conflict
  refusal is the server's `error` with `class: "refused"`, as every refusal is today;
- a header-only server has `class: "change"`, every `changes` list empty and
  `serial.case: "header_only"`;
- `edit` (revoke/rotate) gains `serial` (the new value; omitted when nothing was
  saved), `revoked` (the tombstones this run added, each in the manifest's own shape:
  `{"fingerprint", "user", "date", "reason"}` or `{"user", "servers", "date",
  "reason"}`, `[]` when none), `already_revoked` (D1c/D1b no-ops:
  `[{"user": "alice", "date": "…"}]` or `[{"fingerprint": "SHA256:…", "date": "…"}]`,
  omitted when empty) and `check_command` (the printed audit command, present
  whenever a key was removed and `--sweep` was not given);
- top level `sweep` (revoke/rotate with `--sweep` only):
  `{"checked": N, "still_installed": [{"server", "fingerprint", "user", "file"}], "unreachable": ["db-3"], "unprovable": [{"server", "reason"}]}`,
  where `file` is `"authorized_keys"` or `"authorized_keys2"`, `user` is the
  tombstone's label (omitted when unlabelled), and a skipped sweep (`--dry-run`,
  `--no-apply`) has no `sweep` object;
- a save refused for a policy conflict, and a failed D4b save, are exit 3: no
  document, the message on stderr (the apply JSON contract's exit-3 rule).

**validate** (P10 slice, `--json` from day one per D25a): its document carries
`policy_conflicts` and `manifest_warnings` in the shapes above. A conflict is
validate's finding, not a tool failure, so its document is written on that exit 3
too; the rest of validate's document is P10's.

**adopt and import** (their JSON report is its own slice after W1): each skip this
design adds is one warning object there, `{"kind": "revoked_key_skipped" |
"revoked_access_skipped", "server", "fingerprint", "user", "date", "message"}`
(adopt; `user` is the tombstone label or the owner) and `{"kind":
"revoked_pub_skipped" | "revoked_access_skipped", "identity", "fingerprint", "user",
"date", "message"}` (`import --merge`; `identity` is the `.pub` path, `server` on the
access kind). Until that slice lands they are stderr warnings only, like every
adopt/import warning today.

## Interactions with on-hold items

- **No `apply --force`.** The serial has no override flag. The only override is
  editing `serial:` in the manifest, which the refusal message names. The
  header-only write is not an override: it only raises a serial on a server whose
  keys already match.
- **No `prune`.** The sweep only reads; D1b writes no server; nothing removes an
  unowned key fleet-wide.
- **No wipe/empty-server mode.** A sole-grantee server stays a by-hand fix and the
  sweep says so; a header-only write never empties a file.
- **No scheduled rotation, key generation, `move-key`, `import --prefer`.** Untouched.

## Threat notes

- **A hostile server can claim any serial.** Above M + 1000 it counts as forged:
  audit exits 2 and apply ignores it and rewrites the header (a header-only write
  when the keys match). Within the bound it can only refuse writes that **add** or
  loosen access on that same server; a removal-only write still proceeds, so no
  header can stop an emergency revoke of the attacker's own key.
- **The header is parsed with an anchored regexp and a range check**, never
  evaluated; it gets a fuzz target. The `.orig` decision uses the same parser on the
  compare-and-swapped snapshot, not a shell pattern.
- **A header-only write cannot widen access** (section 3): the body bytes are the
  server's own and only a `#` line changes.
- **Tombstone `user` and `reason` are printed**, so they pass `RenderTextIssue` and
  a 256-byte cap at load and at `--reason`.
- **Remote content never writes manifest authority.** adopt and import never copy a
  server's header serial into the manifest.

## Known limitations (said plainly in the README in W4)

- **The header-only write happens only in the run that bumps.** An affected server
  that run does not write — `--no-apply`, unreachable, refused, or a run that was
  declined or interrupted — and whose keys already match keeps its older header until
  its next real change, so a copy older than the revoke can still re-grant there. For
  a key revoke this is a server where the key was granted but already missing (drift
  audit reported). A plain apply cannot tell those servers from unaffected ones, so it
  does not header-write them. The README's Quick start therefore runs `revoke` with
  its apply phase (then commit and push) rather than `--no-apply` followed by `apply`.
- **A hand edit does not bump the serial by itself.** D4b covers it only when apply
  writes a removal on a server whose header serial is not below the manifest's, and
  only the servers that run writes carry the new serial. A server still at an older
  header when the hand removal is applied gets the current serial, so a copy taken
  at that same serial (after the last bump, before the hand edit) can still
  re-grant there; so can a server whose keys already matched.
- Two branches that each bumped to the same serial cannot be told apart; git
  discipline stays the control for that case. A content hash was rejected as noise.
- The sweep reads `authorized_keys2` only on the default path.
- Deleting a `revoked:` entry by hand is a deliberate un-revoke and is not audited
  beyond git history.
- An access tombstone naming a removed server is ignored for it, with a warning
  (D1e); re-adding a server under the same name re-applies the entry.

## Amendments to earlier specs (applied when this spec is approved)

- **`2026-07-19-apply-slice-design.md`, "Managed header" row (line 76):** the header
  is fixed only at serial 0; above 0 it names the serial, and convergence compares
  bodies plus the serial table in section 3 (including the header-only write).
- **`2026-10-23-revoke-rotate-design.md`, decision 5 and the save note
  (lines 62, 280-295):** the affected-only scope stays (header-only writes stay
  inside it); the `scope:` hint is replaced by the audit command or `--sweep`; the
  save note names the serial; `revoke --key` of an unowned key records a tombstone
  (D1b).
- **`2026-07-10-adopt-fleet-discovery-design.md`, "Access" (lines 123-124):** no
  wildcard compaction; revoked keys are skipped with a warning.
- **`2026-07-16-adopt-merge-design.md`:** merge honours key and access tombstones,
  and regenerate mode round-trips `serial`/`revoked`.

## Dependencies on other packages

| Package | What this design uses |
|---|---|
| P05 (W1, landed) | the authkeys option table in `internal/authkeys/options.go` (the removal-only test compares option lists; `Loosening` names the loosening cases) |
| P06 (W1, landed) | `followUp.command` (`cmd/sshepherd/fleet.go:47-81`) carries the run's flags into every hint; `Example:` blocks; the "keeps access to N other servers" line |
| P07 (W1, landed) | audit's `(unknown)` comment column and renderer changes (`UnknownLabel`, `internal/audit/report.go`); follow-up: label former owners `alice (revoked)` |
| P08 (spec, W1) | apply exit 2 for `lockout_unrestored` shares this table; the apply `--json` widening |
| P10 (after W4) | `validate --json` carries `policy_conflicts` / `manifest_warnings` (section 9) |
| P11 (W2) | the rewritten write script that gets the snapshot-driven `.orig` decision |
| P12 (W2) | `manifest.Store` (lock + compare-and-swap) for D4b; its schema gate must allow `serial`/`revoked` |
| P13 (W2) | `make fuzz` discovers `FuzzParseHeader`; no Makefile edit |
| P14 (W3) | `internal/fleet` / `internal/workflow` layout the W4 plan targets |

## Testing (W4, failing first)

- **Schema (config, manifest):** `TestRevokedRejectsOwnedKey` is replaced by
  `TestConflictsAreReportedNotFatal` (a listed tombstoned fingerprint parses and
  `Conflicts()` names it with the verbatim message), `TestRevokedFingerprintShape`,
  `TestAccessTombstoneConflictsExplicitGrant`, `TestAccessTombstoneUnknownServerWarns`
  (D1e: the manifest loads, `Warnings` holds the verbatim line, `AccessRevoked` and
  `Conflicts()` ignore that server, and re-adding the server re-applies the entry),
  `TestSerialNegativeRejected`, `TestLoadAllowsSerialAndRevoked`,
  `TestBumpSerialCreatesFirstKey` (golden), `TestAddTombstonesPreservesComments`,
  `TestAddTombstonesSkipsKnownFingerprint`, fuzz seeds with tombstones and serials.
- **Header:** `TestRenderSerialZeroIsLegacyBytes`, `TestRenderSerialHeader`,
  `TestParseHeader` (the cases in section 3), `FuzzParseHeader`,
  `TestSnapshotManagedMatchesParseHeader` (`SnapshotOf(…).Managed` equals
  `ParseHeader`'s `managed` over the `TestParseHeader` table and the fuzz corpus),
  and an sshwrite script test: a legacy file and a `(serial 9)` file take no `.orig`;
  files whose first line is `(serial 07)`, `(serial 0)`, the legacy header plus a
  trailing space, or `# Managed by SSHepherd-ish …` **do** take `.orig` (the
  anchored definition, not a prefix).
- **Pure consumers:** `TestBuildSkipsRevokedKey`, `TestBuildHonoursAccessTombstone`,
  `TestBuildNeverWildcards`, `TestReconcileSkipsRevokedPub`,
  `TestPlanRefusesNewerServerSerial`, `TestPlanRemovalOnlyProceedsOnNewerSerial`
  (header keeps S), `TestPlanRemovalOnlyRejectsLoosenedOptions`,
  `TestPlanNewerSerialSameBodyConvergedWithNote` (D4c),
  `TestPlanForgedSerialTreatedAsNone` (header-only write, also in a plain apply),
  **`TestPlanHeaderOnlyWriteOnAffectedOlderSerial`** (replaces
  `TestPlanConvergedOnOlderSerialSameBody`: in a bumped run, an affected server
  with an equal body and S < M — both an older `(serial S)` and a legacy header —
  plans `ClassChange` with `HeaderOnly`, no add/remove/rewrite/normalize rows,
  `Rendered` equal to the server's bytes with only line 1 replaced by the
  `(serial M)` header, and the JSON `serial.case` `"header_only"`),
  `TestPlanOlderSerialSameBodyConvergedWithoutBump` (the same server in a plain
  apply: converged, no write), `TestPlanHeaderOnlyRefusedByGuard` (the guard refuses
  it like any write), `TestAffectedIgnoresSerialBump`,
  `TestPlanRefusesConflictServers`.
- **audit:** `TestExitCodeRevokedKeyIsCritical` (2), `TestStatusSerialAheadIsDrift`
  (1), `TestForgedSerialIsCritical` (2, on an otherwise compliant server),
  `TestPolicyConflictIsCritical` (2), `TestStatusAccessTombstoneIsDrift` (1, D1d
  label), `TestOlderHeaderSerialIsCompliant` (0), and `report_revoked*` /
  `report_serial_ahead*` goldens (text and JSON).
- **cmd:** `TestRevokeWritesTombstoneAndBumpsSerial`,
  `TestRevokeHeaderOnlyWriteOnConvergedAffected` (hermetic `sshtest`: alice granted
  on web-1 and web-2, her key already missing on web-2 → `revoke alice --yes` writes
  web-2's header with the new serial and leaves its keys byte-identical),
  `TestRevokeUnownedKeyRecordsTombstone`, `TestRotateTombstonesOldKey`,
  `TestRevokeSweepFindsStrayExit2`, `TestRevokeSweepFindsKeyInKeys2`,
  `TestRevokeWithoutSweepPrintsAuditCommand`, `TestRevokeAlreadyRevokedExits0`,
  `TestApplyBumpsSerialOnHandRemoval`, `TestSweepSkippedOnDryRunAndNoApply`,
  `TestAdoptRegenerateKeepsRevokedAndSerial`, `TestAdoptMergeNoWildcard`,
  `TestSaveRefusedWhileConflictRemains`, `TestRevokeKeyResolvesConflict`, and JSON
  goldens for `serial`, `serial_bump`, `sweep`, `edit.revoked`,
  `edit.already_revoked`, `check_command`, `policy_conflicts` and
  `manifest_warnings`.
- **E2E (written first against the post-W3 tree, where they must FAIL):**
  `TestE2ERevokeNoResurrect` (adopt → apply → `revoke alice` with one server pointed
  at a closed port → `adopt --merge` on the real port → alice's fingerprint absent
  from `users:` and the warning names it → audit exits 2 → `apply --server` → audit
  exits 0), `TestE2EStaleManifestRefused` (old copy → revoke, where one affected
  server already lacked the key → `apply --yes --config <old copy>` → exit 1 with
  the serial refusal on **every** affected server, including the already-converged
  one, server bytes unchanged), `TestE2EStaleManifestAfterHandEdit` (D4b).
- **Integration:** a serial-header `.orig` case in the sshwrite matrix.

Acceptance after W4: `make check`, `make integration`,
`make fuzz-list | grep -q FuzzParseHeader`, `make fuzz`, and the three E2E tests
pass. The implementation outline (W4a schema + header + failing E2E lane; W4b
consumers, audit, cmd) is in the plan, P04 "Implementation outline"; its lane C
test list takes the section above (`TestPlanHeaderOnlyWriteOnAffectedOlderSerial`
in place of `TestPlanConvergedOnOlderSerialSameBody`).

## Author choices (shown at approval)

Technical choices the author made where the plan's sketch was silent or, on a close
read, unsafe. Each follows from an answered decision and changes no exit code,
refusal or load beyond what that decision states. Numbering of the first draft's
points is kept where they survive.

1. **A removal-only write on a newer-serial server keeps the server's serial S**
   (the sketch said "proceeds with M"). Writing M would lower the header, and a
   second stale copy at M with the revoked key would then pass `S == M` and re-grant.
2. **The PRD-2 fix: header-only writes in the bump scope** (section 3, row 6;
   W0 verifier finding). Bounded to the bumping run so a revoke never writes beyond
   its affected set and a plain apply never churns the fleet; the residual is a known
   limitation, and the Quick start runs `revoke` with its apply phase.
3. **The `.orig` decision comes from `ParseHeader` on the compare-and-swapped
   snapshot** (`Snapshot.Managed`), not from a shell prefix test, so it matches the
   anchored header definition exactly.
4. **One serial note wording** for audit (D4a) and apply (D4c):
   `written by newer manifest serial S (yours is M): pull the latest manifest`.
5. **`statusOf` checks critical and drift before compliant**, so a key-compliant
   server can carry a forged-header, serial-ahead or policy-conflict status.
6. **JSON shapes** (section 9), including `validate` writing its document on a
   conflict's exit 3.
7. **The D1e warning wording** and that re-adding a server re-applies the entry.
8. **Tombstone dates are UTC**, and `--reason` is capped at 256 bytes.

## Out of scope

- `prune`, `apply --force` (or any serial override flag), wipe/empty-server mode,
  key generation and scheduled rotation, `move-key`, `import --prefer` (on hold).
- Import's wildcard compaction (`cmd/sshepherd/import.go:101-108`,
  `internal/reconcile/reconcile.go:307-311`), which comes from the operator's own ssh
  config, not remote content. Not covered by D5.
- Content hashes or signatures for the manifest, and any server-side enforcement
  (agentless design).
- Labelling plain `apply` remove rows `(REVOKED)` in `internal/apply/report.go`
  (follow-up after P07), and audit's "former owner" label for keys a standalone
  audit sees (follow-up candidate after D1).
