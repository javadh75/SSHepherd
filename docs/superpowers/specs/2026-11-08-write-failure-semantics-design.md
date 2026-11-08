# Design: write-path failure semantics (login-check failures, unrestored lockouts, stale locks, interrupts, backup retention)

- **Date:** 2026-11-08 (drafted in wave W1 of the review-remediation plan; approved and re-anchored to `4390667` the same day)
- **Status:** Implemented (W5, 2026-11-08).
- **Owner decisions:** **D9 = (1)**, **D9b = yes**, **D10 = yes** (2026-11-07); **D10a = (2)**, **D10b = (2)**, **D9c = (2)** (2026-11-08). D11, D12 and D13 are stated defaults the owner left standing at approval. The implementation plan (P08-impl, W5+) is written against the tree this spec is anchored to.
- **Findings:** WP-1 (MEDIUM), WP-2, WP-6, WP-7, WP-8 (LOW) from the 2026-11-07 whole-repo
  review. Section 7 also closes a W4 follow-up (`apply.Reserial` has no size check).
- **Plan:** package P08 of `docs/superpowers/plans/2026-11-07-review-remediation.md`
  (spec in W1, implementation W5+).
- **Scope of the implementation:** `internal/sshwrite` (probe verdicts, retries, restore
  retry, lock owner record, keys2 retention, `SkipWrite`, reconnect after a dropped
  connection), `internal/sshconn` (`handshakeKind`'s host-key gate, the MaxAuthTries signal,
  the `Only` offer check, the post-handshake socket deadline), `internal/fleet` (the typed
  write outcomes, the shared host-key predicate, `WriteRequest` fields), `internal/apply`
  (two outcomes, exit code, text and JSON reports, the interrupt notice, the size check),
  `internal/workflow` (`Outcome.ExitCode`'s contract), `cmd/sshepherd` (`plainApply`'s exit
  mapping and size check, the `--help` exit-code footers), README and the CLAUDE.md Status
  paragraph.
- **Code anchors** name functions, as of `4390667`. **README line numbers** are as of
  `4390667`; every implementer finds each section by its heading.

## Context and goal

`apply` (and `revoke`/`rotate`, which share its run body) writes `authorized_keys` on
production servers and then proves the write by logging in afresh with only the surviving
keys the operator holds. The safety net around that write has five gaps:

- **WP-1.** Any failed login check rolls the server back (`FleetWriter.probeOrRestore`,
  `FleetWriter.probe` in `internal/sshwrite/sshwrite.go`) — even a dial timeout, sshd
  `MaxStartups`, a rate-limit rule (`--hitcount 4 --seconds 60`) or a locked agent. During
  `revoke` the manifest is already saved, so a network blip **reinstalls the revoked key**.
- **WP-2.** The safety net lives only in the client. A second signal, SIGKILL after a
  container grace period, a transport drop after the upload started (the stage-1 exec in
  `FleetWriter.Apply`) or a verify transport error (`FleetWriter.verify`) all leave the new
  file in place with no login check, and README's "a dropped connection leaves the original
  untouched" (README:2181) is then not always true.
- **WP-6.** "Login check failed AND restore failed" — the operator may be locked out — exits
  1 (`apply.ExitCode`), the same as harmless drift. JSON has no field for it (`jsonErrorFor`,
  `jsonSummary` in `internal/apply/json.go`), and a restore refused by a busy lock (exit 47,
  `restoreExitError`) is never retried.
- **WP-7.** The lock is a bare `mkdir` (`lockHead`/`lockPrologue`) with no owner or time. A
  stale lock blocks every later write, and `LockedError` cannot say who left it or when.
- **WP-8.** `disableKeys2Cmd` runs `rm -f "$s"` before `mv`, so an earlier disabled
  `authorized_keys2` copy is destroyed. A plan that only disables keys2 still rewrites
  `authorized_keys` and rotates `.bak` (`casBackupBlock`), losing the one-step undo.

Goal: sort login-check failures by **what they prove**, make a possible lockout or a security
regression page a human (exit 2), make locks self-describing without ever breaking them
automatically, close the dropped-connection gap without a server-side agent, and stop
destroying backups.

## What the code does today (grounding, `4390667`)

- `FleetWriter.Apply`: connect (`connectForWrite`, session budget 2 min,
  `defaultSessionBudget`), stage 1 guarded write script (`writeCmdFor`), stage 2 verify (byte
  compare), stage 2b `disableKeys2`, stage 3 `probeOrRestore`. `execCtx` is
  `context.WithoutCancel(ctx)` with no deadline; the socket carries the budget deadline.
- `probe` dials with `ConnectOptions{Only: survivors}`; a connect error is returned as is
  (already an `*sshconn.Error` with a kind), an exec error is wrapped `probe command: …`, a
  wrong exit/output is "a forced command= on the surviving key?". With no explicit deadline
  the probe dial falls back to `3×DialTimeout` = 30 s (`Dialer.ConnectWith`; `dialTimeout` is
  10 s in `cmd/sshepherd/audit.go`).
- `ConnectWith` installs the ctx deadline as the socket deadline **for the whole connection**
  (`conn.SetDeadline(dl)`), so a probe dial bounded at D also bounds the probe's exec at D.
- Any probe error → `restoreCmdFor` over the still-open write connection, then
  `restoreKeys2Cmd` if keys2 was disabled; the keys2 failure is `errors.Join`ed into
  `LockoutError.Restore`. `restoreExitError` maps 47 to "another apply holds the lock" with no
  retry.
- Kinds (`internal/fleet/errors.go`): `unknown`, `host_key_unknown`, `host_key_changed`,
  `host_key_type_unrecorded`, `host_key_revoked`, `host_key`, `agent`, `auth`, `dial`,
  `timeout`, `canceled`, `handshake`, `remote`. `handshakeKind`
  (`internal/sshconn/errors.go`) sets `auth` when the error text contains "unable to
  authenticate"; a failed session open or exec is `remote` (`sshconn.Exec`). audit's exit 2
  for host keys is the unexported predicate `hostKeyAlert` (`internal/audit/errors.go`).
- **A locked agent is not an `agent` error today.** A locked OpenSSH agent answers
  `REQUEST_IDENTITIES` with an empty list, so `Credentials.Signers` returns no agent signers
  and a nil error; `orderSigners` with `Only` then offers nothing; the handshake fails
  "unable to authenticate, attempted methods [none]", kind `auth`. A signer that fails during
  auth (agent locked or killed between list and sign) surfaces as an opaque handshake error.
  `Credentials.Held` re-lists after the prompt, so this window is the seconds or minutes
  between the re-list and the probe.
- **MaxAuthTries is `handshake` today.** sshd disconnects with "Too many authentication
  failures"; x/crypto turns any `msgDisconnect` into `ssh: disconnect, reason 2: "…"` at the
  transport level (at any packet, **including before host-key verification**) and
  `ssh.NewClientConn` wraps it `ssh: handshake failed: …`. `handshakeKind` does not recognize
  it, so it is `handshake`. For the same reason a disconnect whose text contains "unable to
  authenticate" sets `auth` even before the host key is verified.
- Outcomes (`internal/apply/plan.go`): `pending`, `applied`, `refused`, `failed`.
  `apply.ExitCode` returns 0 or 1 only; its comment says 2 stays reserved.
- Exit mapping (`cmd/sshepherd`): `exitFor` maps 2/1 to `errCriticalDrift`/`errNonCompliant`,
  used by `finishDoc` and `finishEdit`. `plainApply.finish` maps any non-zero
  `out.ExitCode()` to `errNonCompliant` and is the one site that must change. `auditVerdict`
  is the model for a 0/1/2 mapping.
- P11, P14 and P04-impl have landed: the write script is upload → snapshot copy compared
  and kept as `.bak` (`casBackupBlock`), per-file flush, refusals create nothing; one probe
  offers survivors in production order (`authkeys.OfferOrder`, `authkeys.OfferRank`, D31;
  `probeOrderFor` in `internal/apply/exec.go`); kinds live in `internal/fleet`; the run body
  is `workflow.Apply` and `workflow.Outcome.ExitCode()`.
- **Layering.** `internal/apply` and `internal/workflow` must not import `internal/sshwrite`
  or `internal/sshconn` (depguard in `.golangci.yml`, `make layering`). Any error type
  `internal/apply` inspects therefore lives in `internal/fleet`, the way `fleet.RefusalError`
  and `fleet.IsRefusal` do.

## Decisions

D9, D9b and D10 were asked one at a time and answered on 2026-11-07 (master plan, "Answers
recorded"). D10a, D10b and D9c were open points in the first draft; each changes an exit
code or the JSON contract, so they were asked as owner questions and answered on 2026-11-08.
D11–D13 are stated defaults the owner left standing at approval.

**Reverses** names the documented decision or text the answer overturns. **README sections
it changes** names each section by its heading, with its line at `4390667`. P08-impl's
integrator updates exactly these sections in the same commit, with sample output copied
from the goldens.

| ID | Finding | Question | Options | Recommendation | Owner choice | Reverses | README sections it changes |
|---|---|---|---|---|---|---|---|
| **D9** | WP-1 | If the login check after a write can't even log in because of the network (the server never answered), should SSHepherd undo the write? | (1) Retry a few times; if it still can't log in, keep the new file and report UNPROVEN (exit 1). Anything that goes wrong after login (a forced command, a hang) still undoes the write. (2) Retry, then undo. (3) Keep today: undo on any failure. | (1) — undoing can put a revoked key back. | **(1)** (2026-11-07) | review-hardening spec `2026-10-16-review-hardening-design.md:260-263` ("That holds for network failures too: if access cannot be proven, the server goes back to its previous file"); README "Verify, then prove you can still log in" (README:2200-2212, "If the probe fails, the previous file … is restored"). | **Safety model → Verify, then prove you can still log in** (l.2200): the stage-sorted verdicts, the retries, the 15 s probe deadline, UNPROVEN (file kept), and the FAILED line naming the removed keys a rollback put back; **Exit codes** (l.1973): row 1 for `apply`, `revoke` and `rotate` gains "unproven"; **`sshepherd apply` → JSON** (l.1011): `outcome` gains `unproven`, `summary` gains its count, and an unproven server's `error_kind` is the last probe failure's; **`sshepherd apply` summary sample** (l.1239): an UNPROVEN example. |
| **D9b** | WP-5 follow-up | Should the login check also try your `--identity` key on its own, and only warn if that fails? | Yes (warn only, unrestricted key-file lines only) / No | Yes, warn only; never undoes a write. | **Yes** (2026-11-07) | Nothing documented (P11 removed the earlier restoring variant). | **Safety model → Verify, then prove you can still log in** (l.2200): the warn-only headless proof (one extra connection, mixed-source runs only) and its stderr line `warn: <server>: your --identity key <path> could not log in on its own (…); a headless run with only that key would fail`. |
| **D10** | WP-6 | If the login check fails and the undo also fails, so you might be locked out, should apply exit 2 so monitoring pages you? | Yes (and retry the undo on a busy lock) / No (stay exit 1) | Yes — follows D28's meaning of exit 2 ("a human must act now on security"). | **Yes** (2026-11-07) | README "Exit codes" row 2's `apply` cell (`—`, README:1982) and its `revoke`/`rotate` cell (the sweep only); `ExitCode` comment (`internal/apply/plan.go`, "2 stays reserved"); apply-json contract "written exactly when the run exits `0`, `1` or (for `revoke`/`rotate --sweep`) `2`" (README:1016). | **Exit codes** (l.1973): row 2 gains `apply`, `revoke` and `rotate`: "lockout not restored", and the `apply`, `revoke` and `rotate --help` footer (l.1999); **`sshepherd apply` → JSON** (l.1011): `outcome` gains `lockout_unrestored`, `summary` gains its count, the exit-2 clause drops "(for `revoke`/`rotate --sweep`)" and lists the causes, and the open-enum rule; **Safety model → Verify, then prove you can still log in** (l.2200): the restore retry on a busy lock and exit 2 for an unrestored lockout; **`sshepherd apply` summary sample** (l.1239): a `LOCKOUT — NOT RESTORED` example. |
| **D10a** | WP-1 | When a failed login check undoes a write and the restored file grants again a key on the manifest's `revoked:` list, should apply exit 2 at once, or exit 1 and leave the page to the next audit? | (1) Exit 1; the FAILED line names each key the rollback put back, and the next audit reports it as critical (D2, P04). (2) Exit 2 at once when a restored file grants a key on the manifest's `revoked:` list (D28). | (1) (not chosen). | **(2)** (2026-11-08) | README "Exit codes" row 2's `apply` and `revoke`/`rotate` cells, beyond D10. | **Exit codes** (l.1973): row 2 for `apply`, `revoke` and `rotate` also covers "a rollback put back a key on the `revoked:` list", and the `--help` footer (l.1999); **`sshepherd apply` → JSON** (l.1011): a `failed` server can come with exit 2; its `error` names each key and `restored_revoked_keys` lists their fingerprints; **Safety model → Verify, then prove you can still log in** (l.2200): the FAILED line names each key and marks the revoked ones; **`sshepherd apply` summary sample** (l.1239): an example ending `→ exit 2`. |
| **D10b** | WP-1 | If the login check right after a write meets a host-key alarm (the server's host key changed or is `@revoked`), should apply exit 2 the way audit does, or report UNPROVEN at exit 1? | (1) UNPROVEN, exit 1, no retry, file kept; the line names the alarm. (2) Exit 2 for the host-key kinds audit exits 2 on (`host_key_changed`, `host_key_revoked`, and `host_key_type_changed` if P09's D16 adds it), UNPROVEN at exit 1 for the other host-key kinds. | (1) (not chosen). | **(2)** (2026-11-08) | README "Exit codes" row 2's audit-only host-key clause (README:1982). | **Exit codes** (l.1973): row 2's host-key clause ("a host key that changed or is `@revoked`") applies to `apply`, `revoke` and `rotate` for the post-write login check, and the `--help` footer (l.1999); **Safety model → Verify, then prove you can still log in** (l.2200): the host-key UNPROVEN line and which kinds exit 2; **`sshepherd apply` → JSON** (l.1011): an `unproven` server whose `error_kind` is one of those kinds means exit 2. |
| **D9c** | WP-5 follow-up | When D9b's extra login check with only your `--identity` key fails, should `--json` output carry the warning too, or only stderr? | (1) Stderr only; no JSON field. (2) An additive per-server `warnings` array in the apply JSON (schema stays 1, omitted when empty). | (1) (not chosen). | **(2)** (2026-11-08) | Nothing documented. | **Safety model → Verify, then prove you can still log in** (l.2200): the warning goes to stderr and into the JSON; **`sshepherd apply` → JSON** (l.1011): the per-server `warnings` array and when it appears. |
| **D11** | WP-7 | (stated) What does a lock record, and who removes a stale one? | (1) Record who and when; show age and the exact removal command; never remove automatically, no flag. (2) Auto-break locks older than N. (3) A `--break-lock` flag. | (1) — today's behavior plus diagnostics; (2)/(3) overlap the on-hold `apply --force`. | **Stated default (1)** | `LockedError` text. | **Safety model → Refusals** lock bullet (l.2162): the owner, age and removal command; removal stays by hand only; **Safety model → Verify, then prove you can still log in** (l.2200): a restore refused by a busy lock names the same owner and age. |
| **D12** | WP-2 | (stated) How is a write protected when the client loses the connection or is interrupted? | (1) No server-side watchdog; a notice on the first Ctrl-C; after a broken connection, reconnect, re-check under the lock, then probe or report. With D10 = yes this adds two exit-2 (`lockout_unrestored`) cases: the reconnect after the upload started is refused with an auth error, or a restore whose connection dropped cannot be retried over the one reconnect (section 4). (2) A detached server-side watchdog that rolls back unless confirmed. | (1) — (2) goes against the agentless design. | **Stated default (1)** | README "One guarded write per server" (README:2181-2182, "a dropped connection leaves the original untouched" — made true again by the re-check, or replaced by an honest "unknown state"). | **Safety model → One guarded write per server** (l.2167): the re-check under the lock and its outcomes, including the refused reconnect (exit 2); **Ctrl-C / SIGTERM** (l.1248): the first-signal notice; **Container usage** (l.1963): the grace-period note; **Exit codes** (l.1973): row 2's "lockout not restored" also covers the refused reconnect and the restore that could not be retried; **Safety model → Verify, then prove you can still log in** (l.2200): a restore over a dropped connection is retried over one reconnect, and its failure is a lockout not restored. |
| **D13** | WP-8 | (stated) Which backups survive? | (1) A moved-aside `authorized_keys2` gets a name that is never overwritten; `authorized_keys` is not rewritten (so `.bak` is not rotated) when its bytes already match. (2) Keep today. | (1) — restores what README already promises about `.bak`. | **Stated default (1)** | `disableKeys2Cmd` doc and `rm -f "$s"` ("replacing an older disabled copy"). | **Safety model → `authorized_keys2`** (l.2191): copies are never overwritten, the timestamped name, copies accumulate; **Safety model → Backups** (l.2184): `.bak` is not rotated when `authorized_keys` already matches. |

Ask order was D9 → D9b → D10 → D10a → D10b → D9c; D10's meaning depends on D9 (with D9 =
(1), an unrestored lockout can only follow a REJECTED login check or a refused reconnect)
and on D28 (Block 1: exit 2 means "a human must act now on security" for every command, one
shared README table). D10a and D10b read D28 the same way: apply exits 2 for a rollback that
reinstates a revoked key and for a post-write host-key alarm audit would page on, not only
for "you may be locked out".

**Scope of D10a.** It counts **key** tombstones only (`Config.Revoked`), matching audit's D2
(a revoked key installed is critical) and D1d (a key installed where an *access* tombstone
removed it is drift, exit 1). It checks the restored `authorized_keys`, whose content the
plan knows (`ServerPlan.Remove`); a rollback that moves `authorized_keys2` back does not
count, because apply never reads that file's contents (only `--sweep` does).

**Scope of D10b.** It covers the post-write login check. A host-key alarm on the write
connection itself or on section 4's reconnect keeps its existing outcome (`failed`, exit 1,
`error_kind` naming the alarm): the question was asked about the login check, the
write connection alarm means nothing was written, and the reconnect outcome is already a
FAILED "unknown state" line. The next audit exits 2 on the same alarm.

## Design

### 1. Sorting login-check failures by stage (D9, D10b, WP-1)

A new pure function, `classifyProbe(stage, err) verdict`, sorts each login-check failure
into one of two verdicts **by the stage the probe reached, not by error kind alone**. The
dividing line is "did authentication finish, and did it mean anything?". The static lockout
guard only checks that a held key's line is present; it never evaluates `from=` or
`command=`, and it only warns when every survivor is restrictive. That is why the probe
exists, so **nothing after a successful login is ever waved through as a blip**, and no
TRANSIENT row below is justified by "the guard already passed".

The probe records its stage: `stageDial` (TCP + kex + host key + auth, i.e. the
`ConnectWith` call) or `stageAuthed` (the connect returned a client; session open, exec,
output). A failure inside `ConnectWith` carries its kind; a failure after it is always
`stageAuthed`.

| Stage of the failure | Examples (kind / site) | Verdict | Action |
|---|---|---|---|
| **Before auth finished:** dial, kex/handshake, timeout during dial or handshake | `dial`, `handshake` (MaxStartups, `kex_exchange_identification`, a dropped socket), `timeout` (`handshakeKind`) | **TRANSIENT** | Retry with backoff; when the retries or the budget run out, **UNPROVEN** (file and disabled keys2 kept). |
| **Before auth finished:** a held survivor could not be offered | `agent`: a `Signers` failure (`Credentials.Signers`, no key files), a locked or emptied agent (`ConnectWith` finds fewer `Only` keys than asked, below), or a signer error during auth (below) | **TRANSIENT** | At most **1 retry** (2 attempts), then **UNPROVEN** with the agent wording. It proves nothing about the server, so nothing is restored. |
| **Before auth finished:** host-key alarm on the probe dial | `host_key_unknown`, `host_key_changed`, `host_key_type_unrecorded`, `host_key_revoked`, `host_key`, and `host_key_type_changed` if P09 adds it (`hostKeyHint`) | **TRANSIENT, flagged** | **No retry** (the answer will not change). UNPROVEN at once; the message names the host-key alarm. Proving access through an impostor proves nothing, so the file is kept. **D10b: exit 2 for the kinds `fleet.HostKeyAlert` covers (`host_key_changed`, `host_key_revoked`, `host_key_type_changed` once P09 adds it to the predicate); exit 1 for the other host-key kinds.** |
| **Auth refused:** every offered survivor rejected, every held survivor offered, and the host key verified in this dial | `auth` ("unable to authenticate": a `from=` miss, an algorithm sshd refuses, a key not accepted) | **REJECTED** | Restore now. |
| **Auth refused:** sshd disconnected after too many failed keys, host key verified | `handshake` with `sshconn.AuthExhausted(err)` (`MaxAuthTries`, below) | **REJECTED** | Restore now, no retry. |
| **After auth succeeded** | session channel refused (`*ssh.OpenChannelError`), exec failed, `*ssh.ExitMissingError` (channel closed with no exit status), EOF, the **probe-exec deadline** while waiting for the output, exit ≠ 0, or output ≠ `sshepherd-probe-ok\n` (a forced `command=`, `rrsync`/`internal-sftp`-style commands that wait on stdin, `command="sleep 3600"`) | **REJECTED** | Restore. A key that logs in but cannot run SSHepherd's command captures every later session. |
| Unclassifiable (`unknown`, or `canceled`, which cannot normally occur under the detached context) | — | **REJECTED** if the stage is `stageAuthed`; **TRANSIENT** if it is `stageDial` | There is no "unknown is safe" rule; the stage decides. |

**Locked agent, in full** (resolves the W1 follow-up). `ConnectOptions.Only` today treats "none
held" as an auth failure; that verdict is wrong for the login check, because an empty offer
proves nothing about the server. Four changes in `internal/sshconn`:

1. When `Only` is non-empty and **none** of its fingerprints is among the current signers
   (`orderSigners` returns nothing), `ConnectWith` returns an `agent`-kind error **before
   dialing**: `none of the N surviving keys is offered (agent locked, or keys removed since
   the plan)`. A locked agent therefore costs the server no connection, and it is TRANSIENT
   with 1 retry, then UNPROVEN.
2. When `Only` is non-empty and **some** of its fingerprints are missing, `ConnectWith` dials
   and offers the rest (a login that succeeds is a valid proof). If that login is refused
   with kind `auth`, the error is reclassified `agent`, naming how many survivors were not
   offered, so an incomplete offer can never reach REJECTED: `auth` alone never proves the
   missing key's line is broken. A rollback needs every held survivor actually tried.
3. A signer error during auth (the agent locks or dies between list and sign) is recorded by
   `recordingSigner`/`recordingAlgorithmSigner` and, when the handshake fails, sets kind
   `agent` instead of `handshake`, so the same 1-retry rule applies.
4. The reconnect after a dropped write (section 4) sets `ConnectOptions.RequireOffer`: with
   no key to offer, `ConnectWith` returns an `agent`-kind error before dialing, so a locked
   agent can never read as a refused reconnect.

Key-file survivors are always offered; `Only` for D9b's headless proof (section 6) lists key
files only and is unaffected.

**MaxAuthTries and server-sent text** (resolves the W1 follow-up). Two rules in
`internal/sshconn/errors.go`, both behind one fact: did the host key pass in this dial?
`ConnectWith`'s host-key callback records a successful verdict, and the handshake-failure
site passes it to `handshakeKind`.

- `auth` requires a verified host key. A pre-kex disconnect whose text contains "unable to
  authenticate" stays `handshake` (TRANSIENT): under D9 an `auth` verdict rolls the server
  back, and it must never be steerable by text an unverified peer sent.
- `sshconn.AuthExhausted(err)` is true when the host key verified and the error text contains
  `Too many authentication failures`. sshd sends that only after it refused as many keys as
  `MaxAuthTries` allows, offered in production order, so the next real login would fail the
  same way: REJECTED, with no retry (a retry only burns more failed attempts against
  `MaxAuthTries` and per-source penalties). The **kind stays `handshake`** so audit's
  `error_kind` for this case does not change; the signal is an `AuthExhausted` flag on
  `sshconn.Error` set at the same site, and `classifyProbe` is its only reader.

**Probe exec deadline: 15 s** (`probeExecDeadline`), starting when `ConnectWith` returns (so
it covers session open, exec and output). On expiry the probe connection is closed and the
verdict is REJECTED. `ConnectWith` gains `ConnectOptions.SessionTimeout`: after a successful
handshake the socket deadline becomes `now + SessionTimeout` instead of the dial deadline.
Without it a handshake that finished late in the dial bound would leave the probe's exec
almost no time and a healthy but slow login would be REJECTED (a rollback) by the dial
bound's own socket deadline.

**Retry policy** (all inside the session budget; numbers are fixed, no flags):

| Item | Value |
|---|---|
| Attempts for TRANSIENT failures | **up to 4** in total; the wait before each attempt is **0, 2 s, 5 s, 10 s** |
| `agent` failures | at most **1 retry** (2 attempts, waits 0 and 2 s): a locked agent rarely recovers in seconds |
| host-key alarms | **no retry** (1 attempt) |
| `restoreReserve` | **20 s** kept back after the probe's own time, for a REJECTED restore over the open write connection (the busy-lock waits of 1 + 3 + 6 = 10 s, plus the restore and keys2 commands) |
| `probeExecDeadline` | **15 s** (above) |
| `minProbeDial` | **1 s**: an attempt never starts with less |
| Dial bound per attempt | `min(3×DialTimeout, avail)`, where `avail = remaining − probeExecDeadline − restoreReserve` |
| Starting an attempt, **including the first** | only while `avail ≥ minProbeDial` at the moment it would start (after its wait; a wait that would leave too little is not taken). There is no first-attempt exception. |
| Logging | each attempt at Debug with its kind and stage; the final message carries the last cause |

**Budget arithmetic** (resolves the W1 follow-ups on restoreReserve and the first-attempt rule).
The budget deadline `T` is `connectForWrite`'s (120 s from the start of the connect). For the
probe to leave `restoreReserve` free, the probe's whole life must end by `T − restoreReserve`:
the dial ends by `T − restoreReserve − probeExecDeadline`, the exec within `probeExecDeadline`
of it. That is exactly the `avail` rule. Let W be the time write and verify took, so
`avail` at the first attempt is `85 s − W`.

| Failure pattern | Attempts | Time spent | Why |
|---|---|---|---|
| Fast failures (connection refused, immediate close) | 4 | waits 17 s + a few ms | All four fit. |
| Every dial runs the full 3×10 s bound, W ≈ 0 | **3** | 30 + 2 + 30 + 5 + 18 (the third attempt's bound is cut to 18 s) | 85 s is spent before the fourth attempt's 10 s wait could fit. |
| Every dial runs the full bound, W ≈ 20 s | **2** | 30 + 2 + 30 | The third attempt would start at 67 s, past `avail` = 65 s. |
| W > 84 s | **0** | — | `avail < minProbeDial`. |

"4" is therefore a ceiling; `UnprovenError.Attempts` is the number actually run, and the
message reports it. A REJECTED verdict on any attempt finds at least `restoreReserve` left.
That reserve does not cover a restore over a dead write connection: section 4's single
reconnect takes whatever is left of the budget, and its failure is `lockout_unrestored`.

The budget deadline becomes explicit: `connectForWrite` returns the deadline it installed,
and the probe, the restore and any reconnect (section 4) derive their contexts from it
instead of `context.WithoutCancel(ctx)` with no deadline. Waits go through a `sleep
func(context.Context, time.Duration) error` seam on `FleetWriter` so tests take no wall-clock
time.

**UNPROVEN outcome.** When the retries run out (or a host-key alarm stops them), the file
and the disabled keys2 are **kept** and `Apply` returns:

```go
// fleet.UnprovenError (internal/fleet/write.go): written and verified, but the
// post-write login never got past authentication (dial, kex, agent, host key)
// after the retries; the file is kept because restoring could reinstall a key
// the manifest removed. Any failure after a successful login is a REJECTED
// probe, never an UnprovenError.
type UnprovenError struct {
	Path     string
	Attempts int
	HostKey  bool  // stopped by a host-key alarm (no retry)
	Last     error // sanitized; its kind is the last probe failure's
}

func (e *UnprovenError) Unwrap() error { return e.Last }
```

`Unwrap` keeps the last kind visible to `jsonErrorFor` (`error_kind` is the last probe
failure's kind, e.g. `dial`) and to `fleet.HostKeyAlert` for D10b, and keeps the host-key
hint visible through `fleet.HintOf`.

Message (`Error()`), verbatim; `attempt` is pluralized and the count is `Attempts`:

- network or kex: `written and verified, but the login check could not reach the server after 4 attempts (dial tcp 10.0.0.1:22: i/o timeout) — kept the new file; run sshepherd audit to confirm`
- agent (kind `agent`): `written and verified, but the login check could not offer the surviving keys you hold after 2 attempts (none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)) — kept the new file; unlock the agent or re-add the key, then run sshepherd audit to confirm`
- host key: `written and verified, but the login check stopped at a host-key alarm (host key changed) — kept the new file; check known_hosts, then run sshepherd audit`
- budget: `written and verified, but the session budget ran out before the login check could start — kept the new file; run sshepherd audit to confirm`

Report line: `web-1: UNPROVEN: written and verified, but the login check could not reach the server after 4 attempts (dial tcp 10.0.0.1:22: i/o timeout) — kept the new file; run sshepherd audit to confirm`.
Outcome `unproven`. Exit **1**, except that a host-key alarm whose kind `fleet.HostKeyAlert`
covers exits **2** (D10b, section 2), and its `UNPROVEN:` label is printed bold red like the
other exit-2 lines. A budget exhausted before any attempt could start (write and verify took
over 84 s) is also UNPROVEN, `Attempts: 0`, last cause `session budget exhausted before the
login check`.

**A rollback that reinstates removed keys** (D9, D10a). After a REJECTED probe the restore
still puts back the keys in the plan's `Remove` list. The FAILED line then names each of
them, the way the plan's `-` rows name it (label and fingerprint), and marks the ones on the
manifest's `revoked:` list, e.g.

`web-1: FAILED: lockout prevented — restored previous file (…); it still grants alice (SHA256:…, on the revoked: list) and bob (SHA256:…), which the manifest removed — fix the surviving key and re-run`

When a key on the manifest's `revoked:` list is among them, the server is `failed` and the
run **exits 2 at once** (D10a; `apply`, `revoke` and `rotate` alike), with the `FAILED:`
label bold red. Otherwise it stays exit 1. Implementation, in the pure layer:

- `planWrite` sets `ServerPlan.RevokedRemovals []string`: the fingerprints in `p.Remove` that
  `cfg.Revoked` holds, in `Remove` order. `cfg` is the rendered config, so `revoke` and
  `rotate` see the tombstones their own edit appended.
- `applyOne` sets `ServerPlan.RolledBack` when the writer returned a `*fleet.LockoutError`
  with `Restore == nil` (a keys2 failure alone does not unset it).
- One helper, `rollbackDetail(cfg, opts, p)`, builds the key list for both the text line and
  JSON's `error`, so they cannot disagree. `RenderSummary` gains a `cfg` parameter for it
  (`jsonServerFor` already has one).

### 2. Unrestored lockout and the exit-2 set (D10, D10a, D10b, WP-6)

- **Split `LockoutError.Restore`** and move the type (`internal/fleet/write.go`, aliased as
  `sshwrite.LockoutError`, the `sshwrite.Snapshot = fleet.Snapshot` pattern), so
  `internal/apply` can inspect it without importing the transport. `Restore` covers only the
  `authorized_keys` restore; a new `RestoreKeys2 error` takes the `restoreKeys2Cmd` failure,
  which today is `errors.Join`ed into `Restore`. A failed keys2 move-back cannot lock anyone
  out (keys2 only adds keys), so it never raises the exit code. `Unwrap` returns `Probe`,
  `Restore` and `RestoreKeys2`. The message's `.bak` path uses `fleet.BackupSuffix`
  (`sshwrite`'s `bakSuffix` becomes that constant).
- **Restore retry on a busy lock.** On exit 47 only, the restore is retried after **1 s,
  3 s, 6 s** (up to 4 restore attempts), each only while the budget has time left. Any other
  restore exit is final. When the lock is still busy after the last attempt, the restore
  error carries the lock owner and age (section 3):
  `restore on web-1 refused: another apply holds the lock (held by ci-runner-3 pid 4121 for 3m12s) after 4 attempts`.
- **Outcomes** (`internal/apply/plan.go`), two new values:
  - `OutcomeUnproven = "unproven"` — written and verified, login not proven (section 1).
  - `OutcomeLockoutUnrestored = "lockout_unrestored"` — a `*fleet.LockoutError` whose
    `Restore` is non-nil (the login check was REJECTED and the previous `authorized_keys`
    could not be put back), or the refused reconnect of section 4.
  A `*fleet.LockoutError` with `Restore == nil` stays `failed` (lockout prevented), even when
  `RestoreKeys2` is non-nil. `applyOne` maps these with `errors.As`.
- **Exit code** (`apply.ExitCode`, still plans-only). Returns **2** if any plan is:
  1. `lockout_unrestored` (D10); or
  2. `failed` with `RolledBack` and a non-empty `RevokedRemovals` (D10a); or
  3. `unproven` with `fleet.HostKeyAlert(fleet.ErrorKindOf(p.OutcomeErr))` (D10b).

  Otherwise today's rule (0 when every server converged, else 1; `unproven` and `failed` are
  not converged → 1). Precedence across a run: **3 > 2 > 1 > 0**.
  `fleet.HostKeyAlert` is audit's predicate moved to `internal/fleet` (`hostKeyAlert` in
  `internal/audit/errors.go` becomes a one-line call), so P09's `host_key_type_changed`
  enters apply's exit 2 and audit's together.
- **Text** (`RenderSummary`, `internal/apply/report.go`): new lines
  `LOCKOUT — NOT RESTORED:` (bold red) and `UNPROVEN:` (yellow, bold red for a D10b kind);
  the Summary line appends `· N unproven` and `· N lockout not restored` after today's
  segments. A D10a rollback stays a `FAILED:` line (bold red) inside the `failed` count.
  Examples (the README copies the real text from the new goldens, never this sketch):
  `Summary: 1/3 servers converged (1 applied) · 1 unproven · 1 lockout not restored  → exit 2`;
  `Summary: 2/3 servers converged (2 applied) · 1 failed  → exit 2` (a rollback that put back
  a revoked key). The `LOCKOUT — NOT RESTORED:` line carries today's `LockoutError` message,
  which names the `.bak` path.
- **JSON** (`internal/apply/json.go`, schema stays **1**, every addition additive):
  - `outcome` gains `unproven` and `lockout_unrestored`; `summary` gains `unproven` and
    `lockout_unrestored` counts.
  - A `failed` server whose rollback put back a key on the `revoked:` list has its `error`
    name each key and carries the additive per-server `restored_revoked_keys` (fingerprints,
    omitted when empty). A D10b server is `unproven` with its `error_kind`; `summary.exit_code`
    is 2 in both cases.
  - D9c: the additive per-server `warnings` array (section 6, omitted when empty).
  - The apply-json contract gains the rule **"treat an unknown `outcome` value as not
    converged"**. `summary.exit_code` reports the exit-2 rules above; a document is written
    on exit 0, 1 or 2 (`finishDoc` already does; the README sentence drops the "for
    `revoke`/`rotate --sweep`" qualifier).
- **Command layer.** `workflow.Outcome.ExitCode()` returns 0, 1 or 2 (its doc changes,
  `apply.ExitCode` carries the logic). `plainApply.finish` (`cmd/sshepherd/apply.go`) maps
  through `exitFor` instead of `errNonCompliant` (`exitFor`, `finishDoc` and `finishEdit`
  already handle 2). `revoke` and `rotate` inherit it, so the D28 table's `apply` and
  revoke/rotate columns gain the same exit-2 row. The `apply`, `revoke` and `rotate` `--help`
  exit-code footers change with it (and their `--help` goldens).

### 3. Lock owner record (D11, WP-7)

- **Record.** `lockPrologue` (and `lockPrologueUndo`) set the EXIT trap **first**, then write
  `$l/owner`, one line:

  ```
  v1 <client-host> <client-pid> <remote-pid> <remote-epoch>
  ```

  `<client-host>` is `os.Hostname()` reduced to `[A-Za-z0-9._-]` and capped at 64 bytes
  (`unknown` if empty); it and `<client-pid>` enter the script as one `sshconn.ShQuote`d
  literal. `<remote-pid>` is `$$`, `<remote-epoch>` is `$(date +%s)`. The trap (`lockTrap`)
  gains `rm -f "$l/owner"` before `rmdir "$l"`. Order matters: the trap must exist before the
  owner file, or a kill in between leaves a non-empty lock. A failed owner write is ignored
  (`|| :`): the lock is still valid; the record is diagnostics only.
- **Busy lock.** On exit 47 the script prints, on stdout, `sshepherd-lock <remote-now>` and
  then the first line of `$l/owner` cut to 200 bytes (`head -n 1 … | cut -c1-200`), if any.
  The client parses the owner line strictly against

  ```
  ^v1 [A-Za-z0-9._-]{1,64} [0-9]{1,10} [0-9]{1,10} [0-9]{1,12}$
  ```

  Anything else is "unrecognized owner record" and nothing remote is echoed raw.
  `LockedError` gains `Owner string`, `Age time.Duration`, `Known bool` and `RemoveCmd string` (the removal command below, built from the server's user, host and port). Age is
  remote-now minus remote-epoch, so clock skew between client and server does not matter; a
  negative age is unknown. A bare lock with no owner file (an older sshepherd, a shell
  killed before the record was written, or the prologue's lost-race path) reports
  `owner unknown (older sshepherd or killed shell)`.
- **Message**, verbatim shape:

  `another apply is in progress on ~/.ssh/authorized_keys (lock held by ci-runner-3 pid 4121 for 3m12s); remove it only if no apply is running on ci-runner-3 (pid 4121): ssh -p 22 deploy@10.0.0.1 'p="$HOME"/'\''.ssh/authorized_keys'\''; rm -f -- "$p.sshepherd.lock/owner"; rmdir -- "$p.sshepherd.lock"'`

  With no record: `… (lock held by an unknown owner (older sshepherd or killed shell)); remove it only if no apply is running: ssh …`.
  The remote part is built with the same quoting as `sshconn.PathAssign`, then quoted once
  more for the local shell with `sshconn.ShQuote`. `rmdir` (not `rm -r`) refuses a lock
  directory holding anything unexpected. The message notes that a killed write can also
  leave `<path>.sshepherd.tmp` and `<path>.sshepherd.cas`; both are reclaimed by the next
  write and need no hand removal.
- **Never automatic.** The lock is never removed by SSHepherd and no `--break-lock` or
  `--force` flag is added (this stays clear of the on-hold `apply --force`).
- The restore script and the reconnect read (section 4) share the prologue, so a busy
  restore lock reports the same owner and age in the `lockout_unrestored` message.

### 4. Interrupt notice and reconnect-and-recheck (D12, WP-2)

- **No server-side watchdog** (rejected alternative, below).
- **First-signal notice, without touching `cmd/sshepherd/run.go`.** `apply.Execute`
  (`internal/apply/exec.go`) keeps an `atomic.Int32` count of in-flight writes and
  registers `context.AfterFunc(ctx, …)`. When the count is above zero, the callback logs
  one Warn, verbatim (`write` pluralized):

  `interrupt: finishing 2 in-flight writes (write, verify, login check — up to 2m); a second Ctrl-C abandons their login check and rollback`

  `watchSignals` (`run.go`) stays unchanged. With nothing in flight, no notice.
- **Container grace period, docs only.** README "Container usage" advises
  `docker stop -t 150` / Kubernetes `terminationGracePeriodSeconds: 150` — more than the
  2-minute session budget. SIGKILL cannot be handled.
- **Reconnect after a transport error.** When an exec on the write connection returns a
  transport error (an `err != nil`, not an exit code) in stage 1 or in verify
  (`FleetWriter.verify`'s exec), `Apply` opens **one** fresh full-credential connection within
  the budget and **takes the per-target lock first** (the dropped script may still be running
  and holding `$p.sshepherd.lock`, e.g. between the upload and `mv`): a script made of the
  lock prologue plus the read of `sshconn.AuthorizedKeysCmdFor`, retried on 47 with the
  restore-retry schedule (1 s, 3 s, 6 s). Only then does it decide:

  | Re-read under the lock | Outcome |
  |---|---|
  | bytes equal the render | the `mv` happened: release the lock and continue with keys2 and the probe over the new connection. A REJECTED probe restores over the new connection; if that fails, `lockout_unrestored`. |
  | the file matches the plan's snapshot (`req.Expect`) | FAILED: `connection dropped before the rename; original untouched (re-checked under the lock)` |
  | the lock never frees within the budget, the reconnect fails with a non-auth kind (an empty offer is `agent`, section 1), the reconnect is refused when the stage-1 session never opened (`sshconn.ErrSessionNotOpened`: nothing was uploaded), or the bytes are anything else | FAILED: `connection dropped; the file is in an unknown state (previous version at <path>.sshepherd.bak) — run sshepherd audit` |
  | the reconnect fails with an **auth**-kind error after the stage-1 exec had started | `lockout_unrestored` (exit 2): `connection dropped after the upload started and a fresh login offering the keys you hold was refused (…) — the new file may lock you out; the previous version is at <path>.sshepherd.bak`. Represented as `*fleet.LockoutError{Probe: <reconnect error>, Restore: errNoSession}`. |

  For a **verify** transport error the same reconnect-and-reread applies (the lock is free
  by then, so it is taken at once). A verify that *read* the file and found different bytes
  stays FAILED with no probe, as today: SSHepherd did not write those bytes, so it must not
  restore over them.
- **Restore over a dead connection.** If the restore exec after a REJECTED probe returns a
  transport error, the same single reconnect is used to retry it (unless the reconnect was
  already spent); a refused or failed reconnect leaves `Restore` set, so the outcome is
  `lockout_unrestored`. At most one reconnect per server write. This reconnect is best
  effort within the budget (section 1): `restoreReserve` is sized for the open connection.
  A retry refused with 46 re-reads under the lock; the file matching `req.Expect` means the
  dropped restore landed, so it counts as restored.

### 5. Backup retention (D13, WP-8)

- **`authorized_keys2` copies are never overwritten.** `disableKeys2Cmd` drops
  `rm -f "$s"`. When `authorized_keys2.sshepherd.disabled` is free it is used (today's plan
  row and goldens stay the same); otherwise
  `authorized_keys2.sshepherd.disabled.<UTC YYYYmmddTHHMMSSZ>` (`date -u +%Y%m%dT%H%M%SZ`),
  with `.$$` appended if that name also exists, each checked with `[ -e ] || [ -L ]` under
  the same ancestor walk (only the login user or root can race the check). The script prints
  `sshepherd-keys2 <basename>`; the client parses the basename strictly against
  `^authorized_keys2\.sshepherd\.disabled(\.[0-9]{8}T[0-9]{6}Z(\.[0-9]+)?)?$` and passes it
  to `restoreKeys2Cmd(name)`, which moves back exactly that name. README states that copies
  accumulate and are never deleted by SSHepherd, and that the plan row shows the base name.
- **Keys2-only plans do not rewrite `authorized_keys`.** `ServerPlan` gains the method
  `KeysUnchanged() bool`: `p.DisableKeys2()` and `p.Rendered` equal to the phase-1 snapshot
  (`authkeys.ManagedSnapshot(false, p.Rendered)` against `p.Expect`, by size and cksum). It
  is evaluated in `applyOne`, **after** `Commit`, because `Reserial` may have re-rendered
  the header. `fleet.WriteRequest` gains `SkipWrite bool`. With `SkipWrite`, `Apply` skips
  stage 1 (no lock, `.bak`, `.orig`, upload or `mv`) but keeps stage 1's symlink and
  ownership refusals, re-reads and byte-compares the file
  (the verify doubles as the compare-and-swap, so a CRC collision is also caught: a mismatch
  is a `*ChangedError`, a refusal, outcome `refused`), disables keys2 and probes. A REJECTED
  probe restores only keys2; an UNPROVEN login keeps keys2 disabled. A header that differs
  (an older serial, or a `Reserial` bump) means the rendered bytes differ, so the method
  returns false and stage 1 runs.
- **JSON: no new field.** The `rewrites_authorized_keys` bool suggested in the plan is
  **not** added: a keys2-only server is already visible as empty `changes` plus
  `disables_authorized_keys2: true`, and the field would touch every golden for no new
  information. Plan text is unchanged.

### 6. Headless key-file proof (D9b, D9c, warn only)

P11 makes the probe offer survivors in the exact order every later run offers them (D31), so
an interactive run with an agent key first proves the agent key, not the `--identity` file.
With D9b = yes:

- **When:** after a passing probe, and only when the production order's first survivor is
  agent-sourced **and** at least one surviving key file's manifest line is unrestricted
  (`authkeys.OfferRank` 0). `internal/apply` computes this from the held keys' sources and
  sets `fleet.WriteRequest.HeadlessProof []string` (those key-file fingerprints; empty
  otherwise).
- **What:** one more login offering only `HeadlessProof` (`ConnectOptions{Only: …}`) that
  runs the probe command, under the same 15 s exec deadline and inside the budget (skipped,
  with a Debug line, when `remaining − probeExecDeadline < minProbeDial`; it needs no
  restore reserve, since it never restores).
- **Failure only warns** and never restores, so it cannot roll back a write the first probe
  proved, or reinstall a revoked key. Warn line (stderr, normal verbosity; `warn: ` is `clog`'s level prefix, printed once):

  `warn: web-1: your --identity key /k/ci could not log in on its own (ssh: unable to authenticate); a headless run with only that key would fail`

  The outcome stays `applied`, and the exit code does not change.
- **D9c: JSON.** The same text, without the `web-1: ` prefix, is one entry of the
  server's additive `warnings` array in the apply JSON (`revoke` and `rotate` share the
  document; schema stays 1; omitted when empty; entries pass `clean`). The transport hands
  it back through `fleet.WriteRequest.OnWarning func(string)`, set by `applyOne`, which
  appends to `ServerPlan.Warnings` and logs the stderr line, so one server's goroutine is
  its only writer and the two surfaces carry the same text.
- **Cost:** one extra connection per written server, in mixed-source runs only. Against
  WP-1's rate-limit evidence (`--hitcount 4 --seconds 60`, `MaxStartups`): a written server
  already sees 3 connections in a run (the phase-1 read, the write, the probe); the proof
  makes it 4 in mixed-source runs, which such a rule may drop. Because the proof is
  warn-only, a dropped proof only produces the warning (naming the cause); it never touches
  the write. Key-file-only and agent-only runs make no extra connection.

### 7. Serial-bump size check (W4 follow-up, closed here)

Plain `apply` can lengthen a rendered file after planning: D4b's `plainApply.commit` saves
the bump, then `apply.Reserial` re-renders the header with `max(to, p.Serial.Writes)`, with
no check against `maxRender`. The growth is one byte per extra digit (eleven when the header
had no serial). `planWrite` refuses a render over the limit, but only for the serial the plan
knew; a render within those bytes of 1 MiB would be installed by `mv`, then fail verify
(`FinishRead`: "remote output exceeded 1MiB"), and leave a file the read path can never read
again. `workflow.ManifestCommitter` allows `Commit` to re-render the header only, so it may
not refuse a server there, and it has already saved the serial.

Resolution, **no owner decision needed**: the same limit, enforced before the prompt, in the
place the workflow already allows a run to be withheld. It adds no exit code, flag, refusal
class or JSON field.

- `apply.ReserialOversize(plans, to) []string` (`internal/apply/serialbump.go`, pure) returns
  one message per `ClassChange` plan whose re-rendered length (`len(authkeys.Header(max(to,
  p.Serial.Writes)))` + 1 + the body) exceeds `maxRender`, or nil. It mirrors `Reserial`'s
  arithmetic.
- `plainApply.question` (`cmd/sshepherd/apply.go`, the `question` seam, which runs before the
  prompt) runs `apply.NeedsSerialBump` and the shared `serialEditable` classification; when a
  bump would be saved it calls `ReserialOversize` with `to = cfg.Serial() + 1` (what
  `File.BumpSerial` writes, since `Unchanged` refuses a manifest that moved). If any message
  comes back it logs each one and returns a wrapped `workflow.ErrWithheld`: **nothing saved
  or written, exit 1** (`StageWithheld`), and under `--json` the document's `serial_bump`
  carries the message in its existing `warning` field (`SerialBump{From: from, Warning: msg}`,
  whose doc comment changes). `Commit`'s contract is unchanged: it still only re-renders
  headers, and `Reserial` can no longer exceed the limit.
- A piped or anchored manifest gets no bump (`errNoSerialSave`), so no growth and no check.
- `dryRunBump` runs the same check, so a dry run never promises a bump the real run would
  withhold: `SerialBump{From: from, Warning: msg}` with `To` nil, printed by
  `printDryRunBump`, the existing shape.

The whole run is withheld rather than refusing one server because the plan classification
cannot change after the plan is shown and `Commit` may not change it; plan time does not yet
know whether the run bumps, and a blanket reserve in `planWrite` would refuse servers that
never bump. The trigger is a render within a few bytes of 1 MiB on a run that bumps.

Message, one per server (bytes and limit are the numbers `refuseOversize` prints):
`<server>: the serial bump to N would make the rendered file B bytes, over the L-byte limit the read path accepts — nothing saved or written (split the grant across accounts)`.

## New exported surface (post-P14 layout)

| Package | Name | Notes |
|---|---|---|
| `internal/fleet` | `UnprovenError{Path, Attempts, HostKey, Last}` | section 1 |
| `internal/fleet` | `LockoutError{Path, Probe, Restore, RestoreKeys2}` (moved; `sshwrite.LockoutError` alias) | section 2 |
| `internal/fleet` | `BackupSuffix`, `HostKeyAlert(kind) bool` (moved from `audit.hostKeyAlert`) | section 2 |
| `internal/fleet` | `WriteRequest.SkipWrite bool`, `WriteRequest.HeadlessProof []string`, `WriteRequest.OnWarning func(string)` | sections 5, 6 |
| `internal/sshconn` | `AuthExhausted(err) bool`, `ConnectOptions.SessionTimeout time.Duration`, `Error.AuthExhausted bool` | section 1 |
| `internal/sshwrite` | `LockedError{Path, Owner, Age, Known, RemoveCmd}` | section 3 |
| `internal/apply` | `OutcomeUnproven`, `OutcomeLockoutUnrestored` | section 2 |
| `internal/apply` | `ServerPlan.RevokedRemovals []string`, `ServerPlan.RolledBack bool`, `ServerPlan.Warnings []string`, `ServerPlan.KeysUnchanged()` | sections 1, 2, 5, 6 |
| `internal/apply` | `ReserialOversize(plans, to) []string` | section 7 |
| `internal/workflow` | `Outcome.ExitCode()` returns 0, 1 or 2 | section 2 |

No new `error_kind` values. Unexported: `classifyProbe`, the probe stage, `parseLockOwner`,
`restoreReserve`, `probeExecDeadline`, `minProbeDial`, the schedules, the `sleep` seam, and
`rollbackDetail`.

## Exit codes and JSON (rows added to the shared D28 table)

This spec adds to the one exit-code table D28 fixes (P04 spec,
`2026-11-08-revocation-memory-design.md` section 8; README "Exit codes", rewritten by P04-impl).

| Code | apply | revoke / rotate |
|---|---|---|
| 1 | **unproven** (written and verified, login check never got past authentication), other than the host-key kinds in row 2; a `failed` server whose rollback put back no key on the `revoked:` list | the same |
| 2 | **lockout not restored** (`lockout_unrestored`: the restore after a REJECTED login check failed, a restore over a dropped connection could not be retried, or the reconnect after the upload started was refused); **a rollback put back a key on the manifest's `revoked:` list** (D10a, `failed`); **the post-write login check stopped at a changed or `@revoked` host key** (D10b, `unproven`; `host_key_type_changed` too if P09 adds it) | the same, plus the existing `--sweep` row |

JSON: `outcome` enum + `unproven`, `lockout_unrestored`; `summary` + `unproven`,
`lockout_unrestored`; per server, additive `restored_revoked_keys` (D10a) and `warnings`
(D9c), each omitted when empty; `schema` stays 1 with the open-enum rule; a document is
written on exit 0, 1 or 2; `summary.exit_code` is 2 for the row-2 cases; `error_kind` on an
unproven server is the last probe failure's kind, and one of `host_key_changed`,
`host_key_revoked` or (with P09) `host_key_type_changed` on an unproven server means exit 2.

## README sections this changes (applied by P08-impl, never before)

Found by heading; line numbers as of `4390667`. Samples are copied from the new goldens.

- **Exit codes** (README:1973-2031): row 1's `apply` and `revoke`/`rotate` cells gain
  unproven; row 2's `apply` cell (`—`) and `revoke`/`rotate` cell gain the D28 row above
  (lockout not restored, including the refused reconnect and the restore that could not be
  retried over a reconnect; a rollback that put back a key on the `revoked:` list; the
  post-write changed/`@revoked` host key). The `apply`, `revoke` and `rotate --help` footer
  (l.1999) is re-copied from the `--help` goldens.
- **`sshepherd apply` → JSON** (README:1011-1027): the outcome list gains `unproven` and
  `lockout_unrestored`; "written exactly when the run exits `0`, `1` or (for
  `revoke`/`rotate --sweep`) `2`" becomes "`0`, `1` or `2`", naming the exit-2 causes; the
  open-enum rule; the per-server `restored_revoked_keys` and `warnings` arrays and when each
  appears.
- **`sshepherd apply` summary sample** (README:1239-1246): re-copied from `summary_*.golden`,
  plus an UNPROVEN, a LOCKOUT — NOT RESTORED, and a rollback that put back a revoked key
  (`→ exit 2`) example.
- **Ctrl-C / SIGTERM** (README:1248-1255): the first-signal notice.
- **Safety model → Refusals** lock bullet (README:2162-2165): owner, age and the removal
  command; still removed by hand only.
- **Safety model → One guarded write per server** (README:2167-2182): the dropped-connection
  sentence becomes the re-check under the lock and its outcomes, including the refused
  reconnect after the upload started (lockout not restored, exit 2).
- **Safety model → Backups** (README:2184-2189): `.bak` is not rotated when
  `authorized_keys` already matches.
- **Safety model → `authorized_keys2`** (README:2191-2198): copies are never overwritten;
  the timestamped name; copies accumulate.
- **Safety model → Verify, then prove you can still log in** (README:2200-2211): the
  stage-sorted verdicts, retries (locked agent included), UNPROVEN and which host-key kinds
  exit 2, the 15 s probe deadline, the FAILED line naming removed keys a rollback put back
  and exit 2 when one is on the `revoked:` list, the restore retry on a busy lock (naming the
  lock's owner and age), a restore over a dropped connection retried over one reconnect,
  exit 2 for an unrestored lockout, and the warn-only headless proof with its stderr line
  and JSON `warnings` entry.
- **Safety model → Refusals** (README:2143-2160), new bullet near the "rendered file would
  exceed the 1 MiB" one: a run whose serial bump would push a rendered file over the limit is
  withheld before the prompt, with the message of section 7.
- **Container usage** (README:1963-1971): `docker stop -t 150` /
  `terminationGracePeriodSeconds: 150`.
- **CLAUDE.md Status** paragraph: one sentence for the landed slice.

## Rejected alternatives

- **Server-side watchdog** (a detached process that rolls back unless the client confirms):
  it starts a process on every server, against the agentless design in CLAUDE.md;
  `nohup`/`setsid` behave differently on busybox; it races a later apply's lock and
  compare-and-swap; and a client that cannot create the confirm marker turns a good write
  into a rollback.
- **Auto-breaking stale locks, or a `--break-lock` flag:** a lock that looks stale may
  belong to a slow live apply, and either form overlaps the on-hold `apply --force`.
- **Keep "restore on any failure" (D9 option 3) or retry-then-undo (option 2):** undoing
  after a network blip can reinstall a key the manifest (already saved by `revoke`) removed.
- **Bump the apply JSON schema to 2:** the change is additive; the open-enum rule covers
  consumers.
- **Configurable session budget or retry flags:** the numbers are fixed so the behavior is
  predictable and documented once.
- **Refusing only the oversized server at Commit (section 7):** a plan's class may not change
  after it is shown, and `workflow.ManifestCommitter` allows `Commit` to re-render headers
  only.

## Interactions with on-hold items and other packages

- **apply wipe/empty-server mode:** not touched. A restore after a REJECTED probe still
  removes a file a first-contact write created (`restoreCmdFor`, `wasAbsent`): that is a
  rollback, not a wipe mode.
- **apply --force:** not touched; no lock is ever broken automatically.
- **prune, import --prefer, key generation/scheduled rotation, move-key:** no overlap.
- **P04 (revocation memory, W4):** a restore puts `.bak` back verbatim, header serial
  included; the next audit sees the previous serial and, per D2, reports a reinstated
  revoked key as critical, so D10a's exit 2 and the next audit agree. D10a reads the same
  key tombstones (`Config.Revoked`) audit does. A keys2-only plan is never a header-only
  serial write.
- **P09 (audit trust posture):** D10b follows `fleet.HostKeyAlert`, so adding
  `host_key_type_changed` there changes both commands together; P09 otherwise leaves apply's
  table to this spec.
- **P11 (W2):** the lock owner record and the reconnect read rebase on P11's prologue and
  trap; `TestWriteCmdOrder` and `TestProbeOfferEqualsProductionOffer` stay green. P11's
  `.sshepherd.cas` is listed as possible residue.
- **P14 (W3):** kinds come from `internal/fleet`, the run body and exit mapping from
  `internal/workflow`; the typed write errors `internal/apply` reads move to `internal/fleet`
  to keep depguard and `make layering` green.
- **P03:** the hermetic REJECTED case uses P03's changeable `sshtest` authorized list.

## Testing (P08-impl, failing first)

Every behavior lands with a test that fails before the change. Unit tests are hermetic
(seams, fake clock, no network).

**`internal/sshconn`**

1. `TestHandshakeKindAuthNeedsVerifiedHostKey`: "unable to authenticate" with the host key
   verified → `auth`; the same text in a pre-kex disconnect → `handshake`.
2. `TestAuthExhausted`: a verified `ssh: disconnect, reason 2: "Too many authentication
   failures"` → true, kind still `handshake`; unverified → false; other disconnects → false.
3. `TestConnectWithOnlyNoneOfferedIsAgent`: `Only` with no matching signer (locked agent: an
   empty signer list) → `agent` kind, **no dial**. `TestConnectWithOnlyPartialOfferAuthIsAgent`:
   some offered and all refused → `agent`, naming the count; offered and accepted → success.
   `TestConnectRequireOfferEmptyIsAgent`: `RequireOffer` with no key to offer → `agent`, no
   dial; without it the dial happens. `TestExecMarksASessionThatNeverOpened`: the marker on a
   dead connection only.
4. `TestSignerErrorDuringAuthIsAgent`: a signer that fails in `Sign` → `agent`.
5. `TestConnectSessionTimeoutExtendsSocketDeadline`: exec after a late handshake runs to the
   session deadline, not the dial deadline.

**`internal/sshwrite`**

1. `TestClassifyProbe` (table): `auth` at `stageDial` → rejected; `AuthExhausted` → rejected,
   no retry; `dial`, `timeout`, `handshake`, `agent` at `stageDial` → transient; each `host_key_*` →
   transient, no retry; `fmt.Errorf("open session: %w", &ssh.OpenChannelError{})` → rejected;
   `&ssh.ExitMissingError{}`, `io.EOF`, a wrong output → rejected (`stageAuthed`); `unknown`
   → rejected after auth, transient before.
2. Seamed `Apply`: an exec that blocks past the 15 s probe deadline (fake clock) → restored
   `*fleet.LockoutError`; an `ExitMissingError` → restored `*fleet.LockoutError`.
3. Retry and UNPROVEN (extends `TestApplyLoginProbeFailureRestores`): the "probe session
   refused" case becomes an `OpenChannelError` and still restores; a dial-kind error each
   attempt → `*fleet.UnprovenError` with `Attempts == 4`, no restore command, 5 connects in
   total; dial fails twice then succeeds → nil; an auth error on the first attempt restores
   with no retry; an agent error is retried once (2 connects); a host-key error is not
   retried and sets `HostKey`.
4. `TestProbeBudget` (fake clock, the arithmetic table): full-bound dials stop at 3 attempts
   at W≈0 (the third attempt's bound cut to 18 s) and at 2 at W≈20 s; a REJECTED
   verdict on the last attempt has at least `restoreReserve` left; W > 84 s →
   `*fleet.UnprovenError` with `Attempts == 0` and no connect (no first-attempt exception).
5. Restore retry and the split: restore exits `[47, 47, 0]` → `Restore == nil` after 3
   restore commands; `[47, 47, 47, 47]` → `Restore != nil` naming the lock owner; a keys2
   restore failure with a good main restore → `Restore == nil`, `RestoreKeys2 != nil`.
6. Lock owner: `TestWriteCmdThroughRealSh` under dash, bash and busybox — a pre-made lock
   with an owner file exits 47 with parsable stdout; after a successful run neither `$l`
   nor `$l/owner` remains; a script killed through its own `trap` path leaves no lock.
   `parseLockOwner` unit cases (valid, bare/absent, hostile ESC bytes, too long, negative
   age) and `FuzzParseLockOwner` with a seed corpus.
7. Keys2 retention (real sh): an existing `.sshepherd.disabled` is never deleted; the second
   copy gets the timestamped name; a third in the same second gets `.$$`;
   `restoreKeys2Cmd(name)` moves back exactly that name.
8. `SkipWrite`: the first command is the read, not `writeCmdFor`; no `.bak`; a mismatch →
   `*ChangedError`; a REJECTED probe restores only keys2.
9. Reconnect (seamed): stage-1 transport error with the re-read returning (a) the render →
   probe runs; (b) the old bytes → "original untouched (re-checked under the lock)"; (c)
   other bytes → "unknown state"; (d) the reconnect's lock exits 47 twice, then the read
   sees the render; (e) the reconnect fails with an auth kind → `*fleet.LockoutError` with
   `Restore` set. The same set for a verify transport error, and a restore transport error
   retried over the reconnect.
   A session that never opened in stage 1, then a refused reconnect → unknown state, not a
   lockout; a reconnect with nothing to offer → unknown state, kind `agent`.
10. D9b/D9c: an agent-first survivor list with an unrestricted key file → one extra `Only`
    connect; its failure logs the warning, calls `OnWarning` once and returns nil; a
    restricted key-file line or a key-file-first order makes no extra connect and no warning.

**`internal/apply`**

1. `TestExitCode`: `lockout_unrestored` → 2; `unproven` (dial) → 1; `unproven` with
   `host_key_changed` or `host_key_revoked` → 2; `unproven` with `host_key_unknown` or
   `host_key_type_unrecorded` → 1; `failed` with `RolledBack` and `RevokedRemovals` → 2;
   `failed` with `RolledBack` and no revoked removal → 1; `failed` with `RolledBack` and only
   an access-tombstoned key → 1; `applied` + `lockout_unrestored` → 2.
2. `TestExecuteOutcomes`: `*fleet.UnprovenError` → `OutcomeUnproven`;
   `&fleet.LockoutError{Restore: errors.New("x")}` → `OutcomeLockoutUnrestored`; the existing
   `Restore == nil` case stays `OutcomeFailed` and sets `RolledBack`; a FAILED rollback with a
   non-empty `Remove` names the reinstated keys and marks the revoked ones.
3. `TestPlanRevokedRemovals`: `Remove` ∩ `Config.Revoked` in `Remove` order; an access
   tombstone does not count.
4. `TestExecuteInterruptNotice`: a blocking fake writer, cancel ctx, the captured Warn
   contains `finishing 1 in-flight write`; no notice with nothing in flight.
5. `KeysUnchanged`/`SkipWrite`: `Rendered` equal to the snapshot with keys2 → true and the
   request carries `SkipWrite`; a `Reserial` header change → false; `HeadlessProof` is
   computed only for the D9b condition; `OnWarning` appends to `Warnings`.
6. `TestReserialOversize`: over and at the limit, `max(to, Writes)` honored, a row-3 plan
   keeps its serial.
7. Goldens via `-update`: `summary_unproven.golden`, `summary_unproven_hostkey.golden`,
   `summary_lockout.golden`, `summary_restored_revoked.golden`, `json_failures.golden.json`;
   the round-trip asserts the `unproven` and `lockout_unrestored` counts,
   `restored_revoked_keys`, the per-server `warnings` (present and omitted), and
   `exit_code: 2`.

**Command layer:** `TestApplyLockoutUnrestoredExits2` (hermetic, fake writer) — exit 2 and a
JSON document still written; `TestApplyRollbackRestoresRevokedKeyExits2` and
`TestApplyProbeHostKeyChangedExits2` likewise; each through `revoke` and `rotate` as well;
`plainApply.finish` no longer collapses 2 to 1.
`TestReserialOversizeWithholdsBeforeSave`: a render at the limit and a run that bumps →
withheld before the prompt, manifest bytes unchanged, no writer call, exit 1, the JSON
`serial_bump.warning`; a dry run reports the same warning. `TestHelpGolden` covers the changed
`apply`/`revoke`/`rotate` footers, and the README help-parity test stays green.

**Integration** (`//go:build integration`, `make integration`):
`TestIntegrationProbeTransientKeepsFile` (the probe's `Only` connects are redirected to a
closed port → UNPROVEN, file kept); `TestIntegrationStaleLockReportsOwnerAndAge`;
`TestIntegrationKeys2DisabledNeverOverwritten`; `TestIntegrationLoginProbeRestores` stays
green; a hermetic case where the written file drops the survivor (auth REJECTED → restore);
`TestIntegrationProbeHostKeyChangedKeepsFileExits2` (the probe's dials use a `known_hosts`
recording another key, as the `host_key_changed` E2E case does); and
`TestIntegrationProbeMaxAuthTriesRestores` (`MaxAuthTries` in the fixture sshd, more refused
survivors than it allows → REJECTED, restored).

**E2E:** one UNPROVEN step in `cmd/sshepherd/e2e_test.go` if P13 leaves a hook for it,
otherwise recorded as a gap; `revoke` + a forced REJECTED probe, asserting exit 2, a tombstoned
key named in the FAILED line and `restored_revoked_keys` in the JSON.

## Implementation timing

P08-impl runs in W5 or later, after P11, P14 and P04-impl (all landed at `4390667`). Two
agents with disjoint files (A: `internal/sshconn`, `internal/sshwrite`, `internal/fleet`; B:
`internal/apply`, `internal/workflow`), then one integrator for `cmd/sshepherd`,
`make check`, `make integration`, README and CLAUDE.md. The integrator pins the exported
types above in the plan before the agents fork.

## Open points for spec approval

None. D10a, D10b and D9c were answered on 2026-11-08. The W1 verifier follow-ups (locked
agent, MaxAuthTries/handshake classification, retry budget against `restoreReserve`, the
first-attempt rule) are resolved in section 1, and the W4 `Reserial` size check in section 7.

## Out of scope

- WP-3 (compare-and-swap before upload), WP-4 (fsync), WP-5 (probe key order), WP-9 (mkdir
  on refusal), WP-10 (keys2 path spelling): P11.
- Re-deciding on-hold items: no automatic lock breaking, no `--break-lock`/`--force`, no
  empty-server or wipe change.
- A configurable session budget or retry flags.
