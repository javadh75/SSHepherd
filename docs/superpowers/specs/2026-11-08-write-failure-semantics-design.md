# Design: write-path failure semantics (login-check failures, unrestored lockouts, stale locks, interrupts, backup retention)

- **Date:** 2026-11-08 (drafted in wave W1 of the review-remediation plan)
- **Status:** Draft — owner decisions recorded (2026-11-07): **D9 = (1)**, **D9b = yes**,
  **D10 = yes**. **D10a, D10b and D9c are pending owner questions** (open points 1, 2 and
  3 of the first draft, promoted because each changes an exit code or the JSON contract);
  each has a stated default that holds until it is answered. D11, D12 and D13 are stated
  defaults that stand unless the owner changes them at spec approval. Awaiting spec approval. Nothing here is built until then; the
  implementation plan (P08-impl) is written after approval against the tree that P11 (W2),
  P14 (W3) and P04-impl (W4) leave.
- **Findings:** WP-1 (MEDIUM), WP-2, WP-6, WP-7, WP-8 (LOW) from the 2026-11-07 whole-repo
  review.
- **Plan:** package P08 of `docs/superpowers/plans/2026-11-07-review-remediation.md`
  (spec in W1, implementation W5+).
- **Scope of the implementation:** `internal/sshwrite` (probe verdicts, retries, restore
  retry, lock owner record, keys2 retention, `SkipWrite`, reconnect after a dropped
  connection), `internal/apply` (two outcomes, exit code, text and JSON reports, the
  interrupt notice, `KeysUnchanged`), the exit-code mapping in the command layer
  (`internal/workflow` after P14; today `cmd/sshepherd/apply.go` and `editrun.go`), README
  and the CLAUDE.md Status paragraph. Error kinds are named against P14's layout
  (`internal/fleet`; today `internal/audit/errors.go`).
- **Code line numbers** are as of `ee14c4d` (identical to `adee207` for the files cited).
  **README line numbers** are as of `ee14c4d`; every implementer finds each section by its
  heading, because W2–W4 move lines.

## Context and goal

`apply` (and `revoke`/`rotate`, which share its run body) writes `authorized_keys` on
production servers and then proves the write by logging in afresh with only the surviving
keys the operator holds. The safety net around that write has five gaps:

- **WP-1.** Any failed login check rolls the server back
  (`probeOrRestore`, `internal/sshwrite/sshwrite.go:542-551`; `probe`, `:591-595`) — even
  a dial timeout, sshd `MaxStartups`, a rate-limit rule (`--hitcount 4 --seconds 60`) or a
  locked agent. During `revoke` the manifest is already saved, so a network blip
  **reinstalls the revoked key**.
- **WP-2.** The safety net lives only in the client. A second signal, SIGKILL after a
  container grace period, a transport drop after the upload started (`sshwrite.go:385-388`)
  or a verify transport error (`sshwrite.go:396`) all leave the new file in place with no
  login check, and README's "a dropped connection leaves the original untouched"
  (README:1454) is then not always true.
- **WP-6.** "Login check failed AND restore failed" — the operator may be locked out — exits
  1 (`ExitCode`, `internal/apply/plan.go:588-603`), the same as harmless drift. JSON has no
  field for it (`internal/apply/json.go:286-287`, the summary struct `:43-53`), and a
  restore refused by a busy lock (exit 47, `sshwrite.go:583-584`) is never retried.
- **WP-7.** The lock is a bare `mkdir` (`lockPrologue`, `sshwrite.go:147`) with no owner or
  time. A stale lock blocks every later write, and `LockedError` (`sshwrite.go:287-293`)
  cannot say who left it or when.
- **WP-8.** `disableKeys2Cmd` runs `rm -f "$s"` before `mv` (`sshwrite.go:247`), so an
  earlier disabled `authorized_keys2` copy is destroyed. A plan that only disables keys2
  (`plan.go:213-216`) still rewrites `authorized_keys` and rotates `.bak`
  (`sshwrite.go:205`), losing the one-step undo.

Goal: sort login-check failures by **what they prove**, make a possible lockout page a
human (exit 2), make locks self-describing without ever breaking them automatically, close
the dropped-connection gap without a server-side agent, and stop destroying backups.

## What the code does today (grounding, `ee14c4d`)

- `Apply` (`sshwrite.go:367-423`): connect (session budget 2 min, `defaultSessionBudget`,
  `:69`), stage 1 guarded write script, stage 2 verify (byte compare), stage 2b disable
  keys2, stage 3 `probeOrRestore`. `execCtx` is `context.WithoutCancel(ctx)` with no
  deadline (`:376`); the socket carries the budget deadline.
- `probe` (`:591-605`) dials with `ConnectOptions{Only: survivors}`; a connect error is
  returned as is (already an `*sshconn.Error` with a kind), an exec error is wrapped
  `probe command: …`, a wrong exit/output is "a forced command= on the surviving key?".
  With no explicit deadline the probe dial falls back to `3×DialTimeout` = 30 s
  (`internal/sshconn/connect.go:134-146`).
- Any probe error → `restoreCmdFor` over the still-open write connection (`:551`), then
  `restoreKeys2Cmd` if keys2 was disabled; the keys2 failure is `errors.Join`ed into
  `LockoutError.Restore` (`:569`). `restoreExitError` maps 47 to "another apply holds the
  lock" with no retry (`:583-584`).
- Kinds (`internal/audit/errors.go:18-40`; `fleet` after P14): `unknown`,
  `host_key_unknown`, `host_key_changed`, `host_key_type_unrecorded`, `host_key_revoked`,
  `host_key`, `agent`, `auth`, `dial`, `timeout`, `canceled`, `handshake`, `remote`.
  `handshakeKind` (`internal/sshconn/errors.go:42-57`) sets `auth` from x/crypto's
  "unable to authenticate" message; a failed session open or exec is `remote`
  (`connect.go:311`, `:329`).
- Outcomes (`plan.go:39-44`): `pending`, `applied`, `refused`, `failed`. `ExitCode`
  (`plan.go:588-603`) returns 0 or 1 only; its comment says 2 stays reserved.
- The command layer maps any `ExitCode != 0` to `errNonCompliant` (exit 1):
  `cmd/sshepherd/apply.go:116`, `editrun.go:335`, `editrun.go:378`. `auditVerdict`
  (`cmd/sshepherd/audit.go:125-131`) is the model for a 0/1/2 mapping.
- P11 (W2) rewrites the write script before this lands: upload first, then a snapshot copy
  (`.sshepherd.cas`) compared and kept as `.bak`, per-file flush, refusals create nothing,
  and one probe offering survivors in production order (`audit.OfferOrder`, P11's
  `offerRank`; owner decision D31). P14 (W3) moves kinds to `internal/fleet` and the run
  body to `internal/workflow` (`Outcome.ExitCode()` is the hook this spec extends).

## Decisions

D9, D9b and D10 were asked one at a time and answered on 2026-11-07 (master plan,
"Answers recorded"). D10a, D10b and D9c were open points 1, 2 and 3 in the first draft;
each changes an exit code or the JSON contract, so under the plan's rule ("Technical
sub-choices that do not change what a user sees are decided by the spec author") they are
owner questions, asked after D10 (the P04 spec did the same with D4c, D1d and D1e). Until
they are answered, their stated default holds. D11–D13 are stated, not asked; the owner can
change any of them at spec approval.

**Reverses** names the documented decision or text the answer overturns. **README sections
it changes** names each section by its heading, with its line at `ee14c4d`, for the
recommended (or chosen) answer, and then what changes instead under the other options.
P08-impl's integrator updates exactly these sections in the same commit, with sample
output copied from the goldens.

| ID | Finding | Question | Options | Recommendation | Owner choice | Reverses | README sections it changes |
|---|---|---|---|---|---|---|---|
| **D9** | WP-1 | If the login check after a write can't even log in because of the network (the server never answered), should SSHepherd undo the write? | (1) Retry a few times; if it still can't log in, keep the new file and report UNPROVEN (exit 1). Anything that goes wrong after login (a forced command, a hang) still undoes the write. (2) Retry, then undo. (3) Keep today: undo on any failure. | (1) — undoing can put a revoked key back. | **(1)** (2026-11-07) | review-hardening spec `2026-10-16-review-hardening-design.md:260-263` ("That holds for network failures too: if access cannot be proven, the server goes back to its previous file"); README "Verify, then prove you can still log in" (README:1470-1481, "If the probe fails, the previous file … is restored"). | **Safety model → Verify, then prove you can still log in** (l.1470): the stage-sorted verdicts, the retries, the 15 s probe deadline, UNPROVEN (file kept), and the FAILED line naming the removed keys a rollback put back; **Exit codes** (l.1373): row 1 for `apply`, `revoke` and `rotate` gains "unproven"; **`sshepherd apply` → JSON** (l.588): `outcome` gains `unproven`, `summary` gains its count, and an unproven server's `error_kind` is the last probe failure's; **`sshepherd apply` summary sample** (l.768): an UNPROVEN example. Under (2): only Verify (retries, then restore); no new outcome or exit row. Under (3): none. |
| **D9b** | WP-5 follow-up | Should the login check also try your `--identity` key on its own, and only warn if that fails? | Yes (warn only, unrestricted key-file lines only) / No | Yes, warn only; never undoes a write. | **Yes** (2026-11-07) | Nothing documented (P11 removed the earlier restoring variant). | **Safety model → Verify, then prove you can still log in** (l.1470): the warn-only headless proof (one extra connection, mixed-source runs only) and its stderr line `<server>: warning: your --identity key <path> could not log in on its own (…); a headless run with only that key would fail`. JSON: nothing under D9c's default. Under No: none. |
| **D10** | WP-6 | If the login check fails and the undo also fails, so you might be locked out, should apply exit 2 so monitoring pages you? | Yes (and retry the undo on a busy lock) / No (stay exit 1) | Yes — follows D28's meaning of exit 2 ("a human must act now on security"). | **Yes** (2026-11-07) | README "Exit codes" row 2 (README:1382, "`apply`, `revoke` and `rotate` never return `2`") and its lead "(code `2` is `audit`-only)" (README:1375-1376); `ExitCode` comment (`plan.go:588-593`); apply-json contract "written exactly when the run exits 0 or 1" (README:593). | **Exit codes** (l.1373): the lead "(code `2` is `audit`-only)" goes and row 2 gains `apply`, `revoke` and `rotate`: "lockout not restored"; **`sshepherd apply` → JSON** (l.588): `outcome` gains `lockout_unrestored`, `summary` gains its count, "written exactly when the run exits `0` or `1`" becomes "0, 1 or 2", and the open-enum rule; **Safety model → Verify, then prove you can still log in** (l.1470): the restore retry on a busy lock and exit 2 for an unrestored lockout; **`sshepherd apply` summary sample** (l.768): a `LOCKOUT — NOT RESTORED` example. Under No: none of these; the unrestored lockout stays a FAILED line at exit 1. |
| **D10a** | WP-1 (open point 1) | When a failed login check undoes a write and the restored file grants again a key the manifest has revoked, should apply exit 2 at once, or exit 1 and leave the page to the next audit? | (1) Exit 1; the FAILED line names each key the rollback put back (label and fingerprint), and the next audit reports a reinstalled revoked key as critical (D2, P04). (2) Exit 2 at once when a restored file grants a key on the manifest's `revoked:` list (D28: "a human must act now on security"). | (1) — apply's exit 2 keeps one meaning ("you may be locked out"), the rollback is the step that kept you able to log in, and the FAILED line already names the keys. Against it: the page waits for the next scheduled audit, so a fleet audited daily may carry the revoked key for up to a day; (2) pages at once. | **pending** (default (1) until answered) | Under (2): README "Exit codes" row 2's audit-only scope, beyond D10. | **Safety model → Verify, then prove you can still log in** (l.1470): the FAILED line names the reinstalled keys (under D9 already). Under (2), in addition: **Exit codes** (l.1373): row 2 for `apply`, `revoke` and `rotate` also covers "a rollback put back a revoked key"; **`sshepherd apply` → JSON** (l.588): a `failed` server can come with exit 2 (its `error` names the keys); **`sshepherd apply` summary sample** (l.768): its example ends `→ exit 2`. |
| **D10b** | WP-1 (open point 2) | If the login check right after a write meets a host-key alarm (the server's host key changed or is `@revoked`), should apply exit 2 the way audit does, or report UNPROVEN at exit 1? | (1) UNPROVEN, exit 1, no retry, file kept; the line names the alarm. (2) Exit 2 for the host-key kinds audit exits 2 on (`host_key_changed`, `host_key_revoked`, and `host_key_type_changed` if P09's D16 adds it), UNPROVEN at exit 1 for the other host-key kinds. | (1) — apply's exit 2 stays the unrestored lockout, and the next audit exits 2 on the same alarm. Against it: the server changed identity seconds after a write, which is exactly what audit pages on (README "Exit codes" row 2); under (1) a scheduled apply alone does not page. | **pending** (default (1) until answered) | Under (2): README "Exit codes" row 2's audit-only host-key clause. | **Safety model → Verify, then prove you can still log in** (l.1470): the host-key UNPROVEN line (under D9 already); **Exit codes** (l.1373): row 1's "unproven" (under D9 already). Under (2), in addition: **Exit codes** (l.1373): row 2's host-key clause ("a server whose host key changed or is `@revoked`") applies to `apply`, `revoke` and `rotate` too; **`sshepherd apply` → JSON** (l.588): an `unproven` server whose `error_kind` is one of those kinds means exit 2. |
| **D9c** | WP-5 follow-up (open point 3) | When D9b's extra login check with only your `--identity` key fails, should `--json` output carry the warning too, or only stderr? | (1) Stderr only; no JSON field. (2) An additive per-server `warnings` array in the apply JSON (schema stays 1, omitted when empty). | (1) — D9b only runs when an agent key is first in the offer order, which is mostly an interactive run where stderr is read, and under `--json` logs stay on stderr, so a CI log still shows the line. Against it: a script that reads only the JSON never sees the warning; (2) lets it act on it. | **pending** (default (1) until answered) | Nothing documented. | **Safety model → Verify, then prove you can still log in** (l.1470): the warning is stderr only (under D9b already). Under (2), in addition: **`sshepherd apply` → JSON** (l.588): the per-server `warnings` array and when it appears. |
| **D11** | WP-7 | (stated) What does a lock record, and who removes a stale one? | (1) Record who and when; show age and the exact removal command; never remove automatically, no flag. (2) Auto-break locks older than N. (3) A `--break-lock` flag. | (1) — today's behavior plus diagnostics; (2)/(3) overlap the on-hold `apply --force`. | **Stated default (1)** | `LockedError` text (`sshwrite.go:291-292`). | **Safety model → Refusals** lock bullet (l.1443): the owner, age and removal command; removal stays by hand only; **Safety model → Verify, then prove you can still log in** (l.1470): a restore refused by a busy lock names the same owner and age. |
| **D12** | WP-2 | (stated) How is a write protected when the client loses the connection or is interrupted? | (1) No server-side watchdog; a notice on the first Ctrl-C; after a broken connection, reconnect, re-check under the lock, then probe or report. With D10 = yes this adds two exit-2 (`lockout_unrestored`) cases: the reconnect after the upload started is refused with an auth error, or a restore whose connection dropped cannot be retried over the one reconnect (section 4). (2) A detached server-side watchdog that rolls back unless confirmed. | (1) — (2) goes against the agentless design. | **Stated default (1)** | README "One guarded write per server" (README:1453-1455, "a dropped connection leaves the original untouched" — made true again by the re-check, or replaced by an honest "unknown state"). | **Safety model → One guarded write per server** (l.1448): the re-check under the lock and its outcomes, including the refused reconnect (exit 2); **Ctrl-C / SIGTERM** (l.777): the first-signal notice; **Container usage** (l.1363): the grace-period note; **Exit codes** (l.1373): row 2's "lockout not restored" also covers the refused reconnect and the restore that could not be retried; **Safety model → Verify, then prove you can still log in** (l.1470): a restore over a dropped connection is retried over one reconnect, and its failure is a lockout not restored. |
| **D13** | WP-8 | (stated) Which backups survive? | (1) A moved-aside `authorized_keys2` gets a name that is never overwritten; `authorized_keys` is not rewritten (so `.bak` is not rotated) when its bytes already match. (2) Keep today. | (1) — restores what README already promises about `.bak`. | **Stated default (1)** | `disableKeys2Cmd` doc and `rm -f "$s"` (`sshwrite.go:239-247`, "replacing an older disabled copy"). | **Safety model → `authorized_keys2`** (l.1462): copies are never overwritten, the timestamped name, copies accumulate; **Safety model → Backups** (l.1457): `.bak` is not rotated when `authorized_keys` already matches. |

Ask order was D9 → D9b → D10; D10's meaning depends on D9 (with D9 = (1), an unrestored
lockout can only follow a REJECTED login check or a refused reconnect) and on D28 (Block 1,
answered: exit 2 means "a human must act now on security" for every command, one shared
README table). The pending questions follow in the order **D10a → D10b → D9c**: the two
exit-code questions first, both read against D10 and D28.

## Design

### 1. Sorting login-check failures by stage (D9, WP-1)

A new pure function, `classifyProbe(stage, err) verdict`, sorts each login-check failure
into one of two verdicts **by the stage the probe reached, not by error kind alone**. The
dividing line is "did authentication finish?". The static lockout guard only checks that a
held key's line is present; it never evaluates `from=` or `command=`, and it only warns when
every survivor is restrictive. That is why the probe exists, so **nothing after a
successful login is ever waved through as a blip**, and no TRANSIENT row below is justified
by "the guard already passed".

The probe records its stage: `stageDial` (TCP + kex + host key + auth, i.e. the
`ConnectWith` call) or `stageAuthed` (the connect returned a client; session open, exec,
output). A failure inside `ConnectWith` carries its kind; a failure after it is always
`stageAuthed`.

| Stage of the failure | Examples (kind / site) | Verdict | Action |
|---|---|---|---|
| **Before auth finished:** dial, kex/handshake, agent, timeout during dial or handshake | `dial`, `handshake` (MaxStartups, `kex_exchange_identification`), `agent` (a `Signers` failure, `connect.go:152`), `timeout` (`handshakeKind`, `errors.go:46-52`) | **TRANSIENT** | Retry with backoff; when the retries run out, **UNPROVEN** (file and disabled keys2 kept). |
| **Before auth finished:** host-key alarm on the probe dial | `host_key_unknown`, `host_key_changed`, `host_key_type_unrecorded`, `host_key_revoked`, `host_key` (`internal/sshconn/hostkey.go`) | **TRANSIENT, flagged** | **No retry** (the answer will not change). UNPROVEN at once; the message names the host-key alarm. Proving access through an impostor proves nothing, so the file is kept. Exit 1 by default; whether a changed or `@revoked` host key exits 2 is owner question D10b. |
| **Auth refused** | `auth` ("unable to authenticate": a `from=` miss, an algorithm sshd refuses, a key not accepted) | **REJECTED** | Restore now (today's path). |
| **After auth succeeded** | session channel refused (`*ssh.OpenChannelError`), exec failed, `*ssh.ExitMissingError` (channel closed with no exit status), EOF, the **probe-exec deadline** while waiting for the output, exit ≠ 0, or output ≠ `sshepherd-probe-ok\n` (a forced `command=`, `rrsync`/`internal-sftp`-style commands that wait on stdin, `command="sleep 3600"`) | **REJECTED** | Restore. A key that logs in but cannot run SSHepherd's command captures every later session. |
| Unclassifiable (`unknown`, or `canceled`, which cannot normally occur under the detached context) | — | **REJECTED** if the stage is `stageAuthed`; **TRANSIENT** if it is `stageDial` | There is no "unknown is safe" rule; the stage decides. |

**Probe exec deadline: 15 s**, starting when the probe's session opens. On expiry the probe
connection is closed and the verdict is REJECTED, so a hanging forced command ends well
inside the restore reserve.

**Retry policy** (all inside the session budget; numbers are fixed, no flags):

| Item | Value |
|---|---|
| Attempts for TRANSIENT failures | **4** in total; the wait before each attempt is **0, 2 s, 5 s, 10 s** |
| `agent` failures | at most **1 retry** (2 attempts): a locked agent rarely recovers in seconds |
| host-key alarms | **no retry** (1 attempt) |
| Dial bound per attempt | `min(3×DialTimeout, remaining − restoreReserve)` |
| `restoreReserve` | **20 s** — kept back so a REJECTED verdict on the last attempt can still restore over the open write connection |
| Starting an attempt | only while `remaining − restoreReserve > 0`; the first attempt always runs (bounded by `min(3×DialTimeout, remaining)`) |
| Logging | each attempt at Debug with its kind and stage; the final message carries the last cause |

The budget deadline becomes explicit: `connectForWrite` returns the deadline it installed
(`sshwrite.go:459-487`), and the probe, the restore and any reconnect (section 4) derive
their contexts from it instead of `context.WithoutCancel(ctx)` with no deadline (`:376`).
Waits go through a `sleep func(context.Context, time.Duration) error` seam on `FleetWriter`
so tests take no wall-clock time.

**UNPROVEN outcome.** When the retries run out (or a host-key alarm stops them), the file
and the disabled keys2 are **kept** and `Apply` returns:

```go
// UnprovenError: written and verified, but the post-write login never got
// past authentication (dial, kex, agent, host key) after the retries; the
// file is kept because restoring could reinstall a key the manifest removed.
// Any failure after a successful login is a REJECTED probe, never an
// UnprovenError.
type UnprovenError struct {
	Path     string
	Attempts int
	HostKey  bool  // stopped by a host-key alarm (no retry)
	Last     error // sanitized; its kind is the last probe failure's
}

func (e *UnprovenError) Unwrap() error { return e.Last }
```

`Unwrap` keeps the last kind visible to `jsonErrorFor` (`error_kind` is the last probe
failure's kind, e.g. `dial`).

Message (`Error()`), verbatim; `attempt` is pluralized:

- `written and verified, but the login check could not reach the server after 4 attempts (dial tcp 10.0.0.1:22: i/o timeout) — kept the new file; run sshepherd audit to confirm`
- host-key case: `written and verified, but the login check stopped at a host-key alarm (host key changed) — kept the new file; check known_hosts, then run sshepherd audit`

Report line: `web-1: UNPROVEN: written and verified, but the login check could not reach the server after 4 attempts (dial tcp 10.0.0.1:22: i/o timeout) — kept the new file; run sshepherd audit to confirm`.
Outcome `unproven`, exit 1. A budget exhausted before any attempt could start (write and
verify took over 100 s) is also UNPROVEN, `Attempts: 0`, with the cause
`session budget exhausted before the login check`.

**A rollback that reinstalls removed keys.** After a REJECTED probe the restore still puts
back the keys in the plan's `Remove` list. The FAILED line then names them, each the way the
plan's `-` rows name it (label and fingerprint), e.g.
`web-1: FAILED: lockout prevented — restored previous file (…); it still grants alice (SHA256:…), which the manifest removed — fix the surviving key and re-run`.
Exit stays 1 here; the next audit reports a revoked key as critical (D2, P04 spec). Whether
apply itself should exit 2 in that case is owner question D10a (default: exit 1).

### 2. Unrestored lockout (D10, WP-6)

- **Split `LockoutError.Restore`** (`sshwrite.go:298-311`). `Restore` covers only the
  `authorized_keys` restore; a new `RestoreKeys2 error` takes the `restoreKeys2Cmd`
  failure, which today is `errors.Join`ed into `Restore` (`:569`). A failed keys2
  move-back cannot lock anyone out (keys2 only adds keys), so it never raises the exit code.
  `Unwrap` returns `Probe`, `Restore` and `RestoreKeys2`.
- **Restore retry on a busy lock.** On exit 47 only, the restore is retried after **1 s,
  3 s, 6 s** (up to 4 restore attempts), each only while the budget has time left. Any other
  restore exit is final. When the lock is still busy after the last attempt, the restore
  error carries the lock owner and age (section 3):
  `restore on web-1 refused: another apply holds the lock (held by ci-runner-3 pid 4121 for 3m12s) after 4 attempts`.
- **Outcomes** (`plan.go:39-44`), two new values:
  - `OutcomeUnproven = "unproven"` — written and verified, login not proven (section 1).
  - `OutcomeLockoutUnrestored = "lockout_unrestored"` — a `*LockoutError` whose `Restore`
    is non-nil (the login check was REJECTED and the previous `authorized_keys` could not be
    put back), or the refused reconnect of section 4.
  A `*LockoutError` with `Restore == nil` stays `failed` (lockout prevented), even when
  `RestoreKeys2` is non-nil.
- **Exit code.** `ExitCode` returns **2** if any plan is `lockout_unrestored`; otherwise
  today's rule (0 when every server converged, else 1; `unproven` is not converged → 1).
  Precedence across a run: **3 > 2 > 1 > 0**.
- **Text** (`RenderSummary`, `internal/apply/report.go:267-304`): new lines
  `LOCKOUT — NOT RESTORED:` (bold red) and `UNPROVEN:` (yellow); the Summary line appends
  `· N unproven` and `· N lockout not restored` after today's segments. Example (the
  README copies the real text from the new goldens, never this sketch):
  `Summary: 1/3 servers converged (1 applied) · 1 unproven · 1 lockout not restored  → exit 2`.
  The `LOCKOUT — NOT RESTORED:` line carries today's `LockoutError` message
  (`sshwrite.go:308`), which names the `.bak` path.
- **JSON** (`internal/apply/json.go`): `outcome` gains `unproven` and
  `lockout_unrestored`; `summary` gains `unproven` and `lockout_unrestored` counts. The
  schema stays **1**: the change is additive, and the apply-json contract gains the rule
  **"treat an unknown `outcome` value as not converged"**. The document rule "written
  exactly when the run exits 0 or 1" becomes **"0, 1 or 2"** (revoke and rotate share it).
- **Command layer.** The mapping from `ExitCode` to the process exit becomes an
  `applyVerdict` that returns the exit-2 error (today `errCriticalDrift`) for 2 and
  `errNonCompliant` for 1, mirroring `auditVerdict`. After P14 this is
  `workflow.Outcome.ExitCode()` and its one caller per command; today it is the three
  sites `cmd/sshepherd/apply.go:116`, `editrun.go:335`, `editrun.go:378`. `revoke` and
  `rotate` inherit it, so the D28 table's revoke/rotate column gains the same exit-2 row.

### 3. Lock owner record (D11, WP-7)

- **Record.** After P11's rewrite, `lockPrologue` sets the EXIT trap **first**, then
  writes `$l/owner`, one line:

  ```
  v1 <client-host> <client-pid> <remote-pid> <remote-epoch>
  ```

  `<client-host>` is `os.Hostname()` reduced to `[A-Za-z0-9._-]` and capped at 64 bytes
  (`unknown` if empty); it and `<client-pid>` enter the script as one `sshconn.ShQuote`d
  literal. `<remote-pid>` is `$$`, `<remote-epoch>` is `$(date +%s)`. The trap gains
  `rm -f "$l/owner"` before `rmdir "$l"`. Order matters: the trap must exist before the
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
  leave `<path>.sshepherd.tmp` and P11's `<path>.sshepherd.cas`; both are reclaimed by the
  next write and need no hand removal.
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
  transport error (an `err != nil`, not an exit code) in stage 1 (`sshwrite.go:385-388`)
  or in verify (`:396`), `Apply` opens **one** fresh full-credential connection within the
  budget and **takes the per-target lock first** (the dropped script may still be running
  and holding `$p.sshepherd.lock`, e.g. between the upload and `mv`): a script made of the
  lock prologue plus the read of `sshconn.AuthorizedKeysCmdFor`, retried on 47 with the
  restore-retry schedule (1 s, 3 s, 6 s). Only then does it decide:

  | Re-read under the lock | Outcome |
  |---|---|
  | bytes equal the render | the `mv` happened: release the lock and continue with keys2 and the probe over the new connection. A REJECTED probe restores over the new connection; if that fails, `lockout_unrestored`. |
  | the file matches the plan's snapshot (`req.Expect`) | FAILED: `connection dropped before the rename; original untouched (re-checked under the lock)` |
  | the lock never frees within the budget, the reconnect fails with a non-auth kind, or the bytes are anything else | FAILED: `connection dropped; the file is in an unknown state (previous version at <path>.sshepherd.bak) — run sshepherd audit` |
  | the reconnect fails with an **auth**-kind error after the stage-1 exec had started | `lockout_unrestored` (exit 2): `connection dropped after the upload started and a fresh login offering the keys you hold was refused (…) — the new file may lock you out; the previous version is at <path>.sshepherd.bak`. Represented as `*LockoutError{Probe: <reconnect error>, Restore: errNoSession}`. |

  For a **verify** transport error the same reconnect-and-reread applies (the lock is free
  by then, so it is taken at once). A verify that *read* the file and found different bytes
  stays FAILED with no probe, as today: SSHepherd did not write those bytes, so it must not
  restore over them.
- **Restore over a dead connection.** If the restore exec after a REJECTED probe returns a
  transport error, the same single reconnect is used to retry it (unless the reconnect was
  already spent); a refused or failed reconnect leaves `Restore` set, so the outcome is
  `lockout_unrestored`. At most one reconnect per server write.

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
- **Keys2-only plans do not rewrite `authorized_keys`.** `planOne` already knows `same`
  (`plan.go:213`). `ServerPlan` gains `KeysUnchanged bool` (`same && AuthorizedKeys2`) and
  `sshwrite.Request` gains `SkipWrite bool`. With `SkipWrite`, `Apply` skips stage 1 (no
  lock, `.bak`, `.orig`, upload or `mv`), re-reads and byte-compares the file (the verify
  doubles as the compare-and-swap: a mismatch is a `*ChangedError`, a refusal, outcome
  `refused`), disables keys2 and probes. A REJECTED probe restores only keys2; an UNPROVEN
  login keeps keys2 disabled. A header-only write P04-impl may require (an older serial) is
  not `same`, so it is never `KeysUnchanged`.
- **JSON: no new field.** The `rewrites_authorized_keys` bool suggested in the plan is
  **not** added: a keys2-only server is already visible as empty `changes` plus
  `disables_authorized_keys2: true`, and the field would touch every golden for no new
  information. Plan text is unchanged.

### 6. Headless key-file proof (D9b, warn only)

P11 makes the probe offer survivors in the exact order every later run offers them (D31),
so an interactive run with an agent key first proves the agent key, not the `--identity`
file. With D9b = yes:

- **When:** after a passing probe, and only when the production order's first survivor is
  agent-sourced **and** at least one surviving key file's manifest line is unrestricted
  (P11's `offerRank` 0). `internal/apply` computes this from the held keys' sources and sets
  `Request.HeadlessProof []string` (those key-file fingerprints; empty otherwise).
- **What:** one more login offering only `HeadlessProof` (`ConnectOptions{Only: …}`) that
  runs the probe command, under the same 15 s exec deadline and inside the budget (skipped,
  with a Debug line, if less than `restoreReserve` remains).
- **Failure only warns** and never restores, so it cannot roll back a write the first probe
  proved, or reinstall a revoked key. Warn line (stderr, normal verbosity):

  `web-1: warning: your --identity key /k/ci could not log in on its own (ssh: unable to authenticate); a headless run with only that key would fail`

  The outcome stays `applied`; no JSON field (owner question D9c, default: stderr only).
- **Cost:** one extra connection per written server, in mixed-source runs only. Against
  WP-1's rate-limit evidence (`--hitcount 4 --seconds 60`, `MaxStartups`): today a written
  server already sees 3 connections in a run (the phase-1 read, the write, the probe); the
  proof makes it 4 in mixed-source runs, which such a rule may drop. Because the proof is
  warn-only, a dropped proof only produces the warning (naming the cause); it never touches
  the write. Key-file-only and agent-only runs make no extra connection.

## New exported surface (post-P14 layout)

| Package | Name | Notes |
|---|---|---|
| `internal/sshwrite` | `UnprovenError{Path, Attempts, HostKey, Last}` | section 1 |
| `internal/sshwrite` | `LockoutError.RestoreKeys2 error` | section 2 |
| `internal/sshwrite` | `LockedError{Path, Owner, Age, Known, RemoveCmd}` | section 3 |
| `internal/sshwrite` | `Request.SkipWrite bool`, `Request.HeadlessProof []string` | sections 5, 6 |
| `internal/apply` | `OutcomeUnproven`, `OutcomeLockoutUnrestored` | section 2 |
| `internal/apply` | `ServerPlan.KeysUnchanged bool` | section 5 |
| `internal/fleet` | no new kinds; `fleet.ErrorKindOf` reads the kind through `UnprovenError.Unwrap` | — |
| `internal/workflow` | `Outcome.ExitCode()` returns 0, 1 or 2 | section 2 |

Unexported: `classifyProbe`, the probe stage, `parseLockOwner`, `restoreReserve`, the
schedules, and the `sleep` seam.

## Exit codes and JSON (rows added to the shared D28 table)

This spec only adds rows to the one exit-code table that D28 fixes (P04 spec,
`2026-11-08-revocation-memory-design.md` section 8). The first wave that lands an exit-2 row
rewrites README "Exit codes" from that table.

| Code | apply | revoke / rotate |
|---|---|---|
| 1 | **unproven** (written and verified, login check never got past authentication) | the same |
| 2 | **lockout not restored** (`lockout_unrestored`: the restore after a REJECTED login check failed, a restore over a dropped connection could not be retried, or the reconnect after the upload started was refused) | the same |

Under D10a's alternative, row 2 also gains "a rollback put back a revoked key"; under D10b's
alternative, an unproven server stopped by a changed or `@revoked` host key moves from row 1
to row 2. With the defaults, neither row changes.

JSON: `outcome` enum + `unproven`, `lockout_unrestored`; `summary` + `unproven`,
`lockout_unrestored`; `schema` stays 1 with the open-enum rule; a document is written on
exit 0, 1 or 2; `error_kind` on an unproven server is the last probe failure's kind.

## README sections this changes (applied by P08-impl, never before)

Found by heading; line numbers as of `ee14c4d`. Samples are copied from the new goldens.
This is the union of the decisions table's **README sections it changes** column for the
recommended answers; an owner answer that picks an alternative (D10a, D10b, D9c) adds the
sections that column names for it.

- **Exit codes** (README:1373-1383): the lead "(code `2` is `audit`-only)" and the row-2
  text "`apply`, `revoke` and `rotate` never return `2`" go; rows come from the shared table
  (apply/revoke/rotate 1: unproven; 2: lockout not restored, including the refused
  reconnect and the restore that could not be retried over a reconnect).
- **`sshepherd apply` → JSON** (README:588-600): the outcome list gains `unproven` and
  `lockout_unrestored`; "written exactly when the run exits `0` or `1`" becomes "0, 1 or 2";
  the open-enum rule. (D9c's alternative adds the per-server `warnings` array.)
- **`sshepherd apply` summary sample** (README:768-775): re-copied from `summary_*.golden`,
  plus an UNPROVEN and a LOCKOUT — NOT RESTORED example.
- **Ctrl-C / SIGTERM** (README:777-784): the first-signal notice.
- **Safety model → Refusals** lock bullet (README:1443-1446): owner, age and the removal
  command; still removed by hand only.
- **Safety model → One guarded write per server** (README:1448-1455): the dropped-connection
  sentence becomes the re-check under the lock and its outcomes, including the refused
  reconnect after the upload started (lockout not restored, exit 2).
- **Safety model → Backups** (README:1457-1460): `.bak` is not rotated when
  `authorized_keys` already matches.
- **Safety model → `authorized_keys2`** (README:1462-1468): copies are never overwritten;
  the timestamped name; copies accumulate.
- **Safety model → Verify, then prove you can still log in** (README:1470-1481): the
  stage-sorted verdicts, retries, UNPROVEN, the 15 s probe deadline, the FAILED line naming
  removed keys a rollback put back, the restore retry on a busy lock (naming the lock's
  owner and age), a restore over a dropped connection retried over one reconnect, exit 2
  for an unrestored lockout, and the warn-only headless proof with its stderr line.
- **Container usage** (README:1363-1371): `docker stop -t 150` /
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

## Interactions with on-hold items and other packages

- **apply wipe/empty-server mode:** not touched. A restore after a REJECTED probe still
  removes a file a first-contact write created (`restoreCmdFor`, `wasAbsent`,
  `sshwrite.go:232-234`): that is a rollback, not a wipe mode.
- **apply --force:** not touched; no lock is ever broken automatically.
- **prune, import --prefer, key generation/scheduled rotation, move-key:** no overlap.
- **P04 (revocation memory, W4):** a restore puts `.bak` back verbatim, header serial
  included; the next audit sees the previous serial and, per D2, reports a reinstalled
  revoked key as critical. A keys2-only plan is never a header-only serial write.
- **P11 (W2):** the lock owner record and the reconnect read rebase on P11's prologue and
  trap; `TestWriteCmdOrder` and `TestProbeOfferEqualsProductionOffer` stay green. P11's
  `.sshepherd.cas` is listed as possible residue.
- **P14 (W3):** kinds come from `internal/fleet`, the run body and exit mapping from
  `internal/workflow`.
- **P03:** the hermetic REJECTED case uses P03's changeable `sshtest` authorized list.

## Testing (P08-impl, failing first)

Every behavior lands with a test that fails before the change. Unit tests are hermetic
(seams, fake clock, no network).

**`internal/sshwrite`**

1. `TestClassifyProbe` (table): `auth` at `stageDial` → rejected; `dial`, `timeout`,
   `handshake`, `agent` at `stageDial` → transient; each `host_key_*` → transient, no retry;
   `fmt.Errorf("open session: %w", &ssh.OpenChannelError{})` → rejected;
   `&ssh.ExitMissingError{}`, `io.EOF`, a wrong output → rejected (`stageAuthed`);
   `unknown` → rejected after auth, transient before.
2. Seamed `Apply`: an exec that blocks past the 15 s probe deadline (fake clock) → restored
   `*LockoutError`; an `ExitMissingError` → restored `*LockoutError`.
3. Retry and UNPROVEN (extends `TestApplyLoginProbeFailureRestores`): the "probe session
   refused" case becomes an `OpenChannelError` and still restores; a dial-kind error 4 times
   → `*UnprovenError`, no restore command, 5 connects in total; dial fails twice then
   succeeds → nil; an auth error on the first attempt restores with no retry; an agent error
   is retried once; a host-key error is not retried and sets `HostKey`.
4. Restore retry and the split: restore exits `[47, 47, 0]` → `Restore == nil` after 3
   restore commands; `[47, 47, 47, 47]` → `Restore != nil` naming the lock owner; a keys2
   restore failure with a good main restore → `Restore == nil`, `RestoreKeys2 != nil`.
5. Lock owner: `TestWriteCmdThroughRealSh` under dash, bash and busybox — a pre-made lock
   with an owner file exits 47 with parsable stdout; after a successful run neither `$l`
   nor `$l/owner` remains; a script killed through its own `trap` path leaves no lock.
   `parseLockOwner` unit cases (valid, bare/absent, hostile ESC bytes, too long, negative
   age) and `FuzzParseLockOwner` with a seed corpus.
6. Keys2 retention (real sh): an existing `.sshepherd.disabled` is never deleted; the second
   copy gets the timestamped name; a third in the same second gets `.$$`;
   `restoreKeys2Cmd(name)` moves back exactly that name.
7. `SkipWrite`: the first command is the read, not `writeCmdFor`; no `.bak`; a mismatch →
   `*ChangedError`; a REJECTED probe restores only keys2.
8. Reconnect (seamed): stage-1 transport error with the re-read returning (a) the render →
   probe runs; (b) the old bytes → "original untouched (re-checked under the lock)"; (c)
   other bytes → "unknown state"; (d) the reconnect's lock exits 47 twice, then the read
   sees the render; (e) the reconnect fails with an auth kind → `*LockoutError` with
   `Restore` set. The same set for a verify transport error, and a restore transport error
   retried over the reconnect.
9. D9b: an agent-first survivor list with an unrestricted key file → one extra `Only`
   connect; its failure logs the warning and returns nil; a restricted key-file line or a
   key-file-first order makes no extra connect.

**`internal/apply`**

1. `TestExitCode`: `lockout_unrestored` → 2; `unproven` → 1; `applied` +
   `lockout_unrestored` → 2.
2. `TestExecuteOutcomes`: `*sshwrite.UnprovenError` → `OutcomeUnproven`;
   `&sshwrite.LockoutError{Restore: errors.New("x")}` → `OutcomeLockoutUnrestored`; the
   existing `Restore == nil` case stays `OutcomeFailed`; a FAILED rollback with a non-empty
   `Remove` names the reinstalled keys.
3. `TestExecuteInterruptNotice`: a blocking fake writer, cancel ctx, the captured Warn
   contains `finishing 1 in-flight write`; no notice with nothing in flight.
4. `KeysUnchanged`/`SkipWrite`: `same && AuthorizedKeys2` → `KeysUnchanged`, and the request
   carries `SkipWrite`; `HeadlessProof` is computed only for the D9b condition.
5. Goldens via `-update`: `summary_unproven.golden`, `summary_lockout.golden`,
   `json_failures.golden.json`; the round-trip asserts the `unproven` and
   `lockout_unrestored` counts and `exit_code: 2`.

**Command layer:** `TestApplyLockoutUnrestoredExits2` (hermetic, fake writer) — exit 2 and a
JSON document still written; the same through `revoke`.

**Integration** (`//go:build integration`, `make integration`):
`TestIntegrationProbeTransientKeepsFile` (the probe's `Only` connects are redirected to a
closed port → UNPROVEN, file kept); `TestIntegrationStaleLockReportsOwnerAndAge`;
`TestIntegrationKeys2DisabledNeverOverwritten`; `TestIntegrationLoginProbeRestores` stays
green; a hermetic case where the written file drops the survivor (auth REJECTED → restore).

**E2E:** one UNPROVEN step in `cmd/sshepherd/e2e_test.go` if P13 leaves a hook for it,
otherwise recorded as a gap.

## Implementation timing

P08-impl runs in W5 or later: after P11 (W2, rewrites the write script and probe order),
P14 (W3, moves kinds to `internal/fleet` and the run body to `internal/workflow`) and
P04-impl (W4, the shared exit-code table and the serial header). Its plan re-targets every
file to P14's layout. Two agents with disjoint files (A: `internal/sshwrite`; B:
`internal/apply` plus the verdict in `internal/workflow`), then one integrator for
`make check`, `make integration`, README and CLAUDE.md. The integrator pins the exported
types above in the plan before the agents fork.

## Open points for spec approval

None remain. The first draft's three open points each changed an exit code or the JSON
contract, so they are now owner questions in the Decisions table: **D10a** (was 1: a
rollback that reinstalls a revoked key), **D10b** (was 2: a host-key alarm on the probe)
and **D9c** (was 3: the D9b warning in JSON). Each keeps its stated default until it is
answered.

## Out of scope

- WP-3 (compare-and-swap before upload), WP-4 (fsync), WP-5 (probe key order), WP-9 (mkdir
  on refusal), WP-10 (keys2 path spelling): P11.
- Re-deciding on-hold items: no automatic lock breaking, no `--break-lock`/`--force`, no
  empty-server or wipe change.
- How loud a rollback that reinstalls a revoked key is beyond naming the keys and D10a's
  exit code (D2 belongs to P04).
- A configurable session budget or retry flags.
