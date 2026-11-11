# Design: audit trust, key policy and connection posture

- **Date:** 2026-11-08 (drafted in wave W1 of the review-remediation plan)
- **Status:** Approved (owner, 2026-11-08). Owner decisions D14–D19 were answered on
  2026-11-07 and OP1–OP6 on 2026-11-08; the spec-author defaults D14a–c and D17a–b
  stand. Implementation is W5+ (**P09-impl**), after P14 (W3, landed).
  Implementation landed in W6.
- **Findings:** SEC-1, COR-5, COR-6, SEC-5 (LOW) and PRD-9, PRD-10 (MEDIUM) from the
  2026-11-07 whole-repo review.
- **Plan:** package P09 of `docs/superpowers/plans/2026-11-07-review-remediation.md`
  (spec in W1, implementation in W5+).
- **Composes with:** `2026-11-08-revocation-memory-design.md` (P04, landed in W4): the
  shared exit-code table (D28) and policy conflicts (D29). This spec adds audit rows
  to that table and one new conflict kind; it does not restate P04's rows.
- **Amends:** `2026-07-06-audit-slice-design.md` (critical tier, read sessions),
  `2026-07-16-audit-json-exit-codes-design.md` (JSON fields, `error_kind`, exit table),
  `2026-07-10-operator-users-wildcard-access-design.md` (what "missing operator key"
  covers), `2026-10-16-identity-keyfile-auth-design.md` (key offering).
- **Code anchors:** by function name, checked against master at `4390667`. README
  sections are named by heading.

How to read this spec: every wording in `code` quotes is target text. It becomes a
test expectation, and after implementation the README copies it **from the goldens**,
never from this document.

## Context and goal

`audit` is the tool's monitoring surface: a scheduled run that exits 0 should mean
"the fleet's managed `authorized_keys` files are what the manifest says, and nothing
about them needs a human". Six review findings show where that promise is weaker
than it reads:

- **What audit sees.** It reads one file per server with a bare `cat`
  (`sshconn.AuthorizedKeysCmdFor`) and never checks that file's mode or owner, or its
  directories' (**SEC-1**). The write path refuses the same conditions with exit 48
  (`ancestorCheck` in `internal/sshwrite/sshwrite.go`). And the README used to promise
  more than one file can show (**PRD-9**, narrowed by D18, section 6).
- **How audit grades it.** An operator key installed as `cert-authority` or
  `principals=` lands in `Diff.OK` and shows as options drift (exit 1), although it
  cannot log in: `criticalDrift` (`internal/audit/report.go`) looks only at
  `Diff.Missing` for operators, while `authkeys.CertOnly` already knows such a line is
  dead (**COR-5**). A server that suddenly presents a host key of a type `known_hosts`
  does not record ends up as `host_key_type_unrecorded` (`hostKeyHint`,
  `internal/sshconn/hostkey.go`), which `hostKeyAlert` (`internal/audit/errors.go`)
  keeps at exit 1 (**COR-6**). And there is no key policy: `authkeys.ParseLine`
  accepts DSA and 1024-bit RSA, and only `rotate` reads `expiry-time` (**PRD-10**).
- **What the client reveals.** `orderSigners` (`internal/sshconn/connect.go`) offers
  the granted keys first and then **every other** held key, so any managed server —
  including a hostile one — learns every public key the operator holds (**SEC-5**).

The goal: audit checks what sshd itself checks before honouring a file, grades a dead
operator key and a host-key type change as the alarms they are, flags weak and
expired keys, the README claims only what audit can see, and each server is offered
only the keys the manifest grants there. All agentless, all additive to JSON
schema 1.

## What the code does today (grounding, `4390667`)

- **Read sessions.** `Client.readAuthorizedKeys` (`internal/sshread/sshread.go`) opens
  one connection and runs the read command, then a second session for **every** read:
  `sshconn.SecondaryKeysCmdFor(path)`, mapped by `FinishSecondaryProbe` (exit 46 =
  non-empty `authorized_keys2`, any other non-zero exit = `ErrorKindRemote`). For a
  path other than the default spelling, the probe first decides on the server whether
  the path is equivalent to `~/.ssh/authorized_keys` (`cd -P`, `test -ef`). So every
  read costs two sessions, override or not. The post-revoke sweep alone adds a third
  (`readKeys2`, when `Client.ReadKeys2` is set and the file is present).
- **One reader for every command.** audit, adopt, apply, revoke, rotate and the sweep
  all read through `sshread.Client`, and `ServerResult.Compliant` is called only from
  `statusOf`.
- **The read command is a contract.** `sshwrite`'s verify step reads back through
  `AuthorizedKeysCmdFor` byte for byte. It must not change.
- **The write walk.** `writeCmdFor` (`internal/sshwrite/sshwrite.go`) refuses (48) a
  symlinked directory, a directory not owned by the login uid, and a **file** not
  owned by the login uid (root is **not** accepted for the file or its directory).
  `ancestorCheck` then walks the directory's ancestors up to `$HOME`, as written and
  resolved (`cd -P`), refusing any component that is group- or world-writable
  (`?????w*` / `????????w*` on `ls -ldn`'s mode) or owned by neither the login uid nor
  root. A symlinked component skips only the mode check; its owner is still checked.
  A symlinked target file exits 45. A path outside `$HOME` is walked to `/`.
  `restoreCmdFor` and `disableKeys2Cmd` share the same `ancestorCheck`.
- **sshd's own rule (StrictModes, default `yes`).** sshd ignores an
  `authorized_keys` file that is group/world-writable or owned by neither the user
  nor root, or whose directories up to the home directory are; it follows symlinks.
  So a login that succeeded on a server whose managed file fails this rule came
  either through another key source or with `StrictModes no` (an open door). Either
  way the file audit read is not what governs access there.
- **sshd tries every line.** For a key listed on several lines, sshd keeps scanning
  after a line it ignores or whose options refuse this login. `authkeys.Diff` keeps
  only the first line per fingerprint (`Result.Actual`), and `ServerResult.Duplicates`
  already says the least restricted copy wins.
- **Critical tier.** `criticalDrift` is true for a missing operator key, a revoked
  key still installed (D2), a forged header serial, or membership in a policy
  conflict's `Servers` (D29). `statusOf` ranks unreachable > critical > drift >
  compliant. `audit.ExitCode` returns 2 whenever `cfg.Conflicts()` is non-empty, even
  with no server read. `ServerResult.Compliant` has no posture input.
- **Host-key negotiation and the certificate path.** `KnownHosts.HostKeyAlgorithms`
  orders certificate algorithms (only when `authorityMatches` finds an
  `@cert-authority` line for the host), then the algorithms for the recorded plain
  types, then every remaining plain algorithm. OpenSSH does the same: it **reorders**,
  it does not restrict. A plain key that mismatches reaches `KeyError`, whose `Want`
  includes the matching `@cert-authority` keys (x/crypto v0.58 `checkAddr`). A
  certificate never does: an unvouched signer fails `CheckHostKey` with "no authorities
  for hostname", which `hostKeyHint` classifies `host_key` (exit 1).
- **Key offering.** `Credentials.Signers` returns every key-file and agent key
  (certificates included). `Dialer.ConnectWith` takes `prefer` from
  `Dialer.PreferKeys`, which audit and adopt (`readFleet`) and apply (`newApplyCmd`)
  set to `audit.GrantedFingerprints` (in `authkeys.OfferOrder`:
  plain, then `from=`/`expiry-time=`/`restrict`, then `command=`, then cert-only;
  stable in `DesiredFor` order, so operators lead within a rank), and revoke/rotate
  (`runEdit`) and their sweep (`runSweep`) to the former∪edited union. The post-write probe passes
  `ConnectOptions.Only`, which never falls back. The write connection
  (`FleetWriter.connectForWrite`) passes `ConnectOptions{}` and inherits
  `Dialer.PreferKeys`.
- **Expiry and option helpers.** P05 already landed `authkeys.CertOnly`,
  `authkeys.FindOption` and `authkeys.ExpiryTime` in `internal/authkeys/options.go`.
  `apply.certOnly` and `cmd/sshepherd/keyarg.go`'s `expiryOption`/`expiryPassed` are
  now thin wrappers over them. D27 makes a malformed `expiry-time` a load error;
  nothing evaluates a well-formed one outside `rotate`.
- **Policy conflicts.** `config.Conflict{Kind, Message, User, Fingerprint, Servers}`
  with `ConflictRevokedKey` and `ConflictRevokedAccess`, computed by
  `Config.computeConflicts`. `audit.renderConflicts` prints them; apply's
  `conflictRefusal` (`internal/apply/serial.go`) refuses every named server from
  `planOne`; cmd's `conflictRefusal` (`cmd/sshepherd/conflicts.go`) refuses any save
  whose result still holds one.

## Owner decisions

Asked one at a time in the plan's order (Block 4: D14 → D15 → D16 → D17 → D18 → D19)
and answered 2026-11-07. They are final. **Safe default (if unanswered)** is what the
implementation would have built had the decision gone unanswered (the plan's rule:
usually today's behavior); it is kept so a reader can see what each answer changes.

| # | Question | Options | Recommendation | Safe default (if unanswered) | Answer (2026-11-07) | What it means here | README sections it changes |
|---|---|---|---|---|---|---|---|
| **D14** | Should audit check file and folder permissions and owners, the way apply does before writing? (SEC-1) | (1) Yes: a new "unsafe permissions" drift at exit 1, and exit 2 when something on the path is world-writable. (2) Yes, but every posture problem at exit 1. (3) No: audit keeps reading only the file's content. | (1): a world-writable path lets any local user add a key, which is "a human must act now" (D28). | (3), today: no posture check; a file sshd ignores, or anyone can rewrite, audits compliant. | **(1) Yes.** | Section 1 (posture probe). | **`sshepherd audit`** drift classes and JSON; **Per-server `authorized_keys_file`**; **Exit codes**; **Safety model**. |
| **D15** | Should an operator key that is on a server but cannot log in (`cert-authority` or `principals=`) be critical (exit 2)? (COR-5) | (1) Yes: critical, the same as a missing operator key. (2) No: it stays options drift at exit 1, as today. | (1): a key that cannot log in is the same as a missing one. | (2), today: options drift, exit 1. | **(1) Yes.** | Section 2. With D19 and OP3, a passed `expiry-time` on the server's operator line is the same class. | **Operator users**; **`sshepherd audit`** (rows, JSON); **Exit codes**. |
| **D16** | Should audit treat it as a possible attack (exit 2) when a server suddenly shows a different kind of host key than the one you saved? (COR-6) | Re-asked with corrected options (see below the table): (new 1) keep today's negotiation and add `host_key_type_changed` at exit 2; (2) restrict `HostKeyAlgorithms` to the recorded types and map a negotiation failure to the new kind; (3) keep today's `host_key_type_unrecorded` at exit 1. | (new 1). | (3), today: `host_key_type_unrecorded`, exit 1. | **(new 1) Yes.** | Section 3. | **`sshepherd audit`** error kinds; **Exit codes**; **Safety model** connection posture. |
| **D17** | Should each server only see the keys the manifest grants there (plus operator keys)? (SEC-5) | (1) Yes, one rule on every command: offer only granted (+operator) keys; when none of the loaded keys is granted on a server, offer all of them with a warning; `--offer-all-keys` turns the filter off. (2) Filter on audit only; the other commands keep offering every held key. (3) No: keep today's order (granted first, then every other held key). | (1): one rule with one default everywhere (review panel, product-ux). | (3), today: every managed server sees every held public key. | **(1) Yes.** | Section 4. | **Authentication** (key offering); flag tables of **`sshepherd audit`**, **`adopt`**, **`apply`**, **`revoke`**, **`rotate`**; **Safety model**. |
| **D18** | Should the README's claim that audit answers "who can log in" be narrowed now to the managed files audit actually reads, with a deeper opt-in check left for later? (PRD-9) | (1) Narrow the claim now; a deeper opt-in check (`sshd -T`, other accounts) gets its own later spec. (2) Narrow the claim now and plan no deeper check. (3) Keep the claim and build the deeper check first. | (1). | (2): the narrowing is doc-only and makes the README true whatever comes later; nothing deeper is built. | **(1) Yes.** | Section 6: exact wording, which landed with this spec's commit (`837fb49`); the deep probe gets its own later spec. | **Why**; **Per-server `authorized_keys_file`**; CLAUDE.md "Core capabilities → Audit"; the README intro (section 6). |
| **D19** | Should weak or expired keys be flagged? (PRD-10) | (1) Built-in rules: DSA and RSA under 2048 bits are policy problems handled as D29 says (audit critical, apply skips those servers, a manifest that loads today keeps loading); a passed `expiry-time` warns. (2) A configurable `policy:` block in the manifest. (3) No key rules. | (1). Key age, an `added:` date and "overdue for rotation" are excluded: they overlap the on-hold scheduled rotation. | (3), today: DSA and 1024-bit RSA keys load, render and audit clean; only `rotate` reads `expiry-time`. | **(1).** | Section 5. | **Validation rules**; **The manifest → Operator users**: a weak operator key freezes every grant on every server until `rotate` replaces it (see Risks); **`sshepherd audit`**; **`sshepherd apply`**: servers granting a weak key are refused, except a write that only removes keys; **`sshepherd adopt`**, **`sshepherd import`**: weak keys are skipped with a warning; **`sshepherd revoke`**, **`sshepherd rotate`**: a save that would add a weak key is refused (exit 3), and the remediation always saves; **Exit codes**. |

### Owner answers at spec approval (2026-11-08)

| # | Question | Answer | Where it lives |
|---|---|---|---|
| **OP1** | Report a symlinked managed `authorized_keys` although sshd follows the link? | **(1) Yes:** `symlink` drift at exit 1. apply cannot converge it (45), and whoever owns the link can redirect it. | Section 1, Exit codes. |
| **OP2** | Run the posture probe in its own session? | **(1) Yes:** a separate session, so the read command's bytes stay unchanged. | Section 1. |
| **OP3** | Is an expired operator line critical even when the manifest declares the same expiry? | **(1) Yes:** critical at exit 2. The operator has lost access either way. | Section 2, Exit codes. |
| **OP4** | Refuse a manifest save only when it adds a weak key? | **(1) Yes:** only when it adds one, so unrelated revokes and the weak key's own remediation always save. | Section 5, Exit codes, Interactions with P04. |
| **OP5** | Should plain `import` also skip a weak `.pub` identity? | **(1) Yes:** plain import and `--merge` both skip it with a warning. | Section 5. |
| **OP6** | Do the per-server "none of the keys granted here are loaded" warnings drop to debug after the preflight warning? | **(1) Yes:** a first-contact run prints one line. | Section 4. |

### Spec-author defaults (stand, 2026-11-08)

The plan lets the spec author decide these technical sub-choices. They were shown at
spec approval and stand.

| # | Question | Decision | Why | README sections it changes |
|---|---|---|---|---|
| **D14a** | Should audit accept a root-owned `authorized_keys` file, as sshd does, although apply refuses to write one? | **Yes:** root is accepted as owner of the file and of every directory, as sshd's StrictModes does. | The write path refuses a root-owned **file** and a root-owned **directory of the file** (48) and accepts root only for higher ancestors. Audit follows sshd, which decides the access that actually exists, so a root-owned file is audit-compliant while apply refuses to write it. | **`sshepherd audit`** drift-class text: unsafe permissions accepts root as owner, and apply still refuses (48) a root-owned file; **Per-server `authorized_keys_file`**: an override path owned by root audits clean but apply refuses to write it. |
| **D14b** | Should a failed or malformed posture probe make the server unreachable rather than a "posture unknown" drift? | **Unreachable** (`error_kind: remote`), like today's failed `authorized_keys2` probe. | One failure path, and a server cannot get its keys graded clean while hiding its posture. | **`sshepherd audit`** error kinds. |
| **D14c** | Should the posture probe also walk an `authorized_keys_file` outside `$HOME`, up to `/`? | **Yes:** the walk stops at `/`, as the write walk does. | A writable directory above an override path must not go unreported while apply refuses it (48). | **Per-server `authorized_keys_file`**: what posture covers on an override path. |
| **D17a** | What should the flag that turns the key filter off be called, and which commands should have it? | **`--offer-all-keys`** on audit, adopt, apply, revoke and rotate, default off on all five. | One rule with one escape hatch on every command (D17). | Flag tables of **`sshepherd audit`**, **`adopt`**, **`apply`**, **`revoke`**, **`rotate`**; **Authentication**. |
| **D17b** | Should a run warn once, before connecting, when none of the loaded keys is granted on any target server? | **Yes, warn only.** | Refusing would break first contact after `import --servers-only`, which D17's fallback exists for. | **Authentication**. |

**Why D16 was re-asked.** The first wording of D16's option 1 said "only accept
recorded types, as OpenSSH's strict mode does". The verifier showed that
OpenSSH only **reorders** host-key algorithms from `known_hosts`; it does not
restrict them. And
restricting would not close the gap: an impersonator offering only an unrecorded type
would then fail with "no common algorithm for host key", which `handshakeKind`
(`internal/sshconn/errors.go`) classifies as `handshake` — still exit 1. The
alarm would only change name. The corrected options were:

1. **(chosen)** Keep today's negotiation; add `host_key_type_changed` (exit 2) when
   `known_hosts` records at least one type x/crypto can verify and the server
   presented a different type.
2. Restrict `HostKeyAlgorithms` to the recorded types **and** map a negotiation
   failure on a host with recorded types to `host_key_type_changed`. Rejected: it
   classifies by an error string (fragile) and loses the presented key's fingerprint
   in the hint.
3. Keep today's behavior.

Answers this design relies on from other blocks: **D28** (one exit-code table; exit 2
= a human must act now on security), **D29** (policy conflicts are reported by audit,
not load errors), **D27** (a malformed `expiry-time` fails the load), **D31** (the
login probe offers keys in the order later runs use).

## Design

### 1. Posture probe (D14, D14a–c, OP1, OP2)

**A new remote command, in its own session (OP2).** `sshconn.PostureCmdFor(path string)`
builds a POSIX-sh script (run through `remoteCommand`'s `exec /bin/sh -c` like every
other script) that inspects the managed file and its directories and prints one
record per problem. It runs as a **separate session** after the read, so the read
command's bytes — which `sshwrite` verify depends on — stay unchanged.

**The `authorized_keys2` probe folds into it.** The script also reports a non-empty
`~/.ssh/authorized_keys2`, with `SecondaryKeysCmdFor`'s rule: the managed path is the
default spelling or resolves on the server to `~/.ssh/authorized_keys` (`cd -P`,
`test -ef`). `SecondaryKeysCmd`, `SecondaryKeysCmdFor` and `FinishSecondaryProbe` are
removed; `Client.readKeys2` stays and still keys off `AuthorizedKeys2`. Session count
per read: **2**, on every path, the same as today, because the posture session
replaces the probe session. The fan-out benchmarks (`make bench`) are re-run in the
implementation; the `--parallel 32` default is not expected to move, and the audit
spec's Tuning resolution gets a one-line note either way.

**Every command runs it.** The probe lives in the shared reader, so adopt, apply,
revoke, rotate and the sweep run it too. Only audit grades `Posture`; the others
ignore it, except that a failed or malformed probe fails the read, as a failed
`authorized_keys2` probe does today.

**Shared walk.** The StrictModes walk moves out of `sshwrite.go` into
`internal/sshconn` as one exported builder parameterized by the action taken on each
kind of bad component: `AncestorWalk(onMode, onOwner string) string`. The action sees
`$1` (mode), `$3` (uid) and `$q` (path). The write path passes `exit 48` for both, and
`writeCmdFor`, `restoreCmdFor` and `disableKeys2Cmd` stay **byte-identical** (each
pinned by a golden taken before the move). The posture script passes actions that
print records and continue.

**What it checks** (`u=$(id -u)`; `set -f`; nothing is ever written):

1. **The file** (`$p`), when it exists:
   - a symlink → `symlink` (OP1; apply refuses to write it with 45, so the managed
     file cannot be converged; whoever owns the link can redirect it), and no further
     check of the link itself;
   - owner neither `$u` nor `0` → `foreign_owner` (D14a: root is fine, as for sshd);
   - group-writable (`?????w*`) → `group_writable`; world-writable (`????????w*`) →
     `world_writable` (both may be printed for one path, each as its own record).
2. **The ancestors**, as written and resolved (the same two loops as the shared walk),
   from the file's nearest existing directory up to `$HOME` — or to `/` when the path
   is outside `$HOME` (D14c) — with the same three classes. A symlinked ancestor has
   no mode check (as today: `l*` skips it) but its owner is checked; the resolved walk
   covers its target. Components that do not exist are skipped: an absent file or
   directory is not a posture problem (absence is already reported by the read).
3. **`authorized_keys2`**: `SSHEPHERD-KEYS2 1` under `SecondaryKeysCmdFor`'s rule and
   `[ -s ]`, exactly today's semantics.

The script **never exits early** on a finding. It exits 0 after the walk; it exits
non-zero only when a required tool fails (`ls`, `dirname`, `cd -P`, `pwd -P`, `id`
— all already required by the write path).

**Record grammar** (stdout, one record per line, nothing else):

```
SSHEPHERD-POSTURE <mode> <uid> <issue> <path>
SSHEPHERD-KEYS2 1
```

- `<mode>` is `ls -ldn`'s first field (`[-dlbcps][-rwxsStT]{9}[.+@]?`), `<uid>` is
  decimal digits, `<issue>` is one of `symlink`, `foreign_owner`, `group_writable`,
  `world_writable`, and `<path>` is the rest of the line (the shell's `$q`, never
  parsed from `ls`).
- Parsing (`FinishPosture(code int, stdout, stderr *CappedBuffer) ([]fleet.PostureIssue, bool, error)`,
  replacing `FinishSecondaryProbe`; the bool is `authorized_keys2`) is **fail-closed**:
  any other line, an unknown issue, a malformed mode or uid, more than **64 records**,
  stdout at the `MaxRemoteOutput` cap (1 MiB), or a non-zero exit → `ErrorKindRemote`
  with the message `posture probe output malformed` (or
  `posture probe failed (exit N): <sanitize.RemoteSnippet of stderr>`), so the server
  is **unreachable** (D14b). The probe prints a path's newlines as `?` (review wave 1,
  G018), so such a path is graded; a raw newline in a record still breaks the grammar and
  fails closed. The as-written and resolved walks visit the same directory when no
  symlink is involved, so identical `(path, issue)` records collapse to one after the
  count check. Paths are sanitized (`sanitize.Remote`) before they are printed; the
  JSON carries the sanitized form.

**Types** (in `internal/fleet/fleet.go`, beside `ReadResult`):

```go
type PostureIssue struct {
    Path  string // sanitized; remote-controlled once resolved
    Issue string // "symlink" | "foreign_owner" | "group_writable" | "world_writable"
    Mode  string // ls -ldn first field, e.g. "drwxrwxrwx"
    UID   string // owner uid as printed
}
// ReadResult gains Posture []PostureIssue; AuthorizedKeys2 keeps its meaning.
// audit.ServerResult gains the same field, copied in auditOne.
```

**Grading.** `ServerResult.Compliant()` is false when `len(r.Posture) > 0`. Any
`world_writable` issue is critical (anyone on the host can then add a key, or replace
the directory; `critical_reasons` value `world_writable`). `symlink`, `foreign_owner`
and `group_writable` are drift (exit 1). The posture issues are graded whether or not
the file's keys match the manifest: a matching file sshd would ignore, or that
someone else can rewrite, is not compliant.

**Interaction with apply.** apply's refusal classes are unchanged: it still refuses
48 for the same components (and also for a root-owned file or directory, which audit
accepts per D14a). An audit posture finding is fixed by hand (`chmod`/`chown`); the
README says so in the drift-class text.

### 2. Operator key that cannot log in (D15, OP3)

- `authkeys.CertOnly` already exists (P05); no move is left to do. `apply.Survivors`
  and audit both use it, so write and audit share one rule.
- New helper in `internal/authkeys/options.go`: `Expired(opts []string, now time.Time, local *time.Location) bool`,
  true when any `expiry-time=` clause is at or before `now`. sshd honours the earliest
  clause of a repeated `expiry-time=`, so one passed clause is enough. It is built on
  `ExpiryTime`, and it replaces the spec's former `ExpiryOption`/`ExpiryPassed`.
  `keyarg.go`'s `expiryOption`/`expiryPassed` stay: `rotate` quotes the option and
  needs its parse error.
- **Grading is per key over every line sshd honours, not `Diff.Actual`.** `auditOne`
  records all parsed lines per fingerprint (`ServerResult.Lines map[string][]authkeys.Key`,
  built by a new `authkeys.LinesByFingerprint(keys []Key)`, which adopt's local
  `linesByFingerprint` also calls). `Diff.Actual` stays first-occurrence for the
  options-drift row. For each `k` in `r.Diff.OK` whose owner is an operator:

  ```
  for each line of r.Lines[k.Fingerprint], in file order:
      IgnoredBySSHD(line.Options) != nil            → remember "ignored"; next line
      Expired(line.Options, now, time.Local)        → remember "expired"; next line
      CertOnly(line.Options) && !CertOnly(k.Options) → remember "cert_only"; next line
      otherwise                                     → this line can log in: not critical
  no line can log in → critical with the first remembered honoured reason
  ("expired" or "cert_only"), else "ignored"
  ```

  A first line sshd cannot use with a working second line is therefore not critical,
  and a first line sshd ignores with a dead second line is. A malformed on-server
  `expiry-time` is a line sshd ignores (`IgnoredBySSHD`'s value check), so it falls
  under `ignored`.
- `expired` applies **whether or not the manifest declares the same expiry** (OP3):
  the operator has lost access either way, which is what D15 protects. A manifest
  that deliberately declares the operator line as `cert-authority` does not make it
  `cert_only`, and is not critical on that ground.
- `now` is a package seam in `internal/audit` (`var now = time.Now`). An expiry without
  `Z`/`UTC` is read in the operator's local zone, as `rotate` does today; sshd reads
  it in the server's, so a verdict can differ by the offset between the two.
- `criticalDrift` becomes `len(criticalReasons(cfg, r)) > 0`, one function that returns
  every reason (JSON section).
- Added `command=`/`from=` on an operator line stay options drift at exit 1: those
  lines still allow some login (out of scope, as the verifier argued).

### 3. Host-key type change (D16, option new 1)

- Negotiation is unchanged (`HostKeyAlgorithms` keeps reordering, not restricting).
- `hostKeyHint` takes the run's `*KnownHosts` in place of `knownHostsPath`, and
  classifies three paths:
  - **Plain key, mismatch** (`KeyError`, `Want` non-empty). `Want` holds the host's
    plain lines and its `@cert-authority` lines, so a host recorded only through a CA
    is covered. The presented type matches a recorded one → `host_key_changed`, as
    today. Otherwise, some recorded `t` has `algosForKeyType(t) != nil` → new kind
    `host_key_type_changed`, exit 2, counted in `host_key_alerts`. Every recorded type
    unsupported (for example only `ssh-dss`) → `host_key_type_unrecorded`, exit 1, as
    today.
  - **Certificate from an unvouched signer** ("no authorities", the `noAuthorityPrefix`
    branch) when `authorityMatches(addr)` is true → `host_key_type_changed`, exit 2.
    Today it is `host_key` (exit 1), which let an impersonator of a CA-vouched host
    dodge the alarm by presenting a certificate from its own CA. Certificate algorithms
    are offered to a host `known_hosts` records only when a CA line matches, so this
    condition is exact. An unknown host (no lines, x/crypto's default algorithms)
    presenting such a certificate stays `host_key`: there is no recorded trust to
    betray.
  - **Certificate from a vouched signer that fails validation** (expired, wrong
    principal) stays `host_key`, exit 1. The signer is trusted, so this is not
    evidence of impersonation, and routine certificate expiry must not page.
- Why this is sound: the certificate algorithms (when a CA matches) and the recorded
  types are negotiated first, so a genuine server reaches the new kind only when it no
  longer serves **any** recorded key and no certificate the CA vouches for. That is a
  re-key, and it needs a human. The meaning of an existing kind never changes tier;
  `host_key_type_unrecorded` keeps exit 1 for the cases it still covers.
- `hostKeyAlert` includes the new kind. The constant
  `ErrorKindHostKeyTypeChanged = "host_key_type_changed"` lives in
  `internal/fleet/errors.go`. apply/adopt/revoke/rotate report the new `error_kind` in
  their own output; their exit codes follow the shared D28 table (P04 section 8), which
  this spec does not change for those commands; P08's D10b later added
  `host_key_type_changed` to exit 2 at the post-write login check, through
  `fleet.HostKeyAlert`.

### 4. Key offering (D17, D17a, D17b, OP6)

- `Dialer.OfferAll bool` and `Dialer.QuietFallback bool`; `sshread.Client` gains both
  and copies them in `getDialer`; `fleetSession.reader` and `fleetSession.dialer` set
  them, so the sweep's reader inherits them. In `ConnectWith`, after `prefer` is
  resolved and when `!d.OfferAll && len(opts.Only) == 0`:
  - if at least one held signer matches `prefer` (by the rules below), offer only
    those;
  - otherwise (no granted key is held — normal right after `import --servers-only`
    or on first contact), offer every held key in today's order and log one warning:
    `web-1: none of the keys granted here are loaded; offering all 3 held keys`.
    No new error kind. With `QuietFallback` the warning is debug level.
- **Operators** need no extra code: `DesiredFor` includes every operator, so
  `GrantedFingerprints` lists them (in `OfferOrder`).
- **Certificates.** A certificate's fingerprint is not its key's. Under the
  restricted offer a held certificate is offered when `cert.Key` **or**
  `cert.SignatureKey` has a granted fingerprint (the second case is a manifest
  `cert-authority` line). The rule lives in `orderSigners`, with table tests, and is
  exported as one matcher for the preflight below.
- **Callers.** audit, adopt and apply keep `GrantedFingerprints`;
  revoke/rotate and their sweep keep the former∪edited union (a pre-edit key still logs in, and the sweep reads servers the run did not write). The
  post-write probe already passes `Only` and is unchanged (D31). The write connection
  (`connectForWrite`) inherits the rule through `Dialer.PreferKeys`.
- **What the fallback covers, and what it does not.** The fallback is about what the
  run **holds**, not what the server has installed. In plain `apply`:
  - no granted key held: the read falls back and the plan is computed, but
    `apply.Survivors` is empty, so the self-lockout guard refuses the write. The
    fallback gives a plan and a refusal, never a write.
  - a granted key held but not yet installed (a new server that only has its
    cloud-init key, or a key changed by hand in the manifest): the fallback does not
    apply, the restricted offer fails, and the server is `auth`-unreachable. Today this
    works, because every other held key follows.
- **No automatic retry.** Falling back after an `auth` failure would let any server
  that refuses the granted keys collect every held key, which is exactly SEC-5.
  Instead, when the restricted offer withheld at least one held key and the handshake
  fails `ErrorKindAuth`, `ConnectWith` attaches the hint
  `none of the keys the manifest grants here were accepted; 2 other loaded keys were not offered — if one of them still logs in here, re-run with --offer-all-keys (this server then sees every loaded key)`.
  The README's Authentication section gives the bootstrap recipe,
  `sshepherd apply --server NAME --offer-all-keys`.
- **`--offer-all-keys`** (D17a), registered once in `connFlags.register` for audit,
  adopt, apply, revoke and rotate, default off, sets `OfferAll` and restores today's
  order (granted first, then every other held key). Help text:
  `offer every loaded key to every server (default: only the keys the manifest grants there)`.
- **Preflight** (D17b, OP6). `sshread.CheckCredentials` holds no manifest, so the
  warning is a `fleetSession` method in `cmd/sshepherd/fleet.go`, run by each command
  once its targets are known and before the first read, skipped under
  `--offer-all-keys`. It warns, once, when no held key is granted on **any** target
  server:
  `none of the loaded keys is granted on any target server; each server will be offered all 3 held keys`
  (count pluralized). When it fires, it sets `QuietFallback`, so the per-server
  fallback warnings drop to debug level and a first-contact run prints one line
  instead of one per server.
- Side benefit: fewer keys offered means fewer `MaxAuthTries` disconnects.

### 5. Key policy (D19 option 1, through D29; OP4, OP5)

- **New `internal/authkeys/policy.go`:** `StrengthIssue(pub ssh.PublicKey) (issue string, bits int)`
  returns `"dsa"`, `"rsa_under_2048"` with the size, or `""` (RSA bits from
  `pub.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey).N.BitLen()`).
  `authkeys.Key` gains `Weak string` and `WeakBits int`, set by `ParseLine`, so the raw
  line is not parsed twice.
- **Load-time behavior follows D29.** A weak key in `users:` is **not a load error**.
  `computeConflicts` adds, after the revoked kinds, one `Conflict` per weak key granted
  on at least one server: `Kind: "weak_key"` (`ConflictWeakKey`), `User`,
  `Fingerprint`, `Servers` every server the key renders on, and the message, in the
  shape W4's conflicts use (what is wrong, then the way out):
  `user "old" key 1 (SHA256:…): dsa keys are not allowed: replace it with 'sshepherd rotate' or remove it with 'sshepherd revoke --key'`
  (or `… rsa keys under 2048 bits are not allowed (1024): …`).
- **An ungranted weak key is a warning, not a conflict.** P04's conflicts exit 2 even
  with no servers, because a revoked key still listed contradicts the manifest's own
  memory. A weak key on a user with no grants renders nowhere, so no human must act now
  (D28): it is a load warning, `user "old" key 1 (SHA256:…): dsa key, granted on no server`,
  and the exit-2 row below holds as written. `Config.WeakKeys()` lists every weak key
  either way, for the save rule. Then, per D29:
  - **`audit`** loads the manifest, prints the conflict in `renderConflicts`, marks
    those servers critical through `inConflict`, exits 2 (`critical_reasons:
    ["policy_conflict"]`).
  - **`apply`** (and the apply phase of revoke/rotate) refuses those servers (nothing
    written there) and plans the rest; exit 1. **One exception, for `weak_key` only:**
    a write that grants nothing and removes at least one key proceeds
    (`removalOnly(r, entries) && len(r.Diff.Unauthorized) > 0`, the rule D4 already
    uses against a newer serial). It cannot install or widen the weak key, and without
    it OP4's unrelated `revoke bob` would save but leave bob's key installed on every
    server granting a weak key. `planOne` therefore checks the revoked kinds where it
    does today and the weak kind after `desiredEntries`. A server already converged
    stays refused (exit 1).
  - **Saving commands** (revoke, rotate, `adopt --merge`, `import --merge`,
    regenerate-mode `adopt`) refuse, exit 3, only when the save **adds** a weak key
    (OP4): a fingerprint in `saved.WeakKeys()` that the loaded manifest does not hold.
    An unrelated `revoke bob` therefore still saves while `alice` holds a DSA key, and
    the remediations `rotate alice --old <dsa> --new <ed25519>` and `revoke --key <dsa>`
    always work. cmd's `conflictRefusal` becomes `conflictRefusal(former, saved *config.Config)`
    (`former` nil for a new manifest) with the message
    `refusing to write the manifest — it would add a weak key: <conflict message>`.
    The revoked kinds keep P04's rule (see "Interactions with P04").
  - **`validate`** (D25, when it lands) exits 3 on a `weak_key` conflict, as on any
    conflict, and 0 for an ungranted weak key (a warning) (built with D25; plan
    decision 14).
- **Expired keys.** A desired key whose `expiry-time` has passed is a load
  **warning** only (`config.Warnings`, printed by `logManifest`):
  `user "alice" key 1: expiry-time="20200101" has passed; sshd no longer accepts this key`.
  The clock is a seam (`var now = time.Now`) so tests pin it.
- **adopt and import.** A weak on-server key (adopt, both modes) or a weak `.pub`
  identity (import, plain and `--merge`, OP5) is **skipped with a warning**:
  `key SHA256:… on web-1: rsa_under_2048 key not adopted` /
  `identity ~/.ssh/old.pub: dsa key not imported`. In `adopt.Build` the check follows
  `revokedWarning` and precedes the owner branch, so a weak key is neither adopted nor
  granted to more servers; it is a warning, not an `Issue`, so it does not move the
  strict gate. In import it lives in `identity.Resolver.Resolve`'s `grant`, which both
  modes share. Emitting either would produce a manifest with a policy conflict. audit
  keeps showing such a key as UNAUTHORIZED, which is the right pressure.
- **`import --operator` naming a weak key is an error** (exit 3). `MarkOperators`
  failures are errors because operator keys are named explicitly on the command line,
  and silently producing a manifest without the requested operator is worse than
  stopping.
- **Audit annotations** (informational, no exit change beyond the conflict): rows whose
  key is weak get ` · WEAK (dsa)` / ` · WEAK (rsa 1024)`, on present and unauthorized
  rows; a `REVOKED` row is already critical and gets none. Present rows whose desired
  `expiry-time` has passed get ` · EXPIRED`. The operator case in section 2 is the
  exception (critical).
- **Excluded** (overlap with the on-hold scheduled rotation): no `added:` date, no
  key-age limit, no "overdue for rotation".
- Note for the README: OpenSSH 9.8 and later build sshd without DSA by default, so a
  DSA key usually cannot log in on a current server anyway; the rule makes that
  visible instead of silent.

### 6. Narrowing the coverage claim (D18)

**Landed** with this spec's commit, `837fb49` (README "Why", README "Per-server
`authorized_keys_file`", and CLAUDE.md "Core capabilities → Audit"). The exact text:

- README "Why", the Audit bullet:

  ```markdown
  - **Audit** — check that every managed `authorized_keys` file holds exactly the
    manifest's keys, in text or JSON. It does not see other accounts on the host or
    sshd's other key sources (see [Per-server `authorized_keys_file`](#per-server-authorized_keys_file)).
  ```

- README "Per-server `authorized_keys_file`", the closing sentences:

  ```markdown
  Audit reads only the managed file (and, on the default path, checks
  `authorized_keys2`). It does not see sshd's other key sources — a custom
  `AuthorizedKeysFile` list in `sshd_config`, `AuthorizedKeysCommand`,
  `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`/`AuthorizedPrincipalsCommand` — or
  other accounts on the same host. Point `authorized_keys_file` at the file sshd
  actually reads.
  ```

- CLAUDE.md "Core capabilities (intended)", the Audit bullet:

  ```markdown
  - **Audit** — check that every managed `authorized_keys` file holds exactly the
    manifest's keys; other accounts and sshd's other key sources are not seen (a
    deeper opt-in check is a later slice).
  ```

**Still to do with P09-impl** (W1 verifier follow-up): the README intro still says
SSHepherd "reads every server, tells you exactly how reality differs from the
manifest". It becomes "reads every managed `authorized_keys` file, tells you exactly
how each differs from the manifest".

**Later** — its own spec, not designed here: an opt-in deeper audit (the flag name is
that spec's to choose) that (1) runs `sshd -T -C user=U,host=H,addr=A` when it works,
falling back to reading `/etc/ssh/sshd_config` and its `Include` files for the
key-source directives, and (2) lists, via `getent passwd`, each account with a
non-empty `~/.ssh/authorized_keys{,2}` that the manifest does not manage. Its
findings are "unmanaged access paths"; their exit tier is that spec's decision. It
only **reports**; it never removes (no `prune`).

## Exit codes

Rows for the one shared table that D28 fixes (P04 section 8). This spec adds
**audit** rows only (plus the save/validate row for D19, which is D29's mechanism):

| Code | Added cases |
|---|---|
| 1 | posture `symlink` (OP1), `foreign_owner`, `group_writable`; posture probe failed or malformed (`error_kind: remote`, server unreachable); `host_key_type_unrecorded` now only when every recorded type is unsupported; an invalid certificate from a vouched CA stays `host_key` |
| 2 | posture `world_writable`; operator key present but `cert_only`, `expired` (OP3, declared or not) or `ignored`; `host_key_type_changed`, including a certificate from an unvouched signer on a CA-vouched host; a weak key granted on a server (policy conflict, D29) |
| 3 | `validate` on a `weak_key` conflict, and saving commands that would **add** a DSA or RSA<2048 key (OP4). audit reports a granted weak key as critical (2) instead; apply refuses the servers that grant it (1), except a write that only removes keys. |

W4 rewrote the README "Exit codes" table from P04's. P09-impl adds these cases to it;
the row-2 text gains the audit cases above.

## JSON

Schema stays **1**; every field is additive and `omitempty` unless stated.

- **Server:**
  - `posture`: `[{"path": "...", "issue": "world_writable", "mode": "drwxrwxrwx", "uid": "1001"}]`.
  - `critical_reasons`: `["forged_serial" | "operator_cannot_log_in" | "operator_missing" | "policy_conflict" | "revoked_key" | "world_writable"]`,
    sorted and de-duplicated, present exactly when `status` is `critical`, so
    monitoring can tell why it got exit 2. W4 landed the classes `revoked_key`,
    `forged_serial` and `policy_conflict` without this list (they show today as
    `revoked` on a key, `forged_header_serial` and `policy_conflicts`), so this slice
    introduces the list with all six values, from `criticalReasons` (section 2). The
    W4 fields stay. A host-key alert is `status: unreachable`, so it carries no reason;
    `error_kind` and `summary.host_key_alerts` say why.
- **Key** (in `present` / `unauthorized`):
  - `cannot_log_in`: `"cert_only" | "expired" | "ignored"` on a present operator key
    graded critical by section 2.
  - `key_issues`: `["dsa" | "rsa_under_2048" | "expired"]`; never on a key with
    `revoked` set (a tombstoned key is already critical).
  - `operator`: `true` now also on a **present** key that is critical
    (`cannot_log_in`), extending `jsonKeyFor`'s rule that `operator` marks only
    critical rows.
- **Top level and summary:** `policy_conflicts` (audit and apply) and
  `summary.policy_conflicts` carry the new `kind: "weak_key"` unchanged in shape.
  `host_key_alerts` also counts `host_key_type_changed`.
- **New `error_kind` value:** `host_key_type_changed`. The existing values keep
  their meaning and tier.

The implementing integrator appends the same paragraph to
`2026-07-16-audit-json-exit-codes-design.md`.

## Text report wording

Target wording; the goldens own the final bytes. Errors render as today's
`ERROR [kind]: …` head plus a separate `  hint:` line (`renderServer`, `Hints`).

- Posture (one line per record, under the server, after the `authorized_keys2` notice
  and before the `→` count line):
  ```
    ‼ unsafe permissions: /home/deploy/.ssh is world-writable (drwxrwxrwx, uid 1001) — anyone on the host can add a key; sshd's StrictModes would ignore this file
    ⚠ unsafe permissions: /home/deploy/.ssh/authorized_keys is group-writable (-rw-rw-r--, uid 1001) — sshd's StrictModes would ignore this file
    ⚠ unsafe permissions: /srv/keys is owned by uid 1002, not the login user or root — sshd's StrictModes would ignore this file
    ⚠ unsafe permissions: /home/deploy/.ssh/authorized_keys is a symlink — apply refuses to write through it
  ```
  followed once per server by
  `  note: fix by hand (chmod go-w / chown); a login that succeeded here came through another key source or with StrictModes off`.
- Operator cannot log in (`okStatus`):
  `‼  op (op@sshepherd)  SHA256:…  ssh-ed25519  present but CANNOT LOG IN (CRITICAL: operator key; server line is cert-only)`,
  `… (CRITICAL: operator key; server line expired 2026-01-01)` and
  `… (CRITICAL: operator key; sshd ignores every line holding it)`.
- Host key: `ERROR [host_key_type_changed]: …` with the hint leading
  `HOST KEY TYPE CHANGED for host:port — the server no longer presents any recorded key type (recorded: ssh-ed25519); possible impersonation; verify the presented fingerprint out of band (…) before touching known_hosts`,
  or, for a certificate,
  `HOST KEY TYPE CHANGED for host:port — the server presented a certificate no @cert-authority line for this host vouches for; possible impersonation; verify the CA out of band before touching known_hosts`.
  A CA line's type appears in the `recorded:` list as `ssh-ed25519 (CA)`.
- Key annotations: ` · WEAK (dsa)`, ` · WEAK (rsa 1024)`, ` · EXPIRED`.
- Policy conflict: printed in `renderConflicts`' `manifest:` block with the D19
  message, and the existing per-server `named by a manifest policy conflict above`
  line.
- Summary line: unchanged format; `HOST KEY ALERT` counts the new kind.

## Remote-script contract (summary)

- `sshconn.PostureCmdFor(path)` = `PathAssign(path)` + the posture script; the path
  enters once, ShQuote-d, exactly as for the read and write commands.
- Output: only `SSHEPHERD-POSTURE <mode> <uid> <issue> <path>` and
  `SSHEPHERD-KEYS2 1` lines; at most 64 records, under `MaxRemoteOutput`; exit 0.
- Parse fail-closed into `ErrorKindRemote`; never into a clean result.
- `AuthorizedKeysCmdFor`, `writeCmdFor`, `restoreCmdFor` and `disableKeys2Cmd` bytes
  are unchanged (golden-pinned).

## Threat notes

- **A compromised server can lie.** It controls `ls`, `id` and stdout, so it can
  print nothing and look clean, exactly as it can serve a fake `authorized_keys`.
  The fail-closed parser guarantees only that malformed or oversized output is never
  read as clean; posture is evidence about an honest server's configuration, not an
  integrity proof against a hostile one. The README says this plainly.
- **Remote paths are printed.** `$HOME` and resolved paths come from the server, so
  they pass `sanitize.Remote` and the grammar forbids newlines.
- **Key offering leaks less, not nothing.** The fallback (no granted key held)
  still offers every held key; `--offer-all-keys` does too. A hostile server that
  is granted nothing on the manifest still sees the operator keys, by design. There
  is deliberately no fallback on `auth` failure (section 4).
- **`host_key_type_changed` cannot be dodged** by offering only an unrecorded type
  (negotiation still succeeds and the presented key reaches the verdict branch), nor
  by presenting a certificate from an unvouched signer on a CA-vouched host (section
  3). An invalid certificate from a vouched CA stays exit 1: it needs the CA's
  signature, so it is a stolen old host credential at worst.

## Risks

- **The restricted offer can break a login that worked by accident** (the working
  key is held but another held key is the granted one), most commonly a new server
  that still has only its cloud-init key. The fallback does not cover this (section
  4). Mitigations: the `auth` hint and `--offer-all-keys`, per run and combinable with
  `apply --server`.
- **The same case can lower an audit tier.** A server where only a non-granted held
  key still logs in reports `auth`-unreachable (exit 1) instead of showing a missing
  operator key (exit 2). The hint names the flag; with it, audit grades the server
  as today.
- **A weak key turns a passing scheduled audit into exit 2 on upgrade** (D29: the
  manifest keeps loading, but every server granting the key goes critical, and apply
  skips those servers). A weak **operator** key freezes every grant on every server
  until `rotate` replaces it; removals still land (section 5). The release note and
  README must say so; `rotate` and `revoke --key` are the way out and always save.
  (The plan's sketch said weak keys would make manifests fail to load; under D29 they
  do not.)
- **A save can succeed where its push cannot** (OP4). `rotate carol` adds a key, so on
  a server granting someone else's weak key it saves and its push is refused (exit 1,
  the refusal names the weak key). The way out is to fix the weak key first.
- **Posture can page on hosts that work today** (world-writable home directories
  exist in the wild). Intended: such a host is either ignoring the file or open to
  every local user.
- **`host_key_type_changed` pages on a legitimate re-key that dropped every recorded
  type, or a CA rotation not yet recorded.** Intended: a re-key needs a human.
- **Tools.** The probe needs `ls -ldn`, `dirname`, `cd -P`, `pwd -P`, `id`, already
  required by the write path; busybox, dash and bash are covered by integration.

## Interactions with P04 (revocation memory)

- **Conflict kinds.** `Conflict.Kind` gains `"weak_key"`. For that kind only, saving
  commands refuse a save that **adds** a weak key (OP4); P04's general rule (refuse
  when the manifest as saved still has a conflict) stays for `revoked_key` and
  `revoked_access`, whose `Servers` may be empty and still exit 2. D4b's serial-only
  save stays exempt. The implementing integrator adds a one-line cross-reference to P04
  section 2.
- **Apply refusal.** A server named by a `revoked_*` conflict is refused
  unconditionally, as in W4. The removal-only exception of section 5 is for `weak_key`
  alone, and a server named by both kinds is refused.
- **Precedence with W4's classes.** A tombstoned key that is also weak is reported as
  `REVOKED` only, adopt's `revokedWarning` runs first, and a key in both lists yields
  two conflicts (one per kind).
- **`critical_reasons`** is introduced by this slice and covers the W4 classes.
- **Exit table.** The rows above merge into P04 section 8's table; neither spec
  changes the other's rows.

## README and CLAUDE.md sections

Updated by the implementing integrator, sample output copied from the goldens:

- **Why** — D18, already applied. The intro sentence (section 6).
- **Status** — the implemented-slice table and CLAUDE.md Status.
- **The manifest → Operator users** — a present-but-cannot-log-in operator key is
  critical too, including a declared expiry that has passed (OP3); a weak operator key
  freezes every grant.
- **Per-server `authorized_keys_file`** — posture checks cover override paths outside
  `$HOME` up to `/` (D14c); a symlinked file is drift at exit 1 (OP1); a root-owned
  override audits clean although apply refuses it (D14a).
- **Validation rules** — a granted weak key is a policy conflict (not a load error);
  an ungranted one and a passed `expiry-time` are warnings.
- **`sshepherd audit`** — flag table gains `--offer-all-keys`; drift classes gain
  unsafe permissions, cannot-log-in, WEAK/EXPIRED annotations, and the new
  `error_kind`; JSON fields, including `critical_reasons`.
- **`sshepherd adopt`**, **`sshepherd import`** — weak keys are skipped with a warning,
  in both modes (OP5); `import --operator` with a weak key is an error; adopt's flag
  table gains `--offer-all-keys`.
- **`sshepherd apply`**, **`sshepherd revoke`**, **`sshepherd rotate`** —
  `--offer-all-keys`; apply refuses servers granting a weak key except a write that
  only removes keys; saves that would add a weak key are refused, others are not
  (OP4).
- **Authentication** — key offering: only granted (+operator) keys, the fallback and
  what it does not cover, the `auth` hint, the bootstrap recipe, the preflight warning
  and its effect on per-server warnings (OP6), `--offer-all-keys`.
- **Exit codes** — the rows above.
- **Safety model** — connection posture: restricted key offer,
  `host_key_type_changed` including the certificate case; audit's posture check mirrors
  StrictModes.
- **CLAUDE.md** — "Core capabilities → Audit" (D18, applied) and Status.

## Files touched by the implementation

`internal/fleet/{errors,fleet}.go`; `internal/sshconn/{sshconn,posture,knownhosts,hostkey,connect}.go`
(`posture.go` new); `internal/sshread/sshread.go`; `internal/sshwrite/sshwrite.go`
(walk moved out, script bytes unchanged); `internal/audit/{audit,errors,report,json}.go`
plus `testdata/`; `internal/authkeys/{authkeys,options,policy}.go` (`policy.go` new);
`internal/config/{config,revoked}.go`; `internal/apply/{plan,serial}.go`;
`internal/adopt/adopt.go`; `internal/identity/identity.go`;
`cmd/sshepherd/{fleet,audit,adopt,apply,conflicts,editrun,import}.go` plus help
goldens. Each with its `_test.go`.

## Testing (W5+, failing first)

The plan's P09 "Implementation outline" (Task 0, Wave A: A1–A4, Wave B: B1–B3) holds,
with these additions and corrections from this spec:

- **A1 (authkeys):** `TestStrengthIssue` (ed25519, RSA 2048 ok; RSA 1024 →
  `rsa_under_2048` with `GODEBUG=rsa1024min=0`; DSA → `dsa`), `TestExpired` (8/12/14
  digits, `Z`/`UTC`, no clause, repeated clause with only the earliest passed),
  `TestLinesByFingerprint`, a DSA seed in the `ParseLine` fuzz corpus. `TestCertOnly`
  already exists as `TestBlocksLoginAndCertOnly`.
- **A2 (posture):** `TestWriteScriptsUnchanged` (goldens of `writeCmdFor`,
  `restoreCmdFor`, `disableKeys2Cmd` taken before the move), `TestReadCmdUnchanged`,
  `TestFinishPosture` table (clean; each issue; garbage line; unknown issue; 65
  records; at the output cap; newline in path; non-zero exit; KEYS2; as-written and
  resolved duplicates collapse), `FuzzFinishPosture` with a committed seed corpus
  (never returns a clean result for input containing a non-record line), hermetic
  `sshtest.ShellHandler` cases (0777 → `world_writable`, 0775 → `group_writable`,
  0700 → clean, symlinked file → `symlink`, override path outside `$HOME`, absent file
  → clean, an equivalent spelling of the default path → KEYS2), a session-count test
  (every read = 2), and an integration case on a real sshd (chmod 0775 → drift).
- **A3 (host key):** ed25519 recorded, server serves only ECDSA →
  `host_key_type_changed`; only `ssh-dss` recorded → `host_key_type_unrecorded`;
  a CA-only host presenting a plain key of another type → `host_key_type_changed`; a
  certificate from an unvouched signer on a CA-vouched host → `host_key_type_changed`
  (`TestHostCertUnvouchedSignerAlerts`); an expired certificate from the vouched CA →
  `host_key`; an unknown host presenting a certificate → `host_key`.
- **A4 (offering):** `orderSigners` table (granted only; `offerAll`; cert by key;
  cert by CA; none granted → all + one warning); a hermetic test that counts the
  public keys the server is queried with (3 loaded, 1 granted → 1 query);
  `TestAuthFailureHintsOfferAllKeys` (granted key held, not installed → `auth` with the
  hint; no second handshake, and every other held key stays unqueried); the same run
  with `--offer-all-keys` logs in with the other held key; no granted key held in
  plain apply → read falls back, write refused by the guard, no write dial; the D17b
  preflight warning and its debug-level per-server suppression (OP6).
- **B1 (audit):** `TestCriticalOperatorCertOnly`, declared `cert-authority` →
  compliant, `TestCriticalOperatorExpired` (declared and undeclared expiry, OP3),
  `TestOperatorLaterLineLogsIn` (dead first line, working second line → not critical),
  `TestOperatorEveryLineIgnored` (`ignored`), `TestOperatorIgnoredThenDeadLine`,
  posture world/group/symlink cases, `host_key_type_changed` → exit 2 and
  `host_key_alerts` 1, EXPIRED/WEAK annotations without exit change, no WEAK on a
  `REVOKED` row, `critical_reasons` ordering with all six values and absent on
  non-critical servers; goldens `report_posture`, `report_operator_certonly`,
  `report_key_issues`, `report_host_key_type_changed` (text and JSON),
  `report_operator_expired`, read back by eye; `report_error_kinds` stays
  byte-identical.
- **B2 (config, apply, adopt, import):** granted DSA user → loads, `Conflicts()` holds
  the message and exit 2; ungranted DSA user → warning, no conflict, exit unchanged;
  apply refuses that server; `TestWeakKeyRemovalOnlyWriteProceeds` and
  `TestWeakKeyConvergedServerStaysRefused`; `TestSaveRefusedWhenAddingWeakKey`,
  `TestRevokeUnrelatedSavesWithWeakKeyPresent` (OP4), a revoked-kind conflict still
  refusing the save; passed expiry → warning with `now` pinned; adopt skips a 1024-bit
  RSA key with the warning and does not extend a known owner's weak key;
  `TestImportSkipsWeakIdentity` for plain import and `--merge` (OP5);
  `import --operator` with a weak key exits 3; `Survivors` unchanged.
- **B3 (cmd):** `--offer-all-keys` on all five help goldens; `rotate` replaces a DSA
  key and saves while `apply` on the original refuses that server (exit 1).
- **E2E:** a 0775 directory above an `authorized_keys_file` override (`~/loose`) in a
  container, because sshd's StrictModes would lock out a login through a 0775
  `~/.ssh` → `audit` exits 1 with
  `group_writable`, `apply` refuses with 48, fix the mode → `audit` exits 0.

Acceptance: `GOTOOLCHAIN=go1.27.3 make check` and `make integration` pass; the README
exit table matches `audit.ExitCode`; a verifier re-checks each exit row against a
real run and the hostile-output parsing of `FinishPosture`.

## Out of scope

- **On hold (owner, 2026-11-07):** key generation and **scheduled rotation** — so no
  `added:` date, no key-age limit and no "overdue for rotation" in audit (that part
  of PRD-10's suggested fix is excluded for this reason); `prune` (the later deep
  probe only reports other accounts' keys and never removes them); `apply --force`;
  `import --prefer`; `move-key`; apply wipe/empty-server mode.
- A configurable `policy:` block in the manifest (D19 option 2 was not chosen).
- Treating an added `command=`/`from=` on an operator line as critical (stays options
  drift, exit 1).
- The design of the deeper PRD-9 probe (`sshd -T`, other accounts): its own later
  spec.
- Restricting `HostKeyAlgorithms` to recorded types (D16 option 2, rejected).
- Changing apply/revoke/rotate exit codes for host-key kinds (the D28 table owns
  them) (apart from D10b above).
- Bastions/ProxyJump (D23, P10) and the operator scope split `protected:` (D21, P10).
