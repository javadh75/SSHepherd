# Design: audit trust, key policy and connection posture

- **Date:** 2026-11-08 (drafted in wave W1 of the review-remediation plan)
- **Status:** Draft — owner decisions D14–D19 are **answered** (2026-11-07, second
  sitting; recorded below). Awaiting spec approval, where the owner sees the
  spec-author defaults D14a–c and D17a–b and the open points at the end. Nothing
  here is built until then. Implementation is W5+ (**P09-impl**), after P14 (W3).
- **Findings:** SEC-1, COR-5, COR-6, SEC-5 (LOW) and PRD-9, PRD-10 (MEDIUM) from the
  2026-11-07 whole-repo review.
- **Plan:** package P09 of `docs/superpowers/plans/2026-11-07-review-remediation.md`
  (spec in W1, implementation in W5+).
- **Composes with:** `2026-11-08-revocation-memory-design.md` (P04): the shared
  exit-code table (D28) and policy conflicts (D29). This spec adds audit rows to that
  table and one new conflict kind; it does not restate P04's rows.
- **Amends:** `2026-07-06-audit-slice-design.md` (critical tier, read sessions),
  `2026-07-16-audit-json-exit-codes-design.md` (JSON fields, `error_kind`, exit table),
  `2026-07-10-operator-users-wildcard-access-design.md` (what "missing operator key"
  covers), `2026-10-16-identity-keyfile-auth-design.md` (key offering).
- **Code anchors:** file:line references are from `ee14c4d`. W1 (P05, P07) and W2
  (P11) move lines, and P14 (W3) moves `ErrorKind`, `ReadResult` and `HeldKey` into
  `internal/fleet`; the W5+ plan re-targets every anchor by function name. README
  line numbers are from `ee14c4d`; the implementing integrator finds each section by
  its heading.

How to read this draft: every wording in `code` quotes is target text. It becomes a
test expectation, and after implementation the README copies it **from the goldens**,
never from this document.

## Context and goal

`audit` is the tool's monitoring surface: a scheduled run that exits 0 should mean
"the fleet's managed `authorized_keys` files are what the manifest says, and nothing
about them needs a human". Six review findings show where that promise is weaker
than it reads:

- **What audit sees.** It reads one file per server with a bare `cat`
  (`AuthorizedKeysCmdFor`, `internal/sshconn/sshconn.go:76-78`) and never checks
  that file's mode or owner, or its directories' (**SEC-1**). The write path refuses
  the same conditions with exit 48 (`ancestorCheck`, `internal/sshwrite/sshwrite.go:149-161`).
  And the README promises more than one file can show: "answer 'who can log into
  which server?'" (README:37), while README:268-272 already admits other layouts
  "are not detected" (**PRD-9**).
- **How audit grades it.** An operator key installed as `cert-authority` or
  `principals=` lands in `Diff.OK` and shows as options drift (exit 1), although it
  cannot log in — `criticalDrift` (`internal/audit/report.go:257-268`) looks only at
  `Diff.Missing`, while `apply`'s `certOnly` (`internal/apply/plan.go:518-527`)
  already knows such a line is dead (**COR-5**). A server that suddenly presents a
  host key of a type `known_hosts` does not record ends up as
  `host_key_type_unrecorded` (`internal/sshconn/hostkey.go:49-54`), which
  `hostKeyAlert` (`internal/audit/errors.go:82-84`) keeps at exit 1 (**COR-6**). And
  there is no key policy: `authkeys.ParseLine` (`internal/authkeys/authkeys.go:27`)
  accepts DSA and 1024-bit RSA, and only `rotate` reads `expiry-time`
  (`cmd/sshepherd/keyarg.go:268-299`) (**PRD-10**).
- **What the client reveals.** `orderSigners` (`internal/sshconn/connect.go:240-266`)
  offers the granted keys first and then **every other** held key, so any managed
  server — including a hostile one — learns every public key the operator holds
  (**SEC-5**).

The goal: audit checks what sshd itself checks before honouring a file, grades a dead
operator key and a host-key type change as the alarms they are, flags weak and
expired keys, the README claims only what audit can see, and each server is offered
only the keys the manifest grants there. All agentless, all additive to JSON
schema 1.

## What the code does today (grounding, `ee14c4d`)

- **Read sessions.** `readAuthorizedKeys` (`internal/sshread/sshread.go:160-199`)
  opens one connection and runs the read command; for the default path only it runs a
  second session, `SecondaryKeysCmd` (`sshconn.go:83-85`), mapped by
  `FinishSecondaryProbe` (`sshconn.go:90-100`): exit 46 = non-empty
  `authorized_keys2`, any other non-zero exit = `ErrorKindRemote`. An override path
  costs one session, the default path two.
- **The read command is a contract.** `sshwrite`'s verify step reads back through
  `AuthorizedKeysCmdFor` byte for byte (its doc comment, `sshconn.go:70-75`). It must
  not change.
- **The write walk.** `writeCmdFor` (`sshwrite.go:194-`) refuses (48) a symlinked
  directory, a directory not owned by the login uid, and a **file** not owned by the
  login uid (`sshwrite.go:199,202`; root is **not** accepted for the file or its
  directory). `ancestorCheck` then walks the directory's ancestors up to `$HOME`,
  as written and resolved (`cd -P`), refusing any component that is group- or
  world-writable (`?????w*` / `????????w*` on `ls -ldn`'s mode) or owned by neither
  the login uid nor root. A symlinked target file exits 45. A path outside `$HOME`
  is walked to `/`.
- **sshd's own rule (StrictModes, default `yes`).** sshd ignores an
  `authorized_keys` file that is group/world-writable or owned by neither the user
  nor root, or whose directories up to the home directory are; it follows symlinks.
  So a login that succeeded on a server whose managed file fails this rule came
  either through another key source or with `StrictModes no` (an open door). Either
  way the file audit read is not what governs access there.
- **Critical tier.** `criticalDrift` returns true only for a missing operator key;
  `statusOf` (`report.go:283-294`) ranks unreachable > compliant > critical > drift.
  `ServerResult.Compliant` (`internal/audit/audit.go:76-84`) has no posture input.
- **Host-key negotiation.** `KnownHosts.HostKeyAlgorithms`
  (`internal/sshconn/knownhosts.go:127-150`) orders certificate algorithms (when an
  `@cert-authority` line matches), then the algorithms for the recorded types, then
  every remaining plain algorithm. OpenSSH does the same: it **reorders**, it does
  not restrict.
- **Key offering.** `Credentials.Signers` (`internal/sshconn/credentials.go:109`)
  returns every key-file and agent key (certificates included). `ConnectWith`
  (`connect.go:182-187`) takes `prefer` from `Dialer.PreferKeys`, which audit
  (`cmd/sshepherd/audit.go:93`), adopt (`adopt.go:150`) and apply (`apply.go:92`)
  set to `audit.GrantedFingerprints` (operators first, `audit.go:125-132`), and
  revoke/rotate to the former∪edited union (`editrun.go:227`). The post-write probe
  passes `Only` (`sshwrite.go:592`), which never falls back.
- **Expiry.** `expiryOption`/`expiryPassed` live in `cmd/sshepherd/keyarg.go:268-299`
  (8/12/14 digits, `Z` = UTC, local time otherwise). D27 (W1, P05) makes a malformed
  `expiry-time` a load error; nothing evaluates a well-formed one outside `rotate`.

## Owner decisions

Asked one at a time in the plan's order (Block 4: D14 → D15 → D16 → D17 → D18 → D19)
and answered 2026-11-07. They are final. The spec-author defaults (D14a–c, D17a–b)
stand unless the owner changes them at spec approval.

| # | Question | Answer (2026-11-07) | What it means here | README sections it changes |
|---|---|---|---|---|
| **D14** | Should audit check file and folder permissions and owners, the way apply does before writing? (SEC-1) | **Yes**: a new "unsafe permissions" drift at exit 1; exit 2 when something on the path is world-writable. | Section 1 (posture probe). | **`sshepherd audit`** drift classes (l.357) and JSON; **Per-server `authorized_keys_file`** (l.255); **Exit codes** (l.1373); **Safety model** (l.1385). |
| **D14a** | *(author default)* Is a root-owned `authorized_keys` acceptable to audit? | **Yes, as sshd accepts it.** Note: the write path refuses a root-owned **file** (48); only its ancestors may be root-owned. Audit follows sshd, not the write path — see section 1. | No posture issue for a root-owned file; apply's 48 refusal is unchanged. | — |
| **D14b** | *(author default)* A failed posture probe: unreachable, or "posture unknown" drift? | **Unreachable (`error_kind: remote`)**, the same as today's failed `authorized_keys2` probe. | Section 1, "Failure". | **`sshepherd audit`** error kinds. |
| **D14c** | *(author default)* Probe an `authorized_keys_file` outside `$HOME`? | **Yes**: the walk stops at `/`, as the write walk does. | Section 1. | **Per-server `authorized_keys_file`**. |
| **D15** | An operator key that is on a server but cannot log in (`cert-authority` / `principals=`): critical (exit 2)? (COR-5) | **Yes.** A key that cannot log in is the same as a missing one. | Section 2. With D19, a passed `expiry-time` on the server's operator line is the same class. | **Operator users** (l.239); **`sshepherd audit`** (rows, JSON); **Exit codes**. |
| **D16** | *(re-asked with corrected options)* A server suddenly shows a different kind of host key than the one you saved: treat it as a possible attack (exit 2)? (COR-6) | **Yes** — corrected option (new 1): keep today's negotiation and add `host_key_type_changed` (exit 2). | Section 3. | **`sshepherd audit`** error kinds; **Exit codes**; **Safety model** connection posture. |
| **D17** | Should each server only see the keys the manifest grants there (plus operator keys)? (SEC-5) | **Yes**: one rule on every command; when none of the loaded keys is granted on a server, offer all of them with a warning; `--offer-all-keys` turns the filter off. | Section 4. | **Authentication** (l.1161, key offering); flag tables of **`sshepherd audit`** (l.346), **`adopt`** (l.542), **`apply`** (l.571), **`revoke`** (l.800), **`rotate`** (l.1059); **Safety model**. |
| **D17a** | *(author default)* Flag name and reach. | `--offer-all-keys` on audit, adopt, apply, revoke and rotate; default off on all five. | Section 4. | The five flag tables. |
| **D17b** | *(author default)* Preflight warning when no held key is granted on any target server? | **Yes, warn only** (from `sshread.CheckCredentials`). | Section 4. | **Authentication**. |
| **D18** | The README says audit answers "who can log in", but it reads only the managed files. Narrow the claim now, deeper opt-in check later? (PRD-9) | **Yes.** | Section 6: exact wording, applied by the next README-touching integrator; the deep probe gets its own later spec. | **Why** (l.37); **Per-server `authorized_keys_file`** (l.268-272); CLAUDE.md "Core capabilities → Audit". |
| **D19** | Should weak or expired keys be flagged? (PRD-10) | **(1)** Built-in rules: DSA and RSA under 2048 bits are policy problems handled as D29 says (audit critical, apply skips those servers, a manifest that loads today keeps loading); a passed `expiry-time` warns. | Section 5. Not options (2) a configurable `policy:` block or (3) no rules. | **Validation rules** (l.274); **`sshepherd audit`**; **`sshepherd apply`**; **`sshepherd adopt`**, **`sshepherd import`**; **Exit codes**. |

**Why D16 was re-asked.** The first wording of D16's option 1 said "only accept
recorded types, as OpenSSH's strict mode does". The verifier showed that
OpenSSH only **reorders** host-key algorithms from `known_hosts`; it does not
restrict them. And
restricting would not close the gap: an impersonator offering only an unrecorded type
would then fail with "no common algorithm for host key", which `handshakeKind`
(`internal/sshconn/errors.go:42-58`) classifies as `handshake` — still exit 1. The
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

### 1. Posture probe (D14, D14a–c)

**A new remote command, in its own session.** `sshconn.PostureCmdFor(path string)`
builds a POSIX-sh script (run through `remoteCommand`'s `exec /bin/sh -c` like every
other script) that inspects the managed file and its directories and prints one
record per problem. It runs as a **separate session** after the read, so the read
command's bytes — which `sshwrite` verify depends on — stay unchanged.

**The `authorized_keys2` probe folds into it.** For the default path the script also
reports a non-empty `~/.ssh/authorized_keys2` (today's `SecondaryKeysCmd`, which is
removed). Session count per server: default path **2** (unchanged: read + posture);
override path **2** (was 1). The fan-out benchmarks (`make bench`) are re-run in the
implementation; the `--parallel 32` default is not expected to move, and the audit
spec's Tuning resolution gets a one-line note either way.

**Shared walk.** The StrictModes walk moves out of `sshwrite.go` into
`internal/sshconn` as one builder parameterized by the action taken on a bad
component: `ancestorWalk(onBad string) string`. The write path passes `exit 48`, and
its script stays **byte-identical** (pinned by a golden of `writeCmdFor` taken before
the move). The posture script passes an action that prints a record and continues.

**What it checks** (`u=$(id -u)`; `set -f`; nothing is ever written):

1. **The file** (`$p`), when it exists:
   - a symlink → `symlink` (apply refuses to write it with 45, so the managed file
     cannot be converged; whoever owns the link can redirect it);
   - owner neither `$u` nor `0` → `foreign_owner` (D14a: root is fine, as for sshd);
   - group-writable (`?????w*`) → `group_writable`; world-writable (`????????w*`) →
     `world_writable` (both may be printed for one path, each as its own record).
2. **The ancestors**, as written and resolved (the same two loops as
   `ancestorCheck`), from the file's directory up to `$HOME` — or to `/` when the
   path is outside `$HOME` (D14c) — with the same three classes (`foreign_owner`,
   `group_writable`, `world_writable`). A symlinked ancestor is not itself an issue
   (as today: `l*` skips the mode check); the resolved walk covers its target.
   Components that do not exist are skipped: an absent file or directory is not a
   posture problem (absence is already reported by the read).
3. **`authorized_keys2`**, default path only: `SSHEPHERD-KEYS2 1` when
   `~/.ssh/authorized_keys2` is non-empty (`[ -s ]`), exactly today's semantics.

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
- Parsing (`FinishPosture(code int, stdout, stderr *CappedBuffer) (fleet.Posture, error)`,
  replacing `FinishSecondaryProbe`) is **fail-closed**: any other line, an unknown
  issue, a malformed mode or uid, more than **64 records**, more than **1 MiB** of
  stdout, or a non-zero exit → `ErrorKindRemote` with the message
  `posture probe output malformed` (or `posture probe failed (exit N): <sanitized stderr>`),
  so the server is **unreachable** (D14b). A path containing a newline therefore
  breaks the grammar and fails closed. Paths are sanitized (`SanitizeRemote`) before
  they are printed; the JSON carries the sanitized form.

**Types** (in P14's leaf package `internal/fleet`):

```go
type PostureIssue struct {
    Path  string // sanitized; remote-controlled once resolved
    Issue string // "symlink" | "foreign_owner" | "group_writable" | "world_writable"
    Mode  string // ls -ldn first field, e.g. "drwxrwxrwx"
    UID   string // owner uid as printed
}
// ReadResult gains Posture []PostureIssue; AuthorizedKeys2 keeps its meaning.
```

**Grading.** `ServerResult.Compliant()` is false when `len(r.Posture) > 0`.
`statusOf` returns critical when any issue is `world_writable` (anyone on the host
can then add a key, or replace the directory). `symlink`, `foreign_owner` and
`group_writable` are drift (exit 1). The posture issues are graded whether or not
the file's keys match the manifest: a matching file sshd would ignore, or that
someone else can rewrite, is not compliant.

**Interaction with apply.** apply's refusal classes are unchanged: it still refuses
48 for the same components (and also for a root-owned file or directory, which audit
accepts per D14a). An audit posture finding is fixed by hand (`chmod`/`chown`); the
README says so in the drift-class text.

### 2. Operator key that cannot log in (D15)

- `certOnly` moves from `internal/apply/plan.go:518-527` to `internal/authkeys`
  (P05's `options.go`) as `CertOnly(options []string) bool`. `apply.Survivors` calls
  it, so write and audit share one rule.
- `expiryOption`/`expiryPassed` move from `cmd/sshepherd/keyarg.go` to
  `internal/authkeys` as `ExpiryOption`/`ExpiryPassed` (section 5); `rotate` calls the
  moved functions.
- `criticalDrift` gains: for each `k` in `r.Diff.OK` whose owner is an operator, with
  `actual := r.Diff.Actual[k.Fingerprint]`:
  - `authkeys.CertOnly(actual.Options) && !authkeys.CertOnly(k.Options)` → critical,
    reason `cert_only`. A manifest that deliberately declares the operator line as
    `cert-authority` does not drift and is not critical.
  - the server line's `expiry-time` has passed (`authkeys.ExpiryPassed` against the
    clock seam) → critical, reason `expired`, **whether or not the manifest declares
    the same expiry**: the operator has lost access either way, which is what D15
    protects. An on-server expiry value `ExpiryPassed` cannot read is not graded
    critical here; it stays whatever the options comparison makes it (options drift
    when it differs from the manifest).
- Added `command=`/`from=` on an operator line stay options drift at exit 1: those
  lines still allow some login (out of scope, as the verifier argued).

### 3. Host-key type change (D16, option new 1)

- Negotiation is unchanged (`HostKeyAlgorithms` keeps reordering, not restricting).
- In `hostKeyHint` (`hostkey.go:49-54`), the unrecorded-type branch splits:
  - `known_hosts` records at least one type x/crypto can verify for this host
    (`algosForKeyType(t) != nil` for some recorded `t`) **and** the presented type is
    not recorded → new kind `host_key_type_changed`, exit 2, counted in
    `host_key_alerts`.
  - every recorded type is unsupported (for example only `ssh-dss`) →
    `host_key_type_unrecorded`, exit 1, as today.
- Why this is sound: the recorded types are negotiated first, so a genuine server
  reaches this branch only when it no longer serves **any** recorded key. That is a
  re-key, and it needs a human. The meaning of an existing kind never changes tier;
  `host_key_type_unrecorded` keeps exit 1 for the cases it still covers.
- `hostKeyAlert` includes the new kind. The constant
  `ErrorKindHostKeyTypeChanged = "host_key_type_changed"` lives in `internal/fleet`
  (P14). apply/adopt/revoke/rotate report the new `error_kind` in their own output;
  their exit codes follow the shared D28 table (P04 section 8), which this spec does
  not change for those commands.

### 4. Key offering (D17, D17a, D17b)

- `Dialer.OfferAll bool` (`connect.go:25-48`). In `ConnectWith`, after `prefer` is
  resolved and when `!d.OfferAll && len(opts.Only) == 0`:
  - if at least one held signer matches `prefer` (by the rules below), offer only
    those (`only = prefer`);
  - otherwise (no granted key is held — normal right after `import --servers-only`
    or on first contact), offer every held key in today's order and log one warning:
    `web-1: none of the keys granted here are loaded; offering all 3 held keys`.
    No new error kind.
- **Operators** need no extra code: `GrantedFingerprints` already lists them first,
  because `DesiredFor` includes every operator.
- **Certificates.** A certificate's fingerprint is not its key's. Under the
  restricted offer a held certificate is offered when `cert.Key` **or**
  `cert.SignatureKey` has a granted fingerprint (the second case is a manifest
  `cert-authority` line). The rule lives in `orderSigners`, with table tests.
- **Callers.** audit and apply keep `GrantedFingerprints`; revoke/rotate keep the
  former∪edited union (a pre-edit key still logs in); adopt uses the same rule, and
  for a server with no granted held key the fallback offers everything. The
  post-write probe already passes `Only` and is unchanged (D31). The write
  connection (`sshwrite.go:470`, `ConnectOptions{}`) inherits the rule through
  `Dialer.PreferKeys`.
- **`--offer-all-keys`** (D17a) on audit, adopt, apply, revoke and rotate, default
  off, sets `OfferAll` and restores today's order (granted first, then every other
  held key). Help text: `offer every loaded key to every server (default: only the keys the manifest grants there)`.
- **Preflight** (D17b). `sshread.CheckCredentials` (`internal/sshread/sshread.go:42`)
  warns, once, when no held key is granted on **any** target server:
  `none of the loaded keys is granted on any target server; each server will be offered all 3 held keys`.
  When this preflight warning fired, the per-server fallback warnings drop to debug
  level, so a first-contact run prints one line instead of one per server.
- Side benefit: fewer keys offered means fewer `MaxAuthTries` disconnects.

### 5. Key policy (D19 option 1, through D29)

- **New `internal/authkeys/policy.go`:** `StrengthIssue(pub ssh.PublicKey) string`
  returns `"dsa"`, `"rsa_under_2048"` or `""` (RSA bits from
  `pub.(ssh.CryptoPublicKey).CryptoPublicKey().(*rsa.PublicKey).N.BitLen()`).
  `authkeys.Key` gains `Weak string`, set by `ParseLine`, so the raw line is not
  parsed twice. `ExpiryOption`/`ExpiryPassed` move here (section 2).
- **Load-time behavior follows D29.** A weak key in `users:` is **not a load error**:
  `config.Parse` returns it as a policy conflict in `Conflicts()` (P04 section 2)
  with `Kind: "weak_key"` and the message
  `user "old" key 1: dsa keys are rejected` (or
  `user "old" key 1: rsa keys under 2048 bits are rejected (1024)`); `Servers` is
  every server that key renders on. Then, per D29:
  - **`audit`** loads the manifest, reports the conflict as critical on those
    servers, exits 2 (`critical_reasons: ["policy_conflict"]`).
  - **`apply`** (and the apply phase of revoke/rotate) refuses those servers (nothing
    written there) and plans the rest; exit 1.
  - **Saving commands** (revoke, rotate, `adopt --merge`, `import --merge`,
    regenerate-mode `adopt`) refuse, exit 3, only when the save **adds** a weak key
    (a fingerprint not in the loaded manifest). An unrelated `revoke bob` therefore
    still saves while `alice` holds a DSA key, and the remediations
    `rotate alice --old <dsa> --new <ed25519>` and `revoke --key <dsa>` always work.
    This is the weak-key reading of P04's "as saved still has a conflict" rule (see
    "Interactions with P04").
  - **`validate`** (D25, when it lands) exits 3 when the manifest holds a weak key.
- **Expired keys.** A desired key whose `expiry-time` has passed is a load
  **warning** only (`config.Warnings`): `user "alice" key 1: expiry-time="20200101" has passed; sshd no longer accepts this key`.
  The clock is a seam (`var now = time.Now`) so tests pin it.
- **adopt and import.** A weak on-server key (adopt, including `--merge`) or a weak
  `.pub` identity (import, both modes) is **skipped with a warning**:
  `key SHA256:… on web-1: rsa_under_2048 key not adopted` /
  `identity ~/.ssh/old.pub: dsa key not imported`. Emitting it would produce a
  manifest with a policy conflict. audit keeps showing such a key as UNAUTHORIZED,
  which is the right pressure.
- **Audit annotations** (informational, no exit change, because the server matches
  the manifest): unauthorized rows whose key is weak get ` · WEAK (dsa)`; present
  rows whose desired `expiry-time` has passed get ` · EXPIRED`. The operator case in
  section 2 is the exception (critical).
- **Excluded** (overlap with the on-hold scheduled rotation): no `added:` date, no
  key-age limit, no "overdue for rotation".
- Note for the README: OpenSSH 9.8 and later build sshd without DSA by default, so a
  DSA key usually cannot log in on a current server anyway; the rule makes that
  visible instead of silent.

### 6. Narrowing the coverage claim (D18)

**Now** — a doc-only change that this spec lane cannot make. It goes to the W1
integrator (or the first README-touching integrator after D18 is answered; it is
answered). The exact text:

- README "Why" (line 37), replacing the Audit bullet:

  ```markdown
  - **Audit** — check that every managed `authorized_keys` file holds exactly the
    manifest's keys, in text or JSON. It does not see other accounts on the host or
    sshd's other key sources (see [Per-server `authorized_keys_file`](#per-server-authorized_keys_file)).
  ```

- README "Per-server `authorized_keys_file`" (lines 270-272), replacing the last
  sentence ("Other sshd `AuthorizedKeysFile` layouts … the file sshd actually reads."):

  ```markdown
  Audit reads only the managed file (and, on the default path, checks
  `authorized_keys2`). It does not see sshd's other key sources — a custom
  `AuthorizedKeysFile` list in `sshd_config`, `AuthorizedKeysCommand`,
  `TrustedUserCAKeys`, `AuthorizedPrincipalsFile`/`AuthorizedPrincipalsCommand` — or
  other accounts on the same host. Point `authorized_keys_file` at the file sshd
  actually reads.
  ```

- CLAUDE.md "Core capabilities (intended)", replacing the Audit bullet:

  ```markdown
  - **Audit** — check that every managed `authorized_keys` file holds exactly the
    manifest's keys; other accounts and sshd's other key sources are not seen (a
    deeper opt-in check is a later slice).
  ```

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
| 1 | posture `symlink`, `foreign_owner`, `group_writable`; posture probe failed or malformed (`error_kind: remote`, server unreachable); `host_key_type_unrecorded` now only when every recorded type is unsupported |
| 2 | posture `world_writable`; operator key present but `cert_only` or `expired`; `host_key_type_changed`; a weak key granted on a server (policy conflict, D29) |
| 3 | `validate`, and saving commands that would **add** a DSA or RSA<2048 key. audit reports a weak key as critical (2) instead; apply refuses the servers that grant it (1). |

The README "Exit codes" table (l.1373) is rewritten from the merged P04 + P09 table by
the wave that lands it; the row-2 text gains the four audit cases above.

## JSON

Schema stays **1**; every field is additive and `omitempty` unless stated.

- **Server:**
  - `posture`: `[{"path": "...", "issue": "world_writable", "mode": "drwxrwxrwx", "uid": "1001"}]`.
  - `critical_reasons`: `["operator_missing" | "operator_cannot_log_in" | "world_writable" | "policy_conflict"]`,
    sorted and de-duplicated, present exactly when `status` is `critical`, so
    monitoring can tell why it got exit 2. (P04's revoked-key and forged-serial cases
    add their own values in W4; the list is open.)
- **Key** (in `present` / `unauthorized`):
  - `cannot_log_in`: `"cert_only" | "expired"` on a present operator key graded
    critical by section 2.
  - `key_issues`: `["dsa" | "rsa_under_2048" | "expired"]`.
  - `operator`: `true` now also on a **present** key that is critical
    (`cannot_log_in`), extending the rule at `internal/audit/json.go:204` that
    `operator` marks only critical rows.
- **Summary:** unchanged, except that `host_key_alerts` also counts
  `host_key_type_changed`.
- **New `error_kind` value:** `host_key_type_changed`. The existing values keep
  their meaning and tier.

The same paragraph is appended to `2026-07-16-audit-json-exit-codes-design.md` at
approval.

## Text report wording

Target wording; the goldens own the final bytes (P07 reshapes the `ERROR` line and
hints in W1, and this wording is re-checked against P07's renderer).

- Posture (one line per record, under the server, before the `→` count line):
  ```
    ‼ unsafe permissions: /home/deploy/.ssh is world-writable (drwxrwxrwx, uid 1001) — anyone on the host can add a key; sshd's StrictModes would ignore this file
    ⚠ unsafe permissions: /home/deploy/.ssh/authorized_keys is group-writable (-rw-rw-r--, uid 1001) — sshd's StrictModes would ignore this file
    ⚠ unsafe permissions: /srv/keys is owned by uid 1002, not the login user or root — sshd's StrictModes would ignore this file
    ⚠ unsafe permissions: /home/deploy/.ssh/authorized_keys is a symlink — apply refuses to write through it
  ```
  followed once per server by
  `  note: fix by hand (chmod go-w / chown); a login that succeeded here came through another key source or with StrictModes off`.
- Operator cannot log in:
  `‼  op (op@sshepherd)  SHA256:…  ssh-ed25519  present but CANNOT LOG IN (CRITICAL: operator key; server line is cert-only)`
  and `… (CRITICAL: operator key; server line expired 2026-01-01)`.
- Host key: `ERROR [host_key_type_changed]: …` with the hint leading
  `HOST KEY TYPE CHANGED for host:port — the server no longer presents any recorded key type (recorded: ssh-ed25519); possible impersonation; verify the presented fingerprint out of band (…) before touching known_hosts`.
- Key annotations: ` · WEAK (dsa)`, ` · WEAK (rsa 1024)`, ` · EXPIRED`.
- Policy conflict: printed in P04's `manifest:` conflict block with the D19 message.
- Summary line: unchanged format; `HOST KEY ALERT` counts the new kind.

## Remote-script contract (summary)

- `sshconn.PostureCmdFor(path)` = `PathAssign(path)` + the posture script; the path
  enters once, ShQuote-d, exactly as for the read and write commands.
- Output: only `SSHEPHERD-POSTURE <mode> <uid> <issue> <path>` and
  `SSHEPHERD-KEYS2 1` lines; at most 64 records and 1 MiB; exit 0.
- Parse fail-closed into `ErrorKindRemote`; never into a clean result.
- `AuthorizedKeysCmdFor` and `writeCmdFor` bytes are unchanged (golden-pinned).

## Threat notes

- **A compromised server can lie.** It controls `ls`, `id` and stdout, so it can
  print nothing and look clean, exactly as it can serve a fake `authorized_keys`.
  The fail-closed parser guarantees only that malformed or oversized output is never
  read as clean; posture is evidence about an honest server's configuration, not an
  integrity proof against a hostile one. The README says this plainly.
- **Remote paths are printed.** `$HOME` and resolved paths come from the server, so
  they pass `SanitizeRemote` and the grammar forbids newlines.
- **Key offering leaks less, not nothing.** The fallback (no granted key held)
  still offers every held key; `--offer-all-keys` does too. A hostile server that
  is granted nothing on the manifest still sees the operator keys, by design.
- **`host_key_type_changed` cannot be dodged** by offering only an unrecorded type:
  negotiation still succeeds and the presented key reaches the verdict branch.

## Risks

- **The restricted offer can break a login that worked by accident** (the working
  key is held but another held key is the granted one). Mitigations: the fallback,
  the warning, `--offer-all-keys`.
- **A weak key turns a passing scheduled audit into exit 2 on upgrade** (D29: the
  manifest keeps loading, but every server granting the key goes critical, and apply
  skips those servers). A weak **operator** key freezes apply on every server until
  `rotate` replaces it. The release note and README must say so; `rotate` and
  `revoke --key` are the way out and always save. (The plan's sketch said weak keys
  would make manifests fail to load; under D29 they do not.)
- **Posture can page on hosts that work today** (world-writable home directories
  exist in the wild). Intended: such a host is either ignoring the file or open to
  every local user.
- **`host_key_type_changed` pages on a legitimate re-key that dropped every recorded
  type.** Intended: a re-key needs a human.
- **Tools.** The probe needs `ls -ldn`, `dirname`, `cd -P`, `pwd -P`, `id`, already
  required by the write path; busybox, dash and bash are covered by integration.
- **An extra session on override-path servers** (section 1); measured by `make bench`.

## Interactions with P04 (revocation memory)

- **Conflict kinds.** `Conflict.Kind` gains `"weak_key"`. For that kind, saving
  commands refuse only a save that **adds** a weak key; P04's general rule (refuse
  when the manifest as saved still has a conflict) stays for `revoked_key` and
  `revoked_access`. Without this narrowing, any existing weak key would block every
  unrelated revoke — the opposite of what D29 is for. P04 section 2 gets a one-line
  cross-reference at approval.
- **`critical_reasons`** is shared: P04's W4 work adds `revoked_key` and
  `forged_serial` values to the same open list.
- **Exit table.** The rows above merge into P04 section 8's table; neither spec
  changes the other's rows.

## README and CLAUDE.md sections

Updated by the implementing integrator, sample output copied from the goldens:

- **Why** (l.37) — D18 now (section 6), already applied by then.
- **Status** — the implemented-slice table and CLAUDE.md Status.
- **The manifest → Operator users** (l.239) — a present-but-cannot-log-in operator
  key is critical too.
- **Per-server `authorized_keys_file`** (l.255-272) — D18 narrowing (now); posture
  checks cover override paths outside `$HOME` up to `/` (D14c).
- **Validation rules** (l.274) — weak keys are policy conflicts (not load errors);
  passed `expiry-time` is a warning.
- **`sshepherd audit`** (l.342) — flag table (l.346) gains `--offer-all-keys`; drift
  classes (l.357) gain unsafe permissions, cannot-log-in, WEAK/EXPIRED annotations,
  and the new `error_kind`; JSON fields.
- **`sshepherd adopt`** (l.534), **`sshepherd import`** (l.477) — weak keys are
  skipped with a warning; adopt's flag table gains `--offer-all-keys`.
- **`sshepherd apply`** (l.566), **`sshepherd revoke`** (l.786),
  **`sshepherd rotate`** (l.1050) — `--offer-all-keys`; apply refuses servers granting
  a weak key; saves that would add a weak key are refused.
- **Authentication** (l.1161) — key offering: only granted (+operator) keys, the
  fallback and its warning, the preflight warning, `--offer-all-keys`.
- **Exit codes** (l.1373) — the rows above.
- **Safety model** (l.1385) — connection posture: restricted key offer,
  `host_key_type_changed`; audit's posture check mirrors StrictModes.
- **CLAUDE.md** — "Core capabilities → Audit" (D18, now) and Status.

## Files touched by the implementation

`internal/fleet/{errors,read}.go`; `internal/sshconn/{sshconn,posture,knownhosts,hostkey,connect,credentials}.go`
(`posture.go` new); `internal/sshread/sshread.go`; `internal/sshwrite/sshwrite.go`
(walk moved out, script bytes unchanged); `internal/audit/{audit,report,json}.go`
plus `testdata/`; `internal/authkeys/{options,policy}.go` (`policy.go` new);
`internal/config/config.go`; `internal/apply/plan.go` (`certOnly` →
`authkeys.CertOnly`; weak-key refusal); `internal/adopt/adopt.go`;
`internal/identity` (weak `.pub` skip) or `internal/reconcile`, wherever import's
identity derivation lives after W3; `cmd/sshepherd/{audit,adopt,apply,revoke,rotate,editrun,keyarg,import}.go`
plus help goldens. Each with its `_test.go`.

## Testing (W5+, failing first)

The plan's P09 "Implementation outline" (Task 0, Wave A: A1–A4, Wave B: B1–B3) holds,
with these additions from this spec:

- **A1 (authkeys):** `TestStrengthIssue` (ed25519, RSA 2048 ok; RSA 1024 →
  `rsa_under_2048` with `GODEBUG=rsa1024min=0`; DSA → `dsa`), `TestCertOnly`,
  `TestExpiryPassed` (moved cases), a DSA seed in the `ParseLine` fuzz corpus.
- **A2 (posture):** `TestWriteCmdUnchanged` (golden taken before the move),
  `TestReadCmdUnchanged`, `TestFinishPosture` table (clean; each issue; garbage line;
  unknown issue; 65 records; >1 MiB; newline in path; non-zero exit; KEYS2),
  `FuzzFinishPosture` (never returns a clean result for input containing a
  non-record line), hermetic `sshtest.ShellHandler` cases (0777 → `world_writable`,
  0775 → `group_writable`, 0700 → clean, override path outside `$HOME`, absent file
  → clean), a session-count test (override path = 2), and an integration case on a
  real sshd (chmod 0775 → drift).
- **A3 (host key):** ed25519 recorded, server serves only ECDSA →
  `host_key_type_changed`; only `ssh-dss` recorded → `host_key_type_unrecorded`.
- **A4 (offering):** `orderSigners` table (granted only; `offerAll`; cert by key;
  cert by CA; none granted → all + one warning); a hermetic test that counts the
  public keys the server is queried with (3 loaded, 1 granted → 1 query); the D17b
  preflight warning and its debug-level per-server suppression.
- **B1 (audit):** `TestCriticalOperatorCertOnly`, declared `cert-authority` →
  compliant, `TestCriticalOperatorExpired` (declared and undeclared expiry),
  posture world/group cases, `host_key_type_changed` → exit 2 and
  `host_key_alerts` 1, EXPIRED/WEAK annotations without exit change,
  `critical_reasons` ordering; goldens `report_posture`, `report_operator_certonly`,
  `report_key_issues`, `report_error_kinds` (text and JSON), read back by eye.
- **B2 (config, apply, adopt):** DSA user → loads, `Conflicts()` holds the message;
  apply refuses that server; `TestSaveRefusedWhenAddingWeakKey`,
  `TestRevokeUnrelatedSavesWithWeakKeyPresent`; passed expiry → warning with `now`
  pinned; adopt skips a 1024-bit RSA key with the warning; `Survivors` unchanged.
- **B3 (cmd):** `--offer-all-keys` on all five help goldens; `rotate` replaces a DSA
  key and saves while `apply` on the original refuses that server; keyarg uses
  `authkeys.ExpiryPassed`.
- **E2E:** chmod 0775 on `~/.ssh` in a container → `audit` exits 1 with
  `group_writable`, `apply` refuses with 48, fix the mode → `audit` exits 0.

Acceptance: `GOTOOLCHAIN=go1.27.3 make check` and `make integration` pass; the README
exit table matches `audit.ExitCode`; a verifier re-checks each exit row against a
real run and the hostile-output parsing of `FinishPosture`.

## Open points for spec approval

Author choices where the plan was silent or, on a close read, inexact. None changes an
answered decision; the owner may change any of them at approval.

1. **D14a differs from the write path.** The plan said "root ownership accepted, the
   same as the write walk"; the write path actually refuses a root-owned **file**
   and a root-owned **directory of the file** (48), and accepts root only for higher
   ancestors. Audit follows sshd (root fine everywhere), so a root-owned file is
   audit-compliant but apply refuses to write it. Alternative: report a root-owned
   file as `foreign_owner` so audit and apply agree.
2. **A symlinked `authorized_keys` is drift**, although sshd follows it, because
   apply cannot converge it (45).
3. **Override-path servers gain a session** (1 → 2).
4. **An expired operator line is critical even when the manifest declares the same
   expiry** (section 2).
5. **Weak-key saves are refused only when they add a weak key** (section 5 and
   "Interactions with P04").
6. **Plain `import` also skips weak `.pub` identities**, not only `import --merge`.
7. **Per-server fallback warnings drop to debug after the D17b preflight warning.**

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
  spec. Only the README narrowing lands now.
- Restricting `HostKeyAlgorithms` to recorded types (D16 option 2, rejected).
- Changing apply/revoke/rotate exit codes for host-key kinds (the D28 table owns
  them).
- Bastions/ProxyJump (D23, P10) and the operator scope split `protected:` (D21, P10).
