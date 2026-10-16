# Design: review-hardening pass

- **Date:** 2026-10-16
- **Status:** Implemented 2026-10-16. A whole-repo code review produced 53
  findings. Five parallel fix groups (A config/authkeys/manifest, B
  import/adopt/naming, C tooling/CI/container, D transport/audit, E write
  path) resolved them, and an integration pass then ran the full gate
  (`make check`, `make integration`). A verification follow-up the same day
  closed the partial fixes and regressions it found; see §7.
- **Amends:**
  [audit slice](2026-07-06-audit-slice-design.md),
  [import ssh config](2026-07-09-import-ssh-config-design.md),
  [import IdentityFile users](2026-07-09-import-identityfile-users-design.md),
  [adopt](2026-07-10-adopt-fleet-discovery-design.md),
  [operator users / wildcard access](2026-07-10-operator-users-wildcard-access-design.md),
  [audit JSON / exit codes](2026-07-16-audit-json-exit-codes-design.md),
  [authorized_keys_file override](2026-07-16-authorized-keys-file-override-design.md),
  [adopt --merge](2026-07-16-adopt-merge-design.md),
  [import --merge](2026-07-19-import-merge-design.md),
  [apply slice](2026-07-19-apply-slice-design.md).

This document records *why* each user-visible behavior changed. The README
says *what* the behavior is, and the tests pin it.

## 1. Manifest validation (`internal/config`, `internal/authkeys`)

Shared principle: **the loader must reject anything apply could write but
sshd would ignore or misread.** Either one makes the lockout guard count a
key that cannot log in, or lets audit report "present" for a key that does
nothing.

- **Single YAML document.** `yaml.v3` decodes only the first document, so a
  stray `---` would silently drop everything after it, including grants.
  Parse decodes a second time and requires `io.EOF`. `manifest.Load` repeats
  the check after its node decode as a second layer. A trailing empty `---`
  is rejected too, because it carries no meaning and is a common
  concatenation artifact.
- **Key-option allow-list.** sshd rejects the *whole line* on an unknown
  option, so a typo such as `no-ptty` would install a dead key that the guard
  counts as a survivor. Options are checked case-insensitively, as sshd does,
  against the sshd(8) list. Valued options must be `name="..."` and flags must
  not carry a value. Unknown options are an error, not a warning, because a
  warning still lets apply write the dead line. `cert-authority` stays
  allowed, and the guard handles it (§5).
- **Declared type must match the blob.** OpenSSH's `sshkey_read` returns
  `KEY_TYPE_MISMATCH` and skips the line. Older x/crypto derived the type
  from the blob alone. `golang.org/x/crypto` v0.56.0 (bumped in this pass for
  GO-2026-6354/6355/6303) now rejects most mismatches itself.
  `authkeys.ParseLine` keeps its own check as defense in depth, so the rule
  does not depend on the dependency version. Tests assert *rejection*, not
  which layer rejected. On servers such a line becomes an unparseable line
  (strict refusal or `--partial`), never an OK key.
- **Unsafe runes: one predicate.** `authkeys.IsUnsafeRune` covers control,
  Cf, Zl and Zp. U+2028/U+2029 render as line breaks in many terminals and
  editors, so they can forge report rows just like `\n`. Names, comments,
  option values and `authorized_keys_file` all use it. Non-ASCII letters stay
  legal: rejecting them would help no one and would break real names.
- **Server name/host/user.** These print raw in plan and audit headers, the
  review surface the confirmation prompt depends on. Whitespace and unsafe
  runes are rejected, and errors quote values with `%q` so the error itself
  is inert. Server names with spaces were previously legal and are now
  rejected. Import skips such hosts with a warning, so a quoted ssh alias
  (`Host "web 1"`) cannot make import fail its self-check (§2).
- **One entry per remote file.** Two server entries with the same target
  would race on one file under parallel apply, and once their grants diverge
  they would overwrite each other forever. The target key is host
  (lower-cased), port (default applied), user, and the effective path, with
  unset treated as `~/.ssh/authorized_keys`. Aliases that cannot be detected
  (an IP versus a hostname, an absolute path versus `~/`) are documented as
  a limitation rather than guessed at.
- **Empty grants.** A non-wildcard access entry with `servers: []` or no
  `servers:` key is almost always a mistake (a half-deleted entry), so it is
  now an error.
- **`authorized_keys_file` is a resolved path.** The earlier spec described
  it as mirroring sshd's directive verbatim. But sshd expands `%u`/`%h` and
  SSHepherd does not, so a copied directive would make apply maintain a file
  sshd never reads. `%` is rejected, and so is a trailing `/`, because it
  names a directory. This amends the override spec, whose accept case
  "trailing slash allowed, fails at runtime" is removed.

## 2. import / adopt (`internal/sshcfg`, `internal/identity`, `internal/reconcile`, `internal/adopt`, `internal/naming`)

Shared principle: **match `ssh -G`.** Import's promise is "the host/port/user
ssh would use", so any divergence from OpenSSH is a bug, not a policy. Every
case was checked against OpenSSH 10.x.

- **Include context.** OpenSSH processes an included file inside the
  enclosing block's context and restores that context afterwards. Host blocks
  opened in a file included from a non-matching `Host X` are never applied
  (NEVERMATCH), so import skips them with a warning. Before, it imported
  them, so such configs now yield fewer servers. That is a correctness fix.
- **Trailing `#` comments** end the argument list, as with
  `terminate_on_comment`. Before, `Host a # prod` created hosts named `#` and
  `prod`.
- **HostName tokens.** `%h` and `%%` are expanded. Any other token skips the
  host, because `ssh -G` fails on it too and a guessed expansion would point
  apply at the wrong machine.
- **IdentityFile tokens and `.pub` identities.** Host-dependent tokens
  (`%n %h %r %p`) expand per host. `--operator` has no host, so those tokens
  are an explicit error there. An IdentityFile that already names a `.pub`
  (agent-held keys: 1Password, Secretive, YubiKey) is read directly.
- **Same-target collapse.** This mirrors §1's rule on the generator side, so
  import never emits a manifest its own loader rejects. The first alias in
  config order wins. Grants derived through dropped aliases move onto the
  kept alias rather than being discarded, because it is the same remote file
  and discarding them would silently drop access. Under `--merge`, an
  incoming alias that duplicates a manifest server is redirected to that
  server and counted in `ConflictsSkipped` (manifest wins, as in the
  import-merge spec). Fresh-import collapse warnings go to stderr only and
  are not written into the manifest header, because the machine is still
  represented.
- **Proxy hosts** are still imported, but with a warning. SSHepherd dials
  directly, and silently importing a bastion-only host would turn every audit
  into an unexplained dial error. The dial error itself also carries the
  hint (§4).
- **Unsafe comments.** An adopted key with a tab/control/format comment is
  still adopted, because dropping it would under-represent access. The
  comment is removed and a warning names the fingerprint. A `.pub` with such
  a comment is skipped (it is an error under `--operator`).
- **Naming.** `internal/naming` is the single collision-free allocator.
  `ClaimNumbered` picks the first free `adopted-key-<n>`, so `adopt --merge`
  continues the numbering instead of producing `adopted-key-1-2`. Only a
  trailing `-N` with N≥2 counts as numbering, so `web-1` becomes `web-1-2`.
- **Output files.** The temp file and directory are fsynced so that a
  published manifest survives a crash. `--force` refuses a symlinked path
  rather than replacing a link the user may not know about. Output is always
  mode 0600, and the original mode is not preserved. On filesystems without
  hard links the code falls back to `O_EXCL`. That still never clobbers, but
  it is not atomic for readers, and that is documented.

## 3. Audit (`internal/audit`, `internal/sshread`)

Amends the audit-slice and JSON/exit-code specs.

- **New drift classes, on by default (exit 1).** Options drift (a server
  copy lost `from=`/`command=`), duplicate entries (sshd tries each line, so
  the least restricted copy wins), and a non-empty unmanaged
  `~/.ssh/authorized_keys2` all grant more access than the manifest says.
  Reporting them as compliant would make audit's answer to "who can log in"
  wrong. Comment drift stays cosmetic, as the comment-policy memo decided.
  Options equality is exact slice equality, the same check apply uses to
  decide a rewrite, so audit and apply never disagree.
- **authorized_keys2 probe.** It runs only when the effective path is the
  default, because only then does sshd's compiled-in default
  `AuthorizedKeysFile` also read the second file. It uses a second session on
  the same connection. A failed probe makes the read fail (kind `remote`)
  rather than report "absent", so the check fails closed.
- **Error kinds.** Monitoring needs to tell "host down" from "possible MITM".
  Every transport error carries a kind, and host-key verdicts are captured in
  the callback, so they do not depend on x/crypto preserving the error chain.
  A changed or `@revoked` host key keeps status `unreachable`, because
  nothing about the keys is knowable, but it raises a host-key alert and
  exit 2. That is the same severity as a missing operator key: both mean
  "you may not be talking to, or able to reach, your fleet". JSON stays
  schema 1. `error_kind` and `host_key_alerts` are additive, and
  `error_kind` appears exactly when `error` is non-null.
- **Hints never pipe `ssh-keyscan` into `known_hosts`.** An unauthenticated
  keyscan is exactly the TOFU this tool refuses. Hints ask for out-of-band
  fingerprint verification first.

## 4. Transport (`internal/sshconn`)

- **Cancellation.** `run()` uses `signal.NotifyContext`. `Exec` closes the
  session on `ctx.Done` and `Connect` closes the socket, so Ctrl-C actually
  stops a wedged fan-out. After the first signal the handler is released, so
  a second Ctrl-C kills the process. Interrupted read-only runs exit 3 (tool
  error). Exit 130 was rejected so the four-code contract stays closed.
  Commands check `ctx.Err()` after the fan-out, not only before it: a server
  the interrupt cut short comes back as a read error, and rendering it as
  "unreachable" would turn Ctrl-C into exit 1/2 (audit) or, under
  `adopt --partial`, a manifest written without that server's access. So an
  interrupted audit renders no report, adopt writes nothing, and `apply`
  interrupted during planning or at the `[y/N]` prompt writes nothing — all
  exit 3. The prompt reads stdin in a goroutine and selects on `ctx.Done`,
  so the first Ctrl-C is not swallowed while the read blocks.
- **`exec /bin/sh -c '…'`.** The remote login shell parses the command
  string. fish treats `\` inside single quotes as an escape, and csh/tcsh
  differ again, so every script is wrapped for `/bin/sh` with `'` and `\`
  written outside the quotes. Multi-line scripts are refused, because csh
  cannot carry a newline inside a quoted argument. Accepted cost: accounts
  that cannot run `/bin/sh` by path — `rbash`, or a `ForceCommand`/`command=`
  wrapper that allows only specific commands — could previously be audited
  (the read script ran directly) and now cannot. Supporting fish/csh/tcsh
  login shells was judged the more common need; the README states the
  limitation.
- **Host-key algorithm order from `known_hosts`.** x/crypto's default order
  can negotiate a key type that is not pinned (ECDSA served, ed25519 pinned),
  which fails strict checking for no reason. With a sshd `HostCertificate`,
  the default order also negotiates the certificate algorithm, which fails
  when no `@cert-authority` line exists. The algorithms for the pinned types
  come first, and certificate algorithms are offered only when a matching CA
  line exists.
- **Preferred agent keys.** sshd's `MaxAuthTries` (default 6) locks out
  many-key agents before the right key is tried. Granted keys, operators
  first, are offered first. `ConnectOptions.Only` offers exactly a given set
  with no fallback, which is the primitive behind apply's login probe (§5).
- **`known_hosts` parsed once** per run and shared read-only across the
  fan-out. This is cheaper, and it gives every server in a run the same
  trust snapshot.
- **`sshtest`.** An in-process SSH server and agent make host-key, auth,
  stall and cancel paths testable without Docker, so they are covered in
  `make check`, not only in `make integration`.

## 5. Write path (`internal/sshwrite`, `internal/apply`)

Amends the apply-slice spec's write protocol. The original design ran a
precheck session, a write session and a verify session. Between them lay
time-of-check/time-of-use gaps, a lost-update window across the
confirmation prompt, and no proof that access survived. The redesign closes
each of those gaps.

- **One guarded script per server.** The symlink, ownership, lock,
  compare-and-swap, backup, upload, length check and `mv` steps all run in
  one remote script under one lock, so nothing can change between check and
  use. Exit sentinels 45–49 map to typed errors.
- **Compare-and-swap against the plan.** The plan stores the phase-1
  snapshot: absent, or byte length plus POSIX `cksum`. The write refuses if
  the file changed, so a long wait at the prompt can no longer silently
  destroy edits someone else made: *what you reviewed is what gets
  replaced.* `cksum` was chosen over `sha256sum` because it is POSIX
  (present in busybox and BSD). The threat model is concurrent honest edits,
  not an attacker who already controls the file.
- **Per-file lock** via `mkdir <path>.sshepherd.lock`. That is atomic on
  every POSIX filesystem, and an EXIT trap removes the lock (signals route
  through `exit`). A lock left by a SIGKILLed shell is removed by hand. The
  refusal names it, because auto-breaking it would reintroduce the race.
  When `mkdir` fails for a reason other than an existing lock, it is re-run
  to surface the error; that re-run happens before the trap exists, so if it
  succeeds (the holder released the lock in between) the script removes the
  directory and exits 47 — a retryable lost race, never a stale lock.
- **Length check before `mv`.** A dropped connection closes stdin, and
  `cat > tmp && mv` would then install a truncated file. The script counts
  the bytes it received against a Go-built literal, so failure leaves the
  original untouched.
- **Unsafe paths.** A symlinked parent directory, or a file or directory not
  owned by `id -u`, is refused. Writing there could follow links someone
  else controls. Managing another user's file as root is therefore refused,
  and the fix is to log in as the owner. Checking only the parent left a gap:
  a symlink further up (root managing `/home/alice/sub/.ssh/...` with
  `sub` swapped for a link to `/root`) resolves to root-owned directories
  that pass. So every ancestor up to the login user's home (or `/` outside
  it) is walked twice, as sshd's `StrictModes` does: as written, where each
  component — a symlink judged by its own owner — must belong to the login
  user or root, and resolved (`cd -P`), where each directory must also not
  be group/other-writable. The restore and `authorized_keys2` scripts run
  the same walk. All exit 48.
- **Backups: `.bak` + `.orig`.** `.bak` holds the previous version, as
  before. `.orig` is written once, the first time an unmanaged file is
  replaced. Without it, the second apply would overwrite the only copy of the
  pre-SSHepherd file. Both are created with `rm -f` followed by a noclobber
  write, so a planted symlink is never written through.
- **Post-write login probe and restore.** After write and verify, a fresh
  connection offers *only* the surviving agent keys — unrestricted ones
  first, since sshd authenticates with the first acceptable key — and runs
  `echo sshepherd-probe-ok` over it, requiring exactly that output. Every
  write is probed, not just writes that remove the session key. `from=` fails
  the handshake, and a forced `command=` replaces the probe command, so its
  output does not match; a handshake alone would pass a key whose line now
  forces a command, and every later SSHepherd run would execute it. sshd
  rejecting the surviving key's algorithm fails too. Any probe failure
  restores the previous file over the still-open session. That holds for
  network failures too: if access cannot be proven, the server goes back to
  its previous file. The outcome is FAILED, exit 1. The write's lock ends
  with the write script, so the restore takes the lock afresh and
  compare-and-swaps against the bytes this apply wrote (exit 46 otherwise):
  a concurrent apply that wrote in between is never blindly replaced by
  `.bak`. A refused restore is reported as a restore failure, untyped, so a
  LockoutError never reads as a "nothing changed" refusal.
- **`authorized_keys2` is disabled, not just reported.** Detection alone
  (§3) left the revoke hole open: a key in `~/.ssh/authorized_keys2` keeps
  logging in after the manifest revokes it. When phase 1 found the file
  non-empty (default path only), the plan is a change even if
  `authorized_keys` already matches, shows a `disable` row, and the write
  moves the file to `authorized_keys2.sshepherd.disabled` after verify and
  *before* the probe, so the probe proves the survivors log in without it
  (a survivor could otherwise pass through a laxer copy in the second file).
  `mv` renames a symlink rather than following it. Disabling cannot lock
  anyone out — the file only adds keys — so a failed move still lets the
  probe run and is then reported FAILED with `authorized_keys` written. A
  failed probe moves the file back unless it was recreated meanwhile. A
  server apply does not write (refused, no grants) keeps a hand-removal
  warning. Other `AuthorizedKeysFile` layouts (custom lists,
  `AuthorizedKeysCommand`) are not detected: reading `sshd -T` needs root,
  so the README tells operators to point `authorized_keys_file` at the file
  sshd reads.
- **Guard refinements.** `cert-authority` and `principals=` lines accept
  certificates, not the bare key, so they never count as survivors. The
  guard re-runs after the prompt against a fresh agent listing, because
  agent keys can expire (`ssh-add -t`) while the prompt waits. The old
  "additive writes may proceed with an empty agent" fallback is removed: with
  no agent keys, nothing could be probed.
- **Option loosening is highlighted, not refused.** Dropping `from=` or
  `command=` is sometimes exactly the intent. A refusal flag would be
  ceremony, and a red row plus a warning line at the confirmation point is
  enough.
- **Size cap.** A rendered file larger than the read path's 1 MiB cap could
  never be verified or audited, so it is refused at plan time.
- **Duplicates in normalize** are counted and called out, especially when
  the copies differ in options, because removing a less restricted duplicate
  changes access.
- **Interruption.** New servers stop on Ctrl-C. A server whose connect
  already succeeded finishes write, verify and probe under
  `context.WithoutCancel`, bounded by a 2-minute session-budget deadline.
  Stopping mid-stream is exactly the truncation hazard the length check
  guards against, and stopping before the probe would skip the lockout
  check. The summary always renders, and unstarted servers show
  `NOT STARTED`.

## 6. Tooling, CI, container

- Every dev tool and every CI action is pinned to an exact version (actions
  by commit SHA, base images by digest). Each pin is a release at least about
  two weeks old, as a supply-chain precaution. `make lint` refuses a
  golangci-lint built by a different Go, because a mismatched build silently
  type-checks against the wrong standard library.
- `make check` ends in `coverage`, so the 80% gate is local as well as CI.
  `tidy` uses `go mod tidy -diff`: a gate must report problems, not repair
  them.
- A daily scheduled job runs `govulncheck` and all fuzz targets, including
  the new `FuzzLoad`, and uploads any new crashers. Dependabot is weekly.
- `.dockerignore` is an allowlist, so tests, testdata and local files never
  reach the builder.
- Image gates (`scripts/docker-gates.sh`) measure the unpacked rootfs for the
  size budget, because `docker image inspect .Size` differs between the
  containerd and classic image stores. Releases are multi-arch with an SBOM
  and provenance, and are signed keyless with cosign.
- Lint bans `ssh.InsecureIgnoreHostKey`/`FixedHostKey` (forbidigo), and
  bans `os/exec` and `math/rand` outside tests (depguard). This turns the
  no-TOFU and no-host-ssh decisions into checks.

## 7. Verification follow-up

An independent verifier re-checked the pass. Its partial fixes and
regressions are resolved in the sections above: the `authorized_keys2`
disable (§5), the full ancestor walk (§5), interrupt handling after the
fan-out and at the prompt (§4), the lock-prologue race and the restore
compare-and-swap (§5), and the probe command (§5). Two behavior changes are
intended and stay, documented in the README: root can no longer manage
another user's `authorized_keys_file` (exit 48), and manifests from older
`import` runs that emitted one server per alias of a `Host a a.example.com`
line now fail the one-entry-per-file rule (exit 3) until merged.
