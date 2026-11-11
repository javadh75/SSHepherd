# Review wave 1: security and data loss

Source: `docs/superpowers/reviews/2026-11-10-full-review.md` (each finding's evidence, repro and fix
direction) and the owner answers in `docs/superpowers/reviews/2026-11-10-owner-answers.md`.
Base: master after this plan's commit. Go 1.27.3 (`GOTOOLCHAIN=go1.27.3` for every go/make command).

Every fix is TDD: write the test, run it and see FAIL, fix, see PASS. A bug fix ships with the test
that fails before it. No JSON field is removed or renamed (schema 1, additive only). Exit codes
follow D28. README and CLAUDE.md Status change in the same commit as the code, with sample output
copied from goldens or real output (lanes hand the text to the integrator as `docsDelta`).

## Answers recorded (owner, 2026-11-11; final)

- **F001 = (a).** A host certificate refused because its CA or the key inside it is `@revoked` is
  `host_key_revoked` (exit 2 where a plain `@revoked` key is), with the `@revoked` hint.
- **F007 = (a).** The bastion forwarding guard judges the first surviving key in `OfferOrder` (the
  key the hop logs in with) and refuses when that key cannot forward to every dependent. The
  post-write forward probe covers every dependent, not `deps[0]`. `OfferOrder` (D31) is unchanged.
- **F010 = (c).** A first-contact write (snapshot absent) removes a stale `.sshepherd.bak` with the
  same `rm -f "$b" || exit 1` step the normal branch uses, after the absent check (a refused write
  still changes nothing). The lockout and unknown-state messages for that case say there was no
  previous file and the undo is deleting it. README's backup rule then holds without exception.
- **G016 = (a).** Explain and test, no fan-out change: a handshake that ends before the server's
  version banner gets a hint naming sshd `PerSourcePenalties` (look for `drop connection ...
  penalty` in the server log; fix the failing account or add the admin address to
  `PerSourcePenaltyExemptList`); README connection-posture section; one integration sshd keeps the
  distro's default penalties and pins how audit and the post-write login check classify a drop.

## Lanes and rounds

| Round | Lane | Owns (shell globs) | Findings |
|---|---|---|---|
| 1 | `parser` | `internal/authkeys/**` `internal/config/**` `internal/adopt/**` `internal/audit/**` | F002, F003, F025, F008, F009 |
| 1 | `transport` | `internal/sshconn/**` `internal/sshread/**` `scripts/integration.sh` `ci/images/sshd-*.Dockerfile` `cmd/sshepherd/penalty_e2e_test.go` | F001, F011, F012, G016 (+ export the route helper G017 needs) |
| 1 | `editor` | `internal/manifest/**` `internal/keyfile/**` `cmd/sshepherd/keyarg*.go` | G001, G020, G009 |
| 2 | `write` | `internal/sshwrite/**` `internal/sshconn/posture*.go` `internal/fleet/**` | F004 (sshwrite side), F010, F014, G017, G018 |
| 2 | `grammar` | `cmd/sshepherd/sshd_grammar_e2e_test.go` | real-sshd ground truth for F002, F003, F025 |
| 3 | `apply` | `internal/apply/**` `internal/workflow/**` `internal/fleet/**` `internal/sshwrite/**` | F007, F004 (apply side) |

`transport` does not touch `internal/sshconn/posture*.go` (round 2 `write` owns it). A lane that needs a
change outside its globs lists it in `foreignBreaks`; the integrator makes it as a merge fix.
Merge order inside a round: parser > transport > editor; write > grammar; apply.

## Lane `parser` (round 1)

- **F002.** Read each authorized_keys line the way sshd does before x/crypto parses it: cut at the
  first NUL (sshd's C string ends there), and drop whitespace bytes inside the base64 key field
  (b64_pton skips them). A line sshd honors must yield its key, so the revoked, unknown, operator
  and protected checks run on it. Pin: unit rows for NUL after the blob, and VT, FF and CR inside
  the blob; an audit test where a re-planted revoked key in such a line is REVOKED (exit 2). A line
  sshd would not honor stays an unparseable entry.
- **F003.** Value validators in the option table (`options.go`), matching sshd's auth-options.c:
  `permitopen` `host:port` or `host:*`; `permitlisten` `[host:]port` or `*`; `environment`
  `NAME=value` with a valid name; `tunnel` a number or `any`; a NUL inside a quoted value is
  rejected (sshd's C string ends there). `CheckOption` (manifest load: key lines and grant
  `options:`) refuses a bad value (load error, exit 3); `IgnoredBySSHD` agrees, so audit no longer
  calls a dead line authorized. Unit rows for each.
- **F025.** Add `touch-required` (restricts) and `no-verify-required` (neutral) to the table.
- **F008.** Invalid UTF-8 counts as unsafe wherever `IsUnsafeRune` guards text
  (`utf8.ValidString`, as clog does): `RenderTextIssue`, `CheckOption`, `config.ServerFieldIssue`,
  `authorized_keys_file` validation. adopt reports such a remote line as an issue instead of adopting
  it; a manifest string field holding invalid UTF-8 (a `!!binary` scalar) is a load error.
  audit's `ServerHead` never prints raw bytes it did not check.
- **F009.** A small Go model of sshd's line acceptance (C-string cut, space/tab field split, base64
  whitespace skipping, option grammar with the F003 value rules) used as the oracle of
  `FuzzParseLine` and `FuzzCheckOption` (they must agree with the model), seeded with the F002,
  F003 and F025 lines. Keep each corpus within 16 entries of at most 4 KiB.
- Export the model's verdict (for example `authkeys.SSHDAccepts(line) bool`) so lane `grammar` can
  compare it with real sshd. If no caller exists outside tests, keep it unexported and tell lane
  `grammar` in docsDelta which test-visible name to use (deadcode fails on an unused export).

## Lane `transport` (round 1)

- **F001 (owner a).** In `hostKeyHint` (`internal/sshconn/hostkey.go`), recognise a certificate
  rejected because its key or its signing CA is `@revoked`: compare the presented cert's `Key` and
  `SignatureKey` against the snapshot's `@revoked` keys (never match x/crypto's error text) and
  classify `host_key_revoked` with the `@revoked` hint. Rows in `TestConnectHostKeyFailures`:
  revoked CA, revoked host key inside a cert, control plain revoked key.
- **F011.** Ctrl-C ends an in-flight read on a peer that stopped answering: on the read path tie the
  whole connection to ctx (a watcher that closes the client and its hop until the read returns);
  keep the write path's detached ctx as it is. Test with a silent peer (sshtest or a proxy that
  stops forwarding): cancel returns within a second, kind `canceled`, goleak clean.
- **F012.** A forward failure after ctx's deadline is a `timeout` (`ctx.Err() != nil ||
  pastDeadline(ctx)`, as `handshakeKind` does) in `forwardFailure`. Deterministic test with a forward
  that never answers; run it `-race -count=50`.
- **G016 (owner a).** A handshake that ends before the server's version banner gets the
  PerSourcePenalties hint (wording in Answers). One integration sshd keeps the distro default
  `PerSourcePenalties` (a fourth container, or a second sshd on A; your choice, documented in the
  script header), with accounts that fail auth and healthy ones; `cmd/sshepherd/penalty_e2e_test.go`
  (name `TestE2EPerSourcePenalties`) pins that audit reports the healthy accounts' drop with the
  hint (exit 1). Keep `PerSourcePenalties no` on A, B and C (the other tests fail logins on purpose).
- **G017 support.** Export the route-command builder behind `keyscanCompareCmd` (the `-J` form and
  the `on bastion "NAME":` fallback) so lane `write` can build the lock-removal command through
  the same route. Give it a caller in this lane (keyscanCompareCmd itself) so deadcode stays green.

## Lane `editor` (round 1)

- **G001.** `checkNodeShapes` (`internal/manifest/manifest.go`) refuses any mapping key tagged
  `!!merge` or spelled `<<` with `UnsupportedError`, as it refuses anchors and aliases. Rows: inline
  merge key on an access entry, on a user, on a server; the `revoke --from-server` repro from the
  report is refused (exit 3, nothing saved). Add a merge-key seed to `FuzzManifestEdit` and
  `FuzzRemoveAccess`.
- **G020.** In `keyarg.go`, a key line is recognised before the fingerprint step: step 2 applies
  only to an argument that does not start with a key type or an option, or only to the
  `ssh-keygen -l` shape (`^\d+ SHA256:\S+ .* \([A-Z0-9-]+\)$`). Classification row for a key line
  whose comment holds ` SHA256:<other fp>`; extend `FuzzKeyArg`'s oracle: a parseable key line
  classifies as its own fingerprint.
- **G009.** While the passphrase prompt is up (`internal/keyfile/tty_unix.go`), handle job control
  like readpassphrase(3): on SIGTSTP/SIGTTIN/SIGTTOU restore the saved termios, reset the handler
  and re-raise the signal; on SIGCONT re-apply echo-off and rewrite the prompt. Pty test: stop and
  continue the prompter and assert ECHO is off when the read resumes (skip cleanly where no pty).

## Lane `write` (round 2)

- **F010 (owner c).** `casBackupBlock` for an absent snapshot: after the absent check, `rm -f "$b"
  || exit 1` (a directory planted at `.bak` still exits 1). Messages: `unknownStateError` and the
  `LockoutError` text (`internal/fleet/write.go`) for a first-contact write say there was no
  previous file and the undo is deleting it, never point at `.bak`. Real-sh rows (sh, dash,
  bash --posix, busybox where present): old `.bak` planted then a create removes it; a refused
  create leaves it. Update `TestWriteScriptsUnchanged`'s golden and the `ownerMutants`-style tables
  if the script text changes; never delete those tests.
- **F004.** A `disableKeys2` outcome whose move may have happened (a transport error after the
  session opened, or an unparseable reply) is an unknown keys2 state. On a REJECTED login check,
  recover the copy's name by listing `authorized_keys2.sshepherd.disabled*` over the restore
  session and move it back; if that is not possible, report it as an unrestored keys2 move-back
  (`LockoutError.RestoreKeys2` non-nil, so `lockout_unrestored`, exit 2). Never report "lockout
  prevented" while keys2's state is unknown. `restoreKeys2Cmd` fails when the expected copy is
  missing instead of exiting 0. Seam tests for a lost reply.
- **F014.** Real-sh behavior rows for refusals pinned today only by the script golden: symlinked
  `.bak` at restore (45, victim untouched), directory at `.bak` (exit 1, target untouched), symlink
  planted at the temp name (victim untouched), a size-only CAS mismatch via a stubbed `cksum`.
- **G017.** `lockRemoveCmd` routes through the server's bastions with the route builder lane
  `transport` exported; a `TestLockRemoveCmd` row for a `via:` server and for a hop that is not a
  plain word. If the chain must be passed from cmd, list the call site in foreignBreaks.
- **G018.** The StrictModes walks (`posture.go` and the shared `ancestorCheck`) never take a path
  from a bare `$(...)`: use a sentinel (`q=$(cd -P "$d" && pwd -P && echo .); q=${q%??}`, same for
  `dirname`) or fail closed when a resolved path holds a newline. Rows in the posture and owner
  matrices for a directory whose name ends in a newline: world-writable is still critical (audit
  exit 2), the write refuses (48).

## Lane `grammar` (round 2)

`cmd/sshepherd/sshd_grammar_e2e_test.go`, `TestE2ESSHDGrammar`: for each line in one table (the F002
NUL/VT/FF/CR lines, the F003 bad and good option values, `touch-required` and
`no-verify-required`), install it as the only line for a fixture account on the integration sshd,
try a real login, and assert the result equals lane `parser`'s model verdict. Use an existing
fixture account whose file the test may rewrite, or ask the integrator (foreignBreaks) for one in
`scripts/integration.sh`; restore the account's file at the end. Runs on alpine, debian and rocky.

## Lane `apply` (round 3)

- **F007 (owner a).** `forwardRefusal` judges the first surviving key in `OfferOrder` for the
  bastion: refuse when it cannot forward to every dependent (`authkeys.Forwards` plus
  `permitopen=` coverage of each dependent's host:port). The post-write forward probe covers every
  dependent (`ServerPlan.ProbeForward` and `fleet.WriteRequest.ProbeForward` become a list; the
  JSON shape does not change, it has no field for it). Rows: the report's repro (key 1
  `permitopen` to web-1 only, key 2 plain, key 1 first) is refused; a first key that forwards to
  both passes; the probe checks web-2.
- **F004 (apply side).** `failureOutcome` maps the unknown keys2 state from lane `write` to
  `lockout_unrestored` exit 2, never "lockout prevented". Exit-code test through `workflow`.

## Verification (per lane, after integration)

Three verifier lenses per code lane (lane `grammar` gets one): failure scenario (rebuild each
finding's repro from the review and show it no longer reproduces), safety and scope (write-path
contracts, refusal guarantees, exit codes, JSON additivity, on-hold boundaries), and tests by
mutation: a mutate/restore script (restore with `git checkout -- FILE` in a trap) over every
changed production line, at least these targets:
- parser: each new value validator, the NUL cut, the base64 whitespace skip, the invalid-UTF-8 check;
- transport: the revoked-cert match, the read-path ctx watcher, `pastDeadline` in forwardFailure,
  the pre-banner hint condition;
- editor: the merge-key refusal, keyarg's step order, the SIGCONT echo re-apply;
- write: the absent-branch `rm -f "$b"`, the keys2 unknown-state branch, the sentinel strip, the
  lock-removal route;
- apply: the first-key choice, the every-dependent loop, the unknown-keys2 exit 2.
The mutation run finishes before the verifier reports; survivors are problems.

## Docs

README: connection posture (G016 hint, PerSourcePenalties), the `.bak` rule (F010), the exit table
row for a revoked host CA or cert (F001), option values the manifest refuses (F003, F025),
`touch-required`/`no-verify-required`, merge keys refused (G001). CLAUDE.md Status: one paragraph
"Review wave 1" naming the findings fixed and the tests that pin them. `--help` goldens change only
if a help text changes.

## Out of scope

The other waves' findings; anything on hold (prune, apply --force, import --prefer, key generation,
scheduled rotation, move-key, wipe mode); Go 1.27.4; x/crypto v0.59.0; any release tag.
