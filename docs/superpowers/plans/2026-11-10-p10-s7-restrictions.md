# Optional per-grant restrictions (P10 S7, D22 = B, OP5, OP6, PRD-6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step, not a commit.

**Commits at:** `docs/superpowers/plans/2026-11-10-p10-s7-restrictions.md` (exactly this path; the runner commits it before round 1).

**Main-session decisions recorded 2026-11-10:** the four items under "Needs an owner decision" are accepted as technical: amendment 3 (one conflict per user and server, the first disagreeing pair), the apply/revoke/rotate `--help` footer wording of gap 13 / amendment 7, gap 14's rule (no release tag may point at the `grants` or `audit` lane commits; only the final S7 commit is releasable), and amendments 8 and 10. S7 runs after F1 (`2026-11-10-p10-f1-owner-followups.md`) has landed: re-read `warnMemoryLost`'s neighbourhood, `Normalize`, `planWrite` and `sshconn.Exec` by name before editing.

**Goal:** Build slice S7 of the approved access-model design (`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, section "S7. Optional per-grant restrictions (D22 = B; PRD-6)", plus its Shared rules and the S7 row of "Order and parallel lanes"): an optional `options:` list on an `access:` entry whose restricting options are appended to the key line on the servers that entry grants, so one key can carry different restrictions on different servers. A grant only narrows (OP5). Two grants that give one key different restrictions on one server are a D29 policy conflict of kind `restriction_conflict` (OP6): audit is critical (exit 2) and skips the options comparison for those keys there, apply refuses only those servers (exit 1), validate exits 3, adopt and `import --merge` refuse a save that would add a clash, and revoke and rotate still save.

**Architecture:** `internal/authkeys/options.go` stays the one source of option meaning: it gains `IsRestriction` (read from the table: `restricts` and not `certOnly`) and `SameOptions` (set equality, names case-insensitive). `internal/config` gains `Access.Options`, its load-time validation (`grantOptionErrors`), the per-pair grant sources (`grantSources`: a fleet-wide operator's implicit grant first, then access entries in order, none for a blocked pair or a `jump_only` server), per-server key copies in `DesiredFor` (`keysOn`: key-line options, then the first source's), the `restriction_conflict` kind in `computeConflicts` (`restrictionConflicts`), the grant half of P09's passed-expiry warning, and `ClashedKeys`. Everything downstream already reads `DesiredFor`: audit's diff, `apply.Affected`, `Survivors`, `authkeys.OfferOrder` (read, write and probe offers), the `Loosens`/`Widens` highlight, the guard's restrictive-options warning and S5's forwarding guard. `internal/audit` skips the options comparison for `ServerResult.Clashed`. `internal/apply` refuses a clashed server with a save-neutral `ServerPlan.ClashRefused`, so revoke and rotate still save (OP6). `cmd/sshepherd/conflicts.go` splits into `editConflictRefusal` (revoke, rotate: never refuses a clash) and `conflictRefusal` (adopt, `import --merge`: refuses an added clash).

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), `gopkg.in/yaml.v3`, the hermetic `internal/sshconn/sshtest` server (`ServerConfig.AuthorizedKeysFile` honours `command=` and `from=` per login), goleak, golden files (`-update`), native fuzzing (`FuzzLoad` gains an in-code seed and the `checkGrantOptions` oracle; its committed corpus is already at 16), golangci-lint (depguard `domain`, gocyclo 15, revive, dupl), `deadcode ./cmd/sshepherd`, `make layering`, the dockerized sshd matrix (`make integration`, alpine/debian/rocky).

**Base:** `master` at `065c1d3` or later (S6, its repair `09c8891` and the test-only follow-up `065c1d3`). S7 does **not** depend on the owner follow-up F1 (planned to commit at `docs/superpowers/plans/2026-11-10-p10-f1-owner-followups.md`; not on master at `065c1d3`), which touches `cmd/sshepherd/import.go` (`warnMemoryLost`), `internal/apply/{plan,report,json}.go` (a `Normalize.ExternalSection` row: the `Normalize` struct, `normalize`, `nonKeyLines` and their report/JSON renderers) and `internal/sshconn/connect.go` (`Exec`'s session-open guard). **Runner precondition:** before round 1, run `git log --oneline -1 -- docs/superpowers/plans/2026-11-10-p10-f1-owner-followups.md`; if F1's plan is committed but its lanes have not all landed, finish F1 first. Never interleave F1's and S7's rounds (both edit `internal/apply/plan.go`). If F1 has not started, S7 may run first; nothing below changes. Every `file:line` below was read at `09c8891` (identical to `065c1d3` outside `internal/audit/preserve_test.go`); F1 may move lines in `internal/apply/plan.go`, so **every lane re-reads each named function before editing it** and anchors on the name. S7 never edits `import.go`, `internal/apply/{report,json}.go`, `internal/sshconn`, `Normalize`, `normalize` or `nonKeyLines`; its only `plan.go` edits are the `ServerPlan` field after `WeakRefused` and three lines in `planOne`. S1, S2, S8, S3a, S3b, S4, S5 and S6 have landed; P08 and P09 have landed, and their landed code wins over the design's older wording (the design's "whichever of S7 and P09-impl lands second adds that" means S7 adds the grant half of `warnExpired`).

**D28 for this slice.** No new exit-2 input: a restriction clash is a policy conflict, and audit already exits 2 on any (`audit.ExitCode`, `internal/audit/report.go:30`). New exit-3 inputs are load errors (a bad or widening grant option, a name already on a reached key line) on every command, validate's finding (it already exits 3 on any conflict, `validateExit`, `cmd/sshepherd/validate.go`) and the save rule's added clash (adopt, `import --merge`). Apply exits 1 for a clashed server (refused). JSON stays schema 1: the only new wire value is the `kind` string `restriction_conflict` inside the existing `policy_conflicts` array (no `fingerprint`), consumers ignore kinds they do not know, and every existing golden stays byte-identical.

**Compile status.** The steps that wrote and revised this plan could write only this plan file, so no Go block below was compiled or run (the revision's new blocks included). Every block was checked by reading against `09c8891`: every helper it calls exists there with the signature used (`authkeys.lookup`, `FindOption`, `CertOnly`, `CheckOption`, `OptionIssue`, `Expired`, `EarliestExpiry`, `OfferOrder`, `PreserveMarker`; `config.entryApplies`, `entryCovers`, `entryUsers`, `fleetWide`, `blocked`, `grantPair`, `ServerNamed`, `warn`, `now`; config tests' `mustParse`, `pinNow`, `fpOfLine`; audit tests' `fakeReader`, `content`, `renderJSON`, `checkGolden`; apply tests' `fakeReader`, `buildPlans`, `agentHeld`, `fp`, `planFor`, `bastionPlans`, `planNamed`, `renderFleet`, `renderedFor`, `checkGolden`; manifest tests' `loadFixture`, `encodeParsed`, `inOrder`; cmd tests' `run`, `writeConfig`, `writeSSHConfig`, `hermeticHome`, `hermeticFleet`, `shortHome`, `editFleet`, `editHost.install`, `editHost.line`, `qk`, `readCfg`, `fileBytes`, `fpOf`, `parseManifest`, `validateCLI`, `roundTripConfig`, `generateAdoptManifest`; the E2E helpers `itE2E`, `itKeys`, `itPubLine`, `runBin`, `writeE2EManifest`, `e2eRemoteCat`). A lane that finds a build error fixes it to the text's intent and says so in its hand-back.

---

## Design gaps and contradictions (for the main session)

No item overrides an answered decision (D22 = B, OP5 and OP6 are final). Item 1 is a real contradiction inside the design; the plan resolves it in the direction OP6 states. The main session can veto any item; Task 16 Step 2 records the ones that change design text.

1. **"`apply`'s refusal already reads `Conflict.Servers`, so it needs no code" contradicts OP6's "revoke and rotate still save".** `planOne` (`internal/apply/plan.go:249`) would refuse a clashed server through `conflictRefusal` (`internal/apply/serial.go:139`, every kind but `weak_key`), but that refusal is not save-neutral: revoke's and rotate's `question` callback (`runEdit`, `cmd/sshepherd/editrun.go:321`) withholds the save when `apply.NothingCanLand` (`internal/apply/predicates.go:27`) finds every affected server refused, and only `WeakRefused` is exempt today. A leaver whose only server carries a clash would get `nothing saved` (exit 1), which is what OP6 forbids ("revoke and rotate still save"), with the design's Risks bullet "A restriction clash holds up every write on its servers, other users' revocations included, until it is fixed. Audit shows it as critical, and `revoke` still saves" and D28's row "`revoke` and `rotate` still save, and their apply phase exits as `apply` does". The plan adds `ServerPlan.ClashRefused`, set by a separate `restrictionRefusal` check in `planOne`, and `NothingCanLand` skips it exactly as it skips `WeakRefused` (P09 plan decision 6's mechanism). `conflictRefusal` in apply stops matching the new kind. Unlike a weak-key refusal there is no removal-only exception: the Risks bullet holds the server for "other users' revocations included".
2. **`conflictRefusal` already has the manifest the command started from.** The design says it "gains" it; P09 added `former` (`cmd/sshepherd/conflicts.go:19`). The plan splits it instead: `editConflictRefusal(former, saved)` is today's body minus the restriction kind and is what `editPrelude` (`cmd/sshepherd/editrun.go:426`, call at `:430`) calls; `conflictRefusal` is `editConflictRefusal` followed by the added-clash rule, and stays what `(*adoptRun).run` (`cmd/sshepherd/adopt.go:276`, call at `:315`) and `(*importRun).run` (`cmd/sshepherd/import.go:396`, call at `:450`) call. So `adopt.go` and `import.go` need **no code**, which the design's Files list names; this also keeps S7 off F1's `import.go`.
3. **The implicit operator grant is the first grant source.** The design names clashes "first two in access order" and renders a clashed pair "with the options of the first `access:` entry reaching it"; neither rule places a fleet-wide operator's implicit grant, which is no `access:` entry. The plan puts it first (`implicitGrant = -1`) for both: the message reads `granted by its operator grant with no options and by access[N] with [...]`, and a clashed operator key renders with no grant options. It is the operator's base grant, its key is written first and offered first (an unrestricted key keeps reads working on a clashed server), and nothing writes a clashed server either way.
4. **One conflict per user and pair of grant sources; a server sits in one conflict per user.** "One conflict per pair" is read as a pair of sources (entry indices, the implicit grant counted as one), not only of `access:` entries. The design's "`Servers` lists every server where those two entries disagree" and "with three different sets on a server, the first two in access order are named" pull apart when three sets meet: the plan names, per server, only the first disagreeing pair, so `Servers` lists, in `servers:` order, every server where that pair is **the first** disagreement. Example: e0 = A on web-1 and web-2, e1 = B on web-1, e2 = C on web-1 and web-2 gives (e0, e1) = [web-1] and (e0, e2) = [web-2], although e0 and e2 also disagree on web-1. This is a narrowing of the design's sentence, recorded in amendment 3 and pinned by `TestRestrictionConflict/a pair is named only where it is the first disagreement`. Every clashed server is still in exactly one conflict of that user, so `ClashedKeys` and apply's refusal cover it. Two different pairs give two conflicts, users in `users:` order, pairs in the order their first server appears.
5. **A user with no keys never clashes.** "For each key on each server" has nothing to compare for a keyless (protected) user, so `restrictionConflicts` skips it; a conflict for it would hold servers for no key.
6. **Same-set grants render the first source's spelling.** `[NO-PTY]` and `[no-pty]` are one set, so they union; the rendered line uses the first source's text verbatim. Sets drop repeats (`[no-pty, no-pty]` equals `[no-pty]`); values compare exactly (`from="A"` differs from `from="a"`).
7. **Conflict order.** `computeConflicts` appends the restriction kind last (after `weak_key`), so every existing `policy_conflicts` array keeps its order.
8. **The combined-line `OptionIssue` check cannot fire.** The design runs `authkeys.OptionIssue` on the key line plus the grant "as a last check". After each option passed `CheckOption`, the grant passed `OptionIssue` and no grant name is on the key line, no repeated once-only clause can exist, so the check is defense in depth: kept, and its mutant is recorded as equivalent (Task 6).
9. **The grant half of P09's expiry warning is one warning per entry.** `warnExpired` (`internal/config/policy.go:67`) gains `access[N]: expiry-time="20200101" has passed; sshd no longer accepts the keys this entry grants` (kind `key_expired`). Audit's `EXPIRED` note, `key_issues: ["expired"]` and the protected `cannot_log_in: expired` already read the desired options, so they see a grant's `expiry-time=` with no code.
10. **Validation wordings** (the design gives none): `access[N]: option "X" <CheckOption issue>`; `access[N]: option "X" does not restrict access; a grant can only add restrictions`; `access[N]: option "X" makes the key accept certificates only; a grant cannot turn a key into a certificate authority`; `access[N]: option "X" repeats from=, which sshd allows once per line` (OptionIssue's own text); `access[N]: option "X": user "U" key K already carries "Y"; restrict a key on its key line or on its grants, not both`. `N` is the 0-based `access:` index, as in `tombstone_blocks_grant` and the clash message.
11. **No new JSON field for the skipped comparison.** The design asks for no drift on clashed keys "in text, JSON and Compliant", which `optionsDrift` gives; the conflict itself is in `policy_conflicts` and the server's `critical_reasons` already carries `policy_conflict`.
12. **The lockout guard needs no change.** A grant can add neither `cert-authority` nor `principals=`, so a grant never turns a held key into a non-survivor (`Survivors`, `internal/apply/plan.go:749`). The guard's "every remaining key you hold carries a restrictive option" warning, S5's `forwardRefusal` (`:645`) and the post-write probe's `OfferOrder` all read the combined options; a grant `from=` that excludes the operator's address is caught by the post-write login check (REJECTED, restored), as a key-line `from=` is today. Tests pin each (Task 10, Task 12).
13. **`--help` footers name the kinds.** Today's "a manifest that would keep a policy conflict" (`exitCodesWrite`, `exitCodesAdopt`, `exitCodesImport`, `cmd/sshepherd/run.go:215-249`) would say a *kept* restriction conflict exits 3, which OP6 and `addedClashes` contradict (a kept clash saves). All three footers now name the kinds that refuse while they remain: `exitCodesWrite` (apply, revoke, rotate) "a manifest that would keep a revoked-key or revoked-access conflict or add a weak key"; `exitCodesAdopt` and `exitCodesImport` "… would keep a revoked-key or revoked-access conflict, or add a weak key or a restriction conflict". Five help goldens change (`apply`, `revoke`, `rotate`, `adopt`, `import`), and README's three footer blocks and its four "would keep a policy conflict" sentences follow (Task 12 Step 1, Task 13 docsDelta).
14. **The intermediate commit is fail-closed, and no release may point at it.** After round 1 alone, a clash loads and apply refuses its servers (through today's `conflictRefusal`), but revoke and rotate refuse to save over it and adopt/`import --merge` refuse any clash, until lane `write` commits in round 2. That window contradicts OP6 ("revoke and rotate still save"). Nothing is written that should not be, README describes the save rule only from lane `write`'s commit, and **no release tag may point at lane `grants`' or lane `audit`'s commit** (Task 16 Step 1). The other fix, moving `ClashRefused`, `editConflictRefusal` and the `editPrelude` line into round 1, would put `internal/apply` and `cmd/sshepherd/{conflicts,editrun}.go` in lane `grants` and was not taken.
15. **Adopt never adds a clash, so its added-clash path is a unit test.** Adopt's extensions only grant servers no entry covers yet, and adopt adds no server, so the design's example (a new server reached by two `*` entries with different `except:`) can only arise through `import --merge`, which is the CLI test. Adopt shares `conflictRefusal`, pinned by `TestRestrictionSaveRule`; its CLI test is the save over a clash already there (both modes). The design's Tests sentence is amended to say so (amendment 8).
16. **Spec test "a `no-port-forwarding` grant reaching a managed bastion is refused by S5's guard" lands here** (S5 landed first). It is a row table in `TestGrantOptionsForwardGuard` (Task 10).

## How this plan is cut (read first)

### Why the lanes look the way they do

1. **`deadcode ./cmd/sshepherd` is in `make check`.** Every function a lane adds is reachable from `main` at that lane's commit: `authkeys.IsRestriction` and `SameOptions` land with their first callers in `internal/config` (lane `grants`); `Config.ClashedKeys` lands with `audit.auditOne`, its first caller, in lane `audit` (a new `internal/config/clashed.go` that lane owns); `restrictionRefusal`, `editConflictRefusal` and `addedClashes` land with their callers in lane `write`.
2. **`TestSchemaRoundTrip*` reflects over `config.Access`,** so the `Options` sample lands in lane `grants` with the field (`fill` fails otherwise).
3. **Round 1 is one lane.** Everything in round 2 reads `Access.Options`, `ConflictRestriction` and the per-server render, so nothing can run beside lane `grants`. Its intermediate commit is fail-closed (gap 14).
4. **Round 2 has three lanes with disjoint files.** `audit` owns `internal/audit/*` and `internal/config/clashed{,_test}.go`. `write` owns three `internal/apply` production files, apply's new tests and goldens, `cmd/sshepherd/{conflicts,editrun,run}.go`, five help goldens (`apply`, `revoke`, `rotate`, `adopt`, `import`) and two new cmd test files. `e2e` owns the real-sshd test and `scripts/integration.sh`; its assertions (per-server render, a probe through a restricted operator key, audit 0, a clash: audit 2 and apply refusing one server) need only round 1.
5. **Lane `write` changes three `--help` footers** (`exitCodesWrite`, `exitCodesAdopt`, `exitCodesImport`; gap 13), and `TestHelpExamplesAndExitCodes` (`cmd/sshepherd/run_test.go:117`) requires README to hold every footer verbatim, so lane `write` applies its README footer delta to its worktree before `make check` (Task 12 Step 1); the ownership filter drops README from the patch and **the integrator must apply that footer delta before lane `write`'s `make check`**. No other lane's tests read README text S7 changes: S7 adds no flag (`TestHelpMatchesREADMETables` is untouched).

### Rounds

| Round | Lanes (disjoint files) | Builds on |
|---|---|---|
| 1 | `grants` (Tasks 1–6): `internal/authkeys/options.go` + `restriction_test.go`, `internal/config/*`, `cmd/sshepherd/schema_roundtrip_test.go`, `cmd/sshepherd/restrict_schema_test.go`, `internal/manifest/edit_options_test.go` | master at `065c1d3` or later (see Base) |
| 2 | `audit` (Tasks 7–8): `internal/audit/*`, `internal/config/clashed.go`, `internal/config/clashed_test.go` | round 1 |
| 2 | `write` (Tasks 9–13): `internal/apply/{plan,serial,predicates}.go`, `internal/apply/{predicates_test,restrict_test}.go`, `internal/apply/testdata/{render_grant_options,plan_restriction_conflict}.golden`, `cmd/sshepherd/{conflicts,editrun,run}.go`, `cmd/sshepherd/testdata/help/{apply,revoke,rotate,adopt,import}.golden`, `cmd/sshepherd/{restrict_save_test,restrict_hermetic_test}.go` | round 1 |
| 2 | `e2e` (Tasks 14–15): `cmd/sshepherd/restrict_e2e_test.go`, `scripts/integration.sh` | round 1 |

After round 2 the integrator runs Task 16 and an independent verifier runs Task 17. No lane owns either.

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted. Every `-update` run is followed by `git status --short -- '*testdata*'` (a new golden is untracked, so `git diff --stat` would not show it), which must list only the files the step names.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests exists; a test that pins behaviour already present says so in its step, and a build failure caused only by a sibling test does not count as seeing it fail.
- **gocyclo 15 is a production-code gate;** never `//nolint:gocyclo`. `validateAccess` gains one call and no branch; `planOne` gains one `if` (9 after); the new helpers stay small.
- **Run `gofmt -w` and `goimports -w` on every Go file you touch** before `make check`. Alignment in these blocks is written by hand.
- **New test variables must not shadow builtins** (revive): no `new`, `len`, `max`, `min`, `copy`, `cap`, `close`, `clear`. The blocks use `want`, `got`, `cfg`, `saved`, `former`, `added`, `more`.
- **Hermetic tests own their goroutines.** Every `sshtest.Server` and agent is closed by `t.Cleanup` (the helpers do this); goleak fails the package otherwise.
- **A mutation run must finish before reporting.** Each lane's last task lists its mutants. Apply one at a time, run the named tests, record killed or survived, and revert. Report the table with the hand-back; explain any survivor (equivalent) or add the test that kills it.
- **`FuzzLoad`'s committed corpus is at 16 entries** (`internal/config/testdata/fuzz/FuzzLoad`): S7 adds an in-code `f.Add` seed and no committed entry. S7 adds no `Fuzz*` target.
- **Before hand-back:** run `make check` (and `make integration IT_DISTRO=alpine` under the runner's lock when the lane says `needsIntegration`; the integrator runs all three distros), then `git add -A`, unstage every path outside the lane's globs (`README.md` and `CLAUDE.md` always), and write the patch.
- **`docsDelta`** blocks are integrator-only text for `README.md`, `CLAUDE.md` Status and the spec. A lane reports them unchanged and never carries those files in its patch (lane `write` applies its footer delta locally for its own gate only). README samples are copied from the goldens or the test expectations named in the delta, never from this plan.

---

## File structure

| File | Round/lane | Responsibility |
|---|---|---|
| `internal/authkeys/options.go` | 1 `grants` | `IsRestriction`, `SameOptions`, `optionSet` |
| `internal/authkeys/restriction_test.go` (new) | 1 `grants` | the table-driven list, `IsRestriction` rows, `SameOptions` rows |
| `internal/config/config.go` | 1 `grants` | `Access.Options`; `Config.optioned`; `validateAccess` calls `grantOptionErrors`; `DesiredFor` renders through `keysOn` |
| `internal/config/restrict.go` (new) | 1 `grants` | `grantOptionErrors`, `grantOptionIssue`, `keyLineClash`; `implicitGrant`, `grantSource`, `grantSources`, `keysOn`; `restrictionConflicts`, `reachedByOptions`, `userClashes`, `firstClash`, `clashMessage`, `sourceLabel` |
| `internal/config/revoked.go` | 1 `grants` | `ConflictRestriction`; `computeConflicts` appends `restrictionConflicts()` |
| `internal/config/policy.go` | 1 `grants` | `warnExpired` reads each entry's `options:` |
| `internal/config/restrict_test.go` (new), `fuzz_test.go` | 1 `grants` | validation, render, group/tag/operator composition, conflicts, blocked, expiry; the `FuzzLoad` seed and `checkGrantOptions` oracle |
| `cmd/sshepherd/schema_roundtrip_test.go`, `restrict_schema_test.go` (new) | 1 `grants` | the `Options` sample; regenerate writes `options:` only when set; a group entry's options regenerate; a widening option exits 3 on every command |
| `internal/manifest/edit_options_test.go` (new) | 1 `grants` | `RemoveAccess` keeps an entry's `options:` |
| `internal/config/clashed.go`, `clashed_test.go` (new) | 2 `audit` | `Config.ClashedKeys` |
| `internal/audit/audit.go` | 2 `audit` | `ServerResult.Clashed`; `auditOne` fills it; `optionsDrift` skips it |
| `internal/audit/restrict_test.go` (new), `testdata/report_restriction_conflict.golden{,.json}` (new) | 2 `audit` | critical, skipped comparison for clashed keys only, per-server drift, `--server` (OP4), JSON shape |
| `internal/apply/plan.go`, `serial.go`, `predicates.go` | 2 `write` | `ServerPlan.ClashRefused`; `planOne` calls `restrictionRefusal`; `conflictRefusal` skips the kind; `NothingCanLand` skips `ClashRefused` |
| `internal/apply/predicates_test.go`, `restrict_test.go` (new), `testdata/render_grant_options.golden` (new), `testdata/plan_restriction_conflict.golden` (new) | 2 `write` | save-neutral refusal, precedence, render golden, forwarding guard, lockout guard, `Affected`, `Loosens`, kept lines, plan golden |
| `cmd/sshepherd/conflicts.go`, `editrun.go` | 2 `write` | `editConflictRefusal`, `addedClashes`; `editPrelude` calls `editConflictRefusal` |
| `cmd/sshepherd/run.go`, `testdata/help/{apply,revoke,rotate,adopt,import}.golden` | 2 `write` | the three footers (gap 13) |
| `cmd/sshepherd/restrict_save_test.go`, `restrict_hermetic_test.go` (new) | 2 `write` | the save rule, `import --merge` (stdout and in place), adopt, revoke/rotate over a clash (text, `--json`, `--sweep`), `revoke --from-server` clears it, plain `apply` refuses only the clashed server (text and `--json`), rotate keeps grant options, validate, the offer order through a grant's `command=` |
| `cmd/sshepherd/restrict_e2e_test.go` (new), `scripts/integration.sh` | 2 `e2e` | real-sshd E2E; fixture accounts `rsta`, `rstb` |

---
## Round 1 — lane `grants` (Tasks 1–6)

Lane `grants` owns `internal/authkeys/options.go`, `internal/authkeys/restriction_test.go`, `internal/config/*`, `cmd/sshepherd/schema_roundtrip_test.go`, `cmd/sshepherd/restrict_schema_test.go`, `internal/manifest/edit_options_test.go`. `needsIntegration: false`. Tasks 1–5 run `go test` per package only; the lane's `make check` runs once, in Task 6, when every new function has its caller.

### Task 1: `IsRestriction` and `SameOptions` (`internal/authkeys`)

**Files:**
- Modify: `internal/authkeys/options.go` (after `FindOption`, `:222-231`)
- Create: `internal/authkeys/restriction_test.go`

- [ ] **Step 1: Write the failing tests.** Create `internal/authkeys/restriction_test.go`:

```go
package authkeys

import (
	"slices"
	"testing"
)

// TestIsRestrictionIsTheSpecList (spec S7 Validation): exactly these options
// may be added by a grant. The table decides, so a restricting option joins
// the list only by being added to the table.
func TestIsRestrictionIsTheSpecList(t *testing.T) {
	want := []string{"command", "expiry-time", "from", "no-agent-forwarding", "no-port-forwarding", "no-pty",
		"no-user-rc", "no-x11-forwarding", "permitlisten", "permitopen", "restrict", "verify-required"}
	var got []string
	for name, s := range options {
		opt := name
		if s.takesValue {
			opt += `="x"`
		}
		if IsRestriction(opt) {
			got = append(got, name)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("restrictions = %v\n          want %v", got, want)
	}
}

func TestIsRestriction(t *testing.T) {
	for opt, want := range map[string]bool{
		`FROM="10.0.0.0/8"`: true, // names are case-insensitive
		"No-Pty":            true,
		"cert-authority":    false, // a grant must not make a key a certificate authority
		`principals="ops"`:  false,
		"pty":               false, // a re-enabler widens
		"no-touch-required": false,
		`environment="A=b"`: false, // neutral
		`tunnel="0"`:        false,
		"bogus":             false,
	} {
		if got := IsRestriction(opt); got != want {
			t.Errorf("IsRestriction(%q) = %v, want %v", opt, got, want)
		}
	}
}

func TestSameOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b []string
		want bool
	}{
		{"both empty", nil, []string{}, true},
		{"order", []string{"no-pty", `from="10.0.0.0/8"`}, []string{`from="10.0.0.0/8"`, "no-pty"}, true},
		{"name case", []string{`FROM="a"`, "No-Pty"}, []string{`from="a"`, "no-pty"}, true},
		{"a repeat", []string{"no-pty", "no-pty"}, []string{"no-pty"}, true},
		{"value case matters", []string{`from="A"`}, []string{`from="a"`}, false},
		{"one more", []string{"no-pty"}, []string{"no-pty", "restrict"}, false},
		{"none and some", nil, []string{"no-pty"}, false},
	} {
		if got := SameOptions(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: SameOptions(%q, %q) = %v, want %v", tc.name, tc.a, tc.b, got, tc.want)
		}
	}
}
```

- [ ] **Step 2: Run them and see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/authkeys -run 'IsRestriction|SameOptions'`
Expected: build failure (`undefined: IsRestriction`, `undefined: SameOptions`).

- [ ] **Step 3: Implement.** In `internal/authkeys/options.go`, after `FindOption`:

```go
// IsRestriction reports whether opt only narrows what a key line allows, so
// a per-grant restriction may add it (spec 2026-11-08 S7, OP5): an option the
// table marks restricts that does not make the line accept certificates only
// (cert-authority, principals=). The name matches case-insensitively;
// CheckOption judges the value.
func IsRestriction(opt string) bool {
	s, ok := lookup(opt)
	return ok && s.effect == restricts && !s.certOnly
}

// SameOptions reports whether a and b hold the same clauses, ignoring order,
// repeats and the case of option names (sshd matches names
// case-insensitively); values compare exactly. Every grant of one key on one
// server must agree by this test (spec S7).
func SameOptions(a, b []string) bool { return slices.Equal(optionSet(a), optionSet(b)) }

// optionSet is opts with each name lower-cased, sorted, repeats removed.
func optionSet(opts []string) []string {
	out := make([]string, 0, len(opts))
	for _, o := range opts {
		name, value, hasValue := strings.Cut(o, "=")
		clause := strings.ToLower(name)
		if hasValue {
			clause += "=" + value
		}
		out = append(out, clause)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
```

- [ ] **Step 4: Run them and see them pass.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/authkeys`
Expected: PASS. (`deadcode` would flag both functions now; Task 2 and Task 4 add their callers before the lane's `make check`.)

### Task 2: `Access.Options` and its validation

**Files:**
- Modify: `internal/config/config.go:85-95` (`Access`), `:98-132` (`Config`: `optioned`), `:451-495` (`validateAccess`)
- Create: `internal/config/restrict.go`, `internal/config/restrict_test.go`

- [ ] **Step 1: Write the failing tests.** Create `internal/config/restrict_test.go` (later tasks append to it):

```go
package config

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// grantFleet (spec S7): alice (k1, her key line prefixed by aliceOpts,
// verbatim, may be ""), bob (k2), carol (k3), op (k4, operator); web-1 and
// web-2 tagged web, db-1 tagged db, no root account. groups and access are
// spliced in verbatim.
func grantFleet(t *testing.T, aliceOpts, groups, access string) string {
	t.Helper()
	return `users:
  - {name: alice, keys: ['` + aliceOpts + testkeys.Line(t, 1) + `']}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
groups:
` + groups + `servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [web]}
  - {name: db-1, host: 10.0.2.1, user: deploy, tags: [db]}
access:
` + access
}

// grantOpts returns the options the key of seed renders with on server, and
// whether it renders there at all.
func grantOpts(t *testing.T, cfg *Config, seed byte, server string) ([]string, bool) {
	t.Helper()
	want := fpOfLine(t, testkeys.Line(t, seed))
	for _, k := range cfg.DesiredFor(server) {
		if k.Fingerprint == want {
			return k.Options, true
		}
	}
	return nil, false
}

// TestGrantOptionValidation (spec S7 Validation): each row is a load error.
func TestGrantOptionValidation(t *testing.T) {
	team := "  - {name: team, members: [bob, alice]}\n"
	for _, tc := range []struct{ name, aliceOpts, groups, access, want string }{
		{"an unknown option", "", "", "  - {user: bob, servers: [web-1], options: [no-ptty]}\n",
			`access[0]: option "no-ptty" is not a recognized authorized_keys option`},
		{"an unquoted value", "", "", "  - {user: bob, servers: [web-1], options: [from=10.0.0.1]}\n",
			`access[0]: option "from=10.0.0.1" requires a quoted value (name="...")`},
		{"a bad expiry", "", "", `  - {user: bob, servers: [web-1], options: ['expiry-time="2027"']}` + "\n",
			`access[0]: option "expiry-time=\"2027\"" has an invalid value (want YYYYMMDD[HHMM[SS]][Z])`},
		{"a widening option", "", "", "  - {user: bob, servers: [web-1], options: [pty]}\n",
			`access[0]: option "pty" does not restrict access; a grant can only add restrictions`},
		{"a neutral option", "", "", `  - {user: bob, servers: [web-1], options: ['environment="A=b"']}` + "\n",
			`access[0]: option "environment=\"A=b\"" does not restrict access; a grant can only add restrictions`},
		{"cert-authority", "", "", "  - {user: bob, servers: [web-1], options: [cert-authority]}\n",
			`access[0]: option "cert-authority" makes the key accept certificates only; a grant cannot turn a key into a certificate authority`},
		{"principals", "", "", `  - {user: bob, servers: [web-1], options: ['principals="ops"']}` + "\n",
			`access[0]: option "principals=\"ops\"" makes the key accept certificates only; a grant cannot turn a key into a certificate authority`},
		{"a repeated from= in one grant", "", "", `  - {user: bob, servers: [web-1], options: ['from="10.0.0.0/8"', 'from="10.1.0.0/16"']}` + "\n",
			`access[0]: option "from=\"10.1.0.0/16\"" repeats from=, which sshd allows once per line`},
		{"a name already on the key line", `from="10.0.0.0/8" `, "", `  - {user: alice, servers: [web-1], options: ['from="10.1.0.0/16"']}` + "\n",
			`access[0]: option "from=\"10.1.0.0/16\"": user "alice" key 1 already carries "from=\"10.0.0.0/8\""; restrict a key on its key line or on its grants, not both`},
		{"the same name in another case", `FROM="10.0.0.0/8" `, "", `  - {user: alice, servers: [web-1], options: ['from="10.0.0.0/8"']}` + "\n",
			`access[0]: option "from=\"10.0.0.0/8\"": user "alice" key 1 already carries "FROM=\"10.0.0.0/8\""`},
		{"a permitopen= union", `permitopen="db:5432" `, "", `  - {user: alice, servers: [web-1], options: ['permitopen="cache:6379"']}` + "\n",
			`access[0]: option "permitopen=\"cache:6379\"": user "alice" key 1 already carries "permitopen=\"db:5432\""`},
		{"a member's key line through a group", "no-pty ", team, "  - {group: team, servers: [web-1], options: [NO-PTY]}\n",
			`access[0]: option "NO-PTY": user "alice" key 1 already carries "no-pty"`},
		{"the entry's own index", "", "", "  - {user: bob, servers: [web-1]}\n  - {user: carol, servers: [web-2], options: [pty]}\n",
			`access[1]: option "pty" does not restrict access`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(grantFleet(t, tc.aliceOpts, tc.groups, tc.access)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestGrantOptionsAccepted: every restricting option loads in one grant, on
// a key line that already carries an option the grant does not name.
func TestGrantOptionsAccepted(t *testing.T) {
	all := `['command="backup"', 'expiry-time="20990101"', 'from="10.0.0.0/8"', no-agent-forwarding, no-port-forwarding, no-pty, no-user-rc, no-x11-forwarding, 'permitlisten="8080"', 'permitopen="db:5432"', restrict, verify-required]`
	cfg := mustParse(t, grantFleet(t, "no-touch-required ", "", "  - {user: alice, servers: [web-1], options: "+all+"}\n"))
	if len(cfg.Access[0].Options) != 12 {
		t.Errorf("Options = %q, want all 12", cfg.Access[0].Options)
	}
}
```

- [ ] **Step 2: Run them and see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'GrantOption'`
Expected: build failure (`cfg.Access[0].Options undefined (type Access has no field or method Options)`, from `TestGrantOptionsAccepted`). That build failure masks `TestGrantOptionValidation`, so Step 4 runs again once the field exists.

- [ ] **Step 3: Add the field.** In `internal/config/config.go`, `Access` (`:90-95`) gains, after `Except`:

```go
	// Options are restrictions this entry adds to its keys' lines on the
	// servers it grants (spec 2026-11-08 S7, OP5): the key line's options,
	// then these. Only restricting options (authkeys.IsRestriction), none
	// already named on a key line the entry reaches. Two grants that give one
	// key different options on one server are a restriction_conflict.
	Options []string `yaml:"options"`
```

Update `Access`'s doc comment (`:85-89`) to end with: "options: adds restrictions to the key lines on the servers the entry grants (spec S7)." In `Config` (`:119-132`), after `preserve`:

```go
	optioned   bool                      // some access: entry has options: (spec S7); keysOn's fast path when false
```

- [ ] **Step 4: See the validation rows fail on their assertions.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'GrantOption'`
Expected: FAIL — each of the 13 `TestGrantOptionValidation` rows fails with `err = <nil>, want it to contain …` (the field now loads and nothing checks it). `TestGrantOptionsAccepted` passes: it pins that the field loads all twelve restrictions; its bite is any later validation that refuses one of them.

- [ ] **Step 5: Validate.** In `validateAccess` (`:451`), after `c.fleetWide = c.fleetWideOperators()` add

```go
	c.optioned = slices.ContainsFunc(c.Access, func(a Access) bool { return len(a.Options) > 0 })
```

and, right after the `entrySubjectError` block (whose `continue` skips an entry with no valid subject), add

```go
		errs = append(errs, c.grantOptionErrors(i, a)...)
```

Create `internal/config/restrict.go`:

```go
package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// grantOptionErrors checks access entry i's options: (spec 2026-11-08 S7
// Validation): each one is an option sshd accepts and a restriction, the
// grant repeats no once-only clause, and no name is already on a key line the
// entry reaches (each member's keys for a group entry), which would repeat a
// once-only clause or widen a permitopen=/permitlisten= union.
func (c *Config) grantOptionErrors(i int, a Access) []error {
	var errs []error
	for _, opt := range a.Options {
		if err := grantOptionIssue(i, opt); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs
	}
	if err := authkeys.OptionIssue(a.Options); err != nil {
		return []error{fmt.Errorf("access[%d]: %w", i, err)}
	}
	for _, user := range c.entryUsers(a) {
		for ki, k := range c.keysByUser[user] {
			if err := keyLineClash(i, a.Options, user, ki+1, k); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errs
}

// grantOptionIssue reports why one grant option is refused; nil when it is
// a restriction sshd accepts.
func grantOptionIssue(i int, opt string) error {
	if issue := authkeys.CheckOption(opt); issue != "" {
		return fmt.Errorf("access[%d]: option %q %s", i, opt, issue)
	}
	if authkeys.CertOnly([]string{opt}) {
		return fmt.Errorf("access[%d]: option %q makes the key accept certificates only; a grant cannot turn a key into a certificate authority", i, opt)
	}
	if !authkeys.IsRestriction(opt) {
		return fmt.Errorf("access[%d]: option %q does not restrict access; a grant can only add restrictions", i, opt)
	}
	return nil
}

// keyLineClash refuses a grant option whose name the key line already
// carries (authkeys.FindOption ignores case), then runs OptionIssue over the
// combined line as a last check; that check cannot fire once the name rule
// passed (plan gap 8) and stays as defense in depth.
func keyLineClash(i int, grant []string, user string, index int, k authkeys.Key) error {
	for _, opt := range grant {
		name, _, _ := strings.Cut(opt, "=")
		if have, ok := authkeys.FindOption(k.Options, name); ok {
			return fmt.Errorf("access[%d]: option %q: user %q key %d already carries %q; restrict a key on its key line or on its grants, not both",
				i, opt, user, index, have)
		}
	}
	if err := authkeys.OptionIssue(slices.Concat(k.Options, grant)); err != nil {
		return fmt.Errorf("access[%d]: user %q key %d: %w", i, user, index, err)
	}
	return nil
}
```

- [ ] **Step 6: Run them and see them pass.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS (the whole package: no existing manifest sets `options:`, and `optioned` is false for all of them).

### Task 3: grant sources and the per-server render

**Files:**
- Modify: `internal/config/restrict.go`, `internal/config/config.go:617-640` (`DesiredFor`)
- Test: `internal/config/restrict_test.go`

- [ ] **Step 1: Write the failing tests.** Add `"reflect"`, `"slices"` and `"github.com/javadh75/SSHepherd/internal/authkeys"` to the imports of `internal/config/restrict_test.go`, then append:

```go
// TestGrantOptionsRenderPerServer (spec S7 Meaning): one key, restricted on
// the servers one entry grants and plain where another grants it; except:
// carves web-2 out of the restricted entry. The key line's own option comes
// first.
func TestGrantOptionsRenderPerServer(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "no-agent-forwarding ", "",
		`  - {user: alice, servers: ["@web"], except: [web-2], options: ['from="10.0.0.0/8"', no-pty]}
  - {user: alice, servers: [web-2]}
`))
	for server, want := range map[string][]string{
		"web-1": {"no-agent-forwarding", `from="10.0.0.0/8"`, "no-pty"},
		"web-2": {"no-agent-forwarding"},
	} {
		if got, ok := grantOpts(t, cfg, 1, server); !ok || !slices.Equal(got, want) {
			t.Errorf("%s: options = %q (rendered %v), want %q", server, got, ok, want)
		}
	}
	if _, ok := grantOpts(t, cfg, 1, "db-1"); ok {
		t.Error("alice renders on db-1, which no entry grants")
	}
	// keysOn copies: the manifest's parsed key line never changes.
	if got := cfg.keysByUser["alice"][0].Options; !slices.Equal(got, []string{"no-agent-forwarding"}) {
		t.Errorf("alice's parsed key line changed to %q", got)
	}
}

// TestKeysOnNeverSharesOptions: each server's render owns its options, so
// rendering web-2 cannot rewrite web-1's earlier result. The parsed key line
// is given spare capacity first: an in-place append (mutant G13) would then
// write both renders into one backing array, which the parsed-line check
// above cannot see (its length never changes).
func TestKeysOnNeverSharesOptions(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "no-agent-forwarding ", "",
		"  - {user: alice, servers: [web-1], options: [no-pty]}\n  - {user: alice, servers: [web-2], options: [restrict]}\n"))
	line := &cfg.keysByUser["alice"][0]
	line.Options = slices.Grow(line.Options, 4) // spare capacity, whatever the parser left
	web1, _ := grantOpts(t, cfg, 1, "web-1")
	_ = cfg.DesiredFor("web-2") // under G13 this overwrites web1's last option
	if want := []string{"no-agent-forwarding", "no-pty"}; !slices.Equal(web1, want) {
		t.Errorf("web-1 renders %q after web-2 was rendered, want %q", web1, want)
	}
}

// TestGroupGrantOptionsMatchFlatTwin (spec S7 composition with S3b): a group
// entry's options reach every member, exactly as one user: entry per member
// with the same options would.
func TestGroupGrantOptionsMatchFlatTwin(t *testing.T) {
	group := mustParse(t, grantFleet(t, "", "  - {name: team, members: [alice, bob]}\n",
		"  - {group: team, servers: [\"@web\"], options: [no-pty, no-x11-forwarding]}\n"))
	flat := mustParse(t, grantFleet(t, "", "",
		"  - {user: alice, servers: [\"@web\"], options: [no-pty, no-x11-forwarding]}\n"+
			"  - {user: bob, servers: [\"@web\"], options: [no-pty, no-x11-forwarding]}\n"))
	for _, s := range []string{"web-1", "web-2", "db-1"} {
		if g, f := group.DesiredFor(s), flat.DesiredFor(s); !reflect.DeepEqual(g, f) {
			t.Errorf("%s: the group renders %+v, its flat twin %+v", s, g, f)
		}
	}
	if got, _ := grantOpts(t, group, 2, "web-2"); !slices.Equal(got, []string{"no-pty", "no-x11-forwarding"}) {
		t.Errorf("bob on web-2 = %q", got)
	}
}

// TestOperatorOwnGrantOptions (spec S7 with S4): an operator's own "*" entry
// replaces the implicit grant, so its options reach every server and its key
// is still written first.
func TestOperatorOwnGrantOptions(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "", "  - {user: bob, servers: [web-1]}\n  - {user: op, servers: [\"*\"], options: [no-pty]}\n"))
	desired := cfg.DesiredFor("web-1")
	if len(desired) != 2 || desired[0].Fingerprint != fpOfLine(t, testkeys.Line(t, 4)) || !slices.Equal(desired[0].Options, []string{"no-pty"}) {
		t.Errorf("web-1 = %+v, want op first with no-pty, then bob", desired)
	}
}

// TestOfferOrderSeesGrantOptions (spec S7 Render): a grant's command= makes
// its key a forced-command line on that server only, so every connection
// offers the plain key first there and keeps grant order elsewhere.
func TestOfferOrderSeesGrantOptions(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "", `  - {user: alice, servers: [web-1], options: ['command="backup"']}
  - {user: alice, servers: [web-2]}
  - {user: bob, servers: [web-1, web-2]}
`))
	a, b, op := fpOfLine(t, testkeys.Line(t, 1)), fpOfLine(t, testkeys.Line(t, 2)), fpOfLine(t, testkeys.Line(t, 4))
	if got := authkeys.OfferOrder(cfg.DesiredFor("web-1")); !slices.Equal(got, []string{op, b, a}) {
		t.Errorf("web-1 offer order = %q, want op, bob, then alice's forced-command line", got)
	}
	if got := authkeys.OfferOrder(cfg.DesiredFor("web-2")); !slices.Equal(got, []string{op, a, b}) {
		t.Errorf("web-2 offer order = %q, want op, alice, bob", got)
	}
}
```

- [ ] **Step 2: Run them and see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'RenderPerServer|KeysOnNeverShares|FlatTwin|OperatorOwnGrantOptions|OfferOrderSees'`
Expected: FAIL — every server renders the key line's options only (`TestKeysOnNeverSharesOptions` fails on `web-1 renders ["no-agent-forwarding"]`).

- [ ] **Step 3: Implement the sources and the copy.** Append to `internal/config/restrict.go`:

```go
// implicitGrant is the entry of a fleet-wide operator's implicit grant of
// every server, which adds no options. It comes before access[0] (plan gap 3).
const implicitGrant = -1

// grantSource is one way a user reaches a server: access entry entry (or
// implicitGrant) and the options it adds there.
type grantSource struct {
	entry   int
	options []string
}

// grantSources lists every way user reaches s, the implicit operator grant
// first, then access entries in order. A jump_only server has none. On a
// pair an access tombstone blocked no entry counts: it renders nothing and
// takes no part in the clash check (spec S7 Tombstones); a fleet-wide
// operator's implicit grant still does, as it still installs the key ("How
// selectors meet tombstones"). A user with a source renders on s exactly when
// DesiredFor emits its keys there (FuzzLoad's checkGrantOptions).
func (c *Config) grantSources(user string, s Server) []grantSource {
	if s.JumpOnly {
		return nil
	}
	var out []grantSource
	if c.fleetWide[user] {
		out = append(out, grantSource{entry: implicitGrant})
	}
	if c.blocked[grantPair{user, s.Name}] {
		return out
	}
	for n, a := range c.Access {
		if c.entryApplies(a, user) && entryCovers(a, s) {
			out = append(out, grantSource{entry: n, options: a.Options})
		}
	}
	return out
}

// keysOn is user's keys as rendered on s (spec S7 Render): each key line's
// options, then the options of the first grant source reaching it. Every
// source agrees unless a restriction conflict names the pair; then the first
// source still decides, so DesiredFor stays deterministic, and apply refuses
// the server. Copies: the manifest's parsed keys never change.
func (c *Config) keysOn(user string, s Server) []authkeys.Key {
	keys := c.keysByUser[user]
	if !c.optioned {
		return keys
	}
	src := c.grantSources(user, s)
	if len(src) == 0 || len(src[0].options) == 0 {
		return keys
	}
	out := make([]authkeys.Key, len(keys))
	for i, k := range keys {
		k.Options = slices.Concat(k.Options, src[0].options)
		out[i] = k
	}
	return out
}
```

Replace `DesiredFor` (`internal/config/config.go:617-640`) with:

```go
// DesiredFor returns the desired key set for a server: protected keys first
// (users order; a fleet-wide operator everywhere, any other protected user
// only where granted), then the keys of every other granted user (access
// order). Deterministic; a user is never emitted twice. An operator's own
// servers: ["*"] entry replaces the implicit grant, so its except: applies.
// A jump_only server renders nothing: no access entry reaches it, and the
// implicit operator grant skips it. Each key carries its grant's options
// after its own (keysOn, spec S7).
func (c *Config) DesiredFor(serverName string) []authkeys.Key {
	var keys []authkeys.Key
	srv, known := c.ServerNamed(serverName)
	if !known {
		srv = Server{Name: serverName}
	}
	first := make(map[string]bool, len(c.protected))
	for _, name := range c.protected {
		if (c.fleetWide[name] && !srv.JumpOnly) || slices.Contains(c.grants[serverName], name) {
			first[name] = true
			keys = append(keys, c.keysOn(name, srv)...)
		}
	}
	for _, userName := range c.grants[serverName] {
		if !first[userName] { // redundant grant for a protected user: already emitted
			keys = append(keys, c.keysOn(userName, srv)...)
		}
	}
	return keys
}
```

(`srv.JumpOnly` is what `c.jumpOnly(serverName)` returned; `jumpOnly` keeps its other callers.)

- [ ] **Step 4: Run the package.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS, including every existing `DesiredFor` test (`TestDesiredForOrdering`, `TestOperatorImplicitGrant`, `TestJumpOnlyReach`, the S3a/S3b twins) unchanged.

### Task 4: the `restriction_conflict` kind and the grant expiry warning

**Files:**
- Modify: `internal/config/revoked.go:90-95` (constants), `:97-108` (`Conflict` doc), `:255-277` (`computeConflicts`); `internal/config/policy.go:65-76` (`warnExpired`); `internal/config/restrict.go`
- Test: `internal/config/restrict_test.go`

- [ ] **Step 1: Write the failing tests.** Add `"time"` to the imports of `internal/config/restrict_test.go`, then append:

```go
// clashTail ends every restriction conflict's message.
const clashTail = "; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user"

// clashesOf is the manifest's restriction conflicts.
func clashesOf(cfg *Config) []Conflict {
	var out []Conflict
	for _, c := range cfg.Conflicts() {
		if c.Kind == ConflictRestriction {
			out = append(out, c)
		}
	}
	return out
}

// TestRestrictionConflict (spec S7, OP6): a clash loads (a policy conflict,
// not a load error), one conflict per user and pair of grant sources, every
// server where the pair disagrees, no fingerprint.
func TestRestrictionConflict(t *testing.T) {
	team := "  - {name: team, members: [alice, bob]}\n"
	clash := func(user string, servers []string, msg string) Conflict {
		return Conflict{Kind: ConflictRestriction, User: user, Servers: servers, Message: msg + clashTail}
	}
	for _, tc := range []struct {
		name, groups, access string
		want                 []Conflict
	}{
		{"a tag and a name", "", `  - {user: alice, servers: ["@web"], options: ['from="10.0.0.0/8"', no-pty]}
  - {user: alice, servers: [web-1]}
`, []Conflict{clash("alice", []string{"web-1"},
			`user "alice": server "web-1" is granted by access[0] with [from="10.0.0.0/8" no-pty] and by access[1] with no options`)}},
		{"several servers", "", `  - {user: alice, servers: ["*"], options: [no-pty]}
  - {user: alice, servers: ["@web"]}
`, []Conflict{clash("alice", []string{"web-1", "web-2"},
			`user "alice": servers "web-1" and 1 more are granted by access[0] with [no-pty] and by access[1] with no options`)}},
		{"a group and a member's own entry", team, `  - {group: team, servers: ["@web"], options: [no-pty]}
  - {user: bob, servers: [web-2]}
`, []Conflict{clash("bob", []string{"web-2"},
			`user "bob": server "web-2" is granted by access[0] with [no-pty] and by access[1] with no options`)}},
		{"an operator's implicit grant", "", "  - {user: op, servers: [db-1], options: [no-pty]}\n",
			[]Conflict{clash("op", []string{"db-1"},
				`user "op": server "db-1" is granted by its operator grant with no options and by access[0] with [no-pty]`)}},
		{"an operator in a restricted group", "  - {name: ops, members: [op]}\n", "  - {group: ops, servers: [\"@web\"], options: [restrict]}\n",
			[]Conflict{clash("op", []string{"web-1", "web-2"},
				`user "op": servers "web-1" and 1 more are granted by its operator grant with no options and by access[0] with [restrict]`)}},
		{"three sets: the first two that differ", "", `  - {user: alice, servers: [web-1], options: [no-pty]}
  - {user: alice, servers: [web-1], options: [NO-PTY]}
  - {user: alice, servers: [web-1], options: [restrict]}
  - {user: alice, servers: [web-1], options: [no-x11-forwarding]}
`, []Conflict{clash("alice", []string{"web-1"},
			`user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[2] with [restrict]`)}},
		{"two pairs, two conflicts", "", `  - {user: alice, servers: [web-1, web-2], options: [no-pty]}
  - {user: alice, servers: [web-1]}
  - {user: alice, servers: [web-2], options: [restrict]}
`, []Conflict{
			clash("alice", []string{"web-1"}, `user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[1] with no options`),
			clash("alice", []string{"web-2"}, `user "alice": server "web-2" is granted by access[0] with [no-pty] and by access[2] with [restrict]`),
		}},
		// plan gap 4: access[0] and access[2] also disagree on web-1, but
		// there the first disagreement is with access[1].
		{"a pair is named only where it is the first disagreement", "", `  - {user: alice, servers: [web-1, web-2], options: [no-pty]}
  - {user: alice, servers: [web-1], options: [restrict]}
  - {user: alice, servers: [web-1, web-2], options: [no-x11-forwarding]}
`, []Conflict{
			clash("alice", []string{"web-1"}, `user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[1] with [restrict]`),
			clash("alice", []string{"web-2"}, `user "alice": server "web-2" is granted by access[0] with [no-pty] and by access[2] with [no-x11-forwarding]`),
		}},
		{"an empty list is no options", "", "  - {user: alice, servers: [web-1], options: []}\n  - {user: alice, servers: [web-1]}\n", nil},
		{"order and name case do not matter", "", `  - {user: alice, servers: ["@web"], options: [no-pty, 'from="10.0.0.0/8"']}
  - {user: alice, servers: [web-1], options: ['FROM="10.0.0.0/8"', NO-PTY]}
`, nil},
		{"a group and a tag with the same set", team, `  - {group: team, servers: [web-1], options: [no-pty]}
  - {user: alice, servers: ["@web"], options: [no-pty]}
`, nil},
		{"no options anywhere", "", "  - {user: alice, servers: [\"@web\"]}\n  - {user: alice, servers: [web-1]}\n", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := mustParse(t, grantFleet(t, "", tc.groups, tc.access))
			if got := clashesOf(cfg); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("restriction conflicts:\n got %+v\nwant %+v", got, tc.want)
			}
		})
	}
}

// TestBlockedGrantCannotClash (spec S7 Tombstones): the access tombstone
// blocks alice's tag and group grants of web-1 (neither names her there
// directly), so they take no part in the clash check; web-2 still clashes.
func TestBlockedGrantCannotClash(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "  - {name: team, members: [alice, bob]}\n", `  - {group: team, servers: ["@web"]}
  - {user: alice, servers: ["@web"], options: [no-pty]}
revoked:
  - {user: alice, servers: [web-1], date: 2026-11-10}
`))
	if got := clashesOf(cfg); len(got) != 1 || !slices.Equal(got[0].Servers, []string{"web-2"}) {
		t.Errorf("clashes = %+v, want alice on web-2 only", got)
	}
	if _, ok := grantOpts(t, cfg, 1, "web-1"); ok {
		t.Error("the blocked pair still renders alice on web-1")
	}
}

// TestBlockedOperatorStillRenders: a tombstone blocks an operator's group
// grant of web-1, but the implicit grant still installs the key there, with
// no options and no clash; web-2 still clashes.
func TestBlockedOperatorStillRenders(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "  - {name: ops, members: [op]}\n", `  - {group: ops, servers: ["@web"], options: [restrict]}
revoked:
  - {user: op, servers: [web-1], date: 2026-11-10}
`))
	if got, ok := grantOpts(t, cfg, 4, "web-1"); !ok || len(got) != 0 {
		t.Errorf("op on web-1 = %q (rendered %v), want the implicit grant's key with no options", got, ok)
	}
	// The blocked pair keeps the implicit grant as its one source (G10b:
	// DesiredFor would still emit op, so only the sources show it).
	if src := cfg.grantSources("op", cfg.Servers[0]); len(src) != 1 || src[0].entry != implicitGrant {
		t.Errorf("op's sources on web-1 = %+v, want the implicit grant alone", src)
	}
	if got := clashesOf(cfg); len(got) != 1 || !slices.Equal(got[0].Servers, []string{"web-2"}) {
		t.Errorf("clashes = %+v, want op on web-2 only", got)
	}
}

// TestEmptyGrantOptions (spec S7 Go shape: "An empty list means no
// restrictions"): options: [] loads, renders the key line alone and never
// clashes with an entry without options:.
func TestEmptyGrantOptions(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "no-agent-forwarding ", "",
		"  - {user: alice, servers: [web-1], options: []}\n  - {user: alice, servers: [web-1]}\n"))
	if got, ok := grantOpts(t, cfg, 1, "web-1"); !ok || !slices.Equal(got, []string{"no-agent-forwarding"}) {
		t.Errorf("alice on web-1 = %q (rendered %v), want the key line's option alone", got, ok)
	}
	if got := clashesOf(cfg); len(got) != 0 {
		t.Errorf("clashes = %+v, want none", got)
	}
}

// TestKeylessUserNeverClashes (plan gap 5): a protected user with no keys
// renders nothing, so two grants cannot disagree about a key.
func TestKeylessUserNeverClashes(t *testing.T) {
	y := strings.Replace(grantFleet(t, "", "", "  - {user: ci, servers: [web-1], options: [no-pty]}\n  - {user: ci, servers: [web-1]}\n"),
		"users:\n", "users:\n  - {name: ci, protected: true, keys: []}\n", 1)
	if got := clashesOf(mustParse(t, y)); len(got) != 0 {
		t.Errorf("clashes = %+v, want none", got)
	}
}

// TestClashedPairRendersFirstSource (spec S7 Render, plan gap 3): a clashed
// pair still renders, with the first source's options; an operator's
// implicit grant comes first and adds none.
func TestClashedPairRendersFirstSource(t *testing.T) {
	cfg := mustParse(t, grantFleet(t, "", "", `  - {user: alice, servers: ["@web"], options: [no-pty]}
  - {user: alice, servers: [web-1], options: [restrict]}
  - {user: op, servers: [web-1], options: [no-pty]}
`))
	if got, _ := grantOpts(t, cfg, 1, "web-1"); !slices.Equal(got, []string{"no-pty"}) {
		t.Errorf("alice on web-1 = %q, want access[0]'s [no-pty]", got)
	}
	if got, ok := grantOpts(t, cfg, 4, "web-1"); !ok || len(got) != 0 {
		t.Errorf("op on web-1 = %q (rendered %v), want the implicit grant's none", got, ok)
	}
	if n := len(clashesOf(cfg)); n != 2 {
		t.Errorf("clashes = %d, want 2 (alice, op)", n)
	}
}

// TestGrantExpiryWarns (P09's passed-expiry warning, plan gap 9): a grant's
// expiry-time= that has passed warns like a key line's, kind key_expired.
func TestGrantExpiryWarns(t *testing.T) {
	pinNow(t, time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))
	cfg := mustParse(t, grantFleet(t, "", "", `  - {user: bob, servers: [web-1], options: ['expiry-time="20990101"']}
  - {user: alice, servers: [web-1], options: ['expiry-time="20200101"']}
`))
	want := ManifestWarning{Kind: WarnKeyExpired, Message: `access[1]: expiry-time="20200101" has passed; sshd no longer accepts the keys this entry grants`}
	if !slices.Contains(cfg.ManifestWarnings, want) || len(cfg.ManifestWarnings) != 1 {
		t.Errorf("warnings = %+v, want exactly %+v", cfg.ManifestWarnings, want)
	}
}
```

- [ ] **Step 2: Run them and see them fail.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run 'RestrictionConflict|BlockedGrantCannotClash|BlockedOperator|KeylessUser|ClashedPair|GrantExpiry|EmptyGrantOptions'`
Expected: build failure (`undefined: ConflictRestriction`, from `clashesOf`). It masks every test in the file, so Step 3 adds the constant alone and runs again.

- [ ] **Step 3: The kind, then see each test fail on its assertion.** In `internal/config/revoked.go`, the constants block (`:91-95`) gains

```go
	// ConflictRestriction: two grants give one user's keys different
	// restrictions on one server (spec S7, OP6). User is set, Fingerprint
	// omitted, Servers the servers where that pair of grants is the first
	// disagreement (plan gap 4).
	ConflictRestriction = "restriction_conflict"
```

and `Conflict`'s doc comment (`:97-101`) reads "a tombstoned key still listed, a grant over an access tombstone, a weak key granted on a server, or two grants that restrict one key differently on one server".

Run the Step 2 command again. Expected: FAIL, test by test:
- `TestRestrictionConflict`: every row with a `want` fails (`got []`); the no-conflict rows pass (they pin).
- `TestBlockedGrantCannotClash`, `TestBlockedOperatorStillRenders`, `TestClashedPairRendersFirstSource`: the clash-count assertion fails (0 conflicts); their render and `grantSources` halves already pass (Task 3 built them).
- `TestGrantExpiryWarns` fails (no warning).
- `TestKeylessUserNeverClashes` and `TestEmptyGrantOptions` pass: they pin. The first bites under mutant G18; the second (with the "an empty list is no options" row) under mutant G22, a `SameOptions` that tells nil from an empty list.

- [ ] **Step 4: Implement.** `computeConflicts` (`:257-277`) ends:

```go
	out = append(out, c.weakConflicts()...)
	return append(out, c.restrictionConflicts()...)
```

Append to `internal/config/restrict.go`:

```go
// restrictionConflicts finds every user whose grants give their keys
// different restrictions on a server (spec S7, OP6): one conflict per user
// and pair of grant sources, users in users order. Only a user an entry with
// options: reaches can clash, and only one with keys (plan gap 5).
func (c *Config) restrictionConflicts() []Conflict {
	if !c.optioned {
		return nil
	}
	var out []Conflict
	for _, u := range c.Users {
		if len(c.keysByUser[u.Name]) > 0 && c.reachedByOptions(u.Name) {
			out = append(out, c.userClashes(u.Name)...)
		}
	}
	return out
}

// reachedByOptions reports whether an access: entry with options: grants to user.
func (c *Config) reachedByOptions(user string) bool {
	return slices.ContainsFunc(c.Access, func(a Access) bool { return len(a.Options) > 0 && c.entryApplies(a, user) })
}

// clashKey names the pair of grant sources a restriction conflict is about.
type clashKey struct{ first, second int }

// clash is one restriction conflict being collected: its two sources and
// every server where they are the first disagreement, servers: order.
type clash struct {
	first, second grantSource
	servers       []string
}

// userClashes collects user's restriction conflicts, one per pair of
// sources, in the order their first server appears.
func (c *Config) userClashes(user string) []Conflict {
	var order []clashKey
	found := make(map[clashKey]*clash)
	for _, s := range c.Servers {
		a, b, ok := firstClash(c.grantSources(user, s))
		if !ok {
			continue
		}
		k := clashKey{a.entry, b.entry}
		if found[k] == nil {
			found[k] = &clash{first: a, second: b}
			order = append(order, k)
		}
		found[k].servers = append(found[k].servers, s.Name)
	}
	out := make([]Conflict, 0, len(order))
	for _, k := range order {
		cl := found[k]
		out = append(out, Conflict{Kind: ConflictRestriction, User: user, Servers: cl.servers, Message: clashMessage(user, cl)})
	}
	return out
}

// firstClash returns the first source and the first later one whose options
// differ from it (spec S7: with three different sets, the first two in order
// are named); ok is false when every source agrees.
func firstClash(src []grantSource) (a, b grantSource, ok bool) {
	for i := 1; i < len(src); i++ {
		if !authkeys.SameOptions(src[0].options, src[i].options) {
			return src[0], src[i], true
		}
	}
	return grantSource{}, grantSource{}, false
}

// clashMessage is the design's text: what is wrong, then the way out.
func clashMessage(user string, cl *clash) string {
	where := fmt.Sprintf("server %q is", cl.servers[0])
	if more := len(cl.servers) - 1; more > 0 {
		where = fmt.Sprintf("servers %q and %d more are", cl.servers[0], more)
	}
	return fmt.Sprintf("user %q: %s granted by %s and by %s; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user",
		user, where, sourceLabel(cl.first), sourceLabel(cl.second))
}

// sourceLabel names a grant source in a conflict: `access[2] with
// [from="10.0.0.0/8" no-pty]`, `access[5] with no options` or `its operator
// grant with no options`. Options print verbatim: each passed CheckOption.
func sourceLabel(s grantSource) string {
	with := "no options"
	if len(s.options) > 0 {
		with = "[" + strings.Join(s.options, " ") + "]"
	}
	if s.entry == implicitGrant {
		return "its operator grant with " + with
	}
	return fmt.Sprintf("access[%d] with %s", s.entry, with)
}
```

In `internal/config/policy.go`, `warnExpired` (`:65-76`): update its doc to "adds one load warning per desired key line, and per access: entry, whose expiry-time has passed" and append after the users loop:

```go
	for i, a := range c.Access {
		if authkeys.Expired(a.Options, now(), time.Local) {
			opt, _, _ := authkeys.EarliestExpiry(a.Options, time.Local)
			c.warn(ManifestWarning{Kind: WarnKeyExpired, Message: fmt.Sprintf("access[%d]: %s has passed; sshd no longer accepts the keys this entry grants", i, opt)})
		}
	}
```

- [ ] **Step 5: Run the package.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config`
Expected: PASS.

### Task 5: the schema sample, regenerate, `RemoveAccess`, `FuzzLoad`

**Files:**
- Modify: `cmd/sshepherd/schema_roundtrip_test.go:18-39` (`samples`), `internal/config/fuzz_test.go` (seeds, oracle)
- Create: `cmd/sshepherd/restrict_schema_test.go`, `internal/manifest/edit_options_test.go`

- [ ] **Step 1: The sample.** `TestSchemaRoundTripAdopt` and `TestSchemaRoundTripAppend` already fail since Task 2 (`config.Access.Options has no sample in schema_roundtrip_test.go`): run `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run SchemaRoundTrip` and see that message. In `samples` (`cmd/sshepherd/schema_roundtrip_test.go:37`) replace the `Access` entry with

```go
		// Options restricts bob's "*" grant (spec S7); bob's key line has no
		// options, and no other entry reaches bob, so nothing clashes.
		"Access": {"User": "bob", "Group": "", "Servers": []string{"*"}, "Except": []string{"web-1"}, "Options": []string{`from="10.0.0.0/8"`, "no-pty"}},
```

Re-run: PASS (`entryNode`, `internal/manifest/manifest.go:328`, emits the new field with no change; `requiredKeys` is untouched, so an entry without options writes none).

- [ ] **Step 2: Write the cmd tests.** Create `cmd/sshepherd/restrict_schema_test.go`:

```go
package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRegenerateWritesOptionsOnlyWhenSet (spec S7, Shared rules): a plain
// adopt carries a grant's options: verbatim and writes no options: key on an
// entry without them (DeepEqual cannot tell: an empty list loads as unset).
func TestRegenerateWritesOptionsOnlyWhenSet(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	cfg.Access = append(cfg.Access, config.Access{User: "bob", Servers: []string{"web-1"}})
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "options:"); n != 1 {
		t.Errorf("options: written %d times, want once (the sampled entry only):\n%s", n, out)
	}
	got, err := config.Parse(out)
	if err != nil || !reflect.DeepEqual(got.Access, cfg.Access) {
		t.Errorf("access changed (err %v):\n%s", err, out)
	}
}

// TestAdoptRegenerateKeepsGroupGrantOptions: a group entry's options:
// survive a plain adopt (spec S7 with S3b).
func TestAdoptRegenerateKeepsGroupGrantOptions(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	cfg.Groups = []config.Group{{Name: "web-team", Members: []string{"op", "bob"}}}
	entry := config.Access{Group: "web-team", Servers: []string{"web-1"}, Options: []string{"no-x11-forwarding"}}
	cfg.Access = append(cfg.Access, entry)
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err != nil || !reflect.DeepEqual(got.Access[len(got.Access)-1], entry) {
		t.Errorf("adopt lost the group entry's options (err %v):\n%s", err, out)
	}
}

// TestWideningGrantExitsThree (spec S7 Validation, D28): a grant option that
// widens access is a load error, exit 3 on every command.
func TestWideningGrantExitsThree(t *testing.T) {
	hermeticHome(t)
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1], options: [port-forwarding]}\n")
	const want = `access[0]: option "port-forwarding" does not restrict access; a grant can only add restrictions`
	for _, args := range [][]string{{"validate"}, {"audit"}, {"apply", "--dry-run"}, {"adopt"}} {
		var out, errBuf bytes.Buffer
		if code := run(append(args, "--config", cfg), &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), want) {
			t.Errorf("%v: exit = %d, stderr %s", args, code, errBuf.String())
		}
	}
}
```

Create `internal/manifest/edit_options_test.go`:

```go
package manifest

import (
	"slices"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRemoveAccessKeepsGrantOptions (spec S7): trimming a server from an
// entry with options: keeps them on what is left, after the except:
// RemoveAccess inserts right after servers:.
func TestRemoveAccessKeepsGrantOptions(t *testing.T) {
	f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\n"+
		"access:\n  - {user: bob, servers: [\"@web\", web-1], options: [no-pty]}\n")
	if _, err := f.RemoveAccess("bob", []string{"web-1"}); err != nil {
		t.Fatal(err)
	}
	out, cfg := encodeParsed(t, f)
	inOrder(t, out, `{user: bob, servers: ["@web"], except: [web-1], options: [no-pty]}`)
	if d := cfg.DesiredFor("web-2"); len(d) != 1 || !slices.Equal(d[0].Options, []string{"no-pty"}) {
		t.Errorf("web-2 desired = %+v, want bob with no-pty", d)
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'RegenerateWritesOptions|GroupGrantOptions|WideningGrant' && GOTOOLCHAIN=go1.27.3 go test ./internal/manifest -run RemoveAccessKeepsGrantOptions`
Expected: PASS — these pin behaviour Tasks 2 and 3 already built (the encoder and `RemoveAccess` need no code). Bite each once: delete the `Options` line from `samples` → `fill` fails; add `"options": true` to `requiredKeys["Access"]` → `TestRegenerateWritesOptionsOnlyWhenSet` fails (revert both).

- [ ] **Step 3: `FuzzLoad`.** In `internal/config/fuzz_test.go`, append to `seeds` (after the last `preserve:` seed):

```go
		// per-grant restrictions (spec S7): a group, a tag and an operator's
		// implicit grant clashing on s1; refused ones: a widening option, a
		// cert option, a key-line clash in another case, a repeated from=
		`
users:
  - {name: op, operator: true, keys: ["` + k1 + `"]}
  - {name: bob, keys: ['no-pty ` + k2 + `']}
groups:
  - {name: team, members: [op, bob]}
servers:
  - {name: s1, host: h1, user: u, tags: [prod]}
  - {name: s2, host: h2, user: u}
access:
  - {group: team, servers: ["@prod"], options: ['from="10.0.0.0/8"', restrict]}
  - {user: bob, servers: [s1, s2], options: [no-x11-forwarding]}
`,
		"users:\n  - {name: a, keys: ['FROM=\"1.2.3.4\" " + k1 + "']}\nservers:\n  - {name: s, host: h, user: u}\naccess:\n  - {user: a, servers: [s], options: [pty, cert-authority, 'from=\"a\"', 'from=\"b\"']}\n",
		// a tombstone blocks a fleet-wide operator's restricted group grant
		// on s1: the implicit grant still renders it there (checkGrantOptions'
		// sources-equal-render rule; mutant G10b)
		`
users:
  - {name: op, operator: true, keys: ["` + k1 + `"]}
groups:
  - {name: ops, members: [op]}
servers:
  - {name: s1, host: h1, user: u}
  - {name: s2, host: h2, user: u}
access:
  - {group: ops, servers: ["*"], options: [restrict]}
revoked:
  - {user: op, servers: [s1], date: 2026-11-10}
`,
```

In the `f.Fuzz` body's `for _, s := range cfg.Servers` loop, after `checkPreserve(t, cfg, s)`, add `checkGrantOptions(t, cfg, s)`, and append the oracle after `checkPreserve`:

```go
// checkGrantOptions (spec S7): on an accepted server each desired key keeps
// its key line's options as a prefix and adds only restrictions, the whole
// line passes OptionIssue, and a user with keys renders there exactly when a
// grant source reaches it.
func checkGrantOptions(t *testing.T, cfg *Config, s Server) {
	t.Helper()
	desired := cfg.DesiredFor(s.Name)
	for _, k := range desired {
		u, _ := cfg.OwnerOf(k.Fingerprint) // checkRenderRoundTrip already proved an owner
		i := slices.IndexFunc(cfg.keysByUser[u.Name], func(l authkeys.Key) bool { return l.Fingerprint == k.Fingerprint })
		line := cfg.keysByUser[u.Name][i].Options
		if len(k.Options) < len(line) || !slices.Equal(k.Options[:len(line)], line) {
			t.Fatalf("server %q: %s renders %q, which does not start with its key line's %q", s.Name, k.Fingerprint, k.Options, line)
		}
		for _, o := range k.Options[len(line):] {
			if !authkeys.IsRestriction(o) {
				t.Fatalf("server %q: a grant added %q, which is not a restriction", s.Name, o)
			}
		}
		if err := authkeys.OptionIssue(k.Options); err != nil {
			t.Fatalf("server %q: rendered options %q: %v", s.Name, k.Options, err)
		}
	}
	for _, u := range cfg.Users {
		keys := cfg.keysByUser[u.Name]
		if len(keys) == 0 {
			continue
		}
		rendered := slices.ContainsFunc(desired, func(k authkeys.Key) bool { return k.Fingerprint == keys[0].Fingerprint })
		if reached := len(cfg.grantSources(u.Name, s)) > 0; reached != rendered {
			t.Fatalf("server %q: user %q reached by a grant source = %v, rendered = %v", s.Name, u.Name, reached, rendered)
		}
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run FuzzLoad && GOTOOLCHAIN=go1.27.3 go test ./internal/config -run '^$' -fuzz '^FuzzLoad$' -fuzztime 60s`
Expected: PASS, no crasher. `git status --short -- 'internal/config/testdata'` lists nothing (in-code seeds only).

### Task 6: mutation run, `make check`, hand back

- [ ] **Step 1: Mutants** (one at a time; run `GOTOOLCHAIN=go1.27.3 go test ./internal/config ./internal/authkeys ./internal/manifest ./cmd/sshepherd -run 'Restriction|SameOptions|Grant|Clash|Keyless|Blocked|KeysOnNeverShares|OfferOrderSees|FlatTwin|Regenerate|RemoveAccessKeeps|SchemaRoundTrip|Widening|FuzzLoad'`, which runs `FuzzLoad`'s seeds through the oracle; record killed/survived; revert):

| # | Mutant | Expected killer |
|---|---|---|
| G1 | `IsRestriction` drops `!s.certOnly` | `TestIsRestrictionIsTheSpecList`, `TestGrantOptionValidation/cert-authority` |
| G2 | `IsRestriction` returns `s.effect != loosens` | `TestIsRestriction` (`environment`), `TestGrantOptionValidation/a neutral option` |
| G3 | `optionSet` without `strings.ToLower` | `TestSameOptions/name case`, `TestRestrictionConflict/order and name case…` |
| G4 | `optionSet` without `slices.Sort` | `TestSameOptions/order` |
| G5 | `optionSet` without `slices.Compact` | `TestSameOptions/a repeat` |
| G6 | `keyLineClash` compares names with `==` instead of `FindOption` | `TestGrantOptionValidation/the same name in another case`, `/a member's key line…` |
| G7 | `grantOptionErrors` drops the `OptionIssue(a.Options)` check | `TestGrantOptionValidation/a repeated from= in one grant` |
| G8 | `grantOptionErrors` checks only `a.User`'s keys (not `entryUsers`) | `TestGrantOptionValidation/a member's key line through a group` |
| G9 | `grantSources` omits the implicit grant | `TestRestrictionConflict/an operator's implicit grant`, `TestClashedPairRendersFirstSource` |
| G10 | `grantSources` ignores `c.blocked` | `TestBlockedGrantCannotClash`; `FuzzLoad` oracle |
| G10b | `grantSources` returns nil on a blocked pair before the implicit grant | `TestBlockedOperatorStillRenders` (the `grantSources` assertion; its render and clash halves cannot see it); `FuzzLoad` oracle through the blocked-operator seed |
| G11 | `grantSources` uses `a.User == user` | `TestGroupGrantOptionsMatchFlatTwin`, `TestRestrictionConflict/a group and…` |
| G12 | `keysOn` returns `keys` unchanged | `TestGrantOptionsRenderPerServer`, `TestOfferOrderSeesGrantOptions` |
| G13 | `keysOn` appends in place (`append(k.Options, …)`) | `TestKeysOnNeverSharesOptions` (the parsed-line check in `TestGrantOptionsRenderPerServer` cannot see it: the parsed slice's length never changes) |
| G14 | `keysOn` uses the last source | `TestClashedPairRendersFirstSource` |
| G15 | `c.optioned` never set | every render and conflict test |
| G16 | `firstClash` returns `src[i-1], src[i]` (comparing `src[i-1]` with `src[i]` is equivalent: `SameOptions` is an equivalence and every earlier source matched `src[0]`) | `TestRestrictionConflict/three sets…` (names `access[1] with [NO-PTY]`) |
| G17 | `clashMessage` drops the "and N more" branch | `TestRestrictionConflict/several servers` |
| G18 | `restrictionConflicts` drops the keyless skip | `TestKeylessUserNeverClashes` |
| G19 | `warnExpired` drops the access loop | `TestGrantExpiryWarns` |
| G20 | `keyLineClash` drops the combined `OptionIssue` | **equivalent** (plan gap 8): record it |
| G21 | `computeConflicts` drops `restrictionConflicts()` | every `TestRestrictionConflict` row with a want |
| G22 | `SameOptions` starts with `if (a == nil) != (b == nil) { return false }` | `TestSameOptions/both empty`, `TestRestrictionConflict/an empty list is no options`, `TestEmptyGrantOptions` |
| G23 | `userClashes` records a server under every disagreeing pair, not only the first | `TestRestrictionConflict/a pair is named only where it is the first disagreement` |

- [ ] **Step 2: `make check`.** Run `make check`. Expected: green (`deadcode`: `IsRestriction` is called by `grantOptionIssue`, `SameOptions` by `firstClash`; `make layering` and depguard: `internal/config` imports nothing new).

- [ ] **Step 3: Hand back** with the mutation table and this docsDelta:

```text
docsDelta (lane grants):
README.md
1. "## The manifest": a new "### Per-grant restrictions" subsection after "### Groups" (anchor
   #per-grant-restrictions). Lead with the design's YAML example (deploy, @prod with
   from="10.0.0.0/8" and no-pty, staging-1 with none). Then: the options are added to the key line
   on the servers that entry grants (the key line's options first); a grant can only narrow
   access, so to vary a restriction per server leave it off the key line and put it on the grants;
   allowed: command=, expiry-time=, from=, no-agent-forwarding, no-port-forwarding, no-pty,
   no-user-rc, no-x11-forwarding, permitlisten=, permitopen=, restrict, verify-required;
   cert-authority and principals= are refused. A group entry's options reach every member.
   A fleet-wide operator's implicit grant adds none (to restrict an operator's key per grant,
   give it its own servers: ["*"] entry with options:, which replaces the implicit grant).
   Lines a preserve: rule keeps are never restricted. Two grants that give one key different
   options on one server are a policy conflict (see Validation rules); its wording is shown
   under sshepherd audit.
2. "### Validation rules": a new bullet "**Grant `options:`**" listing the load errors with the
   texts of TestGrantOptionValidation's want column (internal/config/restrict_test.go), the
   0-based access[N] index, and: "A clash between two grants is not a load error but a policy
   conflict (restriction_conflict): the manifest loads and every command reports it."
3. "### `sshepherd validate`": a restriction conflict is a policy conflict: exit 3, valid: false,
   listed in policy_conflicts (kind restriction_conflict, user, servers; no fingerprint).
4. The load-error paragraph under "## Exit codes" (after the tag/group one): "A bad grant
   options: entry (an option sshd rejects, one that widens access, cert-authority or principals=,
   a repeated once-only clause, or a name already on a key line the entry reaches) is a load
   error: exit 3 on every command."

CLAUDE.md
1. Status: a new paragraph after the S6 one: "**Per-grant restrictions** (P10 S7, D22 = B, OP5,
   OP6, PRD-6; section S7 of docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md,
   planned in docs/superpowers/plans/2026-11-10-p10-s7-restrictions.md): access: entries take
   options: (restricting options only, authkeys.IsRestriction; no name already on a reached key
   line, compared through FindOption), appended after the key line's options on the servers the
   entry grants (config.keysOn over grantSources: a fleet-wide operator's implicit grant first,
   then entries in order; none for a blocked pair or a jump_only server), so DesiredFor returns
   per-server copies and audit drift, apply.Affected, Survivors, OfferOrder, the Loosens
   highlight and S5's forwarding guard follow with no code. Two grant sources giving one key
   different sets on one server (authkeys.SameOptions: order, repeats and name case ignored)
   are a D29 policy conflict, kind restriction_conflict, one per user and pair of sources with
   every server where they disagree; a blocked grant and a keyless user never clash. A grant's
   passed expiry-time= warns (key_expired). FuzzLoad's checkGrantOptions oracle pins the
   prefix, restrictions-only and sources-equal-render rules."
```

---

## Round 2 — lane `audit` (Tasks 7–8)

Lane `audit` owns `internal/audit/*` (testdata included) and `internal/config/clashed.go`, `internal/config/clashed_test.go`. `needsIntegration: false`. It builds on round 1 only.

### Task 7: `ClashedKeys` and the skipped options comparison

**Files:**
- Create: `internal/config/clashed.go`, `internal/config/clashed_test.go`, `internal/audit/restrict_test.go`, `internal/audit/testdata/report_restriction_conflict.golden`, `internal/audit/testdata/report_restriction_conflict.golden.json`
- Modify: `internal/audit/audit.go:27-65` (`ServerResult`), `:96-99` (`optionsDrift`), `:138-141` (`auditOne`)

- [ ] **Step 1: Write the failing config test.** Create `internal/config/clashed_test.go`:

```go
package config

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestClashedKeys (spec S7 Mechanics): every key of a user a restriction
// conflict names on a server, and nothing for other servers or other kinds.
func TestClashedKeys(t *testing.T) {
	cfg := mustParse(t, `users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`", "`+testkeys.Line(t, 5)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [web]}
access:
  - {user: alice, servers: ["@web"], options: [no-pty]}
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: [web-1, web-2]}
revoked:
  - {user: bob, servers: [web-2], date: 2026-11-10}
`)
	got := cfg.ClashedKeys("web-1")
	a1, a2 := fpOfLine(t, testkeys.Line(t, 1)), fpOfLine(t, testkeys.Line(t, 5))
	if len(got) != 2 || !got[a1] || !got[a2] {
		t.Errorf("web-1 = %v, want both of alice's keys", got)
	}
	// web-2: bob's revoked_access conflict names it, alice's clash does not.
	if got := cfg.ClashedKeys("web-2"); got != nil {
		t.Errorf("web-2 = %v, want nil", got)
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run TestClashedKeys`
Expected: build failure (`cfg.ClashedKeys undefined`).

- [ ] **Step 2: Implement it.** Create `internal/config/clashed.go`:

```go
package config

import "slices"

// ClashedKeys lists the fingerprints a restriction conflict names on server
// (spec 2026-11-08 S7 Mechanics): every key of each user whose grants there
// disagree. Audit skips their options comparison, because there is no one
// desired set; presence is still compared. Nil when no restriction conflict
// names server.
func (c *Config) ClashedKeys(server string) map[string]bool {
	var out map[string]bool
	for _, cf := range c.conflicts {
		if cf.Kind != ConflictRestriction || !slices.Contains(cf.Servers, server) {
			continue
		}
		if out == nil {
			out = make(map[string]bool)
		}
		for _, k := range c.keysByUser[cf.User] {
			out[k.Fingerprint] = true
		}
	}
	return out
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config -run TestClashedKeys` → PASS.

- [ ] **Step 3: Write the failing audit tests.** Create `internal/audit/restrict_test.go`:

```go
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// restrictCfg (spec S7): alice (k1) is granted @web with no-pty and web-1
// again with none, a restriction conflict on web-1 only; bob (k2) is granted
// both servers, carol (k3) web-1. web-2 renders alice's key with no-pty.
func restrictCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
access:
  - {user: alice, servers: ["@web"], options: [no-pty]}
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: [web-1, web-2]}
  - {user: carol, servers: [web-1]}
`))
	if err != nil {
		t.Fatalf("restrictCfg: %v", err)
	}
	return cfg
}

// restrictReader: web-1 holds alice with restrict (neither grant's set), bob
// with no-pty (drift: no grant gives bob options) and an unknown key k9;
// carol is missing. web-2 holds alice plain (drift: the manifest wants
// no-pty there) and bob.
func restrictReader(t *testing.T) *fakeReader {
	t.Helper()
	return &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: content("restrict "+testkeys.Line(t, 1), "no-pty "+testkeys.Line(t, 2), testkeys.Line(t, 9))},
		"web-2": {Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2))},
	}}
}

// TestRestrictionConflictAudit (spec S7 audit row): the conflict prints as
// critical and makes web-1 critical (exit 2); on web-1 the options
// comparison is skipped for alice only, while bob's drift, carol's missing
// key and the unknown key are still reported; web-2 compares alice against
// its own grant (no-pty).
func TestRestrictionConflictAudit(t *testing.T) {
	cfg := restrictCfg(t)
	results := Run(context.Background(), cfg, restrictReader(t), Options{Parallel: 2})
	if code := ExitCode(cfg, results); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
	if got, want := criticalReasons(cfg, results[0]), []string{"policy_conflict"}; !reflect.DeepEqual(got, want) {
		t.Errorf("web-1 criticalReasons = %v, want %v", got, want)
	}
	if s := statusOf(cfg, results[1]); s != statusDrift {
		t.Errorf("web-2 status = %s, want drift (alice lacks no-pty)", s)
	}
	for _, k := range results[0].Diff.OK { // the desired form; fpOf: internal/audit/audit_test.go:426
		if _, _, drifted := results[0].optionsDrift(k); drifted && k.Fingerprint == fpOf(t, 1) {
			t.Error("web-1: alice's options were compared despite the clash")
		}
	}
	if len(results[0].Diff.Missing) != 1 || len(results[0].Diff.Unauthorized) != 1 {
		t.Errorf("web-1 missing %d, unauthorized %d; want 1 and 1", len(results[0].Diff.Missing), len(results[0].Diff.Unauthorized))
	}

	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	if strings.Count(out, "OPTIONS DIFFER") != 2 { // bob on web-1, alice on web-2
		t.Errorf("want two OPTIONS DIFFER rows:\n%s", out)
	}
	if !strings.Contains(out, `manifest: user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[1] with no options`) {
		t.Errorf("the conflict is not printed:\n%s", out)
	}
	checkGolden(t, "report_restriction_conflict.golden", buf.Bytes())

	got := renderJSON(t, cfg, results)
	checkGolden(t, "report_restriction_conflict.golden.json", got)
	var doc struct {
		PolicyConflicts []map[string]any `json:"policy_conflicts"`
		Servers         []struct {
			Name string `json:"name"`
			Keys struct {
				Present []struct {
					Owner        *string         `json:"owner"`
					OptionsDrift json.RawMessage `json:"options_drift"`
				} `json:"present"`
			} `json:"keys"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.PolicyConflicts) != 1 || doc.PolicyConflicts[0]["kind"] != "restriction_conflict" ||
		doc.PolicyConflicts[0]["user"] != "alice" || doc.PolicyConflicts[0]["fingerprint"] != nil {
		t.Errorf("policy_conflicts = %+v", doc.PolicyConflicts)
	}
	drift := map[string]bool{}
	for _, s := range doc.Servers {
		for _, k := range s.Keys.Present {
			if k.Owner != nil && k.OptionsDrift != nil {
				drift[s.Name+"/"+*k.Owner] = true
			}
		}
	}
	if want := map[string]bool{"web-1/bob": true, "web-2/alice": true}; !reflect.DeepEqual(drift, want) {
		t.Errorf("options_drift on %v, want %v", drift, want)
	}
}

// TestRestrictionConflictUnderServer (OP4): an audit restricted to web-2
// still prints the conflict about web-1 and still exits 2.
func TestRestrictionConflictUnderServer(t *testing.T) {
	cfg := restrictCfg(t)
	results := Run(context.Background(), cfg, restrictReader(t), Options{Parallel: 1, Servers: []config.Server{cfg.Servers[1]}})
	if len(results) != 1 || ExitCode(cfg, results) != 2 {
		t.Fatalf("results = %d, ExitCode = %d; want 1 and 2", len(results), ExitCode(cfg, results))
	}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	if !strings.Contains(buf.String(), `user "alice": server "web-1" is granted by`) {
		t.Errorf("the conflict about web-1 is missing:\n%s", buf.String())
	}
}

// TestGrantOptionsDriftPerServer (spec S7 Tests): with no clash, audit
// compares each server against its own grant's options.
func TestGrantOptionsDriftPerServer(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1], options: ['from="10.0.0.0/8"']}
  - {user: alice, servers: [web-2]}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: content(`from="10.0.0.0/8" ` + testkeys.Line(t, 1))},
		"web-2": {Content: content(`from="10.0.0.0/8" ` + testkeys.Line(t, 1))},
	}}
	results := Run(context.Background(), cfg, r, Options{Parallel: 2})
	if !results[0].Compliant() || results[1].Compliant() {
		t.Errorf("compliant = %v, %v; want web-1 only (web-2 grants alice no options)", results[0].Compliant(), results[1].Compliant())
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit -run 'RestrictionConflict|GrantOptionsDriftPerServer'`
Expected: FAIL — `TestRestrictionConflictAudit` reports three `OPTIONS DIFFER` rows and `options_drift` on `web-1/alice` (the goldens do not exist yet either). `TestRestrictionConflictUnderServer` and `TestGrantOptionsDriftPerServer` pass already (round 1 and S1 built them): they pin OP4 and the per-server comparison.

- [ ] **Step 4: Implement.** In `internal/audit/audit.go`, `ServerResult` (after `External`, `:64`) gains

```go
	// Clashed holds the fingerprints a restriction conflict names on this
	// server (config.ClashedKeys, spec 2026-11-08 S7): their options are not
	// compared, in text, JSON or Compliant, because the grants disagree on
	// what they should be. Presence is still compared.
	Clashed map[string]bool
```

`auditOne` (`:138`): after `res.NoUsersGranted = len(desired) == 0` add `res.Clashed = cfg.ClashedKeys(srv.Name)`. `optionsDrift` (`:96-99`) becomes:

```go
func (r ServerResult) optionsDrift(k authkeys.Key) (actual, desired []string, drifted bool) {
	actual = r.Diff.Actual[k.Fingerprint].Options
	if r.Clashed[k.Fingerprint] {
		return actual, k.Options, false // no one desired set (spec S7)
	}
	return actual, k.Options, !slices.Equal(actual, k.Options)
}
```

and its doc comment gains: "A key a restriction conflict names here (Clashed) never drifts."

- [ ] **Step 5: Goldens.** Run `GOTOOLCHAIN=go1.27.3 go test ./internal/audit -run TestRestrictionConflictAudit -update`, then `git status --short -- '*testdata*'` (only the two new `report_restriction_conflict` files), and read both back: one `‼ manifest: user "alice": server "web-1" is granted by …` line marked `CRITICAL: policy conflict`; web-1 critical with alice's row `present & authorized`, bob's `OPTIONS DIFFER`, carol `MISSING`, the unknown key; web-2 drift with alice's `OPTIONS DIFFER (… manifest: "no-pty")`. In the JSON: `policy_conflicts` holds one object with `kind`, `message`, `user`, `servers` and no `fingerprint`; web-1's `critical_reasons` is `["policy_conflict"]`. Re-run without `-update`: PASS.

- [ ] **Step 6: The package and the byte-identity check.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit ./internal/config && git diff --stat -- internal/audit/testdata`
Expected: PASS, and the diff lists no existing golden (S7 changes no report without a clash).

### Task 8: mutation run, `make check`, hand back

- [ ] **Step 1: Mutants** (one at a time, `GOTOOLCHAIN=go1.27.3 go test ./internal/audit ./internal/config -run 'Clash|Restriction|GrantOptionsDrift'`):

| # | Mutant | Expected killer |
|---|---|---|
| A1 | `optionsDrift` ignores `r.Clashed` | `TestRestrictionConflictAudit` (count, `web-1/alice`) |
| A2 | `ClashedKeys` ignores the `Servers` check | `TestClashedKeys` (web-2), `TestRestrictionConflictAudit` (`web-2/alice` missing) |
| A3 | `ClashedKeys` ignores the kind | `TestClashedKeys` (bob's `revoked_access` on web-2) |
| A4 | `auditOne` never sets `Clashed` | `TestRestrictionConflictAudit` |
| A5 | `ClashedKeys` adds only the user's first key | `TestClashedKeys` (two keys) |

- [ ] **Step 2: `make check`.** Expected: green (`deadcode`: `ClashedKeys` is called by `auditOne`).

- [ ] **Step 3: Hand back** with the mutation table and this docsDelta:

```text
docsDelta (lane audit):
README.md
1. "### Per-grant restrictions" (added by lane grants): end its clash paragraph with the conflict
   line copied from internal/audit/testdata/report_restriction_conflict.golden (the "‼ manifest:"
   line), and the several-servers and operator wordings from TestRestrictionConflict's want column
   (internal/config/restrict_test.go): `servers "web-1" and 1 more are granted by` and
   `by its operator grant with no options`.
2. "### `sshepherd audit`": options drift is judged per server, against the options that server's
   grant renders; a restriction conflict prints in the manifest block as critical, marks every
   server it names critical (exit 2, also under --server when it names only other servers), and
   skips the options comparison for that user's keys on those servers (presence, missing and
   unauthorized keys are still reported). JSON: the conflict is a policy_conflicts object with
   kind restriction_conflict, user and servers and no fingerprint (copy it from
   report_restriction_conflict.golden.json); critical_reasons on those servers carries
   policy_conflict.
3. "## Exit codes", audit column, row 2: "a policy conflict (including a granted weak key or a
   restriction conflict)".

CLAUDE.md
1. Status, append to the S7 paragraph: "Audit fills ServerResult.Clashed from
   Config.ClashedKeys and optionsDrift skips those keys (text, JSON, Compliant); the conflict
   itself rides the existing policy_conflicts path (critical, exit 2, OP4 under --server)."
```

---

## Round 2 — lane `write` (Tasks 9–13)

Lane `write` owns `internal/apply/plan.go`, `internal/apply/serial.go`, `internal/apply/predicates.go`, `internal/apply/predicates_test.go`, `internal/apply/restrict_test.go`, `internal/apply/testdata/render_grant_options.golden`, `internal/apply/testdata/plan_restriction_conflict.golden`, `cmd/sshepherd/conflicts.go`, `cmd/sshepherd/editrun.go`, `cmd/sshepherd/run.go`, `cmd/sshepherd/testdata/help/{apply,revoke,rotate,adopt,import}.golden`, `cmd/sshepherd/restrict_save_test.go`, `cmd/sshepherd/restrict_hermetic_test.go`. `needsIntegration: false`. It builds on round 1 only. It never edits `internal/apply/{report,json}.go`, `Normalize`, `normalize` or `nonKeyLines` (F1's lines), nor `cmd/sshepherd/{adopt,import}.go` (gap 2).

### Task 9: a clashed server is refused, save-neutral

**Files:**
- Modify: `internal/apply/plan.go:104-112` (`ServerPlan`, after `WeakRefused`), `:249-271` (`planOne`); `internal/apply/serial.go:136-141` (`conflictRefusal`); `internal/apply/predicates.go:23-38` (`NothingCanLand`)
- Test: `internal/apply/predicates_test.go`, `internal/apply/restrict_test.go` (new), `cmd/sshepherd/restrict_save_test.go` (new)

- [ ] **Step 1: Write the failing tests.** In `internal/apply/predicates_test.go`, `TestNothingCanLand`'s table gains two rows after the weak-key ones:

```go
		{"only clash refusals do not withhold the save (OP6)", []ServerPlan{{Class: ClassRefused, ClashRefused: true}, {Class: ClassRefused, ClashRefused: true}}, false},
		{"a clash refusal beside another refusal still withholds", []ServerPlan{{Class: ClassRefused, ClashRefused: true}, p(ClassRefused)}, true},
```

Create `internal/apply/restrict_test.go` (later tasks append to it):

```go
package apply

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// clashText is the restriction conflict clashCfg holds (spec S7 wording).
const clashText = `user "alice": server "web-1" is granted by access[0] with [no-pty] and by access[1] with no options; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user`

// clashCfg (spec S7): op (k1, operator, held); alice (k2) is granted @web
// with no-pty and web-1 again with none, a restriction conflict on web-1
// only. extra is appended verbatim (a revoked: section).
func clashCfg(t *testing.T, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
access:
  - {user: alice, servers: ["@web"], options: [no-pty]}
  - {user: alice, servers: [web-1]}
` + extra))
	if err != nil {
		t.Fatalf("clashCfg: %v", err)
	}
	return cfg
}

// opOnly serves the operator's key alone on both servers.
func opOnly(t *testing.T) *fakeReader {
	t.Helper()
	body := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n")}
	return &fakeReader{byName: map[string]fleet.ReadResult{"web-1": body, "web-2": body}}
}

// TestClashRefusesOnlyItsServers (spec S7 apply row, OP6): web-1 is refused
// with the conflict text and is save-neutral; web-2 is planned.
func TestClashRefusesOnlyItsServers(t *testing.T) {
	plans := buildPlans(t, clashCfg(t, ""), opOnly(t), []string{fp(t, 1)})
	p := planFor(t, plans, "web-1")
	if p.Class != ClassRefused || p.Refusal != clashText || !p.ClashRefused || p.WeakRefused {
		t.Errorf("web-1 = %s %q clash=%v weak=%v", p.Class, p.Refusal, p.ClashRefused, p.WeakRefused)
	}
	if q := planFor(t, plans, "web-2"); q.Class != ClassChange {
		t.Errorf("web-2 = %s %q, want a change", q.Class, q.Refusal)
	}
	if NothingCanLand([]ServerPlan{p}) {
		t.Error("a clash alone withholds an edit's save; OP6 says revoke and rotate still save")
	}
}

// TestRevokedKindOutranksClash: a server that a revoked-kind conflict and a
// clash both name is refused by the revoked kind, which still withholds a
// save, exactly as before S7. It pins today's precedence and bites only
// under mutant W3.
func TestRevokedKindOutranksClash(t *testing.T) {
	cfg := clashCfg(t, "revoked:\n  - {user: alice, servers: [web-1], date: 2026-11-10}\n")
	p := planFor(t, buildPlans(t, cfg, opOnly(t), []string{fp(t, 1)}), "web-1")
	if p.Class != ClassRefused || p.ClashRefused || !strings.Contains(p.Refusal, "revoked[0] removed that access") {
		t.Errorf("web-1 = %s %q clash=%v", p.Class, p.Refusal, p.ClashRefused)
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'NothingCanLand|ClashRefuses|RevokedKindOutranks'`
Expected: build failure (`unknown field ClashRefused`). `TestRevokedKindOutranksClash` is not a failing-first test: once the field exists it passes on today's code (the revoked-kind refusal already wins, and `ClashRefused` stays false); it guards the precedence against W3.

Then create `cmd/sshepherd/restrict_save_test.go` (Task 11 and Task 12 append to it) with the OP6 CLI tests, so they are seen failing before the cmd half of the rule exists:

```go
package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// clashPushFleet is one server a restriction conflict holds: alice (key 1,
// held) and bob (key 3) are granted web-1, and deploy (key 2) twice with
// different options. The server holds all three keys.
func clashPushFleet(t *testing.T) (kh, cfg string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	host := hosts["web-1"]
	host.install(t, []byte{1, 2, 3})
	y := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: deploy, keys: [" + qk(t, 2) + "]}\n  - {name: bob, keys: [" + qk(t, 3) + "]}\n" +
		"servers:\n" + host.line("web-1") +
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: deploy, servers: [web-1], options: [no-pty]}\n" +
		"  - {user: deploy, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n"
	return kh, writeConfig(t, y)
}

// checkSavedClashRefused runs an edit whose only server a restriction
// conflict holds: the edit saves (OP6), the push is refused there, exit 1.
func checkSavedClashRefused(t *testing.T, args []string, cfg string) {
	t.Helper()
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run(args, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if strings.Contains(errBuf.String(), "nothing saved") || bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("the edit was not saved\nstderr: %s", errBuf.String())
	}
	want := `REFUSED: user "deploy": server "web-1" is granted by access[1] with [no-pty] and by access[2] with no options`
	if !strings.Contains(out.String(), want) {
		t.Errorf("the push was not refused over the clash:\n%s", out.String())
	}
}

// TestRevokeSavesOverRestrictionClash (OP6): a leaver's revoke saves while
// a clash holds its only server; the push is refused there.
func TestRevokeSavesOverRestrictionClash(t *testing.T) {
	kh, cfg := clashPushFleet(t)
	checkSavedClashRefused(t, []string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
	if _, ok := readCfg(t, cfg).Revoked(fpOf(t, 3)); !ok {
		t.Error("bob's tombstone was not saved")
	}
}

// TestRotateSavesOverRestrictionClash (OP6): rotate saves too.
func TestRotateSavesOverRestrictionClash(t *testing.T) {
	kh, cfg := clashPushFleet(t)
	checkSavedClashRefused(t, []string{"rotate", "bob", "--old", fpOf(t, 3), "--new", testkeys.Line(t, 5), "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
}

// TestRevokeJSONSavesOverRestrictionClash (OP6; owner rule: schema 1,
// additive): the --json document of a revoke that saves while a clash holds
// its only server says so: edit.saved, the server refused, and the conflict
// as a restriction_conflict with no fingerprint.
func TestRevokeJSONSavesOverRestrictionClash(t *testing.T) {
	kh, cfg := clashPushFleet(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"revoke", "bob", "--yes", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	var doc struct {
		Schema int `json:"schema"`
		Edit   struct {
			Saved bool `json:"saved"`
		} `json:"edit"`
		Summary struct {
			Refused int `json:"refused"`
		} `json:"summary"`
		PolicyConflicts []map[string]any `json:"policy_conflicts"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || code != 1 {
		t.Fatalf("exit = %d, want 1 with a document (err %v)\nstdout: %s\nstderr: %s", code, err, out.String(), errBuf.String())
	}
	if doc.Schema != 1 || !doc.Edit.Saved || doc.Summary.Refused != 1 || len(doc.PolicyConflicts) != 1 ||
		doc.PolicyConflicts[0]["kind"] != "restriction_conflict" || doc.PolicyConflicts[0]["fingerprint"] != nil {
		t.Errorf("document:\n%s", out.String())
	}
}

// TestRevokeSweepOverRestrictionClash (OP6, D28): the leaver's key stays on
// the server the clash holds, so --sweep finds it there: exit 2, and the
// tombstone is saved.
func TestRevokeSweepOverRestrictionClash(t *testing.T) {
	kh, cfg := clashPushFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if _, ok := readCfg(t, cfg).Revoked(fpOf(t, 3)); !ok {
		t.Error("bob's tombstone was not saved")
	}
	if want := "REVOKED KEY STILL INSTALLED: bob " + fpOf(t, 3) + " on web-1"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'SavesOverRestrictionClash|SweepOverRestrictionClash'`
Expected: FAIL, all four: exit 3 with `refusing to write the manifest — it would keep 1 policy conflict: user "deploy": server "web-1" is granted by …` (round 1's cmd `conflictRefusal`, which refuses every non-weak kind; the JSON test gets no document). They stay failing after Step 2, because `editPrelude` still refuses; they pass after Task 11. Task 9's own half (`ClashRefused`) is pinned by mutants W1 and W2 against them.

- [ ] **Step 2: Implement.** In `internal/apply/plan.go`, `ServerPlan` gains after `WeakRefused`:

```go
	// ClashRefused marks a refusal by a restriction conflict alone (spec
	// 2026-11-08 S7, OP6). Like WeakRefused it never withholds an edit's
	// save: revoke and rotate never add a grant, and a leaver's revoke must
	// save while a clash holds the server. Unlike a weak-key refusal it has
	// no removal-only exception: the server is held even for a revoke.
	ClashRefused bool
```

In `planOne`, right after the `conflictRefusal` block (`:264-270`) and before `p.Kept = len(r.External)`:

```go
	if refusal := restrictionRefusal(cfg, r.Server.Name); refusal != "" {
		p.Class, p.Refusal, p.ClashRefused = ClassRefused, refusal, true
		return p, nil
	}
```

In `internal/apply/serial.go`, replace `conflictRefusal` (`:136-141`) with:

```go
// conflictRefusal is the refusal text for a server a revoked-kind policy
// conflict names (D29): each conflict's message, joined; "" when none names
// it. Weak-key conflicts have their own rule, weakRefusal; restriction
// conflicts theirs, restrictionRefusal.
func conflictRefusal(cfg *config.Config, server string) string {
	return conflictMessages(cfg, server, func(kind string) bool {
		return kind != config.ConflictWeakKey && kind != config.ConflictRestriction
	})
}

// restrictionRefusal is the refusal text for a server a restriction conflict
// names (spec S7, OP6), "" when none does. planOne marks it ClashRefused, so
// it never withholds a revoke's or rotate's save.
func restrictionRefusal(cfg *config.Config, server string) string {
	return conflictMessages(cfg, server, func(kind string) bool { return kind == config.ConflictRestriction })
}
```

In `internal/apply/predicates.go`, `NothingCanLand`'s doc reads "…at least one is refused for a reason other than a weak-key or restriction conflict. Unreachable servers can converge later, and neither of those refusals may withhold the save (OP4, OP6)." and its loop line becomes:

```go
			refused = refused || !(p.WeakRefused || p.ClashRefused)
```

- [ ] **Step 3: Run them and see them pass.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply`
Expected: PASS. (The four cmd tests of Step 1 still fail until Task 11.)

### Task 10: apply composes with grant options

Every test in this task pins behaviour round 1 already built (the render and every guard read `DesiredFor`), except the two goldens, which are new files. Each step says how to see it bite.

**Files:**
- Test: `internal/apply/restrict_test.go`; create `internal/apply/testdata/render_grant_options.golden`, `internal/apply/testdata/plan_restriction_conflict.golden`

- [ ] **Step 1: Append the tests** to `internal/apply/restrict_test.go`, adding `"bytes"`, `"slices"` and `"github.com/javadh75/SSHepherd/internal/authkeys"` to its imports:

```go
// TestRenderGrantOptionsGolden (spec S7 Render): a group grant restricts its
// members on web-1, alice's own web-2 grant adds nothing to her key line's
// option, and bob's db-1 grant restricts him there; the operator's implicit
// grant adds none.
func TestRenderGrantOptionsGolden(t *testing.T) {
	got := renderFleet(t, `users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: alice, keys: ['no-agent-forwarding `+testkeys.Line(t, 2)+`']}
  - {name: bob, keys: ["`+testkeys.Line(t, 3)+`"]}
groups:
  - {name: team, members: [alice, bob]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  - {group: team, servers: ["@web"], except: [web-2], options: ['from="10.0.0.0/8"', no-pty]}
  - {user: alice, servers: [web-2]}
  - {user: bob, servers: [db-1], options: [restrict, 'permitopen="db:5432"']}
`)
	for server, line := range map[string]string{
		"web-1": `no-agent-forwarding,from="10.0.0.0/8",no-pty ` + testkeys.Line(t, 2) + " alice",
		"web-2": "no-agent-forwarding " + testkeys.Line(t, 2) + " alice",
		"db-1":  `restrict,permitopen="db:5432" ` + testkeys.Line(t, 3) + " bob",
	} {
		if block := fleetBlock(t, got, server); !strings.Contains(block, line+"\n") {
			t.Errorf("%s lacks %q:\n%s", server, line, block)
		}
	}
	checkGolden(t, "render_grant_options.golden", got)
}

// TestGrantOptionsForwardGuard (spec S7 Tests, with S5's guard): a grant
// restriction on the held operator key at a managed bastion is judged like
// a key-line one; a restriction on the dependents is not.
func TestGrantOptionsForwardGuard(t *testing.T) {
	const refusal = "none of the surviving keys you hold may forward through bastion-eu (no-port-forwarding, restrict or permitopen=); this write would cut off web-1 and 1 more"
	for _, tt := range []struct {
		name, opts string
		refused    bool
	}{
		{"no-port-forwarding", "no-port-forwarding", true},
		{"restrict", "restrict", true},
		{"permitopen for one dependent only", `'permitopen="10.0.1.5:22"'`, true},
		{"no-pty", "no-pty", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			y := bastionYAML(t, "") + "access:\n  - {user: op, servers: [\"*\"], except: [bastion-eu]}\n" +
				"  - {user: op, servers: [bastion-eu], options: [" + tt.opts + "]}\n"
			_, plans := bastionPlans(t, y)
			p := planNamed(t, plans, "bastion-eu")
			switch {
			case tt.refused && (p.Class != ClassRefused || p.Refusal != refusal):
				t.Errorf("bastion plan = %s %q, want refused with %q", p.Class, p.Refusal, refusal)
			case !tt.refused && p.Class != ClassChange:
				t.Errorf("bastion plan = %s %q, want a change", p.Class, p.Refusal)
			}
			if w := planNamed(t, plans, "web-1"); w.Class != ClassChange {
				t.Errorf("web-1 = %s %q", w.Class, w.Refusal)
			}
		})
	}
}

// TestGrantRestrictionKeepsGuardSurvivor (plan gap 12): a grant cannot add
// cert-authority, so a restricted held key still survives the lockout guard;
// the guard warns that every surviving key is restricted, and the rewrite
// narrows (no Loosens).
func TestGrantRestrictionKeepsGuardSurvivor(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: op, servers: ["*"], options: [restrict]}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(testkeys.Line(t, 1) + " op\n")}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassChange || !strings.HasPrefix(p.Warning, "every remaining key you hold carries a restrictive option") {
		t.Errorf("plan = %s %q warning %q", p.Class, p.Refusal, p.Warning)
	}
	if len(p.Rewrites) != 1 || !p.Rewrites[0].OptionsDiffer || len(p.Rewrites[0].Loosens)+len(p.Rewrites[0].Widens) != 0 {
		t.Errorf("rewrites = %+v, want one narrowing options row", p.Rewrites)
	}
}

// TestAffectedFollowsGrantOptions (spec S7 Tests): an edit that changes only
// a grant's options affects exactly the servers that grant reaches.
func TestAffectedFollowsGrantOptions(t *testing.T) {
	manifest := func(opts string) *config.Config {
		cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]` + opts + `}
  - {user: alice, servers: [web-2]}
`))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	if got := Affected(manifest(", options: [no-pty]"), manifest("")); !slices.Equal(got.Servers, []string{"web-1"}) {
		t.Errorf("Affected = %v, want [web-1]", got.Servers)
	}
}

// TestRewriteFlagsDroppedGrantOption (spec S7 Render): dropping a grant's
// restriction on one server is a loosening rewrite there and nowhere else.
func TestRewriteFlagsDroppedGrantOption(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: alice, servers: [web-2], options: [no-pty]}
`))
	if err != nil {
		t.Fatal(err)
	}
	body := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + " op\nno-pty " + testkeys.Line(t, 2) + " alice\n")}
	plans := buildPlans(t, cfg, &fakeReader{byName: map[string]fleet.ReadResult{"web-1": body, "web-2": body}}, []string{fp(t, 1)})
	if rows := planFor(t, plans, "web-1").Rewrites; len(rows) != 1 || !slices.Equal(rows[0].Loosens, []string{"no-pty"}) {
		t.Errorf("web-1 rewrites = %+v, want alice losing no-pty", rows)
	}
	if rows := planFor(t, plans, "web-2").Rewrites; len(rows) != 0 {
		t.Errorf("web-2 rewrites = %+v, want none (its grant keeps no-pty)", rows)
	}
}

// TestGrantOptionsNeverTouchKeptLines (spec S7 with S6): a restricted grant
// on a preserve: server changes the desired line only; the kept line is
// written back verbatim under the marker.
func TestGrantOptionsNeverTouchKeptLines(t *testing.T) {
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: gitea, host: g.example.com, user: git, preserve: [{command: 'gitea serv key-[0-9]+'}]}
access:
  - {user: alice, servers: [gitea], options: [no-pty]}
`))
	if err != nil {
		t.Fatal(err)
	}
	kept := `command="gitea serv key-7" ` + testkeys.Line(t, 9) + " git@laptop"
	r := &fakeReader{byName: map[string]fleet.ReadResult{"gitea": {Content: []byte(testkeys.Line(t, 2) + "\n" + kept + "\n")}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 2)}), "gitea")
	want := authkeys.ManagedHeader + "\nno-pty " + testkeys.Line(t, 2) + " alice\n" + authkeys.PreserveMarker + "\n" + kept + "\n"
	if p.Class != ClassChange || string(p.Rendered) != want {
		t.Errorf("plan = %s %q, rendered:\n%s\nwant:\n%s", p.Class, p.Refusal, p.Rendered, want)
	}
}

// TestPlanRestrictionConflictGolden (spec S7 apply row): the plan report's
// REFUSED row carries the conflict text; web-2 is planned.
func TestPlanRestrictionConflictGolden(t *testing.T) {
	cfg := clashCfg(t, "")
	plans := buildPlans(t, cfg, opOnly(t), []string{fp(t, 1)})
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	if !strings.Contains(buf.String(), "REFUSED: "+clashText) {
		t.Errorf("no REFUSED row with the conflict:\n%s", buf.String())
	}
	checkGolden(t, "plan_restriction_conflict.golden", buf.Bytes())
}
```

- [ ] **Step 2: Goldens.** Run `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'RenderGrantOptionsGolden|PlanRestrictionConflictGolden' -update`, then `git status --short -- '*testdata*'` (only the two new files), read both back: `render_grant_options.golden` has the three lines the test names, op's line first and plain on every server; `plan_restriction_conflict.golden` has web-1 `REFUSED:` with the conflict text and web-2's change (alice add with `no-pty`). Re-run without `-update`: PASS.

- [ ] **Step 3: Run the package and see the tests bite.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply`
Expected: PASS. Bite once (revert after): make `config.keysOn` (`internal/config/restrict.go`) return `keys` unconditionally → `TestRenderGrantOptionsGolden`, `TestGrantOptionsForwardGuard` (the refused rows), `TestGrantRestrictionKeepsGuardSurvivor`, `TestAffectedFollowsGrantOptions`, `TestRewriteFlagsDroppedGrantOption` and `TestGrantOptionsNeverTouchKeptLines` fail. Record it with the lane's mutants (W6).

### Task 11: the save rule (`cmd/sshepherd/conflicts.go`, `editrun.go`)

**Files:**
- Modify: `cmd/sshepherd/conflicts.go:11-46`, `cmd/sshepherd/editrun.go:430` (`editPrelude`)
- Test: `cmd/sshepherd/restrict_save_test.go` (created in Task 9)

- [ ] **Step 1: Write the failing CLI tests.** Append to `cmd/sshepherd/restrict_save_test.go`, adding `"os"` and `"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"` to its imports:

```go
// wildcardPair: deploy (k2) holds two "*" entries that do not meet today:
// web-1 only through the first (no-pty), db-1 only through the second.
// extra (server lines) is spliced in after db-1; any server it adds is
// reached by both entries.
func wildcardPair(t *testing.T, extra string) string {
	t.Helper()
	return "users:\n  - {name: deploy, keys: [\"" + testkeys.Line(t, 2) + "\"]}\nservers:\n" +
		"  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n" + extra +
		"access:\n  - {user: deploy, servers: [\"*\"], except: [db-1], options: [no-pty]}\n" +
		"  - {user: deploy, servers: [\"*\"], except: [web-1]}\n"
}

// TestImportMergeRefusesAddedClash (spec S7 save row): the new host is
// reached by both "*" entries with different options: exit 3 and nothing
// saved, whether the merge goes to stdout or in place.
func TestImportMergeRefusesAddedClash(t *testing.T) {
	const want = `it would add 1 restriction conflict: user "deploy": server "web-3"`
	t.Run("stdout", func(t *testing.T) {
		hermeticHome(t)
		path := writeConfig(t, wildcardPair(t, ""))
		sshCfg := writeSSHConfig(t, "Host web-3\n  HostName 10.0.0.3\n  User deploy\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", sshCfg, "--merge", path, "--servers-only"}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
		}
		if out.Len() != 0 || !strings.Contains(errBuf.String(), want) {
			t.Errorf("stdout %q; stderr %q", out.String(), errBuf.String())
		}
	})
	t.Run("in place", func(t *testing.T) {
		hermeticHome(t)
		path := writeConfig(t, wildcardPair(t, ""))
		before := fileBytes(t, path)
		sshCfg := writeSSHConfig(t, "Host web-3\n  HostName 10.0.0.3\n  User deploy\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", sshCfg, "--merge", path, "--servers-only", "-o", path, "--force"}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
		}
		if !strings.Contains(errBuf.String(), want) || !bytes.Equal(fileBytes(t, path), before) {
			t.Errorf("the manifest changed or the refusal is missing; stderr %q", errBuf.String())
		}
	})
}

// TestImportMergeKeepsExistingClash: a clash the manifest already has does
// not stop the save, and its options: survive the merge.
func TestImportMergeKeepsExistingClash(t *testing.T) {
	hermeticHome(t)
	path := writeConfig(t, "users:\n  - {name: deploy, keys: [\""+testkeys.Line(t, 2)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"+
		"access:\n  - {user: deploy, servers: [web-1], options: [no-pty]}\n  - {user: deploy, servers: [web-1]}\n")
	sshCfg := writeSSHConfig(t, "Host web-3\n  HostName 10.0.0.3\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", sshCfg, "--merge", path, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "web-3") || !strings.Contains(out.String(), "options: [no-pty]") {
		t.Errorf("merged manifest:\n%s", out.String())
	}
}

// appendAccess adds one access: line at the end of the manifest at path,
// whose last section is access:.
func appendAccess(t *testing.T, path, entry string) {
	t.Helper()
	if err := os.WriteFile(path, append(fileBytes(t, path), entry...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAdoptSavesOverExistingClash (spec S7, plan gap 15): adopt, both modes,
// re-emits a clash the manifest already holds; the regenerate carries
// options: through the encoder.
func TestAdoptSavesOverExistingClash(t *testing.T) {
	for _, merge := range []bool{false, true} {
		t.Run(map[bool]string{false: "regenerate", true: "merge"}[merge], func(t *testing.T) {
			srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
			appendAccess(t, cfg, "  - {user: alice, servers: [web-1], options: [no-pty]}\n")
			if len(readCfg(t, cfg).Conflicts()) != 1 {
				t.Fatal("the fixture must hold one restriction conflict")
			}
			args := []string{"adopt", "--config", cfg, "--known-hosts", sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))}
			if merge {
				args = append(args, "--merge")
			}
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
			}
			if !strings.Contains(out.String(), "no-pty") {
				t.Errorf("the grant's options were not carried:\n%s", out.String())
			}
		})
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'ImportMerge.*Clash|AdoptSavesOverExistingClash'`
Expected: FAIL, each on its assertion. Round 1's `conflictRefusal` refuses every non-weak kind, so `TestImportMergeRefusesAddedClash` exits 3 with `would keep 1 policy conflict`, not the `would add 1 restriction conflict` wording (both subtests), and `TestImportMergeKeepsExistingClash` and both `TestAdoptSavesOverExistingClash` cases exit 3 instead of 0.

- [ ] **Step 2: Write the failing unit test.** Append to `cmd/sshepherd/restrict_save_test.go`:

```go
// clashTail ends every restriction conflict's message (spec S7 wording).
const clashTail = "; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user"

// TestRestrictionSaveRule (spec S7 save rows, OP6): adopt and import --merge
// refuse a save that adds a clash on a (user, server) pair; a clash already
// there saves; revoke and rotate never refuse one.
func TestRestrictionSaveRule(t *testing.T) {
	web3 := "  - {name: web-3, host: 10.0.0.3, user: deploy}\n"
	former := parseManifest(t, wildcardPair(t, ""))
	added := parseManifest(t, wildcardPair(t, web3))
	want := `refusing to write the manifest — it would add 1 restriction conflict: user "deploy": server "web-3" is granted by access[0] with [no-pty] and by access[1] with no options` + clashTail
	if err := conflictRefusal(former, added); err == nil || err.Error() != want {
		t.Errorf("added clash: err = %v\nwant %s", err, want)
	}
	if err := conflictRefusal(added, added); err != nil {
		t.Errorf("a clash already there must save: %v", err)
	}
	if err := editConflictRefusal(former, added); err != nil {
		t.Errorf("revoke and rotate never refuse over a clash: %v", err)
	}
	// One more server on a pair former already had is a clash on a new (user, server) pair.
	more := parseManifest(t, wildcardPair(t, web3+"  - {name: web-4, host: 10.0.0.4, user: deploy}\n"))
	if err := conflictRefusal(added, more); err == nil || !strings.Contains(err.Error(), `servers "web-3" and 1 more are granted`) {
		t.Errorf("web-4 joining an existing clash: err = %v", err)
	}
	if err := conflictRefusal(nil, added); err == nil {
		t.Error("a new manifest holding a clash adds it")
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestRestrictionSaveRule`
Expected: build failure (`undefined: editConflictRefusal`), a failure of this test's own reference (the Step 1 tests were already seen failing on their assertions).

- [ ] **Step 3: Implement.** Replace `conflictRefusal` in `cmd/sshepherd/conflicts.go` (`:11-46`) with the three functions below (keep `formerManifest` as is; add `"slices"` to the imports):

```go
// conflictRefusal is the save refusal of adopt (both modes) and import
// --merge (D29). former is the manifest as loaded (nil for a new one), saved
// the manifest as it would be written. It is editConflictRefusal, then a
// restriction conflict (spec S7, OP6) refuses only when the save adds one: a
// clash on a (user, server) pair former did not have. A clash already there
// does not stop the save.
func conflictRefusal(former, saved *config.Config) error {
	if err := editConflictRefusal(former, saved); err != nil {
		return err
	}
	if added := addedClashes(former, saved); len(added) > 0 {
		return fmt.Errorf("refusing to write the manifest — it would add %s: %s",
			apply.Plural(len(added), "restriction conflict", "restriction conflicts"), strings.Join(added, "; "))
	}
	return nil
}

// editConflictRefusal is the save refusal of revoke and rotate, and the
// first half of conflictRefusal. A revoked-kind conflict refuses while it
// remains (exit 3, nothing written), so 'sshepherd revoke --key FP' of a
// revoked key still listed is the natural fix. A weak key refuses only when
// the save adds one (OP4): an unrelated revoke saves while another user holds
// a DSA key, and the weak key's own rotate or revoke always saves. A
// restriction conflict never refuses here: an edit never adds a grant, and a
// leaver's revoke must save while a clash holds a server (OP6).
func editConflictRefusal(former, saved *config.Config) error {
	var msgs []string
	for _, c := range saved.Conflicts() {
		if c.Kind != config.ConflictWeakKey && c.Kind != config.ConflictRestriction {
			msgs = append(msgs, c.Message)
		}
	}
	if len(msgs) > 0 {
		return fmt.Errorf("refusing to write the manifest — it would keep %s: %s",
			apply.Plural(len(msgs), "policy conflict", "policy conflicts"), strings.Join(msgs, "; "))
	}
	held := make(map[string]bool)
	if former != nil {
		for _, w := range former.WeakKeys() {
			held[w.Fingerprint] = true
		}
	}
	var added []string
	for _, w := range saved.WeakKeys() {
		if !held[w.Fingerprint] {
			added = append(added, w.Message)
		}
	}
	if len(added) > 0 {
		return fmt.Errorf("refusing to write the manifest — it would add a weak key: %s", strings.Join(added, "; "))
	}
	return nil
}

// addedClashes lists the message of every restriction conflict of saved
// that names a (user, server) pair no restriction conflict of former names.
func addedClashes(former, saved *config.Config) []string {
	had := make(map[[2]string]bool)
	if former != nil {
		for _, c := range former.Conflicts() {
			if c.Kind != config.ConflictRestriction {
				continue
			}
			for _, s := range c.Servers {
				had[[2]string{c.User, s}] = true
			}
		}
	}
	var added []string
	for _, c := range saved.Conflicts() {
		if c.Kind == config.ConflictRestriction && slices.ContainsFunc(c.Servers, func(s string) bool { return !had[[2]string{c.User, s}] }) {
			added = append(added, c.Message)
		}
	}
	return added
}
```

In `editPrelude` (`cmd/sshepherd/editrun.go:426`), the call at `:430` becomes `editConflictRefusal(ep.former, ep.edited)`; its doc's "the D29 save refusal (exit 3)" reads "the D29 save refusal (exit 3; a restriction conflict never refuses an edit, OP6)". `(*adoptRun).run` and `(*importRun).run` keep calling `conflictRefusal` (no change to `adopt.go` or `import.go`).

- [ ] **Step 4: Run them, Task 9's CLI tests and the existing save tests.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'RestrictionSaveRule|ImportMerge.*Clash|AdoptSavesOverExistingClash|SavesOverRestrictionClash|SweepOverRestrictionClash|SaveRefused|WeakKey|Conflict'`
Expected: PASS: the Step 1 tests, Task 9's four OP6 tests (they needed both `ClashRefused` and `editConflictRefusal`), and `TestSaveRefusedWhileConflictRemains`, `TestSaveRefusedWhenAddingWeakKey` and the weak-push tests unchanged.

### Task 12: the footers and the pinning CLI tests

**Files:**
- Modify: `cmd/sshepherd/run.go:215-249` (`exitCodesWrite`, `exitCodesAdopt`, `exitCodesImport`), `cmd/sshepherd/testdata/help/{apply,revoke,rotate,adopt,import}.golden`
- Test: `cmd/sshepherd/restrict_save_test.go`; create `cmd/sshepherd/restrict_hermetic_test.go`

- [ ] **Step 1: The footers (README first, locally).** Apply this lane's README footer delta (Task 13 docsDelta item 1) to the worktree's `README.md` **before** editing `run.go` (it is dropped from the patch and re-applied by the integrator): in "## Exit codes", the `apply --help`/`revoke --help`/`rotate --help` block's row 3, and the `adopt --help` and `import --help` blocks, become exactly the constants below. Then in `cmd/sshepherd/run.go` change `exitCodesWrite`'s row 3 and set the other two (gap 13: a kept restriction conflict saves, so no footer may say a kept policy conflict of any kind exits 3):

```go
	// exitCodesWrite's last row (rows 0-2 unchanged):
  3  tool error: bad flags, unloadable manifest, failed preflight, a manifest
     that would keep a revoked-key or revoked-access conflict or add a weak
     key, a failed serial save, or refused before anything was saved or
     written`

const exitCodesAdopt = `Exit codes:
  0  manifest emitted
  1  a server could not be fully read and --partial was not given (nothing
     emitted), or --partial could not read some servers (the partial manifest
     is emitted)
  3  tool error: bad flags, unloadable manifest, failed preflight, an existing
     --output without --force, an in-place save refused, a manifest that
     would keep a revoked-key or revoked-access conflict, or add a weak key
     or a restriction conflict, --partial with no server read, interrupted`

const exitCodesImport = `Exit codes:
  0  manifest emitted
  3  tool error: bad flags, unreadable ssh config or --merge manifest, an
     existing --output without --force, an in-place save refused, a --merge
     manifest that would keep a revoked-key or revoked-access conflict, or
     add a weak key or a restriction conflict`
```

(The first block is the tail of the raw string, not a Go statement: replace the four lines from `  3  tool error: bad flags, unloadable manifest, failed preflight, a manifest` to the closing backquote of `exitCodesWrite`.)

Run `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden -update`, then `git status --short -- '*testdata*'` (only `testdata/help/{apply,revoke,rotate,adopt,import}.golden`), read the five diffs (only the footer's row-3 lines change), then `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestHelpGolden|TestHelpExamplesAndExitCodes|TestHelpMatchesREADMETables'` → PASS. (Before the README edit, `TestHelpExamplesAndExitCodes` fails with `README lacks the --help footer`; that is the failing-first run for this step.)

- [ ] **Step 2: The pinning CLI tests.** Each test below pins behaviour that round 1 or Tasks 9-11 already built, and says which mutant it bites. Append to `cmd/sshepherd/restrict_save_test.go`, adding `"slices"` to its imports:

```go
// TestApplyRefusesOnlyClashedServer (spec S7 apply row, D28): plain apply
// refuses the server a restriction conflict holds and writes the other,
// exit 1; its --json document carries the conflict as a
// restriction_conflict with no fingerprint (owner rule: schema 1).
func TestApplyRefusesOnlyClashedServer(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1})
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: deploy, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: deploy, servers: [web-1, web-2], options: [no-pty]}\n"+
		"  - {user: deploy, servers: [web-1]}\n")
	web1 := hosts["web-1"].keys(t)

	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--dry-run", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	var doc struct {
		Schema  int `json:"schema"`
		Summary struct {
			Refused int `json:"refused"`
		} `json:"summary"`
		PolicyConflicts []map[string]any `json:"policy_conflicts"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || code != 1 || doc.Schema != 1 || doc.Summary.Refused != 1 ||
		len(doc.PolicyConflicts) != 1 || doc.PolicyConflicts[0]["kind"] != "restriction_conflict" || doc.PolicyConflicts[0]["fingerprint"] != nil {
		t.Errorf("apply --dry-run --json exit = %d (err %v):\n%s\nstderr: %s", code, err, out.String(), errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("apply exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if want := `REFUSED: user "deploy": server "web-1" is granted by access[1] with [no-pty] and by access[2] with no options`; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
	if got := hosts["web-1"].keys(t); got != web1 {
		t.Errorf("web-1 was written:\n%s", got)
	}
	if got := hosts["web-2"].keys(t); !strings.Contains(got, "no-pty "+testkeys.Line(t, 2)) {
		t.Errorf("web-2 lacks deploy's restricted line:\n%s", got)
	}
}

// TestRotateKeepsGrantOptions (spec S7 Render): rotate and rotate --keep-old
// touch the key line only, so a grant's options carry over to the new key
// (and stay on the old one under --keep-old).
func TestRotateKeepsGrantOptions(t *testing.T) {
	for _, keepOld := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "--keep-old"}[keepOld], func(t *testing.T) {
			hosts, _, _ := editFleet(t, []byte{1}, "web-1")
			cfg := writeConfig(t, "users:\n  - {name: deploy, keys: ["+qk(t, 2)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
				"access:\n  - {user: deploy, servers: [web-1], options: [no-pty]}\n")
			args := []string{"rotate", "deploy", "--old", fpOf(t, 2), "--new", testkeys.Line(t, 5), "--no-apply", "--yes", "--config", cfg}
			want := []string{fpOf(t, 5)}
			if keepOld {
				args = append(args, "--keep-old")
				want = []string{fpOf(t, 2), fpOf(t, 5)}
			}
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
			}
			saved := readCfg(t, cfg)
			if got := saved.Access[0].Options; !slices.Equal(got, []string{"no-pty"}) {
				t.Errorf("access[0].options = %q, want [no-pty]", got)
			}
			var got []string
			for _, k := range saved.DesiredFor("web-1") {
				if !slices.Equal(k.Options, []string{"no-pty"}) {
					t.Errorf("%s renders %q on web-1, want [no-pty]", k.Fingerprint, k.Options)
				}
				got = append(got, k.Fingerprint)
			}
			if !slices.Equal(got, want) {
				t.Errorf("web-1 renders %q, want %q", got, want)
			}
		})
	}
}

// TestRevokeFromServerClearsClash (spec S7 Tests): trimming the clashed
// server from deploy's entries removes the clash; the tagged entry keeps its
// options on web-2.
func TestRevokeFromServerClearsClash(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: deploy, keys: ["+qk(t, 2)+"]}\nservers:\n"+
		"  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\n"+
		"access:\n  - {user: alice, servers: [\"@web\"]}\n  - {user: deploy, servers: [\"@web\"], options: [no-pty]}\n  - {user: deploy, servers: [web-1]}\n")
	if n := len(readCfg(t, cfg).Conflicts()); n != 1 {
		t.Fatalf("fixture conflicts = %d, want 1", n)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "deploy", "--from-server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	if len(saved.Conflicts()) != 0 {
		t.Errorf("conflicts left: %+v", saved.Conflicts())
	}
	if d := saved.DesiredFor("web-2"); len(d) != 2 || strings.Join(d[1].Options, ",") != "no-pty" {
		t.Errorf("web-2 desired = %+v, want alice, then deploy with no-pty", d)
	}
}

// TestValidateRestrictionConflict (spec S7 validate row): exit 3, and the
// JSON document says valid: false with the conflict, no fingerprint.
func TestValidateRestrictionConflict(t *testing.T) {
	hermeticHome(t)
	cfg := writeConfig(t, wildcardPair(t, "  - {name: web-3, host: 10.0.0.3, user: deploy}\n"))
	code, _, stderr := validateCLI(t, "--config", cfg)
	if code != 3 || !strings.Contains(stderr, `manifest has 1 policy conflict: user "deploy": server "web-3" is granted by`) {
		t.Errorf("exit = %d, stderr %s", code, stderr)
	}
	code, out, _ := validateCLI(t, "--config", cfg, "--json")
	var doc struct {
		Valid           bool             `json:"valid"`
		PolicyConflicts []map[string]any `json:"policy_conflicts"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 3 || doc.Valid || len(doc.PolicyConflicts) != 1 ||
		doc.PolicyConflicts[0]["kind"] != "restriction_conflict" || doc.PolicyConflicts[0]["fingerprint"] != nil {
		t.Errorf("--json exit = %d (err %v):\n%s", code, err, out)
	}
}
```


Create `cmd/sshepherd/restrict_hermetic_test.go`:

```go
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestGrantCommandOfferedLast (spec S7 Render, WP-5's twin): a grant puts
// command= on the first-listed key, so the post-write login check and the
// next audit must offer the plain key first. Against a server that
// authorizes from the written file and forces command= per login, a probe
// or read that logged in with the forced-command key would run `echo
// forced` and fail.
func TestGrantCommandOfferedLast(t *testing.T) {
	home := shortHome(t)
	k1, k2 := sshtest.Key(1), sshtest.Key(2)
	line := func(k any) string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, k).PublicKey())))
	}
	akf := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(akf), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(akf, []byte(line(k2)+"\n"), 0o600); err != nil { // only the plain key today
		t.Fatal(err)
	}
	host := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys: []ssh.Signer{host}, AuthorizedKeysFile: akf, Handle: sshtest.ShellHandler(home),
	})
	t.Setenv("SSH_AUTH_SOCK", sshtest.Agent(t, k1, k2))
	cfg := writeConfig(t, fmt.Sprintf(`
users:
  - {name: backup, keys: ["%s"]}
  - {name: admin, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: backup, servers: [web-1], options: ['command="echo forced"']}
  - {user: admin, servers: [web-1]}
`, line(k1), line(k2), srv.Port))
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey()))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("apply exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if got, err := os.ReadFile(akf); err != nil || !strings.Contains(string(got), `command="echo forced" `+line(k1)+" backup\n") { // #nosec G304 -- t.TempDir-backed path
		t.Fatalf("written file (err %v):\n%s", err, got)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("audit after apply exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
}
```



Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'ApplyRefusesOnlyClashedServer|RotateKeepsGrantOptions|FromServerClearsClash|ValidateRestrictionConflict|GrantCommandOfferedLast'`
Expected: PASS. None of these is failing-first: each pins behaviour already built, and bites as follows (revert after each):
- `TestApplyRefusesOnlyClashedServer`: round 1 (apply's old `conflictRefusal` already refused every non-weak kind) and Task 9; bites under W9 (`planOne` skips `restrictionRefusal`: web-1 is written).
- `TestRotateKeepsGrantOptions`: round 1 (rotate edits the key line through `manifest.ReplaceKey`/`AddKeyAfter`); bites under W8 (`keysOn` returns `keys`: the rendered keys lose `no-pty`).
- `TestValidateRestrictionConflict` and `TestRevokeFromServerClearsClash`: round 1 (validate exits 3 on any conflict; the trimmed manifest holds no clash, so even round 1's save rule lets it save); they bite under G21 (no conflict found) and W8 respectively.
- `TestGrantCommandOfferedLast`: round 1; bites under W8 (the written file lacks the `command=` line).

The tests that are failing-first in this lane are Task 9's four OP6 tests (exit 3 under round 1's cmd save rule, passing after Task 11) and Task 11's import and adopt tests (wrong wording or exit 3 under round 1's rule). `TestAdoptSavesOverExistingClash`'s regenerate case does **not** pin round 1: round 1's `conflictRefusal` refuses it (`would keep 1 policy conflict`, exit 3); both its cases need Task 11.

### Task 13: mutation run, `make check`, hand back

- [ ] **Step 1: Mutants** (one at a time, `GOTOOLCHAIN=go1.27.3 go test ./internal/apply ./cmd/sshepherd -run 'NothingCanLand|Clash|Restriction|GrantOptions|GrantRestriction|AffectedFollows|RewriteFlags|GrantCommand|SaveRule|ImportMerge|AdoptSaves|FromServerClears|RotateKeepsGrantOptions'`; `Clash` and `Restriction` also select `TestApplyRefusesOnlyClashedServer`, `TestRevokeJSONSavesOverRestrictionClash` and `TestRevokeSweepOverRestrictionClash`):

| # | Mutant | Expected killer |
|---|---|---|
| W1 | apply `conflictRefusal` keeps matching `restriction_conflict` | `TestClashRefusesOnlyItsServers` (`ClashRefused` false), the revoke/rotate pair, `TestRevokeJSONSavesOverRestrictionClash` and `TestRevokeSweepOverRestrictionClash` (`nothing saved`); not `TestApplyRefusesOnlyClashedServer` (plain apply never calls `NothingCanLand`) |
| W2 | `NothingCanLand` ignores `ClashRefused` | `TestNothingCanLand` rows, `TestClashRefusesOnlyItsServers`, the revoke/rotate pair, `TestRevokeJSONSavesOverRestrictionClash`, `TestRevokeSweepOverRestrictionClash` |
| W3 | `planOne` checks `restrictionRefusal` before `conflictRefusal` | `TestRevokedKindOutranksClash` |
| W4 | `editConflictRefusal` refuses the restriction kind | `TestRestrictionSaveRule`, the revoke/rotate pair |
| W5 | `addedClashes` ignores `former` | `TestRestrictionSaveRule` (`added, added`), `TestImportMergeKeepsExistingClash`, `TestAdoptSavesOverExistingClash` (both cases) |
| W6 | `addedClashes` keys by user only | `TestRestrictionSaveRule` (`web-4`) |
| W7 | `conflictRefusal` skips `addedClashes` | `TestRestrictionSaveRule`, `TestImportMergeRefusesAddedClash` |
| W8 | `config.keysOn` returns `keys` (round-1 code, reverted after) | Task 10's composition tests, `TestGrantCommandOfferedLast`, `TestRotateKeepsGrantOptions`, `TestRevokeFromServerClearsClash` |
| W9 | `planOne` skips the `restrictionRefusal` check | `TestClashRefusesOnlyItsServers`, `TestPlanRestrictionConflictGolden`, `TestApplyRefusesOnlyClashedServer` (web-1 written) |
| W10 | `exitCodesWrite` keeps "keep a policy conflict" (help text) | `TestHelpGolden` (`apply`, `revoke`, `rotate`), `TestHelpExamplesAndExitCodes` against the edited README |

- [ ] **Step 2: `make check`** (README in the worktree carries the three footers from Task 12 Step 1). Expected: green (`deadcode`: `restrictionRefusal` from `planOne`, `editConflictRefusal` from `editPrelude`, `addedClashes` from `conflictRefusal`).

- [ ] **Step 3: Hand back** with the mutation table and this docsDelta (the footer item is the one applied locally in Task 12 Step 1):

```text
docsDelta (lane write):
README.md
1. "## Exit codes" (applied locally by this lane in Task 12 Step 1, for TestHelpExamplesAndExitCodes;
   the integrator applies it before this lane's make check): the shared `apply`/`revoke`/`rotate`
   --help block's row 3 and the `adopt --help` and `import --help` blocks are replaced by
   exitCodesWrite, exitCodesAdopt and exitCodesImport verbatim (cmd/sshepherd/run.go). Table row 1,
   apply column: "refused servers (a newer manifest's serial, a policy conflict, a granted weak key,
   a restriction conflict, …)". Table row 3, revoke/rotate column: "a manifest that would keep a
   policy conflict" becomes "a manifest that would keep a revoked-key or revoked-access conflict (a
   restriction conflict never stops a revoke or rotate save; its servers are refused in the apply
   phase, exit 1)". Under the table, the adopt/import sentence or a new one: "adopt and import
   --merge also exit 3 when the save would add a restriction conflict on a (user, server) pair the
   manifest did not have; a clash already there does not stop the save."
   The same narrowing in the prose that says "would keep a policy conflict": the import --merge
   paragraph ("A `--merge` manifest that would keep a policy conflict is refused", near "### `sshepherd
   import`"), revoke's ("`revoke` refuses to save a manifest that would keep a policy conflict") and
   rotate's ("`rotate` refuses, exit `3`, to save a manifest that would keep a policy conflict")
   each name "a revoked-key or revoked-access conflict" and add "(a restriction conflict does not
   stop the save; see Per-grant restrictions)", the import one with "unless the merge adds it".
2. "### `sshepherd apply`": a server a restriction conflict names is refused with the conflict text
   (copy the REFUSED row from internal/apply/testdata/plan_restriction_conflict.golden); other
   servers are planned; exit 1. Grant options render after the key line's options on that grant's
   servers only (copy one block from internal/apply/testdata/render_grant_options.golden); the
   loosening highlight, the lockout guard's restrictive-options warning, the forwarding guard on a
   managed bastion and the key offer order all see them; lines a preserve: rule keeps are never
   restricted.
3. "### `sshepherd adopt`" and "### `sshepherd import [ssh-config-path]`": the save refusal
   `refusing to write the manifest — it would add 1 restriction conflict: …` (the exact prefix from
   TestRestrictionSaveRule's want); adopt and import never write options: themselves, and a
   regenerate or merge carries existing ones.
4. "### `sshepherd revoke`" and "### `sshepherd rotate`": they still save over a restriction
   conflict (OP6) and their apply phase refuses those servers (exit 1); grant options are not part
   of the key line, so rotate and rotate --keep-old leave them untouched; revoke --from-server
   keeps an entry's options: on what remains (an added except: goes right after servers:).

CLAUDE.md
1. Status, append to the S7 paragraph: "Apply refuses a clashed server through restrictionRefusal
   with the save-neutral ServerPlan.ClashRefused (NothingCanLand skips it like WeakRefused, so
   revoke and rotate still save, OP6; a revoked-kind conflict on the same server outranks it).
   cmd's save rule splits: editConflictRefusal (revoke, rotate) never refuses a clash;
   conflictRefusal (adopt, import --merge) refuses only a clash on a (user, server) pair the
   loaded manifest did not have (addedClashes). The apply, revoke, rotate, adopt and import --help
   footers name the conflict kinds a kept manifest refuses on (revoked-key, revoked-access) and the
   ones a save may not add (a weak key; for adopt and import, a restriction conflict)."
```

---

## Round 2 — lane `e2e` (Tasks 14–15)

Lane `e2e` owns `cmd/sshepherd/restrict_e2e_test.go` and `scripts/integration.sh`. `needsIntegration: true`. Its assertions need only round 1: the per-server render, the post-write login check through a restricted operator key, a clean audit, and a clash that audit reports (exit 2) and apply refuses on one server (exit 1), both through code that predates S7's round 2.

### Task 14: the fixture accounts and the real-sshd E2E

**Files:**
- Modify: `scripts/integration.sh` container A's fixture lists (at `09c8891`: the `mkuser` list `:91`, the comment `:95-101`, the `cp` list `:102`, the `chown` list `:129`; anchor on the lists that end in `presv`, not on line numbers)
- Create: `cmd/sshepherd/restrict_e2e_test.go`

- [ ] **Step 1: Fixture accounts.** In `scripts/integration.sh`'s `FIXTURE_A`, add `rsta rstb` after `presv` at the end of the three `for u in …` lists (the `mkuser` list, the `cp /seed/key.pub` list and the `chown` list), and extend the comment above the `cp` list (`:95-101` at `09c8891`) with "rsta/rstb: the agent key alone (per-grant restrictions E2E);". Both accounts then hold only the agent key, like `presv`.

- [ ] **Step 2: Write the test.** Create `cmd/sshepherd/restrict_e2e_test.go`:

```go
//go:build integration

package main

import (
	"strings"
	"testing"
)

// TestE2EGrantRestrictions (spec S7 Tests): against real sshd, per-grant
// restrictions render per server, the post-write login check still proves
// the operator's key with a grant restriction on it, a re-apply is a no-op
// and audit is clean; a second grant with other restrictions is a policy
// conflict: audit exits 2 and apply refuses that server only (exit 1).
func TestE2EGrantRestrictions(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	material := func(line string) string {
		f := strings.Fields(line)
		return f[0] + " " + f[1]
	}
	dir := t.TempDir()
	base := "users:\n  - {name: op, operator: true, keys: [\"" + pub + "\"]}\n  - {name: alice, keys: [\"" + stale + "\"]}\n" +
		"servers:\n  - {name: rsta, host: " + host + ", port: " + port + ", user: rsta}\n" +
		"  - {name: rstb, host: " + host + ", port: " + port + ", user: rstb}\n" +
		"access:\n  - {user: op, servers: [\"*\"], options: [no-pty, no-x11-forwarding]}\n" +
		"  - {user: alice, servers: [rsta], options: ['from=\"10.0.0.0/8\"', no-agent-forwarding]}\n" +
		"  - {user: alice, servers: [rstb]}\n"
	m := writeE2EManifest(t, dir, "restrict.yaml", base)
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if got := e2eRemoteCat(t, host, port, kh, "rsta"); !strings.Contains(got, "no-pty,no-x11-forwarding "+material(pub)) ||
		!strings.Contains(got, `from="10.0.0.0/8",no-agent-forwarding `+material(stale)) {
		t.Errorf("rsta does not carry both grants' options:\n%s", got)
	}
	if got := e2eRemoteCat(t, host, port, kh, "rstb"); !strings.Contains(got, "\n"+material(stale)+" ") {
		t.Errorf("rstb must hold alice's key with no options:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", m, "--known-hosts", kh); code != 0 || strings.Count(out, "converged (no changes)") != 2 {
		t.Fatalf("re-apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	clash := writeE2EManifest(t, dir, "clash.yaml", base+"  - {user: alice, servers: [rsta]}\n")
	if code, out, stderr := runBin(t, bin, "audit", "--config", clash, "--known-hosts", kh); code != 2 || !strings.Contains(out, "a key gets one set of restrictions on a server") {
		t.Fatalf("clash: audit exit = %d, want 2 (stderr: %s)\n%s", code, stderr, out)
	}
	code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", clash, "--known-hosts", kh)
	if code != 1 || !strings.Contains(out, `REFUSED: user "alice": server "rsta" is granted by access[1]`) || strings.Count(out, "converged (no changes)") != 1 {
		t.Errorf("clash: apply --dry-run exit = %d, want 1 with rsta refused and rstb converged (stderr: %s)\n%s", code, stderr, out)
	}
}
```

- [ ] **Step 3: Run it.**

Run: `make integration IT_DISTRO=alpine` (under the runner's lock).
Expected: PASS, `TestE2EGrantRestrictions` included (`go test -tags=integration -run TestE2EGrantRestrictions -v` in the script's log).

### Task 15: check the test bites; hand back

- [ ] **Step 1: Bite checks** (one at a time, against round 1's code; revert each): `config.keysOn` returns `keys` → the `rsta` content check fails; `computeConflicts` drops `restrictionConflicts()` → the clash audit exits 0 and apply plans rsta. Record each as killed.

- [ ] **Step 2: `make check`** and `make integration IT_DISTRO=alpine`, then hand back with this docsDelta:

```text
docsDelta (lane e2e):
README.md
1. "### Per-grant restrictions": no new text; the subsection's example stays the design's.

CLAUDE.md
1. Testing → Integration: no change (the container A list names no accounts).
2. Testing → End-to-end: add "`TestE2EGrantRestrictions` applies per-grant restrictions against
   real sshd (an operator key restricted by its own "*" grant still passes the post-write login
   check; one key restricted on one server and plain on another), checks the re-apply is a no-op
   and audit is clean, then adds a clashing grant: audit exits 2 and apply refuses only that
   server (exit 1)."
3. Status, append to the S7 paragraph: "`TestE2EGrantRestrictions` is the E2E (fixture accounts
   `rsta`, `rstb`)."
```

---

## Task 16: integrator (no lane owns this)

- [ ] **Step 1: Per lane, in merge order `grants`, `audit`, `write`, `e2e`:** before the first lane, record `BASE=$(git rev-parse HEAD)` (master at the start of round 1, with this plan committed; see Base for F1). `git apply` the patch, apply that lane's docsDelta (README and CLAUDE.md: Task 6 for `grants`, Task 8 for `audit`, Task 13 for `write`, Task 15 for `e2e`) **before** `make check`, then `make check` (plus `make integration` for `e2e`, run for `IT_DISTRO=alpine`, `debian` and `rocky`). Commit the patch and its docsDelta together, one commit per lane. Lane `e2e`'s commit also carries Steps 2–4. **No release tag may point at lane `grants`' or lane `audit`'s commit** (gap 14: until lane `write` lands, revoke and rotate refuse to save over a clash, against OP6); the first taggable S7 commit is lane `write`'s, and the runner finishes round 2 before any tag.

Order notes. `grants` is round 1 alone; its README text describes the schema, validation and validate, never the save rule (gap 14). `audit`, `write` and `e2e` are one round with disjoint files, so any order works; this order puts the audit wording (whose golden the grants subsection's clash paragraph quotes) before apply's and the save rule. **Lane `write`'s README footer item is required before its `make check`:** `TestHelpExamplesAndExitCodes` reads README's `apply`/`revoke`/`rotate`, `adopt --help` and `import --help` footer blocks. Every README sample is copied from the goldens and test expectations its delta names (`internal/audit/testdata/report_restriction_conflict.golden{,.json}`, `internal/apply/testdata/render_grant_options.golden`, `internal/apply/testdata/plan_restriction_conflict.golden`, `TestGrantOptionValidation`, `TestRestrictionConflict`, `TestRestrictionSaveRule`), never from this plan. README's "## Status" gains the S7 row beside S6's and must agree with CLAUDE.md Status.

- [ ] **Step 2: Design amendments** (commit with lane `e2e`) in `docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`:

  1. Header `Status`: add `S7 built (plan 2026-11-10-p10-s7-restrictions)` after S6.
  2. S7 **Validation**: add the load-error wordings of gap 10, and "The combined-line OptionIssue check cannot fire after the name rule; it stays as defense in depth."
  3. S7 **Two grants, different restrictions**: after "counts as no options" add "and is the first grant source, before access[0], for naming and rendering". After "There is one conflict per pair" add "of grant sources (the implicit grant counts as one), users in users order, pairs in the order their first server appears; a user with no keys never clashes; restriction conflicts come last in `policy_conflicts`". Replace "`Servers` lists every server where those two entries disagree" with "`Servers` lists every server where that pair is the first disagreement; a server appears in one conflict per user" (plan gap 4: with e0, e1, e2 all on web-1 and e0, e2 on web-2, (e0, e2) lists web-2 only). After "Same-set grants union as today" add "and render the first source's spelling; sets ignore repeats, values compare exactly".
  4. S7 **Mechanics**: replace "`apply`'s refusal already reads `Conflict.Servers`, so it needs no code." with "`apply` refuses through `restrictionRefusal` with the save-neutral `ServerPlan.ClashRefused`, which `NothingCanLand` skips like `WeakRefused` (without it a revoke whose only server is clashed would be withheld, against OP6); a revoked-kind conflict on the same server outranks it." Replace "`conflictRefusal` in `cmd/sshepherd/conflicts.go` gains the manifest the command started from: revoke and rotate skip this kind, and adopt and import count only a clash that manifest did not have." with "`cmd/sshepherd/conflicts.go` splits: `editConflictRefusal` (revoke, rotate) never refuses this kind; `conflictRefusal` (adopt, `import --merge`) is `editConflictRefusal` plus `addedClashes`, a clash on a (user, server) pair the loaded manifest did not have. `adopt.go` and `import.go` need no code."
  5. S7 **Render**: "with the options of the first `access:` entry reaching it" becomes "with the options of the first grant source reaching it (the implicit operator grant first)". Replace "P09's expiry-time warning must also read grant options; whichever of S7 and P09-impl lands second adds that." with "P09's passed-expiry warning reads grant options too: one warning per entry, `access[N]: expiry-time="…" has passed; sshd no longer accepts the keys this entry grants` (kind `key_expired`)."
  6. S7 **Files**: replace with `internal/authkeys/options.go` (`IsRestriction`, `SameOptions`), `internal/config/{config,restrict,revoked,policy,clashed}.go`, `internal/audit/audit.go`, `internal/apply/{plan,serial,predicates}.go`, `cmd/sshepherd/{conflicts,editrun,run}.go`, `cmd/sshepherd/schema_roundtrip_test.go`, `scripts/integration.sh` (fixtures `rsta`, `rstb`).
  7. S7 **README**: add "the `apply`, `revoke`, `rotate`, `adopt` and `import --help` footers name the conflict kinds a kept manifest refuses on (revoked-key, revoked-access) instead of any policy conflict, and the `adopt` and `import` footers an added restriction conflict".
  8. S7 **Tests**: add "Integration: `TestE2EGrantRestrictions` (fixtures `rsta`, `rstb`)", and mark the forwarding-guard sentence done ("S7 landed second: `TestGrantOptionsForwardGuard`"). After "Adopt and `import --merge` refuse a save that adds a clash (…), exit 3 and nothing saved, and save over a clash already there." add "Adopt cannot add a clash (its extensions reach only ungranted servers, and it adds no server); its refusal is pinned by `TestRestrictionSaveRule`, and its CLI test is the save over an existing clash."
  9. "Order and parallel lanes", S7 row: `` round 1 A: `internal/authkeys/options.go`, `internal/config` (schema, render, conflicts) · round 2 B: `internal/audit`, `internal/config/clashed.go` · C (beside B): `internal/apply/{plan,serial,predicates}.go`, `conflicts.go`, `editrun.go`, `run.go` (footers) · D (beside B): the E2E, `scripts/integration.sh` · integrator: README ``.
  10. The shared D28 table ("**Exit codes.** … The new rows of the shared D28 table"), row "Unknown tag, group or `via`, a second entry for one address, an `access:` entry naming a `jump_only` server, or a bad `preserve:` rule (load error) | 3 on every command": insert before " (load error)" ", or a bad grant `options:` entry (an option sshd rejects, a non-restricting or certificate option, a repeated once-only clause, a name already on a reached key line)".

- [ ] **Step 3: CLAUDE.md beyond the lane paragraphs** (commit with lane `e2e`): check that the S7 paragraph reads as one paragraph in the Status section's style (bold lead, spec and plan paths, then mechanics) and agrees with README's Status; the Fuzz count sentence ("every one of the N `Fuzz*` targets") is unchanged: S7 adds no target (`make fuzz-list | wc -l` equals its value at `$BASE`).

- [ ] **Step 4: Checks.** `git diff --stat "$BASE" -- 'internal/*/testdata' 'cmd/sshepherd/testdata'` changes no file that existed at `$BASE` except `cmd/sshepherd/testdata/help/{apply,revoke,rotate,adopt,import}.golden` (footer row 3 only; new files only: `internal/audit/testdata/report_restriction_conflict.golden{,.json}`, `internal/apply/testdata/render_grant_options.golden`, `internal/apply/testdata/plan_restriction_conflict.golden`); `internal/apply/testdata/render_operator_unchanged.golden` is untouched; `git diff "$BASE" -- internal/config/testdata` is empty.

## Task 17: independent verifier (no lane owns this)

Check against `master` after Task 16 and report findings; change nothing.

- [ ] Schema and validation: every row of `TestGrantOptionValidation` fails with its text; `IsRestriction` is exactly the design's twelve options and is read from the table (no second list in `internal/config`); a grant naming an option its key line carries fails in any case (`FROM=`), per member for a group entry; an entry without `options:` regenerates with no `options:` key (`TestRegenerateWritesOptionsOnlyWhenSet`); a bad grant option exits 3 on validate, audit, apply and adopt.
- [ ] Render: `DesiredFor` returns copies (the parsed key line never changes, and two servers' renders never share a backing array, `TestKeysOnNeverSharesOptions`); the key line's options come first; the first grant source decides, the implicit operator grant first; a blocked pair renders nothing except a fleet-wide operator's implicit grant; a manifest without `options:` renders byte-identically (`render_operator_unchanged.golden` and every other existing golden untouched); `FuzzLoad`'s `checkGrantOptions` oracle holds for `make fuzz FUZZTIME=30s`.
- [ ] Conflicts: one per user and pair of sources, each server under the pair that is its first disagreement (`a pair is named only where it is the first disagreement`), no fingerprint; `options: []` is no options; order and name case ignored; three sets name the first two that differ; a blocked grant and a keyless user never clash; the implicit operator grant clashes with a restricted literal or group entry; the kind comes last in `Conflicts()`.
- [ ] Audit: a clash is critical and exits 2, also under `--server` naming only other servers (OP4); `optionsDrift` skips only the clashed users' keys on the clashed servers (`TestRestrictionConflictAudit`), presence and every other key still compared; JSON adds no field beyond the `restriction_conflict` kind value.
- [ ] Apply and the write path: a clashed server is refused with `ClashRefused`, a revoked-kind conflict outranks it, `NothingCanLand` skips it; plain apply refuses only that server and writes the rest, exit 1, text and `--json` (`TestApplyRefusesOnlyClashedServer`); revoke and rotate save over a clash and exit 1 (`TestRevokeSavesOverRestrictionClash`, `TestRotateSavesOverRestrictionClash`), the `--json` document says `edit.saved: true` with the conflict as `restriction_conflict` and no fingerprint (`TestRevokeJSONSavesOverRestrictionClash`), and `--sweep` finds the leaver's key on the held server, exit 2 (`TestRevokeSweepOverRestrictionClash`); rotate and `--keep-old` keep grant options (`TestRotateKeepsGrantOptions`); the forwarding guard refuses a grant `no-port-forwarding`/`restrict`/narrow `permitopen=` on a managed bastion; the lockout guard keeps a restricted held key as a survivor; the probe and every read offer a grant's forced-command key last (`TestGrantCommandOfferedLast`); kept `preserve:` lines are written back verbatim.
- [ ] Save rule: adopt and `import --merge` refuse only an added clash (by (user, server) pair, `TestRestrictionSaveRule`'s `web-4` case), an in-place `import --merge -o FILE --force` leaves FILE byte-identical, save over one already there, and other kinds keep today's wording and precedence; `adopt.go` and `import.go` are unchanged by S7 (`git log -p` over the four S7 commits).
- [ ] Gates: `deadcode` green at each of the four commits; `make layering` (no transport in `internal/config` or `internal/audit`); gocyclo 15 with no `nolint` (`planOne`, `validateAccess`, `DesiredFor`); the help goldens differ from the base only in the three footers' row 3 (`apply`, `revoke`, `rotate`, `adopt`, `import`), and no footer says a kept restriction conflict exits 3; README's footers match `--help`; no release tag points at lane `grants`' or `audit`'s commit.
- [ ] Integration: `TestE2EGrantRestrictions` runs on alpine, debian and rocky (`rsta`, `rstb` exist in all three through `FIXTURE_A`).
- [ ] README: the Per-grant restrictions subsection, the Validation rules bullet, the audit, apply, validate, adopt, import, revoke and rotate texts, and the Exit codes table and footers all describe S7 with samples matching their goldens; README Status and CLAUDE.md Status agree.
- [ ] Each lane's mutation table is complete and every survivor is explained (G20 is the expected equivalent; G16 is defined so it is not).

---

## Spec coverage (self-review)

| Design text (S7, Shared rules, Order row) | Task |
|---|---|
| Go shape: `Access.Options` (`yaml:"options"`), optional, empty = none | 2, 4 (`TestEmptyGrantOptions`), 5 |
| Meaning: key line's options, then the grant's; narrowing only; vary per server through grants | 3 |
| Validation: `CheckOption` per option, `OptionIssue` per grant, restricting options only (`IsRestriction` from the table), `cert-authority`/`principals=` refused, a name on a reached key line refused per key and per member (`FindOption`, any case), combined `OptionIssue` as a last check | 1, 2 (gap 8) |
| Two grants, different restrictions: every source (direct, group, tag, implicit operator) gives the same set, order and name case ignored, same-set grants union | 3, 4 (gaps 3, 6) |
| A clash is a D29 conflict `restriction_conflict`, not a load error; computed in `computeConflicts` after blocking; `Conflict` unchanged; one per pair, `user` set, no `fingerprint`, every disagreeing server (narrowed to "where the pair is the first disagreement", gap 4, amendment 3); first two sets named; the several-servers and operator wordings | 4 (gaps 4, 5, 7) |
| Audit: critical, exit 2, also under `--server` (OP4); options comparison skipped for those keys only, presence still compared | 7 |
| Apply refuses only those servers, exit 1 | 9, 10, 12 (`TestApplyRefusesOnlyClashedServer`, text and `--json`; gap 1) |
| Validate: exit 3, `valid: false`, `policy_conflicts` | 12 |
| Adopt (both modes) and `import --merge` refuse an added clash, exit 3, nothing saved (in place: the file byte-identical); save over one already there | 11 (gap 15, amendment 8) |
| Revoke and rotate still save; their apply phase refuses those servers | 9, 11 (text, `--json`, `--sweep` exit 2; gaps 1, 14) |
| Mechanics: `ServerResult` set from `Config.ClashedKeys`; `optionsDrift` in text, JSON, `Compliant`; the save-rule wording `it would add 1 restriction conflict: MESSAGE`, other kinds first | 7, 11 (gap 2) |
| Render: per-server `Key` copies; audit drift, `apply.Affected`, `Survivors`, `OfferOrder`, `Loosens`, the guard's warning follow; `OwnerOf` and fingerprint uniqueness unchanged; a clashed pair renders deterministically | 3, 7, 10, 12 |
| `rotate`/`--keep-old` touch the key line only; adopt and import never write `options:`; regenerate carries it; P09's expiry warning reads grant options | 4, 5, 11, 12 (`TestRotateKeepsGrantOptions`; gap 9) |
| Tombstones: a blocked grant takes no part | 4 |
| Composition: groups (every member), tags and `except:`, protected/operators (written first; guard, forwarding guard and probe), `preserve:` (never restricted), revocation tombstones, `jump_only` (no grant reaches it), adopt/import regeneration, validate, audit JSON, the option table as the one source | 3, 4, 5, 7, 10, 12, 14 (gap 12) |
| Shared rules: a per-entry field needs a sample (`TestSchemaRoundTrip*`); JSON additive, schema 1 (audit, validate, apply and revoke documents); D28 rows (the load-error row gains grant `options:`, amendment 10) | 5, 7, 9, 12, header |
| Tests: validation table, conflict and no-conflict across direct/group/tag/implicit, order-insensitive, one per pair, wordings, a clash loads, audit (critical, exit 2, `--server`, skipped comparison, JSON), apply refuses only clashed servers, validate 3, adopt/import refuse an added clash (`*` with different `except:`) and save over an existing one, revoke/rotate save and push refused, a revoke removing a clashing grant clears it, a blocked grant causes no clash, render golden, existing manifests byte-identical, clashed pair renders the first source, audit drift and `Affected` per server, offer order, the bastion forwarding guard, round-trip sample, fuzz seed | 1–5, 7, 9–12, 14 |
| README items (manifest subsection, Validation rules, audit, apply, validate, adopt, import, revoke, rotate, Exit codes and the three footers) | 6, 8, 12, 13, 15, 16 (gap 13) |
| Order row: A authkeys + config · B audit, conflicts, editrun, adopt, import · integrator tests and README | Rounds (re-cut: audit and write split, e2e added; amendment 9) |

---

## Review log

Two independent reviews of the draft (R0: spec and owner answers; R1: code, compile and gates), each issue checked against the code at `065c1d3` and the design before it was applied.

| Issue | Verdict | Where |
|---|---|---|
| R0-1 rotate/`--keep-old` keep grant options untested | applied: `TestRotateKeepsGrantOptions` (pin; bites under W8) | Task 12, W8, coverage |
| R0-2 no hermetic plain-`apply` exit 1 | applied: `TestApplyRefusesOnlyClashedServer`; **not** as a W1/W2 killer (plain apply never calls `NothingCanLand`, `cmd/sshepherd/editrun.go:321` is its only caller); new mutant W9 instead | Task 12, W9 |
| R0-3 `Servers` narrowed to "first disagreement" without a record | applied: gap 4, amendment 3, new `TestRestrictionConflict` row, mutant G23 | gap 4, Task 4, Task 16 |
| R0-4 D28 load-error row lacks grant `options:` | applied: amendment 10 | Task 16 Step 2 |
| R0-5 in-place `import --merge` "nothing saved" untested | applied: `in place` subtest (file byte-identical) | Task 11 |
| R0-6 no `--json` test for OP6's save-over-clash | applied: `TestRevokeJSONSavesOverRestrictionClash`; `apply --dry-run --json` in `TestApplyRefusesOnlyClashedServer` | Tasks 9, 12 |
| R0-7 footers say a kept clash exits 3 | applied: all three footers name revoked-key/revoked-access; five help goldens; README prose; gap 13 rewritten | gap 13, Task 12, Task 13 docsDelta, amendment 7 |
| R0-8 gap 1 quotes text the design lacks | applied: cites the Risks bullet and D28's row | gap 1 |
| R0-9 adopt's spec-test change unrecorded | applied: amendment 8, gap 15 | Task 16 Step 2 |
| R0-10 `options: []` untested | applied: `TestEmptyGrantOptions`, conflict row, mutant G22 | Task 4 |
| R0-11 round-1 commit contradicts OP6 | applied (option 1): no release tag at lane `grants`' or `audit`'s commit; moving code into round 1 rejected | gap 14, Task 16, handoffs |
| R0-12 (optional) `revoke --sweep` over a clash | applied: `TestRevokeSweepOverRestrictionClash` (exit 2, `cmd/sshepherd/sweep.go:20` sweeps refused servers) | Task 9 |
| R1-1 G13's killer cannot see an in-place append | applied: `TestKeysOnNeverSharesOptions`, with `slices.Grow` so it does not rely on x/crypto's capacity | Task 3, G13 |
| R1-2 G16 equivalent | applied: redefined as "returns `src[i-1], src[i]`" | G16 |
| R1-3 G10b not killed; `FuzzLoad` not in the run | applied: `grantSources` assertion, blocked-operator seed, `|FuzzLoad` in the regex | Tasks 4, 5, 6 |
| R1-4 Task 2 expected failure wrong | applied: build failure, then a run with the field and no validation | Task 2 |
| R1-5 Task 4 build failure masks tests | applied: the constant first, then per-test expectations | Task 4 |
| R1-6 lane `write` CLI tests not failing-first; adopt claim wrong | applied: OP6 CLI tests in Task 9 Step 1, import/adopt tests in Task 11 Step 1 before `TestRestrictionSaveRule`; paragraph corrected; W5 gains the adopt test | Tasks 9, 11, 12, 13 |
| R1-7 `TestRevokedKindOutranksClash` is a pin | applied: says so | Task 9 |
| R1-8 `integration.sh` comment lines | applied: `:95-101`, anchor on the `presv` lists | Task 14 |
| R1-9 F1 not on master | applied: Base names `065c1d3`, S7 does not depend on F1, runner precondition | header, Task 16 |

---

## Wave lanes (for the runner)

- **`plan`** (the runner's `args.plan`): `docs/superpowers/plans/2026-11-10-p10-s7-restrictions.md`, committed before round 1.
- **`handoffs`** (the runner's `args.handoffs`), one entry: "P10-S7, per lane in the order grants, audit, write, e2e: git apply that lane's patch, apply its docsDelta (README and CLAUDE.md; Task 6 for grants, Task 8 for audit, Task 13 for write, Task 15 for e2e) before make check, then make check (make integration for lane e2e, all three distros), then commit patch and docsDelta together, one commit per lane. Lane write's README footer item (Task 13 docsDelta item 1) must be applied before its make check (TestHelpExamplesAndExitCodes reads README's apply/revoke/rotate, adopt and import --help footer blocks). No release tag may point at lane grants' or audit's commit (gap 14). Lane e2e's commit also carries Task 16 Steps 2-4."

Rounds run in sequence and each lane builds only on the previous rounds' commits. Round 1 holds `grants` alone: every later lane reads `Access.Options`, `ConflictRestriction` and the per-server render. Round 2 holds `audit`, `write` and `e2e`, which own disjoint files and need only round 1. Globs are shell `case` patterns (`*` crosses `/`); each lane's testdata folders are listed (`internal/config/*` and `internal/audit/*` cover theirs; `internal/config/clashed.go` and `clashed_test.go` are created in round 2 by lane `audit`, outside lane `grants`' round). `README.md` and `CLAUDE.md` are integrator-only: each lane reports its `docsDelta`, and the integrator applies it after the patch and before `make check`.

```json
{
  "rounds": [
    [
      {
        "pkg": "P10-S7",
        "lane": "grants",
        "kind": "fix",
        "ids": ["PRD-6", "D22", "OP5", "OP6"],
        "tasks": "Tasks 1-6",
        "files": [
          "internal/authkeys/options.go",
          "internal/authkeys/restriction_test.go",
          "internal/config/*",
          "cmd/sshepherd/schema_roundtrip_test.go",
          "cmd/sshepherd/restrict_schema_test.go",
          "internal/manifest/edit_options_test.go"
        ],
        "needsIntegration": false
      }
    ],
    [
      {
        "pkg": "P10-S7",
        "lane": "audit",
        "kind": "fix",
        "ids": ["PRD-6", "D22", "OP6"],
        "tasks": "Tasks 7-8",
        "files": [
          "internal/audit/*",
          "internal/config/clashed.go",
          "internal/config/clashed_test.go"
        ],
        "needsIntegration": false
      },
      {
        "pkg": "P10-S7",
        "lane": "write",
        "kind": "fix",
        "ids": ["PRD-6", "D22", "OP5", "OP6"],
        "tasks": "Tasks 9-13",
        "files": [
          "internal/apply/plan.go",
          "internal/apply/serial.go",
          "internal/apply/predicates.go",
          "internal/apply/predicates_test.go",
          "internal/apply/restrict_test.go",
          "internal/apply/testdata/render_grant_options.golden",
          "internal/apply/testdata/plan_restriction_conflict.golden",
          "cmd/sshepherd/conflicts.go",
          "cmd/sshepherd/editrun.go",
          "cmd/sshepherd/run.go",
          "cmd/sshepherd/testdata/help/apply.golden",
          "cmd/sshepherd/testdata/help/revoke.golden",
          "cmd/sshepherd/testdata/help/rotate.golden",
          "cmd/sshepherd/testdata/help/adopt.golden",
          "cmd/sshepherd/testdata/help/import.golden",
          "cmd/sshepherd/restrict_save_test.go",
          "cmd/sshepherd/restrict_hermetic_test.go"
        ],
        "needsIntegration": false
      },
      {
        "pkg": "P10-S7",
        "lane": "e2e",
        "kind": "fix",
        "ids": ["PRD-6", "D22", "OP6"],
        "tasks": "Tasks 14-15",
        "files": [
          "cmd/sshepherd/restrict_e2e_test.go",
          "scripts/integration.sh"
        ],
        "needsIntegration": true
      }
    ]
  ],
  "mergeOrder": ["P10-S7"]
}
```
