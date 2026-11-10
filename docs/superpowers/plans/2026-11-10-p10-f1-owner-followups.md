# Owner follow-ups F1 (P10 F1: fresh-import losses, the preserve: marker row, a bounded session open) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step, not a commit.

**Commits at:** `docs/superpowers/plans/2026-11-10-p10-f1-owner-followups.md` (exactly this path; the runner commits it before round 1).

**Owner answers recorded 2026-11-10 (after review):** gap 4 is APPROVED: the `--force` warning also covers `authorized_keys_file:` overrides, using the `settingLosses` row sketched in gap 4 (placed before `tags:`), with one more fixture field, one more expected line in Task 2's tables, a mutant row, and the README sample re-copied from real output. Gap 9: KEEP today's P08 verdict (a session that never opens after a good login is REJECTED and restores); no code change beyond the `TestClassifyProbe` pin.

**Goal:** Build the three owner follow-ups decided on 2026-11-10 (F1) on top of the access-model design (`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`; F1 has no section of its own there, so this plan is the description, under the design's Shared rules): **(Q1)** a fresh `import -o FILE --force` also warns, one line per kind of setting, when FILE holds manifest-only settings the fresh output drops (`operator: true` and `protected: true` marks, `groups:`, server `tags:`, `via:` routes, `jump_only: true`, `preserve:` rules); **(Q3)** a write that adds the `preserve:` marker the file lacks gets its own plan row, `(preserve:) add the externally-managed section marker` (`Normalize.ExternalSection`, JSON `normalize.external_section`), instead of `(formatting) normalize: whitespace/format`; **(Q4)** `sshconn.Exec` stops waiting for a session open that never answers (ctx, or a new `SessionOpenTimeout` of 10 s), closes the client and returns the existing `ErrSessionNotOpened`-marked error with kind `timeout` (or ctx's kind).

**Architecture:** Three independent changes, three disjoint lanes, one round. Q1 lives in `cmd/sshepherd` only: `run` already parses the fresh output (`saved`, `cmd/sshepherd/import.go:446`) before it calls `warnMemoryLost` (`:453-455`); a new `warnFreshDrops` reads FILE once and calls the (now parse-free) `warnMemoryLost` and a new table-driven `warnSettingsLost` (`cmd/sshepherd/import_settings.go`), which adds kind `manifest_settings_dropped` through the existing `importWarnings` collector, so `import --json` carries it with no new JSON code. Q3 lives in `internal/apply`: `nonKeyLines` (`internal/apply/plan.go:473`) already counts markers; it also returns whether the render adds one, `normalize` (`:454`) stores it and stops calling that drift whitespace, `report.go` prints one row beside `emptySectionRow` (`:225`) and `json.go` maps one `omitempty` field. Q4 lives in `internal/sshconn`: `Exec` (`internal/sshconn/connect.go:659`) opens its session through a new `openSession` that runs `client.NewSession` in a goroutine; `sshtest.ServerConfig` gains `SilentSessions` so the test is deterministic; sshread and sshwrite need no production change (their handling is pinned by new tests).

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), `golang.org/x/crypto/ssh`, the hermetic `internal/sshconn/sshtest` server, goleak (`TestMain` in every package), golden files (`-update`), golangci-lint (gocyclo 15, revive, depguard), `deadcode ./cmd/sshepherd`, `make layering`, the dockerized sshd matrix (`make integration`, alpine/debian/rocky).

**Base:** `master` at `065c1d3`. S1-S6 and the S6 follow-up have landed; F1 lands before S7. Every `file:line` below was read at `09c8891` and still holds at `065c1d3`, which changes only `CLAUDE.md` and `internal/audit/preserve_test.go`, neither of them cited or owned here.

**D28 for this follow-up.** No new exit-2 input and no exit code changes. Q1 is a warning on an exit-0 run. Q3 changes a plan row, never a class. Q4 turns a hang into the failure classes that already exist: an audit read of a server whose session never opens is `unreachable` with `error_kind: timeout` (exit 1, as any timeout); a write's stage-1 session that never opens is a session that never opened (`sshwrite` re-checks under the lock, P08); the post-write login check whose session never opens is REJECTED and restores, exactly as README already promises for "a session that will not open" (gap 9). JSON stays schema 1: `normalize.external_section` (apply, revoke, rotate) is additive with `omitempty`; Q1's kind `manifest_settings_dropped` is a new value in `import --json`'s existing `warnings[].kind` (consumers ignore kinds they do not know).

**Compile status.** An independent review (Review log, R1) exported `065c1d3` to a scratch copy and applied every Go block of the draft as written: `go vet`, `golangci-lint run ./...`, `goimports -l`, `deadcode ./cmd/sshepherd` and `go test -race` on every touched package were clean, and the regenerated preserve goldens matched Task 5 Step 4's prediction. The blocks this revision changed were **not** compiled: `lostServers` and the `settingLosses` consequences (Task 1), the import test expectations and the quiet table (Tasks 1-2), the `TestPreserveHermetic` step (Task 5), the sshwrite rows (Task 9) and the `openSession` doc comment (Task 8). They were checked by reading against `065c1d3`. Every helper the blocks call was read there (`importWarnings.addAll`, `hintArg` (`cmd/sshepherd/editrun.go:673`), `config.Parse`, `Config.OwnerOf`, `Config.ServerNamed`, `Config.Serial`, `authkeys.ParseLine`, `apply.Plural`, `writeConfig`, `writeSSHConfig`, `hermeticHome`, `qk`, `parseManifest`, `fileBytes`, `importJSONCLI`, `run`; `preserveCfg`, `giteaPlan`, `giteaLine`, `opLine`, `preservedPlans`, `buildPlans`, `planFor`, `checkGolden`, `renderJSONCfg`, `fp`; `classify`, `ctxKind`, `remoteText`, `kindOf`, `ctxTimeout`, `sshtest.NewServer`/`Key`/`Signer`/`Agent`/`KnownHostsFile`, `Dialer.Connect`, `Client.ReadAuthorizedKeys`, `scriptedExec`, `execResp`, `seamedWriter`, `seamedConnect`, `req`, `kinded`, `lockoutOf`, `classifyProbe`). Goldens named below change; the lane regenerates them with `-update` and reads each one back before accepting it. On a compile error a lane fixes the block within its stated intent and reports the fix.

---

## Design gaps and contradictions (for the main session)

No item overrides an owner decision. One is a real contradiction with the design text (gap 7: the S6 Render paragraph says the first marker write reads as formatting; the owner's Q3 replaces that), which Task 11 amends. The main session can veto any other item.

1. **Q1: one warning kind, one line per kind of setting.** The owner asked to decide between one combined line and one per kind. One line per kind reads better: each line carries its own consequence and its own remedy (`--operator-key PATH` re-marks an operator; nothing re-creates a group), a combined line with seven name lists would wrap past any terminal, and it matches the existing style, where `revocation_memory_dropped` is one line for one kind of loss and every other import warning is one line per finding. Every line has the memory warning's shape, `FILE holds <setting> (<names>) that this fresh import <drops|does not mark|does not reproduce>: <consequence>; <remedy> with --merge FILE`, so the paste-ready `--merge FILE` hint (`hintArg`) always ends the line. The JSON kind is one new value, `manifest_settings_dropped` (the owner's "its own warning kind"), with one `warnings[]` entry per line; the message names the setting, as every other import kind carries only a message.
2. **Q1: users are matched by key, servers by name.** A fresh import names users after their identity files (`identity.Resolve`), so a FILE user `legacy-ops` with key K is "still marked" when any fresh user holding K carries the same flag; `import --operator-key PATH` with K's `.pub` therefore silences the operator line, exactly as the owner's "(--operator-key re-marks operators)" asks. Each flag is compared on its own field: `operator:` with `Operator`, `protected:` with `Protected` (a fresh import never writes `protected: true`, so a FILE protected user is always named, even when its key is re-marked as an operator: the `protected:` mark itself is gone). Servers keep their ssh-config alias as name, so a server setting is reproduced when the fresh output has a server with that name and the same value (`slices.Equal` for `tags:` and `preserve:`, `==` for `via:`, `JumpOnly` for `jump_only:`). Groups compare by name. A setting on a user or server the fresh output does not have at all is named too: the setting is gone either way. A server missing from the fresh output is labelled `NAME [not in this import]` (`NAME via HOP [not in this import]` for a route), and the server consequences are worded so they hold either way ("where they stay, apply would …"): apply never touches a server the manifest no longer lists, so "apply would remove the lines they keep" would be false for a dropped server (Review log, R0-1). The fresh output never carries groups, protected marks, tags, `jump_only:` or `preserve:` today; the comparison is still written generically (and unit-tested with hand-built "fresh" configs, Task 1) so a future import that learns one of them does not warn falsely.
3. **Q1: order.** Manifest order: users (`operator:`, then `protected:`), `groups:`, then the server fields in `config.Server` order (`tags:`, `via:`, `jump_only:`, `preserve:`). The memory warning, when present, comes first, as today.
4. **Q1: scope.** Only the path that already warns: a fresh run (`--merge` unset) with `-o FILE --force` over a FILE that parses (`warnMemoryLost`'s best-effort rule). `--merge` keeps every one of these settings (README: "`adopt --merge` and `import --merge` leave them as they are"), so it never warns. `adopt` regenerate is untouched (it keeps all of them through `manifest.Draft`). Exit code stays 0; `validate --strict` is unaffected (these are import warnings, not manifest warnings). Without `--force` the run is refused (exit 3) before anything is written, and `warnFreshDrops` returns before reading FILE, so no misleading "drops" line precedes the refusal (the collector logs each warning as it is added, `cmd/sshepherd/import_json.go:35-38`); Task 2's `no --force` row pins it. **Not covered, flagged for the owner:** a server's `authorized_keys_file:` override is also manifest-only, and dropping it sends apply and audit to `~/.ssh/authorized_keys`, leaving the real file (and any revoked key in it) unmanaged, a bigger security loss than `tags:`. Hand-written `access:` entries and `except:` carve-outs are dropped too (an `--servers-only` import writes no access at all). Neither is in the owner's F1 list, so this plan does not add them. If the owner approves in one line, the `authorized_keys_file` row is one more `settingLosses` entry: `{"authorized_keys_file: overrides on servers", "drops", "where they stay, apply and audit would use ~/.ssh/authorized_keys", "keep them", lostServers(…, s.AuthorizedKeysFile != "", was.AuthorizedKeysFile == now.AuthorizedKeysFile, serverName)}`, placed before `tags:` (the field precedes `Tags` in `config.Server`), with one more fixture field and one more expected line.
5. **Q1 fixes two recorded gaps.** S3b's gap 11 (groups dropped silently) and S4's gap 12 (`protected:` dropped silently) are closed by this change; README's groups paragraph (`README.md:415`) gains "and warns".
6. **Q3: when the row shows.** Whenever the write adds a marker the file lacks: `nonKeyLines` saw no marker line and `len(r.External) > 0` (the render writes the marker exactly when something is kept: `authkeys.RenderKept`, `internal/authkeys/render.go:79-96`). So it also shows beside other rows (`gitea` removes a stray and adds the marker; `session` rewrites a comment and adds the marker); it replaces the formatting row only when the marker is the only difference (`gitea-3`), because `ExternalSection` explains the byte drift exactly as `EmptyExternalSection` does today (`normalize`'s whitespace condition, `plan.go:462`). Like `EmptyExternalSection`, it is not part of `Normalize.Any()` (it prints its own row). Both cannot be true at once (no marker vs a marker).
7. **Q3 contradicts the S6 design text.** The design's S6 Render paragraph (`docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md:1162-1165`) says the first marker write shows as `(formatting) normalize: whitespace/format`; that text was S6 plan gap 17's interim choice, which left the dedicated row to the owner. The owner chose the row on 2026-11-10. Task 11 Step 2 item 2 replaces the paragraph in lane `report`'s commit, together with README's matching sentence (`README.md:2180-2183`) and the code, so design, README and code never disagree at any commit.
8. **Q3: a guard-refused server's JSON.** `planWrite` computes `Normalize` before `guardCheck` (`plan.go:343-354`), and `jsonServerFor` always maps `changes` (`json.go:434-446`), so a refused-by-guard server already shows what the write would have done (`locked`'s `add` in `json_preserved.golden.json`). `external_section` follows that rule: `locked` gains `"external_section": true` and the text prints no row (a refused server prints no change rows). Pinned in Task 5 (the JSON presence check), not changed, and documented in README by Task 6's docsDelta ("like the other `changes`, also on a server the guard refuses").
9. **Q4: the login check's verdict is unchanged, and it is not "could not check".** The owner's text names the probe's "could not check" path. That path is the hop failure (S5: `fleet.FailedHopOf(err) != ""` in `classifyProbe`, `internal/sshwrite/probe.go:61-68`), which this error never takes: `Exec` runs on the target's client and the error carries no `HopStage`. The probe's exec runs after the connect returned, so it is `stageAuthed`, and P08 already sorts every `stageAuthed` failure as REJECTED, which restores (`probe.go:69-71`; README `:3228`: "anything that goes wrong after it succeeded (… a session that will not open …) restores the previous file"; the P08 spec, line 719, tests `open session: OpenChannelError` as rejected; `TestClassifyProbe`'s `exec deadline` row). Before Q4 a session open that hit the x/crypto race hung the whole apply; after it, the open fails within 10 s and the verdict is the one P08 designed. Task 9 pins it with a `TestClassifyProbe` row. Whether an unanswered session open after a good login should instead be UNPROVEN (file kept) is a P08 design question, not part of F1; flagged for the owner, no code.
10. **Q4: the bound.** `SessionOpenTimeout = 10 * time.Second`, exported from `internal/sshconn`. Why 10 s: opening a session on an authenticated connection is one round trip (a `CHANNEL_OPEN` and its confirmation), cheaper than the TCP connect plus key exchange the CLI already bounds by `dialTimeout = 10 * time.Second` (`cmd/sshepherd/audit.go:22`), so the dial bound is a generous ceiling for a healthy server and a short wait for a dead one. It is not derived from `Dialer.DialTimeout` because `Exec` takes an `*ssh.Client`, not a `Dialer`, and its signature is the `execFn` seam type in sshwrite (`internal/sshwrite/sshwrite.go:420`); widening it would touch every seam for no gain. The wait is `min(ctx, SessionOpenTimeout)`: a caller with an earlier deadline (audit's 30 s per-server context, the probe's 15 s `probeExecDeadline`) ends sooner and gets ctx's kind; a caller that passed `context.WithoutCancel` (the write session derives its own deadline from that, `sshwrite.go:403`; any future caller without one) is still bounded. Tests shorten it through an unexported `sessionOpenWait` (no sshconn test calls `t.Parallel`).
11. **Q4: what is returned.** On the bound: `open session: no answer from the server within 10s`, kind `timeout`. On ctx: `open session: context deadline exceeded` / `context canceled`, kind `ctxKind(ctx)` (`timeout` / `canceled`). Both wrap `ErrSessionNotOpened`, so sshwrite's stage-1 rule ("a session that never opened cannot have started the script", `internal/sshwrite/session.go:90-92`) still holds: `Exec` sends the exec request only after the open is confirmed, and a confirmation that never arrived means no script ran. A session open the server refuses promptly is unchanged: kind `remote` (`TestExecMarksASessionThatNeverOpened`'s "a dead connection" subtest). A silent-but-alive server used to fail when the socket deadline fired, as `remote`; it now fails at the bound as `timeout`, which describes it better (audit's `error_kind` for that server changes from `remote` to `timeout`; README's Classified-errors paragraph says so).
12. **Q4: closing the client, and the goroutine that may stay.** On giving up, `openSession` closes the client. On a direct connection that closes the socket and drops every pending channel, so a `NewSession` still waiting returns and its goroutine ends (goleak-clean, Task 8). On a tunnelled (`via:`) target the client runs over a direct-tcpip channel, and `ssh.Client.Close` only sends the channel close: the waiting `NewSession` (and its goroutine) ends when the bastion answers that close, or when `Conn.Close` closes the hop. Every caller closes its `Conn`, so it is still goleak-safe, but no test drives a silent session behind a bastion (open risk; an `sshtest` bastion row with `Forward` is the follow-up if the owner wants it). In the true x/crypto race (the mux already dropped its channels before this open was registered, so nothing will ever close its reply channel) the goroutine stays blocked until the process exits: one goroutine per stuck open, in a short-lived CLI. A session that opens after the wait ended is closed by the goroutine itself. Callers are safe with a closed client: every caller closes its `Conn` afterwards (a second `Close` only returns an error that is discarded), a tunnelled connection's hop is closed by `Conn.Close` as before, sshwrite's one reconnect replaces `s.conn` (`session.go:242-254`), and a later `Exec` on the dead client fails promptly or within the same bound.
13. **Q4: no caller changes.** sshread wraps with `%w` (`internal/sshread/sshread.go:189-192, 200-203, 220-223`) and `ReadAuthorizedKeys` wraps in `SanitizedError`, which unwraps (`internal/sshconn/sshconn.go:106-109`), so `fleet.ErrorKindOf` and `errors.Is(err, ErrSessionNotOpened)` see through both (Task 8's sshread test). sshwrite's stage-1 write reads the marker with `errors.Is` (`session.go:92`), never the kind; Task 9 adds the timeout-kinded error as a second row of the existing `a session that never opened did not start the upload` subtest (`internal/sshwrite/session_test.go:270-286`) and of `TestClassifyProbe`. Both rows are documentation pins: the existing remote-kinded row already kills a mutant of `session.go:92`, and `classifyProbe` returns REJECTED for every `stageAuthed` error without a hop (`probe.go:69`), so no new mutant is killed by them alone. The verify and later stages pass `started = true`, as today.

## How this plan is cut (read first)

### Why the lanes look the way they do

1. **One round, three lanes.** The three questions share no file: Q1 is `cmd/sshepherd/import*.go`, Q3 is `internal/apply/{plan,report,json}.go`, their preserve tests and goldens, and one assertion in `cmd/sshepherd/preserve_hermetic_test.go`, Q4 is `internal/sshconn` (with `sshtest`), a new sshread test file and one row in each of two existing sshwrite test files. Each lane builds and passes `make check` on `065c1d3` alone.
2. **`deadcode ./cmd/sshepherd` stays green per lane.** Lane `import` adds `warnFreshDrops`, `warnSettingsLost`, `lostUsers`, `markedByKey`, `lostGroups`, `lostServers`, `serverName` and the `settingLosses` table, all reached from `importRun.run`. Lane `report` adds `newSectionRow`, called by `renderChange`. Lane `sshconn` adds `openSession`, called by `Exec`. `sshtest` is a test-support package outside `main`'s reach, and a struct field is not a function.
3. **No lane's tests read the README text F1 changes.** F1 adds no flag and changes no `--help` text: `TestHelpMatchesREADMETables` reads only README's flag tables, and `TestHelpExamplesAndExitCodes` checks that README carries each `exitCodes*` `--help` footer verbatim; lane `sshconn`'s delta edits an Exit codes **table row**, never a footer block. So no lane applies a delta locally; the integrator still applies each lane's docsDelta **before** that lane's `make check` (Task 11), which runs both tests against the edited README.
4. **Integration.** Only lane `sshconn` changes code the real-sshd suite exercises on every command (`Exec`), so it is `needsIntegration: true`; the lane runs `make integration IT_DISTRO=alpine`, the integrator all three distros.

### Rounds

| Round | Lane (disjoint files) | Builds on |
|---|---|---|
| 1 | `import` (Tasks 1-3): `cmd/sshepherd/import.go`, `cmd/sshepherd/import_json.go`, `cmd/sshepherd/import_settings.go` (new), `cmd/sshepherd/import_settings_test.go` (new) | `065c1d3` |
| 1 | `report` (Tasks 4-6): `internal/apply/{plan,report,json}.go`, `internal/apply/preserve_plan_test.go`, `internal/apply/preserve_report_test.go`, `internal/apply/testdata/{plan_preserved.golden,json_preserved.golden.json}`, `cmd/sshepherd/preserve_hermetic_test.go` | same |
| 1 | `sshconn` (Tasks 7-10): `internal/sshconn/connect.go`, `internal/sshconn/session_open_test.go` (new), `internal/sshconn/handshake_test.go` (one comment), `internal/sshconn/sshtest/sshtest.go`, `internal/sshread/session_open_test.go` (new), `internal/sshwrite/session_test.go` (one row), `internal/sshwrite/probe_test.go` (one row) | same |

After round 1 the integrator runs Task 11 and an independent verifier runs Task 12. No lane owns either.

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted. Every `-update` run is followed by `git status --short -- '*testdata*'`, which must list only the files the step names.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests exists; a test that pins behaviour already present says so in its step. A build failure caused only by a sibling test does not count as seeing it fail; where a test's first failure would be a build failure, the step adds the bare declaration first and shows the assertion failing.
- **gocyclo 15 is a production-code gate;** never `//nolint:gocyclo`. `normalize` gains one `&&` (it stays well under 15); `openSession` is a single `select`.
- **Run `gofmt -w` and `goimports -w` on every Go file you touch** before `make check`. Alignment in these blocks is written by hand.
- **New test variables must not shadow builtins** (revive): no `new`, `len`, `max`, `min`, `copy`, `cap`, `close`, `clear`. The blocks use `want`, `got`, `lost`, `wait`, `fresh`, `old`.
- **Hermetic tests own their goroutines.** Every `sshtest.Server` and agent is closed by `t.Cleanup` (the helpers do this); goleak fails the package otherwise. Q4's tests also wait for every goroutine they start.
- **A mutation run must finish before reporting.** Each lane's last task lists its mutants. Apply one at a time, run the named tests, record killed or survived, and revert. Report the table with the hand-back; explain any survivor (equivalent) or add the test that kills it.
- **Before hand-back:** run `make check` (and `make integration IT_DISTRO=alpine` under the runner's lock when the lane says `needsIntegration`), then `git add -A`, unstage every path outside the lane's globs (`README.md`, `CLAUDE.md` and `docs/` always), and write the patch.
- **`docsDelta`** blocks are integrator-only text for `README.md`, `CLAUDE.md` Status and the spec. A lane reports them unchanged and never edits those files in its patch. README samples are copied from the goldens or the test expectations the delta names, never from this plan.

---

## File structure

| File | Lane | Responsibility |
|---|---|---|
| `cmd/sshepherd/import.go` | `import` | `warnFreshDrops` (reads FILE once), `warnMemoryLost` takes the parsed FILE; `run` passes `saved` |
| `cmd/sshepherd/import_json.go` | `import` | `importWarnSettingsDropped = "manifest_settings_dropped"` |
| `cmd/sshepherd/import_settings.go` (new) | `import` | `settingLoss`, `settingLosses`, `warnSettingsLost`, `lostUsers`, `markedByKey`, `lostGroups`, `lostServers`, `serverName` |
| `cmd/sshepherd/import_settings_test.go` (new) | `import` | `TestSettingLossesCompare`, `TestImportForceWarnsSettingsLost` (incl. the `no --force` and `--merge into another FILE` rows), `TestImportForceOperatorKeyReMarks`, `TestImportJSONSettingsDroppedWarning` |
| `internal/apply/plan.go` | `report` | `Normalize.ExternalSection`; `nonKeyLines` returns it; `normalize` stores it and drops the whitespace residual for it |
| `internal/apply/report.go` | `report` | `newSectionRow` |
| `internal/apply/json.go` | `report` | `jsonNormalize.ExternalSection` (`external_section,omitempty`) |
| `internal/apply/preserve_plan_test.go`, `preserve_report_test.go`, `testdata/plan_preserved.golden`, `testdata/json_preserved.golden.json` | `report` | `TestPlanExternalSection`; `TestRenderPreservedGoldens`' `gitea-3` assertion and JSON presence check; regenerated goldens |
| `cmd/sshepherd/preserve_hermetic_test.go` | `report` | `TestPreserveHermetic` gains a first `apply --dry-run` asserting the marker row and no `(formatting)` row |
| `internal/sshconn/connect.go` | `sshconn` | `SessionOpenTimeout`, `sessionOpenWait`, `openSession`; `Exec` calls it |
| `internal/sshconn/sshtest/sshtest.go` | `sshconn` | `ServerConfig.SilentSessions`: never answer a session open |
| `internal/sshconn/session_open_test.go` (new), `handshake_test.go` (comment) | `sshconn` | `TestExecBoundsASessionThatNeverOpens`, `TestExecHealthySessionUnchanged` |
| `internal/sshread/session_open_test.go` (new) | `sshconn` | `TestReadSessionThatNeverOpens` |
| `internal/sshwrite/session_test.go` | `sshconn` | `TestApplyReconnectAfterDrop`'s `a session that never opened did not start the upload` subtest runs for a refused open (`remote`, as today) and a bounded one (`timeout`, F1 Q4) |
| `internal/sshwrite/probe_test.go` | `sshconn` | `TestClassifyProbe` row `session open given up (F1 Q4)` |

---

## Round 1 — lane `import` (Tasks 1-3)

Lane `import` owns `cmd/sshepherd/import.go`, `cmd/sshepherd/import_json.go`, `cmd/sshepherd/import_settings.go`, `cmd/sshepherd/import_settings_test.go`. `needsIntegration: false`.

### Task 1: the comparison (`settingLosses`)

**Files:**
- Modify: `cmd/sshepherd/import_json.go:19-26` (the kind constants)
- Create: `cmd/sshepherd/import_settings.go`, `cmd/sshepherd/import_settings_test.go`

- [ ] **Step 1: Write the failing test.** Create `cmd/sshepherd/import_settings_test.go`:

```go
package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
)

// settingsFixture holds every manifest-only setting a fresh import cannot
// derive from an ssh config: ops (k1) operator, alice (k2) protected, bob
// (k3) in group web-team, db-1 tagged db and reached via the jump_only
// bastion, and gitea with a preserve: rule.
func settingsFixture(t *testing.T) string {
	t.Helper()
	return "users:\n" +
		"  - {name: ops, operator: true, keys: [" + qk(t, 1) + "]}\n" +
		"  - {name: alice, protected: true, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: bob, keys: [" + qk(t, 3) + "]}\n" +
		"groups:\n  - {name: web-team, members: [bob]}\n" +
		"servers:\n" +
		"  - {name: bastion, host: 10.0.0.9, user: jump, jump_only: true}\n" +
		"  - {name: db-1, host: 10.0.1.5, user: deploy, via: bastion, tags: [db]}\n" +
		"  - {name: gitea, host: 10.0.0.2, user: git, preserve: [{command: '/usr/local/bin/gitea serv key-[0-9]+'}]}\n" +
		"access:\n" +
		"  - {user: alice, servers: [gitea]}\n" +
		"  - {group: web-team, servers: [\"@db\"]}\n"
}

// parseManifest is the package's existing helper (cmd/sshepherd/conflicts_test.go:291).

// lossesOf runs every settingLosses entry, keyed by what it names.
func lossesOf(old, fresh *config.Config) map[string][]string {
	got := map[string][]string{}
	for _, l := range settingLosses {
		if names := l.lost(old, fresh); len(names) > 0 {
			got[l.what] = names
		}
	}
	return got
}

// TestSettingLossesCompare (F1 Q1, gap 2): a setting the fresh output
// reproduces is not lost; users are matched by key, never by name; each
// flag is compared on its own field; a server setting is lost when the
// server is missing (labelled "[not in this import]") or its value differs.
func TestSettingLossesCompare(t *testing.T) {
	fixture := settingsFixture(t)
	old := parseManifest(t, fixture)
	everything := map[string][]string{
		"operator: true users":       {"ops"},
		"protected: true users":      {"alice"},
		"groups:":                    {"web-team"},
		"tags: on servers":           {"db-1"},
		"via: routes":                {"db-1 via bastion"},
		"jump_only: true servers":    {"bastion"},
		"preserve: rules on servers": {"gitea"},
	}
	missing := map[string][]string{
		"operator: true users":       {"ops"},
		"protected: true users":      {"alice"},
		"groups:":                    {"web-team"},
		"tags: on servers":           {"db-1 [not in this import]"},
		"via: routes":                {"db-1 via bastion [not in this import]"},
		"jump_only: true servers":    {"bastion [not in this import]"},
		"preserve: rules on servers": {"gitea [not in this import]"},
	}
	changed := "users:\n" +
		"  - {name: ops, keys: [" + qk(t, 1) + "]}\n" +
		"  - {name: alice, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: bob, keys: [" + qk(t, 3) + "]}\n" +
		"groups:\n  - {name: ops-team, members: [bob]}\n" +
		"servers:\n" +
		"  - {name: bastion, host: 10.0.0.9, user: jump}\n" +
		"  - {name: edge, host: 10.0.0.8, user: jump}\n" +
		"  - {name: db-1, host: 10.0.1.5, user: deploy, via: edge, tags: [db2]}\n" +
		"  - {name: gitea, host: 10.0.0.2, user: git, preserve: [{command: '/usr/local/bin/gitea hook key-[0-9]+'}]}\n" +
		"access:\n" +
		"  - {user: alice, servers: [gitea]}\n" +
		"  - {group: ops-team, servers: [\"@db2\"]}\n"
	// If the hook pattern is ever refused at load (a probe), use any other
	// rule that loads: the row needs only a preserve: value that differs.
	renamed := strings.Replace(fixture, "{name: ops, operator: true", "{name: k1-user, operator: true", 1)
	for _, tt := range []struct {
		name  string
		fresh string
		want  map[string][]string
	}{
		{"everything reproduced", fixture, map[string][]string{}},
		{"an operator renamed but holding the same key", renamed, map[string][]string{}},
		{"every value changed", changed, everything},
		{"nothing at all (a --servers-only import of other hosts)", "users: []\nservers: []\naccess: []\n", missing},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := lossesOf(old, parseManifest(t, tt.fresh))
			if len(got) != len(tt.want) {
				t.Fatalf("losses = %v, want %v", got, tt.want)
			}
			for what, names := range tt.want {
				if !slices.Equal(got[what], names) {
					t.Errorf("%s: %v, want %v", what, got[what], names)
				}
			}
		})
	}
	if order := []string{"operator: true users", "protected: true users", "groups:", "tags: on servers", "via: routes", "jump_only: true servers", "preserve: rules on servers"}; !slices.EqualFunc(settingLosses, order, func(l settingLoss, w string) bool { return l.what == w }) {
		t.Errorf("settingLosses order differs from manifest order %v (gap 3)", order)
	}
}
```

- [ ] **Step 2: Add only the declarations and see the test fail on its assertions.** Add the kind to `cmd/sshepherd/import_json.go`'s constant block (after `importWarnMemoryDropped`, `:25`):

```go
	importWarnSettingsDropped = "manifest_settings_dropped"
```

Create `cmd/sshepherd/import_settings.go` with the type and an empty table:

```go
package main

import "github.com/javadh75/SSHepherd/internal/config"

// settingLoss is one kind of manifest-only setting a fresh import cannot
// derive from an ssh config (F1 Q1). lost names what FILE (old) holds that
// the fresh output does not reproduce, in manifest order.
type settingLoss struct {
	what        string // the setting, as the warning names it
	verb        string // what the fresh import does to it
	consequence string
	remedy      string // ends just before "with --merge FILE"
	lost        func(old, fresh *config.Config) []string
}

var settingLosses = []settingLoss{}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestSettingLossesCompare' -count=1`
Expected: FAIL (`every value changed` and `nothing at all`: `losses = map[], want map[…]`; the order check fails).

- [ ] **Step 3: Write the comparison.** Replace `cmd/sshepherd/import_settings.go`:

```go
package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// settingLoss is one kind of manifest-only setting a fresh import cannot
// derive from an ssh config (F1 Q1). lost names what FILE (old) holds that
// the fresh output does not reproduce, in manifest order.
type settingLoss struct {
	what        string // the setting, as the warning names it
	verb        string // what the fresh import does to it
	consequence string
	remedy      string // ends just before "with --merge FILE"
	lost        func(old, fresh *config.Config) []string
}

// settingLosses is checked in manifest order: users, groups, then the
// server fields in config.Server order. One warning per kind keeps each
// remedy beside its names (only an operator can be re-marked from the
// command line).
var settingLosses = []settingLoss{
	{"operator: true users", "does not mark", "they lose their fleet-wide grant", "re-mark them with --operator-key PATH, or keep them",
		func(old, fresh *config.Config) []string {
			return lostUsers(old, fresh, func(u config.User) bool { return u.Operator })
		}},
	{"protected: true users", "does not mark", "their keys lose the critical audit tier and the --operator gate", "keep them",
		func(old, fresh *config.Config) []string {
			return lostUsers(old, fresh, func(u config.User) bool { return u.Protected })
		}},
	{"groups:", "drops", "their members lose the grants made through them", "keep them", lostGroups},
	{"tags: on servers", "drops", "@tag grants no longer reach them", "keep them",
		func(old, fresh *config.Config) []string {
			return lostServers(old, fresh, func(s config.Server) bool { return len(s.Tags) > 0 },
				func(was, now config.Server) bool { return slices.Equal(was.Tags, now.Tags) }, serverName)
		}},
	{"via: routes", "does not reproduce", "where they stay, they would be dialed another way", "keep them",
		func(old, fresh *config.Config) []string {
			return lostServers(old, fresh, func(s config.Server) bool { return s.Via != "" },
				func(was, now config.Server) bool { return was.Via == now.Via },
				func(s config.Server) string { return s.Name + " via " + s.Via })
		}},
	{"jump_only: true servers", "does not mark", "where they stay, apply would manage their authorized_keys", "keep them",
		func(old, fresh *config.Config) []string {
			return lostServers(old, fresh, func(s config.Server) bool { return s.JumpOnly },
				func(_, now config.Server) bool { return now.JumpOnly }, serverName)
		}},
	{"preserve: rules on servers", "drops", "where they stay, apply would remove the lines they keep", "keep them",
		func(old, fresh *config.Config) []string {
			return lostServers(old, fresh, func(s config.Server) bool { return len(s.Preserve) > 0 },
				func(was, now config.Server) bool { return slices.Equal(was.Preserve, now.Preserve) }, serverName)
		}},
}

// warnSettingsLost: a fresh import -o FILE --force drops whatever its ssh
// config cannot reproduce. One line per kind of setting, each ending with
// the paste-ready --merge FILE that keeps it (F1 Q1).
func warnSettingsLost(w *importWarnings, out string, old, fresh *config.Config) {
	for _, l := range settingLosses {
		names := l.lost(old, fresh)
		if len(names) == 0 {
			continue
		}
		w.addAll(importWarnSettingsDropped, fmt.Sprintf("%s holds %s (%s) that this fresh import %s: %s; %s with --merge %s",
			out, l.what, strings.Join(names, ", "), l.verb, l.consequence, l.remedy, hintArg(out)))
	}
}

// lostUsers names old's users that has marks when no fresh user that has
// marks holds one of their keys. A fresh import names users after their
// identity files, so users are matched by key, never by name.
func lostUsers(old, fresh *config.Config, has func(config.User) bool) []string {
	var names []string
	for _, u := range old.Users {
		if has(u) && !markedByKey(fresh, u.Keys, has) {
			names = append(names, u.Name)
		}
	}
	return names
}

// markedByKey reports whether a fresh user that has marks owns one of keys.
func markedByKey(fresh *config.Config, keys []string, has func(config.User) bool) bool {
	for _, line := range keys {
		if k, err := authkeys.ParseLine(line); err == nil && k != nil {
			if owner, ok := fresh.OwnerOf(k.Fingerprint); ok && has(owner) {
				return true
			}
		}
	}
	return false
}

// lostGroups names old's groups the fresh output has no group of that name for.
func lostGroups(old, fresh *config.Config) []string {
	var names []string
	for _, g := range old.Groups {
		if !slices.ContainsFunc(fresh.Groups, func(f config.Group) bool { return f.Name == g.Name }) {
			names = append(names, g.Name)
		}
	}
	return names
}

// lostServers labels old's servers that has selects when the fresh output
// has no server of that name (marked "[not in this import]": apply will not
// touch it, so the consequence applies only where the server stays), or one
// whose setting same rejects.
func lostServers(old, fresh *config.Config, has func(config.Server) bool, same func(was, now config.Server) bool, label func(config.Server) string) []string {
	var names []string
	for _, s := range old.Servers {
		if !has(s) {
			continue
		}
		now, ok := fresh.ServerNamed(s.Name)
		switch {
		case !ok:
			names = append(names, label(s)+" [not in this import]")
		case !same(s, now):
			names = append(names, label(s))
		}
	}
	return names
}

func serverName(s config.Server) string { return s.Name }
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestSettingLossesCompare' -count=1`
Expected: PASS. (`deadcode` would still flag `warnSettingsLost` here; Task 2 adds its caller before any `make check`.)

### Task 2: warn on a fresh `-o FILE --force`

**Files:**
- Modify: `cmd/sshepherd/import.go:22-40` (`warnMemoryLost`), `:453-455` (the call in `run`)
- Test: `cmd/sshepherd/import_settings_test.go`

- [ ] **Step 1: Write the failing CLI tests.** Append to `cmd/sshepherd/import_settings_test.go` (add `"bytes"`, `"os"`, `"path/filepath"` and `"github.com/javadh75/SSHepherd/internal/testkeys"` to its imports):

```go
// wantSettingLines are the fixture's warnings over FILE m, in order (gap 3).
func wantSettingLines(m string) []string {
	h := hintArg(m)
	return []string{
		m + " holds operator: true users (ops) that this fresh import does not mark: they lose their fleet-wide grant; re-mark them with --operator-key PATH, or keep them with --merge " + h,
		m + " holds protected: true users (alice) that this fresh import does not mark: their keys lose the critical audit tier and the --operator gate; keep them with --merge " + h,
		m + " holds groups: (web-team) that this fresh import drops: their members lose the grants made through them; keep them with --merge " + h,
		m + " holds tags: on servers (db-1) that this fresh import drops: @tag grants no longer reach them; keep them with --merge " + h,
		m + " holds via: routes (db-1 via bastion) that this fresh import does not reproduce: where they stay, they would be dialed another way; keep them with --merge " + h,
		m + " holds jump_only: true servers (bastion [not in this import]) that this fresh import does not mark: where they stay, apply would manage their authorized_keys; keep them with --merge " + h,
		m + " holds preserve: rules on servers (gitea) that this fresh import drops: where they stay, apply would remove the lines they keep; keep them with --merge " + h,
	}
}

// settingLines returns stderr's manifest_settings_dropped lines, in order.
func settingLines(stderr string) []string {
	var got []string
	for _, line := range strings.Split(stderr, "\n") {
		if i := strings.Index(line, " that this fresh import "); i >= 0 && !strings.Contains(line, "revocation memory") {
			got = append(got, line)
		}
	}
	return got
}

// TestImportForceWarnsSettingsLost (F1 Q1): a fresh import -o FILE --force
// over a manifest holding manifest-only settings warns once per kind, in
// manifest order, exit 0, the file is still replaced; a via: the ssh
// config reproduces is not named; --merge (in place or into another FILE),
// a FILE without such settings, a run without -o and a run refused for
// lack of --force (exit 3) stay quiet.
func TestImportForceWarnsSettingsLost(t *testing.T) {
	hermeticHome(t)
	direct := writeSSHConfig(t, "Host gitea\n  HostName 10.0.0.2\n  User git\nHost db-1\n  HostName 10.0.1.5\n  User deploy\n")
	routed := writeSSHConfig(t, "Host bastion\n  HostName 10.0.0.9\n  User jump\nHost db-1\n  HostName 10.0.1.5\n  User deploy\n  ProxyJump bastion\nHost gitea\n  HostName 10.0.0.2\n  User git\n")
	other := writeSSHConfig(t, "Host web-9\n  HostName 10.0.9.9\n  User deploy\n")
	t.Run("every kind, one line each", func(t *testing.T) {
		m := writeConfig(t, settingsFixture(t))
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", direct, "--servers-only", "-o", m, "--force"}, &out, &errBuf); code != 0 {
			t.Fatalf("exit %d\n%s", code, errBuf.String())
		}
		got, want := settingLines(errBuf.String()), wantSettingLines(m)
		if len(got) != len(want) {
			t.Fatalf("got %d lines, want %d:\n%s", len(got), len(want), errBuf.String())
		}
		for i := range want {
			if !strings.HasSuffix(got[i], want[i]) {
				t.Errorf("line %d = %q\nwant suffix %q", i, got[i], want[i])
			}
		}
		if strings.Contains(fileString(t, m), "groups:") {
			t.Error("FILE was not replaced by the fresh manifest")
		}
	})
	t.Run("a reproduced via: is not named", func(t *testing.T) {
		m := writeConfig(t, settingsFixture(t))
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", routed, "--servers-only", "-o", m, "--force"}, &out, &errBuf); code != 0 {
			t.Fatalf("exit %d\n%s", code, errBuf.String())
		}
		got := settingLines(errBuf.String())
		if len(got) != 6 || strings.Contains(errBuf.String(), "via: routes") || !strings.Contains(errBuf.String(), "jump_only: true servers (bastion)") {
			t.Errorf("want six lines, no via: line, the jump_only: line still there:\n%s", errBuf.String())
		}
	})
	plainFile := "users:\n  - {name: bob, keys: [" + qk(t, 3) + "]}\nservers:\n  - {name: gitea, host: 10.0.0.2, user: git}\naccess:\n  - {user: bob, servers: [gitea]}\n"
	plain := writeConfig(t, plainFile) // a --merge source with no manifest-only setting
	for _, tt := range []struct {
		name     string
		args     func(m string) []string
		file     string
		wantCode int
	}{
		{"--merge keeps every setting", func(m string) []string {
			return []string{"import", other, "--servers-only", "--merge", m, "-o", m, "--force"}
		}, settingsFixture(t), 0},
		// Kills a warnFreshDrops call moved outside `if mergePath == ""`: -o names
		// a different existing FILE holding every setting, which a merge run
		// replaces with --force but never compares (R1-1).
		{"--merge into another FILE stays quiet", func(m string) []string {
			return []string{"import", other, "--servers-only", "--merge", plain, "-o", m, "--force"}
		}, settingsFixture(t), 0},
		{"a FILE without such settings", func(m string) []string { return []string{"import", direct, "--servers-only", "-o", m, "--force"} },
			plainFile, 0},
		{"no -o", func(string) []string { return []string{"import", direct, "--servers-only"} }, settingsFixture(t), 0},
		// Without --force the write is refused (exit 3): no "drops" line may
		// precede the refusal, and FILE is untouched (R0-2).
		{"no --force (refused)", func(m string) []string { return []string{"import", direct, "--servers-only", "-o", m} },
			settingsFixture(t), 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := writeConfig(t, tt.file)
			var out, errBuf bytes.Buffer
			if code := run(tt.args(m), &out, &errBuf); code != tt.wantCode {
				t.Fatalf("exit %d, want %d\n%s", code, tt.wantCode, errBuf.String())
			}
			if got := settingLines(errBuf.String()); len(got) != 0 {
				t.Errorf("warned:\n%s", strings.Join(got, "\n"))
			}
			if tt.wantCode != 0 && fileString(t, m) != tt.file {
				t.Error("a refused run changed FILE")
			}
		})
	}
}

// TestImportForceOperatorKeyReMarks (F1 Q1, gap 2): --operator-key with
// the operator's key re-marks it under the fresh name, so no operator line;
// the same import without --operator-key names the FILE user.
func TestImportForceOperatorKeyReMarks(t *testing.T) {
	home := hermeticHome(t)
	work := filepath.Join(home, "work")
	if err := os.WriteFile(work+".pub", []byte(testkeys.Line(t, 1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sshCfg := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n  IdentityFile "+work+"\n")
	file := "users:\n  - {name: legacy-ops, operator: true, keys: [" + qk(t, 1) + "]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\naccess: []\n"
	for _, tt := range []struct {
		name  string
		extra []string
		warns bool
	}{
		{"re-marked by --operator-key", []string{"--operator-key", work}, false},
		{"imported as a plain user", nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := writeConfig(t, file)
			var out, errBuf bytes.Buffer
			args := append([]string{"import", sshCfg, "-o", m, "--force"}, tt.extra...)
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit %d\n%s", code, errBuf.String())
			}
			wantLines := 0
			if tt.warns {
				wantLines = 1
			}
			got := strings.Contains(errBuf.String(), "holds operator: true users (legacy-ops)")
			if got != tt.warns || len(settingLines(errBuf.String())) != wantLines {
				t.Errorf("operator line = %v, want %v:\n%s", got, tt.warns, errBuf.String())
			}
		})
	}
}

// TestImportJSONSettingsDroppedWarning (F1 Q1): --json carries one
// manifest_settings_dropped entry per line, counted in summary.warnings,
// each message exactly what stderr printed.
func TestImportJSONSettingsDroppedWarning(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host gitea\n  HostName 10.0.0.2\n  User git\nHost db-1\n  HostName 10.0.1.5\n  User deploy\n")
	dst := writeConfig(t, settingsFixture(t))
	code, doc, stderr := importJSONCLI(t, path, "--servers-only", "-o", dst, "--force")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	want := wantSettingLines(dst)
	if len(doc.Warnings) != len(want) || doc.Summary.Warnings != len(want) {
		t.Fatalf("warnings = %+v (summary %d), want %d", doc.Warnings, doc.Summary.Warnings, len(want))
	}
	for i, w := range doc.Warnings {
		if w.Kind != importWarnSettingsDropped || w.Message != want[i] || !strings.Contains(stderr, w.Message) {
			t.Errorf("warning %d = %+v, want kind %s, message %q", i, w, importWarnSettingsDropped, want[i])
		}
	}
}

func fileString(t *testing.T, path string) string { t.Helper(); return string(fileBytes(t, path)) }
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestImportForceWarnsSettingsLost|TestImportForceOperatorKeyReMarks|TestImportJSONSettingsDroppedWarning' -count=1`
Expected: FAIL (`got 0 lines, want 7`; `imported as a plain user: operator line = false, want true`; `warnings = [] … want 7`). The quiet rows already pass (they pin behaviour that holds before the change and must still hold after it).

- [ ] **Step 2: Wire the warning.** In `cmd/sshepherd/import.go`, replace `warnMemoryLost` (`:22-40`) with:

```go
// warnFreshDrops: a fresh import replacing an existing manifest with -o
// --force drops what the ssh config cannot reproduce: its revocation memory
// and its manifest-only settings (F1 Q1). --force names the overwrite, so
// this warns rather than refuses. Best effort: a missing or invalid file
// has nothing to lose. fresh is the generated manifest.
func warnFreshDrops(w *importWarnings, out string, force bool, fresh *config.Config) {
	if out == "" || !force {
		return
	}
	raw, err := os.ReadFile(out) // #nosec G304 -- the path the user passed to -o
	if err != nil {
		return
	}
	old, err := config.Parse(raw)
	if err != nil {
		return
	}
	warnMemoryLost(w, out, old)
	warnSettingsLost(w, out, old, fresh)
}

// warnMemoryLost: FILE's serial: and revoked: entries go with it, so every
// revoked key could be re-granted.
func warnMemoryLost(w *importWarnings, out string, old *config.Config) {
	if old.Serial() == 0 && len(old.Tombstones) == 0 {
		return
	}
	w.addAll(importWarnMemoryDropped, fmt.Sprintf("%s holds revocation memory (serial %d, %s) that this fresh import drops: a revoked key could be re-granted; keep it with --merge %s",
		out, old.Serial(), apply.Plural(len(old.Tombstones), "revoked: entry", "revoked: entries"), hintArg(out)))
}
```

and the call in `run` (`:453-455`):

```go
	if r.opts.mergePath == "" {
		warnFreshDrops(warns, r.opts.outPath, r.opts.force, saved)
	}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'Setting|OperatorKeyReMarks|MemoryLost|MemoryDropped|TestImportJSON' -count=1`
Expected: PASS (the memory tests, `TestImportForceWarnsMemoryLost` and `TestImportJSONMemoryDroppedWarning`, are byte-identical: their fixtures hold no manifest-only setting).

- [ ] **Step 3: Gates.** `gofmt -w` and `goimports -w` the three files; `make check`.
Expected: PASS (`deadcode` sees every new function reached from `importRun.run`).

### Task 3: mutation run; hand back

- [ ] **Step 1: Mutants** (run `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'Setting|OperatorKeyReMarks|Memory|TestImportJSON' -count=1`; revert each):

| # | Mutant | Killed by |
|---|---|---|
| 1 | `run` never calls `warnFreshDrops` | `TestImportForceWarnsSettingsLost`, `TestImportForceWarnsMemoryLost` |
| 2 | the call moved outside `if r.opts.mergePath == ""` | `--merge into another FILE stays quiet` (FILE holds every setting); `TestImportForceWarnsMemoryLost` (its `--merge` half). Not `--merge keeps every setting`: in place, FILE and the merged output hold the same settings, so nothing is lost (R1-1) |
| 3 | `warnFreshDrops` drops `warnSettingsLost` | `every kind, one line each` |
| 4 | `markedByKey` matches by name (`fresh.Users` holding `u.Name` with the flag) | `an operator renamed …` (Task 1), `re-marked by --operator-key` |
| 5 | `markedByKey` ignores `has(owner)` (any owner keeps the mark) | `every value changed` (ops is owned, not an operator), `imported as a plain user` |
| 6 | operator `has` reads `u.IsProtected()` | `every value changed` (alice named under operators) and the exact lines |
| 7 | `lostServers`: `ok && same(s, now)` → `ok` (name only) | `every value changed` (db-1, bastion and gitea exist with other values) |
| 8 | via `same` → `true` | `every value changed`, `every kind, one line each` (db-1 exists in the fresh output without via) |
| 9 | jump_only `same` → `true` | `every value changed` (bastion exists, not jump_only); `nothing at all` alone would not kill it (a missing server is named either way) |
| 10 | preserve `same` → `true` | `every value changed` |
| 11 | tags `same` → `true` | `every value changed` |
| 12 | `lostGroups` compares nothing (always lost) | `everything reproduced` |
| 13 | two `settingLosses` entries swapped | the order check in `TestSettingLossesCompare`, `every kind, one line each` |
| 14 | `warnSettingsLost` drops `continue` on empty names (prints `()` lines) | `a FILE without such settings` |
| 15 | the message ends with `hintArg(out)` replaced by `out` | equivalent for temp paths that `hintArg` leaves unquoted; state it, or rerun with a path holding a space to kill it |
| 16 | kind `importWarnMemoryDropped` used for the new lines | `TestImportJSONSettingsDroppedWarning` |
| 17 | `warnFreshDrops` drops `\|\| !force` | `no --force (refused)` (seven lines would print before the exit-3 refusal) |
| 18 | `lostServers` labels a missing server without ` [not in this import]` | `nothing at all`, `every kind, one line each` (bastion) |
| 19 | `lostServers` labels every lost server ` [not in this import]` | `every value changed`, `every kind, one line each` |

- [ ] **Step 2: `make check`,** then hand back with the table and this docsDelta:

```text
docsDelta (lane import):
README.md, "Output files" paragraph (README.md:1642-1645): after the revocation-memory sentence
("… and proceeds.") add:
  It also warns, one line per kind of setting, when FILE holds manifest-only settings an ssh
  config cannot reproduce: `operator: true` and `protected: true` users the fresh output does not
  mark (users are matched by key, so `--operator-key` re-marks an operator), `groups:`, server
  `tags:`, `via:` routes the fresh output does not reproduce, `jump_only: true` servers and
  `preserve:` rules. Each line names what is lost and ends with `--merge FILE`, for example
  `FILE holds preserve: rules on servers (gitea) that this fresh import drops: where they stay, apply would remove the lines they keep; keep them with --merge FILE`
  (copy the wording from wantSettingLines in cmd/sshepherd/import_settings_test.go, with the path
  replaced by FILE). A server the fresh output does not list at all is named
  `NAME [not in this import]`: its setting is gone with it, and apply leaves it alone. The
  warning does not cover a server's `authorized_keys_file:` override or hand-written `access:`
  entries (gap 4; if the owner approves the `authorized_keys_file` row, list it here too). The
  run still exits 0; without `--force` it is refused as before and prints none of these lines.
README.md, `import --json` paragraph (README.md:1461): in the warnings kinds list add
  `manifest_settings_dropped` after `revocation_memory_dropped`.
README.md, groups paragraph (README.md:415): "a fresh `import -o FILE --force` replaces the file
  without them" → "a fresh `import -o FILE --force` replaces the file without them and warns".

README.md, "## Status", after the "Co-managed accounts" paragraph (README.md:86), add a new
  paragraph (lanes report and sshconn extend it):
  "Owner follow-ups: a fresh `import -o FILE --force` warns, one line per kind, about the
  manifest-only settings it drops (`operator:`/`protected:` marks, `groups:`, `tags:`, `via:`,
  `jump_only:`, `preserve:`; kind `manifest_settings_dropped`)."

docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md (Task 11 Step 2 item 4, this
  lane's commit): in the S8 "Warning kinds" import bullet (:449-452), after
  `revocation_memory_dropped`, add `manifest_settings_dropped` (F1 Q1, owner 2026-11-10).

CLAUDE.md, Status: add a new paragraph after the S6 paragraph:
  **Owner follow-ups F1** (decided 2026-11-10; planned in
  `docs/superpowers/plans/2026-11-10-p10-f1-owner-followups.md`): a fresh `import -o FILE --force`
  also warns (kind `manifest_settings_dropped`, one line per kind, each ending with `--merge FILE`)
  when FILE holds `operator:`/`protected:` marks the fresh output does not carry (matched by key),
  `groups:`, server `tags:`, `via:` routes it does not reproduce, `jump_only:` or `preserve:`
  rules (`cmd/sshepherd/import_settings.go`, `warnFreshDrops`).
```

---

## Round 1 — lane `report` (Tasks 4-6)

Lane `report` owns `internal/apply/plan.go`, `internal/apply/report.go`, `internal/apply/json.go`, `internal/apply/preserve_plan_test.go`, `internal/apply/preserve_report_test.go`, `internal/apply/testdata/plan_preserved.golden`, `internal/apply/testdata/json_preserved.golden.json`, `cmd/sshepherd/preserve_hermetic_test.go`. `needsIntegration: false` (the real-sshd `TestE2EPreserve*` in `cmd/sshepherd/preserve_e2e_test.go` asserts only `converged (no changes)` and `remove (unauthorized)`, never the formatting row).

### Task 4: `Normalize.ExternalSection`

**Files:**
- Modify: `internal/apply/plan.go:81-96` (`Normalize`), `:448-466` (`normalize`), `:468-499` (`nonKeyLines`)
- Test: `internal/apply/preserve_plan_test.go`

- [ ] **Step 1: Write the failing test.** Append to `internal/apply/preserve_plan_test.go`:

```go
// TestPlanExternalSection (F1 Q3): a write that adds the preserve: marker
// the file lacks is its own normalize finding (never whitespace, never a
// non-key line); it is not set when the marker is already there, when
// nothing is kept, or for a marker with nothing under it.
func TestPlanExternalSection(t *testing.T) {
	cfg := preserveCfg(t, 0)
	head := authkeys.ManagedHeader + "\n" + opLine(t) + "\n"
	for _, tt := range []struct {
		name, content            string
		section, empty, residual bool
	}{
		{"kept line, no marker", head + giteaLine(t, 7, 1) + "\n", true, false, false},
		{"kept line and its comment, no marker", head + "# gitea public key\n" + giteaLine(t, 7, 1) + "\n", true, false, false},
		{"marker there, a stray removed", head + testkeys.Line(t, 9) + " stray@laptop\n" + authkeys.PreserveMarker + "\n" + giteaLine(t, 7, 1) + "\n", false, false, false},
		{"nothing kept, no marker", authkeys.ManagedHeader + "\n  " + opLine(t) + "\n", false, false, true},
		{"marker with nothing under it", head + authkeys.PreserveMarker + "\n", false, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			p := giteaPlan(t, cfg, fleet.ReadResult{Content: []byte(tt.content)})
			n := p.Normalize
			if p.Class != ClassChange || n.ExternalSection != tt.section || n.EmptyExternalSection != tt.empty || n.Whitespace != tt.residual || n.NonKeyLines != 0 {
				t.Errorf("Class = %s, normalize %+v; want section %v, empty %v, whitespace %v, no non-key lines", p.Class, n, tt.section, tt.empty, tt.residual)
			}
		})
	}
}
```

- [ ] **Step 2: Add only the field and see the test fail on its assertions.** In `Normalize` (`plan.go:81-96`), after `EmptyExternalSection bool`:

```go
	// ExternalSection: the write adds the preserve: marker the file lacks
	// (kept lines sit in the file with no marker above them yet, most often
	// the first apply after preserve: is added). Not part of Any: the plan
	// prints it as its own row (F1 Q3).
	ExternalSection bool
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestPlanExternalSection' -count=1`
Expected: FAIL in `kept line, no marker` and `kept line and its comment, no marker` (`ExternalSection:false … Whitespace:true`). The other three rows pass already (they pin today's behaviour).

- [ ] **Step 3: Compute it.** Replace `normalize`'s first statement and its whitespace condition (`plan.go:456` and `:462`):

```go
	n.NonKeyLines, n.EmptyExternalSection, n.ExternalSection = nonKeyLines(r)
```

```go
	if !explained && !n.Reorder && n.NonKeyLines == 0 && n.Duplicates == 0 && !n.EmptyExternalSection && !n.ExternalSection {
```

and extend `normalize`'s doc comment's last sentence to "A marker with nothing under it is EmptyExternalSection, and a marker the render adds is ExternalSection (spec S6, F1 Q3)." Replace `nonKeyLines` (`plan.go:468-499`) with:

```go
// nonKeyLines counts the comment and blank lines the rewrite removes: not
// the managed header (re-emitted), not the comment lines kept above a
// preserved line, and not the one PreserveMarker the render writes back
// while lines are kept. A marker with nothing left under it is
// emptySection instead; every further marker is a removed non-key line.
// newSection: lines are kept and the file has no marker, so the render
// adds one (authkeys.RenderKept writes it exactly when something is kept).
func nonKeyLines(r audit.ServerResult) (n int, emptySection, newSection bool) {
	lines := strings.Split(string(r.Content), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // a well-formed file's trailing newline, not a blank line
	}
	markers := 0
	for _, line := range lines {
		t := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		_, managed := authkeys.ParseHeader(t)
		switch {
		case managed:
		case t == authkeys.PreserveMarker:
			markers++
		case t == "" || strings.HasPrefix(t, "#"):
			n++
		}
	}
	for _, e := range r.External {
		n -= len(e.Line.Above)
	}
	if markers > 0 {
		n += markers - 1
		emptySection = len(r.External) == 0
	}
	newSection = markers == 0 && len(r.External) > 0
	return n, emptySection, newSection
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestPlanExternalSection|TestPlanEmptyExternalSection|Preserv|Kept' -count=1`
Expected: `TestPlanExternalSection` PASS; `TestRenderPreservedGoldens` FAILS (its `gitea-3` assertion still wants `Whitespace`; Task 5 updates it with the goldens). Every other test PASS.

### Task 5: the plan row and the JSON field

**Files:**
- Modify: `internal/apply/report.go:182-183` (`renderChange`), `:222-229` (beside `emptySectionRow`), `internal/apply/json.go:254-263` (`jsonNormalize`), `:438-445` (`jsonServerFor`)
- Test: `internal/apply/preserve_report_test.go:15-26, 70-121`; `internal/apply/testdata/plan_preserved.golden`, `json_preserved.golden.json`

- [ ] **Step 1: Update the test to the owner's decision (it fails first).** In `internal/apply/preserve_report_test.go`, in `preservedPlans`' doc comment replace "gitea-3: a managed file whose kept line has no marker yet (the first write after adding preserve:, gap 17)" with "gitea-3: a managed file whose kept line has no marker yet (the first write after adding preserve:, F1 Q3: its own row)". In `TestRenderPreservedGoldens`, replace the `gitea-3` check (`:76-78`):

```go
	if p := planFor(t, plans, "gitea-3"); p.Class != ClassChange || !p.Normalize.ExternalSection || p.Normalize.Whitespace || p.Kept != 1 || len(p.Remove) != 0 {
		t.Errorf("gitea-3: Class = %s, normalize %+v, Kept = %d, Remove = %d; want change, the marker row (not whitespace), 1, 0 (F1 Q3)", p.Class, p.Normalize, p.Kept, len(p.Remove))
	}
```

and, in the per-server JSON loop (after the `empty_external_section` check, `:111-113`), add:

```go
		// gitea and session add the marker beside other rows; locked is
		// refused by the guard but, like its add, still shows what the
		// write would have done (gap 8).
		wantSection := s.Name == "gitea" || s.Name == "gitea-3" || s.Name == "session" || s.Name == "locked"
		if _, ok := s.Changes.Normalize["external_section"]; ok != wantSection {
			t.Errorf("%s: external_section present = %v, want %v", s.Name, ok, wantSection)
		}
```

Update the test's doc comment: "the first write that only adds the marker" → "the marker row on the first write that only adds it, and beside other rows".

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestRenderPreservedGoldens' -count=1`
Expected: FAIL (the goldens: `gitea-3` still prints the formatting row, no `(preserve:) add …` row; JSON has no `external_section`).

- [ ] **Step 2: Print the row.** In `internal/apply/report.go`, add after `headerOnlyRow` (before `emptySectionRow`'s doc comment, `:222`):

```go
// newSectionRow is the row of a write that adds the preserve: marker the
// file lacks (F1 Q3): on the first apply after preserve: is added to a
// server whose tool lines are already there, it is the only row.
func newSectionRow(tw io.Writer, p ServerPlan, pal palette) {
	if p.Normalize.ExternalSection {
		fmt.Fprintf(tw, "  %s\t(preserve:)\t\t\tadd the externally-managed section marker\n", pal.paint(codeYellow, "~"))
	}
}
```

and in `renderChange` (`:182-183`):

```go
	headerOnlyRow(tw, p, pal)
	newSectionRow(tw, p, pal)
	emptySectionRow(tw, p, pal)
```

- [ ] **Step 3: Map the field.** In `jsonNormalize` (`internal/apply/json.go:254-263`), after `EmptyExternalSection`:

```go
	// ExternalSection is additive-optional (schema stays 1): the write adds
	// the preserve: marker the file lacks (F1 Q3).
	ExternalSection bool `json:"external_section,omitempty"`
```

and in `jsonServerFor`'s `jsonNormalize` literal (`:444`), after `EmptyExternalSection: …`:

```go
				ExternalSection:        p.Normalize.ExternalSection,
```

- [ ] **Step 4: Regenerate the two goldens and read them back.**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestRenderPreservedGoldens' -update -count=1 && git status --short -- '*testdata*'`
Expected: only `internal/apply/testdata/plan_preserved.golden` and `internal/apply/testdata/json_preserved.golden.json` modified. Read both back:
- `plan_preserved.golden`: `gitea-3`'s `(formatting)      normalize: whitespace/format` row is replaced by `  ~  (preserve:)      add the externally-managed section marker` (tabwriter pads the two empty cells exactly as on `empty`'s row); `gitea` and `session` each gain that row after their key rows (padded to their own columns); `bare`, `bare-k2`, `empty`, `gitea-2` and `locked` are unchanged.
- `json_preserved.golden.json`: `"external_section": true` appears after `"whitespace"` (and after `"empty_external_section"` where present) on `gitea`, `gitea-3`, `locked` and `session` only; `gitea-3`'s `"whitespace"` is `false`; nothing else changes.

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -count=1`
Expected: PASS, every other golden byte-identical (`git status --short -- '*testdata*'` still lists only the two files).

- [ ] **Step 5: Pin the owner's case at the CLI (R0-9).** `TestPreserveHermetic` (`cmd/sshepherd/preserve_hermetic_test.go:23`) already drives exactly the owner's case: the first apply after adding `preserve:` to a file whose Gitea line is already there. Insert before its first `cli("apply", "--yes")` (`:55`):

```go
	// F1 Q3: the first apply after adding preserve: shows the marker as its
	// own row, never as a formatting drift (exit 1: a pending change).
	if code, out, _ := cli("apply", "--dry-run"); code != 1 || !strings.Contains(out, "(preserve:)") ||
		!strings.Contains(out, "add the externally-managed section marker") || strings.Contains(out, "(formatting)") {
		t.Errorf("first apply --dry-run exit = %d, want 1 with the marker row and no formatting row:\n%s", code, out)
	}
```

The `(preserve:)` cell and its text are matched separately because tabwriter pads between them. To see it fail first, run it with Step 2 reverted (`newSectionRow` not called): expected FAIL, no `add the externally-managed section marker` in the output (`(preserve:)` appears today only on an empty-section row, which this server never has). Then restore Step 2.

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestPreserveHermetic' -count=1 -race`
Expected: PASS.

### Task 6: mutation run; hand back

- [ ] **Step 1: Mutants** (run `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -count=1` and `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run 'TestPreserveHermetic' -count=1`; revert each):

| # | Mutant | Killed by |
|---|---|---|
| 1 | `newSection = len(r.External) > 0` (marker count ignored) | `marker there, a stray removed` |
| 2 | `newSection = markers == 0` (kept lines ignored) | `nothing kept, no marker`; every non-preserve plan golden whose file lacks a marker |
| 3 | `normalize` drops `&& !n.ExternalSection` | `kept line, no marker` (whitespace); `plan_preserved.golden` (`gitea-3` formatting row) |
| 4 | `Normalize.Any()` also returns `n.ExternalSection` | `plan_preserved.golden` (an extra `(formatting)` row) |
| 5 | `newSectionRow` condition inverted | `plan_preserved.golden` |
| 6 | `renderChange` does not call `newSectionRow` | `plan_preserved.golden`, `TestPreserveHermetic` |
| 7 | `ExternalSection` not mapped in `jsonServerFor` | `TestRenderPreservedGoldens` (presence check), `json_preserved.golden.json` |
| 8 | `json:"external_section"` without `omitempty` | every other JSON golden (`"external_section": false` appears) |
| 9 | `nonKeyLines` returns `emptySection` in both slots | `kept line, no marker`, `marker with nothing under it` |

- [ ] **Step 2: `make check`,** then hand back with the table and this docsDelta:

```text
docsDelta (lane report):
README.md, "### `sshepherd apply`", the co-managed paragraph (README.md:2172-2184): replace
  "The first apply after adding `preserve:` to a server whose tool lines are already there writes
  only the marker, which the plan shows as `(formatting) normalize: whitespace/format` (`gitea-3`
  below)."
with
  "A write that adds the marker the file lacks shows it as its own row,
  `(preserve:) add the externally-managed section marker`; on the first apply after adding
  `preserve:` to a server whose tool lines are already there it is the only row (`gitea-3`
  below)."
and re-copy the console sample below it (bare, empty, gitea, gitea-3 blocks) from
internal/apply/testdata/plan_preserved.golden.
README.md, the JSON paragraph that follows (README.md:2204-2222): "and the empty section as
  `changes.normalize.empty_external_section`" → "the empty section as
  `changes.normalize.empty_external_section`, and a marker the write adds as
  `changes.normalize.external_section` (like the other `changes`, also on a server the guard
  refuses)"; re-copy the normalize snippet from
  internal/apply/testdata/json_preserved.golden.json, adding gitea-3's normalize object (it shows
  "external_section": true).

README.md, "## Status", append a sentence to the Owner follow-ups paragraph lane import created:
  "Apply shows a write that adds the `preserve:` marker as its own row,
  `(preserve:) add the externally-managed section marker`."

docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md (Task 11 Step 2 item 2, this
  lane's commit, gap 7): replace the S6 Render paragraph at :1162-1165 as Task 11 Step 2 item 2
  gives it.

CLAUDE.md, Status, append to the F1 paragraph:
  apply's plan shows a write that adds the `preserve:` marker as its own row, `(preserve:) add the
  externally-managed section marker` (`Normalize.ExternalSection`, JSON
  `normalize.external_section`, additive), instead of `(formatting) normalize: whitespace/format`.
```

---

## Round 1 — lane `sshconn` (Tasks 7-10)

Lane `sshconn` owns `internal/sshconn/connect.go`, `internal/sshconn/session_open_test.go`, `internal/sshconn/handshake_test.go`, `internal/sshconn/sshtest/sshtest.go`, `internal/sshread/session_open_test.go`, `internal/sshwrite/session_test.go`, `internal/sshwrite/probe_test.go`. `needsIntegration: true`.

### Task 7: `sshtest.ServerConfig.SilentSessions`

**Files:**
- Modify: `internal/sshconn/sshtest/sshtest.go:230-249` (`ServerConfig`), `:252-262` (`Server`), `:297` (`NewServer`), `:408-416` (`serveConn`'s channel loop)

- [ ] **Step 1: Add the option** (test support; it is exercised by Task 8's tests, which fail before Task 8's production change). In `ServerConfig`, after `Stall`:

```go
	// SilentSessions completes the handshake and login but never answers a
	// session channel open (no confirmation, no rejection), so the client's
	// NewSession waits until the connection ends: the x/crypto race behind
	// sshconn.Exec's bounded session open, made deterministic.
	SilentSessions bool
```

In `Server`, after `forward`:

```go
	silentSessions bool
```

In `NewServer` (`:297`):

```go
	s := &Server{Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, forward: cfg.Forward, silentSessions: cfg.SilentSessions}
```

In `serveConn`'s `switch` (`:409-416`), after the `nc.ChannelType() != "session"` case:

```go
		case s.silentSessions:
			continue // never answered: the open waits until the connection ends
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn/... -count=1`
Expected: PASS (nothing sets the option yet).

### Task 8: `openSession` and `SessionOpenTimeout`

**Files:**
- Modify: `internal/sshconn/connect.go:647-693` (`ErrSessionNotOpened`, `Exec`)
- Create: `internal/sshconn/session_open_test.go`, `internal/sshread/session_open_test.go`
- Modify: `internal/sshconn/handshake_test.go:403-407` (comment only)

- [ ] **Step 1: Write the failing test.** Create `internal/sshconn/session_open_test.go`:

```go
package sshconn

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// silentConn logs in to a server that never answers a session open.
func silentConn(t *testing.T) *Conn {
	t.Helper()
	key := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:       []ssh.Signer{host},
		Authorized:     []ssh.PublicKey{sshtest.Signer(t, key).PublicKey()},
		SilentSessions: true,
	})
	srv := config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
	kh := sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey()))
	d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, key)}, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 30*time.Second), srv) // socket deadline 30 s: never the bound here
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// withSessionOpenWait shortens the bound for one test (no sshconn test runs
// in parallel).
func withSessionOpenWait(t *testing.T, wait time.Duration) {
	t.Helper()
	was := sessionOpenWait
	sessionOpenWait = wait
	t.Cleanup(func() { sessionOpenWait = was })
}

// TestExecBoundsASessionThatNeverOpens (F1 Q4): x/crypto's NewSession can
// wait forever on a dying connection. Exec stops waiting when the bound
// elapses (a ctx without a deadline, as context.WithoutCancel gives) or ctx
// ends first, returns the never-opened marker with kind timeout or ctx's
// kind, and closes the client so the waiting open returns: goleak (TestMain)
// fails the package if the opener goroutine is still running when the
// package's tests end.
func TestExecBoundsASessionThatNeverOpens(t *testing.T) {
	for _, tt := range []struct {
		name     string
		wait     time.Duration
		ctx      func(tb testing.TB) context.Context
		wantKind fleet.ErrorKind
		wantText string
	}{
		{"the bound ends a wait ctx cannot", 100 * time.Millisecond,
			func(testing.TB) context.Context { return context.WithoutCancel(context.Background()) },
			fleet.ErrorKindTimeout, "open session: no answer from the server within 100ms"},
		{"a ctx deadline ends it first", time.Hour,
			func(tb testing.TB) context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				tb.Cleanup(cancel)
				return ctx
			},
			fleet.ErrorKindTimeout, "open session: context deadline exceeded"},
		{"cancellation ends it", time.Hour,
			func(tb testing.TB) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				tb.Cleanup(cancel)
				time.AfterFunc(100*time.Millisecond, cancel)
				return ctx
			},
			fleet.ErrorKindCanceled, "open session: context canceled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			withSessionOpenWait(t, tt.wait)
			conn := silentConn(t)
			ctx := tt.ctx(t)
			done := make(chan error, 1)
			go func() {
				_, _, _, err := Exec(ctx, conn.Client, "x", nil)
				done <- err
			}()
			var err error
			select {
			case err = <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("Exec still waiting for a session that never opens")
			}
			if !errors.Is(err, ErrSessionNotOpened) || err.Error() != tt.wantText || kindOf(t, err) != tt.wantKind {
				t.Fatalf("err = %v, want %q with the marker and kind %s", err, tt.wantText, tt.wantKind)
			}
			waited := make(chan struct{})
			go func() { _ = conn.Client.Wait(); close(waited) }()
			select {
			case <-waited:
			case <-time.After(10 * time.Second):
				t.Fatal("Exec left the client open after giving up")
			}
		})
	}
}

// TestExecHealthySessionUnchanged (F1 Q4): a server that answers runs the
// script as before, well inside the bound.
func TestExecHealthySessionUnchanged(t *testing.T) {
	withSessionOpenWait(t, 5*time.Second)
	key := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, key).PublicKey()},
		Handle: func(_ context.Context, _ string, _ io.Reader, stdout, _ io.Writer) int {
			_, _ = io.WriteString(stdout, "ok\n")
			return 3
		},
	})
	srv := config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey())), Creds: &Credentials{AgentSock: sshtest.Agent(t, key)}, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	code, stdout, _, err := Exec(context.WithoutCancel(context.Background()), conn.Client, "x", nil)
	if err != nil || code != 3 || stdout.String() != "ok\n" {
		t.Fatalf("Exec = %d, %q, %v; want 3, \"ok\\n\", nil", code, stdout.String(), err)
	}
}
```

- [ ] **Step 2: Add only the declarations and see the bound test fail.** In `internal/sshconn/connect.go`, after `ErrSessionNotOpened` (`:649`):

```go
// SessionOpenTimeout bounds how long Exec waits for the server to answer a
// session open when ctx allows longer, or has no deadline at all (a caller
// that passed context.WithoutCancel). Opening a session on an authenticated
// connection is one round trip, cheaper than the TCP connect and key
// exchange the CLI bounds by its 10 s dial timeout, so the same 10 s is a
// generous ceiling for a healthy server (F1 Q4).
const SessionOpenTimeout = 10 * time.Second

// sessionOpenWait is SessionOpenTimeout; tests shorten it.
var sessionOpenWait = SessionOpenTimeout
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run 'TestExecBoundsASessionThatNeverOpens|TestExecHealthySessionUnchanged' -count=1 -timeout 5m`
Expected: FAIL, each `TestExecBoundsASessionThatNeverOpens` subtest with `Exec still waiting for a session that never opens` after 20 s (NewSession ignores ctx, and the socket deadline is 30 s away). `TestExecHealthySessionUnchanged` PASS (it pins today's behaviour).

- [ ] **Step 3: Write the read-path test and see it fail (no stash).** Create `internal/sshread/session_open_test.go`. It takes `SessionOpenTimeout` (10 s) by design: sshread cannot shorten the bound, and a ctx deadline would equal the socket deadline (`ConnectWith` installs one as the other), so which fires first would not be deterministic. It is written here, after the declarations and before `openSession`, so it fails naturally on the lane's own tree (never `git stash`: `refs/stash` is shared by every worktree of the repo, R1-2).

```go
package sshread

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestReadSessionThatNeverOpens (F1 Q4, gap 13): a server that accepts the
// login but never answers the session open fails the read at
// SessionOpenTimeout, kind timeout, still marked as never opened, through
// the read's %w wrapping and ReadAuthorizedKeys' SanitizedError. The ctx
// has no deadline, so Connect's 3×DialTimeout floor (30 s) is the socket
// deadline and the bound (10 s) is what ends the wait.
func TestReadSessionThatNeverOpens(t *testing.T) {
	user := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:       []ssh.Signer{host},
		Authorized:     []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		SilentSessions: true,
	})
	c := &Client{
		KnownHostsPath: sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey())),
		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, user)},
		DialTimeout:    10 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.ReadAuthorizedKeys(context.Background(), config.Server{Name: "web-1", Host: srv.Host, Port: srv.Port, User: "deploy"})
		done <- err
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(25 * time.Second):
		t.Fatal("the read is still waiting for a session that never opens")
	}
	if !errors.Is(err, sshconn.ErrSessionNotOpened) || fleet.ErrorKindOf(err) != fleet.ErrorKindTimeout {
		t.Fatalf("err = %v (kind %q), want the never-opened marker, kind timeout", err, fleet.ErrorKindOf(err))
	}
	if !strings.HasPrefix(err.Error(), "remote read on ") || !strings.HasSuffix(err.Error(), "open session: no answer from the server within 10s") {
		t.Errorf("err = %q", err)
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshread -run 'TestReadSessionThatNeverOpens' -count=1 -timeout 5m`
Expected: FAIL, `the read is still waiting for a session that never opens` after 25 s (the open waits for the 30 s socket deadline). After Step 4 it passes in about 10 s.

- [ ] **Step 4: Write `openSession` and call it from `Exec`.** Add after `sessionOpenWait`:

```go
// openSession opens a session on client, giving up when ctx ends or
// sessionOpenWait elapses. x/crypto's NewSession takes no context and can
// wait forever on a dying connection: the mux drops its channels before the
// transport records its write error, and an open sent in that gap goes
// into the closed socket without error and waits for a reply that never
// comes (TestExecMarksASessionThatNeverOpened). On giving up it closes
// client: on a direct connection that ends a NewSession still waiting; on
// a tunnelled (via:) target the client runs over a direct-tcpip channel,
// so the wait ends when the bastion answers the channel close or when
// Conn.Close closes the hop. In the true race nothing will ever answer the
// open, so its goroutine stays blocked until the process exits: one
// goroutine per stuck open, in a short-lived CLI. A session that opens
// after the wait ended is closed by the goroutine. Either way the exec
// request was never sent, so no script ran: the error wraps
// ErrSessionNotOpened.
func openSession(ctx context.Context, client *ssh.Client) (*ssh.Session, error) {
	type opened struct {
		sess *ssh.Session
		err  error
	}
	result := make(chan opened)
	gaveUp := make(chan struct{})
	go func() {
		sess, err := client.NewSession()
		select {
		case result <- opened{sess, err}:
		case <-gaveUp:
			if sess != nil {
				_ = sess.Close()
			}
		}
	}()
	wait := sessionOpenWait
	timer := time.NewTimer(wait)
	defer timer.Stop()
	var (
		cause error
		kind  = fleet.ErrorKindTimeout
	)
	select {
	case o := <-result:
		if o.err != nil {
			// A rejected channel (*ssh.OpenChannelError) carries the server's
			// free-text message: bounded like stderr (SEC-8).
			return nil, classify(fleet.ErrorKindRemote, fmt.Errorf("%w: %w", ErrSessionNotOpened, remoteText{o.err}))
		}
		return o.sess, nil
	case <-ctx.Done():
		cause, kind = ctx.Err(), ctxKind(ctx)
	case <-timer.C:
		cause = fmt.Errorf("no answer from the server within %s", wait)
	}
	close(gaveUp)
	_ = client.Close() // ends a waiting NewSession (on a tunnel: once the bastion answers, or Conn.Close)
	return nil, classify(kind, fmt.Errorf("%w: %w", ErrSessionNotOpened, cause))
}
```

In `Exec`, replace the `client.NewSession()` block (`:666-671`) with:

```go
	sess, err := openSession(ctx, client)
	if err != nil {
		return 0, nil, nil, err // already classified, marked ErrSessionNotOpened
	}
```

and extend `Exec`'s doc comment (`:651-658`) with: "Opening the session is bounded too: by ctx, and by SessionOpenTimeout when ctx allows longer (openSession); a session that never opens closes client and wraps ErrSessionNotOpened."

- [ ] **Step 5: Refresh the stale comment.** In `TestExecMarksASessionThatNeverOpened` (`internal/sshconn/handshake_test.go:403-407`), replace the comment's last two sentences ("…a NewSession started in that gap sends into the closed socket without error and waits forever for a reply. Wait returns only after the transport's Close, which records the error.") with:

```go
		// Wait for the client to be fully dead first. x/crypto's mux drops
		// its channels before the transport records its write error, so a
		// NewSession started in that gap sends into the closed socket
		// without error and gets no reply; Exec gives up on it after
		// SessionOpenTimeout as timeout (TestExecBoundsASessionThatNeverOpens).
		// Wait returns only after the transport's Close, which records the
		// error, so this open fails at once and stays remote.
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn/... ./internal/sshread -count=1 -race`
Expected: PASS (goleak clean: every opener goroutine returned once `Exec` closed the client; `TestReadSessionThatNeverOpens` in about 10 s).

### Task 9: the write path keeps its meaning (documentation pins, no production change)

**Files:**
- Modify: `internal/sshwrite/session_test.go:270-286` (`TestApplyReconnectAfterDrop`'s `a session that never opened did not start the upload`), `internal/sshwrite/probe_test.go:20-61` (`TestClassifyProbe`)

These rows pin what `errors.Is` (`session.go:92`) and the stage (`probe.go:69`) already give for Exec's new timeout-kinded error (gap 13). They kill no mutant on their own: the existing remote-kinded row already kills a mutant of `session.go:92`, and `classifyProbe` returns REJECTED for every `stageAuthed` error without a hop. They say so in a comment, and they would fail only if a later change read the kind instead of the marker, or sorted a `stageAuthed` timeout as transient (R1-3: no new duplicate test file).

- [ ] **Step 1: A second never-opened error in the existing stage-1 subtest.** In `internal/sshwrite/session_test.go`, replace the subtest at `:270-286` with (add `"fmt"` to the file's imports):

```go
	// A session open the server refused (remote) and one Exec gave up on
	// after SessionOpenTimeout (timeout, F1 Q4) both carry the never-opened
	// marker; stage 1 reads the marker, never the kind (gap 13). The second
	// row is a documentation pin: it kills no mutant the first does not.
	for _, nv := range []struct {
		name string
		err  error
	}{
		{"refused", &sshconn.Error{Kind: fleet.ErrorKindRemote, Err: sshconn.ErrSessionNotOpened}},
		{"given up after the bound", &sshconn.Error{Kind: fleet.ErrorKindTimeout, Err: fmt.Errorf("%w: no answer from the server within 10s", sshconn.ErrSessionNotOpened)}},
	} {
		t.Run("a session that never opened did not start the upload: "+nv.name, func(t *testing.T) {
			never := execResp{err: nv.err}
			refused := []error{kinded(fleet.ErrorKindAuth, "unable to authenticate")}
			t.Run("in stage 1: a refused reconnect is not a lockout", func(t *testing.T) {
				err := seamedWriter(&scriptedExec{responses: []execResp{never}}, &seamedConnect{fullErrs: refused}).Apply(ctx, srv, req(content))
				var lo *LockoutError
				if errors.As(err, &lo) || err == nil || !strings.Contains(err.Error(), "unknown state") || fleet.ErrorKindOf(err) != fleet.ErrorKindAuth {
					t.Fatalf("err = %v (kind %q), want an unknown state keeping the kind", err, fleet.ErrorKindOf(err))
				}
			})
			t.Run("in verify: stage 1 had finished, so it is a lockout", func(t *testing.T) {
				err := seamedWriter(&scriptedExec{responses: []execResp{{code: 0}, never}}, &seamedConnect{fullErrs: refused}).Apply(ctx, srv, req(content))
				if lo := lockoutOf(t, err); !errors.Is(lo.Restore, fleet.ErrNoSession) {
					t.Fatalf("Restore = %v", lo.Restore)
				}
			})
		})
	}
```

- [ ] **Step 2: One `TestClassifyProbe` row.** In `internal/sshwrite/probe_test.go`, after the `exec deadline` row (`:45`), add:

```go
		// F1 Q4: a session open Exec gave up on runs after a good login, so it
		// is REJECTED and restores (gap 9); documentation pin, as every
		// stageAuthed error without a hop is.
		{"session open given up", stageAuthed, fmt.Errorf("probe command: %w", &sshconn.Error{Kind: fleet.ErrorKindTimeout, Err: fmt.Errorf("%w: no answer from the server within 10s", sshconn.ErrSessionNotOpened)}), verdictRejected},
```

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run 'TestApplyReconnectAfterDrop|TestClassifyProbe' -count=1 -race`
Expected: PASS (behaviour already present; the rows are pins, as the step's note says, so there is no failing-first run).

### Task 10: mutation run; integration; hand back

- [ ] **Step 1: Mutants** (run `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn/... ./internal/sshread ./internal/sshwrite -count=1 -timeout 10m`; revert each):

| # | Mutant | Killed by |
|---|---|---|
| 1 | drop the `case <-timer.C` branch | `the bound ends a wait ctx cannot` (failsafe), `TestReadSessionThatNeverOpens` |
| 2 | drop the `case <-ctx.Done()` branch | `a ctx deadline ends it first`, `cancellation ends it` (failsafe) |
| 3 | timer branch kind `fleet.ErrorKindRemote` | `the bound ends a wait ctx cannot`, `TestReadSessionThatNeverOpens` |
| 4 | ctx branch kind `fleet.ErrorKindTimeout` (not `ctxKind`) | `cancellation ends it` |
| 5 | `_ = client.Close()` removed | the `Client.Wait` check (`Exec left the client open`); goleak |
| 6 | `close(gaveUp)` removed | goleak (the opener blocks on `result <-` forever) |
| 7 | the never-opened marker dropped from the bounded error (`fmt.Errorf("open session: %w", cause)`) | every `TestExecBoundsASessionThatNeverOpens` row, `TestReadSessionThatNeverOpens` |
| 8 | the goroutine does not close a late session (`_ = sess.Close()` removed) | **equivalent**: the waiter closed the client first, and x/crypto closes every channel of a closed connection; state it |
| 9 | `wait := SessionOpenTimeout` (test override ignored) | `the bound ends a wait ctx cannot` (wants `within 100ms`) |
| 10 | `SessionOpenTimeout = 30 * time.Second` | `TestReadSessionThatNeverOpens` (failsafe 25 s, and the `within 10s` text) |
| 11 | `serveConn`'s `case s.silentSessions` answers instead (`continue` removed) | every test using `SilentSessions` |
| 12 | `sshwrite/session.go:92`: `!errors.Is(err, sshconn.ErrSessionNotOpened)` → `true` | `in stage 1: a refused reconnect is not a lockout`, both rows (the `refused` row already killed it before F1) |

- [ ] **Step 2: Gates.** `gofmt -w`, `goimports -w`, then `make check`, then `make integration IT_DISTRO=alpine` under the runner's lock.
Expected: PASS. The real-sshd suites open sessions through `openSession` on every command; a healthy open never waits on the bound.

- [ ] **Step 3: Hand back** with the table and this docsDelta:

```text
docsDelta (lane sshconn):
README.md, "Classified errors" paragraph (README.md:1097-1102): after "Unclassified errors keep a
  plain `ERROR:` head." add: "A server that accepts the login but never answers a session open is
  given up after 10 seconds, or sooner when the per-server timeout ends, and reports `timeout`; a
  session open the server refuses stays `remote`."
README.md, the write-failure paragraph (README.md:3228): "a session that will not open" → "a
  session that will not open (given up after 10 s)".
README.md, three posture-probe statements (R0-5; a posture session that is accepted but never
  answered was `remote` when the socket deadline fired, and is now `timeout`; the exit code stays 1):
  - README.md:176: "(`error_kind: remote`, exit `1`)" → "(`error_kind: remote`, or `timeout` when
    its session never opens; exit `1`)".
  - README.md:1104: "unreachable with `error_kind: remote` (exit 1)" → "unreachable with
    `error_kind: remote` (`timeout` when its session never opens; exit 1)".
  - README.md:2976, the Exit codes table row `1` for audit: "a failed or malformed posture probe
    (`error_kind: remote`)" → "a failed or malformed posture probe (`error_kind: remote`;
    `timeout` when its session never opens)". Edit the table row only, never an `exitCodes*`
    footer block (`TestHelpExamplesAndExitCodes` checks those verbatim).
README.md, "## Status", append a sentence to the Owner follow-ups paragraph: "A session the server
  accepts but never opens fails after 10 s as `timeout` instead of hanging the run."

docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md (Task 11 Step 2 items 1 and 3,
  this lane's commit, the last lane): the header Status entry and the F1 order row.

CLAUDE.md, Status, append to the F1 paragraph:
  `sshconn.Exec` opens its session through `openSession`: it stops waiting when ctx ends or after
  `SessionOpenTimeout` (10 s; callers with `context.WithoutCancel` are bounded too), closes the
  client and returns the `ErrSessionNotOpened`-marked error with kind `timeout` (or ctx's kind),
  so x/crypto's dying-connection race can no longer hang a run (its goroutine may stay blocked
  until exit); `sshtest.ServerConfig.SilentSessions` makes it testable. sshread and sshwrite keep
  their meaning (the stage-1 "never started" rule, the login check's REJECTED verdict).
```

---

## Task 11: integrator (no lane owns this)

- [ ] **Step 1: Per lane, in merge order `import`, `report`, `sshconn`:** `git apply` the patch, apply that lane's docsDelta (README, CLAUDE.md and its Step 2 spec items; `import` creates the README and CLAUDE.md Status F1 paragraphs, `report` and `sshconn` append to them) **before** `make check`, then `make check` (plus `make integration` for `sshconn`, for `IT_DISTRO=alpine`, `debian` and `rocky`). Commit the patch and its docsDelta together, one commit per lane. Step 2's spec items go with the lane that makes them true: item 4 with `import`, item 2 with `report`, items 1 and 3 with `sshconn` (the last lane), which also carries Step 3's checks.

Order notes. The three lanes own disjoint files and share no production symbol, so any order works; this order lands the user-visible warning and plan row before the transport change. No lane's tests read the README text F1 changes (no flag, no `--help` change), so no lane applies a delta locally; still apply each delta before that lane's `make check`. Every README sample is copied from `internal/apply/testdata/plan_preserved.golden`, `json_preserved.golden.json` or the expectations in `cmd/sshepherd/import_settings_test.go`, never from this plan.

- [ ] **Step 2: Design amendments** in `docs/superpowers/specs/2026-11-08-access-model-fleet-reach-design.md`, each in the commit named (R0-3, R0-4: the design never disagrees with the code at any commit):

  1. (lane `sshconn`) Header `Status`: add `F1 owner follow-ups built (plan 2026-11-10-p10-f1-owner-followups)` after the S6 entry.
  2. (lane `report`) S6 **Render**, the paragraph at `:1162-1165` ("The first write after `preserve:` is added … the wording for any byte drift no row explains."): replace with "A write that adds the marker the file lacks has its own plan row, `~ (preserve:) add the externally-managed section marker`; JSON `normalize.external_section` (owner, 2026-11-10, F1 Q3). On the first write after `preserve:` is added to a server whose tool lines are already present it is the only row." (gap 7).
  3. (lane `sshconn`) "Order and parallel lanes" table: add a row `| F1 | A: \`import.go\`, \`import_settings.go\`, \`import_json.go\` · B: \`internal/apply/{plan,report,json}.go\`, the preserve plan goldens and \`TestPreserveHermetic\` · C: \`internal/sshconn\` (\`connect.go\`, \`sshtest\`), the sshread session-open test and two sshwrite rows (one round) |`.
  4. (lane `import`) S8 **Warning kinds**, the import bullet (`:449-452`): after `revocation_memory_dropped`, add `manifest_settings_dropped` (F1 Q1, owner 2026-11-10).

- [ ] **Step 3: Checks.** `git diff --stat 065c1d3 -- 'internal/*/testdata' 'cmd/sshepherd/testdata'` lists only `internal/apply/testdata/plan_preserved.golden` and `internal/apply/testdata/json_preserved.golden.json`. `git diff --stat 065c1d3 -- cmd/sshepherd/testdata/help` is empty. README's Status "Owner follow-ups" paragraph and CLAUDE.md's Status F1 paragraph name the same three changes (R0-7).

## Task 12: independent verifier (no lane owns this)

Check against `master` after Task 11 and report findings; change nothing.

- [ ] Q1: a fresh `import -o FILE --force` over the fixture prints exactly seven `manifest_settings_dropped` lines in manifest order, each ending `with --merge FILE` (`hintArg`), exit 0, and FILE is replaced; a server the fresh output lacks is labelled `[not in this import]` and no consequence claims apply would touch it; `--merge` (in place or into another FILE), a FILE without such settings, a run without `-o`, and a run without `--force` (refused, exit 3, FILE unchanged) print none; `--operator-key` with the operator's key silences only the operator line; the memory warning is byte-identical and comes first; `import --json` carries one entry per line and counts them in `summary.warnings`.
- [ ] Q3: the `(preserve:) add the externally-managed section marker` row prints whenever the file has kept lines and no marker, replaces the formatting row when it is the only difference (`gitea-3`), and sits beside other rows otherwise (`gitea`, `session`); `external_section` is omitted everywhere else (every other JSON golden byte-identical); a guard-refused server's JSON carries it like its other `changes` (gap 8) and its text shows no row; `Normalize.Any()` does not include it.
- [ ] Q4: grep `NewSession(` in production code: the only call is inside `openSession`. Every `Exec` caller (`internal/sshread/sshread.go:189,200,220`, `internal/sshwrite/session.go` via `writeSession.exec`, `internal/sshwrite/probe.go:135`) handles the bounded error as gaps 9, 11 and 13 say; a healthy session never waits; `make test` is goleak-clean; `SessionOpenTimeout` is documented in README as 10 s.
- [ ] Layering and gates: `make layering` green; no function added by a lane is unreachable at that lane's commit (`deadcode`); gocyclo 15 holds with no `nolint`.
- [ ] D28 and JSON: no new exit-2 input and no exit-code change; every new JSON field or kind is additive; schema stays 1.
- [ ] Integration: `make integration` is green on alpine, debian and rocky.
- [ ] Each lane's mutation table is complete and every survivor is explained.

---

## Spec coverage (self-review)

| Owner decision (F1, 2026-11-10) and design rule | Task |
|---|---|
| Q1: extend the fresh `-o FILE --force` warning to `groups:` (named), `protected: true` and `operator: true` users the fresh output no longer marks (named; `--operator-key` re-marks), server `tags:`, `preserve:` rules, `jump_only:` and `via:` routes not reproduced | 1, 2 |
| Q1: its own warning kind in the `importWarnings` collector, reported in `import --json` warnings | 1, 2 (`TestImportJSONSettingsDroppedWarning`) |
| Q1: exit 0; each line ends with the paste-ready `--merge FILE`; one line per kind, justified (gap 1) and consistent with the memory warning's shape; nothing printed before a refusal without `--force` | 2 |
| Q1 scope: `authorized_keys_file:` and hand-written `access:` not covered, flagged for the owner | gap 4 |
| Q3: dedicated row `(preserve:) add the externally-managed section marker`, `Normalize.ExternalSection`, JSON `normalize.external_section` (additive, omitempty) | 4, 5 |
| Q3: shown whenever the write adds a marker the file lacks; replaces, not duplicates, the formatting row when it is the only difference; goldens and README sample copied from goldens; the owner's case pinned at the CLI (`TestPreserveHermetic`) | 4, 5, 6 (docsDelta) |
| Q4: `Exec` opens the session in a goroutine, stops at ctx or a bounded wait (`SessionOpenTimeout`, justified, gap 10), returns the `ErrSessionNotOpened` error with kind `timeout` or ctx's, closes the client; the race goroutine documented | 8 |
| Q4: deterministic, goleak-clean unit test (`SilentSessions` server; the client close releases the goroutine) | 7, 8 |
| Q4: every `Exec` caller still classifies correctly (sshread, the write's stage 1 and one reconnect, the login check) | 8 (sshread), 9, gaps 9, 11-13 |
| Shared rules: JSON schema 1, additive, omitted when empty; consumers ignore unknown kinds; no D28 row added | header, 5, 2 |
| Order and parallel lanes: a row for F1 | 11 Step 2 |
| README, README Status, CLAUDE.md Status and the design text in the same commit as the lane that makes them true | 3, 6, 10 (docsDeltas), 11 |

## Review log

Two independent reviews of the draft (R0: spec and owner answers; R1: code and execution, which compiled and ran every draft block at `065c1d3`). Each issue was checked against the code at `065c1d3` and the design before it was applied. No owner decision was changed.

| Issue | Verdict | Where |
|---|---|---|
| R0-1 consequence text false for a server the fresh output drops | applied, option (a): `NAME [not in this import]` (brackets, so the label nests inside the parenthesised list), consequences reworded "where they stay, …"; `nothing at all` expects the labelled names | gap 2, Task 1, Task 2 (`wantSettingLines`), Task 3 docsDelta, mutants 18-19 |
| R0-2 `!force` early return untested | applied: `no --force (refused)` row with `wantCode` 3 and FILE unchanged; mutant 17. Verified: the collector logs as it adds (`import_json.go:35-38`), so the mutant would print before `emitManifest`'s refusal | Task 2, Task 3, gap 4 |
| R0-3 S8 import warning-kind list not amended | applied: Task 11 Step 2 item 4, lane `import`'s commit (spec `:449-452` verified) | Task 3 docsDelta, Task 11 |
| R0-4 Q3 design amendment in the wrong commit | applied: item 2 with `report`, item 4 with `import`, items 1 and 3 with `sshconn` | Task 11, handoffs |
| R0-5 three README posture-probe `remote` statements | applied (lines 176, 1104, 2976 verified); the table row only, never a footer block | Task 10 docsDelta |
| R0-6 `authorized_keys_file:` (and hand-written `access:`) neither covered nor excluded | applied as an owner flag with a one-line row sketch; not built | gap 4, README note in Task 3 docsDelta |
| R0-7 README Status never updated | applied: lane `import` creates an "Owner follow-ups" paragraph (README `:86`, after Co-managed accounts), `report` and `sshconn` add a sentence each; Step 3 compares the two Status sections | docsDeltas, Task 11 Step 3 |
| R0-8 `external_section` on a guard-refused server undocumented | applied | gap 8, Task 6 docsDelta |
| R0-9 no CLI-level assertion of the new row | applied: `cmd/sshepherd/preserve_hermetic_test.go` joins lane `report` (disjoint from lane `import`'s `import*.go`); a first `apply --dry-run` asserts exit 1, the row, no `(formatting)` | Task 5 Step 5, mutant 6 |
| R0-10 / R1-5 stale Base | applied: Base `065c1d3` (verified: it touches only `CLAUDE.md` and `internal/audit/preserve_test.go`); checks diff from `065c1d3` | header, Rounds, Task 11, Wave lanes |
| R0-11 File structure incomplete | applied: every new test name listed | File structure |
| R1-1 mutant 2's named killer survives | applied both fixes: the killer is now `--merge into another FILE stays quiet` (new row) and `TestImportForceWarnsMemoryLost`'s `--merge` half. Verified: with `-o` naming another file, `publishManifest` takes the `!same` path and `WriteFile(…, force)` | Task 2, Task 3 |
| R1-2 `git stash` in a lane worktree | applied: the sshread test moves to Task 8 Step 3, between the declarations and `openSession`, and fails on the lane's own tree | Task 8 |
| R1-3 the two sshwrite tests duplicate existing ones | applied: `internal/sshwrite/session_open_test.go` dropped; one row each in `TestApplyReconnectAfterDrop`'s never-opened subtest (`session_test.go:270-286`, verified) and `TestClassifyProbe` (`probe_test.go:45`), stated as documentation pins | Task 9, gap 13, lane files |
| R1-4 `client.Close()` on a tunnel overstated | applied: gap 12 and the `openSession` comment reworded; the `via:` silent-session test is **not** added (open risk below) | gap 12, Task 8 |
| R1-6 goleak comment | applied | Task 8 |

Rejected: none. **Open risks:** (1) no test drives a silent session behind a bastion (R1-4's optional row); goleak stays safe because every caller closes its `Conn`, which closes the hop. (2) The revised blocks listed under Compile status were not compiled; lanes fix within stated intent. (3) The `TestPreserveHermetic` step assumes the first plan of that unmanaged file shows no other `(formatting)` cause (traced: no non-key line beyond the kept comment, no reorder, no duplicate; the marker suppresses the whitespace residual); if it fails for another normalize reason, the lane reports it rather than loosening the check. **Owner decisions:** gap 4 (`authorized_keys_file:` row: add or not) and gap 9 (an unanswered session open after a good login stays REJECTED, as P08 designed, or becomes UNPROVEN: a P08 question, no code here).

## Wave lanes (for the runner)

- **`plan`** (the runner's `args.plan`): `docs/superpowers/plans/2026-11-10-p10-f1-owner-followups.md`, committed before round 1.
- **`handoffs`** (the runner's `args.handoffs`), one entry: "P10-F1, per lane in the order import, report, sshconn: git apply that lane's patch, apply its docsDelta (README, README Status, CLAUDE.md Status and its spec items) before make check, then make check (make integration for lane sshconn, all three distros), then commit patch and docsDelta together, one commit per lane. import creates the README and CLAUDE.md Status F1 paragraphs; report and sshconn append to them. Spec items (Task 11 Step 2): item 4 (S8 import warning kinds: manifest_settings_dropped) with import; item 2 (S6 Render paragraph) with report; items 1 (spec Status) and 3 (F1 order row) with sshconn, which also runs Task 11 Step 3's checks. No lane's own tests read the README text F1 changes (sshconn's delta edits an exit-codes table row, never a --help footer block), so no lane applies a delta locally; every delta is still applied before that lane's make check."

One round of three lanes with disjoint files; each builds on `065c1d3` alone and passes `make check` alone. Globs are shell `case` patterns (`*` crosses `/`); the only testdata a lane changes is listed by file. `README.md`, `CLAUDE.md` and `docs/` are integrator-only.

```json
{
  "rounds": [
    [
      {
        "pkg": "P10-F1",
        "lane": "import",
        "kind": "fix",
        "ids": ["F1-Q1"],
        "tasks": "Tasks 1-3",
        "files": [
          "cmd/sshepherd/import.go",
          "cmd/sshepherd/import_json.go",
          "cmd/sshepherd/import_settings.go",
          "cmd/sshepherd/import_settings_test.go"
        ],
        "needsIntegration": false
      },
      {
        "pkg": "P10-F1",
        "lane": "report",
        "kind": "fix",
        "ids": ["F1-Q3", "PRD-8"],
        "tasks": "Tasks 4-6",
        "files": [
          "internal/apply/plan.go",
          "internal/apply/report.go",
          "internal/apply/json.go",
          "internal/apply/preserve_plan_test.go",
          "internal/apply/preserve_report_test.go",
          "internal/apply/testdata/plan_preserved.golden",
          "internal/apply/testdata/json_preserved.golden.json",
          "cmd/sshepherd/preserve_hermetic_test.go"
        ],
        "needsIntegration": false
      },
      {
        "pkg": "P10-F1",
        "lane": "sshconn",
        "kind": "fix",
        "ids": ["F1-Q4"],
        "tasks": "Tasks 7-10",
        "files": [
          "internal/sshconn/connect.go",
          "internal/sshconn/session_open_test.go",
          "internal/sshconn/handshake_test.go",
          "internal/sshconn/sshtest/sshtest.go",
          "internal/sshread/session_open_test.go",
          "internal/sshwrite/session_test.go",
          "internal/sshwrite/probe_test.go"
        ],
        "needsIntegration": true
      }
    ]
  ],
  "mergeOrder": ["P10-F1"]
}
```
