# Audit trust, key policy and connection posture (P09-impl, W6) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step, not a commit.

**Goal:** Build the approved audit-trust-posture design (`docs/superpowers/specs/2026-11-08-audit-trust-posture-design.md`, findings SEC-1, COR-5, COR-6, SEC-5, PRD-9, PRD-10): a posture probe in its own session (replacing the `authorized_keys2` probe) that audit grades as drift or critical, operator keys that cannot log in graded critical over every line sshd honours, `host_key_type_changed` (exit 2), a restricted key offer with `--offer-all-keys`, built-in weak-key and expiry rules through D29, the JSON additions, and the README narrowing.

**Architecture:** The StrictModes walk moves to `sshconn.AncestorWalk`, shared byte-for-byte by the write scripts and the new `sshconn.PostureCmdFor`; `sshread` runs the probe in the session the `authorized_keys2` probe used, so a read stays at two sessions. `internal/authkeys` owns the strength and expiry rules (`StrengthIssue`, `Key.Weak`, `Expired`, `LinesByFingerprint`), `internal/config` turns them into `weak_key` conflicts and warnings, and `internal/audit` grades everything through one `criticalReasons`. Key offering moves into `sshconn` (`orderSigners`, `GrantIndex`, `Dialer.OfferAll`), with the D17b preflight on `fleetSession`.

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), `golang.org/x/crypto/ssh` v0.58 through the hermetic `internal/sshconn/sshtest` server, POSIX sh scripts run under `sh`, goleak, golden files (`-update`), native fuzzing (`FuzzFinishPosture`), golangci-lint v2.15.0 (depguard layering, gocyclo 15, dupl), `deadcode ./cmd/sshepherd`, the dockerized sshd matrix (`make integration`).

**Base:** Wave W6, on top of `master` after P08-impl (W5). Every `file:line` below was read at `4390667`, which **predates P08**; function names are the stable anchors. P08 edits `internal/sshconn/connect.go`, `internal/sshwrite/sshwrite.go`, `internal/apply/{plan,json,report,exec,serial}.go`, `internal/workflow`, `cmd/sshepherd/{apply,editrun,run,sweep}.go` and the help goldens, so **every lane re-reads each named function before editing it** and rebases its edit onto what is there. The draft's code was compiled and tested against `4390667` plus the one P08 change named below; the additions from the review pass (see Review log) were not compiled, so a lane that finds a build error in one fixes it to the text's intent. Adapt everything to P08's edits, do not revert them.

**Named dependency on P08:** `fleet.HostKeyAlert(kind ErrorKind) bool` (P08 spec "New exported surface": audit's predicate moved to `internal/fleet`, with `hostKeyAlert` in `internal/audit/errors.go` becoming a one-line call). Lane `posture` Task 2 adds `ErrorKindHostKeyTypeChanged` to that predicate, which is how P09's new kind enters audit's exit 2 and apply's (P08 D10b) together; decision 13 records what that does to the write commands. If `fleet.HostKeyAlert` does not exist at the lane's base, stop and report: W6 ran before W5. Nothing else in P09 needs P08 code.

---

## How this plan is cut (read first)

### Why the lanes look the way they do

Three gates shape the rounds, beyond file ownership:

1. **`deadcode ./cmd/sshepherd` is part of `make check`.** Every function a lane adds must be reachable from `main` when that lane is committed, so a producer and its first caller share a lane: `FinishPosture` and `PostureCmdFor` land with `sshread`'s call; `Expired`, `EarliestExpiry` and `WeakKeys` land with `config.warnExpired` and cmd's save rule; `LinesByFingerprint` lands with adopt's call. Constants, types and struct fields are exempt, so shared vocabulary (`fleet.PostureIssue`, `ReadResult.Posture`, `ErrorKindHostKeyTypeChanged`) lands in round 1 ahead of its audit consumers.
2. **`TestHelpMatchesREADMETables` and `TestHelpExamplesAndExitCodes` read `README.md`.** A lane that changes a flag or an exit-code footer applies its own `docsDelta` to its worktree's `README.md` before `make check`; the ownership filter drops that change from the patch and the integrator re-applies it from `docsDelta`. The lanes that need this say so.
3. **`sshconn_test.go` and `sshread/sshread.go` are shared by the posture and offering work, and `connect.go` by the host-key and offering work.** The posture work therefore runs in round 1 and the host-key and offering work (one lane, because they share `connect.go`) in round 2. The E2E runs last, on every lane's merged result.

### Rounds

| Round | Lanes (disjoint files) | Builds on |
|---|---|---|
| 1 | `posture` (fleet vocabulary, `AncestorWalk`, `PostureCmdFor`/`FinishPosture`, sshread, sshwrite) · `keypolicy` (authkeys, config, apply, adopt, identity, cmd save rule) | W5 |
| 2 | `transport` (hostKeyHint, offering, `--offer-all-keys`, the preflight) · `audit` (grading, report, JSON) | round 1 |
| 3 | `e2e` (the real-sshd E2E) | round 2 |

After round 3 the integrator runs Task 28 and an independent verifier runs Task 29. No lane owns either.

### Plan decisions (not in the spec; none changes an exit code, refusal or load beyond an answered decision)

1. **The E2E and integration fixtures use an override path below a 0775 `~/loose`, not a 0775 `~/.ssh`.** The spec's wording (chmod 0775 on `~/.ssh`) cannot run: the container sshd has StrictModes on, so that login would fail before audit could see anything. The fixture user logs in through its 0700 `~/.ssh`, and `~/loose/keys` is the managed file sshd never reads. Exit flow unchanged: audit 1 `group_writable`, apply refuses (48), fix the mode, audit 0. Task 28 amends the spec's E2E line to match.
2. **`authkeys.EarliestExpiry(opts, local) (opt string, t time.Time, ok bool)`** is added beside the spec's `Expired` (built on it). The report needs the expiry date and the warning needs the option text; both come from the earliest clause.
3. **`config.WeakKey` carries `{User, Index, Fingerprint, Issue, Bits, Servers, Message}`**, so the conflict, the warning and the save rule share one record. `sshconn.GrantIndex(pub, granted) int` is the spec's exported matcher (-1 = not granted).
4. **`FinishPosture` also refuses output that does not end in a newline** (a truncated stream). The probe always ends its records with one; this only tightens fail-closed.
5. **The posture walk starts from the nearest existing directory using `[ ! -d "$d" ]`**, not the write path's `-e`/`-L` loop, because a dangling symlink there fails the resolved walk and would turn a server unreachable. A dangling symlink passed on the way up still has its owner checked (`ls -ldn`, `foreign_owner`), as section 1 requires for a symlinked ancestor; only components that do not exist are skipped.
6. **A weak-key refusal never withholds a save (OP4).** `planOne` sets `ServerPlan.WeakRefused` where it applies `weakRefusal`, and `apply.NothingCanLand` counts a refusal only when `!p.WeakRefused`. So `rotate carol`, `rotate alice --old <dsa> --new <ed25519>` beside a second weak key, and `revoke bob` whose key is already gone all save, report the server refused and exit 1 (spec section 5 and Risks). A server refused for any other reason still counts, so a refusal beside it withholds the save as today.
7. **`--offer-all-keys` is carried in `followUp`**, so paste-ready hints repeat it (CLAUDE.md's "follow-up hints carry the run's own flags").
8. **`TestIntegrationHeadlessRotation` passes `--offer-all-keys`.** This is the spec's "key changed by hand in the manifest" case: the restricted offer presents only `ci_new`, not installed yet, so `old + new` fails `auth` without the flag. The lockout refusal's "pass the new key with another `--identity`" stays; the auth hint then names the flag.
9. **Spec test names that describe table rows are subtests:** `TestHostCertUnvouchedSignerAlerts`, `TestCriticalOperatorCertOnly`/`Expired`, `TestOperatorEveryLineIgnored`, `TestOperatorIgnoredThenDeadLine` and `TestOperatorLaterLineLogsIn` are rows of `TestHostKeyTypeClassification` and `TestCriticalOperatorCannotLogIn`, each row's name starting with the spec's test name. New goldens beyond the spec's list: `report_host_key_type_changed.golden{,.json}` and `report_operator_expired.golden` (the spec's `report_error_kinds` stays byte-identical; Task 28 amends the spec's B1 list).
10. **No `GODEBUG=rsa1024min=0`:** `testkeys.RSALine` builds a modulus of the wanted size without `crypto/rsa`'s minimum check, and `testkeys.DSALine` builds the wire form because `crypto/dsa` is deprecated (staticcheck).
11. **`key_issues`' `"expired"` is a present row's desired `expiry-time`**, and appears on a `CANNOT LOG IN` row too; the text report omits ` · EXPIRED` there because the row's reason already says it.
12. **The identity warning uses the path as the ssh config spells it** (`pubPaths(c.source)`), so `~/.ssh/old` reads `identity ~/.ssh/old.pub: dsa key not imported`, as the spec shows.
13. **`host_key_type_changed` exits 2 on `apply`, `revoke` and `rotate` at the post-write login check.** P08's D10b (owner answer, 2026-11-08) is the answered decision: exit 2 for the host-key kinds audit exits 2 on, "and `host_key_type_changed` if P09's D16 adds it". It overrides the P09 spec's section 3 sentence and Out of scope line, which predate it. The kind enters through `fleet.HostKeyAlert` (Task 2); Task 20 updates `exitCodesWrite` row 2 and its goldens, adds the test and carries the README text; Task 28 amends the spec.
14. **`validate` is deferred to D25.** The command does not exist at `4390667`. The spec's exit-row-3 case and section 5's `validate` line (exit 3 on a `weak_key` conflict, exit 0 for an ungranted weak key) are built with D25, whose plan must add both tests.
15. **A failed `ls` fails closed as `posture probe output malformed`**, not `posture probe failed (exit N)`. The walk's bytes are pinned to the write path, so it cannot exit on a failed `ls`; the empty `$1`/`$3` give a record the grammar refuses, and the server is unreachable with `error_kind: remote` either way (`TestPostureFailedLsFailsClosed`).

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted.
- **Before hand-back:** apply this lane's `docsDelta` to the worktree's `README.md` (gate only), run `make check` (and `make integration` under the runner's lock when the lane says `needsIntegration`), then `git add -A`, unstage every path outside the lane's globs (README.md and CLAUDE.md always), and write the patch. README text goes in `docsDelta`, samples copied from regenerated goldens.
- Coverage: `make coverage` gates production packages at `COVERAGE_MIN := 93`; every new branch below has a test that reaches it.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests exists; a test that pins behaviour already present says so.
- **gocyclo 15 is a production-code gate** (`_test.go` is exempt; function literals count toward their enclosing function). `ConnectWith`, `Build`, `renderServer` and `jsonServerFor` are near the limit: new branches go into the named helpers the tasks give; never `//nolint:gocyclo`.
- **errorlint applies to tests too:** compare sentinels with `errors.Is`.
- **`docsDelta`** blocks are integrator-only text for `README.md`, `CLAUDE.md` Status and spec Status. Sample output is copied from the regenerated golden named beside it, never from this plan.

---

## File structure

| File | Round/lane | Responsibility |
|---|---|---|
| `internal/fleet/fleet.go`, `errors.go`, `errors_test.go` | 1 `posture` | `PostureIssue`, `Posture*` names, `ReadResult.Posture`, `ErrorKindHostKeyTypeChanged`, `HostKeyAlert` includes it |
| `internal/sshconn/posture.go` (new), `posture_test.go` (new) | 1 `posture` | `AncestorWalk`, `PostureCmdFor`, `keys2Check`, `FinishPosture` |
| `internal/sshconn/sshconn.go`, `sshconn_test.go`, `fuzz_test.go`, `testdata/fuzz/FuzzFinishPosture/*` (new) | 1 `posture` | `SecondaryKeysCmd*`, `FinishSecondaryProbe` removed; `FuzzFinishPosture` |
| `internal/sshread/sshread.go`, `hermetic_test.go`, `integration_test.go` | 1 `posture`, 2 `transport` | posture session; `Client.OfferAll`/`QuietFallback` |
| `internal/sshwrite/sshwrite.go`, `scripts_golden_test.go` (new), `testdata/script_*.golden` (new) | 1 `posture` | `ancestorCheck` built from `AncestorWalk`; the scripts stay byte-identical |
| `scripts/integration.sh` | 1 `posture`, 3 `e2e` | fixture users `loose`, `e2eloose` |
| `internal/authkeys/policy.go` (new), `policy_test.go` (new), `authkeys.go`, `options.go`, `testdata/fuzz/FuzzParseLine/seed-dsa` (new, replacing `dde7a120ccdf11af`) | 1 `keypolicy` | `StrengthIssue`, `Key.Weak`, `LinesByFingerprint`, `EarliestExpiry`, `Expired` |
| `internal/testkeys/testkeys.go` | 1 `keypolicy` | `RSALine`, `DSALine` |
| `internal/config/policy.go` (new), `policy_test.go` (new), `revoked.go`, `config.go` | 1 `keypolicy` | `ConflictWeakKey`, `WeakKey`, `weakConflicts`, `warnExpired` |
| `internal/apply/plan.go`, `serial.go`, `predicates.go`, `predicates_test.go`, `weak_test.go` (new) | 1 `keypolicy` | `weakRefusal`, the removal-only exception, `ServerPlan.WeakRefused`, `NothingCanLand` |
| `internal/adopt/adopt.go`, `adopt_test.go` | 1 `keypolicy` | `skipKey` |
| `internal/identity/identity.go`, `identity_test.go` | 1 `keypolicy` | weak identities skipped; `--operator` refuses |
| `cmd/sshepherd/conflicts.go`, `conflicts_test.go`, `adopt.go`, `import.go`, `editrun.go`, `run.go`, `testdata/help/{adopt,apply,import,revoke,rotate}.golden` | 1 `keypolicy` | `conflictRefusal(former, saved)`, `formerManifest`, footers |
| `internal/sshconn/hostkey.go`, `hostkey_test.go` (new), `connect.go`, `connect_test.go`, `offer_test.go` (new) | 2 `transport` | host-key classification; `offering`, `offerFor`, `GrantIndex`, `orderSigners` |
| `cmd/sshepherd/fleet.go`, `apply.go`, `sweep.go`, `editrun.go`, `run.go`, `offer_test.go` (new), `hostkey_type_exit_test.go` (new), `revoke_test.go`, `identity_integration_test.go`, `testdata/help/*.golden` | 2 `transport` | `--offer-all-keys`, `connectionFlags`, `grantedOn`, `warnNoGrantedKeys`, the audit and write footers |
| `internal/audit/audit.go`, `report.go`, `json.go`, `trust_test.go` (new), `testdata/*` | 2 `audit` | `Posture`/`Lines`, `cannotLogIn`, `criticalReasons`, rows, JSON |
| `cmd/sshepherd/e2e_test.go` | 3 `e2e` | `TestE2EPostureGroupWritable` |

---

## Round 1 — lane `posture` (Tasks 1–6)

Owns: `internal/fleet/*`, `internal/sshconn/{sshconn,sshconn_test,posture,posture_test,fuzz_test}.go`, `internal/sshconn/testdata/fuzz/FuzzFinishPosture/*`, `internal/sshread/*`, `internal/sshwrite/{sshwrite.go,scripts_golden_test.go}`, `internal/sshwrite/testdata/script_*.golden`, `scripts/integration.sh`. Finding: SEC-1.

P08 edits `writeCmdFor`, `restoreCmdFor`, `disableKeys2Cmd` and `lockHead`; the golden in Task 1 is taken on this lane's base, so it pins P08's scripts, not `4390667`'s.

### Task 1: pin the scripts before the walk moves

**Files:** Create `internal/sshwrite/scripts_golden_test.go`, `internal/sshwrite/testdata/script_*.golden`, `internal/sshconn/posture_test.go`.

- [ ] **Step 1: Write the golden test** (`internal/sshwrite/scripts_golden_test.go`; check the file for an existing `update` flag first and reuse it if P08 added one):

```go
package sshwrite

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestWriteScriptsUnchanged pins every remote script that carries the
// StrictModes walk, byte for byte: the walk moved to sshconn.AncestorWalk and
// these goldens are the proof the move changed nothing. The golden is
// taken before the move; a later rewrite of a script updates it knowingly.
func TestWriteScriptsUnchanged(t *testing.T) {
	expect := Snapshot{Size: 7, Cksum: 4242, Managed: true}
	scripts := map[string]string{
		"write":         writeCmdFor("~/.ssh/authorized_keys", expect, 12),
		"write_absent":  writeCmdFor("/srv/keys/deploy", Snapshot{Absent: true}, 12),
		"restore":       restoreCmdFor("~/.ssh/authorized_keys", false, expect),
		"restore_empty": restoreCmdFor("~/.ssh/authorized_keys", true, expect),
		"disable_keys2": disableKeys2Cmd(),
	}
	for name, got := range scripts {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("testdata", "script_"+name+".golden")
			if *update {
				if err := os.WriteFile(path, []byte(got+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
			if err != nil {
				t.Fatalf("read golden (run with -update first): %v", err)
			}
			if got+"\n" != string(want) {
				t.Errorf("script changed:\n got %s\nwant %s", got, want)
			}
		})
	}
}
```

Create the `testdata` directory with `mkdir -p internal/sshwrite/testdata`.

- [ ] **Step 2: Create `internal/sshconn/posture_test.go`** with only this for now:

```go
package sshconn

import "testing"

// TestReadCmdUnchanged: sshwrite's verify reads back through this exact
// command, so the posture work must not touch it.
func TestReadCmdUnchanged(t *testing.T) {
	want := `p="${HOME:?}"/'.ssh/authorized_keys'; if [ -e "$p" ]; then cat "$p"; else exit 44; fi`
	if got := AuthorizedKeysCmdFor(DefaultAuthorizedKeysPath); got != want {
		t.Errorf("read command changed:\n got %s\nwant %s", got, want)
	}
}
```

- [ ] **Step 3: Capture the goldens and confirm the tests are green on the unmoved code**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite/ -run TestWriteScriptsUnchanged -update && GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite/ ./internal/sshconn/ -run 'TestWriteScriptsUnchanged|TestReadCmdUnchanged'`
Expected: PASS. Read the five `testdata/script_*.golden` files: each is one line holding the walk (`set -- $(ls -ldn "$q")`), `exit 48`, and no `SSHEPHERD`. These are the before-the-move pins; do not regenerate them in the later tasks.

**docsDelta:** none.

### Task 2: the shared vocabulary

**Files:** Modify `internal/fleet/fleet.go`, `internal/fleet/errors.go`. Test: `internal/fleet/errors_test.go`.

- [ ] **Step 1: Write the failing test** (append to `internal/fleet/errors_test.go`):

```go
func TestHostKeyAlertIncludesTypeChanged(t *testing.T) {
	for kind, want := range map[ErrorKind]bool{
		ErrorKindHostKeyChanged:        true,
		ErrorKindHostKeyRevoked:        true,
		ErrorKindHostKeyTypeChanged:    true,
		ErrorKindHostKeyTypeUnrecorded: false,
		ErrorKindHostKey:               false,
		ErrorKindAuth:                  false,
	} {
		if got := HostKeyAlert(kind); got != want {
			t.Errorf("HostKeyAlert(%q) = %v, want %v", kind, got, want)
		}
	}
}
```

In the same file, add `ErrorKindHostKeyTypeChanged: "host_key_type_changed"` to the `want` map of the existing `TestErrorKindWireValues`: the wire value is JSON contract.

- [ ] **Step 2: Run it to verify it fails**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/fleet/`
Expected: FAIL, `undefined: ErrorKindHostKeyTypeChanged`.

- [ ] **Step 3: Add the kind and the types.** In `internal/fleet/errors.go`, inside the `const (` block, after `ErrorKindHostKeyTypeUnrecorded`:

```go
	// ErrorKindHostKeyTypeChanged: known_hosts records a key type x/crypto
	// can verify for this host, and the server presented a key of another
	// type, or (on a CA-vouched host) a certificate no matching CA signed.
	// A possible impersonation: escalates the audit exit code to 2.
	ErrorKindHostKeyTypeChanged ErrorKind = "host_key_type_changed"
```

Change `HostKeyAlert` (P08 moved it here) to:

```go
func HostKeyAlert(kind ErrorKind) bool {
	return kind == ErrorKindHostKeyChanged || kind == ErrorKindHostKeyRevoked || kind == ErrorKindHostKeyTypeChanged
}
```

In `internal/fleet/fleet.go`, add to `ReadResult` after `Keys2Err`:

```go
	// Posture lists the StrictModes problems on the managed file and its
	// directories, as the posture probe reported them. Nil on a clean path.
	Posture []PostureIssue
```

and below the struct:

```go
// The posture issue names: the JSON "issue" values and the probe's grammar.
const (
	PostureSymlink       = "symlink"
	PostureForeignOwner  = "foreign_owner"
	PostureGroupWritable = "group_writable"
	PostureWorldWritable = "world_writable"
)
```

```go
// PostureIssue is one problem on the managed authorized_keys file or one of
// its directories, the conditions sshd's StrictModes refuses.
type PostureIssue struct {
	Path  string // sanitized; remote-controlled once resolved
	Issue string // one of the Posture* names
	Mode  string // ls -ldn's first field, e.g. "drwxrwxrwx"
	UID   string // the owner's uid as printed
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/fleet/`
Expected: PASS.

**docsDelta:** none.

### Task 3: move the walk to `sshconn.AncestorWalk`

**Files:** Create `internal/sshconn/posture.go`. Modify `internal/sshwrite/sshwrite.go:134` (`ancestorCheck`, including its doc comment).

- [ ] **Step 1: Confirm the failing state.** The Task 1 golden test passes today; the move is a refactor, so its failing-first evidence is Step 4's green after replacing the text.

- [ ] **Step 2: Create `internal/sshconn/posture.go`** with just the walk:

`package sshconn`, then:

```go
// AncestorWalk is sshd's StrictModes walk, shared by the write path (which
// refuses) and the posture probe (which reports). It walks the directory
// "$d" up to the login user's home (or /, for a path outside it) twice: as
// written, and resolved with cd -P. onMode runs for a component that is
// group- or other-writable, onOwner for one owned by neither the login user
// nor root; each action sees $1 (ls -ldn's mode), $3 (the owner uid) and $q
// (the path). Whoever can write an ancestor, or owns a symlink along the
// path, can redirect the file, e.g. a link that turns root's write into
// /root/.ssh. Symlinks are judged by owner only (their mode bits are
// meaningless); the resolved walk covers the directories they lead to.
// ls -ldn reports a symlink itself, so the as-written walk sees each link,
// not its target. Needs u and d.
func AncestorWalk(onMode, onOwner string) string {
	return `h=${HOME%/}; ph=$(cd -P "$h" 2>/dev/null && pwd -P)` +
		`; q="$d"; while :; do set -- $(ls -ldn "$q"); case $1 in l*) ;; ?????w*|????????w*) ` + onMode +
		`;; esac; if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + onOwner +
		`; fi; if [ "$q" = "$h" ] || [ "$q" = / ] || [ "$q" = . ]; then break; fi; q=$(dirname "$q"); done` +
		`; q=$(cd -P "$d" && pwd -P) || exit 1; while :; do set -- $(ls -ldn "$q"); case $1 in ?????w*|????????w*) ` + onMode +
		`;; esac; if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + onOwner +
		`; fi; if [ "$q" = "$ph" ] || [ "$q" = / ]; then break; fi; q=$(dirname "$q"); done`
}
```

- [ ] **Step 3: Replace `ancestorCheck` in `internal/sshwrite/sshwrite.go`**, including its doc comment, with:

```go
// ancestorCheck is the write path's StrictModes walk: the shared
// sshconn.AncestorWalk refusing (48) any component it objects to. Needs u
// and d. Every write-path script carries it, byte for byte.
var ancestorCheck = sshconn.AncestorWalk("exit "+strconv.Itoa(unsafePathExit), "exit "+strconv.Itoa(unsafePathExit))
```

`ancestorCheck` was a `const` used only inside function bodies, so a package-level `var` works; `TestOwnerChecksBite` reads it unchanged.

- [ ] **Step 4: Run to verify nothing moved**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite/ ./internal/sshconn/`
Expected: PASS, including every `TestWriteScriptsUnchanged` subtest against Task 1's goldens. A diff here means the extraction changed a byte: fix `AncestorWalk`, never the golden.

**docsDelta:** none.

### Task 4: the posture probe and its parser

**Files:** Modify `internal/sshconn/posture.go`, `internal/sshconn/posture_test.go`, `internal/sshconn/fuzz_test.go`. Create `internal/sshconn/testdata/fuzz/FuzzFinishPosture/{empty,garbage,no_newline,record_and_keys2}`.

- [ ] **Step 1: Replace `internal/sshconn/posture_test.go` with the full test file:**

```go
package sshconn

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
)

func capped(s string) *CappedBuffer {
	b := NewCappedBuffer(MaxRemoteOutput)
	_, _ = b.Write([]byte(s))
	return b
}

func TestFinishPosture(t *testing.T) {
	rec := func(mode, uid, issue, path string) string {
		return "SSHEPHERD-POSTURE " + mode + " " + uid + " " + issue + " " + path + "\n"
	}
	worldHome := fleet.PostureIssue{Path: "/home/d/.ssh", Issue: fleet.PostureWorldWritable, Mode: "drwxrwxrwx", UID: "1001"}
	tests := []struct {
		name    string
		code    int
		stdout  string
		want    []fleet.PostureIssue
		keys2   bool
		wantErr string
	}{
		{name: "clean", stdout: ""},
		{name: "one finding", stdout: rec("drwxrwxrwx", "1001", "world_writable", "/home/d/.ssh"), want: []fleet.PostureIssue{worldHome}},
		{name: "keys2", stdout: "SSHEPHERD-KEYS2 1\n", keys2: true},
		{name: "mode with an xattr marker", stdout: rec("-rw-rw-r--@", "5", "group_writable", "/k"),
			want: []fleet.PostureIssue{{Path: "/k", Issue: "group_writable", Mode: "-rw-rw-r--@", UID: "5"}}},
		{name: "path with spaces", stdout: rec("lrwxrwxrwx", "5", "symlink", "/a b/k"),
			want: []fleet.PostureIssue{{Path: "/a b/k", Issue: "symlink", Mode: "lrwxrwxrwx", UID: "5"}}},
		{name: "as-written and resolved duplicates collapse",
			stdout: rec("drwxrwxrwx", "1001", "world_writable", "/home/d/.ssh") + rec("drwxrwxrwx", "1001", "world_writable", "/home/d/.ssh"),
			want:   []fleet.PostureIssue{worldHome}},
		{name: "both write bits are two records",
			stdout: rec("drwxrwxrwx", "1", "group_writable", "/x") + rec("drwxrwxrwx", "1", "world_writable", "/x"),
			want: []fleet.PostureIssue{{Path: "/x", Issue: "group_writable", Mode: "drwxrwxrwx", UID: "1"},
				{Path: "/x", Issue: "world_writable", Mode: "drwxrwxrwx", UID: "1"}}},
		{name: "path is sanitized", stdout: rec("drwxrwxrwx", "1", "world_writable", "/x\x1b[31m"),
			want: []fleet.PostureIssue{{Path: "/x[31m", Issue: "world_writable", Mode: "drwxrwxrwx", UID: "1"}}},
		{name: "garbage line", stdout: "hello\n", wantErr: "malformed"},
		{name: "blank line", stdout: "\n", wantErr: "malformed"},
		{name: "unknown issue", stdout: rec("drwxrwxrwx", "1", "cursed", "/x"), wantErr: "malformed"},
		{name: "bad mode", stdout: rec("drwx", "1", "world_writable", "/x"), wantErr: "malformed"},
		{name: "bad uid", stdout: rec("drwxrwxrwx", "root", "world_writable", "/x"), wantErr: "malformed"},
		{name: "newline in path", stdout: rec("drwxrwxrwx", "1", "world_writable", "/x\n/y"), wantErr: "malformed"},
		{name: "no final newline", stdout: strings.TrimSuffix(rec("drwxrwxrwx", "1", "world_writable", "/x"), "\n"), wantErr: "malformed"},
		{name: "keys2 with another value", stdout: "SSHEPHERD-KEYS2 2\n", wantErr: "malformed"},
		{name: "65 records", stdout: strings.Repeat(rec("drwxrwxrwx", "1", "world_writable", "/x"), 65), wantErr: "malformed"},
		{name: "64 records", stdout: strings.Repeat(rec("drwxrwxrwx", "1", "world_writable", "/x"), 64),
			want: []fleet.PostureIssue{{Path: "/x", Issue: "world_writable", Mode: "drwxrwxrwx", UID: "1"}}},
		{name: "non-zero exit", code: 2, stdout: rec("drwxrwxrwx", "1", "world_writable", "/x"), wantErr: "posture probe failed (exit 2): boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, keys2, err := FinishPosture(tt.code, capped(tt.stdout), capped("boom\n"))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || fleet.ErrorKindOf(err) != fleet.ErrorKindRemote {
					t.Fatalf("err = %v, want a remote error containing %q", err, tt.wantErr)
				}
				if got != nil || keys2 {
					t.Fatalf("a failed probe must return nothing: %v, %v", got, keys2)
				}
				return
			}
			if err != nil {
				t.Fatalf("FinishPosture: %v", err)
			}
			if !slices.Equal(got, tt.want) || keys2 != tt.keys2 {
				t.Errorf("got %+v keys2=%v, want %+v keys2=%v", got, keys2, tt.want, tt.keys2)
			}
		})
	}
	t.Run("output at the capture limit", func(t *testing.T) {
		b := NewCappedBuffer(MaxRemoteOutput)
		_, _ = b.Write([]byte(strings.Repeat("x", MaxRemoteOutput+1)))
		if _, _, err := FinishPosture(0, b, capped("")); fleet.ErrorKindOf(err) != fleet.ErrorKindRemote {
			t.Errorf("err = %v, want remote", err)
		}
	})
}

// postureHome builds a HOME the walk accepts: home 0700, ~/.ssh 0700, a
// 0600 authorized_keys.
func postureHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	must(t, os.Chmod(home, 0o700)) // t.TempDir's mode follows the umask
	must(t, os.Mkdir(filepath.Join(home, ".ssh"), 0o700))
	must(t, os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("k\n"), 0o600))
	return home
}

// runPosture runs the probe through a real sh, parses it, and fails on any
// probe error.
func runPosture(t *testing.T, home, path string) ([]fleet.PostureIssue, bool) {
	t.Helper()
	c := exec.CommandContext(t.Context(), "sh", "-c", PostureCmdFor(path)) // #nosec G204 -- the probe under test
	c.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	c.Stdout, c.Stderr = &stdout, &stderr
	code := 0
	var exitErr *exec.ExitError
	if err := c.Run(); errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	issues, keys2, err := FinishPosture(code, capped(stdout.String()), capped(stderr.String()))
	if err != nil {
		t.Fatalf("FinishPosture: %v\nstdout: %s", err, stdout.String())
	}
	return issues, keys2
}

// issueSet renders findings as sorted, distinct "base-of-path issue": a
// macOS TempDir is /var/… as written and /private/var/… resolved, so full
// paths do not compare and one directory yields two records.
func issueSet(issues []fleet.PostureIssue) []string {
	out := make([]string, 0, len(issues))
	for _, i := range issues {
		out = append(out, filepath.Base(i.Path)+" "+i.Issue)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestPostureCmdFindings(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, home string)
		want  []string
	}{
		{"0700 is clean", func(*testing.T, string) {}, nil},
		{"world-writable ~/.ssh",
			func(t *testing.T, h string) { must(t, os.Chmod(filepath.Join(h, ".ssh"), 0o777)) },
			[]string{".ssh group_writable", ".ssh world_writable"}},
		{"group-writable ~/.ssh",
			func(t *testing.T, h string) { must(t, os.Chmod(filepath.Join(h, ".ssh"), 0o770)) },
			[]string{".ssh group_writable"}},
		{"group-writable file",
			func(t *testing.T, h string) { must(t, os.Chmod(filepath.Join(h, ".ssh", "authorized_keys"), 0o660)) },
			[]string{"authorized_keys group_writable"}},
		{"world-writable file",
			func(t *testing.T, h string) { must(t, os.Chmod(filepath.Join(h, ".ssh", "authorized_keys"), 0o602)) },
			[]string{"authorized_keys world_writable"}},
		{"group-writable home",
			func(t *testing.T, h string) { must(t, os.Chmod(h, 0o770)) },
			[]string{"HOME group_writable"}},
		{"symlinked file is reported, its target's mode is not",
			func(t *testing.T, h string) {
				f := filepath.Join(h, ".ssh", "authorized_keys")
				must(t, os.Remove(f))
				must(t, os.WriteFile(filepath.Join(h, ".ssh", "real"), []byte("k\n"), 0o666))
				must(t, os.Symlink("real", f))
			},
			[]string{"authorized_keys symlink"}},
		{"absent file is clean", func(t *testing.T, h string) { must(t, os.Remove(filepath.Join(h, ".ssh", "authorized_keys"))) }, nil},
		{"absent ~/.ssh is clean", func(t *testing.T, h string) { must(t, os.RemoveAll(filepath.Join(h, ".ssh"))) }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := postureHome(t)
			tt.setup(t, home)
			issues, _ := runPosture(t, home, DefaultAuthorizedKeysPath)
			got := issueSet(issues)
			want := slices.Clone(tt.want)
			for i := range want {
				want[i] = strings.Replace(want[i], "HOME", filepath.Base(home), 1)
			}
			slices.Sort(want)
			if len(got) == 0 && len(want) == 0 {
				return
			}
			if !slices.Equal(got, want) {
				t.Errorf("findings = %v, want %v", got, want)
			}
		})
	}
}

// TestPostureOutsideHomeWalksToRoot (D14c): an override outside $HOME is
// walked up to /, so a writable directory far above it is reported.
func TestPostureOutsideHomeWalksToRoot(t *testing.T) {
	home := postureHome(t)
	outer := t.TempDir()
	must(t, os.Chmod(outer, 0o700))
	loose := filepath.Join(outer, "loose")
	must(t, os.Mkdir(loose, 0o777))
	must(t, os.Chmod(loose, 0o777)) // defeat the umask
	inner := filepath.Join(loose, "inner")
	must(t, os.Mkdir(inner, 0o700))
	must(t, os.WriteFile(filepath.Join(inner, "keys"), []byte("k\n"), 0o600))
	issues, _ := runPosture(t, home, filepath.Join(inner, "keys"))
	if got := issueSet(issues); !slices.Contains(got, "loose world_writable") || !slices.Contains(got, "loose group_writable") {
		t.Errorf("findings = %v, want the loose ancestor reported", got)
	}
}

// TestPostureRootIsAnAcceptedOwner (D14a): the outside-home walk passes
// through root-owned directories up to / and must not report any of them.
func TestPostureRootIsAnAcceptedOwner(t *testing.T) {
	home := postureHome(t)
	outer := t.TempDir()
	must(t, os.Chmod(outer, 0o700))
	must(t, os.WriteFile(filepath.Join(outer, "keys"), []byte("k\n"), 0o600))
	issues, _ := runPosture(t, home, filepath.Join(outer, "keys"))
	for _, i := range issues {
		if i.Issue == fleet.PostureForeignOwner && i.UID == "0" {
			t.Errorf("root reported as a foreign owner: %+v", i)
		}
	}
}

func TestPostureForeignOwnerUsesProbeUID(t *testing.T) {
	home := postureHome(t)
	bin := t.TempDir()
	// A stubbed id: the probe thinks it runs as uid 4242, so every owner is
	// foreign — without needing root to chown anything.
	must(t, os.WriteFile(filepath.Join(bin, "id"), []byte("#!/bin/sh\necho 4242\n"), 0o755))    // #nosec G306 -- test stub on PATH
	c := exec.CommandContext(t.Context(), "sh", "-c", PostureCmdFor(DefaultAuthorizedKeysPath)) // #nosec G204 -- the probe under test
	c.Env = []string{"HOME=" + home, "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
	out, err := c.Output()
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if os.Getuid() == 0 {
		t.Skip("running as root: root is an accepted owner, so nothing is foreign")
	}
	issues, _, err := FinishPosture(0, capped(string(out)), capped(""))
	if err != nil {
		t.Fatalf("FinishPosture: %v", err)
	}
	got := issueSet(issues)
	want := []string{filepath.Base(home) + " foreign_owner", ".ssh foreign_owner", "authorized_keys foreign_owner"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
}

// runStubbed runs the probe with a stub of tool first on PATH and returns
// FinishPosture's verdict.
func runStubbed(t *testing.T, home, path, tool, body string) ([]fleet.PostureIssue, error) {
	t.Helper()
	bin := t.TempDir()
	must(t, os.WriteFile(filepath.Join(bin, tool), []byte(body), 0o755))   // #nosec G306 -- test stub on PATH
	c := exec.CommandContext(t.Context(), "sh", "-c", PostureCmdFor(path)) // #nosec G204 -- the probe under test
	c.Env = []string{"HOME=" + home, "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	c.Stdout, c.Stderr = &stdout, &stderr
	code := 0
	var exitErr *exec.ExitError
	if err := c.Run(); errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	issues, _, err := FinishPosture(code, capped(stdout.String()), capped(stderr.String()))
	return issues, err
}

// TestPostureDanglingSymlinkAncestor: a symlink along the path that points
// nowhere is not a directory, so the walk starts above it, but its owner is
// still judged. Only components that do not exist are skipped.
func TestPostureDanglingSymlinkAncestor(t *testing.T) {
	home := postureHome(t)
	must(t, os.Symlink(filepath.Join(home, "nowhere"), filepath.Join(home, "dangle")))
	path := filepath.Join(home, "dangle", "keys")
	if issues, _ := runPosture(t, home, path); len(issues) != 0 {
		t.Errorf("a dangling link owned by the login user is clean, got %+v", issues)
	}
	if os.Getuid() == 0 {
		t.Skip("running as root: root is an accepted owner, so nothing is foreign")
	}
	issues, err := runStubbed(t, home, path, "id", "#!/bin/sh\necho 4242\n")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if got := issueSet(issues); !slices.Contains(got, "dangle foreign_owner") {
		t.Errorf("findings = %v, want the dangling link's owner reported", got)
	}
}

// TestPostureFailedLsFailsClosed: a failed ls leaves $1 and $3 empty, so the
// probe prints a record the grammar refuses and the server is unreachable,
// never clean. The message is "malformed", not "failed (exit N)": the
// shared walk's bytes are pinned and it cannot exit on a failed ls (plan
// decision 15).
func TestPostureFailedLsFailsClosed(t *testing.T) {
	_, err := runStubbed(t, postureHome(t), DefaultAuthorizedKeysPath, "ls", "#!/bin/sh\nexit 1\n")
	if fleet.ErrorKindOf(err) != fleet.ErrorKindRemote || err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("err = %v, want a remote malformed-output error", err)
	}
}

// TestPostureKeys2 keeps the removed SecondaryKeysCmdFor rule: any spelling
// that resolves on the server to ~/.ssh/authorized_keys sees keys2; nothing
// else does.
func TestPostureKeys2(t *testing.T) {
	linkFile := func(rel string) func(t *testing.T, home string) {
		return func(t *testing.T, home string) {
			t.Helper()
			must(t, os.WriteFile(filepath.Join(home, rel), []byte("k\n"), 0o600))
			must(t, os.MkdirAll(filepath.Join(home, "keys"), 0o700))
			must(t, os.Symlink(filepath.Join(home, rel), filepath.Join(home, "keys", "ak")))
		}
	}
	tests := []struct {
		name  string
		path  func(home string) string
		setup func(t *testing.T, home string)
		ak2   bool
		empty bool
		want  bool
	}{
		{name: "default spelling", path: func(string) string { return DefaultAuthorizedKeysPath }, ak2: true, want: true},
		{name: "default spelling, absent", path: func(string) string { return DefaultAuthorizedKeysPath }},
		{name: "default spelling, empty", path: func(string) string { return DefaultAuthorizedKeysPath }, ak2: true, empty: true},
		{name: "absolute default", path: func(h string) string { return filepath.Join(h, ".ssh", "authorized_keys") }, ak2: true, want: true},
		{name: "absolute default, no keys2", path: func(h string) string { return filepath.Join(h, ".ssh", "authorized_keys") }},
		{name: "through a symlinked dir", path: func(h string) string { return filepath.Join(h, "link", "authorized_keys") },
			setup: func(t *testing.T, h string) { must(t, os.Symlink(filepath.Join(h, ".ssh"), filepath.Join(h, "link"))) }, ak2: true, want: true},
		{name: "other file in ~/.ssh", path: func(h string) string { return filepath.Join(h, ".ssh", "other") }, ak2: true},
		{name: "tilde override elsewhere", path: func(string) string { return "~/keys/deploy" }, ak2: true},
		{name: "missing dir never matches", path: func(h string) string { return filepath.Join(h, "nodir", "authorized_keys") }, ak2: true},
		{name: "symlinked file to the default", path: func(h string) string { return filepath.Join(h, "keys", "ak") },
			setup: linkFile(".ssh/authorized_keys"), ak2: true, want: true},
		{name: "tilde symlinked file to the default", path: func(string) string { return "~/keys/ak" },
			setup: linkFile(".ssh/authorized_keys"), ak2: true, want: true},
		{name: "symlinked file to the default, no keys2", path: func(h string) string { return filepath.Join(h, "keys", "ak") },
			setup: linkFile(".ssh/authorized_keys")},
		{name: "symlinked file to another file", path: func(h string) string { return filepath.Join(h, "keys", "ak") },
			setup: linkFile(".ssh/other"), ak2: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := postureHome(t)
			if tt.ak2 {
				content := "ssh-ed25519 AAAA planted\n"
				if tt.empty {
					content = ""
				}
				must(t, os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys2"), []byte(content), 0o600))
			}
			if tt.setup != nil {
				tt.setup(t, home)
			}
			if _, got := runPosture(t, home, tt.path(home)); got != tt.want {
				t.Errorf("keys2 = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPostureCmdIsSingleLineAndQuotesPath(t *testing.T) {
	script := PostureCmdFor(`/srv/it's; touch /tmp/pwn`)
	if strings.ContainsAny(script, "\r\n") {
		t.Fatal("remote scripts must be single-line")
	}
	if want := `p='/srv/it'\''s; touch /tmp/pwn'`; !strings.HasPrefix(script, want+";") {
		t.Errorf("script %q does not start with the quoted assignment", script[:60])
	}
	if n := strings.Count(script, "touch"); n != 1 {
		t.Errorf("the path entered the script %d times, want 1", n)
	}
}

// TestReadCmdUnchanged: sshwrite's verify reads back through this exact
// command, so the posture work must not touch it.
func TestReadCmdUnchanged(t *testing.T) {
	want := `p="${HOME:?}"/'.ssh/authorized_keys'; if [ -e "$p" ]; then cat "$p"; else exit 44; fi`
	if got := AuthorizedKeysCmdFor(DefaultAuthorizedKeysPath); got != want {
		t.Errorf("read command changed:\n got %s\nwant %s", got, want)
	}
}
```

- [ ] **Step 2: Append `FuzzFinishPosture` to `internal/sshconn/fuzz_test.go`** and add its seed corpus:

```go
// FuzzFinishPosture pins the fail-closed property: whatever a server prints,
// a nil error means every line was a well-formed record, so garbage can
// never be read as a clean posture.
func FuzzFinishPosture(f *testing.F) {
	f.Add("")
	f.Add("SSHEPHERD-KEYS2 1\n")
	f.Add("SSHEPHERD-POSTURE drwxrwxrwx 1001 world_writable /home/d/.ssh\n")
	f.Add("hello\n")
	f.Add("\n")
	f.Fuzz(func(t *testing.T, out string) {
		stdout := NewCappedBuffer(MaxRemoteOutput)
		_, _ = stdout.Write([]byte(out))
		issues, _, err := FinishPosture(0, stdout, NewCappedBuffer(16))
		if err != nil {
			return
		}
		if out == "" {
			if issues != nil {
				t.Fatalf("no output produced findings: %+v", issues)
			}
			return
		}
		if !strings.HasSuffix(out, "\n") {
			t.Fatalf("accepted output without a final newline: %q", out)
		}
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if line != postureKeys2Record && !postureRecord.MatchString(line) {
				t.Fatalf("accepted a non-record line %q in %q", line, out)
			}
		}
		if len(issues) > maxPostureRecords {
			t.Fatalf("%d issues exceed the cap", len(issues))
		}
	})
}
```

Corpus files (each a Go fuzz seed file under `internal/sshconn/testdata/fuzz/FuzzFinishPosture/`):

```text
empty:             go test fuzz v1\nstring("")\n
garbage:           go test fuzz v1\nstring("hello\\n")\n
no_newline:        go test fuzz v1\nstring("SSHEPHERD-POSTURE -rw-r--r-- 1 world_writable /x")\n
record_and_keys2:  go test fuzz v1\nstring("SSHEPHERD-POSTURE drwxrwxrwx 1001 world_writable /home/d/.ssh\\nSSHEPHERD-KEYS2 1\\n")\n
```

(the `\n` after each `go test fuzz v1` and after the closing `)` is a real newline; the `\\n` inside the string is the two characters backslash-n, as `printf` wrote them.)

- [ ] **Step 3: Run to verify they fail**

Run: `GOTOOLCHAIN=go1.27.3 go vet ./internal/sshconn/`
Expected: FAIL, `undefined: FinishPosture`.

- [ ] **Step 4: Implement.** Replace `internal/sshconn/posture.go` with:

```go
package sshconn

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sanitize"
)

// AncestorWalk is sshd's StrictModes walk, shared by the write path (which
// refuses) and the posture probe (which reports). It walks the directory
// "$d" up to the login user's home (or /, for a path outside it) twice: as
// written, and resolved with cd -P. onMode runs for a component that is
// group- or other-writable, onOwner for one owned by neither the login user
// nor root; each action sees $1 (ls -ldn's mode), $3 (the owner uid) and $q
// (the path). Whoever can write an ancestor, or owns a symlink along the
// path, can redirect the file, e.g. a link that turns root's write into
// /root/.ssh. Symlinks are judged by owner only (their mode bits are
// meaningless); the resolved walk covers the directories they lead to.
// ls -ldn reports a symlink itself, so the as-written walk sees each link,
// not its target. Needs u and d.
func AncestorWalk(onMode, onOwner string) string {
	return `h=${HOME%/}; ph=$(cd -P "$h" 2>/dev/null && pwd -P)` +
		`; q="$d"; while :; do set -- $(ls -ldn "$q"); case $1 in l*) ;; ?????w*|????????w*) ` + onMode +
		`;; esac; if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + onOwner +
		`; fi; if [ "$q" = "$h" ] || [ "$q" = / ] || [ "$q" = . ]; then break; fi; q=$(dirname "$q"); done` +
		`; q=$(cd -P "$d" && pwd -P) || exit 1; while :; do set -- $(ls -ldn "$q"); case $1 in ?????w*|????????w*) ` + onMode +
		`;; esac; if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + onOwner +
		`; fi; if [ "$q" = "$ph" ] || [ "$q" = / ]; then break; fi; q=$(dirname "$q"); done`
}

// Records the posture probe prints, one per line.
const (
	postureKeys2Record = "SSHEPHERD-KEYS2 1"
	// maxPostureRecords bounds what a server can make audit print: a real
	// path has far fewer components than two walks times two findings.
	maxPostureRecords = 64
)

// postureRecord is the probe's one record shape. Issue names and the mode
// are closed sets; the path is the rest of the line, so a path containing a
// newline breaks the grammar and fails closed.
var postureRecord = regexp.MustCompile(`^SSHEPHERD-POSTURE ([-dlbcps][-rwxsStT]{9}[.+@]?) ([0-9]+) (` +
	fleet.PostureSymlink + `|` + fleet.PostureForeignOwner + `|` + fleet.PostureGroupWritable + `|` + fleet.PostureWorldWritable + `) (.+)$`)

var errPostureMalformed = errors.New("posture probe output malformed")

// PostureCmdFor builds the read-only posture probe for the managed file at
// path: it prints one SSHEPHERD-POSTURE record per StrictModes problem on
// the file and its directories (group- or world-writable, owned by neither
// the login user nor root, a symlinked file), and SSHEPHERD-KEYS2 1 when a
// non-empty ~/.ssh/authorized_keys2 sits beside a default-equivalent managed
// path. It walks from the file's nearest existing directory, checking the
// owner of any dangling symlink it passes on the way up, never exits early
// on a finding, and exits non-zero only when a required tool fails. Absent
// components are not findings: the read already reports absence.
func PostureCmdFor(path string) string {
	const (
		rec        = `R() { printf 'SSHEPHERD-POSTURE %s %s %s %s\n' "$1" "$2" "$3" "$q"; }`
		modeFinds  = `case $1 in ?????w*) R "$1" "$3" ` + fleet.PostureGroupWritable + `;; esac; case $1 in ????????w*) R "$1" "$3" ` + fleet.PostureWorldWritable + `;; esac`
		ownerFinds = `R "$1" "$3" ` + fleet.PostureForeignOwner
	)
	return PathAssign(path) + `; set -f; u=$(id -u) || exit 1; ` + rec +
		`; q="$p"; if [ -L "$p" ]; then set -- $(ls -ldn "$p"); R "$1" "$3" ` + fleet.PostureSymlink +
		`; elif [ -e "$p" ]; then set -- $(ls -ldn "$p"); if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + ownerFinds + `; fi; ` + modeFinds + `; fi` +
		`; d=$(dirname "$p"); while [ ! -d "$d" ]; do if [ -L "$d" ]; then q="$d"; set -- $(ls -ldn "$q"); if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + ownerFinds + `; fi; fi; d=$(dirname "$d"); done; ` + AncestorWalk(modeFinds, ownerFinds) +
		`; k="${HOME:?}"/.ssh; ` + keys2Check(path) + `; exit 0`
}

// keys2Check prints the keys2 record for a managed path that is the default
// spelling or resolves on the server to ~/.ssh/authorized_keys (cd -P for the
// directory; test -ef for a symlinked final component, degrading to the
// directory-only comparison on a shell without it). A directory that does
// not resolve never matches, so two missing directories cannot both collapse
// to "/authorized_keys". Needs p and k.
func keys2Check(path string) string {
	const report = `if [ -s "$k/authorized_keys2" ]; then printf '` + postureKeys2Record + `\n'; fi`
	if path == DefaultAuthorizedKeysPath {
		return report
	}
	return `a=$(cd -P "$(dirname "$p")" 2>/dev/null && pwd -P) && s=$(cd -P "$k" 2>/dev/null && pwd -P)` +
		` && { [ "$a/${p##*/}" = "$s/authorized_keys" ] || [ "$p" -ef "$s/authorized_keys" ] 2>/dev/null; } && { ` + report + `; }`
}

// FinishPosture parses the probe's outcome, fail-closed: a non-zero exit,
// any line outside the grammar, more than maxPostureRecords records or
// output at the capture limit is ErrorKindRemote, never a clean result, so
// the server is unreachable rather than graded. The as-written and resolved
// walks visit the same directory when no symlink is involved, so identical
// (path, issue) records collapse to one, after the count check.
func FinishPosture(code int, stdout, stderr *CappedBuffer) ([]fleet.PostureIssue, bool, error) {
	if code != 0 {
		return nil, false, classify(fleet.ErrorKindRemote,
			fmt.Errorf("posture probe failed (exit %d): %s", code, sanitize.RemoteSnippet(stderr.String())))
	}
	if stdout.truncated || stdout.Len() >= MaxRemoteOutput {
		return nil, false, classify(fleet.ErrorKindRemote, errPostureMalformed)
	}
	out := stdout.String()
	if out == "" {
		return nil, false, nil
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if !strings.HasSuffix(out, "\n") || len(lines) > maxPostureRecords {
		return nil, false, classify(fleet.ErrorKindRemote, errPostureMalformed)
	}
	var issues []fleet.PostureIssue
	keys2 := false
	for _, line := range lines {
		if line == postureKeys2Record {
			keys2 = true
			continue
		}
		m := postureRecord.FindStringSubmatch(line)
		if m == nil {
			return nil, false, classify(fleet.ErrorKindRemote, errPostureMalformed)
		}
		issue := fleet.PostureIssue{Mode: m[1], UID: m[2], Issue: m[3], Path: sanitize.Remote(m[4])}
		seen := slices.ContainsFunc(issues, func(i fleet.PostureIssue) bool { return i.Path == issue.Path && i.Issue == issue.Issue })
		if !seen {
			issues = append(issues, issue)
		}
	}
	return issues, keys2, nil
}
```

- [ ] **Step 5: Run to verify they pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn/ -run 'Posture|FuzzFinishPosture|ReadCmd'`
Expected: PASS. The expected output in `TestFinishPosture`'s "path is sanitized" row is `/x[31m` because `sanitize.Remote` strips the escape byte only.

**docsDelta:** none.

### Task 5: `sshread` runs the probe; the keys2 probe is removed

**Files:** Modify `internal/sshread/sshread.go:168` (`readAuthorizedKeys`, its doc comment), `internal/sshconn/sshconn.go`, `internal/sshconn/sshconn_test.go`, `internal/sshread/hermetic_test.go`.

- [ ] **Step 1: Write the failing tests.** Append to `internal/sshread/hermetic_test.go` (and add `"io"`, `"slices"` and the `internal/fleet` import):

```go
// TestReadPosture: the probe's findings reach ReadResult.Posture through a
// real SSH session and a real shell.
func TestReadPosture(t *testing.T) {
	tests := []struct {
		name  string
		chmod func(t *testing.T, home string)
		want  string // "" = clean
	}{
		{"0700 is clean", func(*testing.T, string) {}, ""},
		{"0777 ~/.ssh is world-writable", func(t *testing.T, h string) { mustChmod(t, filepath.Join(h, ".ssh"), 0o777) }, fleet.PostureWorldWritable},
		{"0775 ~/.ssh is group-writable", func(t *testing.T, h string) { mustChmod(t, filepath.Join(h, ".ssh"), 0o775) }, fleet.PostureGroupWritable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := shortTempDir(t)
			mustChmod(t, home, 0o700)
			writeHomeFile(t, home, ".ssh/authorized_keys", "key-line\n")
			tt.chmod(t, home)
			c, _, srv := hermeticClient(t, home)
			res := readHermetic(t, c, srv)
			if tt.want == "" {
				if len(res.Posture) != 0 {
					t.Fatalf("posture = %+v, want clean", res.Posture)
				}
				return
			}
			if !slices.ContainsFunc(res.Posture, func(i fleet.PostureIssue) bool { return i.Issue == tt.want }) {
				t.Errorf("posture = %+v, want a %s finding", res.Posture, tt.want)
			}
		})
	}
	t.Run("symlinked file", func(t *testing.T) {
		home := shortTempDir(t)
		mustChmod(t, home, 0o700)
		writeHomeFile(t, home, ".ssh/real", "key-line\n")
		if err := os.Symlink("real", filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
			t.Fatal(err)
		}
		c, _, srv := hermeticClient(t, home)
		res := readHermetic(t, c, srv)
		if string(res.Content) != "key-line\n" {
			t.Errorf("content = %q", res.Content)
		}
		if !slices.ContainsFunc(res.Posture, func(i fleet.PostureIssue) bool { return i.Issue == fleet.PostureSymlink }) {
			t.Errorf("posture = %+v, want a symlink finding", res.Posture)
		}
	})
	t.Run("absent file is clean", func(t *testing.T) {
		home := shortTempDir(t)
		mustChmod(t, home, 0o700)
		c, _, srv := hermeticClient(t, home)
		res := readHermetic(t, c, srv)
		if !res.FileAbsent || len(res.Posture) != 0 {
			t.Errorf("FileAbsent=%v posture=%+v, want absent and clean", res.FileAbsent, res.Posture)
		}
	})
	t.Run("override path outside HOME", func(t *testing.T) {
		home := shortTempDir(t)
		mustChmod(t, home, 0o700)
		outside := shortTempDir(t)
		mustChmod(t, outside, 0o777)
		if err := os.WriteFile(filepath.Join(outside, "keys"), []byte("key-line\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c, _, srv := hermeticClient(t, home)
		srv.AuthorizedKeysFile = filepath.Join(outside, "keys")
		res := readHermetic(t, c, srv)
		if !slices.ContainsFunc(res.Posture, func(i fleet.PostureIssue) bool {
			return i.Issue == fleet.PostureWorldWritable && filepath.Base(i.Path) == filepath.Base(outside)
		}) {
			t.Errorf("posture = %+v, want the override's directory reported", res.Posture)
		}
	})
}

// TestReadCostsTwoSessions: the posture session replaced the keys2 probe, so
// a read stays at two sessions on the default path and on an override.
func TestReadCostsTwoSessions(t *testing.T) {
	for _, override := range []string{"", "~/keys/deploy"} {
		home := shortTempDir(t)
		mustChmod(t, home, 0o700)
		writeHomeFile(t, home, ".ssh/authorized_keys", "key-line\n")
		writeHomeFile(t, home, "keys/deploy", "key-line\n")
		c, fake, srv := hermeticClient(t, home)
		srv.AuthorizedKeysFile = override
		readHermetic(t, c, srv)
		if got := len(fake.Commands()); got != 2 {
			t.Errorf("override %q: %d sessions, want 2", override, got)
		}
	}
}

// TestReadFailsClosedOnBadPosture: a probe that exits non-zero or prints
// garbage fails the read as ErrorKindRemote (D14b).
func TestReadFailsClosedOnBadPosture(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		code   int
		want   string
	}{
		{"garbage output", "not a record\n", 0, "posture probe output malformed"},
		{"failed tool", "", 7, "posture probe failed (exit 7)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, host := sshtest.Key(1), sshtest.Signer(t, sshtest.Key(40))
			srv := sshtest.NewServer(t, sshtest.ServerConfig{
				HostKeys:   []ssh.Signer{host},
				Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
				Handle: func(_ context.Context, cmd string, _ io.Reader, stdout, _ io.Writer) int {
					if strings.Contains(cmd, "SSHEPHERD-POSTURE") {
						_, _ = io.WriteString(stdout, tt.stdout)
						return tt.code
					}
					_, _ = io.WriteString(stdout, "key-line\n")
					return 0
				},
			})
			c := &Client{
				KnownHostsPath: sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey())),
				Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, user)},
				DialTimeout:    5 * time.Second,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "web-1", Host: srv.Host, Port: srv.Port, User: "deploy"})
			if fleet.ErrorKindOf(err) != fleet.ErrorKindRemote || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want a remote error containing %q", err, tt.want)
			}
		})
	}
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readHermetic(t *testing.T, c *Client, srv config.Server) fleet.ReadResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, srv)
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	return res
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshread/ -run 'TestReadPosture|TestReadCostsTwoSessions|TestReadFailsClosed'`
Expected: FAIL: `res.Posture` is empty and the sessions are still two probes with no posture findings; `TestReadFailsClosedOnBadPosture` reads successfully.

- [ ] **Step 3: Implement.** Replace the second session of `readAuthorizedKeys` (from `code, _, stderr, err = sshconn.Exec(ctx, conn.Client, sshconn.SecondaryKeysCmdFor(path), nil)` down to `res.AuthorizedKeys2 = present`) with:

```go
	code, stdout, stderr, err = sshconn.Exec(ctx, conn.Client, sshconn.PostureCmdFor(path), nil)
	if err != nil {
		return zero, fmt.Errorf("posture probe on %s: %w", addr, err)
	}
	posture, present, err := sshconn.FinishPosture(code, stdout, stderr)
	if err != nil {
		return zero, fmt.Errorf("on %s: %w", addr, err)
	}
	res.Posture = posture
	res.AuthorizedKeys2 = present
```

Replace the `readAuthorizedKeys` doc comment's probe sentences with:

```go
// otherwise — via a one-shot session. A second short session on the same
// connection runs the posture probe (sshconn.PostureCmdFor), for every read:
// the StrictModes state of the file and its directories, and whether a
// non-empty ~/.ssh/authorized_keys2 sits beside a managed path that is the
// default one or an equivalent spelling of it. A failed or malformed probe
// fails the read (fail-closed: a server cannot look clean by hiding its
// posture). Deadline semantics live
```

- [ ] **Step 4: Remove the old probe.** Delete from `internal/sshconn/sshconn.go` the const `secondaryPresentExit` (and its doc comment) and the functions `SecondaryKeysCmd`, `SecondaryKeysCmdFor`, `FinishSecondaryProbe`. Keep `SecondaryAuthorizedKeysPath` (`readKeys2` still uses it). In `internal/sshconn/sshconn_test.go`, delete `TestSecondaryKeysCmd`, `TestSecondaryKeysCmdFor` and `linkFile` (`TestPostureKeys2` keeps every row), and in `TestRemoteErrorsBoundStderr` replace the `FinishSecondaryProbe` line with:

```go
	_, _, err2 := FinishPosture(2, NewCappedBuffer(10), stderr)
```

- [ ] **Step 5: Run to verify they pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshread/ ./internal/sshconn/ ./internal/sshwrite/ ./cmd/sshepherd/`
Expected: PASS. `TestReadReportsAuthorizedKeys2`'s rows stand unchanged.

**docsDelta:** none.

### Task 6: real-sshd fixture and integration case

**Files:** Modify `scripts/integration.sh`, `internal/sshread/integration_test.go`.

- [ ] **Step 1: Add the fixture user.** In `scripts/integration.sh`'s `FIXTURE_A`, add `loose` to all three user lists (the `mkuser`, `cp /seed/key.pub` and `chown -R` loops), and before `# Ownership-refusal fixtures (TST-1).` add:

```sh
    # loose: logs in through its 0700 ~/.ssh; the managed override sits below
    # a 0775 ~/loose (posture finding), which sshd never reads.
    mkdir -p /home/loose/loose && cp /seed/key.pub /home/loose/loose/keys
    chown -R loose:loose /home/loose/loose && chmod 775 /home/loose/loose && chmod 600 /home/loose/loose/keys
```

- [ ] **Step 2: Append the integration tests** to `internal/sshread/integration_test.go`:

```go
// TestIntegrationPostureGroupWritable: on a real sshd and every distro's
// shell, a 0775 directory reports group_writable. User "loose" logs in via
// its 0700 ~/.ssh; the managed file is an override below a 0775 ~/loose, so
// sshd's StrictModes (on in the container) still lets the login through.
func TestIntegrationPostureGroupWritable(t *testing.T) {
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "it", Host: host, Port: port, User: "loose", AuthorizedKeysFile: "~/loose/keys"})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if len(res.Posture) != 1 || res.Posture[0].Issue != fleet.PostureGroupWritable || res.Posture[0].Path != "/home/loose/loose" {
		t.Fatalf("posture = %+v, want one group_writable finding on /home/loose/loose", res.Posture)
	}
	if !strings.HasPrefix(res.Posture[0].Mode, "drwxrwx") {
		t.Errorf("mode = %q", res.Posture[0].Mode)
	}
}

// TestIntegrationPostureRootOwnedClean (D14a): sshd accepts root as owner of
// the file and of its directory, so audit does too, although apply refuses
// both (TestIntegrationOwnershipRefusals). The fixtures are read-only here.
func TestIntegrationPostureRootOwnedClean(t *testing.T) {
	c, host, port := itClient(t)
	for _, user := range []string{"ffile", "fdir"} { // root-owned authorized_keys; root-owned ~/.ssh
		t.Run(user, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: user, Host: host, Port: port, User: user})
			if err != nil {
				t.Fatalf("ReadAuthorizedKeys: %v", err)
			}
			if len(res.Posture) != 0 {
				t.Errorf("posture = %+v, want clean: root is an accepted owner", res.Posture)
			}
		})
	}
}

// TestIntegrationPostureClean: a stock fixture user has no findings.
func TestIntegrationPostureClean(t *testing.T) {
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "it", Host: host, Port: port, User: "present"})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if len(res.Posture) != 0 {
		t.Errorf("posture = %+v, want clean", res.Posture)
	}
}
```

- [ ] **Step 3: Run the integration suite, then hand back**

Run: `make integration IT_DISTRO=alpine`, then `make check`.
Expected: `ok` for `internal/sshread` and `internal/sshwrite`. (The `e2eloose` user is added by lane `e2e`.)

Hand back per Conventions.

**docsDelta:** none.

---

## Round 1 — lane `keypolicy` (Tasks 7–14)

Owns: `internal/authkeys/*`, `internal/testkeys/*`, `internal/config/*`, `internal/apply/{plan.go,serial.go,predicates.go,predicates_test.go,weak_test.go}`, `internal/adopt/*`, `internal/identity/*`, `cmd/sshepherd/{conflicts.go,conflicts_test.go,adopt.go,import.go,editrun.go,run.go}`, `cmd/sshepherd/testdata/help/{adopt,apply,import,revoke,rotate}.golden`. Finding: PRD-10.

### Task 7: key strength and the test keys

**Files:** Create `internal/authkeys/policy.go`, `internal/authkeys/policy_test.go`, `internal/authkeys/testdata/fuzz/FuzzParseLine/seed-dsa`. Modify `internal/authkeys/authkeys.go:27` (`ParseLine`), `internal/testkeys/testkeys.go`.

- [ ] **Step 1: Write the test keys** (`internal/testkeys/testkeys.go`; add `"crypto/rsa"` and `"math/big"` to its imports):

```go
// RSALine returns a parseable ssh-rsa authorized_keys line with a modulus of
// exactly bits bits, derived from seed. The modulus is not a real RSA
// modulus: enough for parsing, fingerprints and the key-strength policy,
// which is all tests need, and free of crypto/rsa's minimum-size checks.
func RSALine(tb testing.TB, seed byte, bits int) string {
	tb.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1)) // #nosec G115 -- bits is a small positive test constant
	n.Or(n, big.NewInt(int64(seed)<<1|1))
	pub, err := ssh.NewPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		tb.Fatalf("testkeys: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// DSALine returns a parseable ssh-dss authorized_keys line derived from
// seed, built from the wire format because crypto/dsa is deprecated. The
// values are not a valid DSA group; x/crypto only checks P's and Q's sizes.
func DSALine(tb testing.TB, seed byte) string {
	tb.Helper()
	blob := ssh.Marshal(struct {
		Name       string
		P, Q, G, Y *big.Int
	}{
		"ssh-dss",
		new(big.Int).Lsh(big.NewInt(1), 1023),
		new(big.Int).Lsh(big.NewInt(1), 159),
		big.NewInt(2),
		big.NewInt(int64(seed) + 3),
	})
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		tb.Fatalf("testkeys: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}
```

- [ ] **Step 2: Write the failing test** (the full file; Task 8 appends the expiry tests):

```go
package authkeys

import (
	"reflect"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func parseOne(t *testing.T, line string) *Key {
	t.Helper()
	k, err := ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("ParseLine(%q) = %v, %v", line, k, err)
	}
	return k
}

func TestStrengthIssue(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		issue string
		bits  int
	}{
		{"ed25519 is fine", testkeys.Line(t, 1), "", 0},
		{"rsa 2048 is fine", testkeys.RSALine(t, 1, 2048), "", 0},
		{"rsa 4096 is fine", testkeys.RSALine(t, 1, 4096), "", 0},
		{"rsa 2047 is weak", testkeys.RSALine(t, 1, 2047), WeakRSAUnder2K, 2047},
		{"rsa 1024 is weak", testkeys.RSALine(t, 1, 1024), WeakRSAUnder2K, 1024},
		{"dsa is weak", testkeys.DSALine(t, 1), WeakDSA, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(tt.line))
			if err != nil {
				t.Fatal(err)
			}
			if issue, bits := StrengthIssue(pub); issue != tt.issue || bits != tt.bits {
				t.Errorf("StrengthIssue = (%q, %d), want (%q, %d)", issue, bits, tt.issue, tt.bits)
			}
			k := parseOne(t, tt.line)
			if k.Weak != tt.issue || k.WeakBits != tt.bits {
				t.Errorf("ParseLine Weak = (%q, %d), want (%q, %d)", k.Weak, k.WeakBits, tt.issue, tt.bits)
			}
		})
	}
}

func TestLinesByFingerprint(t *testing.T) {
	a := parseOne(t, testkeys.Line(t, 1))
	aAgain := parseOne(t, `no-pty `+testkeys.Line(t, 1))
	b := parseOne(t, testkeys.Line(t, 2))
	got := LinesByFingerprint([]Key{*a, *b, *aAgain})
	want := map[string][]Key{a.Fingerprint: {*a, *aAgain}, b.Fingerprint: {*b}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LinesByFingerprint = %+v, want %+v", got, want)
	}
}
```

- [ ] **Step 3: Swap in the fuzz seed.** The corpus already holds 16 entries, CLAUDE.md's cap per target, so remove `internal/authkeys/testdata/fuzz/FuzzParseLine/dde7a120ccdf11af` (its input `"00"` is a second one-token non-key that `e6a5d81a40b57795`'s `"0"` already covers) and create `internal/authkeys/testdata/fuzz/FuzzParseLine/seed-dsa` with exactly these bytes (`testkeys.DSALine(t, 7)` as a Go fuzz seed):

```text
go test fuzz v1
string("ssh-dss AAAAB3NzaC1kc3MAAACBAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFQCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECAAAAAQo=")
```

- [ ] **Step 4: Run to verify it fails**

Run: `GOTOOLCHAIN=go1.27.3 go vet ./internal/authkeys/`
Expected: FAIL, `undefined: StrengthIssue`.

- [ ] **Step 5: Implement.** Create `internal/authkeys/policy.go`:

```go
package authkeys

import (
	"crypto/rsa"

	"golang.org/x/crypto/ssh"
)

// The StrengthIssue verdicts: Key.Weak values, and the JSON key_issues names.
const (
	WeakDSA        = "dsa"
	WeakRSAUnder2K = "rsa_under_2048"
)

// minRSABits is the smallest RSA modulus the key policy accepts.
const minRSABits = 2048

// keyTypeDSA is ssh.KeyAlgoDSA's value, spelled here because x/crypto marks
// the constant deprecated (staticcheck SA1019).
const keyTypeDSA = "ssh-dss"

// StrengthIssue names a key too weak to use: WeakDSA, or WeakRSAUnder2K with
// the modulus size; "" otherwise. A certificate's own type never matches,
// so a certificate line is judged by nothing here.
func StrengthIssue(pub ssh.PublicKey) (issue string, bits int) {
	switch pub.Type() {
	case keyTypeDSA:
		return WeakDSA, 0
	case ssh.KeyAlgoRSA:
		cpk, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return "", 0
		}
		if k, ok := cpk.CryptoPublicKey().(*rsa.PublicKey); ok && k.N.BitLen() < minRSABits {
			return WeakRSAUnder2K, k.N.BitLen()
		}
	}
	return "", 0
}

// LinesByFingerprint indexes parsed lines by fingerprint, in file order. Diff
// keeps only the first line per fingerprint; sshd reads them all.
func LinesByFingerprint(keys []Key) map[string][]Key {
	m := make(map[string][]Key, len(keys))
	for _, k := range keys {
		m[k.Fingerprint] = append(m[k.Fingerprint], k)
	}
	return m
}
```

In `authkeys.go`, add to the `Key` struct:

```go
	// Weak is StrengthIssue's verdict ("" for an acceptable key) and WeakBits
	// the RSA modulus size it found, set by ParseLine so the line is parsed once.
	Weak     string
	WeakBits int
```

and in `ParseLine`, build the return value with:

```go
	weak, bits := StrengthIssue(pub)
	return &Key{
		Weak:        weak,
		WeakBits:    bits,
		Type:        pub.Type(),
```

- [ ] **Step 6: Run to verify it passes**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/authkeys/ -run 'TestStrengthIssue|TestLinesByFingerprint'`
Expected: PASS.

**docsDelta:** none.

### Task 8: expiry helpers

**Files:** Modify `internal/authkeys/options.go`.

- [ ] **Step 1: Write the failing tests.** Append to `internal/authkeys/policy_test.go` (add `"time"` to its imports):

```go
func TestExpired(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		opts []string
		want bool
	}{
		{"no clause", []string{"no-pty"}, false},
		{"8 digits, passed", []string{`expiry-time="20260101"`}, true},
		{"8 digits, future", []string{`expiry-time="20270101"`}, false},
		{"12 digits, passed", []string{`expiry-time="202606151159"`}, true},
		{"14 digits, passed", []string{`expiry-time="20260615115959"`}, true},
		{"exactly now counts", []string{`expiry-time="20260615120000"`}, true},
		{"Z suffix, future", []string{`expiry-time="20260615130000Z"`}, false},
		{"UTC suffix, passed", []string{`expiry-time="20260615110000UTC"`}, true},
		{"case-insensitive name", []string{`Expiry-Time="20260101"`}, true},
		{"only the earliest of a repeated clause has passed", []string{`expiry-time="20270101"`, `expiry-time="20260101"`}, true},
		{"malformed clause is skipped", []string{`expiry-time="garbage"`}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Expired(tt.opts, now, time.UTC); got != tt.want {
				t.Errorf("Expired = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEarliestExpiry(t *testing.T) {
	opt, when, ok := EarliestExpiry([]string{`expiry-time="20270101"`, "no-pty", `expiry-time="20260101"`}, time.UTC)
	if !ok || opt != `expiry-time="20260101"` || when.Year() != 2026 {
		t.Errorf("EarliestExpiry = %q, %v, %v", opt, when, ok)
	}
	if _, _, ok := EarliestExpiry([]string{"no-pty"}, time.UTC); ok {
		t.Error("EarliestExpiry found a clause in a line that has none")
	}
}
```

Run: `GOTOOLCHAIN=go1.27.3 go vet ./internal/authkeys/`
Expected: FAIL, `undefined: Expired` and `undefined: EarliestExpiry`.

- [ ] **Step 2: Implement.** Add to `internal/authkeys/options.go`, before `validExpiry`:

```go
// EarliestExpiry returns the earliest parseable expiry-time="…" clause of a
// line (sshd honours the earliest of a repeated clause), verbatim and as a
// time; ok is false when the line carries none. Malformed clauses are
// skipped: IgnoredBySSHD and manifest validation own that verdict.
func EarliestExpiry(opts []string, local *time.Location) (opt string, t time.Time, ok bool) {
	for _, o := range opts {
		if nameOf(o) != "expiry-time" {
			continue
		}
		when, err := ExpiryTime(o, local)
		if err == nil && (!ok || when.Before(t)) {
			opt, t, ok = o, when, true
		}
	}
	return opt, t, ok
}

// Expired reports whether a line's expiry-time has been reached: true when
// any clause is at or before now.
func Expired(opts []string, now time.Time, local *time.Location) bool {
	_, t, ok := EarliestExpiry(opts, local)
	return ok && !t.After(now)
}
```

- [ ] **Step 3: Run to verify they pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/authkeys/`
Expected: PASS.

**docsDelta:** none.

### Task 9: weak keys and passed expiry in the manifest

**Files:** Create `internal/config/policy.go`, `internal/config/policy_test.go`. Modify `internal/config/revoked.go:268` (`computeConflicts`, the kind constants, `Conflict`'s doc comment), `internal/config/config.go:96` (`Parse`, `Config`).

- [ ] **Step 1: Write the failing test:**

```go
package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fpOfLine is the line's SHA256 fingerprint.
func fpOfLine(t *testing.T, line string) string {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("ParseLine: %v", err)
	}
	return k.Fingerprint
}

// policyManifest: user old holds line on a one-server fleet; grant, when
// set, is old's access entry.
func policyManifest(t *testing.T, line, grant string) string {
	t.Helper()
	return `users:
  - {name: old, keys: ["` + line + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
` + grant
}

const grantOld = "access:\n  - {user: old, servers: [web-1]}\n"

func TestWeakKeyGrantedIsAConflict(t *testing.T) {
	dsa := testkeys.DSALine(t, 1)
	fp := fpOfLine(t, dsa)
	cfg, err := Parse([]byte(policyManifest(t, dsa, grantOld)))
	if err != nil {
		t.Fatalf("a weak key must not be a load error: %v", err)
	}
	cs := cfg.Conflicts()
	if len(cs) != 1 || cs[0].Kind != ConflictWeakKey || cs[0].User != "old" || cs[0].Fingerprint != fp || !slices.Equal(cs[0].Servers, []string{"web-1"}) {
		t.Fatalf("conflicts = %+v", cs)
	}
	want := `user "old" key 1 (` + fp + `): dsa keys are not allowed: replace it with 'sshepherd rotate' or remove it with 'sshepherd revoke --key'`
	if cs[0].Message != want {
		t.Errorf("message:\n got %s\nwant %s", cs[0].Message, want)
	}
}

func TestWeakRSAMessageNamesTheSize(t *testing.T) {
	cfg, err := Parse([]byte(policyManifest(t, testkeys.RSALine(t, 1, 1024), grantOld)))
	if err != nil {
		t.Fatal(err)
	}
	if cs := cfg.Conflicts(); len(cs) != 1 || !strings.Contains(cs[0].Message, "rsa keys under 2048 bits are not allowed (1024)") {
		t.Fatalf("conflicts = %+v", cs)
	}
}

func TestWeakOperatorNamesEveryServer(t *testing.T) {
	cfg, err := Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.DSALine(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cs := cfg.Conflicts(); len(cs) != 1 || !slices.Equal(cs[0].Servers, []string{"web-1", "web-2"}) {
		t.Fatalf("conflicts = %+v", cs)
	}
}

func TestWeakKeyUngrantedIsAWarning(t *testing.T) {
	dsa := testkeys.DSALine(t, 1)
	fp := fpOfLine(t, dsa)
	cfg, err := Parse([]byte(policyManifest(t, dsa, "")))
	if err != nil {
		t.Fatal(err)
	}
	if cs := cfg.Conflicts(); len(cs) != 0 {
		t.Fatalf("an ungranted weak key renders nowhere: conflicts = %+v", cs)
	}
	want := `user "old" key 1 (` + fp + `): dsa key, granted on no server`
	if !slices.Contains(cfg.Warnings, want) {
		t.Errorf("warnings = %q, want %q", cfg.Warnings, want)
	}
	if ws := cfg.WeakKeys(); len(ws) != 1 || ws[0].Fingerprint != fp || len(ws[0].Servers) != 0 || ws[0].Servers == nil {
		t.Errorf("WeakKeys = %+v, want the ungranted key, Servers empty and non-nil", ws)
	}
}

func TestStrongKeyHasNoPolicyFinding(t *testing.T) {
	cfg, err := Parse([]byte(policyManifest(t, testkeys.Line(t, 1), grantOld)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Conflicts()) != 0 || len(cfg.WeakKeys()) != 0 || len(cfg.Warnings) != 0 {
		t.Errorf("conflicts %+v, weak %+v, warnings %q", cfg.Conflicts(), cfg.WeakKeys(), cfg.Warnings)
	}
}

// TestWeakAndRevokedYieldTwoConflicts: a key in both lists is one conflict
// per kind, revoked kinds first.
func TestWeakAndRevokedYieldTwoConflicts(t *testing.T) {
	dsa := testkeys.DSALine(t, 1)
	fp := fpOfLine(t, dsa)
	cfg, err := Parse([]byte(policyManifest(t, dsa, grantOld) + "revoked:\n  - {fingerprint: " + fp + ", user: old, date: 2026-11-08}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cs := cfg.Conflicts()
	if len(cs) != 2 || cs[0].Kind != ConflictRevokedKey || cs[1].Kind != ConflictWeakKey {
		t.Fatalf("conflicts = %+v", cs)
	}
}

func pinNow(t *testing.T, when time.Time) {
	t.Helper()
	orig := now
	now = func() time.Time { return when }
	t.Cleanup(func() { now = orig })
}

func TestPassedExpiryWarns(t *testing.T) {
	pinNow(t, time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))
	line := `expiry-time=\"20200101\" ` + testkeys.Line(t, 1) // escaped: the line sits in a YAML double-quoted scalar
	cfg, err := Parse([]byte(policyManifest(t, line, grantOld)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := `user "old" key 1: expiry-time="20200101" has passed; sshd no longer accepts this key`
	if !slices.Contains(cfg.Warnings, want) {
		t.Errorf("warnings = %q, want %q", cfg.Warnings, want)
	}
	if len(cfg.Conflicts()) != 0 {
		t.Errorf("a passed expiry is a warning only: conflicts = %+v", cfg.Conflicts())
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOTOOLCHAIN=go1.27.3 go vet ./internal/config/`
Expected: FAIL, `undefined: ConflictWeakKey`.

- [ ] **Step 3: Implement.** Create `internal/config/policy.go`:

```go
package config

import (
	"fmt"
	"slices"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// now is the clock of the passed-expiry warning, a seam so tests pin it.
var now = time.Now

// WeakKey is a manifest key that fails the strength policy
// (authkeys.StrengthIssue), whether or not it is granted anywhere.
type WeakKey struct {
	User        string
	Index       int // 1-based position in the user's keys
	Fingerprint string
	Issue       string // authkeys.WeakDSA or authkeys.WeakRSAUnder2K
	Bits        int
	Servers     []string // every server the key renders on; never nil
	Message     string   // the conflict text (what is wrong, then the way out)
}

// WeakKeys lists every weak key in the manifest, in users order: granted
// ones are also policy conflicts, ungranted ones load warnings. The save
// rule (does this write add a weak key?) reads this, so an ungranted weak
// key cannot slip into a saved manifest unnoticed.
func (c *Config) WeakKeys() []WeakKey { return slices.Clone(c.weak) }

// weakConflicts records every weak key and returns the conflicts of the
// ones rendered somewhere. A weak key on a user with no grants renders
// nowhere, so no human must act now (D28): a load warning, not a conflict.
func (c *Config) weakConflicts() []Conflict {
	var out []Conflict
	c.weak = nil
	for _, u := range c.Users {
		for i, k := range c.keysByUser[u.Name] {
			if k.Weak == "" {
				continue
			}
			w := WeakKey{User: u.Name, Index: i + 1, Fingerprint: k.Fingerprint, Issue: k.Weak, Bits: k.WeakBits,
				Servers: c.serversRendering(u), Message: weakMessage(u.Name, i+1, k)}
			c.weak = append(c.weak, w)
			if len(w.Servers) == 0 {
				c.Warnings = append(c.Warnings, fmt.Sprintf("user %q key %d (%s): %s key, granted on no server", u.Name, i+1, k.Fingerprint, k.Weak))
				continue
			}
			out = append(out, Conflict{Kind: ConflictWeakKey, User: u.Name, Fingerprint: k.Fingerprint, Servers: w.Servers, Message: w.Message})
		}
	}
	return out
}

func weakMessage(user string, index int, k authkeys.Key) string {
	what := "dsa keys are not allowed"
	if k.Weak == authkeys.WeakRSAUnder2K {
		what = fmt.Sprintf("rsa keys under 2048 bits are not allowed (%d)", k.WeakBits)
	}
	return fmt.Sprintf("user %q key %d (%s): %s: replace it with 'sshepherd rotate' or remove it with 'sshepherd revoke --key'",
		user, index, k.Fingerprint, what)
}

// warnExpired adds one load warning per desired key whose expiry-time has
// passed: sshd no longer accepts that line, but the manifest stays valid.
func (c *Config) warnExpired() {
	for _, u := range c.Users {
		for i, k := range c.keysByUser[u.Name] {
			if authkeys.Expired(k.Options, now(), time.Local) {
				opt, _, _ := authkeys.EarliestExpiry(k.Options, time.Local)
				c.Warnings = append(c.Warnings, fmt.Sprintf("user %q key %d: %s has passed; sshd no longer accepts this key", u.Name, i+1, opt))
			}
		}
	}
}
```

In `internal/config/revoked.go`, add `ConflictWeakKey = "weak_key"` to the conflict-kind constants, change `computeConflicts`' last line to `return append(out, c.weakConflicts()...)`, and replace `Conflict`'s doc comment with:

```go
// Conflict is a manifest that breaks its own policy: a tombstoned key still
// listed, a grant over an access tombstone, or a weak key granted on a
// server. It is not a load error (D29): audit reports it critical, apply
// refuses Servers, and a saving command refuses per conflictRefusal in
// cmd/sshepherd. The json tags are the wire shape of policy_conflicts.
```

In `internal/config/config.go`, add to `Config`:

```go
	weak       []WeakKey                 // every key failing the strength policy, granted or not
```

and in `Parse`, after `c.conflicts = c.computeConflicts()`:

```go
	c.warnExpired()
```

- [ ] **Step 4: Run to verify it passes**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/config/`
Expected: PASS.

**docsDelta (README "Validation rules", new bullets; "The manifest → Operator users", new paragraph):**

```markdown
- A weak key (DSA, or RSA under 2048 bits) that renders on at least one server is a policy conflict, not a load error: `audit` reports it critical (exit 2) and `apply` refuses those servers. A weak key granted on no server is a load warning. A desired key whose `expiry-time` has passed is a load warning.
- OpenSSH 9.8 and later build sshd without DSA by default, so a DSA key usually cannot log in on a current server anyway; the rule makes that visible instead of silent.
- **On upgrade:** a manifest holding a weak key keeps loading, but every server granting that key goes critical, so a scheduled `audit` that passed before now exits 2 and `apply` skips those servers. `rotate` and `revoke --key` are the way out and always save.
```

```markdown
A weak operator key freezes every grant on every server: apply refuses each one until `rotate` replaces it. Removals still land. A present operator key that cannot log in (a `cert-authority` or `principals=` line the manifest does not declare, a passed `expiry-time`, or every line ignored by sshd) is critical like a missing one, even when the manifest declares the expiry.
```

### Task 10: apply refuses, with the removal-only exception

**Files:** Modify `internal/apply/serial.go:138` (`conflictRefusal`), `internal/apply/plan.go:87,199` (`ServerPlan`, `planOne`), `internal/apply/predicates.go:26` (`NothingCanLand`). Tests: `internal/apply/weak_test.go` (new), `internal/apply/predicates_test.go`.

- [ ] **Step 1: Write the failing test:**

```go
package apply

import (
	"context"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// weakCfg: op (k1, operator); alice (k2) and old (a DSA key) -> web-1; web-2
// holds only the operator.
func weakCfg(t *testing.T) (*config.Config, string) {
	t.Helper()
	dsa := testkeys.DSALine(t, 7)
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: old, keys: ["` + dsa + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: old, servers: [web-1]}
`))
	if err != nil {
		t.Fatalf("weakCfg: %v", err)
	}
	return cfg, dsa
}

func planWeak(t *testing.T, cfg *config.Config, content string) ServerPlan {
	t.Helper()
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(content)}, "web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{})
	if err != nil {
		t.Fatalf("BuildWith: %v", err)
	}
	return planFor(t, plans, "web-1")
}

func TestWeakKeyServerIsRefused(t *testing.T) {
	cfg, _ := weakCfg(t)
	p := planWeak(t, cfg, testkeys.Line(t, 1)+"\n") // alice and old are missing: a grant
	if p.Class != ClassRefused || !p.WeakRefused || !strings.Contains(p.Refusal, "dsa keys are not allowed") {
		t.Fatalf("plan = %+v", p)
	}
}

// TestWeakKeyRemovalOnlyWriteProceeds (OP4): every rendered key is present
// and bob's key (k9) is removed, so the write grants nothing and proceeds.
func TestWeakKeyRemovalOnlyWriteProceeds(t *testing.T) {
	cfg, dsa := weakCfg(t)
	p := planWeak(t, cfg, testkeys.Line(t, 1)+"\n"+testkeys.Line(t, 2)+"\n"+dsa+"\n"+testkeys.Line(t, 9)+"\n")
	if p.Class != ClassChange || p.WeakRefused {
		t.Fatalf("class = %s, weakRefused = %v (refusal %q), want a change", p.Class, p.WeakRefused, p.Refusal)
	}
}

// TestWeakKeyConvergedServerStaysRefused: nothing to remove, so the
// exception does not apply and the server is refused (exit 1).
func TestWeakKeyConvergedServerStaysRefused(t *testing.T) {
	cfg, dsa := weakCfg(t)
	p := planWeak(t, cfg, testkeys.Line(t, 1)+"\n"+testkeys.Line(t, 2)+"\n"+dsa+"\n")
	if p.Class != ClassRefused || !p.WeakRefused {
		t.Fatalf("class = %s, weakRefused = %v, want a weak-key refusal", p.Class, p.WeakRefused)
	}
}

// TestRevokedConflictHasNoRemovalException pins P04's behaviour: a server
// named by a revoked-kind conflict is refused even for a removal-only write.
// It passes before this task's code; the exception must not reach it.
func TestRevokedConflictHasNoRemovalException(t *testing.T) {
	line := testkeys.Line(t, 1)
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + line + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
revoked:
  - {fingerprint: ` + fp(t, 1) + `, user: op, date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(line + "\n" + testkeys.Line(t, 9) + "\n")}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p := planFor(t, plans, "web-1"); p.Class != ClassRefused {
		t.Fatalf("class = %s, want refused", p.Class)
	}
}

// TestWeakAndRevokedKeyHasNoRemovalException: a server named by both kinds is
// refused on a removal-only write, and the refusal is not a weak-key one, so
// it still withholds an edit's save.
func TestWeakAndRevokedKeyHasNoRemovalException(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(dsa)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: old, keys: ["` + dsa + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: old, servers: [web-1]}
revoked:
  - {fingerprint: ` + k.Fingerprint + `, user: old, date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + dsa + "\n" + testkeys.Line(t, 9) + "\n")}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p := planFor(t, plans, "web-1"); p.Class != ClassRefused || p.WeakRefused {
		t.Fatalf("class = %s, weakRefused = %v, want a revoked-kind refusal", p.Class, p.WeakRefused)
	}
}

// TestWeakKeyExceptionKeepsParseRefusal: the removal-only exception hands
// the plan to the ordinary checks; it does not bypass them.
func TestWeakKeyExceptionKeepsParseRefusal(t *testing.T) {
	cfg, dsa := weakCfg(t)
	p := planWeak(t, cfg, testkeys.Line(t, 1)+"\n"+testkeys.Line(t, 2)+"\n"+dsa+"\n"+testkeys.Line(t, 9)+"\nnot a key\n")
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "unparseable") {
		t.Fatalf("plan = %+v", p)
	}
}
```

Add these rows to the existing `TestNothingCanLand` table in `internal/apply/predicates_test.go`:

```go
		{"only weak-key refusals do not withhold the save", []ServerPlan{{Class: ClassRefused, WeakRefused: true}, {Class: ClassRefused, WeakRefused: true}}, false},
		{"a weak-key refusal beside another refusal still withholds", []ServerPlan{{Class: ClassRefused, WeakRefused: true}, p(ClassRefused)}, true},
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/ -run 'Weak|RevokedConflict|TestNothingCanLand'`
Expected: FAIL to build: `p.WeakRefused undefined` (unknown field `WeakRefused`). Once the field exists, `TestWeakKeyRemovalOnlyWriteProceeds` reports class `refused`.

- [ ] **Step 3: Implement.** In `internal/apply/serial.go`, replace `conflictRefusal` (re-read it first; P08 may have touched this file):

```go
// conflictRefusal is the refusal text for a server a revoked-kind policy
// conflict names (D29): each conflict's message, joined; "" when none names
// it. Weak-key conflicts have their own rule, weakRefusal.
func conflictRefusal(cfg *config.Config, server string) string {
	return conflictMessages(cfg, server, func(kind string) bool { return kind != config.ConflictWeakKey })
}

// weakRefusal is the refusal text for a server a weak-key conflict names, ""
// when none does. Unlike the revoked kinds it has one exception: a write
// that grants nothing and removes at least one key cannot install or widen
// the weak key, and without it an unrelated revoke would save but leave the
// revoked key installed on every server granting a weak key (OP4).
func weakRefusal(cfg *config.Config, r audit.ServerResult, entries []authkeys.RenderEntry) string {
	msgs := conflictMessages(cfg, r.Server.Name, func(kind string) bool { return kind == config.ConflictWeakKey })
	if msgs == "" || (removalOnly(r, entries) && len(r.Diff.Unauthorized) > 0) {
		return ""
	}
	return msgs
}

func conflictMessages(cfg *config.Config, server string, match func(kind string) bool) string {
	var msgs []string
	for _, c := range cfg.Conflicts() {
		if match(c.Kind) && slices.Contains(c.Servers, server) {
			msgs = append(msgs, c.Message)
		}
	}
	return strings.Join(msgs, "; ")
}
```

In `planOne` (`internal/apply/plan.go`), replace the conflict comment with:

```go
	// A revoked-kind policy conflict names this server (D29): nothing is
	// written here — a revoked key is never installed, a revoked grant never
	// restored. The weak-key kind is checked below, once entries exist.
```

and immediately after the `len(entries) == 0` block insert:

```go
	if refusal := weakRefusal(cfg, r, entries); refusal != "" {
		p.Class, p.Refusal, p.WeakRefused = ClassRefused, refusal, true
		return p, nil
	}
```

Add to `ServerPlan`, after `Refusal`:

```go
	// WeakRefused marks a refusal by a weak-key conflict alone. It never
	// withholds an edit's save (OP4): an unrelated edit and the weak key's
	// own remediation save, and the push is refused at this server.
	WeakRefused bool
```

In `internal/apply/predicates.go`, replace `NothingCanLand` and its doc comment:

```go
// NothingCanLand reports that no affected server is change-planned or
// converged, and at least one is refused for a reason other than a weak-key
// conflict. Unreachable servers can converge later, and a weak-key refusal
// must not withhold the save that remediates it (OP4).
func NothingCanLand(plans []ServerPlan) bool {
	refused := false
	for _, p := range plans {
		switch p.Class {
		case ClassChange, ClassConverged:
			return false
		case ClassRefused:
			refused = refused || !p.WeakRefused
		}
	}
	return refused
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply/`
Expected: PASS.

**docsDelta (README "`sshepherd apply`", new paragraph under the refusal list; "Exit codes" row `1`):**

```markdown
A server that grants a weak key (DSA, RSA under 2048 bits) is refused and the rest of the plan proceeds, exit 1, except a write that grants nothing and removes at least one key: it cannot install or widen the weak key, so it proceeds. A server already holding exactly its keys stays refused until the weak key is gone. A refusal for a weak key never stops `revoke` or `rotate` from saving their edit.
```

In the "Exit codes" table, `apply` cell of row `1`, add "a granted weak key" to the refused list.

### Task 11: the save rule refuses only an added weak key

**Files:** Modify `cmd/sshepherd/conflicts.go` (`conflictRefusal`, new `formerManifest`), `cmd/sshepherd/adopt.go` (`conflictRefusal` call), `cmd/sshepherd/import.go` (call), `cmd/sshepherd/editrun.go` (`editPrelude`'s call), `cmd/sshepherd/run.go` (`exitCodesWrite`, `exitCodesAdopt`, `exitCodesImport`), help goldens. Test: `cmd/sshepherd/conflicts_test.go`.

- [ ] **Step 1: Write the failing tests.** Append to `cmd/sshepherd/conflicts_test.go` (add the import `internal/config`; Tasks 13 and 14 add the rest):

```go
// parseManifest parses a test manifest or fails.
func parseManifest(t *testing.T, y string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cfg
}

// weakAndGrant: alice holds line, granted on web-1.
func weakAndGrant(line string) string {
	return "users:\n  - {name: alice, keys: [\"" + line + "\"]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n"
}

// TestSaveRefusedWhenAddingWeakKey (OP4): a save that adds a weak key is
// refused, even when that key is granted nowhere.
func TestSaveRefusedWhenAddingWeakKey(t *testing.T) {
	strong, weak := testkeys.Line(t, 1), testkeys.DSALine(t, 7)
	former := parseManifest(t, weakAndGrant(strong))
	granted := parseManifest(t, weakAndGrant(weak))
	ungranted := parseManifest(t, "users:\n  - {name: alice, keys: [\""+weak+"\"]}\n")
	for name, saved := range map[string]*config.Config{"granted": granted, "ungranted": ungranted} {
		t.Run(name, func(t *testing.T) {
			err := conflictRefusal(former, saved)
			if err == nil || !strings.Contains(err.Error(), "refusing to write the manifest — it would add a weak key: ") ||
				!strings.Contains(err.Error(), "dsa keys are not allowed") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if err := conflictRefusal(nil, granted); err == nil {
		t.Error("a new manifest holding a weak key must be refused too")
	}
}

// TestRevokeUnrelatedSavesWithWeakKeyPresent (OP4): a weak key the manifest
// already holds never blocks an unrelated save, nor its own removal.
func TestRevokeUnrelatedSavesWithWeakKeyPresent(t *testing.T) {
	weak := testkeys.DSALine(t, 7)
	former := parseManifest(t, weakAndGrant(weak))
	if err := conflictRefusal(former, parseManifest(t, weakAndGrant(weak))); err != nil {
		t.Errorf("unrelated save refused: %v", err)
	}
	if err := conflictRefusal(former, parseManifest(t, weakAndGrant(testkeys.Line(t, 1)))); err != nil {
		t.Errorf("the remediation (rotate away from the weak key) refused: %v", err)
	}
}

// TestRevokedConflictStillRefusesSave pins P04's rule, unchanged for the
// revoked kinds whatever the former manifest held; it passes as soon as the
// new signature compiles.
func TestRevokedConflictStillRefusesSave(t *testing.T) {
	line := testkeys.Line(t, 1)
	y := weakAndGrant(line) + "revoked:\n  - {fingerprint: " + fpOf(t, 1) + ", user: alice, date: 2026-11-08}\n"
	if err := conflictRefusal(parseManifest(t, y), parseManifest(t, y)); err == nil || !strings.Contains(err.Error(), "it would keep 1 policy conflict") {
		t.Fatalf("err = %v", err)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'WeakKey|TestRevokedConflictStillRefusesSave'`
Expected: FAIL, `too many arguments in call to conflictRefusal`.

- [ ] **Step 3: Implement.** Replace `cmd/sshepherd/conflicts.go`'s body from `conflictRefusal` on:

```go
// conflictRefusal is the save refusal of every command that writes the
// manifest: revoke, rotate, adopt (both modes), import --merge (D29). former
// is the manifest as loaded (nil for a new one), saved the manifest as it
// would be written. A revoked-kind conflict refuses while it remains (exit
// 3, nothing written), so 'sshepherd revoke --key FP' of a revoked key still
// listed is the natural fix. A weak key refuses only when the save adds one
// (OP4): an unrelated revoke saves while another user holds a DSA key, and
// the weak key's own rotate or revoke always saves.
func conflictRefusal(former, saved *config.Config) error {
	var msgs []string
	for _, c := range saved.Conflicts() {
		if c.Kind != config.ConflictWeakKey {
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

// formerManifest is the manifest m loaded, for the save rule; nil when m
// holds none (a plain import: the output is a new manifest).
func formerManifest(m manifestTarget) *config.Config {
	cfg, err := config.Parse(m.Loaded)
	if err != nil || len(m.Loaded) == 0 {
		return nil
	}
	return cfg
}
```

Update the call sites: `cmd/sshepherd/adopt.go`: `if err := conflictRefusal(cfg, saved); err != nil {`; `cmd/sshepherd/import.go`: `if err := conflictRefusal(formerManifest(m), saved); err != nil {`; `cmd/sshepherd/editrun.go` (`editPrelude`): `if err := conflictRefusal(ep.former, ep.edited); err != nil {`.

Update the footers in `cmd/sshepherd/run.go`: in `exitCodesWrite`, the `3` row reads `that would keep a policy conflict or add a weak key, a failed serial`, wrapped as:

```go
     that would keep a policy conflict or add a weak key, a failed serial
     save, or refused before anything was saved or written`
```

In `exitCodesAdopt` and `exitCodesImport`:

```go
     would keep a policy conflict or add a weak key, --partial with no server
     read, interrupted`
```
```go
     manifest that would keep a policy conflict or add a weak key`
```

(Keep P08's edits to the `exitCodesWrite` `2` row; Task 20 extends it. Only the `3` row changes here.)

- [ ] **Step 4: Regenerate the help goldens and run.** Apply this lane's footer `docsDelta` below to the worktree's `README.md` first.

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestHelp' -update && GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/`
Expected: PASS; read the five regenerated help goldens, each differs only in its `3` row.

**docsDelta (README "Exit codes" table row `3` cell "Tool error", and the `--help` samples for `apply`/`revoke`/`rotate`, `adopt`, `import`, copied from the regenerated goldens):**

```markdown
`3` for saving commands additionally covers a save that would **add** a DSA or RSA<2048 key; unrelated saves and a weak key's own `rotate`/`revoke --key` always save.
```

Replace in the README's three `console` samples the `3` rows with the text from `cmd/sshepherd/testdata/help/{apply,adopt,import}.golden`.

**docsDelta (README "`sshepherd revoke`" and "`sshepherd rotate`", the same paragraph in both):**

```markdown
A save that would **add** a weak key (DSA, or RSA under 2048 bits) is refused, exit `3`, with nothing saved or written. Any other save goes through while the manifest still holds a weak key: an unrelated edit is never blocked, and a weak key's own `rotate` or `revoke --key` always saves. A server that still grants a weak key after the edit is refused in the push (exit `1`), and the edit is saved anyway.
```

### Task 12: adopt skips weak keys

**Files:** Modify `internal/adopt/adopt.go:68` (`Build`), `linesByFingerprint`. Test: `internal/adopt/adopt_test.go`.

- [ ] **Step 1: Write the failing tests** (append; add `"slices"` to the imports):

```go
// TestBuildSkipsWeakKey: an unknown 1024-bit RSA key is skipped with a
// warning, not adopted and not an Issue (the strict gate does not move).
func TestBuildSkipsWeakKey(t *testing.T) {
	line := testkeys.RSALine(t, 7, 1024)
	k, err := authkeys.ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(line + "\n")}}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 0 || len(p.Issues) != 0 {
		t.Fatalf("plan = %+v, want no new user and no issue", p)
	}
	want := "key " + k.Fingerprint + " on web-1: rsa_under_2048 key not adopted"
	if !slices.Contains(p.Warnings, want) {
		t.Errorf("warnings = %q, want %q", p.Warnings, want)
	}
}

// TestBuildDoesNotExtendWeakOwnerKey: a known owner's weak key found on one
// more server is not granted there.
func TestBuildDoesNotExtendWeakOwnerKey(t *testing.T) {
	line := testkeys.DSALine(t, 7)
	cfg := parseConfig(t, `users:
  - {name: old, keys: ["`+line+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: old, servers: [web-1]}
`)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(line + "\n")}, "web-2": {Content: []byte(line + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 {
		t.Errorf("extensions = %+v, want none", p.Extensions)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "dsa key not adopted") {
		t.Errorf("warnings = %q", p.Warnings)
	}
}

// TestBuildRevokedWeakKeyWarnsOnce: tombstones run first, so a key that is
// both revoked and weak gets only the REVOKED warning.
func TestBuildRevokedWeakKeyWarnsOnce(t *testing.T) {
	line := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	cfg := parseConfig(t, `servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
revoked:
  - {fingerprint: `+k.Fingerprint+`, user: old, date: 2026-11-08}
`)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(line + "\n")}}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "REVOKED") {
		t.Errorf("warnings = %q, want only the REVOKED one", p.Warnings)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/adopt/ -run 'Weak'`
Expected: FAIL: the weak key is adopted.

- [ ] **Step 3: Implement.** In `Build`, replace the opening revoked check inside the loop over `r.Diff.Unauthorized` with:

```go
			// Revocation memory first (D2a): a tombstoned key is never
			// adopted — not even as an Issue that would move adopt's exit
			// code — whatever its lines look like. A weak key likewise: a
			// warning, and it is neither adopted nor granted to more servers.
			if w, skip := skipKey(cfg, r.Server.Name, first); skip {
				p.Warnings = append(p.Warnings, w)
				continue
			}
```

Add the helper next to `revokedWarning`, and make `linesByFingerprint` call the shared indexer:

```go
// skipKey reports a key adopt never takes: one the manifest's revoked: list
// remembers (first, so a key that is both warns only as REVOKED), or a weak
// one (emitting it would produce a manifest with a policy conflict).
func skipKey(cfg *config.Config, server string, k authkeys.Key) (string, bool) {
	if w, revoked := revokedWarning(cfg, server, k.Fingerprint); revoked {
		return w, true
	}
	if k.Weak != "" {
		return fmt.Sprintf("key %s on %s: %s key not adopted", k.Fingerprint, server, k.Weak), true
	}
	return "", false
}

// linesByFingerprint indexes every parsed line of a server's file by
// fingerprint, in file order. audit's Diff keeps only the first line per
// fingerprint; sshd reads them all.
func linesByFingerprint(content []byte) map[string][]authkeys.Key {
	keys, _ := authkeys.ParseFile(content) // parse errors are already Issues (r.ParseErrs)
	return authkeys.LinesByFingerprint(keys)
}
```

- [ ] **Step 4: Run to verify they pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/adopt/`
Expected: PASS.

**docsDelta (README "`sshepherd adopt`"):**

```markdown
A weak on-server key (DSA, RSA under 2048 bits) is skipped with a warning in both modes and never granted to more servers; audit keeps showing it as `UNAUTHORIZED`.
```

### Task 13: import skips weak identities; `--operator` refuses

**Files:** Modify `internal/identity/identity.go:208` (`grant`), `:284` (`MarkOperators`). Tests: `internal/identity/identity_test.go`, `cmd/sshepherd/conflicts_test.go`.

- [ ] **Step 1: Write the failing tests.** Append to `internal/identity/identity_test.go` (add `"slices"`):

```go
// writeWeakPub writes a DSA public key as dir/old.pub and returns the
// private-key path ssh config would name.
func writeWeakPub(t *testing.T, dir string) string {
	t.Helper()
	key := filepath.Join(dir, "old")
	if err := os.WriteFile(key+".pub", []byte(testkeys.DSALine(t, 7)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return key
}

// TestResolveSkipsWeakIdentity (OP5): a weak .pub is skipped with a warning,
// in the one code path plain import and --merge share.
func TestResolveSkipsWeakIdentity(t *testing.T) {
	key := writeWeakPub(t, t.TempDir())
	r := Resolver{Home: "/home/j", LocalUser: "javad"}
	users, warns := r.Resolve([]sshcfg.Host{{Alias: "web", HostName: "web", User: "deploy", Identities: []string{key}}})
	if len(users) != 0 {
		t.Fatalf("users = %+v, want the weak identity skipped", users)
	}
	want := "identity " + key + ".pub: dsa key not imported"
	if !slices.Contains(warns, want) {
		t.Errorf("warnings = %q, want %q", warns, want)
	}
}

// TestMarkOperatorsRefusesWeakKey: --operator names a key explicitly, so a
// weak one is an error rather than a skip.
func TestMarkOperatorsRefusesWeakKey(t *testing.T) {
	key := writeWeakPub(t, t.TempDir())
	r := Resolver{Home: "/home/j", LocalUser: "javad"}
	_, err := r.MarkOperators(nil, []string{key})
	if err == nil || !strings.Contains(err.Error(), "weak key (dsa)") {
		t.Fatalf("err = %v, want a weak-key refusal", err)
	}
}
```

Append to `cmd/sshepherd/conflicts_test.go` (add the imports `"os"` and `"path/filepath"`):

```go
// TestImportSkipsWeakIdentity (OP5): plain import and --merge both skip a
// weak .pub with a warning and still exit 0.
func TestImportSkipsWeakIdentity(t *testing.T) {
	for _, merge := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "merge"}[merge], func(t *testing.T) {
			home := hermeticHome(t)
			key := filepath.Join(home, "old")
			if err := os.WriteFile(key+".pub", []byte(testkeys.DSALine(t, 7)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"import", writeSSHConfig(t, "Host web-1\n  User deploy\n  IdentityFile "+key+"\n")}
			if merge {
				args = append(args, "--merge", writeConfig(t, "users: []\nservers: []\naccess: []\n"))
			}
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), "dsa key not imported") {
				t.Errorf("stderr lacks the warning: %s", errBuf.String())
			}
			if strings.Contains(out.String(), "ssh-dss") {
				t.Errorf("the weak key reached the manifest:\n%s", out.String())
			}
		})
	}
}

// TestImportOperatorWeakKeyExits3: --operator naming a weak key stops.
func TestImportOperatorWeakKeyExits3(t *testing.T) {
	home := hermeticHome(t)
	key := filepath.Join(home, "old")
	if err := os.WriteFile(key+".pub", []byte(testkeys.DSALine(t, 7)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := run([]string{"import", writeSSHConfig(t, "Host web-1\n  User deploy\n"), "--operator", key}, &out, &errBuf)
	if code != 3 || !strings.Contains(errBuf.String(), "weak key (dsa)") {
		t.Fatalf("exit = %d, stderr %s", code, errBuf.String())
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/identity/ ./cmd/sshepherd/ -run 'Weak'`
Expected: FAIL: the weak key is imported.

- [ ] **Step 3: Implement.** In `grant`, before the `RenderTextIssue` check:

```go
	if k.Weak != "" {
		// Importing it would produce a manifest with a policy conflict.
		res.failed[c.path] = true
		shown, _ := pubPaths(c.source) // as written, so a ~ path reads as the user spelled it
		res.warnf("identity %s: %s key not imported", shown, k.Weak)
		return false
	}
```

In `MarkOperators`, before the `RenderTextIssue` check on the operator key:

```go
		if k.Weak != "" {
			return nil, fmt.Errorf("operator key %q: %s is a weak key (%s); generate a stronger one", raw, pubPath, k.Weak)
		}
```

- [ ] **Step 4: Run to verify they pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/identity/ ./cmd/sshepherd/ -run 'Weak|Import'`
Expected: PASS.

**docsDelta (README "`sshepherd import`"):**

```markdown
A weak `.pub` identity (DSA, RSA under 2048 bits) is skipped with a warning, in plain `import` and under `--merge`. `--operator` naming a weak key is an error (exit 3).
```

### Task 14: end-to-end save and refusal through the CLI

**Files:** Test: `cmd/sshepherd/conflicts_test.go`.

- [ ] **Step 1: Append the tests** (add the imports `"encoding/json"`, `internal/authkeys` and `internal/sshconn/sshtest`; they exercise lanes' finished code; each must fail before Tasks 9-13 and pass now):

```go
// withWeakUser adds user old (a DSA key, granted web-1) to a hermeticFleet
// manifest and returns its fingerprint.
func withWeakUser(t *testing.T, cfgPath string) string {
	t.Helper()
	dsa := testkeys.DSALine(t, 7)
	b, err := os.ReadFile(cfgPath) // #nosec G304 -- a test temp file
	if err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(string(b), "servers:\n", "  - {name: old, keys: [\""+dsa+"\"]}\nservers:\n", 1)
	y = strings.Replace(y, "access:\n", "access:\n  - {user: old, servers: [web-1]}\n", 1)
	if err := os.WriteFile(cfgPath, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := authkeys.ParseLine(dsa)
	if err != nil {
		t.Fatal(err)
	}
	return k.Fingerprint
}

// TestGrantedWeakKeyAuditExits2: the manifest loads, the conflict prints,
// and the exit is 2 (D29).
func TestGrantedWeakKeyAuditExits2(t *testing.T) {
	srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
	withWeakUser(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "dsa keys are not allowed") {
		t.Errorf("report lacks the conflict:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"audit", "--json", "--config", cfg, "--known-hosts", sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))}, &out, &errBuf); code != 2 {
		t.Fatalf("--json exit = %d, want 2\n%s", code, errBuf.String())
	}
	var doc struct {
		PolicyConflicts []struct {
			Kind string `json:"kind"`
		} `json:"policy_conflicts"`
		Summary struct {
			PolicyConflicts int `json:"policy_conflicts"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if len(doc.PolicyConflicts) != 1 || doc.PolicyConflicts[0].Kind != "weak_key" || doc.Summary.PolicyConflicts != 1 {
		t.Errorf("doc = %+v, want one weak_key conflict, counted in the summary", doc)
	}
}

// TestGrantedWeakKeyApplyJSON: apply's document names the conflict and
// marks the server refused.
func TestGrantedWeakKeyApplyJSON(t *testing.T) {
	srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
	withWeakUser(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--json", "--dry-run", "--config", cfg, "--known-hosts", sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	var doc struct {
		PolicyConflicts []struct {
			Kind string `json:"kind"`
		} `json:"policy_conflicts"`
		Servers []struct {
			Class string `json:"class"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if len(doc.PolicyConflicts) != 1 || doc.PolicyConflicts[0].Kind != "weak_key" || len(doc.Servers) != 1 || doc.Servers[0].Class != "refused" {
		t.Errorf("doc = %+v, want a weak_key conflict and a refused server", doc)
	}
}

// TestUngrantedWeakKeyWarnsAndKeepsTheExit: no server renders it, so no
// human must act now (D28): a warning, exit unchanged.
func TestUngrantedWeakKeyWarnsAndKeepsTheExit(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: old, keys: [\""+testkeys.DSALine(t, 7)+"\"]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "dsa key, granted on no server") {
		t.Errorf("stderr lacks the warning: %s", errBuf.String())
	}
}

// TestRotateReplacesWeakKeyWhileApplyRefuses: apply on the original refuses
// the server (exit 1); rotate of the weak key saves and pushes.
func TestRotateReplacesWeakKeyWhileApplyRefuses(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	fp := withWeakUser(t, cfg)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", cfg, "--known-hosts", kh, "--yes"}, &out, &errBuf); code != 1 {
		t.Fatalf("apply exit = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "dsa keys are not allowed") {
		t.Errorf("apply did not name the weak key:\n%s", out.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"rotate", "old", "--old", fp, "--new", testkeys.Line(t, 8), "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("rotate exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	saved, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Conflicts()) != 0 || len(saved.WeakKeys()) != 0 {
		t.Errorf("the rotate should clear the conflict: %+v, %+v", saved.Conflicts(), saved.WeakKeys())
	}
}
```

Also append the save-versus-push tests (spec section 5 and Risks: a save that cannot land on any server still happens):

```go
// weakPushFleet is one server every affected plan refuses over user old's
// DSA key: alice (key 1, held), carol (key 2) and old are granted web-1,
// bob (key 3) too when withBob. The server holds keys 1 and 2 and the DSA key.
func weakPushFleet(t *testing.T, withBob bool, extraUser string) (kh, cfg string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	host := hosts["web-1"]
	dsa := testkeys.DSALine(t, 7)
	y := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: carol, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: old, keys: [\"" + dsa + "\"]}\n" + extraUser
	access := "access:\n  - {user: alice, servers: [web-1]}\n  - {user: carol, servers: [web-1]}\n  - {user: old, servers: [web-1]}\n"
	if withBob {
		y += "  - {name: bob, keys: [" + qk(t, 3) + "]}\n"
		access += "  - {user: bob, servers: [web-1]}\n"
	}
	host.install(t, []byte{1, 2}, dsa)
	return kh, writeConfig(t, y+"servers:\n"+host.line("web-1")+access)
}

// checkSavedAndRefused runs a save whose only server is weak-refused: the
// edit saves, the server is refused, exit 1.
func checkSavedAndRefused(t *testing.T, args []string, cfg string) {
	t.Helper()
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run(args, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if strings.Contains(errBuf.String(), "nothing saved") || bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("the edit was not saved\nstderr: %s", errBuf.String())
	}
	if !strings.Contains(out.String(), "REFUSED") || !strings.Contains(out.String(), "dsa keys are not allowed") {
		t.Errorf("the push was not refused over the weak key:\n%s", out.String())
	}
}

// TestRotateSavesWhileAnotherWeakKeyRefusesThePush: rotate carol adds a
// key on a server granting someone else's weak key.
func TestRotateSavesWhileAnotherWeakKeyRefusesThePush(t *testing.T) {
	kh, cfg := weakPushFleet(t, false, "")
	checkSavedAndRefused(t, []string{"rotate", "carol", "--old", fpOf(t, 2), "--new", testkeys.Line(t, 5), "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
}

// TestRotateWeakKeySavesBesideASecondWeakKey: with two weak keys, replacing
// one is not removal-only, and its save must not deadlock.
func TestRotateWeakKeySavesBesideASecondWeakKey(t *testing.T) {
	kh, cfg := weakPushFleet(t, false, "  - {name: op2, operator: true, keys: [\""+testkeys.DSALine(t, 8)+"\"]}\n")
	k, err := authkeys.ParseLine(testkeys.DSALine(t, 7))
	if err != nil {
		t.Fatal(err)
	}
	checkSavedAndRefused(t, []string{"rotate", "old", "--old", k.Fingerprint, "--new", testkeys.Line(t, 5), "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
	if got := readCfg(t, cfg).WeakKeys(); len(got) != 1 || got[0].User != "op2" {
		t.Errorf("WeakKeys = %+v, want only op2's", got)
	}
}

// TestRevokeSavesBesideWeakKeyWhenItsKeyIsAlreadyGone: bob's key is not on the server,
// so nothing is unauthorized and the removal-only exception does not apply;
// the tombstone is still saved.
func TestRevokeSavesBesideWeakKeyWhenItsKeyIsAlreadyGone(t *testing.T) {
	kh, cfg := weakPushFleet(t, true, "")
	checkSavedAndRefused(t, []string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
	if _, ok := readCfg(t, cfg).Revoked(fpOf(t, 3)); !ok {
		t.Error("the tombstone for bob's key was not saved")
	}
}
```

- [ ] **Step 2: Run, then hand back**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'Weak'`, then `make check`.
Expected: PASS. (`make check`: the README must carry this lane's footer and flag docsDelta locally.)

Hand back per Conventions.

**docsDelta:** none.

---

## Round 2 — lane `transport` (Tasks 15–20)

Owns: `internal/sshconn/{hostkey.go,hostkey_test.go,connect.go,connect_test.go,offer_test.go,sshconn_test.go}`, `internal/sshread/*`, `cmd/sshepherd/{fleet.go,apply.go,sweep.go,editrun.go,run.go,offer_test.go,hostkey_type_exit_test.go,revoke_test.go,identity_integration_test.go}`, `cmd/sshepherd/testdata/help/*.golden`. Findings: COR-6, SEC-5.

P08 changes `ConnectWith` (the `Only` agent checks, `handshakeKind`'s host-key gate, `SessionTimeout`) and `orderSigners`'s neighbours: re-read `ConnectWith` before editing and apply each edit below to the code that is there. The `offering` value must survive P08's changes to the `Only` path untouched.

### Task 15: classify the host-key type change

**Files:** Modify `internal/sshconn/hostkey.go:26` (`hostKeyHint`, `recordedTypes`), the one call in `ConnectWith`. Tests: `internal/sshconn/hostkey_test.go` (new), `internal/sshconn/sshconn_test.go`, `internal/sshconn/connect_test.go`.

- [ ] **Step 1: Write the failing tests.** Create `internal/sshconn/hostkey_test.go`:

```go
package sshconn

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// hostCert signs a host certificate for plain with ca.
func hostCert(t *testing.T, plain ssh.Signer, ca ssh.Signer, validBefore uint64) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key: plain.PublicKey(), CertType: ssh.HostCert, KeyId: "web-1",
		ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: validBefore,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("sign host cert: %v", err)
	}
	s, err := ssh.NewCertSigner(cert, plain)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	return s
}

func caLine(f fixture, ca ssh.PublicKey) string {
	return "@cert-authority " + knownhosts.Normalize(f.srv.Addr()) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca)))
}

// TestHostKeyTypeClassification drives every row of spec section 3 through a
// real handshake.
func TestHostKeyTypeClassification(t *testing.T) {
	user := sshtest.Key(1)
	plain := sshtest.Signer(t, sshtest.Key(40))
	ca := sshtest.Signer(t, sshtest.Key(50))
	otherCA := sshtest.Signer(t, sshtest.Key(51))
	past := uint64(time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	tests := []struct {
		name     string
		hostKeys []ssh.Signer
		khLines  func(f fixture) []string
		kind     fleet.ErrorKind
		want     []string
	}{
		{
			name:     "only ssh-dss recorded: nothing verifiable was lost",
			hostKeys: []ssh.Signer{plain},
			khLines:  func(f fixture) []string { return []string{f.srv.KnownHostsLine(dsaKey(t))} },
			kind:     fleet.ErrorKindHostKeyTypeUnrecorded,
			want:     []string{"not recorded", "recorded: ssh-dss"},
		},
		{
			name:     "a CA-only host presenting a plain key of another type",
			hostKeys: []ssh.Signer{ecdsaSigner(t)},
			khLines:  func(f fixture) []string { return []string{caLine(f, ca.PublicKey())} },
			kind:     fleet.ErrorKindHostKeyTypeChanged,
			want:     []string{"HOST KEY TYPE CHANGED", "recorded: ssh-ed25519 (CA)"},
		},
		{
			name:     "TestHostCertUnvouchedSignerAlerts: a certificate from an unvouched signer on a CA-vouched host",
			hostKeys: []ssh.Signer{hostCert(t, plain, otherCA, ssh.CertTimeInfinity)},
			khLines:  func(f fixture) []string { return []string{caLine(f, ca.PublicKey())} },
			kind:     fleet.ErrorKindHostKeyTypeChanged,
			want:     []string{"HOST KEY TYPE CHANGED", "no @cert-authority line for this host vouches for"},
		},
		{
			name:     "an expired certificate from the vouched CA stays host_key",
			hostKeys: []ssh.Signer{hostCert(t, plain, ca, past)},
			khLines:  func(f fixture) []string { return []string{caLine(f, ca.PublicKey())} },
			kind:     fleet.ErrorKindHostKey,
		},
		{
			name:     "an unknown host presenting a certificate stays host_key",
			hostKeys: []ssh.Signer{hostCert(t, plain, otherCA, ssh.CertTimeInfinity)},
			khLines:  func(fixture) []string { return nil },
			kind:     fleet.ErrorKindHostKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, sshtest.ServerConfig{HostKeys: tt.hostKeys, Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()}}, user)
			kh := sshtest.KnownHostsFile(t, tt.khLines(f)...)
			conn, err := f.dialer(kh).Connect(ctxTimeout(t, 10*time.Second), f.cfgSrv)
			if err == nil {
				_ = conn.Close()
				t.Fatal("Connect succeeded, want a host-key refusal")
			}
			if got := kindOf(t, err); got != tt.kind {
				t.Errorf("kind = %q, want %q (err: %v)", got, tt.kind, err)
			}
			hint := fleet.HintOf(err)
			for _, w := range tt.want {
				if !strings.Contains(hint, w) {
					t.Errorf("hint lacks %q:\n%s", w, hint)
				}
			}
			if n := len(f.srv.Attempts()); n != 0 {
				t.Errorf("%d auth attempts reached an untrusted host, want 0", n)
			}
		})
	}
}
```

In `internal/sshconn/sshconn_test.go`'s `TestHostKeyHint`, add `kh := &KnownHosts{Path: "/kh"}` as the first statement and pass `kh` for `"/kh"` in every `hostKeyHint` call. Add the `dsaKey` helper and these subtests, replacing the "unrecorded key type" subtest:

```go
// dsaKey is an ssh-dss key: a type known_hosts can record and x/crypto
// cannot verify.
func dsaKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testkeys.DSALine(t, 1)))
	if err != nil {
		t.Fatalf("parse dsa key: %v", err)
	}
	return k
}
```

```go
	t.Run("a verifiable recorded type replaced by another is a type change", func(t *testing.T) {
		// known_hosts records only an ed25519 key; the host presents only an
		// ECDSA key — negotiation offers the recorded type first, so a genuine
		// server reaches this only by no longer serving it.
		ke := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: ed25519Key(t, 2)}}}
		_, hint := splitHint(t, hostKeyHint(ke, ecdsaKey(t), srv, kh))
		if !strings.Contains(hint, "HOST KEY TYPE CHANGED") || !strings.Contains(hint, "recorded: ssh-ed25519") {
			t.Errorf("hint = %q", hint)
		}
	})
	t.Run("only unsupported types recorded stays unrecorded, not alarmed", func(t *testing.T) {
		ke := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: dsaKey(t)}}}
		msg, hint := splitHint(t, hostKeyHint(ke, ecdsaKey(t), srv, kh))
		if strings.Contains(msg+hint, "CHANGED") {
			t.Errorf("hint = %q, must not raise an alarm", hint)
		}
		if !strings.Contains(hint, "not recorded in known_hosts") || !strings.Contains(hint, "recorded: ssh-dss") {
			t.Errorf("hint = %q", hint)
		}
	})
```

In the `"kinds"` subtest's table replace the `"unrecorded type"` row with:

```go
			{"type changed", recorded, ecdsaKey(t), fleet.ErrorKindHostKeyTypeChanged},
			{"unrecorded type", &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: dsaKey(t)}}}, ecdsaKey(t), fleet.ErrorKindHostKeyTypeUnrecorded},
```

In `internal/sshconn/connect_test.go`'s `TestConnectHostKeyFailures`, replace the "unrecorded key type" row with:

```go
		{
			name:     "a verifiable type recorded and another presented is a type change",
			hostKeys: []ssh.Signer{ecdsaSigner(t)},
			khLines: func(f fixture) []string {
				return []string{f.srv.KnownHostsLine(host.PublicKey())}
			},
			kind:    fleet.ErrorKindHostKeyTypeChanged,
			want:    []string{"HOST KEY TYPE CHANGED", "recorded: ssh-ed25519", "out of band", "| ssh-keygen -lf -"},
			notWant: []string{"HOST KEY CHANGED for", ">>"},
		},
```

- [ ] **Step 2: Run to verify they fail**

Run: `GOTOOLCHAIN=go1.27.3 go vet ./internal/sshconn/`
Expected: FAIL: `cannot use kh (variable of type *KnownHosts) as string value`.

- [ ] **Step 3: Implement.** Replace `hostKeyHint` and `recordedTypes`, and add `anyVerifiableType`:

```go
// hostKeyHint classifies a known_hosts verification failure and attaches
// actionable remediation as the error's separate Hint (never part of the
// message: reports print it on its own line, JSON as `hint`), using the key the server actually presented
// to tell a genuinely changed key apart from a merely unrecorded key type.
// known_hosts entries are keyed by the exact host form used, so hints name
// the configured host:port verbatim — ShQuote-d wherever they enter a
// suggested command. No hint ever pipes unauthenticated ssh-keyscan output
// straight into known_hosts: that is trust-on-first-use through the back
// door. Every hint asks for out-of-band verification of the presented
// fingerprint first. The result is always an *Error.
//
// A host that once had a key type x/crypto can verify and now presents only
// another type is host_key_type_changed (exit 2), and so is a certificate
// from a signer no matching @cert-authority line vouches for on a CA-vouched
// host: negotiation offers the recorded types and the CA's certificates
// first, so a genuine server reaches either case only by dropping them all.
func hostKeyHint(err error, presented ssh.PublicKey, srv config.Server, kh *KnownHosts) error {
	if presented != nil {
		err = fmt.Errorf("presented %s key %s: %w", presented.Type(), ssh.FingerprintSHA256(presented), err)
	}
	var revoked *knownhosts.RevokedError
	if errors.As(err, &revoked) {
		return classifyHint(fleet.ErrorKindHostKeyRevoked, fmt.Sprintf(
			"this key is marked @revoked in %s — do not connect until the host is re-keyed and the new key verified out of band",
			kh.Path), err)
	}
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		if strings.Contains(err.Error(), noAuthorityPrefix) {
			if kh.authorityMatches(net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))) {
				return classifyHint(fleet.ErrorKindHostKeyTypeChanged, fmt.Sprintf(
					"HOST KEY TYPE CHANGED for %s:%d — the server presented a certificate no @cert-authority line for this host vouches for; possible impersonation; verify the CA out of band before touching known_hosts",
					srv.Host, srv.Port), err)
			}
			return classifyHint(fleet.ErrorKindHostKey, fmt.Sprintf(
				"the host presented a certificate but no @cert-authority line in %s vouches for it here; record the host's plain key or its CA (verified out of band)",
				kh.Path), err)
		}
		return classify(fleet.ErrorKindHostKey, err)
	}
	if len(ke.Want) == 0 {
		return classifyHint(fleet.ErrorKindHostKeyUnknown, fmt.Sprintf(
			"host is not in %s; verify the presented fingerprint out of band (on the server console: %s, or the cloud provider's console output), then compare before recording: %s — append only a line whose fingerprint matches",
			kh.Path, consoleFingerprintCmd(presented), keyscanCompareCmd(presented, srv)), err)
	}
	if presented != nil && !typeRecorded(ke, presented.Type()) {
		if anyVerifiableType(ke) {
			return classifyHint(fleet.ErrorKindHostKeyTypeChanged, fmt.Sprintf(
				"HOST KEY TYPE CHANGED for %s:%d — the server no longer presents any recorded key type (recorded: %s); possible impersonation; verify the presented fingerprint out of band (console: %s; compare with: %s) before touching known_hosts",
				srv.Host, srv.Port, strings.Join(recordedTypes(ke, kh), ", "),
				consoleFingerprintCmd(presented), keyscanCompareCmd(presented, srv)), err)
		}
		return classifyHint(fleet.ErrorKindHostKeyTypeUnrecorded, fmt.Sprintf(
			"host key type %s is not recorded in known_hosts for this host (recorded: %s) — unverified, not proof of a change; verify the presented fingerprint out of band (%s on the console), compare with: %s — and append only a matching line",
			presented.Type(), strings.Join(recordedTypes(ke, kh), ", "),
			consoleFingerprintCmd(presented), keyscanCompareCmd(presented, srv)), err)
	}
	return classifyHint(fleet.ErrorKindHostKeyChanged, fmt.Sprintf(
		"HOST KEY CHANGED for %s:%d — possible impersonation; investigate and verify the new fingerprint out of band before touching %s",
		srv.Host, srv.Port, kh.Path), err)
}

// anyVerifiableType reports whether known_hosts records, for this host, a
// key type x/crypto can verify (Want holds the host's plain lines and its
// @cert-authority lines). A host recorded only under an unsupported type
// (ssh-dss) stays host_key_type_unrecorded: nothing is known to have changed.
func anyVerifiableType(ke *knownhosts.KeyError) bool {
	for _, k := range ke.Want {
		if k.Key != nil && algosForKeyType(k.Key.Type()) != nil {
			return true
		}
	}
	return false
}

// recordedTypes lists the distinct key types known_hosts records for the
// host, a CA line's type marked "(CA)".
func recordedTypes(ke *knownhosts.KeyError, kh *KnownHosts) []string {
	var types []string
	seen := make(map[string]bool)
	for _, k := range ke.Want {
		if k.Key == nil {
			continue
		}
		label := k.Key.Type()
		if kh.isAuthority(k.Key) {
			label += " (CA)"
		}
		if !seen[label] {
			seen[label] = true
			types = append(types, label)
		}
	}
	return types
}
```

Add `"net"` to the imports. In `ConnectWith`'s host-key callback, change the call to `hostKeyHint(khErr, key, srv, kh)`.

- [ ] **Step 4: Run to verify they pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn/ -run 'HostKey|Host'`
Expected: PASS, every `TestHostKeyTypeClassification` row included.

**docsDelta (README "`sshepherd audit`" error kinds; "Exit codes" row `2`; "Safety model" connection posture):**

```markdown
`host_key_type_changed` (exit 2): `known_hosts` records a key type x/crypto can verify and the server presented a different type, or a certificate from a signer no `@cert-authority` line for this host vouches for. `host_key_type_unrecorded` (exit 1) now remains only when every recorded type is unsupported. A certificate from a vouched CA that fails validation stays `host_key` (exit 1).
```

### Task 16: `orderSigners` restricts the offer

**Files:** Modify `internal/sshconn/connect.go:267` (`orderSigners`). Test: `internal/sshconn/connect_test.go`.

- [ ] **Step 1: Write the failing tests.** Replace `TestOrderSigners` in `internal/sshconn/connect_test.go` and add the certificate test:

```go
func TestOrderSigners(t *testing.T) {
	keys := []ssh.Signer{
		sshtest.Signer(t, sshtest.Key(1)), sshtest.Signer(t, sshtest.Key(2)), sshtest.Signer(t, sshtest.Key(3)),
	}
	fp := func(i int) string { return ssh.FingerprintSHA256(keys[i].PublicKey()) }
	tests := []struct {
		name         string
		prefer, only []string
		offerAll     bool
		want         []int
		withheld     int
		fellBack     bool
	}{
		{name: "no grant falls back to every key", want: []int{0, 1, 2}, fellBack: true},
		{name: "granted keys only", prefer: []string{fp(2)}, want: []int{2}, withheld: 2},
		{name: "grant order wins", prefer: []string{fp(2), fp(1)}, want: []int{2, 1}, withheld: 1},
		{name: "unheld grants are skipped", prefer: []string{"SHA256:nope", fp(1)}, want: []int{1}, withheld: 2},
		{name: "nothing held is granted: fall back", prefer: []string{"SHA256:nope"}, want: []int{0, 1, 2}, fellBack: true},
		{name: "duplicates offered once", prefer: []string{fp(1), fp(1)}, want: []int{1}, withheld: 2},
		{name: "offerAll: granted first, then the rest", prefer: []string{fp(2)}, offerAll: true, want: []int{2, 0, 1}},
		{name: "offerAll with nothing granted is no fallback", prefer: []string{"SHA256:nope"}, offerAll: true, want: []int{0, 1, 2}},
		{name: "only restricts and orders", prefer: []string{fp(0)}, only: []string{fp(2), fp(1)}, want: []int{2, 1}},
		{name: "only with nothing held offers nothing", only: []string{"SHA256:nope"}},
		{name: "only beats offerAll", only: []string{fp(1)}, offerAll: true, want: []int{1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orderSigners(keys, tt.prefer, tt.only, tt.offerAll)
			var idx []int
			for _, s := range got.signers {
				for i, k := range keys {
					if s == k {
						idx = append(idx, i)
					}
				}
			}
			if !slices.Equal(idx, tt.want) || got.withheld != tt.withheld || got.fellBack != tt.fellBack {
				t.Errorf("order = %v withheld=%d fellBack=%v, want %v withheld=%d fellBack=%v",
					idx, got.withheld, got.fellBack, tt.want, tt.withheld, tt.fellBack)
			}
		})
	}
}

// TestOrderSignersCertificates: a certificate's fingerprint is not its
// key's, so it is offered when its key or its CA is granted.
func TestOrderSignersCertificates(t *testing.T) {
	user, ca, other := sshtest.Key(1), sshtest.Key(50), sshtest.Key(2)
	cert := sshtest.UserCert(t, user, ca, "deploy")
	certSigner, err := ssh.NewCertSigner(cert, sshtest.Signer(t, user))
	if err != nil {
		t.Fatal(err)
	}
	plain := sshtest.Signer(t, other)
	held := []ssh.Signer{plain, certSigner}
	tests := []struct {
		name  string
		grant string
		want  []ssh.Signer
	}{
		{"granted by its key", sshtest.Fingerprint(t, user), []ssh.Signer{certSigner}},
		{"granted by its CA", sshtest.Fingerprint(t, ca), []ssh.Signer{certSigner}},
		{"not granted", sshtest.Fingerprint(t, other), []ssh.Signer{plain}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := orderSigners(held, []string{tt.grant}, nil, false); !slices.Equal(got.signers, tt.want) {
				t.Errorf("offered %d keys, want %d", len(got.signers), len(tt.want))
			}
		})
	}
}
```

Rename `TestConnectKeyOffering`'s first subtest to `"agent order when nothing is granted (fallback)"`.

- [ ] **Step 2: Run to verify they fail**

Run: `GOTOOLCHAIN=go1.27.3 go vet ./internal/sshconn/`
Expected: FAIL: `too many arguments in call to orderSigners`.

- [ ] **Step 3: Implement.** Replace `orderSigners` (add `"cmp"` to the imports):

```go
// offering is one connection's key offer.
type offering struct {
	signers  []ssh.Signer
	withheld int  // held keys the restricted offer left out
	fellBack bool // no granted key is held, so every held key is offered
}

// GrantIndex is the offering's one matcher: pub's position in granted, or
// -1 when it is not granted. A certificate's fingerprint is not its key's,
// so a certificate matches through its key or through its CA (a manifest
// cert-authority line grants the signer).
func GrantIndex(pub ssh.PublicKey, granted []string) int {
	fps := []string{ssh.FingerprintSHA256(pub)}
	if cert, ok := pub.(*ssh.Certificate); ok {
		fps = append(fps, ssh.FingerprintSHA256(cert.Key), ssh.FingerprintSHA256(cert.SignatureKey))
	}
	best := -1
	for _, fp := range fps {
		if i := slices.Index(granted, fp); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

// orderSigners applies the per-connection key offering. With only set:
// exactly those keys, in that order, and never a fallback (the login probe's
// IdentitiesOnly posture). Otherwise the held keys matching prefer, in
// prefer order, and nothing else; when none matches, every held key in
// Signers order (key files before agent keys) with fellBack set. offerAll
// restores the unrestricted offer: granted first, then every other key.
func orderSigners(signers []ssh.Signer, prefer, only []string, offerAll bool) offering {
	if len(only) > 0 {
		return offering{signers: pickExact(signers, only)}
	}
	var granted, rest []ssh.Signer
	for _, s := range signers {
		if GrantIndex(s.PublicKey(), prefer) >= 0 {
			granted = append(granted, s)
		} else {
			rest = append(rest, s)
		}
	}
	slices.SortStableFunc(granted, func(a, b ssh.Signer) int {
		return cmp.Compare(GrantIndex(a.PublicKey(), prefer), GrantIndex(b.PublicKey(), prefer))
	})
	switch {
	case offerAll:
		return offering{signers: append(granted, rest...)}
	case len(granted) == 0:
		return offering{signers: signers, fellBack: len(signers) > 0}
	default:
		return offering{signers: granted, withheld: len(rest)}
	}
}

// pickExact returns the held keys with exactly these fingerprints, in this
// order, each once.
func pickExact(signers []ssh.Signer, fps []string) []ssh.Signer {
	byFP := make(map[string]ssh.Signer, len(signers))
	for _, s := range signers {
		byFP[ssh.FingerprintSHA256(s.PublicKey())] = s
	}
	var out []ssh.Signer
	var seen []string
	for _, fp := range fps {
		if s, ok := byFP[fp]; ok && !slices.Contains(seen, fp) {
			out = append(out, s)
			seen = append(seen, fp)
		}
	}
	return out
}
```

So the package keeps building, change `ConnectWith`'s call to the interim form below. Task 17 Step 3 replaces this line, and the `prefer`/`only` lines above it, with `d.offerFor`.

```go
	offered := wrapSigners(orderSigners(signers, prefer, only, false).signers, rec)
```

- [ ] **Step 4: Run to verify they pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn/ -run 'TestOrderSigners'`
Expected: PASS.

**docsDelta:** none (documented in Task 19).

### Task 17: the dialer's offer rule and the `auth` hint

**Files:** Modify `internal/sshconn/connect.go:138` (`ConnectWith`, `Dialer`), `internal/sshread/sshread.go` (`Client`, `getDialer`). Test: `internal/sshconn/offer_test.go` (new).

- [ ] **Step 1: Write the failing tests** (`internal/sshconn/offer_test.go`):

```go
package sshconn

import (
	"bytes"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// offerFixture: a server that accepts only key 3, an agent holding 1, 2, 3.
func offerFixture(t *testing.T) (fixture, string, []string) {
	t.Helper()
	a, b, c := sshtest.Key(1), sshtest.Key(2), sshtest.Key(3)
	host := sshtest.Signer(t, sshtest.Key(40))
	f := newFixture(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, c).PublicKey()},
	}, a, b, c)
	return f, sshtest.KnownHostsFile(t, f.srv.KnownHostsLine(host.PublicKey())),
		[]string{sshtest.Fingerprint(t, a), sshtest.Fingerprint(t, b), sshtest.Fingerprint(t, c)}
}

func grants(fps ...string) func(config.Server) []string {
	return func(config.Server) []string { return fps }
}

func logBuffer() (*bytes.Buffer, *slog.Logger) {
	var buf bytes.Buffer
	return &buf, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

func tryConnect(t *testing.T, d *Dialer, srv config.Server) error {
	t.Helper()
	conn, err := d.ConnectWith(ctxTimeout(t, 10*time.Second), srv, ConnectOptions{})
	if err == nil {
		_ = conn.Close()
	}
	return err
}

// TestRestrictedOfferRevealsOnlyGranted (SEC-5): three keys loaded, two
// granted, neither accepted: the server is asked about exactly those two and
// the login fails. The old order (granted first, then the rest) goes on to
// offer key 3 and logs in, so this fails without the restriction. The
// spec's "3 loaded, 1 granted → 1 query" is TestAuthFailureHintsOfferAllKeys.
func TestRestrictedOfferRevealsOnlyGranted(t *testing.T) {
	f, kh, fps := offerFixture(t)
	d := f.dialer(kh)
	d.PreferKeys = grants(fps[0], fps[1])
	err := tryConnect(t, d, f.cfgSrv)
	if err == nil {
		t.Fatal("connect succeeded: a withheld key was offered")
	}
	if k := kindOf(t, err); k != fleet.ErrorKindAuth {
		t.Fatalf("kind = %q, want auth", k)
	}
	if got := f.srv.Attempts(); !slices.Equal(got, []string{fps[0], fps[1]}) {
		t.Errorf("server was offered %v, want only the granted keys", got)
	}
}

// TestAuthFailureHintsOfferAllKeys: the granted key is held but not
// installed. No retry widens the offer; the hint names the flag.
func TestAuthFailureHintsOfferAllKeys(t *testing.T) {
	f, kh, fps := offerFixture(t)
	d := f.dialer(kh)
	d.PreferKeys = grants(fps[0]) // held, but the server only accepts key 3
	err := tryConnect(t, d, f.cfgSrv)
	if err == nil {
		t.Fatal("connect succeeded")
	}
	if k := kindOf(t, err); k != fleet.ErrorKindAuth {
		t.Fatalf("kind = %q, want auth", k)
	}
	want := "none of the keys the manifest grants here were accepted; 2 other loaded keys were not offered — if one of them still logs in here, re-run with --offer-all-keys (this server then sees every loaded key)"
	if got := fleet.HintOf(err); got != want {
		t.Errorf("hint:\n got %s\nwant %s", got, want)
	}
	if got := f.srv.Attempts(); !slices.Equal(got, []string{fps[0]}) {
		t.Errorf("attempts = %v, want exactly the granted key and no second handshake", got)
	}
}

func TestAuthFailureHintSingularAndAbsent(t *testing.T) {
	if got := (offering{withheld: 1}).authHint(fleet.ErrorKindAuth); !strings.Contains(got, "1 other loaded key was not offered") {
		t.Errorf("hint = %q", got)
	}
	if got := (offering{withheld: 2}).authHint(fleet.ErrorKindDial); got != "" {
		t.Errorf("a non-auth failure carries no offer hint: %q", got)
	}
	if got := (offering{}).authHint(fleet.ErrorKindAuth); got != "" {
		t.Errorf("nothing withheld, nothing to hint: %q", got)
	}
}

// TestOfferAllKeysLogsInWithAnotherHeldKey: the escape hatch restores
// today's offer, granted first and then the rest.
func TestOfferAllKeysLogsInWithAnotherHeldKey(t *testing.T) {
	f, kh, fps := offerFixture(t)
	d := f.dialer(kh)
	d.PreferKeys = grants(fps[0])
	d.OfferAll = true
	if err := tryConnect(t, d, f.cfgSrv); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := f.srv.Attempts(); !slices.Equal(got, []string{fps[0], fps[1], fps[2]}) {
		t.Errorf("attempts = %v, want granted first, then the rest", got)
	}
}

func TestFallbackWarnsOnceAndOffersEveryKey(t *testing.T) {
	f, kh, fps := offerFixture(t)
	buf, log := logBuffer()
	d := f.dialer(kh)
	d.PreferKeys = grants("SHA256:unheld")
	d.Log = log
	if err := tryConnect(t, d, f.cfgSrv); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got := f.srv.Attempts(); !slices.Equal(got, fps) {
		t.Errorf("attempts = %v, want every held key", got)
	}
	want := "web-1: none of the keys granted here are loaded; offering all 3 held keys"
	if n := strings.Count(buf.String(), want); n != 1 || !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("want one WARN %q, got:\n%s", want, buf.String())
	}
}

// TestQuietFallbackIsDebug (OP6): after the run's preflight warned, the
// per-server fallback line is debug level.
func TestQuietFallbackIsDebug(t *testing.T) {
	f, kh, _ := offerFixture(t)
	var buf bytes.Buffer
	d := f.dialer(kh)
	d.PreferKeys = grants("SHA256:unheld")
	d.QuietFallback = true
	d.Log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	if err := tryConnect(t, d, f.cfgSrv); err != nil {
		t.Fatalf("connect: %v", err)
	}
	lines := strings.Split(buf.String(), "\n")
	i := slices.IndexFunc(lines, func(l string) bool { return strings.Contains(l, "none of the keys granted here") })
	if i < 0 || !strings.Contains(lines[i], "level=DEBUG") {
		t.Errorf("want the fallback line at debug level, got:\n%s", buf.String())
	}
}

func TestGrantIndex(t *testing.T) {
	user, ca := sshtest.Key(1), sshtest.Key(50)
	plain := sshtest.Signer(t, user).PublicKey()
	cert := sshtest.UserCert(t, user, ca, "deploy")
	fpUser, fpCA := sshtest.Fingerprint(t, user), sshtest.Fingerprint(t, ca)
	if got := GrantIndex(plain, []string{"x", fpUser}); got != 1 {
		t.Errorf("plain key index = %d", got)
	}
	if got := GrantIndex(plain, []string{fpCA}); got != -1 {
		t.Errorf("ungranted key index = %d", got)
	}
	if got := GrantIndex(cert, []string{fpCA, "y", fpUser}); got != 0 {
		t.Errorf("certificate takes its best match, got %d", got)
	}
}
```

- [ ] **Step 2: Run to verify they fail**

Run: `GOTOOLCHAIN=go1.27.3 go vet ./internal/sshconn/`
Expected: FAIL: `d.OfferAll undefined`.

- [ ] **Step 3: Implement.** In `Dialer`, replace `PreferKeys`' doc comment and add the new fields:

```go
	// PreferKeys optionally returns the keys the manifest grants on srv
	// (audit.GrantedFingerprints), in offer order. Only those of the held
	// keys are offered, so a server never learns a key it was not granted
	// (D17); when the run holds none of them, every held key is offered
	// with a warning. Without it, nothing is granted: the fallback applies.
	PreferKeys func(srv config.Server) []string
	// OfferAll is --offer-all-keys: offer the granted keys first, then every
	// other held key, with no restriction.
	OfferAll bool
	// QuietFallback drops the per-server fallback warning to debug level,
	// after a preflight that already warned once for the whole run.
	QuietFallback bool
	Log           *slog.Logger // optional stage-level telemetry; nil discards
```

In `ConnectWith`, replace the `prefer`/`only` lines and Task 16's interim `orderSigners` call with:

```go
	offer := d.offerFor(srv, signers, opts)
	rec := &sessionKey{}
	offered := wrapSigners(offer.signers, rec)
```

and at the handshake-failure return (keep P08's `handshakeKind` arguments):

```go
		kind := handshakeKind(ctx, err)
		return nil, classifyHint(kind, offer.authHint(kind), fmt.Errorf("ssh %s@%s: %w", srv.User, addr, remoteText{err}))
```

Add the helpers:

```go
// offerFor resolves the keys this connection offers and logs a fallback.
func (d *Dialer) offerFor(srv config.Server, signers []ssh.Signer, opts ConnectOptions) offering {
	prefer := opts.Prefer
	if prefer == nil && d.PreferKeys != nil {
		prefer = d.PreferKeys(srv)
	}
	offer := orderSigners(signers, prefer, opts.Only, d.OfferAll)
	if offer.fellBack {
		msg := fmt.Sprintf("%s: none of the keys granted here are loaded; offering all %s", srv.Name, heldKeys(len(signers)))
		if d.QuietFallback {
			d.log().Debug(msg)
		} else {
			d.log().Warn(msg)
		}
	}
	return offer
}

// authHint is the remediation for a server that refused the granted keys
// while other held keys were withheld. The offer is never widened by
// itself: a retry would hand every held key to any server that refuses the
// granted ones, which is what the restricted offer prevents.
func (o offering) authHint(kind fleet.ErrorKind) string {
	if kind != fleet.ErrorKindAuth || o.withheld == 0 {
		return ""
	}
	keys := fmt.Sprintf("%d other loaded key was", o.withheld)
	if o.withheld > 1 {
		keys = fmt.Sprintf("%d other loaded keys were", o.withheld)
	}
	return "none of the keys the manifest grants here were accepted; " + keys +
		" not offered — if one of them still logs in here, re-run with --offer-all-keys (this server then sees every loaded key)"
}

func heldKeys(n int) string {
	if n == 1 {
		return "1 held key"
	}
	return fmt.Sprintf("%d held keys", n)
}
```

In `internal/sshread/sshread.go`, add `OfferAll bool` and `QuietFallback bool` to `Client` and copy them in `getDialer`:

```go
	// OfferAll and QuietFallback: see sshconn.Dialer.
	OfferAll      bool
	QuietFallback bool
```

```go
			OfferAll:       c.OfferAll,
			QuietFallback:  c.QuietFallback,
```

- [ ] **Step 4: Run to verify they pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn/ ./internal/sshread/`
Expected: PASS.

**docsDelta:** none.

### Task 18: `--offer-all-keys`

**Files:** Modify `cmd/sshepherd/fleet.go` (`connFlags`, `register`, `followUp`, `fleetSession`, `openFleet`, `reader`, `dialer`), `cmd/sshepherd/editrun.go:50` (`connectionFlags`), `cmd/sshepherd/identity_integration_test.go`, help goldens. Tests: `cmd/sshepherd/offer_test.go` (new), `cmd/sshepherd/revoke_test.go`.

- [ ] **Step 1: Write the failing test** (`cmd/sshepherd/offer_test.go`, the file; Task 19 implements its preflight):

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
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// offerFleet: two servers accepting agent key 1. The manifest grants key
// grantSeed, so the run's agent (key 1, key 2) may hold none of it.
func offerFleet(t *testing.T, grantSeed byte) (cfgPath, kh string, servers []*sshtest.Server) {
	t.Helper()
	agentKey, other := sshtest.Key(1), sshtest.Key(2)
	host := sshtest.Signer(t, sshtest.Key(40))
	t.Setenv("SSH_AUTH_SOCK", sshtest.Agent(t, agentKey, other))
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, agentKey).PublicKey())))
	var lines []string
	var body strings.Builder
	body.WriteString("users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, grantSeed) + "\"]}\nservers:\n")
	for _, name := range []string{"web-1", "web-2"} {
		home := shortHome(t)
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		srv := sshtest.NewServer(t, sshtest.ServerConfig{
			HostKeys:   []ssh.Signer{host},
			Authorized: []ssh.PublicKey{sshtest.Signer(t, agentKey).PublicKey()},
			Handle:     sshtest.ShellHandler(home),
		})
		servers = append(servers, srv)
		lines = append(lines, srv.KnownHostsLine(host.PublicKey()))
		fmt.Fprintf(&body, "  - {name: %s, host: 127.0.0.1, port: %d, user: deploy}\n", name, srv.Port)
	}
	body.WriteString("access:\n  - {user: alice, servers: [web-1, web-2]}\n")
	return writeConfig(t, body.String()), sshtest.KnownHostsFile(t, lines...), servers
}

// TestPreflightWarnsOnceWhenNothingGranted (D17b, OP6): one line for the
// whole run, and the per-server fallback lines are silent.
func TestPreflightWarnsOnceWhenNothingGranted(t *testing.T) {
	cfg, kh, servers := offerFleet(t, 9) // key 9 is held by nobody
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (drift), stderr: %s", code, errBuf.String())
	}
	want := "none of the loaded keys is granted on any target server; each server will be offered all 2 held keys"
	if n := strings.Count(errBuf.String(), want); n != 1 {
		t.Errorf("preflight warning appeared %d times, want once:\n%s", n, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "none of the keys granted here") {
		t.Errorf("per-server fallback warning printed after the preflight:\n%s", errBuf.String())
	}
	if got := len(servers[0].Attempts()); got == 0 {
		t.Error("the fallback offered nothing")
	}
}

// TestPreflightSilentWhenAnyServerGranted pins the negative: one granted
// key anywhere keeps the preflight quiet. It passes before Task 19 (no
// preflight exists yet) and guards against one that warns too eagerly.
func TestPreflightSilentWhenAnyServerGranted(t *testing.T) {
	cfg, kh, _ := offerFleet(t, 1) // key 1 is held
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0, stderr: %s\n%s", code, errBuf.String(), out.String())
	}
	if strings.Contains(errBuf.String(), "none of the loaded keys") {
		t.Errorf("unexpected preflight warning:\n%s", errBuf.String())
	}
}

// TestOfferAllKeysSkipsPreflight: --offer-all-keys asks for the old offer,
// so neither warning is printed.
func TestOfferAllKeysSkipsPreflight(t *testing.T) {
	cfg, kh, _ := offerFleet(t, 9)
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--offer-all-keys"}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1, stderr: %s", code, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "none of the") {
		t.Errorf("unexpected warning under --offer-all-keys:\n%s", errBuf.String())
	}
}

// TestApplyNoGrantedKeyRefusedByGuard: no granted key held — the read falls
// back and the plan is computed, but the self-lockout guard refuses the
// write. One preflight line, one connection (one auth attempt: the first
// held key is accepted) and the two read sessions: no write dial.
func TestApplyNoGrantedKeyRefusedByGuard(t *testing.T) {
	cfg, kh, servers := offerFleet(t, 9)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", cfg, "--known-hosts", kh, "--yes"}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1, stdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "REFUSED") {
		t.Errorf("report lacks the guard's refusal:\n%s", out.String())
	}
	if n := strings.Count(errBuf.String(), "none of the loaded keys is granted on any target server"); n != 1 {
		t.Errorf("preflight warning appeared %d times, want once:\n%s", n, errBuf.String())
	}
	for _, srv := range servers {
		if got := srv.Attempts(); len(got) != 1 {
			t.Errorf("auth attempts = %v, want one connection's single attempt", got)
		}
		if got := srv.Commands(); len(got) != 2 {
			t.Errorf("commands = %q, want the two read sessions and no write", got)
		}
	}
}

// TestPreflightWarnsOnceOnRevoke: the edit path has its own preflight call
// site, with the former-and-edited grants. Every server is refused (revoke
// never empties one), so a dry run ends at exit 1.
func TestPreflightWarnsOnceOnRevoke(t *testing.T) {
	cfg, kh, _ := offerFleet(t, 9)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "alice", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1, stdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if n := strings.Count(errBuf.String(), "none of the loaded keys is granted on any target server"); n != 1 {
		t.Errorf("preflight warning appeared %d times, want once:\n%s", n, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "none of the keys granted here") {
		t.Errorf("per-server fallback warning printed after the preflight:\n%s", errBuf.String())
	}
}

// TestAuditAuthFailureHintsFlag: a granted key held but not installed fails
// auth with a hint naming the flag, which then reads the server.
func TestAuditAuthFailureHintsFlag(t *testing.T) {
	cfg, kh, _ := offerFleet(t, 2) // key 2 is held and granted, but the server accepts only key 1
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1, stdout: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "re-run with --offer-all-keys") {
		t.Errorf("report lacks the hint:\n%s", out.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--offer-all-keys"}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (the read now works and shows drift), stdout: %s", code, out.String())
	}
	if strings.Contains(out.String(), "ERROR") || !strings.Contains(out.String(), "UNAUTHORIZED") {
		t.Errorf("the flag should read the server and show drift:\n%s", out.String())
	}
}

// TestFollowUpCarriesOfferAll: paste-ready hints repeat the flag.
func TestFollowUpCarriesOfferAll(t *testing.T) {
	f := connFlags{cfgPath: defaultConfigPath, knownHosts: defaultKnownHosts, offerAll: true}
	if got := f.followUp().command("apply", nil); got != "sshepherd apply --offer-all-keys" {
		t.Errorf("command = %q", got)
	}
}
```

Add this row to the table of `TestRevokeUsage` in `cmd/sshepherd/revoke_test.go`, after `--no-apply with --parallel`:

```go
		{"--no-apply with --offer-all-keys", []string{"revoke", "bob", "--no-apply", "--offer-all-keys"}, cfgBody, "--offer-all-keys would be unused"},
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOTOOLCHAIN=go1.27.3 go vet ./cmd/sshepherd/`
Expected: FAIL: `unknown field offerAll in struct literal of type connFlags` (first error).

- [ ] **Step 3: Implement the flag.** Add `offerAll bool` to `connFlags`. In `register`:

```go
	cmd.Flags().BoolVar(&f.offerAll, "offer-all-keys", false,
		"offer every loaded key to every server (default: only the keys the manifest grants there)")
```

In `followUp` (the `for _, kv := range f.idf.perKey` loop's successor):

```go
	if f.offerAll {
		h.conn = append(h.conn, "--offer-all-keys")
	}
```

In `cmd/sshepherd/editrun.go`, add `"offer-all-keys"` to `connectionFlags`: `--no-apply` refuses it, so its hints still carry `--config` only.

Add `offerAll bool` and a `quietFallback bool` field (with doc comment) to `fleetSession`; `openFleet` sets `offerAll: f.offerAll`. Add to `reader` and `dialer` their `OfferAll: s.offerAll, QuietFallback: s.quietFallback` fields.

- [ ] **Step 4: Update the headless rotation test.** In `cmd/sshepherd/identity_integration_test.go`'s `TestIntegrationHeadlessRotation`, the "old + new" subtest now passes `--offer-all-keys`, since the restricted offer would present only `ci_new`, which is not installed yet:

```go
		code, out, stderr := runHeadless(t, bin, append(append(append(base, "--offer-all-keys"), oldKey...), newKey...)...)
```

and the test's doc comment says so.

- [ ] **Step 5: Regenerate the help goldens, apply the README rows and run.** Add the README rows below to the worktree first.

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestHelp' -update && GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestHelp|TestFollowUpCarriesOfferAll|TestRevokeUsage'`
Expected: PASS; read the five regenerated goldens (only the new flag line).

**docsDelta (README flag tables of `sshepherd audit`, `adopt`, `apply`, `revoke`, `rotate`, a row after `--parallel`):**

```markdown
| `--offer-all-keys` | off | Offer every loaded key to every server (default: only the keys the manifest grants there). |
```

### Task 19: the preflight and the call sites

**Files:** Modify `cmd/sshepherd/fleet.go` (`readFleet`), `cmd/sshepherd/apply.go:303` (`runWorkflow`, `newApplyCmd`'s `preferKeys`), `cmd/sshepherd/editrun.go:360` (`sweepAll`), `cmd/sshepherd/sweep.go` (`runSweep`). Test: `cmd/sshepherd/offer_test.go`.

- [ ] **Step 1: Run the failing tests** (written in Task 18)

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run 'TestPreflight|TestOfferAllKeysSkips|TestApplyNoGrantedKey|TestAuditAuthFailure'`
Expected: FAIL: the preflight warning is absent.

- [ ] **Step 2: Implement.** In `cmd/sshepherd/fleet.go` add:

```go
// grantedOn is every command's PreferKeys for cfg: the keys it grants on srv.
func grantedOn(cfg *config.Config) func(config.Server) []string {
	return func(srv config.Server) []string { return audit.GrantedFingerprints(cfg, srv.Name) }
}

// warnNoGrantedKeys warns, before the first read of a run, when no
// held key is granted on any target server: normal right after import
// --servers-only, and then one line is enough, so the per-server fallback
// warnings drop to debug level. Warn only: first contact is what the
// fallback exists for. Skipped under --offer-all-keys; a credential error is
// left for the first connection to report.
func (s *fleetSession) warnNoGrantedKeys(ctx context.Context, servers []config.Server, preferKeys func(config.Server) []string) {
	if s.offerAll {
		return
	}
	signers, release, err := s.creds.Signers(ctx)
	if err != nil {
		return
	}
	defer release()
	for _, srv := range servers {
		granted := preferKeys(srv)
		for _, signer := range signers {
			if sshconn.GrantIndex(signer.PublicKey(), granted) >= 0 {
				return
			}
		}
	}
	s.quietFallback = true
	s.log.Warn("none of the loaded keys is granted on any target server; each server will be offered all " +
		apply.Plural(len(signers), "held key", "held keys"))
}
```

`readFleet` becomes:

```go
	s.warnNoGrantedKeys(ctx, cfg.Servers, grantedOn(cfg))
	return s.Read(ctx, verb, cfg, cfg.Servers, grantedOn(cfg))
```

In `runWorkflow`, before `workflow.Apply`:

```go
	pre.warnNoGrantedKeys(ctx, s.servers, s.preferKeys)
```

In `newApplyCmd`, `preferKeys: grantedOn(cfg),`. In `sweepAll`, before `runSweep`:

```go
	sess.warnNoGrantedKeys(ctx, cfg.Servers, grantedOn(cfg))
```

In `runSweep`: `reader := sess.reader(grantedOn(cfg))`. (`runEdit` keeps its union `preferKeys`.)

- [ ] **Step 3: Run to verify they pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/`
Expected: PASS.

**docsDelta (README "Authentication", new section "Key offering"):**

```markdown
#### Key offering

Each server is offered only the keys the manifest grants there (plus operator keys), so a managed server never learns the rest of your keys. A held key that matches through a certificate's key or its CA counts as granted.

If you hold none of the keys granted on a server (normal right after `import --servers-only`), every loaded key is offered with one warning. Before any connection, a run warns once when no loaded key is granted on any target server and silences the per-server line. The fallback is about what you **hold**, not what the server has installed: a key granted and held but not yet installed (a new VM with only its cloud-init key, or a key changed by hand in the manifest) fails with `auth`, and the report's hint names `--offer-all-keys`. There is no automatic retry, because that would hand every held key to any server that refuses the granted ones. Bootstrap: `sshepherd apply --server NAME --offer-all-keys`.
```

### Task 20: audit's and the write commands' footers, then hand back

**Files:** Modify `cmd/sshepherd/run.go:197,207` (`exitCodesAudit`, `exitCodesWrite`), `testdata/help/{audit,apply,revoke,rotate}.golden`. Test: `cmd/sshepherd/hostkey_type_exit_test.go` (new).

- [ ] **Step 1: Update the footer:**

```go
  2  critical: a missing operator key or one that cannot log in, a changed or
     @revoked host key or a changed host key type, a world-writable managed
     path, a revoked key still installed, a forged header serial, or a policy
     conflict in the manifest
```

In `exitCodesWrite`'s row `2`, extend P08's host-key clause (decision 13), keeping the rest of the row as P08 wrote it:

```go
     changed or @revoked host key or a changed host key type at the
     post-write login check, or revoke/rotate --sweep found a revoked key
     still installed
```

- [ ] **Step 2: Add the exit test** (`cmd/sshepherd/hostkey_type_exit_test.go`, on P08's `failure_exit_test.go` helpers; re-read them first). This pins round 1: the exit 2 comes from Task 2's `fleet.HostKeyAlert`, so it passes as soon as it compiles and would fail without Task 2:

```go
package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// TestApplyProbeHostKeyTypeChangedExits2 (D10b, plan decision 13): a login
// check stopped by host_key_type_changed keeps the file, reports unproven
// and exits 2, in text and in JSON.
func TestApplyProbeHostKeyTypeChangedExits2(t *testing.T) {
	useWriter(t, &fleet.UnprovenError{Path: "~/.ssh/authorized_keys", Attempts: 1, HostKey: true,
		Last: &sshconn.Error{Kind: fleet.ErrorKindHostKeyTypeChanged, Err: errors.New("host key type changed")}})
	text, doc := runApplyFailure(t, applyDrift(t, ""), 2)
	if !strings.Contains(text, "UNPROVEN:") || doc.Servers[0].Outcome != "unproven" || doc.Servers[0].ErrorKind != "host_key_type_changed" {
		t.Errorf("text:\n%s\ndoc: %+v", text, doc)
	}
}
```

- [ ] **Step 3: Regenerate and hand back.** Apply the README footer deltas.

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd/ -run TestHelp -update && make check && make integration IT_DISTRO=alpine`
Expected: PASS; read the regenerated `audit.golden`, `apply.golden`, `revoke.golden` and `rotate.golden`.

Hand back per Conventions.

**docsDelta (README "Exit codes" `audit --help` sample, row `2`, copied from `cmd/sshepherd/testdata/help/audit.golden`; row `2` audit cell of the table):**

```markdown
**Critical**: a missing operator key or an operator key present but unable to log in (`cert_only`, `expired`, `ignored`), a host key that **changed**, a host key type that changed, a host key `@revoked` in `known_hosts` (possible impersonation), a world-writable managed path, a revoked key still installed, a policy conflict (including a granted weak key), a forged header serial
```

**docsDelta (README "Exit codes" `apply`/`revoke`/`rotate --help` sample and row `2`, per decision 13; copied from the regenerated goldens):** in the row `2` cell for `apply`, `revoke` and `rotate`, extend P08's "a changed or `@revoked` host key at the login check" to "a changed or `@revoked` host key, or a changed host key type (`host_key_type_changed`), at the login check".

**docsDelta (README "Safety model → Verify, then prove you can still log in"):** P08's sentence becomes: "That is exit `1`, except that a login check stopped by a changed or `@revoked` host key, or a changed host key type, is exit `2`."

**docsDelta (README "`sshepherd apply` → JSON"):** in P08's `outcome` text, add `host_key_type_changed` to the kinds that make `unproven` exit `2`.

---

## Round 2 — lane `audit` (Tasks 21–26)

Owns: `internal/audit/*` (code, tests, `testdata/*`). Findings: SEC-1, COR-5, PRD-10, COR-6 (report side). Depends on round 1: `fleet.PostureIssue`, `authkeys.Expired`, `EarliestExpiry`, `LinesByFingerprint`, `Key.Weak`, and `fleet.ErrorKindHostKeyTypeChanged`/`HostKeyAlert`.

### Task 21: `ServerResult` carries posture and every line

**Files:** Modify `internal/audit/audit.go:68` (`Compliant`), `:124` (`auditOne`, the struct). Test: `internal/audit/trust_test.go` (new; Tasks 21-26 share the file).

- [ ] **Step 1: Create the test file:**

```go
package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// trustConfig: op (k1) is an operator, alice (k2) is granted web-1; extra
// is appended to the manifest.
func trustConfig(t *testing.T, opLine, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, comment: "op@sshepherd", keys: ["` + opLine + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
` + extra))
	if err != nil {
		t.Fatalf("trustConfig: %v", err)
	}
	return cfg
}

func pinNow(t *testing.T) {
	t.Helper()
	orig := now
	now = func() time.Time { return time.Date(2026, 6, 15, 12, 0, 0, 0, time.Local) }
	t.Cleanup(func() { now = orig })
}

func runOne(t *testing.T, cfg *config.Config, read fleet.ReadResult) ServerResult {
	t.Helper()
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": read}}
	return Run(context.Background(), cfg, r, Options{Parallel: 1})[0]
}

// content builds an authorized_keys body, one line per argument.
func content(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func reasonOf(t *testing.T, cfg *config.Config, r ServerResult) string {
	t.Helper()
	for _, k := range r.Diff.OK {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			reason, _ := r.cannotLogIn(cfg, k)
			return reason
		}
	}
	t.Fatal("no present operator key")
	return ""
}

func TestCriticalOperatorCannotLogIn(t *testing.T) {
	pinNow(t)
	op, alice := testkeys.Line(t, 1), testkeys.Line(t, 2)
	expired := `expiry-time="20260101" ` + op
	tests := []struct {
		name     string
		manifest string // the operator's manifest line; "" = op
		lines    []string
		reason   string
		status   serverStatus
	}{
		{name: "plain", lines: []string{op, alice}, status: statusCompliant},
		{name: "TestCriticalOperatorCertOnly: cert-authority on the server", lines: []string{"cert-authority " + op, alice}, reason: "cert_only", status: statusCritical},
		{name: "TestCriticalOperatorCertOnly: principals= on the server", lines: []string{`principals="ops" ` + op, alice}, reason: "cert_only", status: statusCritical},
		{name: "declared cert-authority is not cert_only", manifest: "cert-authority " + op, lines: []string{"cert-authority " + op, alice}, status: statusCompliant},
		{name: "TestCriticalOperatorExpired: undeclared passed expiry", lines: []string{expired, alice}, reason: "expired", status: statusCritical},
		{name: "TestCriticalOperatorExpired: declared passed expiry is critical too", manifest: expired, lines: []string{expired, alice}, reason: "expired", status: statusCritical},
		{name: "future expiry", lines: []string{`expiry-time="20990101" ` + op, alice}, status: statusDrift},
		{name: "TestOperatorEveryLineIgnored: bad option", lines: []string{"bogus-option " + op, alice}, reason: "ignored", status: statusCritical},
		{name: "malformed expiry is a line sshd ignores", lines: []string{`expiry-time="2027" ` + op, alice}, reason: "ignored", status: statusCritical},
		{name: "TestOperatorLaterLineLogsIn: dead first, working second", lines: []string{"cert-authority " + op, op, alice}, status: statusDrift},
		{name: "TestOperatorIgnoredThenDeadLine: ignored first, dead second", lines: []string{"bogus-option " + op, "cert-authority " + op, alice}, reason: "cert_only", status: statusCritical},
		{name: "added from= still logs in (drift, not critical)", lines: []string{`from="10.0.0.1" ` + op, alice}, status: statusDrift},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := tt.manifest
			if manifest == "" {
				manifest = op
			}
			cfg := trustConfig(t, strings.ReplaceAll(manifest, `"`, `\"`), "")
			r := runOne(t, cfg, fleet.ReadResult{Content: content(tt.lines...)})
			if got := reasonOf(t, cfg, r); got != tt.reason {
				t.Errorf("cannotLogIn = %q, want %q", got, tt.reason)
			}
			if got := statusOf(cfg, r); got != tt.status {
				t.Errorf("status = %s, want %s", got, tt.status)
			}
		})
	}
}

// TestNonOperatorDeadLineIsDrift: only operator keys are graded critical.
func TestNonOperatorDeadLineIsDrift(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), "cert-authority "+testkeys.Line(t, 2))})
	if got := statusOf(cfg, r); got != statusDrift {
		t.Errorf("status = %s, want drift", got)
	}
}

func TestPostureGrading(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	clean := content(testkeys.Line(t, 1), testkeys.Line(t, 2))
	tests := []struct {
		name  string
		issue string
		want  serverStatus
		code  int
	}{
		{"world_writable is critical", fleet.PostureWorldWritable, statusCritical, 2},
		{"group_writable is drift", fleet.PostureGroupWritable, statusDrift, 1},
		{"foreign_owner is drift", fleet.PostureForeignOwner, statusDrift, 1},
		{"symlink is drift", fleet.PostureSymlink, statusDrift, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runOne(t, cfg, fleet.ReadResult{Content: clean, Posture: []fleet.PostureIssue{{Path: "/home/d/.ssh", Issue: tt.issue, Mode: "drwxrwxrwx", UID: "1001"}}})
			if r.Compliant() {
				t.Error("a posture finding must not be compliant, even with matching keys")
			}
			if got := statusOf(cfg, r); got != tt.want {
				t.Errorf("status = %s, want %s", got, tt.want)
			}
			if got := ExitCode(cfg, []ServerResult{r}); got != tt.code {
				t.Errorf("ExitCode = %d, want %d", got, tt.code)
			}
		})
	}
}

func TestHostKeyTypeChangedIsAnAlert(t *testing.T) {
	cfg := reportConfig(t)
	r := &fakeReader{errs: map[string]error{
		"web-1": hintedErr{kindedErr{fleet.ErrorKindHostKeyTypeChanged, "ssh deploy@10.0.0.1:22: presented ecdsa-sha2-nistp256 key SHA256:abc: knownhosts: key mismatch"},
			"HOST KEY TYPE CHANGED for 10.0.0.1:22 — the server no longer presents any recorded key type (recorded: ssh-ed25519); possible impersonation"},
	}, byName: map[string]fleet.ReadResult{"web-2": {Content: content(testkeys.Line(t, 1))}}}
	results := Run(context.Background(), cfg, r, Options{Parallel: 2})
	if got := ExitCode(cfg, results); got != 2 {
		t.Errorf("ExitCode = %d, want 2", got)
	}
	if c := tallyResults(cfg, results); c.hostKeyAlerts != 1 {
		t.Errorf("hostKeyAlerts = %d, want 1", c.hostKeyAlerts)
	}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_host_key_type_changed.golden", buf.Bytes())
	checkGolden(t, "report_host_key_type_changed.golden.json", renderJSON(t, cfg, results))
}

func postureResults(t *testing.T, cfg *config.Config) []ServerResult {
	t.Helper()
	return []ServerResult{runOne(t, cfg, fleet.ReadResult{
		Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2)),
		Posture: []fleet.PostureIssue{
			{Path: "/home/deploy/.ssh", Issue: fleet.PostureWorldWritable, Mode: "drwxrwxrwx", UID: "1001"},
			{Path: "/home/deploy/.ssh/authorized_keys", Issue: fleet.PostureGroupWritable, Mode: "-rw-rw-r--", UID: "1001"},
			{Path: "/srv/keys", Issue: fleet.PostureForeignOwner, Mode: "drwxr-xr-x", UID: "1002"},
			{Path: "/home/deploy/.ssh/authorized_keys2", Issue: fleet.PostureSymlink, Mode: "lrwxrwxrwx", UID: "1001"},
		},
	})}
}

func TestReportPostureGolden(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	results := postureResults(t, cfg)
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_posture.golden", buf.Bytes())
	checkGolden(t, "report_posture.golden.json", renderJSON(t, cfg, results))
}

func TestReportOperatorCertOnlyGolden(t *testing.T) {
	pinNow(t)
	op := testkeys.Line(t, 1)
	cfg := trustConfig(t, op, "")
	var buf bytes.Buffer
	results := []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content(`expiry-time="20260101" `+op, testkeys.Line(t, 2))})}
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_operator_expired.golden", buf.Bytes())
	buf.Reset()
	results = []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content("cert-authority "+op, testkeys.Line(t, 2))})}
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_operator_certonly.golden", buf.Bytes())
	checkGolden(t, "report_operator_certonly.golden.json", renderJSON(t, cfg, results))
}

func TestReportKeyIssuesGolden(t *testing.T) {
	pinNow(t)
	op := `expiry-time=\"20260101\" ` + testkeys.Line(t, 1)
	cfg := trustConfig(t, op, "  - {user: op, servers: [web-1]}\n")
	dsa := testkeys.DSALine(t, 7)
	results := []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content(
		`expiry-time="20260101" `+testkeys.Line(t, 1), testkeys.Line(t, 2), dsa, testkeys.RSALine(t, 8, 1024),
	)})}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	for _, want := range []string{" · WEAK (dsa)", " · WEAK (rsa 1024)", "CANNOT LOG IN"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "report_key_issues.golden", buf.Bytes())
	checkGolden(t, "report_key_issues.golden.json", renderJSON(t, cfg, results))
}

func TestPresentExpiredAndWeakAnnotations(t *testing.T) {
	pinNow(t)
	dsa := testkeys.DSALine(t, 7)
	line := `expiry-time=\"20260101\" ` + dsa // a non-operator: annotations only
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: old, keys: ["` + line + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: old, servers: [web-1]}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), `expiry-time="20260101" `+dsa)})
	var buf bytes.Buffer
	Render(&buf, cfg, []ServerResult{r}, RenderOptions{})
	if !strings.Contains(buf.String(), " · WEAK (dsa) · EXPIRED") {
		t.Errorf("report lacks the annotations:\n%s", buf.String())
	}
}

// TestAnnotationsDoNotChangeExit (spec B1): EXPIRED and WEAK are
// informational. A non-operator's passed expiry on an otherwise compliant
// server exits 0, and an ungranted DSA key exits 1 as ordinary drift.
func TestAnnotationsDoNotChangeExit(t *testing.T) {
	pinNow(t)
	t.Run("non-operator with a passed desired expiry", func(t *testing.T) {
		line := testkeys.Line(t, 3)
		cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: old, keys: ["expiry-time=\"20260101\" ` + line + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: old, servers: [web-1]}
`))
		if err != nil {
			t.Fatal(err)
		}
		r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), `expiry-time="20260101" `+line)})
		var buf bytes.Buffer
		Render(&buf, cfg, []ServerResult{r}, RenderOptions{})
		if !strings.Contains(buf.String(), " · EXPIRED") {
			t.Errorf("report lacks the annotation:\n%s", buf.String())
		}
		if got := ExitCode(cfg, []ServerResult{r}); got != 0 {
			t.Errorf("ExitCode = %d, want 0", got)
		}
		if got := criticalReasons(cfg, r); got != nil {
			t.Errorf("critical reasons = %v, want none", got)
		}
	})
	t.Run("an ungranted DSA key on the server", func(t *testing.T) {
		cfg := trustConfig(t, testkeys.Line(t, 1), "")
		r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2), testkeys.DSALine(t, 7))})
		var buf bytes.Buffer
		Render(&buf, cfg, []ServerResult{r}, RenderOptions{})
		if !strings.Contains(buf.String(), "UNAUTHORIZED · WEAK (dsa)") {
			t.Errorf("report lacks the annotation:\n%s", buf.String())
		}
		if got := ExitCode(cfg, []ServerResult{r}); got != 1 {
			t.Errorf("ExitCode = %d, want 1", got)
		}
	})
}

// TestGrantedWeakKeyJSON (D29): the conflict's kind, the summary count and
// the critical reason, on the wire.
func TestGrantedWeakKeyJSON(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: old, keys: ["` + dsa + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: old, servers: [web-1]}
`))
	if err != nil {
		t.Fatal(err)
	}
	results := []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), dsa)})}
	var rep struct {
		PolicyConflicts []struct {
			Kind string `json:"kind"`
		} `json:"policy_conflicts"`
		Summary struct {
			PolicyConflicts int `json:"policy_conflicts"`
		} `json:"summary"`
		Servers []struct {
			CriticalReasons []string `json:"critical_reasons"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(renderJSON(t, cfg, results), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.PolicyConflicts) != 1 || rep.PolicyConflicts[0].Kind != "weak_key" || rep.Summary.PolicyConflicts != 1 {
		t.Errorf("report = %+v, want one weak_key conflict, counted in the summary", rep)
	}
	if got := rep.Servers[0].CriticalReasons; !slices.Equal(got, []string{"policy_conflict"}) {
		t.Errorf("critical_reasons = %v, want [policy_conflict]", got)
	}
}

func TestNoWeakAnnotationOnRevokedRow(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(dsa)
	if err != nil {
		t.Fatal(err)
	}
	cfg := trustConfig(t, testkeys.Line(t, 1), "revoked:\n  - {fingerprint: "+k.Fingerprint+", user: old, date: 2026-11-08}\n")
	results := []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2), dsa)})}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	if !strings.Contains(buf.String(), "REVOKED") || strings.Contains(buf.String(), "WEAK") {
		t.Errorf("a REVOKED row carries no WEAK note:\n%s", buf.String())
	}
	var rep struct {
		Servers []struct {
			Keys struct {
				Unauthorized []struct {
					KeyIssues []string `json:"key_issues"`
				} `json:"unauthorized"`
			} `json:"keys"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(renderJSON(t, cfg, results), &rep); err != nil {
		t.Fatal(err)
	}
	if got := rep.Servers[0].Keys.Unauthorized[0].KeyIssues; got != nil {
		t.Errorf("key_issues on a revoked key: %v", got)
	}
}

// TestCriticalReasonsAllSix: every reason at once, sorted, and absent on a
// server that is not critical.
func TestCriticalReasonsAllSix(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(testkeys.Line(t, 9))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(`users:
  - {name: gone, operator: true, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: dead, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
  - {name: old, keys: ["` + dsa + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: old, servers: [web-1]}
revoked:
  - {fingerprint: ` + k.Fingerprint + `, user: carol, date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {
			Content: content(authkeys.Header(9999), "cert-authority "+testkeys.Line(t, 4), dsa, testkeys.Line(t, 9)),
			Posture: []fleet.PostureIssue{{Path: "/x", Issue: fleet.PostureWorldWritable, Mode: "drwxrwxrwx", UID: "0"}},
		},
		"web-2": {Content: content(authkeys.Header(0), testkeys.Line(t, 3), testkeys.Line(t, 4))},
	}}
	results := Run(context.Background(), cfg, r, Options{Parallel: 1})
	want := []string{"forged_serial", "operator_cannot_log_in", "operator_missing", "policy_conflict", "revoked_key", "world_writable"}
	if got := criticalReasons(cfg, results[0]); !slices.Equal(got, want) {
		t.Errorf("reasons = %v, want %v", got, want)
	}
	if got := criticalReasons(cfg, results[1]); got != nil {
		t.Errorf("web-2 reasons = %v, want none", got)
	}
	var rep struct {
		Servers []struct {
			Status          string   `json:"status"`
			CriticalReasons []string `json:"critical_reasons"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(renderJSON(t, cfg, results), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Servers[1].CriticalReasons != nil {
		t.Errorf("critical_reasons on %s: %v", rep.Servers[1].Status, rep.Servers[1].CriticalReasons)
	}
}

func TestLinesRecordedByAuditOne(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	op := testkeys.Line(t, 1)
	r := runOne(t, cfg, fleet.ReadResult{Content: content(op, "no-pty "+op)})
	if got := len(r.Lines[fpOf(t, 1)]); got != 2 {
		t.Errorf("Lines holds %d lines, want 2", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `GOTOOLCHAIN=go1.27.3 go vet ./internal/audit/`
Expected: FAIL: `undefined: now`, `r.cannotLogIn undefined`, `undefined: criticalReasons`.

- [ ] **Step 3: Add the fields and their population.** In `ServerResult`, after `Keys2Err`:

```go
	// Posture is the posture probe's findings (fleet.ReadResult): anything
	// here is drift, and a world-writable path is critical.
	Posture []fleet.PostureIssue
	// Lines holds every parsed line per fingerprint, in file order. sshd
	// tries each line, so grading whether a key can still log in looks at
	// all of them; Diff.Actual keeps only the first.
	Lines map[string][]authkeys.Key
```

In `Compliant`, add `len(r.Posture) == 0 &&` before `!r.anyOptionsDrift()`. In `auditOne`, after `res.Keys2, res.Keys2Err = …`: `res.Posture = read.Posture`, and after `res.Duplicates = duplicatesOf(actual)`: `res.Lines = authkeys.LinesByFingerprint(actual)`.

### Task 22: one list of critical reasons

**Files:** Modify `internal/audit/report.go:395` (`criticalDrift`), `:26` (`ExitCode`'s doc comment).

- [ ] **Step 1: Implement.** Replace `criticalDrift` (add `"slices"`, `"time"` imports as needed):

```go
// criticalDrift reports drift that threatens the fleet: criticalReasons in
// short. Every status, count and exit code goes through it.
func criticalDrift(cfg *config.Config, r ServerResult) bool {
	return len(criticalReasons(cfg, r)) > 0
}

// cannotLogIn grades a matched key owned by an operator over every line sshd
// honours: a key with one usable line can log in, whatever its other lines
// say. It returns the first dead-line reason sshd honoured (expired or
// cert_only), else "ignored" when sshd ignores all of them, and the expiry
// when that is the reason. A manifest that declares cert-authority does not
// make the key cert_only. "" means the key can log in, or the owner is not
// an operator.
func (r ServerResult) cannotLogIn(cfg *config.Config, k authkeys.Key) (reason string, expired time.Time) {
	if u, ok := cfg.OwnerOf(k.Fingerprint); !ok || !u.Operator {
		return "", time.Time{}
	}
	lines := r.Lines[k.Fingerprint]
	if len(lines) == 0 {
		return "", time.Time{} // only a hand-built result: auditOne fills Lines
	}
	for _, line := range lines {
		switch {
		case authkeys.IgnoredBySSHD(line.Options) != nil:
			continue
		case authkeys.Expired(line.Options, now(), time.Local):
			if reason == "" {
				_, expired, _ = authkeys.EarliestExpiry(line.Options, time.Local)
				reason = cannotLogInExpired
			}
		case authkeys.CertOnly(line.Options) && !authkeys.CertOnly(k.Options):
			if reason == "" {
				reason = cannotLogInCertOnly
			}
		default:
			return "", time.Time{} // this line can log in
		}
	}
	if reason == "" {
		reason = cannotLogInIgnored
	}
	return reason, expired
}

// criticalReasons lists why this server is critical, sorted and without
// duplicates; nil when it is not. A missing operator key and a present one
// that cannot log in are the same emergency. An unreachable server has no
// reasons: nothing is knowable about its keys.
func criticalReasons(cfg *config.Config, r ServerResult) []string {
	if r.Err != nil {
		return nil
	}
	found := map[string]bool{
		reasonForgedSerial:  r.forged(cfg.Serial()),
		reasonPolicy:        inConflict(cfg, r.Server.Name),
		reasonWorldWritable: slices.ContainsFunc(r.Posture, func(p fleet.PostureIssue) bool { return p.Issue == fleet.PostureWorldWritable }),
	}
	for _, k := range r.Diff.Missing {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			found[reasonMissing] = true
		}
	}
	for _, k := range r.Diff.OK {
		if reason, _ := r.cannotLogIn(cfg, k); reason != "" {
			found[reasonCannotLogIn] = true
		}
	}
	for _, k := range r.Diff.Unauthorized {
		if _, revoked := cfg.Revoked(k.Fingerprint); revoked {
			found[reasonRevokedKey] = true
		}
	}
	var out []string
	for reason, on := range found {
		if on {
			out = append(out, reason)
		}
	}
	slices.Sort(out)
	return out
}
```

Add these constants and the clock seam beside them:

```go
// The critical_reasons values: why a server is critical.
const (
	reasonForgedSerial  = "forged_serial"
	reasonCannotLogIn   = "operator_cannot_log_in"
	reasonMissing       = "operator_missing"
	reasonPolicy        = "policy_conflict"
	reasonRevokedKey    = "revoked_key"
	reasonWorldWritable = "world_writable"
)

// The cannot_log_in values on a present operator key.
const (
	cannotLogInCertOnly = "cert_only"
	cannotLogInExpired  = "expired"
	cannotLogInIgnored  = "ignored"
)

// now is the expiry clock, a seam so tests pin it.
var now = time.Now
```

Update `ExitCode`'s doc comment to name `criticalReasons`, a posture finding short of world-writable (exit 1) and the new host-key kinds; `ExitCode`'s body does not change (host-key alerts already go through `hostKeyAlert`, which P08 made a one-line call).

- [ ] **Step 2: Run to verify the grading passes**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run 'TestCriticalOperatorCannotLogIn|TestNonOperatorDeadLine|TestPostureGrading|TestCriticalReasons|TestLinesRecorded'`
Expected: PASS; other new tests still fail on missing report work.

**docsDelta:** none.

### Task 23: posture lines in the report

**Files:** Modify `internal/audit/report.go:156` (`renderServer`).

- [ ] **Step 1: Implement.** In `renderServer`, call `renderPosture(w, r, pal)` immediately before `renderMemoryNotes` (after the `authorized_keys2` block). Add:

```go
// renderPosture prints one line per posture finding, then the shared note.
func renderPosture(w io.Writer, r ServerResult, pal palette) {
	const ignored = "sshd's StrictModes would ignore this file"
	for _, p := range r.Posture {
		switch p.Issue {
		case fleet.PostureWorldWritable:
			fmt.Fprintf(w, "  %s unsafe permissions: %s is world-writable (%s, uid %s) — anyone on the host can add a key; %s\n", pal.paint(codeBoldRed, "‼"), p.Path, p.Mode, p.UID, ignored)
		case fleet.PostureGroupWritable:
			fmt.Fprintf(w, "  ⚠ unsafe permissions: %s is group-writable (%s, uid %s) — %s\n", p.Path, p.Mode, p.UID, ignored)
		case fleet.PostureForeignOwner:
			fmt.Fprintf(w, "  ⚠ unsafe permissions: %s is owned by uid %s, not the login user or root — %s\n", p.Path, p.UID, ignored)
		case fleet.PostureSymlink:
			fmt.Fprintf(w, "  ⚠ unsafe permissions: %s is a symlink — apply refuses to write through it\n", p.Path)
		}
	}
	if len(r.Posture) > 0 {
		fmt.Fprintln(w, "  note: fix by hand (chmod go-w / chown); a login that succeeded here came through another key source or with StrictModes off")
	}
}
```

- [ ] **Step 2: Generate the golden and read it**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run 'TestReportPostureGolden' -update`
Expected: PASS; read `testdata/report_posture.golden` line by line against spec "Text report wording" (four `unsafe permissions` lines, the `note:` line once, before the `→` count).

**docsDelta (README "`sshepherd audit`", drift classes):**

```markdown
- **Unsafe permissions** — audit checks what sshd's StrictModes checks: the managed file and its directories up to `$HOME` (up to `/` for an override path outside it). A group-writable path, a path owned by neither the login user nor root, or a symlinked managed file is drift (exit 1); a world-writable path is critical (exit 2), since anyone on the host can add a key. The report says to fix by hand (`chmod go-w`, `chown`); `apply` refuses to write through these paths (exit 48 in the write script; 45 for a symlinked managed file). A root-owned file audits clean, though `apply` refuses to write it. The probe is evidence about an honest server: a compromised one can print nothing and look clean.
```

README "`sshepherd audit`", error-kinds text, add (D14b): a failed or malformed posture probe makes the server unreachable with `error_kind: remote` (exit 1), so a server cannot be graded clean while hiding its posture.

README "Per-server `authorized_keys_file`", add: override paths outside `$HOME` are walked up to `/`; a symlinked managed file is drift at exit 1 (OP1); a root-owned override audits clean although `apply` refuses it (D14a).

### Task 24: `okStatus` — cannot log in, weak, expired

**Files:** Modify `internal/audit/report.go:269` (`okStatus`), `renderServer`'s unauthorized row.

- [ ] **Step 1: Implement.** Replace `okStatus` and add helpers:

```go
// okStatus renders a matched key's glyph and status cell. An operator key
// that cannot log in outranks every other cell: it is the same class as a
// missing operator key.
func okStatus(cfg *config.Config, r ServerResult, k authkeys.Key, pal palette, comments bool) (glyph, status string) {
	glyph = pal.paint(codeGreen, "✓")
	status = "present & authorized"
	reason, expired := r.cannotLogIn(cfg, k)
	switch actual, desired, drifted := r.optionsDrift(k); {
	case reason != "":
		glyph = pal.paint(codeBoldRed, "‼")
		status = fmt.Sprintf("present but %s (%s: operator key; %s)",
			pal.paint(codeRed, "CANNOT LOG IN"), pal.paint(codeBoldRed, "CRITICAL"), cannotLogInText(reason, expired))
	case drifted:
		// Options drift is security drift (a stripped from=/command=/restrict
		// widens the key's power), so it changes the glyph and the verdict;
		// %q keeps hostile option text on one inert line.
		glyph = pal.paint(codeYellow, "⚠")
		status = fmt.Sprintf("present but %s (server: %s · manifest: %s)",
			pal.paint(codeYellow, "OPTIONS DIFFER"), quoteOptions(actual), quoteOptions(desired))
	}
	// Plain text on purpose: no new SGR codes, so the color-stripped-
	// equals-plain invariant keeps holding.
	if actual, desired, drifted := commentDrift(cfg, r, k); comments && drifted {
		status += fmt.Sprintf(" · comment differs: %q → %q", actual, desired)
	}
	status += weakNote(k)
	if reason == "" && authkeys.Expired(k.Options, now(), time.Local) {
		status += " · EXPIRED"
	}
	return glyph, status
}

// weakNote is a key's WEAK annotation; "" for an acceptable key.
func weakNote(k authkeys.Key) string {
	switch k.Weak {
	case authkeys.WeakDSA:
		return " · WEAK (dsa)"
	case authkeys.WeakRSAUnder2K:
		return fmt.Sprintf(" · WEAK (rsa %d)", k.WeakBits)
	}
	return ""
}

// cannotLogInText ends a CANNOT LOG IN row with the reason.
func cannotLogInText(reason string, expired time.Time) string {
	switch reason {
	case cannotLogInCertOnly:
		return "server line is cert-only"
	case cannotLogInExpired:
		return "server line expired " + expired.Format(time.DateOnly)
	default:
		return "sshd ignores every line holding it"
	}
}
```

In `renderServer`, in the unauthorized row (not the `REVOKED` branch), append `weakNote(k)`:

```go
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tinstalled but %s%s%s\n",
			pal.paint(codeYellow, "⚠"), unauthorizedLabel(cfg, r.Server.Name, k), k.Fingerprint, k.Type,
			pal.paint(codeYellow, "UNAUTHORIZED"), suffix, weakNote(k))
```

- [ ] **Step 2: Generate the goldens and read them**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run 'Golden|Annotations|NoWeak' -update`
Expected: PASS; read `report_operator_certonly.golden`, `report_operator_expired.golden` and `report_key_issues.golden` against the spec's wording. `TestRenderColorStrippedEqualsPlain` must still pass.

**docsDelta (README "`sshepherd audit`"):**

```markdown
- **Operator key that cannot log in** — a present operator key on a line sshd will not honour (a `cert-authority`/`principals=` line the manifest does not declare, a passed `expiry-time` whether declared or not, or every line ignored) is critical. Audit checks every line of a key, as sshd does: a working second line keeps it non-critical.
- Rows are annotated ` · WEAK (dsa)`, ` · WEAK (rsa 1024)` and ` · EXPIRED`; annotations alone do not change the exit code.
```

### Task 25: the JSON report

**Files:** Modify `internal/audit/json.go:186` (`jsonServerFor`), `:303` (`jsonKeyFor`, comment), the `jsonServer`/`jsonKey` structs.

- [ ] **Step 1: Implement.** Add `"time"` to `json.go`'s imports (`keyIssues` uses `time.Local`). Add to `jsonServer`:

```go
	// Posture and CriticalReasons are additive-optional (schema stays 1):
	// the posture probe's findings, and exactly when status is critical why,
	// sorted and de-duplicated.
	Posture         []jsonPosture `json:"posture,omitempty"`
	CriticalReasons []string      `json:"critical_reasons,omitempty"`
```

Add to `jsonKey`:

```go
	// CannotLogIn (a present operator key that is critical) and KeyIssues
	// (dsa, rsa_under_2048, expired; never on a revoked key) are
	// additive-optional (schema stays 1).
	CannotLogIn string   `json:"cannot_log_in,omitempty"`
	KeyIssues   []string `json:"key_issues,omitempty"`
```

Add the type and helpers:

```go
type jsonPosture struct {
	Path  string `json:"path"`
	Issue string `json:"issue"`
	Mode  string `json:"mode"`
	UID   string `json:"uid"`
}

// jsonPresentKey is one matched key, with its drift, cannot_log_in and
// key_issues findings.
func jsonPresentKey(cfg *config.Config, r ServerResult, k authkeys.Key, opts JSONOptions) jsonKey {
	jk := jsonKeyFor(cfg, k, false)
	if actual, desired, drifted := r.optionsDrift(k); drifted {
		jk.OptionsDrift = &jsonOptionsDrift{Actual: sanitizeAll(actual), Desired: sanitizeAll(desired)}
	}
	if actual, desired, drifted := commentDrift(cfg, r, k); opts.Comments && drifted {
		jk.CommentDrift = &jsonCommentDrift{Actual: sanitize.Remote(actual), Desired: sanitize.Remote(desired)}
	}
	if reason, _ := r.cannotLogIn(cfg, k); reason != "" {
		jk.CannotLogIn, jk.Operator = reason, true
	}
	jk.KeyIssues = keyIssues(k, true)
	return jk
}

// keyIssues lists a key's strength finding and, for a desired key, whether
// its expiry-time has passed; nil when there are none (omitted).
func keyIssues(k authkeys.Key, desired bool) []string {
	var out []string
	if k.Weak != "" {
		out = append(out, k.Weak)
	}
	if desired && authkeys.Expired(k.Options, now(), time.Local) {
		out = append(out, cannotLogInExpired)
	}
	return out
}

// postureJSON is the server's posture findings; nil when clean (omitted).
func postureJSON(r ServerResult) []jsonPosture {
	var out []jsonPosture
	for _, p := range r.Posture {
		out = append(out, jsonPosture{Path: sanitize.Remote(p.Path), Issue: p.Issue, Mode: p.Mode, UID: p.UID})
	}
	return out
}
```

In `jsonServerFor`, before `serialFields`:

```go
	s.Posture, s.CriticalReasons = postureJSON(r), criticalReasons(cfg, r)
```

replace the present-key loop body with `s.Keys.Present = append(s.Keys.Present, jsonPresentKey(cfg, r, k, opts))`, and after `memoryKey(&jk, cfg, r.Server.Name, k)` add:

```go
		if jk.Revoked == nil {
			jk.KeyIssues = keyIssues(k, false)
		}
```

Update `jsonKeyFor`'s doc comment: `operator: true` now also appears on a present key that cannot log in (set in `jsonPresentKey`).

- [ ] **Step 2: Generate and read the JSON goldens**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -update && GOTOOLCHAIN=go1.27.3 go test ./internal/audit/`
Expected: PASS. Existing golden changes are exactly: `report_critical.golden.json` gains `critical_reasons: ["operator_missing"]`, `report_revoked.golden.json` gains `["policy_conflict", "revoked_key"]`, `report_serial_ahead.golden.json` gains `["forged_serial"]` on the forged row. Any other change is a bug.

**docsDelta (README "`sshepherd audit`", JSON section):**

```markdown
- Server: `posture`: `[{"path", "issue", "mode", "uid"}]`; `critical_reasons`: sorted list from `forged_serial`, `operator_cannot_log_in`, `operator_missing`, `policy_conflict`, `revoked_key`, `world_writable`, present exactly when `status` is `critical`. A host-key alert is `status: unreachable` and carries no reason; `error_kind` and `summary.host_key_alerts` say why.
- Key: `cannot_log_in` (`cert_only`, `expired`, `ignored`) on a present operator key that is critical, with `operator: true`; `key_issues` (`dsa`, `rsa_under_2048`, `expired`), never on a key with `revoked`.
- `policy_conflicts` carries the new `kind: "weak_key"`. New `error_kind`: `host_key_type_changed`.
```

Sample objects copied from `testdata/report_posture.golden.json`, `report_key_issues.golden.json`.

### Task 26: host-key type change in the report, then hand back

**Files:** none beyond the shared test file (`TestHostKeyTypeChangedIsAnAlert`).

- [ ] **Step 1: Generate the golden and read it**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/audit/ -run TestHostKeyTypeChanged -update`
Expected: PASS; `report_host_key_type_changed.golden` shows `ERROR [host_key_type_changed]:` and `1 HOST KEY ALERT`.

- [ ] **Step 2: Hand back**

Run: `make check`
Expected: PASS.

Hand back per Conventions.

**docsDelta:** none (Task 15 documents the kind).

---

## Round 3 — lane `e2e` (Task 27)

Owns: `cmd/sshepherd/e2e_test.go`, `scripts/integration.sh`. Findings: SEC-1 (end to end). Tasks 28 and 29 follow this round and belong to no lane.

### Task 27: the posture E2E

**Files:** Modify `scripts/integration.sh`, `cmd/sshepherd/e2e_test.go`.

- [ ] **Step 1: Add the fixture user.** In `FIXTURE_A`, add `e2eloose` to the three user lists, and replace the `loose` block (lane `posture`) with:

```sh
    # loose: logs in through its 0700 ~/.ssh; the managed override sits below
    # a 0775 ~/loose (posture finding), which sshd never reads.
    # e2eloose: the same, for the E2E that tightens the mode and re-audits.
    for u in loose e2eloose; do
      mkdir -p "/home/$u/loose" && cp /seed/key.pub "/home/$u/loose/keys"
      chown -R "$u:$u" "/home/$u/loose" && chmod 775 "/home/$u/loose" && chmod 600 "/home/$u/loose/keys"
    done
```

- [ ] **Step 2: Write the E2E test** (append to `cmd/sshepherd/e2e_test.go`):

```go
// e2eRemote runs a shell script on the container as user.
func e2eRemote(t *testing.T, host, port, kh, user, script string) string {
	t.Helper()
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	d := &sshconn.Dialer{KnownHostsPath: kh, Creds: &sshconn.Credentials{AgentSock: os.Getenv("SSH_AUTH_SOCK")}, DialTimeout: 10 * time.Second}
	conn, err := d.Connect(ctx, config.Server{Name: user, Host: host, Port: p, User: user})
	if err != nil {
		t.Fatalf("connect %s: %v", user, err)
	}
	defer func() { _ = conn.Close() }()
	code, stdout, stderr, err := sshconn.Exec(ctx, conn.Client, script, nil)
	if err != nil || code != 0 {
		t.Fatalf("remote: code %d, err %v, stderr %q", code, err, stderr.String())
	}
	return stdout.String()
}

// TestE2EPostureGroupWritable: a 0775 directory on the managed path is
// drift (exit 1, group_writable), apply refuses to write through it, and
// tightening the mode by hand makes the audit clean. The override sits
// below ~/loose because the container runs StrictModes yes: a 0775 ~/.ssh
// would lock the login out before audit could see anything.
func TestE2EPostureGroupWritable(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
servers:
  - {name: e2eloose, host: `+host+`, port: `+port+`, user: e2eloose, authorized_keys_file: ~/loose/keys}
`)
	code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh)
	if code != 1 {
		t.Fatalf("audit exit = %d, want 1 (stderr: %s)\n%s", code, stderr, out)
	}
	if !strings.Contains(out, "group-writable") || !strings.Contains(out, "/home/e2eloose/loose") {
		t.Errorf("audit lacks the finding:\n%s", out)
	}
	if code, out, stderr = runBin(t, bin, "audit", "--json", "--config", m, "--known-hosts", kh); code != 1 {
		t.Fatalf("audit --json exit = %d, want 1 (stderr: %s)\n%s", code, stderr, out)
	}
	var rep struct {
		Servers []struct {
			Posture []struct {
				Issue string `json:"issue"`
			} `json:"posture"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("audit --json: %v\n%s", err, out)
	}
	if len(rep.Servers) != 1 || len(rep.Servers[0].Posture) != 1 || rep.Servers[0].Posture[0].Issue != "group_writable" {
		t.Errorf("posture = %+v, want one group_writable finding", rep.Servers)
	}
	if code, out, stderr = runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 1 {
		t.Fatalf("apply exit = %d, want 1 (stderr: %s)\n%s", code, stderr, out)
	}
	// UnsafePathError's text: the write script exited 48.
	if !strings.Contains(out+stderr, "ancestor directory is writable by or owned by another user") {
		t.Errorf("apply did not refuse the writable path with 48:\n%s\n%s", out, stderr)
	}
	e2eRemote(t, host, port, kh, "e2eloose", `chmod 755 "$HOME/loose"`)
	if code, out, stderr = runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit after the fix exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
}
```

- [ ] **Step 3: Prove it fails before P09.** In a scratch worktree of the lane's base with lane `audit`'s `Compliant` change reverted (or against the tree before round 2), run `make integration IT_DISTRO=alpine` and see `audit exit = 0, want 1`.

- [ ] **Step 4: Run the full suite on every distro, then hand back**

Run: `make integration IT_DISTRO=alpine && make integration IT_DISTRO=debian && make integration IT_DISTRO=rocky`, then `make check`.
Expected: PASS on all three.

Hand back per Conventions.

**docsDelta:** none.

### Task 28: integrator-only documents

This task is the integrator's after round 3 merges. No lane owns it. Task 29 follows it.

- [ ] **Step 1: Re-run the fan-out benchmarks** (the posture session replaced the probe session, so a read stays at two sessions):

Run: `make bench` and confirm `--parallel 32` still sits on the plateau.

- [ ] **Step 2: Copy the sample output from the goldens into README** (`report_posture.golden`, `report_operator_certonly.golden`, `report_key_issues.golden`, `report_host_key_type_changed.golden`, the JSON ones) and apply every task's `docsDelta`. Read the README diff top to bottom.

- [ ] **Step 3: Apply these remaining edits.**

**docsDelta (README intro, spec section 6):** the intro sentence "reads every server, tells you exactly how reality differs from the manifest" becomes "reads every managed `authorized_keys` file, tells you exactly how each differs from the manifest".

**docsDelta (README "Status", a paragraph after "Revocation memory"):**

```markdown
Audit trust and posture: audit checks the managed file and its directories the way StrictModes does, and pages on a world-writable path, an operator key that cannot log in, a host key whose type changed, and a weak key granted on a server. Each server is offered only its granted keys (`--offer-all-keys` restores the old offer).
```

**docsDelta (README "Safety model" connection posture):**

```markdown
Each server is offered only the keys the manifest grants there (`--offer-all-keys` turns the filter off), and a server presenting a different host key type than `known_hosts` records, or a certificate no `@cert-authority` line for this host vouches for, is an impersonation alarm (`host_key_type_changed`, exit 2). Audit's posture check mirrors StrictModes.
```

**docsDelta (README "Exit codes" table, audit cells):**

- Row `1`: "Drift or unreachable servers — compliance not proven; a server serial ahead of the manifest; a key installed where its access was revoked; a posture finding short of world-writable (`symlink`, `foreign_owner`, `group_writable`); a failed or malformed posture probe (`error_kind: remote`); `host_key_type_unrecorded`, now only when every recorded type is unsupported; an invalid certificate from a vouched CA (`host_key`)".
- Row `2`: as in Task 20.
- Row `3`, `audit`: add nothing; saving commands: as in Task 11.

**docsDelta (CLAUDE.md Status, a new paragraph; keep the existing text in the same voice):**

```markdown
**Audit trust and connection posture** (P09, specced in
`docs/superpowers/specs/2026-11-08-audit-trust-posture-design.md`, planned in
`docs/superpowers/plans/2026-11-08-audit-trust-posture.md`): every read runs a
fail-closed posture probe in its own session (`sshconn.PostureCmdFor`, sharing
`AncestorWalk` with the write scripts); audit grades group-writable, foreign-owned
and symlinked paths as drift and world-writable as critical. Operator keys are
graded over every line sshd honours (`cert_only`, `expired`, `ignored` are critical),
`host_key_type_changed` exits 2, each server is offered only its granted keys
(`--offer-all-keys`, one preflight warning, no automatic retry after an `auth`
failure), and DSA/RSA<2048 keys are policy conflicts through D29 (the save rule
refuses only a save that adds one; a removal-only write proceeds). `critical_reasons`
lists all six classes. JSON stays schema 1.
```

**docsDelta (spec Status, `docs/superpowers/specs/2026-11-08-audit-trust-posture-design.md`):** `Implementation landed in W6.`

**docsDelta (same spec, section 3 and "Out of scope", per decision 13):** after "this spec does not change for those commands" add "; P08's D10b later added `host_key_type_changed` to exit 2 at the post-write login check, through `fleet.HostKeyAlert`". On the Out of scope line "Changing apply/revoke/rotate exit codes for host-key kinds", append "(apart from D10b above)".

**docsDelta (same spec, "Testing", so the approved text matches what was built):** in B1's golden list, replace `report_error_kinds` with `report_host_key_type_changed` and add `report_operator_expired`; `report_error_kinds` stays byte-identical. In the E2E line, replace "chmod 0775 on `~/.ssh` in a container" with "a 0775 directory above an `authorized_keys_file` override (`~/loose`) in a container, because sshd's StrictModes would lock out a login through a 0775 `~/.ssh`". After section 5's `validate` line add "(built with D25; plan decision 14)".

**docsDelta (`docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md`, appended):**

```markdown
Additive to schema 1 (P09): server `posture`, `critical_reasons`; key `cannot_log_in`, `key_issues`; `operator: true` on a present key that is critical; `error_kind: host_key_type_changed`; `policy_conflicts`/`summary.policy_conflicts` carry `kind: "weak_key"`.
```

**docsDelta (`docs/superpowers/specs/2026-07-06-audit-slice-design.md`, Tuning resolution, one line):**

```markdown
P09 replaced the authorized_keys2 probe with the posture session, so a read stays at two sessions on every path; `make bench` confirms `--parallel 32` is unchanged.
```

**docsDelta (`docs/superpowers/specs/2026-11-08-revocation-memory-design.md`, section 2, one line):**

```markdown
See `2026-11-08-audit-trust-posture-design.md` for the `weak_key` conflict kind and its save rule: a save is refused only when it adds a weak key.
```

**Release note (not a repo file; the integrator puts this text in the run's final report).** The repository has no changelog and `release.yml` uses `gh release create --generate-notes`, so the owner adds it to the next tag's release:

```markdown
**Upgrade note:** weak keys (DSA, RSA under 2048 bits) are now a policy problem. A manifest holding one keeps loading, but every server granting that key goes critical, so a scheduled `audit` that passed before now exits 2, and `apply` skips those servers. A weak operator key freezes every grant on every server until `rotate` replaces it; removals still land. `rotate` and `revoke --key` are the way out and always save.
```

### Task 29: independent verification (Acceptance)

This task is the independent verifier's, after Task 28 is committed. It is read-only: findings go to the repair pass. No lane owns it.

- [ ] **Step 1: Run the gates**

Run: `GOTOOLCHAIN=go1.27.3 make check`, then `make integration` for `IT_DISTRO=alpine`, `debian` and `rocky`.
Expected: PASS on all.

- [ ] **Step 2: The README exit table against `audit.ExitCode`.** Read `ExitCode`, `criticalReasons` and `hostKeyAlert` in `internal/audit`, and the README "Exit codes" table. Every case the code returns appears in its row, and no row claims a case the code does not produce.

- [ ] **Step 3: Re-check each exit row on a real run.** Drive the built binary against the integration containers where a fixture exists, otherwise the named hermetic test. Record the observed exit for each row:

| Exit | Case (spec "Exit codes", plan decision 13) | Check |
|---|---|---|
| 1 | posture `group_writable` | `TestE2EPostureGroupWritable`, JSON `posture[].issue` |
| 1 | posture `symlink` | `audit` as fixture user `sym`; `TestPostureGrading` |
| 1 | posture `foreign_owner` | `audit` of `~/shared/keys/authorized_keys` as fixture user `fanc`; `TestPostureGrading` |
| 1 | posture probe failed or malformed | `TestReadFailsClosedOnBadPosture`, `TestPostureFailedLsFailsClosed`; `error_kind: remote` in `--json` |
| 1 | `host_key_type_unrecorded`, only unsupported types recorded | `audit` with `known_hosts` recording only `ssh-dss` for the container; `TestHostKeyTypeClassification` |
| 1 | a server refused for a granted weak key | `TestRotateReplacesWeakKeyWhileApplyRefuses`, `TestRotateSavesWhileAnotherWeakKeyRefusesThePush` |
| 2 | posture `world_writable` | as `e2eloose`, `chmod 777 ~/loose`, then `audit`; `TestPostureGrading` |
| 2 | operator key `cert_only`, `expired`, `ignored` | edit the operator's line on a container user, then `audit`; `TestCriticalOperatorCannotLogIn` |
| 2 | `host_key_type_changed` | `audit` with `known_hosts` recording only a type the container does not serve; `TestHostKeyTypeChangedIsAnAlert` |
| 2 | a weak key granted on a server | `TestGrantedWeakKeyAuditExits2`, `TestGrantedWeakKeyJSON` |
| 2 | `apply`/`revoke`/`rotate`: login check stopped on `host_key_type_changed` | `TestApplyProbeHostKeyTypeChangedExits2` |
| 3 | a save that would add a DSA or RSA<2048 key | `rotate USER --old FP --new dsa.pub` on a scratch manifest; `TestSaveRefusedWhenAddingWeakKey` |
| 3 | `validate` | not built (decision 14): confirm the command is still absent and the README does not claim it |

- [ ] **Step 4: `FinishPosture`'s hostile-output parsing.** Read `FinishPosture` and `TestFinishPosture`, then run `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn/ -run '^$' -fuzz '^FuzzFinishPosture$' -fuzztime 2m`. Confirm garbage lines, an unknown issue, a bad mode or uid, 65 records, output at the capture limit, a path with a newline, no final newline and a non-zero exit each return `ErrorKindRemote` and never a clean result.

**docsDelta:** none.

---

## Review log

Two independent reviews of the draft, each issue checked against the code at `4390667`, the P08 plan and spec, and the approved P09 spec. All 28 issues were confirmed and applied; none was rejected. The code added in this revision was written read-only and has not been compiled or run; the lanes' failing-first runs are its first execution.

| Review | Issue | Result |
|---|---|---|
| 0.1 | `NothingCanLand` withholds OP4 saves | Applied: decision 6 reversed in place, `WeakRefused`, three `run()` tests (Tasks 10, 14). A weak refusal beside another refusal still withholds. |
| 0.2 | Unannounced exit-code change on write commands | Applied: decision 13, Task 20 footer, goldens, test and README text, Task 28 spec amendment. |
| 0.3 | `--offer-all-keys` with `--no-apply` | Applied: `connectionFlags`, `TestRevokeUsage` row (Task 18). |
| 0.4 | Annotations without exit change | Applied: `TestAnnotationsDoNotChangeExit` (Task 21). |
| 0.5 | D14a has no real test | Applied: `TestIntegrationPostureRootOwnedClean` (Task 6). The `ffile`/`fdir` fixtures are read-only and safe to share. |
| 0.6 | E2E too loose | Applied: `UnsafePathError` text, `audit --json` posture assertion (Task 27). |
| 0.7 | Acceptance has no task | Applied: Task 29. |
| 0.8 | README and release-note gaps | Applied: Tasks 9, 11, 23, 28. There is no changelog, so the release note goes in the final report. |
| 0.9 | JSON kind and counts unasserted | Applied, split by round: `critical_reasons` lands in round 2, so Task 14 asserts the kind and summary (audit and apply) and `TestGrantedWeakKeyJSON` (Task 21) asserts all three. |
| 0.10 | Preflight tested on audit only | Applied: apply assertion, `TestPreflightWarnsOnceOnRevoke` (Task 18). |
| 0.11 | Weak assertions | Applied: `level=DEBUG`; one connection and two sessions (Tasks 17, 18). |
| 0.12 | Both-kinds server untested | Applied: `TestWeakAndRevokedKeyHasNoRemovalException` (Task 10). |
| 0.13 | Dangling symlinked ancestor | Applied as a fix, no spec amendment: its owner is reported (decision 5, Task 4). |
| 0.14 | `ls` failure | Applied: `TestPostureFailedLsFailsClosed`, decision 15. |
| 0.15 | Test and golden names | Applied: rows renamed (Task 21), spec Testing amendment (Task 28). |
| 0.16 | `validate` | Applied: decision 14. |
| 1.1 | Task 11 imports | Applied: imports moved to Tasks 11, 13, 14. |
| 1.2 | Task 7 cannot pass | Applied: expiry tests moved to Task 8. |
| 1.3 | Task 16 cannot pass | Applied: interim `ConnectWith` call in Task 16, replaced in Task 17. |
| 1.4 | gosec G115 in `testkeys` | Applied: `#nosec` (Task 7). |
| 1.5 | Fuzz corpus at the cap | Applied: `seed-dsa` replaces `dde7a120ccdf11af` (Task 7). |
| 1.6 | `json.go` missing `time` | Applied (Task 25). |
| 1.7 | Vacuous offer test | Applied: two refused grants; old code logs in with key 3 and fails (Task 17). |
| 1.8 | Lane `e2e` owned Task 28 | Applied: `"Task 27"`, and a new heading (Round 3). |
| 1.9 | Lost keys2 rows | Applied: both rows added (Task 4). |
| 1.10 | Wire-value map | Applied (Task 2). |
| 1.11 | Panic on empty posture | Applied (Task 6). |
| 1.12 | Unlabelled pins | Applied: labelled, except the two weak-refusal tests, which now fail first on `WeakRefused`. |

## Wave lanes (for the runner)

Rounds run in sequence; lanes inside a round own disjoint files and build only on the previous rounds' commits. Globs are shell `case` patterns (`*` crosses `/`). `README.md` and `CLAUDE.md` belong to no lane: each lane hands its text over as `docsDelta` (and applies it locally only to pass `make check`). The integrator commits once per lane, in the order the rounds list them, then runs Task 28; an independent verifier then runs Task 29.

```json
{
  "rounds": [
    [
      {
        "pkg": "P09",
        "lane": "posture",
        "kind": "fix",
        "ids": ["SEC-1"],
        "tasks": "Tasks 1-6",
        "files": [
          "internal/fleet/*",
          "internal/sshconn/sshconn.go",
          "internal/sshconn/sshconn_test.go",
          "internal/sshconn/posture.go",
          "internal/sshconn/posture_test.go",
          "internal/sshconn/fuzz_test.go",
          "internal/sshconn/testdata/fuzz/FuzzFinishPosture/*",
          "internal/sshread/*",
          "internal/sshwrite/sshwrite.go",
          "internal/sshwrite/scripts_golden_test.go",
          "internal/sshwrite/testdata/script_*.golden",
          "scripts/integration.sh"
        ],
        "needsIntegration": true
      },
      {
        "pkg": "P09",
        "lane": "keypolicy",
        "kind": "fix",
        "ids": ["PRD-10"],
        "tasks": "Tasks 7-14",
        "files": [
          "internal/authkeys/*",
          "internal/testkeys/*",
          "internal/config/*",
          "internal/apply/plan.go",
          "internal/apply/serial.go",
          "internal/apply/predicates.go",
          "internal/apply/predicates_test.go",
          "internal/apply/weak_test.go",
          "internal/adopt/*",
          "internal/identity/*",
          "cmd/sshepherd/conflicts.go",
          "cmd/sshepherd/conflicts_test.go",
          "cmd/sshepherd/adopt.go",
          "cmd/sshepherd/import.go",
          "cmd/sshepherd/editrun.go",
          "cmd/sshepherd/run.go",
          "cmd/sshepherd/testdata/help/adopt.golden",
          "cmd/sshepherd/testdata/help/apply.golden",
          "cmd/sshepherd/testdata/help/import.golden",
          "cmd/sshepherd/testdata/help/revoke.golden",
          "cmd/sshepherd/testdata/help/rotate.golden"
        ],
        "needsIntegration": false
      }
    ],
    [
      {
        "pkg": "P09",
        "lane": "transport",
        "kind": "fix",
        "ids": ["COR-6", "SEC-5"],
        "tasks": "Tasks 15-20",
        "files": [
          "internal/sshconn/hostkey.go",
          "internal/sshconn/hostkey_test.go",
          "internal/sshconn/connect.go",
          "internal/sshconn/connect_test.go",
          "internal/sshconn/offer_test.go",
          "internal/sshconn/sshconn_test.go",
          "internal/sshread/*",
          "cmd/sshepherd/fleet.go",
          "cmd/sshepherd/apply.go",
          "cmd/sshepherd/sweep.go",
          "cmd/sshepherd/editrun.go",
          "cmd/sshepherd/run.go",
          "cmd/sshepherd/offer_test.go",
          "cmd/sshepherd/hostkey_type_exit_test.go",
          "cmd/sshepherd/revoke_test.go",
          "cmd/sshepherd/identity_integration_test.go",
          "cmd/sshepherd/testdata/help/*.golden"
        ],
        "needsIntegration": true
      },
      {
        "pkg": "P09",
        "lane": "audit",
        "kind": "fix",
        "ids": ["SEC-1", "COR-5", "COR-6", "PRD-10"],
        "tasks": "Tasks 21-26",
        "files": [
          "internal/audit/*"
        ],
        "needsIntegration": false
      }
    ],
    [
      {
        "pkg": "P09",
        "lane": "e2e",
        "kind": "fix",
        "ids": ["SEC-1"],
        "tasks": "Task 27",
        "files": [
          "cmd/sshepherd/e2e_test.go",
          "scripts/integration.sh"
        ],
        "needsIntegration": true
      }
    ]
  ],
  "mergeOrder": ["P09"]
}
```
