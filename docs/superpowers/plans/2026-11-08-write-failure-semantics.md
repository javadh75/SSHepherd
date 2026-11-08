# Write-path failure semantics (P08-impl, W5) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. This plan is executed by the wave runner of `docs/superpowers/plans/2026-11-07-review-remediation.md` ("Reusable workflow skeleton"): lane agents work in git worktrees, never commit, and hand back ownership-filtered patches; the integrator commits once per lane. Where a task says "Hand back", that is the lane's last step — not a commit.

**Goal:** Build the approved write-failure design (`docs/superpowers/specs/2026-11-08-write-failure-semantics-design.md`, findings WP-1, WP-2, WP-6, WP-7, WP-8, plus the W4 `Reserial` size follow-up): login-check failures sorted by the stage they reached (UNPROVEN keeps the file, REJECTED restores it), exit 2 for an unrestored lockout, a rollback that reinstates a revoked key and a post-write host-key alarm, self-describing locks that are never removed automatically, a reconnect-and-recheck after a dropped connection, backups that are never destroyed, a warn-only headless key-file proof, and a pre-prompt size check for the serial bump.

**Architecture:** `internal/sshconn` learns three facts at the handshake site (did the host key verify, was every `Only` key offered, did a signer fail). `internal/sshwrite` gains `classifyProbe` (a pure stage + kind verdict), a retry loop inside one budget rule, a `writeSession` that owns the current connection and its single reconnect, a lock owner record and non-destructive `authorized_keys2` retention. `internal/fleet` carries the typed outcomes the domain reads (`UnprovenError`, `LockoutError`, `HostKeyAlert`), so `internal/apply` maps them to two new outcomes, the exit-2 set and the reports without importing the transport.

**Tech Stack:** Go 1.27.3 (`GOTOOLCHAIN=go1.27.3`, the Makefile's `GO_PIN`), `golang.org/x/crypto/ssh` through the hermetic `internal/sshconn/sshtest` server, goleak, golden files (`-update`), native fuzzing (`FuzzParseLockOwner`), golangci-lint v2.15.0 (depguard layering, gocyclo 15, dupl), `deadcode ./cmd/sshepherd`, the dockerized sshd matrix (`make integration`).

**Base:** `master` at `4390667` (W4/P04-impl and its follow-ups landed). Every `file:line` below was read at `4390667`; function names are the stable anchors — re-read before editing, because earlier lanes of this wave move lines. The additions from the review pass (see Review log) were not compiled, so a lane that finds a build error in one fixes it to the text's intent.

**Plan file:** this plan is committed as `docs/superpowers/plans/2026-11-08-write-failure-semantics.md`, together with the amended spec, before round 1 (the runner's scout checks both are committed and every lane agent runs `test -f` on it inside its worktree). That path is the runner's `args.plan`.

---

## How this plan is cut (read first)

### Why the lanes look the way they do

Three gates shape the rounds, beyond file ownership:

1. **`deadcode ./cmd/sshepherd` is part of `make check`.** A function or method a round adds must be reachable from `main` when that round is committed. So `sshconn.AuthExhausted` (the exported reader of the `Error.AuthExhausted` flag) lands in round 2 with its only caller, `classifyProbe`, while round 1's lane `conn` sets the flag (a struct field, exempt). `fleet.UnprovenError`'s methods land with the transport code that constructs it, for the same reason. `fleet.HostKeyAlert` lands in the same lane as its first caller, `audit.hostKeyAlert`.
2. **`TestHelpExamplesAndExitCodes` and `TestHelpMatchesREADMETables` read `README.md`.** Lane `report` changes the `apply`/`revoke`/`rotate` exit-code footer, so it must apply its own `docsDelta` to its worktree's `README.md` before `make check`; the ownership filter drops that change from the patch. The integrator runs `make check` right after `git apply`, before it would normally apply docs, so for this lane it applies the Exit-codes part of the `docsDelta` **first** (see "Integrator" and the runner's `handoffs` in "Wave lanes").
3. **`RenderSummary` changes signature** (it gains `cfg`). Its callers are `cmd/sshepherd/apply.go` and `cmd/sshepherd/editrun.go`, so lane `report` owns those two command files as well as `internal/apply` and `internal/workflow`, and the exit mapping lands with it.

Lane `report` needs `fleet.UnprovenError`/`fleet.LockoutError`, so it must follow lane `probe`; lane `probe` needs `ConnectOptions.SessionTimeout` and the classified kinds, so it must follow lane `conn`. Lane `scripts` and lane `reserial` depend on nothing else in this wave and run beside `conn`.

### Rounds

| Round | Lanes (disjoint files) | Builds on |
|---|---|---|
| 1 | `conn` (sshconn handshake facts, `Only` offer check, session deadline) · `scripts` (lock owner record, `LockedError`, keys2 retention) · `reserial` (`ReserialOversize`, `plainApply.question`) | `4390667` |
| 2 | `probe` (fleet vocabulary, `classifyProbe`, retries, UNPROVEN, restore retry, reconnect, `SkipWrite`, headless proof) | round 1 |
| 3 | `report` (outcomes, exit-2 set, text and JSON reports, interrupt notice, request fields, exit mapping, footers, cmd exit tests) | round 2 |
| 4 | `itest` (real-sshd integration, the rollback E2E, fixture users) | round 3 |

### Plan decisions (not in the spec; each changes no exit code, refusal class or schema beyond an answered decision)

1. **`fleet.ErrNoSession` is exported** (the spec's `errNoSession`): `LockoutError.Error()` lives in `internal/fleet` and must word the refused-reconnect case, and `sshwrite` constructs the error.
2. **`RemoveCmd` uses `sshconn.PathAssign` verbatim**, so the printed command reads `p="${HOME:?}"/'…'` where the spec's sample abbreviates it as `p="$HOME"/`. The spec says "built with the same quoting as `sshconn.PathAssign`".
3. **`user@host` in `RemoveCmd` is shell-safe.** It is printed bare when it matches `^[A-Za-z0-9@%+=:,./_-]+$` (every real value, so the spec's shape holds) and `sshconn.ShQuote`d otherwise; a target starting with `-` gets a `--` before it. A manifest field must not become a pasted option or command.
4. **`fleet.WriteRequest.OnWarning` receives the failure cause only.** The transport knows fingerprints, not `--identity` paths; `applyOne` (which has `HeldKey.Source`) builds the full text and is the single place that wording lives. With two or more proof keys the text reads `your --identity keys /a, /b could not log in on their own (…); a headless run with only those keys would fail`.
5. **The stderr warning is `log.Warn("web-1: your --identity key …")`**, so `clog` prints it as `warn: web-1: your --identity key …`. The handler's `warn: ` prefix already states the level, so the message does not repeat it, and `-q`, color and `NO_COLOR` behave as for every other warning. This changes the line recorded in spec §6 and D9b's README cell (`web-1: warning: …`); see "Spec amendments". The JSON entry is unaffected.
6. **`rollbackDetail(cfg, former, p)` labels a key by bare owner name** (or `audit.UnknownLabel` for a key nobody owned), not `label()`'s `alice (revoked)`. Text and JSON must not disagree, `JSONOptions` has no `FormerNote`, and the spec's sample reads `alice (SHA256:…, on the revoked: list)`.
7. **`cmd/sshepherd` gains the seam `newWriter`** (a package variable building the `apply.Writer`), like `promptStreams` and `beforeManifestSave`; the spec's "hermetic, fake writer" tests need it.
8. **An incomplete `Only` offer also blocks `AuthExhausted`.** The spec's rule is "an incomplete offer can never reach REJECTED"; a `MaxAuthTries` disconnect with a key not offered is reclassified `agent` the same way a refused login is.
9. **`Error.AuthExhausted` is set only when the kind is `handshake`**, so a context that ended at the same instant cannot pair a `timeout` kind with a REJECTED verdict.
10. **A failed reconnect's kind survives** through `unknownStateError` (message fixed by the spec, `Unwrap` returns the sanitized reconnect error), so D10b's "keeps `error_kind` naming the alarm" holds for a host-key alarm on the reconnect.
11. **`sshconn.Exec` marks a session that never opened** (`sshconn.ErrSessionNotOpened`, wrapped at its `open session` error; the message is unchanged). Spec §4 row 4 gives exit 2 only when the reconnect is refused "after the stage-1 exec had started", so a stage-1 error carrying the marker passes `started=false`, and a refused reconnect is then row 3's FAILED "unknown state" (exit 1): nothing was uploaded, so the new file cannot have locked anyone out. Every other stage-1 transport error, and every verify transport error (stage 1 has finished by then), counts as started.
12. **`lockedReadCmdFor` exits 44 when the target's directory is absent**, before taking the lock: a first-contact write dropped before `mkdir` would otherwise fail `mkdir "$l"` with exit 1 and read as "unknown state" instead of "original untouched".
13. **An UNPROVEN login keeps precedence over a failed keys2 disable** (today's precedence: the probe's error is returned first). The next audit reports the keys2 drift.
14. **An unrecognized owner record renders as `an unrecognized owner record`** (`Known` false); the absent record as `an unknown owner (older sshepherd or killed shell)`, per the spec.
15. **`dryRunBump` joins several `ReserialOversize` messages with `"; "`** into the one `SerialBump.Warning` field; a real run logs each on its own line and joins them the same way for JSON.
16. **E2E gap, recorded:** the spec's UNPROVEN E2E step has no hook (`e2e_test.go` drives the built binary and nothing can close a port between the write and the probe). `TestIntegrationProbeTransientKeepsFile` covers it through the `connect` seam against real sshd.
17. **`TestIntegrationProbeHostKeyChangedKeepsFileExits2` asserts `fleet.HostKeyAlert(fleet.ErrorKindOf(err))`**, the predicate `apply.ExitCode` reads: the sshwrite test package cannot see an exit code, and the host key cannot change mid-run through the CLI because `known_hosts` is parsed once. The method differs from the spec's too: instead of swapping the sshd host key between write and probe, the test hands the probe's `Only` dials a `known_hosts` recording another key (the `host_key_changed` E2E case also works by a wrong `known_hosts` entry). The client verdict is the same, and the shared fixture sshd is left alone for the other tests. The process exit is pinned by `TestApplyProbeHostKeyChangedExits2`.
18. **`ConnectOptions.RequireOffer` (the reconnect only).** A locked agent returns no signers and a nil error (`Credentials.Signers`), and the reconnect passes no `Only`, so Task 3's check would not fire; the handshake would fail as kind `auth` and report `lockout_unrestored` ("was refused"), though an empty offer proves nothing about the server (spec §1) and D28 reserves exit 2 for a human acting now. With `RequireOffer`, nothing to offer is an `agent`-kind error before dialing, which spec §4 row 3 reports as FAILED "unknown state", exit 1. Only the reconnect sets it, so audit's and adopt's kinds do not change. See "Spec amendments".

### Conventions every lane follows

- Go runs under the pin: prefix every `go` command with `GOTOOLCHAIN=go1.27.3`. The rtk hook summarizes test output; use `rtk proxy go test …` when exact failure lines matter.
- A golden is rewritten only with `-update` and then read back line by line before it is accepted.
- **Before hand-back:** apply this lane's `docsDelta` to the worktree's `README.md` (gate only, and only when the lane says so), run `make check` (and `make integration` under the runner's lock when the lane says `needsIntegration`), then `git add -A`, unstage every path outside the lane's globs (README.md and CLAUDE.md always), and write the patch. The README text goes in `docsDelta`, verbatim, with samples copied from the regenerated goldens.
- Coverage: `make coverage` gates production packages at `COVERAGE_MIN := 93`; every new branch below has a test that reaches it.
- **Failing first.** Every test is run and seen failing (build failure or assertion) before the code it tests exists; a test that pins behaviour already present says so.
- **gocyclo 15 is a production-code gate** (`_test.go` is exempt). Function literals count toward their enclosing function. `ConnectWith` is at 14 and `RenderSummary` at 12; the new branches go into the named helpers the tasks give; never `//nolint:gocyclo`.
- **errorlint applies to tests too**: compare sentinels with `errors.Is`.
- **No wall-clock waits in `internal/sshwrite` unit tests.** `FleetWriter.now` and `FleetWriter.sleep` are the seams; `seamedWriter` installs a fake clock. The one exception there is `TestSleepCtx`, which tests the real timer for 1 ms. `TestConnectSessionTimeoutExtendsSocketDeadline` in `internal/sshconn` needs a real socket deadline (2 s dial bound, 2.3 s handler per subtest).

---

## File structure

| File | Round/lane | Responsibility |
|---|---|---|
| `internal/sshconn/errors.go` | 1 `conn`, then 2 `probe` | `Error.AuthExhausted`, `handshakeKind`'s host-key gate, `authExhausted`; then the exported `AuthExhausted` |
| `internal/sshconn/connect.go` | 1 `conn` | `ConnectOptions.SessionTimeout`/`RequireOffer`, `hostKeyState`, `dialFacts.failure`, `dialFailure`, `notOffered`, `emptyOffer`, `ErrSessionNotOpened` |
| `internal/sshconn/session.go` | 1 `conn` | `sessionKey` records a signer failure |
| `internal/sshconn/handshake_test.go` (new) | 1 `conn`, then 2 `probe` | classification tables, pre-kex disconnect, offer and signer cases, session deadline |
| `internal/sshwrite/lock.go` (new) | 1 `scripts` | owner record, `parseLockOwner`, `LockedError`, removal command |
| `internal/sshwrite/lock_test.go` (new), `fuzz_test.go`, `testdata/fuzz/FuzzParseLockOwner/*` (new) | 1 `scripts` | real-shell lock cases, parse tables, fuzz |
| `internal/sshwrite/sshwrite.go` | 1 `scripts`, then 2 `probe` | scripts use `lockPrologue()`; keys2 retention; then alias, seams, `Apply` shell |
| `internal/sshwrite/sshwrite_test.go` | 1 `scripts`, then 2 `probe` | keys2 cases; fake clock, seam extensions, rewritten stage tests |
| `internal/apply/serialbump.go`, `serialbump_test.go`, `json.go` (doc comment) | 1 `reserial` | `ReserialOversize` |
| `cmd/sshepherd/apply.go`, `apply_serial_test.go` | 1 `reserial`, then 3 `report` | `plainApply.question`, `dryRunBump` check; then the exit mapping and `newWriter` |
| `internal/fleet/write.go`, `errors.go`, tests | 2 `probe` | `UnprovenError`, `LockoutError` (moved), `ErrNoSession`, `BackupSuffix`, `HostKeyAlert`, `WriteRequest` fields |
| `internal/audit/errors.go` | 2 `probe` | `hostKeyAlert` delegates to `fleet.HostKeyAlert` |
| `internal/sshwrite/session.go` (new), `session_test.go` (new) | 2 `probe` | `writeSession`: write, verify, keys2, restore, reconnect, `SkipWrite` |
| `internal/sshwrite/probe.go` (new), `probe_test.go` (new) | 2 `probe` | `classifyProbe`, retry loop, budget, `UNPROVEN`, headless proof |
| `internal/apply/plan.go`, `exec.go`, `report.go`, `json.go`, tests, `testdata/*` | 3 `report` | outcomes, `ExitCode`, `RevokedRemovals`, `RolledBack`, `Warnings`, `KeysUnchanged`, reports, goldens |
| `internal/workflow/workflow.go`, `workflow_test.go` | 3 `report` | `Outcome.ExitCode`'s contract |
| `cmd/sshepherd/editrun.go`, `run.go`, `failure_exit_test.go` (new), `testdata/help/{apply,revoke,rotate}.golden` | 3 `report` | `RenderSummary` caller, `exitCodesWrite`, exit-2 tests |
| `internal/sshwrite/integration_test.go`, `cmd/sshepherd/e2e_test.go`, `scripts/integration.sh` | 4 `itest` | real-sshd cases, rollback E2E, `maxauth` and `e2eroll` fixture users |

---

## Round 1 — lane `conn` (Tasks 1–4)

Owns: `internal/sshconn/connect.go`, `internal/sshconn/errors.go`, `internal/sshconn/session.go`, `internal/sshconn/handshake_test.go`. Findings: WP-1. `Error.AuthExhausted`, `ConnectOptions.SessionTimeout` and `ConnectOptions.RequireOffer` are struct fields and `ErrSessionNotOpened` a variable (all deadcode-exempt), and `emptyOffer` is reached from `ConnectWith`; the exported `AuthExhausted` function lands with its caller in lane `probe`.

### Task 1: `auth` needs a verified host key; the MaxAuthTries signal

**Files:**
- Modify: `internal/sshconn/errors.go:17-21` (`Error`), `internal/sshconn/errors.go:51-70` (`handshakeKind`)
- Modify: `internal/sshconn/connect.go:227` (the one caller, temporarily)
- Create: `internal/sshconn/handshake_test.go`

- [ ] **Step 1: Write the failing tests**

`internal/sshconn/handshake_test.go`:

```go
package sshconn

import (
	"context"
	"errors"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
)

const (
	refusedText   = "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"
	exhaustedText = "ssh: handshake failed: ssh: disconnect, reason 2: Too many authentication failures"
)

// TestHandshakeKindAuthNeedsVerifiedHostKey: under D9 an auth verdict rolls
// a server back, so text an unverified peer sent can never produce it.
func TestHandshakeKindAuthNeedsVerifiedHostKey(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name     string
		text     string
		verified bool
		want     fleet.ErrorKind
	}{
		{"refused after the host key verified", refusedText, true, fleet.ErrorKindAuth},
		{"the same text before verification", refusedText, false, fleet.ErrorKindHandshake},
		{"a pre-kex disconnect quoting it", "ssh: handshake failed: ssh: disconnect, reason 2: unable to authenticate", false, fleet.ErrorKindHandshake},
		{"other handshake failure", "ssh: handshake failed: EOF", true, fleet.ErrorKindHandshake},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := handshakeKind(ctx, errors.New(tt.text), tt.verified); got != tt.want {
				t.Errorf("handshakeKind = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAuthExhaustedText pins the MaxAuthTries signal: the text sshd sends,
// and only after the host key verified.
func TestAuthExhaustedText(t *testing.T) {
	for _, tt := range []struct {
		name     string
		text     string
		verified bool
		want     bool
	}{
		{"verified", exhaustedText, true, true},
		{"unverified", exhaustedText, false, false},
		{"another disconnect", "ssh: handshake failed: ssh: disconnect, reason 11: bye", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := authExhausted(errors.New(tt.text), tt.verified); got != tt.want {
				t.Errorf("authExhausted = %v, want %v", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run 'TestHandshakeKindAuthNeedsVerifiedHostKey|TestAuthExhaustedText'`
Expected: FAIL to build: `too many arguments in call to handshakeKind`, `undefined: authExhausted`.

- [ ] **Step 3: Implement**

In `internal/sshconn/errors.go`, give `Error` the flag:

```go
type Error struct {
	Kind fleet.ErrorKind
	Err  error
	Hint string // operator remediation, never part of Error()
	// AuthExhausted reports that a server whose host key verified
	// disconnected after too many refused keys (MaxAuthTries). The kind
	// stays ErrorKindHandshake, so audit's error_kind does not change;
	// apply's login check reads this flag.
	AuthExhausted bool
}
```

Replace `handshakeKind`, and add the text constant and `authExhausted` under it:

```go
// tooManyAuthText is the disconnect text sshd sends once it has refused as
// many keys as MaxAuthTries allows.
const tooManyAuthText = "Too many authentication failures"

// handshakeKind classifies an ssh.NewClientConn failure that was not a
// host-key verdict (those are captured from the callback directly). The
// auth case has no typed error in x/crypto, so its fixed message prefix is
// the only signal, and it counts only after the host key verified: a
// disconnect sent before key exchange can carry any text, and an auth
// verdict rolls a server back.
func handshakeKind(ctx context.Context, err error, hostVerified bool) fleet.ErrorKind {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fleet.ErrorKindCanceled
	case ctx.Err() != nil:
		return fleet.ErrorKindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fleet.ErrorKindTimeout
	}
	if hostVerified && strings.Contains(err.Error(), "unable to authenticate") {
		return fleet.ErrorKindAuth
	}
	return fleet.ErrorKindHandshake
}

// authExhausted reports sshd's MaxAuthTries disconnect from a server whose
// host key verified. x/crypto turns any msgDisconnect into a transport
// error, so the text is the only signal.
func authExhausted(err error, hostVerified bool) bool {
	return hostVerified && strings.Contains(err.Error(), tooManyAuthText)
}
```

In `internal/sshconn/connect.go:227`, keep it compiling until Task 2 by passing `false`:

```go
		return nil, classify(handshakeKind(ctx, err, false), fmt.Errorf("ssh %s@%s: %w", srv.User, addr, remoteText{err}))
```

(`authExhausted` has no production caller until Task 2; deadcode only runs at the lane's end.)

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run 'TestHandshakeKindAuthNeedsVerifiedHostKey|TestAuthExhaustedText'`
Expected: `ok`.

### Task 2: the handshake-failure site knows what the dial proved

**Files:**
- Modify: `internal/sshconn/connect.go:167-181` (the host-key callback), `:219-228` (the failure branch)
- Modify: `internal/sshconn/session.go:13-28`, `:38-45`, `:55-62` (`sessionKey`, the two `Sign` methods)
- Test: `internal/sshconn/handshake_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/sshconn/handshake_test.go` (imports gain `encoding/binary`, `io`, `net`, `time`, `golang.org/x/crypto/ssh`, `internal/config`, `internal/keyfile`, `internal/sshconn/sshtest`):

```go
// disconnectServer speaks just enough SSH to send one msgDisconnect with
// desc before any key exchange, and returns its port.
func disconnectServer(t *testing.T, desc string) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(c, "SSH-2.0-evil\r\n")
		payload := []byte{1, 0, 0, 0, 2}
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(desc))) // #nosec G115 -- small test constant
		payload = append(payload, desc...)
		payload = binary.BigEndian.AppendUint32(payload, 0)
		pad := 8 - (5+len(payload))%8
		if pad < 4 {
			pad += 8
		}
		pkt := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad)) // #nosec G115 -- small test constant
		pkt = append(pkt, byte(pad))
		pkt = append(pkt, payload...)
		pkt = append(pkt, make([]byte, pad)...)
		_, _ = c.Write(pkt)
		_, _ = io.Copy(io.Discard, c)
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestPreKexDisconnectNeverSteersAVerdict: text a server sends before its
// host key is verified sets neither auth nor the exhausted flag.
func TestPreKexDisconnectNeverSteersAVerdict(t *testing.T) {
	for _, desc := range []string{"ssh: unable to authenticate", tooManyAuthText} {
		t.Run(desc, func(t *testing.T) {
			port := disconnectServer(t, desc)
			d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: time.Second}
			_, err := d.Connect(ctxTimeout(t, 5*time.Second), config.Server{Name: "evil", Host: "127.0.0.1", Port: port, User: "u"})
			if err == nil {
				t.Fatal("dial succeeded against a disconnecting server")
			}
			var e *Error
			if !errors.As(err, &e) || e.Kind != fleet.ErrorKindHandshake || e.AuthExhausted {
				t.Fatalf("err = %#v, want kind handshake with AuthExhausted false", e)
			}
		})
	}
}

// TestDialFactsFailure pins the failure site's table with the facts set
// directly: a verified MaxAuthTries disconnect, the keep-the-kind rule, the
// incomplete offer and the signer failure.
func TestDialFactsFailure(t *testing.T) {
	ctx := context.Background()
	verified := func() *hostKeyState { return &hostKeyState{verified: true} }
	failedSign := &sessionKey{}
	failedSign.fail()
	for _, tt := range []struct {
		name          string
		f             dialFacts
		text          string
		kind          fleet.ErrorKind
		authExhausted bool
	}{
		{"exhausted, every key offered", dialFacts{hk: verified(), rec: &sessionKey{}}, exhaustedText, fleet.ErrorKindHandshake, true},
		{"exhausted, a key not offered", dialFacts{hk: verified(), rec: &sessionKey{}, asked: 2, missing: 1}, exhaustedText, fleet.ErrorKindAgent, false},
		{"refused, every key offered", dialFacts{hk: verified(), rec: &sessionKey{}}, refusedText, fleet.ErrorKindAuth, false},
		{"refused, a key not offered", dialFacts{hk: verified(), rec: &sessionKey{}, asked: 2, missing: 1}, refusedText, fleet.ErrorKindAgent, false},
		{"a signer failed", dialFacts{hk: verified(), rec: failedSign}, "ssh: handshake failed: agent refused", fleet.ErrorKindAgent, false},
		{"plain handshake failure", dialFacts{hk: verified(), rec: &sessionKey{}}, "ssh: handshake failed: EOF", fleet.ErrorKindHandshake, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.f.user, tt.f.addr = "u", "h:22"
			var e *Error
			if err := tt.f.failure(ctx, errors.New(tt.text)); !errors.As(err, &e) {
				t.Fatalf("err = %v, want *Error", err)
			}
			if e.Kind != tt.kind || e.AuthExhausted != tt.authExhausted {
				t.Errorf("kind = %q, exhausted = %v; want %q, %v", e.Kind, e.AuthExhausted, tt.kind, tt.authExhausted)
			}
		})
	}
	t.Run("a host-key verdict wins", func(t *testing.T) {
		verdict := &Error{Kind: fleet.ErrorKindHostKeyChanged, Err: errors.New("mismatch")}
		f := dialFacts{user: "u", addr: "h:22", hk: &hostKeyState{verdict: verdict}, rec: &sessionKey{}}
		if got := fleet.ErrorKindOf(f.failure(ctx, errors.New(refusedText))); got != fleet.ErrorKindHostKeyChanged {
			t.Errorf("kind = %q, want host_key_changed", got)
		}
	})
}

type failingSigner struct{ ssh.Signer }

func (failingSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("agent refused to sign")
}

// failingAlgoSigner fails the path real agent signers take: x/crypto calls
// SignWithAlgorithm on any signer that has it, never Sign.
type failingAlgoSigner struct{ ssh.AlgorithmSigner }

func (failingAlgoSigner) SignWithAlgorithm(io.Reader, []byte, string) (*ssh.Signature, error) {
	return nil, errors.New("agent refused to sign")
}

// TestSignerErrorDuringAuthIsAgent: a signer that fails between list and
// sign (a locked or killed agent) is an agent failure, not an opaque
// handshake error.
func TestSignerErrorDuringAuthIsAgent(t *testing.T) {
	key := sshtest.Key(1)
	_, kh, srv := credServer(t, sshtest.Signer(t, key).PublicKey())
	for name, wrap := range map[string]func(ssh.Signer) ssh.Signer{
		"Sign":              func(s ssh.Signer) ssh.Signer { return failingSigner{s} },
		"SignWithAlgorithm": func(s ssh.Signer) ssh.Signer { return failingAlgoSigner{s.(ssh.AlgorithmSigner)} },
	} {
		t.Run(name, func(t *testing.T) {
			id := sshtest.Identity(t, "/k/ci", key)
			id.Signer = wrap(id.Signer)
			d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{Files: []keyfile.Identity{id}}, DialTimeout: 5 * time.Second}
			if _, err := d.Connect(ctxTimeout(t, 10*time.Second), srv); err == nil || kindOf(t, err) != fleet.ErrorKindAgent {
				t.Fatalf("Connect err = %v, want ErrorKindAgent", err)
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run 'TestPreKexDisconnectNeverSteersAVerdict|TestDialFactsFailure|TestSignerErrorDuringAuthIsAgent'`
Expected: FAIL to build: `undefined: hostKeyState`, `undefined: dialFacts`, `failedSign.fail undefined`.

- [ ] **Step 3: Implement**

In `internal/sshconn/session.go`, the recorder also remembers a failed signature:

```go
type sessionKey struct {
	mu      sync.Mutex
	fp      string
	signErr bool
}

// fail records that a signer failed during auth.
func (s *sessionKey) fail() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signErr = true
}

// signFailed reports whether any signer failed during auth.
func (s *sessionKey) signFailed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.signErr
}
```

and in both `recordingSigner.Sign` and `recordingAlgorithmSigner.SignWithAlgorithm` replace the `if err == nil { … }` with:

```go
	if err == nil {
		r.rec.record(r.PublicKey())
	} else {
		r.rec.fail()
	}
```

In `internal/sshconn/connect.go`, add above `remoteText`:

```go
// hostKeyState is what the host-key callback saw during one dial: its
// failing verdict (kept here because x/crypto may not keep it in the chain
// NewClientConn returns), or that the key verified.
type hostKeyState struct {
	mu       sync.Mutex
	verdict  error
	verified bool
}

func (h *hostKeyState) record(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.verdict, h.verified = err, err == nil
}

func (h *hostKeyState) get() (verified bool, verdict error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.verified, h.verdict
}

// dialFacts is what one dial knows when its handshake fails.
type dialFacts struct {
	user, addr string
	hk         *hostKeyState
	rec        *sessionKey
	asked      int // len(ConnectOptions.Only)
	missing    int // how many of those fingerprints were not offered
}

// failure classifies a failed ssh.NewClientConn. An incomplete Only offer
// never reports auth or the MaxAuthTries signal: a rollback needs every held
// survivor actually tried, so it is an agent failure naming what was not
// offered. A signer that failed during auth is an agent failure too.
func (f dialFacts) failure(ctx context.Context, err error) error {
	verified, verdict := f.hk.get()
	if verdict != nil {
		return fmt.Errorf("ssh %s@%s: %w", f.user, f.addr, verdict)
	}
	wrapped := fmt.Errorf("ssh %s@%s: %w", f.user, f.addr, remoteText{err})
	kind := handshakeKind(ctx, err, verified)
	exhausted := kind == fleet.ErrorKindHandshake && authExhausted(err, verified)
	switch {
	case f.missing > 0 && (kind == fleet.ErrorKindAuth || exhausted):
		return classify(fleet.ErrorKindAgent, fmt.Errorf("%w; %d of the %d surviving keys not offered (agent locked, or keys removed since the plan)", wrapped, f.missing, f.asked))
	case kind == fleet.ErrorKindHandshake && f.rec.signFailed():
		return classify(fleet.ErrorKindAgent, wrapped)
	}
	return &Error{Kind: kind, Err: wrapped, AuthExhausted: exhausted}
}
```

Replace the callback block (`var ( hkMu … )` and `cb := …`) with:

```go
	hk := &hostKeyState{}
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := kh.callback(hostname, remote, key)
		if err != nil {
			err = hostKeyHint(err, key, srv, kh.Path)
		} else {
			log.Debug("host key verified", "server", srv.Name)
		}
		hk.record(err)
		return err
	}
```

Replace the `if err != nil { _ = conn.Close(); hkMu.Lock(); … }` failure branch with:

```go
	if err != nil {
		_ = conn.Close()
		return nil, dialFacts{user: srv.User, addr: addr, hk: hk, rec: rec, asked: len(only), missing: 0}.failure(ctx, err)
	}
```

(`missing` becomes real in Task 3.) `sync` stays imported: `khOnce` and `hostKeyState` use it.

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn`
Expected: `ok` (the existing `TestConnectKeyOffering`, `TestHandshakeDisconnectTextIsBounded`, `TestConnectHostKeyFailures` still pass).

### Task 3: an incomplete `Only` offer is an agent failure

**Files:**
- Modify: `internal/sshconn/connect.go:51-62` (`ConnectOptions` doc), `:183-189` (the offer)
- Test: `internal/sshconn/handshake_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/sshconn/handshake_test.go` (imports gain `strings`, `sync/atomic`):

```go
// closingListener accepts and closes every connection and counts them.
func closingListener(t *testing.T) (int, *atomic.Int32) {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); <-done })
	return l.Addr().(*net.TCPAddr).Port, accepted
}

// TestConnectWithOnlyNoneOfferedIsAgent: a locked agent answers with an
// empty list, so nothing could be offered. That proves nothing about the
// server, costs it no connection, and is an agent failure.
func TestConnectWithOnlyNoneOfferedIsAgent(t *testing.T) {
	port, accepted := closingListener(t)
	srv := config.Server{Name: "web-1", Host: "127.0.0.1", Port: port, User: "deploy"}
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t)}, DialTimeout: time.Second}
	_, err := d.ConnectWith(ctxTimeout(t, 5*time.Second), srv, ConnectOptions{Only: []string{"SHA256:gone"}})
	if err == nil || kindOf(t, err) != fleet.ErrorKindAgent {
		t.Fatalf("err = %v, want ErrorKindAgent", err)
	}
	if !strings.Contains(err.Error(), "none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)") {
		t.Errorf("err = %q", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("%d TCP connections, want none", n)
	}
}

// TestConnectWithOnlyPartialOfferAuthIsAgent: some survivors offered and
// all refused cannot prove the missing key's line is broken; a login that
// succeeds on the offered keys is still a valid proof.
func TestConnectWithOnlyPartialOfferAuthIsAgent(t *testing.T) {
	held, gone := sshtest.Key(1), sshtest.Key(2)
	only := []string{sshtest.Fingerprint(t, held), sshtest.Fingerprint(t, gone)}
	t.Run("refused", func(t *testing.T) {
		_, kh, srv := credServer(t, sshtest.Signer(t, sshtest.Key(3)).PublicKey())
		d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, held)}, DialTimeout: 5 * time.Second}
		_, err := d.ConnectWith(ctxTimeout(t, 10*time.Second), srv, ConnectOptions{Only: only})
		if err == nil || kindOf(t, err) != fleet.ErrorKindAgent {
			t.Fatalf("err = %v, want ErrorKindAgent", err)
		}
		if !strings.Contains(err.Error(), "1 of the 2 surviving keys not offered") {
			t.Errorf("err = %q, want the count", err)
		}
	})
	t.Run("accepted", func(t *testing.T) {
		_, kh, srv := credServer(t, sshtest.Signer(t, held).PublicKey())
		d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, held)}, DialTimeout: 5 * time.Second}
		conn, err := d.ConnectWith(ctxTimeout(t, 10*time.Second), srv, ConnectOptions{Only: only})
		if err != nil {
			t.Fatalf("a login on an offered survivor is a valid proof: %v", err)
		}
		_ = conn.Close()
	})
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run 'TestConnectWithOnly'`
Expected: FAIL. `TestConnectWithOnlyNoneOfferedIsAgent` stops at `err = ssh deploy@127.0.0.1:…: ssh: handshake failed: EOF, want ErrorKindAgent` (kind `handshake`: today it dials, and the listener closes the connection; the fatal comes before the no-dial assertion). `TestConnectWithOnlyPartialOfferAuthIsAgent/refused` reports `… want ErrorKindAgent` for an `unable to authenticate` error (kind `auth`); its `accepted` subtest passes.

- [ ] **Step 3: Implement**

Update `ConnectOptions.Only`'s doc:

```go
	// Only, when non-empty, offers exactly the held keys (key files or
	// agent) with these fingerprints (in this order) and nothing else — the
	// IdentitiesOnly posture. A login that succeeds therefore proves the
	// server accepts one of them (apply's post-write login probe). Holding
	// none of them is an ErrorKindAgent error before any dial, never a
	// fallback to other keys, and a login refused with some of them not
	// offered is ErrorKindAgent too: an incomplete offer proves nothing
	// about the keys it left out.
	Only []string
```

Replace the `rec := &sessionKey{}` / `offered := …` lines with:

```go
	rec := &sessionKey{}
	ordered := orderSigners(signers, prefer, only)
	if len(only) > 0 && len(ordered) == 0 {
		return nil, classify(fleet.ErrorKindAgent, fmt.Errorf("none of the %d surviving keys is offered (agent locked, or keys removed since the plan)", len(only)))
	}
	missing := notOffered(only, ordered)
	offered := wrapSigners(ordered, rec)
```

Pass it at the failure site: `dialFacts{user: srv.User, addr: addr, hk: hk, rec: rec, asked: len(only), missing: missing}.failure(ctx, err)`.

Add after `orderSigners`:

```go
// notOffered counts the distinct fingerprints in only that ordered does not
// hold.
func notOffered(only []string, ordered []ssh.Signer) int {
	held := make(map[string]bool, len(ordered))
	for _, s := range ordered {
		held[ssh.FingerprintSHA256(s.PublicKey())] = true
	}
	missing := make(map[string]bool)
	for _, fp := range only {
		if !held[fp] {
			missing[fp] = true
		}
	}
	return len(missing)
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn`
Expected: `ok`.

- [ ] **Step 5: Write the failing test for `RequireOffer`** (plan decision 18)

Add to `internal/sshconn/handshake_test.go`:

```go
// TestConnectRequireOfferEmptyIsAgent: the reconnect after a dropped write
// must not read an empty offer as "this server refused you". Without the
// option an empty offer still dials, so audit's kinds do not change.
func TestConnectRequireOfferEmptyIsAgent(t *testing.T) {
	port, accepted := closingListener(t)
	srv := config.Server{Name: "web-1", Host: "127.0.0.1", Port: port, User: "deploy"}
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t)}, DialTimeout: time.Second}
	_, err := d.ConnectWith(ctxTimeout(t, 5*time.Second), srv, ConnectOptions{RequireOffer: true})
	if err == nil || kindOf(t, err) != fleet.ErrorKindAgent {
		t.Fatalf("err = %v, want ErrorKindAgent", err)
	}
	if !strings.Contains(err.Error(), "no key to offer (agent locked, or keys removed since the plan)") {
		t.Errorf("err = %q", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("%d TCP connections, want none", n)
	}
	if _, err := d.ConnectWith(ctxTimeout(t, 5*time.Second), srv, ConnectOptions{}); err == nil || kindOf(t, err) == fleet.ErrorKindAgent {
		t.Fatalf("without RequireOffer: err = %v, want a dial that fails on the server side", err)
	}
	if n := accepted.Load(); n != 1 {
		t.Errorf("%d TCP connections without RequireOffer, want 1", n)
	}
}
```

- [ ] **Step 6: Run the test to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run TestConnectRequireOfferEmptyIsAgent`
Expected: FAIL to build: `unknown field RequireOffer in struct literal of type ConnectOptions`.

- [ ] **Step 7: Implement**

Add to `ConnectOptions`:

```go
	// RequireOffer refuses to dial with no key to offer: that is an
	// ErrorKindAgent error before any connection. Only the reconnect after a
	// dropped write sets it, where a handshake with nothing to offer would
	// otherwise fail as auth and read as "this server refused you".
	RequireOffer bool
```

Replace Step 3's `if len(only) > 0 && len(ordered) == 0 { … }` with the helper, which also keeps `ConnectWith` under the gocyclo limit:

```go
	if err := emptyOffer(opts, ordered); err != nil {
		return nil, err
	}
```

and add after `notOffered`:

```go
// emptyOffer reports a dial that has no key to offer although its caller
// needs one. An empty offer proves nothing about the server, so it is an
// agent failure before any connection, not an auth verdict.
func emptyOffer(opts ConnectOptions, ordered []ssh.Signer) error {
	switch {
	case len(ordered) > 0:
		return nil
	case len(opts.Only) > 0:
		return classify(fleet.ErrorKindAgent, fmt.Errorf("none of the %d surviving keys is offered (agent locked, or keys removed since the plan)", len(opts.Only)))
	case opts.RequireOffer:
		return classify(fleet.ErrorKindAgent, errors.New("no key to offer (agent locked, or keys removed since the plan)"))
	}
	return nil
}
```

- [ ] **Step 8: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn`
Expected: `ok`.

### Task 4: the probe's exec deadline starts after the handshake; `Exec` marks a session that never opened

**Files:**
- Modify: `internal/sshconn/connect.go:51-62` (`ConnectOptions`), `:193-204` (the dial failure), `:229-235` (after the handshake)
- Test: `internal/sshconn/handshake_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/sshconn/handshake_test.go`:

```go
// TestConnectSessionTimeoutExtendsSocketDeadline: with SessionTimeout the
// socket deadline restarts at the handshake's end, so a slow but healthy
// login is not cut off by the dial bound; without it the dial deadline
// still bounds the session.
func TestConnectSessionTimeoutExtendsSocketDeadline(t *testing.T) {
	key := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, key).PublicKey()},
		Handle: func(_ context.Context, _ string, _ io.Reader, stdout, _ io.Writer) int {
			time.Sleep(2300 * time.Millisecond) // past the 2 s dial bound below
			_, _ = io.WriteString(stdout, "done\n")
			return 0
		},
	})
	srv := config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
	kh := sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey()))
	d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, key)}, DialTimeout: 2 * time.Second}
	run := func(t *testing.T, opts ConnectOptions) error {
		t.Helper()
		conn, err := d.ConnectWith(ctxTimeout(t, 2*time.Second), srv, opts)
		if err != nil {
			t.Fatalf("ConnectWith: %v", err)
		}
		defer func() { _ = conn.Close() }()
		_, _, _, err = Exec(context.Background(), conn.Client, "x", nil)
		return err
	}
	t.Run("session deadline replaces the dial deadline", func(t *testing.T) {
		if err := run(t, ConnectOptions{SessionTimeout: 10 * time.Second}); err != nil {
			t.Fatalf("exec after a late handshake: %v", err)
		}
	})
	t.Run("without it the dial deadline bounds the exec", func(t *testing.T) {
		if err := run(t, ConnectOptions{}); err == nil {
			t.Fatal("exec past the dial deadline succeeded")
		}
	})
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run TestConnectSessionTimeoutExtendsSocketDeadline`
Expected: FAIL to build: `unknown field SessionTimeout`.

- [ ] **Step 3: Implement**

Add the field to `ConnectOptions`:

```go
	// SessionTimeout, when positive, replaces the dial deadline as the
	// socket deadline once the handshake finishes: now + SessionTimeout.
	// Without it a handshake that finished late in the dial bound would
	// leave the caller's sessions almost no time.
	SessionTimeout time.Duration
```

Extract the dial-failure classification (the block under `conn, err := dialer.DialContext(…)`), which pays for the new branch (`ConnectWith` is at gocyclo 14):

```go
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, dialFailure(ctx, addr, err)
	}
```

```go
// dialFailure classifies a TCP connect that failed.
func dialFailure(ctx context.Context, addr string, err error) error {
	kind, hint := fleet.ErrorKindDial, DialHint
	if ctx.Err() != nil {
		kind = ctxKind(ctx)
		if kind == fleet.ErrorKindCanceled {
			hint = "" // the operator interrupted; there is nothing to fix
		}
	}
	return classifyHint(kind, hint, dialErr(addr, err))
}
```

After the `if !stopCancel() { … }` block, before the `log.Debug("auth ok", …)` line:

```go
	if opts.SessionTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(opts.SessionTimeout))
	}
```

Update `ConnectWith`'s doc sentence "and is installed as the socket deadline, so it keeps bounding whatever sessions the caller runs" to add "unless ConnectOptions.SessionTimeout replaces it after the handshake".

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/sshconn/...`
Expected: `ok`.

- [ ] **Step 5: Write the failing test for `ErrSessionNotOpened`** (plan decision 11)

Add to `internal/sshconn/handshake_test.go`:

```go
// TestExecMarksASessionThatNeverOpened: the marker means no script ran. A
// session that opened and then dropped must not carry it, and the message
// stays what it was.
func TestExecMarksASessionThatNeverOpened(t *testing.T) {
	key := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	started, release := make(chan struct{}), make(chan struct{})
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, key).PublicKey()},
		Handle: func(_ context.Context, _ string, _ io.Reader, _, _ io.Writer) int {
			close(started)
			<-release
			return 0
		},
	})
	srv := config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
	kh := sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey()))
	d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, key)}, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Run("a session that opened and then dropped is not marked", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			select {
			case <-started:
			case <-time.After(5 * time.Second):
			}
			_ = conn.Close()
		}()
		_, _, _, err := Exec(context.Background(), conn.Client, "x", nil)
		<-done
		close(release)
		if err == nil || errors.Is(err, ErrSessionNotOpened) {
			t.Fatalf("err = %v, want a transport error without the marker", err)
		}
	})
	t.Run("a dead connection never opens a session", func(t *testing.T) {
		_, _, _, err := Exec(context.Background(), conn.Client, "x", nil)
		if !errors.Is(err, ErrSessionNotOpened) || !strings.HasPrefix(err.Error(), "open session: ") || kindOf(t, err) != fleet.ErrorKindRemote {
			t.Fatalf("err = %v, want the marker and today's message", err)
		}
	})
}
```

- [ ] **Step 6: Run the test to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshconn -run TestExecMarksASessionThatNeverOpened`
Expected: FAIL to build: `undefined: ErrSessionNotOpened`.

- [ ] **Step 7: Implement**

In `internal/sshconn/connect.go`, above `Exec`:

```go
// ErrSessionNotOpened marks an Exec whose SSH session never opened, so the
// script cannot have started. Its text is the failure message's prefix.
var ErrSessionNotOpened = errors.New("open session")
```

and in `Exec`'s `client.NewSession()` branch (the text is unchanged):

```go
		return 0, nil, nil, classify(fleet.ErrorKindRemote, fmt.Errorf("%w: %w", ErrSessionNotOpened, remoteText{err}))
```

- [ ] **Step 8: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/sshconn/...`
Expected: `ok`.

- [ ] **Step 9: Hand back** (lane `conn`; the integrator commits `feat(sshconn): login-check facts — verified host key, MaxAuthTries, incomplete offers, session deadline, unopened-session marker (P08 W5, WP-1)`)

Run `make check` and `make integration`, then the conventions' hand-back steps.

**docsDelta (lane `conn`):** none. Nothing user-visible changes until lane `probe`.

---

## Round 1 — lane `scripts` (Tasks 5–7)

Owns: `internal/sshwrite/sshwrite.go`, `internal/sshwrite/sshwrite_test.go`, `internal/sshwrite/lock.go`, `internal/sshwrite/lock_test.go`, `internal/sshwrite/fuzz_test.go`, `internal/sshwrite/testdata/fuzz/FuzzParseLockOwner/*`. Findings: WP-7, WP-8.

### Task 5: the lock records who holds it, and a busy lock says so

**Files:**
- Create: `internal/sshwrite/lock.go`, `internal/sshwrite/lock_test.go`
- Modify: `internal/sshwrite/sshwrite.go:84-106` (`lockPrologue`, `lockHead`, `lockTrap`, `lockPrologueUndo`), `:209` and `:276` (their uses), `:328-334` (`LockedError`, removed)

- [ ] **Step 1: Write the failing tests**

`internal/sshwrite/lock_test.go`:

```go
package sshwrite

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// runShOut is runSh that also returns stdout.
func runShOut(t *testing.T, shell []string, script, home string, stdin []byte) (int, string) {
	t.Helper()
	argv := append(append([]string{}, shell[1:]...), "-c", script)
	c := exec.CommandContext(t.Context(), shell[0], argv...) // #nosec G204 -- test runs the package's own scripts
	c.Env = append(os.Environ(), "HOME="+home)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var stdout bytes.Buffer
	c.Stdout = &stdout
	err := c.Run()
	if err == nil {
		return 0, stdout.String()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), stdout.String()
	}
	t.Fatalf("%v -c %q: %v", shell, script, err)
	return -1, ""
}

func TestLockOwnerRecordThroughRealSh(t *testing.T) {
	old := SnapshotOf(false, []byte("old\n"))
	setup := func(t *testing.T) (home, target, lock string) {
		home = t.TempDir()
		target = filepath.Join(home, "auth")
		writeFile(t, target, "old\n")
		return home, target, target + lockSuffix
	}
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("a held lock exits 47 and names its owner", func(t *testing.T) {
			home, target, lock := setup(t)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, lock+"/owner", "v1 ci-runner-3 4121 99 1000\n")
			code, out := runShOut(t, sh, writeCmdFor(target, old, len(managed)), home, []byte(managed))
			if code != lockedExit {
				t.Fatalf("exit = %d, want %d", code, lockedExit)
			}
			info := parseLockOwner(out)
			if !info.known || info.owner != "ci-runner-3 pid 4121" || info.age <= 0 {
				t.Errorf("parsed %+v from %q", info, out)
			}
			if got := readFile(t, target); got != "old\n" {
				t.Errorf("file = %q, want it untouched", got)
			}
			assertDir(t, lock, "another apply's lock must stay")
		})
		t.Run("a bare lock reports no owner", func(t *testing.T) {
			home, target, lock := setup(t)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			code, out := runShOut(t, sh, writeCmdFor(target, old, len(managed)), home, []byte(managed))
			if code != lockedExit {
				t.Fatalf("exit = %d, want %d", code, lockedExit)
			}
			if info := parseLockOwner(out); info.known || info.owner != ownerUnknown {
				t.Errorf("parsed %+v from %q", info, out)
			}
		})
		t.Run("a completed write leaves neither lock nor record", func(t *testing.T) {
			home, target, _ := setup(t)
			if code := runSh(t, sh, writeCmdFor(target, old, len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("exit = %d", code)
			}
			assertNoResidue(t, target)
		})
		t.Run("a failing write clears them through the trap", func(t *testing.T) {
			home, target, _ := setup(t)
			if code := runSh(t, sh, writeCmdFor(target, old, len(managed)+1), home, []byte(managed)); code != shortWriteExit {
				t.Fatalf("exit = %d, want %d", code, shortWriteExit)
			}
			assertNoResidue(t, target)
		})
		t.Run("a signal clears them through the trap", func(t *testing.T) {
			home, target, lock := setup(t)
			argv := append(append([]string{}, sh[1:]...), "-c", writeCmdFor(target, old, len(managed)))
			c := exec.CommandContext(t.Context(), sh[0], argv...) // #nosec G204 -- test runs the package's own scripts
			c.Env = append(os.Environ(), "HOME="+home)
			in, err := c.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if _, err := os.Stat(lock + "/owner"); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the owner record never appeared")
				}
			}
			if err := c.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			_ = in.Close() // cat sees EOF, then the shell runs its deferred trap
			_ = c.Wait()
			assertNoResidue(t, target)
		})
		t.Run("the removal command clears a stale lock and only that", func(t *testing.T) {
			home, target, lock := setup(t)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, lock+"/owner", "v1 h 1 2 3\n")
			if code := runSh(t, sh, lockRemovalScript(target), home, nil); code != 0 {
				t.Fatalf("exit = %d", code)
			}
			assertAbsent(t, lock, "the removal command must clear the lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, lock+"/unexpected", "x")
			if code := runSh(t, sh, lockRemovalScript(target), home, nil); code == 0 {
				t.Fatal("rmdir must refuse a lock holding something unexpected")
			}
			assertDir(t, lock, "an unexpected lock directory stays")
		})
	})
}

func TestParseLockOwner(t *testing.T) {
	ten := 10 * time.Second
	for _, tt := range []struct {
		name, out string
		known     bool
		owner     string
		age       time.Duration
	}{
		{"valid", "sshepherd-lock 1010\nv1 ci-runner-3 4121 99 1000\n", true, "ci-runner-3 pid 4121", ten},
		{"no record", "sshepherd-lock 1010\n", false, ownerUnknown, ageUnknown},
		{"no marker at all", "", false, ownerUnknown, ageUnknown},
		{"hostile bytes", "sshepherd-lock 1010\nv1 \x1b]0;pwned\a 1 2 3\n", false, ownerUnrecognized, ageUnknown},
		{"host too long", "sshepherd-lock 1010\nv1 " + strings.Repeat("h", 65) + " 1 2 3\n", false, ownerUnrecognized, ageUnknown},
		{"future epoch is an unknown age", "sshepherd-lock 10\nv1 h 1 2 1000\n", true, "h pid 1", ageUnknown},
		{"bad clock is an unknown age", "sshepherd-lock soon\nv1 h 1 2 1000\n", true, "h pid 1", ageUnknown},
		{"absurd gap is an unknown age", "sshepherd-lock 9000000000000000000\nv1 h 1 2 1000\n", true, "h pid 1", ageUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLockOwner(tt.out)
			if got.known != tt.known || got.owner != tt.owner || got.age != tt.age {
				t.Errorf("parseLockOwner = %+v", got)
			}
		})
	}
}

func TestClientIdent(t *testing.T) {
	for _, tt := range []struct {
		host string
		want string
	}{
		{"ci-runner-3.example", "ci-runner-3.example 77"},
		{"bad host!;$(id)", "badhostid 77"},
		{"", "unknown 77"},
		{strings.Repeat("h", 70), strings.Repeat("h", 64) + " 77"},
	} {
		if got := clientIdent(tt.host, 77); got != tt.want {
			t.Errorf("clientIdent(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}

func TestLockedErrorMessage(t *testing.T) {
	const tail = " (a killed write can also leave ~/.ssh/authorized_keys.sshepherd.tmp and ~/.ssh/authorized_keys.sshepherd.cas; the next write reclaims both)"
	known := &LockedError{Path: "~/.ssh/authorized_keys", Owner: "ci-runner-3 pid 4121", Age: 192 * time.Second, Known: true, RemoveCmd: "ssh -p 22 deploy@10.0.0.1 'x'"}
	if want := "another apply is in progress on ~/.ssh/authorized_keys (lock held by ci-runner-3 pid 4121 for 3m12s); remove it only if no apply is running on ci-runner-3 (pid 4121): ssh -p 22 deploy@10.0.0.1 'x'" + tail; known.Error() != want {
		t.Errorf("known:\n got %s\nwant %s", known, want)
	}
	unknown := &LockedError{Path: "~/.ssh/authorized_keys", Owner: ownerUnknown, Age: ageUnknown, RemoveCmd: "ssh x"}
	if want := "another apply is in progress on ~/.ssh/authorized_keys (lock held by an unknown owner (older sshepherd or killed shell)); remove it only if no apply is running: ssh x" + tail; unknown.Error() != want {
		t.Errorf("unknown:\n got %s\nwant %s", unknown, want)
	}
}

func TestLockRemoveCmd(t *testing.T) {
	srv := config.Server{User: "deploy", Host: "10.0.0.1", Port: 22}
	want := `ssh -p 22 deploy@10.0.0.1 ` + sshconn.ShQuote(`p="${HOME:?}"/'.ssh/authorized_keys'; rm -f -- "$p.sshepherd.lock/owner"; rmdir -- "$p.sshepherd.lock"`)
	if got := lockRemoveCmd(srv, "~/.ssh/authorized_keys"); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	for _, tt := range []struct {
		user, want string
	}{
		{"a;b", "ssh -p 22 'a;b@h' "},
		{"-oProxyCommand=x", "ssh -p 22 -- -oProxyCommand=x@h "},
	} {
		if got := lockRemoveCmd(config.Server{User: tt.user, Host: "h", Port: 22}, "/p"); !strings.HasPrefix(got, tt.want) {
			t.Errorf("user %q: got %s", tt.user, got)
		}
	}
}
```

In `internal/sshwrite/sshwrite_test.go`, `TestWriteCmdOrder`: spec §3 needs the EXIT trap to exist before the owner file is written, or a kill leaves a non-empty lock. Insert the step `` `> "$l/owner"` `` right after `` `[ "$x" = 0 ] || U' EXIT` `` and before `` `command -v cksum` ``, and pin the restore script's prologue after the loop:

```go
	restore := restoreCmdFor("~/.ssh/authorized_keys", false, SnapshotOf(false, []byte("new\n")))
	trap, owner := strings.Index(restore, `rmdir "$l" 2>/dev/null' EXIT`), strings.Index(restore, `> "$l/owner"`)
	if trap < 0 || owner <= trap {
		t.Errorf("restore: EXIT trap at %d, owner record at %d; the trap must come first in:\n%s", trap, owner, restore)
	}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run 'TestWriteCmdOrder|TestLockOwnerRecordThroughRealSh|TestParseLockOwner|TestClientIdent|TestLockedErrorMessage|TestLockRemoveCmd'`
Expected: FAIL to build: `undefined: parseLockOwner`, `ownerUnknown`, `ageUnknown`, `ownerUnrecognized`, `clientIdent`, `lockRemovalScript`, `lockRemoveCmd`.

- [ ] **Step 3: Implement**

`internal/sshwrite/lock.go`:

```go
package sshwrite

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// Owner descriptions of a busy lock with no usable record.
const (
	ownerUnknown      = "an unknown owner (older sshepherd or killed shell)"
	ownerUnrecognized = "an unrecognized owner record"
)

// ageUnknown is the age of a lock whose record gave no usable clock.
const ageUnknown time.Duration = -1

// maxLockAge caps a believable age (68 years): beyond it the record's
// numbers are garbage, and multiplying them would overflow a Duration.
const maxLockAge = 1 << 31

// lockOwnerRE is the only owner record the client believes:
// v1 <client-host> <client-pid> <remote-pid> <remote-epoch>. Remote bytes
// reach a report only through its digits and host alphabet.
var lockOwnerRE = regexp.MustCompile(`^v1 ([A-Za-z0-9._-]{1,64}) ([0-9]{1,10}) ([0-9]{1,10}) ([0-9]{1,12})$`)

// lockInfo is what a busy lock's stdout said about its holder.
type lockInfo struct {
	owner string
	age   time.Duration
	known bool
}

// parseLockOwner reads a busy script's stdout: "sshepherd-lock <remote-now>",
// then the first line of the owner record if there is one. The age uses
// only the server's clock, so client clock skew does not matter.
func parseLockOwner(stdout string) lockInfo {
	head, rest, _ := strings.Cut(stdout, "\n")
	now, ok := strings.CutPrefix(head, "sshepherd-lock ")
	line, _, _ := strings.Cut(rest, "\n")
	if !ok || line == "" {
		return lockInfo{owner: ownerUnknown, age: ageUnknown}
	}
	m := lockOwnerRE.FindStringSubmatch(line)
	if m == nil {
		return lockInfo{owner: ownerUnrecognized, age: ageUnknown}
	}
	info := lockInfo{owner: m[1] + " pid " + m[2], age: ageUnknown, known: true}
	nowSec, nowErr := strconv.ParseInt(now, 10, 64)
	epoch, epochErr := strconv.ParseInt(m[4], 10, 64)
	if nowErr == nil && epochErr == nil && nowSec >= epoch && nowSec-epoch < maxLockAge {
		info.age = time.Duration(nowSec-epoch) * time.Second
	}
	return info
}

// heldText is "<owner>" or "<owner> for <age>".
func heldText(owner string, age time.Duration) string {
	if age < 0 {
		return owner
	}
	return owner + " for " + age.Round(time.Second).String()
}

// LockedError reports a refused write: another apply holds the target's
// lock directory. Owner is a description; Known says it came from a valid
// record; Age is negative when the record gave no usable clock. RemoveCmd is
// the by-hand removal: SSHepherd never removes a lock itself.
type LockedError struct {
	Path      string
	Owner     string
	Age       time.Duration
	Known     bool
	RemoveCmd string
}

func (e *LockedError) Error() string {
	scope := ""
	if e.Known {
		host, pid, _ := strings.Cut(e.Owner, " pid ")
		scope = fmt.Sprintf(" on %s (pid %s)", host, pid)
	}
	return fmt.Sprintf("another apply is in progress on %s (lock held by %s); remove it only if no apply is running%s: %s (a killed write can also leave %s%s and %s%s; the next write reclaims both)",
		e.Path, heldText(e.Owner, e.Age), scope, e.RemoveCmd, e.Path, tmpSuffix, e.Path, casSuffix)
}

// lockedErrorFor builds the refusal for a script that exited 47.
func lockedErrorFor(srv config.Server, path, stdout string) *LockedError {
	info := parseLockOwner(stdout)
	return &LockedError{Path: path, Owner: info.owner, Age: info.age, Known: info.known, RemoveCmd: lockRemoveCmd(srv, path)}
}

// lockRemovalScript removes a stale lock. rmdir, not rm -r: it refuses a
// lock directory holding anything unexpected.
func lockRemovalScript(path string) string {
	return sshconn.PathAssign(path) + `; rm -f -- "$p` + lockSuffix + `/owner"; rmdir -- "$p` + lockSuffix + `"`
}

// plainShellWord matches what a shell reads as one literal word.
var plainShellWord = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

// lockRemoveCmd is the paste-ready removal: the remote script quoted once
// more for the local shell, and a manifest-controlled target that can
// become neither a local command nor an ssh option.
func lockRemoveCmd(srv config.Server, path string) string {
	target := srv.User + "@" + srv.Host
	word := target
	if !plainShellWord.MatchString(target) {
		word = sshconn.ShQuote(target)
	}
	if strings.HasPrefix(target, "-") {
		word = "-- " + word
	}
	return fmt.Sprintf("ssh -p %d %s %s", srv.Port, word, sshconn.ShQuote(lockRemovalScript(path)))
}

// clientIdent is the "<host> <pid>" of the lock record: the host reduced to
// the record's alphabet and capped at 64 bytes.
func clientIdent(host string, pid int) string {
	clean := strings.Map(func(r rune) rune {
		if r < 0x80 && plainHostRune(byte(r)) { // #nosec G115 -- r < 0x80
			return r
		}
		return -1
	}, host)
	if len(clean) > 64 {
		clean = clean[:64]
	}
	if clean == "" {
		clean = "unknown"
	}
	return clean + " " + strconv.Itoa(pid)
}

func plainHostRune(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

// ownerIdent is this process's clientIdent. An os.Hostname failure yields
// "unknown": the record is diagnostics only.
var ownerIdent = sync.OnceValue(func() string {
	host, _ := os.Hostname()
	return clientIdent(host, os.Getpid())
})

// ownerRecord writes $l/owner. It runs after the EXIT trap exists: a kill
// in between must not leave a non-empty lock. A failed write is ignored:
// the lock is still valid.
func ownerRecord() string {
	return `printf 'v1 %s %s %s\n' ` + sshconn.ShQuote(ownerIdent()) + ` "$$" "$(date +%s)" > "$l/owner" 2>/dev/null || :`
}

// lockPrologue takes the per-target lock (mkdir is atomic on every POSIX
// filesystem), arranges its removal on every exit path together with the
// temp file, the CAS staging copy and the owner record, and then records
// who holds it. A held lock prints "sshepherd-lock <remote-now>" and the
// owner record's first line, cut to 200 bytes, and exits 47; a lost race
// also exits 47, with no record; any other mkdir failure re-runs mkdir to
// surface its real error and exits 1. That re-run happens before the EXIT
// trap exists, so if it succeeds (the holder released the lock in between)
// it removes the directory it just made and exits 47 — a retryable lost
// race, never a stale lock. Signals route through exit so the EXIT trap
// runs.
func lockPrologue() string {
	return lockHead + lockTrap + `' EXIT; ` + signalTrap + `; ` + ownerRecord()
}

// lockPrologueUndo is lockPrologue for the write script: its EXIT trap also
// runs U (createDirs) on a nonzero exit, after the lock and scratch files
// are gone, so a refusal or failure removes the directories this run
// created (WP-9). A lost lock race (47) exits before this trap exists;
// createDirs' own EXIT trap covers it.
func lockPrologueUndo() string {
	return lockHead + lockTrap + `; [ "$x" = 0 ] || U' EXIT; ` + signalTrap + `; ` + ownerRecord()
}
```

In `internal/sshwrite/sshwrite.go`, delete the `lockPrologue` and `lockPrologueUndo` constants and their comments (now in `lock.go`), delete the `LockedError` type (now in `lock.go`), and replace the `lockHead`/`lockTrap`/`signalTrap` block with:

```go
const (
	lockBusy   = `{ echo "sshepherd-lock $(date +%s)"; head -n 1 "$l/owner" 2>/dev/null | cut -c1-200; exit 47; }`
	lockHead   = `l="$p"` + lockSuffix + `; mkdir "$l" 2>/dev/null || { [ -d "$l" ] && ` + lockBusy + `; if mkdir "$l"; then rmdir "$l"; exit 47; fi; exit 1; }; `
	lockTrap   = `trap 'x=$?; rm -f "$p"` + tmpSuffix + ` "$p"` + casSuffix + ` "$l/owner"; rmdir "$l" 2>/dev/null`
	signalTrap = `trap 'exit 1' HUP INT TERM PIPE`
)
```

In `writeCmdFor` use `lockPrologueUndo()`, and in `restoreCmdFor` use `lockPrologue()`.

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite`
Expected: `ok` (the shell tests, `TestWriteCmdOrder` and `TestOwnerChecksBite` included).

### Task 6: a refused write carries the lock's owner; `FuzzParseLockOwner`

**Files:**
- Modify: `internal/sshwrite/sshwrite.go` (`writeExitError`, `FleetWriter.Apply`'s stage-1 exec)
- Modify: `internal/sshwrite/fuzz_test.go`
- Create: `internal/sshwrite/testdata/fuzz/FuzzParseLockOwner/valid`, `bare`, `hostile`
- Test: `internal/sshwrite/sshwrite_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/sshwrite/sshwrite_test.go`:

```go
// TestApplyLockedCarriesOwner: exit 47's stdout reaches the typed refusal,
// with a removal command built from the server's own coordinates.
func TestApplyLockedCarriesOwner(t *testing.T) {
	s := &scriptedExec{responses: []execResp{{code: lockedExit, stdout: "sshepherd-lock 1192\nv1 ci-runner-3 4121 99 1000\n"}}}
	srv := config.Server{Name: "w", Host: "10.0.0.1", Port: 22, User: "deploy"}
	err := seamedWriter(s, &seamedConnect{}).Apply(context.Background(), srv, req("x\n"))
	var locked *LockedError
	if !errors.As(err, &locked) || !fleet.IsRefusal(err) {
		t.Fatalf("err = %v, want a *LockedError refusal", err)
	}
	if !locked.Known || locked.Owner != "ci-runner-3 pid 4121" || locked.Age != 192*time.Second {
		t.Errorf("locked = %+v", locked)
	}
	if !strings.HasPrefix(locked.RemoveCmd, "ssh -p 22 deploy@10.0.0.1 ") {
		t.Errorf("RemoveCmd = %q", locked.RemoveCmd)
	}
}
```

Add to `internal/sshwrite/fuzz_test.go` (imports gain `regexp`):

```go
// FuzzParseLockOwner: whatever a server prints, the description is a fixed
// string or the record's own safe alphabet, so remote bytes never reach a
// report raw; the age is unknown or non-negative.
func FuzzParseLockOwner(f *testing.F) {
	f.Add("sshepherd-lock 1010\nv1 ci-runner-3 4121 99 1000\n")
	f.Add("sshepherd-lock 1010\n")
	f.Add("sshepherd-lock 1010\nv1 \x1b]0;x\a 1 2 3\n")
	safe := regexp.MustCompile(`^[A-Za-z0-9._-]+ pid [0-9]+$`)
	f.Fuzz(func(t *testing.T, stdout string) {
		info := parseLockOwner(stdout)
		if info.known && !safe.MatchString(info.owner) {
			t.Fatalf("known owner %q is not in the record's alphabet", info.owner)
		}
		if !info.known && info.owner != ownerUnknown && info.owner != ownerUnrecognized {
			t.Fatalf("unknown owner %q is not a fixed description", info.owner)
		}
		if info.age != ageUnknown && info.age < 0 {
			t.Fatalf("age = %v", info.age)
		}
	})
}
```

`internal/sshwrite/testdata/fuzz/FuzzParseLockOwner/valid`:

```text
go test fuzz v1
string("sshepherd-lock 1010\nv1 ci-runner-3 4121 99 1000\n")
```

`internal/sshwrite/testdata/fuzz/FuzzParseLockOwner/bare`:

```text
go test fuzz v1
string("sshepherd-lock 1010\n")
```

`internal/sshwrite/testdata/fuzz/FuzzParseLockOwner/hostile`:

```text
go test fuzz v1
string("sshepherd-lock 1010\nv1 \x1b]0;x\a 1 2 3\n")
```

- [ ] **Step 2: Run the test to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run 'TestApplyLockedCarriesOwner|FuzzParseLockOwner'`
Expected: FAIL: `locked = &{Path:~/.ssh/authorized_keys Owner: Age:0s Known:false RemoveCmd:}` (`FuzzParseLockOwner` passes, it reads Task 5's parser; its corpus is new).

- [ ] **Step 3: Implement**

Change `writeExitError`'s signature and its lock case:

```go
func writeExitError(code int, path string, srv config.Server, stdout, stderr *sshconn.CappedBuffer) error {
```

```go
	case lockedExit:
		return fleet.Refused(lockedErrorFor(srv, path, stdout.String())) //nolint:wrapcheck // Refused is the refusal marker itself; the message is the typed error's
```

Change the other uses of `server` in the function to `srv.Name`. In `Apply`'s stage 1 keep stdout and pass it:

```go
	code, stdout, stderr, err := w.execFn()(execCtx, conn.Client, writeCmdFor(path, req.Expect, len(req.Content)), bytes.NewReader(req.Content))
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("write on %s: %w (the server installs only a complete upload)", srv.Name, err)}
	}
	if err := writeExitError(code, path, srv, stdout, stderr); err != nil {
		return err
	}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite`
Expected: `ok`.

### Task 7: a moved-aside `authorized_keys2` is never overwritten

**Files:**
- Modify: `internal/sshwrite/sshwrite.go:280-297` (`disableKeys2Cmd`, `restoreKeys2Cmd`), `FleetWriter.disableKeys2`, `FleetWriter.Apply` (stage 2b), `FleetWriter.probeOrRestore`
- Test: `internal/sshwrite/sshwrite_test.go` (`TestKeys2CmdsThroughRealSh`, `TestApplyDisablesKeys2BeforeTheProbe`)

- [ ] **Step 1: Write the failing tests**

In `TestKeys2CmdsThroughRealSh`, replace the first subtest and change the two `restoreKeys2Cmd()` calls to `restoreKeys2Cmd("authorized_keys2" + fleet.Keys2DisabledSuffix)`:

```go
		t.Run("disable uses the free base name and says so", func(t *testing.T) {
			home, k2 := setup(t)
			writeFile(t, k2, "ssh-ed25519 AAAA revoked\n")
			code, out := runShOut(t, sh, disableKeys2Cmd(), home, nil)
			if code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			assertAbsent(t, k2, "authorized_keys2 must be gone")
			if got := readFile(t, k2+fleet.Keys2DisabledSuffix); got != "ssh-ed25519 AAAA revoked\n" {
				t.Errorf("disabled copy = %q, want the moved file", got)
			}
			if name, ok := parseKeys2Name(out); !ok || name != "authorized_keys2"+fleet.Keys2DisabledSuffix {
				t.Errorf("stdout %q parsed to %q, %v", out, name, ok)
			}
		})
		t.Run("an earlier disabled copy is never overwritten", func(t *testing.T) {
			home, k2 := setup(t)
			writeFile(t, k2, "second\n")
			writeFile(t, k2+fleet.Keys2DisabledSuffix, "first\n")
			code, out := runShOut(t, sh, disableKeys2Cmd(), home, nil)
			if code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, k2+fleet.Keys2DisabledSuffix); got != "first\n" {
				t.Errorf("earlier copy = %q, want it kept", got)
			}
			name, ok := parseKeys2Name(out)
			if !ok || name == "authorized_keys2"+fleet.Keys2DisabledSuffix {
				t.Fatalf("stdout %q parsed to %q, %v; want the timestamped name", out, name, ok)
			}
			if got := readFile(t, filepath.Join(filepath.Dir(k2), name)); got != "second\n" {
				t.Errorf("timestamped copy = %q", got)
			}
		})
		t.Run("a second copy in the same second gets the pid", func(t *testing.T) {
			home, k2 := setup(t)
			stub, mark := t.TempDir(), filepath.Join(t.TempDir(), "date.called")
			writeFile(t, filepath.Join(stub, "date"), "#!/bin/sh\n: > '"+mark+"'\necho 20261108T010203Z\n")
			if err := os.Chmod(filepath.Join(stub, "date"), 0o700); err != nil { // #nosec G302 -- test stub
				t.Fatal(err)
			}
			writeFile(t, k2, "third\n")
			writeFile(t, k2+fleet.Keys2DisabledSuffix, "first\n")
			stamped := k2 + fleet.Keys2DisabledSuffix + ".20261108T010203Z"
			writeFile(t, stamped, "second\n")
			argv := append(append([]string{}, sh[1:]...), "-c", disableKeys2Cmd())
			c := exec.CommandContext(t.Context(), sh[0], argv...) // #nosec G204 -- test runs the package's own script
			c.Env = append(os.Environ(), "HOME="+home, "PATH="+stub+":"+os.Getenv("PATH"))
			out, err := c.Output()
			if err != nil {
				t.Fatalf("disable: %v", err)
			}
			if _, err := os.Stat(mark); os.IsNotExist(err) {
				t.Skipf("%v runs date as a built-in applet; a PATH stub cannot observe it", sh)
			}
			name, ok := parseKeys2Name(string(out))
			if !ok || !strings.HasPrefix(name, "authorized_keys2"+fleet.Keys2DisabledSuffix+".20261108T010203Z.") {
				t.Fatalf("stdout %q parsed to %q, %v", out, name, ok)
			}
			if readFile(t, stamped) != "second\n" || readFile(t, filepath.Join(filepath.Dir(k2), name)) != "third\n" {
				t.Error("a copy was overwritten")
			}
		})
```

Add after that subtest, inside the same `forEachShell`:

```go
		t.Run("restore moves back exactly the named copy", func(t *testing.T) {
			home, k2 := setup(t)
			named := "authorized_keys2" + fleet.Keys2DisabledSuffix + ".20261108T010203Z"
			writeFile(t, k2+fleet.Keys2DisabledSuffix, "older\n")
			writeFile(t, filepath.Join(filepath.Dir(k2), named), "newest\n")
			if code := runSh(t, sh, restoreKeys2Cmd(named), home, nil); code != 0 {
				t.Fatalf("exit = %d", code)
			}
			if got := readFile(t, k2); got != "newest\n" {
				t.Errorf("authorized_keys2 = %q", got)
			}
			if got := readFile(t, k2+fleet.Keys2DisabledSuffix); got != "older\n" {
				t.Errorf("older copy = %q, want it kept", got)
			}
		})
```

Add a parser table to the same file:

```go
func TestParseKeys2Name(t *testing.T) {
	base := "authorized_keys2" + fleet.Keys2DisabledSuffix
	for _, tt := range []struct {
		out  string
		want string
		ok   bool
	}{
		{"", "", true},
		{"sshepherd-keys2 " + base + "\n", base, true},
		{"sshepherd-keys2 " + base + ".20261108T010203Z\n", base + ".20261108T010203Z", true},
		{"sshepherd-keys2 " + base + ".20261108T010203Z.4121\n", base + ".20261108T010203Z.4121", true},
		{"sshepherd-keys2 ../../etc/passwd\n", "", false},
		{"garbage\n", "", false},
	} {
		if got, ok := parseKeys2Name(tt.out); got != tt.want || ok != tt.ok {
			t.Errorf("parseKeys2Name(%q) = %q, %v", tt.out, got, ok)
		}
	}
}
```

In `TestApplyDisablesKeys2BeforeTheProbe`, script the disable's stdout:

```go
	const moved = "sshepherd-keys2 authorized_keys2" + fleet.Keys2DisabledSuffix + "\n"
```

Use `{code: 0, stdout: moved}` as the third response in the "order" and "probe failure restores both files" subtests, and compare `s.cmds[4] != restoreKeys2Cmd("authorized_keys2"+fleet.Keys2DisabledSuffix)`. Add a subtest:

```go
	t.Run("unrecognized output is a failure, and nothing is moved back", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: 0, stdout: "sshepherd-keys2 /etc/passwd\n"}}}
		err := seamedWriter(s, &seamedConnect{}).Apply(context.Background(), config.Server{Name: "w"}, r)
		if err == nil || !strings.Contains(err.Error(), "unrecognized") {
			t.Fatalf("err = %v, want the unrecognized-name failure", err)
		}
	})
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run 'TestKeys2CmdsThroughRealSh|TestParseKeys2Name|TestApplyDisablesKeys2BeforeTheProbe'`
Expected: FAIL to build: `too many arguments in call to restoreKeys2Cmd`, `undefined: parseKeys2Name`.

- [ ] **Step 3: Implement**

Replace `disableKeys2Cmd` and `restoreKeys2Cmd`:

```go
// disableKeys2Cmd moves ~/.ssh/authorized_keys2 aside and prints
// "sshepherd-keys2 <basename>". A copy is never overwritten: the name is
// fleet.Keys2DisabledSuffix when free, otherwise that plus a UTC timestamp,
// plus .$$ if that is taken too; copies accumulate and SSHepherd never
// deletes them. mv renames a symlink itself, never writing through it; the
// directory passes the same ancestor walk as the write, so only the login
// user (or root) can race the checks. An absent file is a no-op.
func disableKeys2Cmd() string {
	taken := func(v string) string { return `[ -e "` + v + `" ] || [ -L "` + v + `" ]` }
	return sshconn.PathAssign(sshconn.SecondaryAuthorizedKeysPath) +
		`; set -f; u=$(id -u); d=$(dirname "$p"); s="$p"` + fleet.Keys2DisabledSuffix + `; ` + ancestorCheck +
		`; if ` + taken("$p") + `; then` +
		` if ` + taken("$s") + `; then s="$s.$(date -u +%Y%m%dT%H%M%SZ)"; if ` + taken("$s") + `; then s="$s.$$"; fi; if ` + taken("$s") + `; then exit 1; fi; fi` +
		`; mv -f "$p" "$s" || exit 1; echo "sshepherd-keys2 ${s##*/}"; fi`
}

// restoreKeys2Cmd undoes disableKeys2Cmd after a failed login probe,
// moving back exactly the copy this run made (name passed parseKeys2Name),
// refusing (46) to clobber an authorized_keys2 recreated meanwhile.
func restoreKeys2Cmd(name string) string {
	return sshconn.PathAssign(sshconn.SecondaryAuthorizedKeysPath) +
		`; set -f; s="$(dirname "$p")"/` + sshconn.ShQuote(name) +
		`; if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi; if [ -e "$s" ] || [ -L "$s" ]; then mv -f "$s" "$p" || exit 1; fi`
}

// keys2NameRE is the only copy name the client passes back to a script.
var keys2NameRE = regexp.MustCompile(`^authorized_keys2\.sshepherd\.disabled(\.[0-9]{8}T[0-9]{6}Z(\.[0-9]+)?)?$`)

// parseKeys2Name reads disableKeys2Cmd's stdout: "" when nothing was
// there to move, the copy's basename otherwise; false for anything else.
func parseKeys2Name(stdout string) (string, bool) {
	line := strings.TrimSpace(stdout)
	if line == "" {
		return "", true
	}
	name, ok := strings.CutPrefix(line, "sshepherd-keys2 ")
	if !ok || !keys2NameRE.MatchString(name) {
		return "", false
	}
	return name, true
}
```

`internal/sshwrite/sshwrite.go`'s imports gain `regexp` and `strings`.

Change `FleetWriter.disableKeys2` to return the name:

```go
func (w *FleetWriter) disableKeys2(ctx context.Context, conn *sshconn.Conn, server string) (string, error) {
	code, stdout, stderr, err := w.execFn()(ctx, conn.Client, disableKeys2Cmd(), nil)
	switch {
	case err != nil:
		return "", sshconn.SanitizedError{Err: fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s failed: %w", server, err)}
	case code == unsafePathExit:
		return "", fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s was refused: its directory fails the ownership/mode walk", server)
	case code != 0:
		return "", fmt.Errorf("authorized_keys written and verified, but %w", stageFailure("disabling authorized_keys2", server, code, stderr))
	}
	name, ok := parseKeys2Name(stdout.String())
	if !ok {
		return "", fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s printed an unrecognized name", server)
	}
	return name, nil
}
```

In `Apply`, stage 2b becomes:

```go
	var (
		keys2Name string
		keys2Err  error
	)
	if req.DisableKeys2 {
		keys2Name, keys2Err = w.disableKeys2(execCtx, conn, srv.Name)
		if keys2Err == nil {
			log.Debug("authorized_keys2 disabled", "server", srv.Name)
		}
	}
```

and the probe call passes `keys2Name` instead of the bool. `probeOrRestore`'s last parameter becomes `keys2Name string`, its guard `if keys2Name != ""`, its command `restoreKeys2Cmd(keys2Name)`, and the refused message `… (the disabled copy is at %s)` with `keys2Name`.

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite`
Expected: `ok`.

- [ ] **Step 5: Hand back** (lane `scripts`; the integrator commits `feat(sshwrite): self-describing locks and non-destructive authorized_keys2 retention (P08 W5, WP-7, WP-8)`)

Run `make check` and `make integration`, then the conventions' hand-back steps.

**docsDelta (lane `scripts`):**

- README **Safety model → Refusals**, the lock bullet: replace the message with the real one, copied from `TestLockedErrorMessage`'s `known` literal (the `'x'` becomes the removal command printed by `TestLockRemoveCmd`'s `want`, and say so with `…`), and replace "A lock left behind by a killed remote shell must be removed by hand" with: "The refusal names who holds the lock and for how long (a lock with no record reports `an unknown owner (older sshepherd or killed shell)`) and prints the exact removal command. SSHepherd never removes a lock itself and has no flag to; check that no apply is running there first. A killed write can also leave `<path>.sshepherd.tmp` and `<path>.sshepherd.cas`; the next write reclaims both."
- README **Safety model → `authorized_keys2`**: after the plan-row sentence add: "A moved-aside copy is never overwritten: if `authorized_keys2.sshepherd.disabled` already exists, the copy is named `authorized_keys2.sshepherd.disabled.<UTC YYYYmmddTHHMMSSZ>` (plus `.<pid>` if that is taken too). The plan row always shows the base name. Copies accumulate; SSHepherd never deletes them."

---

## Round 1 — lane `reserial` (Task 8)

Owns: `internal/apply/serialbump.go`, `internal/apply/serialbump_test.go`, `internal/apply/json.go`, `cmd/sshepherd/apply.go`, `cmd/sshepherd/apply_serial_test.go`. Finding: the W4 `Reserial` follow-up (spec §7).

### Task 8: a bump that would overflow the limit is withheld before the prompt

**Files:**
- Modify: `internal/apply/serialbump.go` (add `ReserialOversize`), `internal/apply/json.go` (`SerialBump`'s doc comment), `cmd/sshepherd/apply.go` (`newApplyCmd`, `plainApply`, `dryRunBump`)
- Test: `internal/apply/serialbump_test.go`, `cmd/sshepherd/apply_serial_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/apply/serialbump_test.go`:

```go
func TestReserialOversize(t *testing.T) {
	cfg := serialCfg(t)
	plain := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	higher := planWeb1(t, cfg, authkeys.Header(20)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	size := func(serial uint64) int { return len(authkeys.Header(serial)) + 1 + len(web1Body(t, cfg)) }
	saved := maxRender
	t.Cleanup(func() { maxRender = saved })

	t.Run("exactly at the limit passes", func(t *testing.T) {
		maxRender = size(100)
		if got := ReserialOversize([]ServerPlan{plain}, 100); got != nil {
			t.Errorf("got %q, want nil", got)
		}
	})
	t.Run("over the limit names the server and the numbers", func(t *testing.T) {
		maxRender = size(100) - 1
		got := ReserialOversize([]ServerPlan{plain}, 100)
		want := fmt.Sprintf("web-1: the serial bump to 100 would make the rendered file %d bytes, over the %d-byte limit the read path accepts — nothing saved or written (split the grant across accounts)", size(100), maxRender)
		if len(got) != 1 || got[0] != want {
			t.Errorf("got %q\nwant %q", got, want)
		}
	})
	t.Run("a removal-only write is measured at its higher serial", func(t *testing.T) {
		maxRender = size(20) - 1 // serial 8 would fit; the 20 it writes does not
		got := ReserialOversize([]ServerPlan{higher}, 8)
		if len(got) != 1 || !strings.Contains(got[0], "the serial bump to 20 ") {
			t.Errorf("got %q, want one message at max(to, Writes) = 20", got)
		}
	})
	t.Run("other classes are ignored", func(t *testing.T) {
		maxRender = 1
		refused := plain
		refused.Class = ClassRefused
		if got := ReserialOversize([]ServerPlan{refused}, 100); got != nil {
			t.Errorf("got %q, want nil", got)
		}
	})
	t.Run("a render with no header line is left to Reserial", func(t *testing.T) {
		maxRender = 1
		bad := plain
		bad.Rendered = []byte("no newline")
		if got := ReserialOversize([]ServerPlan{bad}, 100); got != nil {
			t.Errorf("got %q, want nil", got)
		}
	})
}
```

(imports gain `fmt` and `strings` if absent.)

Add to `cmd/sshepherd/apply_serial_test.go` (imports gain `encoding/json`, `internal/fleet`):

```go
// bumpOverLimit is a hermetic fleet where one extra installed key forces a
// D4b bump and alice's comment leaves the render 5 bytes under the limit,
// so the bump's 11-byte header growth would overflow it.
func bumpOverLimit(t *testing.T) (cfg, kh, target string) {
	t.Helper()
	home := shortHome(t)
	srv, hostKey, c := hermeticFleet(t, home)
	kh = sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	target = filepath.Join(home, ".ssh", "authorized_keys")
	line := strings.TrimSpace(string(fileBytes(t, target)))
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("ParseLine: %v", err)
	}
	base, err := authkeys.RenderSerial([]authkeys.RenderEntry{{Key: *k, Comment: "x"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 1+fleet.MaxRemoteOutput-5-len(base))
	text := strings.Replace(string(fileBytes(t, c)), `keys: ["`+line+`"]`, `keys: ["`+line+` `+pad+`"]`, 1)
	if err := os.WriteFile(c, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(line+"\n"+testkeys.Line(t, 9)+" handed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c, kh, target
}

// TestReserialOversizeWithholdsBeforeSave (spec §7): nothing saved or
// written, exit 1, the message on stderr and in serial_bump.warning; a dry
// run reports the same warning.
func TestReserialOversizeWithholdsBeforeSave(t *testing.T) {
	const wantMsg = "web-1: the serial bump to 1 would make the rendered file"
	cfg, kh, target := bumpOverLimit(t)
	manifestBefore, serverBefore := fileBytes(t, cfg), fileBytes(t, target)
	unchanged := func(t *testing.T) {
		t.Helper()
		if !bytes.Equal(fileBytes(t, cfg), manifestBefore) || !bytes.Equal(fileBytes(t, target), serverBefore) {
			t.Error("a withheld run changed the manifest or the server")
		}
	}
	warning := func(t *testing.T, out []byte) {
		t.Helper()
		var doc struct {
			SerialBump struct {
				To      *uint64 `json:"to"`
				Warning string  `json:"warning"`
			} `json:"serial_bump"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("json: %v", err)
		}
		if doc.SerialBump.To != nil || !strings.Contains(doc.SerialBump.Warning, wantMsg) {
			t.Errorf("serial_bump = %+v", doc.SerialBump)
		}
	}
	t.Run("text", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(errBuf.String(), wantMsg) || !strings.Contains(errBuf.String(), "nothing saved or written") {
			t.Errorf("stderr = %.400s", errBuf.String())
		}
		unchanged(t)
	})
	t.Run("json", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		warning(t, out.Bytes())
		unchanged(t)
	})
	t.Run("dry run", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(errBuf.String(), wantMsg) || strings.Contains(out.String(), "would bump serial") {
			t.Errorf("a dry run must warn instead of promising the bump\nstdout %.400s\nstderr %.400s", out.String(), errBuf.String())
		}
		out.Reset()
		if code := run([]string{"apply", "--json", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("json dry run exit = %d", code)
		}
		warning(t, out.Bytes())
		unchanged(t)
	})
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply ./cmd/sshepherd -run 'TestReserialOversize'`
Expected: FAIL to build in `internal/apply` (`undefined: ReserialOversize`); in `cmd/sshepherd` the run is not withheld (exit 0 or a verify failure).

- [ ] **Step 3: Implement**

Add to `internal/apply/serialbump.go`:

```go
// ReserialOversize reports every change plan the bumped header would push
// over maxRender (one message per server, nil when none). It mirrors
// Reserial's arithmetic and runs before the prompt: a file over the limit
// could be installed but never verified or read again, and Commit may
// re-render headers only, so the run is withheld here rather than one
// server refused after the plan was shown.
func ReserialOversize(plans []ServerPlan, to uint64) []string {
	var msgs []string
	for _, p := range plans {
		if p.Class != ClassChange {
			continue
		}
		_, body, ok := bytes.Cut(p.Rendered, []byte("\n"))
		if !ok {
			continue // Reserial reports this bug
		}
		w := max(to, p.Serial.Writes)
		if size := len(authkeys.Header(w)) + 1 + len(body); size > maxRender {
			msgs = append(msgs, fmt.Sprintf("%s: the serial bump to %d would make the rendered file %d bytes, over the %d-byte limit the read path accepts — nothing saved or written (split the grant across accounts)", p.Server.Name, w, size, maxRender))
		}
	}
	return msgs
}
```

In `internal/apply/json.go`, `SerialBump`'s comment:

```go
// SerialBump is apply's D4b serial bump (spec §6) for the JSON document:
// From → To, saved or not. To is nil and Warning set when the manifest
// cannot be saved (a piped --config) or when the bump would push a render
// over the read path's limit (ReserialOversize; the run is withheld).
```

In `cmd/sshepherd/apply.go`, `plainApply` gains `targets int`, `newApplyCmd` builds it with `targets: len(targets)` and passes `question: pa.question` in place of the closure, and add:

```go
// question is plain apply's confirmation question. A bump that would push
// a render over the limit withholds the run here, before the prompt and the
// save (spec §7): a plan's class may not change after it is shown.
func (pa *plainApply) question(plans []apply.ServerPlan, toWrite int) (string, error) {
	if msgs := pa.oversizedBump(plans); len(msgs) > 0 {
		for _, m := range msgs {
			pa.log.Error(m)
		}
		pa.bump = &apply.SerialBump{From: pa.cfg.Serial(), Warning: strings.Join(msgs, "; ")}
		return "", fmt.Errorf("%w: a serial bump would exceed the render limit", workflow.ErrWithheld)
	}
	return fmt.Sprintf("apply %d of %s?", toWrite, apply.Plural(pa.targets, "server", "servers")), nil
}

// oversizedBump is ReserialOversize for a run that will bump and can save:
// a pipe or an anchored manifest gets no bump, so no growth and no check.
func (pa *plainApply) oversizedBump(plans []apply.ServerPlan) []string {
	from := pa.cfg.Serial()
	if !apply.NeedsSerialBump(plans, from) {
		return nil
	}
	if _, err := serialEditable(pa.m); err != nil {
		return nil // the commit reports a manifest it cannot edit
	}
	return apply.ReserialOversize(plans, from+1)
}
```

In `dryRunBump`, after the `serialEditable` check:

```go
	if msgs := apply.ReserialOversize(plans, from+1); len(msgs) > 0 {
		return &apply.SerialBump{From: from, Warning: strings.Join(msgs, "; ")}
	}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply ./cmd/sshepherd`
Expected: `ok`.

- [ ] **Step 5: Hand back** (lane `reserial`; the integrator commits `fix(apply): withhold a run whose serial bump would overflow the read limit (P08 W5)`)

Run `make check`, then the conventions' hand-back steps.

**docsDelta (lane `reserial`):** README **Safety model → Refusals**, a new bullet after "the rendered file would exceed the 1 MiB": "- a serial bump would push a rendered file over that limit: the whole run is withheld before the prompt, nothing saved or written, exit 1. Its message is `<server>: the serial bump to N would make the rendered file B bytes, over the L-byte limit the read path accepts — nothing saved or written (split the grant across accounts)`, and under `--json` it is `serial_bump.warning`."

---

## Round 2 — lane `probe` (Tasks 9–15)

Owns: `internal/fleet/*`, `internal/audit/errors.go`, `internal/sshconn/errors.go`, `internal/sshconn/handshake_test.go`, `internal/sshwrite/sshwrite*.go`, `internal/sshwrite/session*.go`, `internal/sshwrite/probe*.go`, `internal/sshwrite/fuzz_test.go`. Findings: WP-1, WP-2, WP-6 (the transport half), WP-8 (`SkipWrite`), D9b.

Until lane `report` lands, an `*fleet.UnprovenError` reaches `applyOne`'s default branch and reports `FAILED:`, exit 1. That is correct, if plain: the message says what happened and nothing is misreported.

### Task 9: the typed write outcomes and the shared host-key predicate

**Files:**
- Modify: `internal/fleet/write.go`, `internal/fleet/errors.go`, `internal/audit/errors.go`
- Modify: `internal/sshwrite/sshwrite.go:52-61` (`bakSuffix`), `:336-352` (`LockoutError`)
- Test: `internal/fleet/write_test.go`, `internal/fleet/errors_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/fleet/write_test.go` (imports gain `errors`, `testing` if absent):

```go
type outcomeKind struct {
	kind ErrorKind
	msg  string
}

func (e outcomeKind) Error() string        { return e.msg }
func (e outcomeKind) ErrorKind() ErrorKind { return e.kind }

func TestUnprovenErrorMessages(t *testing.T) {
	const dial = "dial tcp 10.0.0.1:22: i/o timeout"
	for _, tt := range []struct {
		name string
		err  UnprovenError
		want string
	}{
		{"network", UnprovenError{Attempts: 4, Last: outcomeKind{ErrorKindDial, dial}},
			"written and verified, but the login check could not reach the server after 4 attempts (" + dial + ") — kept the new file; run sshepherd audit to confirm"},
		{"one attempt", UnprovenError{Attempts: 1, Last: outcomeKind{ErrorKindDial, dial}},
			"written and verified, but the login check could not reach the server after 1 attempt (" + dial + ") — kept the new file; run sshepherd audit to confirm"},
		{"agent", UnprovenError{Attempts: 2, Last: outcomeKind{ErrorKindAgent, "none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)"}},
			"written and verified, but the login check could not offer the surviving keys you hold after 2 attempts (none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)) — kept the new file; unlock the agent or re-add the key, then run sshepherd audit to confirm"},
		{"host key", UnprovenError{Attempts: 1, HostKey: true, Last: outcomeKind{ErrorKindHostKeyChanged, "host key changed"}},
			"written and verified, but the login check stopped at a host-key alarm (host key changed) — kept the new file; check known_hosts, then run sshepherd audit"},
		{"budget", UnprovenError{Last: errors.New("session budget exhausted before the login check")},
			"written and verified, but the session budget ran out before the login check could start — kept the new file; run sshepherd audit to confirm"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
	e := &UnprovenError{Attempts: 1, Last: outcomeKind{ErrorKindHostKeyRevoked, "revoked"}}
	if got := ErrorKindOf(e); got != ErrorKindHostKeyRevoked {
		t.Errorf("ErrorKindOf = %q, want the last failure's kind through Unwrap", got)
	}
}

func TestLockoutErrorMessages(t *testing.T) {
	probe := errors.New("auth failed")
	restored := "lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: auth failed)"
	for _, tt := range []struct {
		name string
		err  LockoutError
		want string
	}{
		{"restored", LockoutError{Path: "~/k", Probe: probe}, restored},
		{"keys2 alone failed", LockoutError{Path: "~/k", Probe: probe, RestoreKeys2: errors.New("kept")},
			restored + ", but restoring authorized_keys2 failed (kept)"},
		{"restore failed", LockoutError{Path: "~/k", Probe: probe, Restore: errors.New("denied")},
			"post-write login offering only the surviving keys you hold failed (auth failed) AND restoring the previous file failed (denied) — the previous version is at ~/k" + BackupSuffix + "; repair it over a session that is still open"},
		{"reconnect refused", LockoutError{Path: "~/k", Probe: probe, Restore: ErrNoSession},
			"connection dropped after the upload started and a fresh login offering the keys you hold was refused (auth failed) — the new file may lock you out; the previous version is at ~/k" + BackupSuffix},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
	wrapped := &LockoutError{Probe: outcomeKind{ErrorKindAuth, "x"}, RestoreKeys2: errors.New("y")}
	if got := ErrorKindOf(wrapped); got != ErrorKindAuth {
		t.Errorf("ErrorKindOf = %q, want the probe's kind", got)
	}
}
```

Add to `internal/fleet/errors_test.go`:

```go
func TestHostKeyAlert(t *testing.T) {
	for kind, want := range map[ErrorKind]bool{
		ErrorKindHostKeyChanged: true, ErrorKindHostKeyRevoked: true,
		ErrorKindHostKeyUnknown: false, ErrorKindHostKeyTypeUnrecorded: false, ErrorKindHostKey: false, ErrorKindDial: false,
	} {
		if got := HostKeyAlert(kind); got != want {
			t.Errorf("HostKeyAlert(%q) = %v, want %v", kind, got, want)
		}
	}
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/fleet`
Expected: FAIL to build: `undefined: UnprovenError`, `LockoutError`, `BackupSuffix`, `ErrNoSession`, `HostKeyAlert`.

- [ ] **Step 3: Implement**

Add to `internal/fleet/errors.go`:

```go
// HostKeyAlert reports whether kind is a host-key failure that may mean the
// server is being impersonated: exit 2 for audit and for apply's post-write
// login check, not a mere unreachable.
func HostKeyAlert(kind ErrorKind) bool {
	return kind == ErrorKindHostKeyChanged || kind == ErrorKindHostKeyRevoked
}
```

`internal/audit/errors.go` becomes:

```go
package audit

import "github.com/javadh75/SSHepherd/internal/fleet"

// hostKeyAlert reports whether kind is a host-key failure that may mean the
// server is being impersonated — exit 2, not a mere unreachable.
func hostKeyAlert(kind fleet.ErrorKind) bool { return fleet.HostKeyAlert(kind) }
```

In `internal/fleet/write.go`, the imports become `errors`, `fmt`; add below `Keys2DisabledSuffix`:

```go
// BackupSuffix names the previous version the write protocol keeps next to
// the target (replaced by every write that changes the file).
const BackupSuffix = ".sshepherd.bak"
```

Extend `WriteRequest`:

```go
	// SkipWrite: authorized_keys already holds Content (a plan that only
	// disables authorized_keys2), so no lock, backup, upload or rename runs:
	// the writer re-reads and compares the file (a mismatch is a refusal),
	// disables authorized_keys2 and proves the login. A rejected login check
	// restores only authorized_keys2.
	SkipWrite bool
	// HeadlessProof lists key-file fingerprints for one more login after a
	// passing probe (D9b: warn-only; it never restores); empty skips it.
	HeadlessProof []string
	// OnWarning receives the sanitized cause when the headless proof fails.
	OnWarning func(cause string)
```

and append to the file:

```go
// ErrNoSession is LockoutError.Restore when no session could be opened to
// restore over: the reconnect after a dropped write was refused.
var ErrNoSession = errors.New("no session left to restore over")

// LockoutError reports a write that verified but whose surviving held keys
// (key files or agent) could not log in on a fresh connection, or whose
// reconnect after a dropped connection was refused. Restore is nil when the
// previous authorized_keys was put back; RestoreKeys2 is the separate
// authorized_keys2 move-back, whose failure cannot lock anyone out (the
// file only ever adds keys).
type LockoutError struct {
	Path         string
	Probe        error // why the login failed
	Restore      error // nil when the previous file was put back
	RestoreKeys2 error // nil when authorized_keys2 went back, or was not moved
}

func (e *LockoutError) Error() string {
	switch {
	case errors.Is(e.Restore, ErrNoSession):
		return fmt.Sprintf("connection dropped after the upload started and a fresh login offering the keys you hold was refused (%v) — the new file may lock you out; the previous version is at %s%s", e.Probe, e.Path, BackupSuffix)
	case e.Restore != nil:
		return fmt.Sprintf("post-write login offering only the surviving keys you hold failed (%v) AND restoring the previous file failed (%v) — the previous version is at %s%s; repair it over a session that is still open", e.Probe, errors.Join(e.Restore, e.RestoreKeys2), e.Path, BackupSuffix)
	case e.RestoreKeys2 != nil:
		return fmt.Sprintf("lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: %v), but restoring authorized_keys2 failed (%v)", e.Probe, e.RestoreKeys2)
	}
	return fmt.Sprintf("lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: %v)", e.Probe)
}

// Unwrap keeps the probe's kind first in the chain.
func (e *LockoutError) Unwrap() []error { return []error{e.Probe, e.Restore, e.RestoreKeys2} }

// UnprovenError reports a write that was written and verified but whose
// post-write login never got past authentication (dial, kex, agent, host
// key) after the retries. The
// file is kept because restoring could reinstall a key the manifest
// removed. Any failure after a successful login is a rejected probe, never
// an UnprovenError.
type UnprovenError struct {
	Path     string
	Attempts int
	HostKey  bool  // stopped by a host-key alarm (no retry)
	Last     error // sanitized; its kind is the last probe failure's
}

func (e *UnprovenError) Error() string {
	const kept = " — kept the new file; "
	switch {
	case e.Attempts == 0:
		return "written and verified, but the session budget ran out before the login check could start" + kept + "run sshepherd audit to confirm"
	case e.HostKey:
		return fmt.Sprintf("written and verified, but the login check stopped at a host-key alarm (%v)%scheck known_hosts, then run sshepherd audit", e.Last, kept)
	case ErrorKindOf(e.Last) == ErrorKindAgent:
		return fmt.Sprintf("written and verified, but the login check could not offer the surviving keys you hold after %s (%v)%sunlock the agent or re-add the key, then run sshepherd audit to confirm", attempts(e.Attempts), e.Last, kept)
	}
	return fmt.Sprintf("written and verified, but the login check could not reach the server after %s (%v)%srun sshepherd audit to confirm", attempts(e.Attempts), e.Last, kept)
}

// Unwrap exposes the last failure's kind and hint.
func (e *UnprovenError) Unwrap() error { return e.Last }

func attempts(n int) string {
	if n == 1 {
		return "1 attempt"
	}
	return fmt.Sprintf("%d attempts", n)
}
```

In `internal/sshwrite/sshwrite.go`, delete `type LockoutError struct …` with its `Error` and `Unwrap`, and add after `type Request`:

```go
// LockoutError is the typed rollback outcome (fleet.LockoutError).
type LockoutError = fleet.LockoutError
```

and change the `bakSuffix` line to `bakSuffix  = fleet.BackupSuffix`.

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/fleet ./internal/audit ./internal/sshwrite`
Expected: `ok` (`probeOrRestore` still builds: `lockout.Restore` remains a joined error until Task 12).

### Task 10: the session budget is explicit; the write runs in a `writeSession`

**Files:**
- Create: `internal/sshwrite/session.go`
- Modify: `internal/sshwrite/sshwrite.go` (`FleetWriter`, `Apply`, `connectForWrite`; `disableKeys2`, `verify` move out)
- Test: `internal/sshwrite/sshwrite_test.go`

- [ ] **Step 1: Write the failing test and the seams**

In `internal/sshwrite/sshwrite_test.go` replace `seamedConnect`, its `connect`, and `seamedWriter` with:

```go
// seamedConnect records every connect's options. onlyErrs scripts the
// post-write logins (connects with Only set) in order, then probeErr
// applies; fullErrs scripts the reconnects (full connects after the first).
type seamedConnect struct {
	opts     []sshconn.ConnectOptions
	probeErr error
	onlyErrs []error
	fullErrs []error
	onlyHook func(ctx context.Context) // runs on each Only connect

	onlySeen, fullSeen int
}

func (c *seamedConnect) connect(ctx context.Context, _ config.Server, opts sshconn.ConnectOptions) (*sshconn.Conn, error) {
	c.opts = append(c.opts, opts)
	var err error
	if len(opts.Only) > 0 {
		if c.onlyHook != nil {
			c.onlyHook(ctx)
		}
		err = c.probeErr
		if c.onlySeen < len(c.onlyErrs) {
			err = c.onlyErrs[c.onlySeen]
		}
		c.onlySeen++
	} else {
		if c.fullSeen > 0 && c.fullSeen <= len(c.fullErrs) {
			err = c.fullErrs[c.fullSeen-1]
		}
		c.fullSeen++
	}
	if err != nil {
		return nil, err
	}
	return &sshconn.Conn{}, nil // Close is nil-safe by design
}

// fakeClock is the now/sleep seam: time passes only when a test says so.
type fakeClock struct {
	t     time.Time
	slept []time.Duration
}

func newClock() *fakeClock { return &fakeClock{t: time.Now()} }

func (c *fakeClock) now() time.Time { return c.t }

func (c *fakeClock) sleep(_ context.Context, d time.Duration) error {
	c.slept = append(c.slept, d)
	c.t = c.t.Add(d)
	return nil
}

// kinded is a transport error of the given kind.
func kinded(kind fleet.ErrorKind, msg string) error {
	return &sshconn.Error{Kind: kind, Err: errors.New(msg)}
}

// seamedWriter builds a FleetWriter whose network and clock are scripted.
func seamedWriter(s *scriptedExec, c *seamedConnect) *FleetWriter {
	clk := newClock()
	return &FleetWriter{connect: c.connect, exec: s.exec, now: clk.now, sleep: clk.sleep}
}
```

Add the test:

```go
// TestApplyExecsRunUnderTheBudget: the budget is a context deadline, not
// just a socket deadline, so the probe, the restore and a reconnect can
// derive theirs from it.
func TestApplyExecsRunUnderTheBudget(t *testing.T) {
	var remaining []time.Duration
	s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}}}
	w := &FleetWriter{SessionBudget: 90 * time.Second, connect: (&seamedConnect{}).connect,
		exec: func(ctx context.Context, c *ssh.Client, cmd string, in io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
			if dl, ok := ctx.Deadline(); ok {
				remaining = append(remaining, time.Until(dl))
			}
			return s.exec(ctx, c, cmd, in)
		}}
	if err := w.Apply(context.Background(), config.Server{Name: "w"}, req("x\n")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(remaining) != 3 || remaining[0] <= 0 || remaining[0] > 90*time.Second {
		t.Errorf("exec deadlines = %v, want three bounded by the 90s budget", remaining)
	}
}

// TestSleepCtx: every other test injects the sleep seam, so the real wait
// is pinned here.
func TestSleepCtx(t *testing.T) {
	if err := sleepCtx(context.Background(), time.Millisecond); err != nil {
		t.Errorf("timer expiry = %v, want nil", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sleepCtx(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled = %v, want one wrapping context.Canceled", err)
	}
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run 'TestApplyExecsRunUnderTheBudget|TestSleepCtx'`
Expected: FAIL to build: `unknown field now`, `unknown field sleep`, `undefined: sleepCtx`.

- [ ] **Step 3: Implement**

In `FleetWriter`, add to the test seams:

```go
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
```

Add with the other seam accessors:

```go
// clock and sleepFn resolve the time seams to the real implementations.
func (w *FleetWriter) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

func (w *FleetWriter) sleepFn() func(context.Context, time.Duration) error {
	if w.sleep != nil {
		return w.sleep
	}
	return sleepCtx
}

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("wait: %w", ctx.Err())
	case <-t.C:
		return nil
	}
}
```

Replace `connectForWrite`:

```go
// connectForWrite opens the write connection and returns the budget
// deadline it installed (also the socket deadline), detached from ctx; ctx
// still aborts the dial and handshake through the AfterFunc until the
// connect returns. Canceled before or during the connect, it returns an
// error wrapping fleet.ErrWriteNotStarted.
func (w *FleetWriter) connectForWrite(ctx context.Context, srv config.Server) (*sshconn.Conn, time.Time, error) {
	notStarted := fmt.Errorf("%s: %w", srv.Name, fleet.ErrWriteNotStarted)
	if ctx.Err() != nil {
		return nil, time.Time{}, notStarted
	}
	budget := w.SessionBudget
	if budget <= 0 {
		budget = defaultSessionBudget
	}
	deadline := w.clock().Add(budget)
	connCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	stop := context.AfterFunc(ctx, cancel)
	conn, err := w.connectFn()(connCtx, srv, sshconn.ConnectOptions{})
	stop()
	// Releasing connCtx after a successful connect is safe: ConnectWith
	// stops watching it once the handshake completes, and the socket keeps
	// the budget deadline.
	cancel()
	interrupted := errors.Is(ctx.Err(), context.Canceled)
	switch {
	case err != nil && interrupted:
		return nil, time.Time{}, notStarted
	case err != nil:
		return nil, time.Time{}, sshconn.SanitizedError{Err: err}
	case interrupted:
		_ = conn.Close()
		return nil, time.Time{}, notStarted
	}
	return conn, deadline, nil
}
```

Replace `Apply`'s body after the survivors check (keep its doc comment; Task 15 finalizes it):

```go
	conn, deadline, err := w.connectForWrite(ctx, srv)
	if err != nil {
		return err
	}
	sessCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()
	path := srv.AuthorizedKeysFile
	if path == "" {
		path = sshconn.DefaultAuthorizedKeysPath
	}
	s := &writeSession{w: w, ctx: sessCtx, deadline: deadline, srv: srv, path: path, req: req, conn: conn}
	defer s.close()
	return s.run()
}
```

Delete `FleetWriter.disableKeys2` and `FleetWriter.verify` from `sshwrite.go` (its `bytes` import goes with them), and create `internal/sshwrite/session.go`:

```go
package sshwrite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// writeSession is one server's write: the connection in use (replaced by at
// most one reconnect), the budget it all runs under, and the request.
type writeSession struct {
	w           *FleetWriter
	ctx         context.Context // detached from the caller; ends at deadline
	deadline    time.Time
	srv         config.Server
	path        string
	req         Request
	conn        *sshconn.Conn
	reconnected bool
}

func (s *writeSession) close() { _ = s.conn.Close() } // the verdict is already decided

func (s *writeSession) exec(script string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
	return s.w.execFn()(s.ctx, s.conn.Client, script, stdin)
}

func (s *writeSession) remaining() time.Duration { return s.deadline.Sub(s.w.clock()) }

// run is the protocol: write and verify, disable authorized_keys2, prove
// the login. A keys2 failure cannot lock anyone out (the file only ever
// adds keys), so the login check still runs and the failure is reported
// after it.
func (s *writeSession) run() error {
	if err := s.writeAndVerify(); err != nil {
		return err
	}
	keys2Name, keys2Err := s.disableKeys2()
	if err := s.w.probeOrRestore(s.ctx, s.conn, s.srv, s.path, s.req, keys2Name); err != nil {
		return err
	}
	return keys2Err
}

// writeAndVerify is the guarded write (rendered bytes on stdin) and the
// read-back: trusting mv's exit status would leave silent-corruption blind
// spots for the cost of one extra cat.
func (s *writeSession) writeAndVerify() error {
	code, stdout, stderr, err := s.exec(writeCmdFor(s.path, s.req.Expect, len(s.req.Content)), bytes.NewReader(s.req.Content))
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("write on %s: %w (the server installs only a complete upload)", s.srv.Name, err)}
	}
	if err := writeExitError(code, s.path, s.srv, stdout, stderr); err != nil {
		return err
	}
	s.w.log().Debug("write ok", "server", s.srv.Name, "bytes", len(s.req.Content))
	if err := s.verify(); err != nil {
		return err
	}
	s.w.log().Debug("verify ok", "server", s.srv.Name)
	return nil
}

// verify re-reads the file and byte-compares it with the render.
func (s *writeSession) verify() error {
	code, stdout, stderr, err := s.exec(sshconn.AuthorizedKeysCmdFor(s.path), nil)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("verify on %s: %w", s.srv.Name, err)}
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, s.srv.Name, s.w.log())
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("verify on %s: %w", s.srv.Name, err)}
	}
	if res.FileAbsent {
		return fmt.Errorf("verify on %s: file absent after write", s.srv.Name)
	}
	if !bytes.Equal(res.Content, s.req.Content) {
		return fmt.Errorf("verify on %s: file bytes differ from the rendered desired state", s.srv.Name)
	}
	return nil
}

// disableKeys2 moves a non-empty authorized_keys2 aside before the login
// check, so the check proves the survivors log in without it. It returns
// the copy's basename ("" when nothing was moved).
func (s *writeSession) disableKeys2() (string, error) {
	if !s.req.DisableKeys2 {
		return "", nil
	}
	code, stdout, stderr, err := s.exec(disableKeys2Cmd(), nil)
	switch {
	case err != nil:
		return "", sshconn.SanitizedError{Err: fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s failed: %w", s.srv.Name, err)}
	case code == unsafePathExit:
		return "", fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s was refused: its directory fails the ownership/mode walk", s.srv.Name)
	case code != 0:
		return "", fmt.Errorf("authorized_keys written and verified, but %w", stageFailure("disabling authorized_keys2", s.srv.Name, code, stderr))
	}
	name, ok := parseKeys2Name(stdout.String())
	if !ok {
		return "", fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s printed an unrecognized name", s.srv.Name)
	}
	s.w.log().Debug("authorized_keys2 disabled", "server", s.srv.Name)
	return name, nil
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite`
Expected: `ok`.

### Task 11: `classifyProbe` sorts a failure by the stage it reached

**Files:**
- Create: `internal/sshwrite/probe.go`, `internal/sshwrite/probe_test.go`
- Modify: `internal/sshconn/errors.go` (add `AuthExhausted`)
- Test: `internal/sshconn/handshake_test.go`

- [ ] **Step 1: Write the failing tests**

`internal/sshwrite/probe_test.go`:

```go
package sshwrite

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

func TestClassifyProbe(t *testing.T) {
	sanitized := func(err error) error { return sshconn.SanitizedError{Err: err} }
	for _, tt := range []struct {
		name  string
		stage probeStage
		err   error
		want  verdict
	}{
		{"auth refused", stageDial, kinded(fleet.ErrorKindAuth, "unable to authenticate"), verdictRejected},
		{"auth refused, sanitized", stageDial, sanitized(kinded(fleet.ErrorKindAuth, "x")), verdictRejected},
		{"MaxAuthTries", stageDial, sanitized(&sshconn.Error{Kind: fleet.ErrorKindHandshake, Err: errors.New("x"), AuthExhausted: true}), verdictRejected},
		{"dial", stageDial, kinded(fleet.ErrorKindDial, "x"), verdictTransient},
		{"timeout", stageDial, kinded(fleet.ErrorKindTimeout, "x"), verdictTransient},
		{"handshake", stageDial, kinded(fleet.ErrorKindHandshake, "x"), verdictTransient},
		{"agent", stageDial, kinded(fleet.ErrorKindAgent, "x"), verdictAgent},
		{"host_key_unknown", stageDial, kinded(fleet.ErrorKindHostKeyUnknown, "x"), verdictHostKey},
		{"host_key_changed", stageDial, kinded(fleet.ErrorKindHostKeyChanged, "x"), verdictHostKey},
		{"host_key_type_unrecorded", stageDial, kinded(fleet.ErrorKindHostKeyTypeUnrecorded, "x"), verdictHostKey},
		{"host_key_revoked", stageDial, kinded(fleet.ErrorKindHostKeyRevoked, "x"), verdictHostKey},
		{"host_key", stageDial, kinded(fleet.ErrorKindHostKey, "x"), verdictHostKey},
		{"a future host-key kind", stageDial, kinded("host_key_type_changed", "x"), verdictHostKey},
		{"session channel refused", stageAuthed, fmt.Errorf("open session: %w", &ssh.OpenChannelError{}), verdictRejected},
		{"no exit status", stageAuthed, &ssh.ExitMissingError{}, verdictRejected},
		{"EOF after login", stageAuthed, io.EOF, verdictRejected},
		{"wrong output", stageAuthed, errors.New("probe command did not run as sent"), verdictRejected},
		{"exec deadline", stageAuthed, kinded(fleet.ErrorKindTimeout, "x"), verdictRejected},
		{"unknown after auth", stageAuthed, errors.New("x"), verdictRejected},
		{"unknown before auth", stageDial, errors.New("x"), verdictTransient},
		{"canceled before auth", stageDial, kinded(fleet.ErrorKindCanceled, "x"), verdictTransient},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyProbe(tt.stage, tt.err); got != tt.want {
				t.Errorf("classifyProbe = %v, want %v", got, tt.want)
			}
		})
	}
	for v, want := range map[verdict]int{verdictTransient: 4, verdictAgent: 2, verdictHostKey: 1} {
		if got := v.maxAttempts(); got != want {
			t.Errorf("%v.maxAttempts = %d, want %d", v, got, want)
		}
	}
}
```

Add to `internal/sshconn/handshake_test.go`:

```go
func TestAuthExhausted(t *testing.T) {
	ctx := context.Background()
	verified := dialFacts{user: "u", addr: "h:22", hk: &hostKeyState{verified: true}, rec: &sessionKey{}}
	unverified := dialFacts{user: "u", addr: "h:22", hk: &hostKeyState{}, rec: &sessionKey{}}
	err := verified.failure(ctx, errors.New(exhaustedText))
	if !AuthExhausted(SanitizedError{Err: err}) {
		t.Errorf("AuthExhausted(%v) = false through the sanitizing wrapper", err)
	}
	if got := fleet.ErrorKindOf(err); got != fleet.ErrorKindHandshake {
		t.Errorf("kind = %q, want handshake (audit's error_kind must not change)", got)
	}
	if AuthExhausted(unverified.failure(ctx, errors.New(exhaustedText))) || AuthExhausted(errors.New("x")) || AuthExhausted(nil) {
		t.Error("AuthExhausted is true without the flag")
	}
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite ./internal/sshconn -run 'TestClassifyProbe|TestAuthExhausted$'`
Expected: FAIL to build: `undefined: probeStage`, `verdict`, `AuthExhausted`.

- [ ] **Step 3: Implement**

Add to `internal/sshconn/errors.go`:

```go
// AuthExhausted reports whether err's chain carries the MaxAuthTries signal
// from a server whose host key verified.
func AuthExhausted(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.AuthExhausted
}
```

`internal/sshwrite/probe.go`:

```go
package sshwrite

import (
	"strings"
	"time"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// probeStage is how far a login check got: stageDial is everything inside
// the connect (TCP, key exchange, host key, authentication); stageAuthed is
// after the connect returned a client.
type probeStage int

const (
	stageDial probeStage = iota
	stageAuthed
)

func (s probeStage) String() string {
	if s == stageAuthed {
		return "authed"
	}
	return "dial"
}

// verdict is what a failed login check proves.
type verdict int

const (
	verdictTransient verdict = iota // nothing proved: retry, then UNPROVEN
	verdictAgent                    // a held survivor could not be offered: one retry, then UNPROVEN
	verdictHostKey                  // a host-key alarm: no retry, UNPROVEN
	verdictRejected                 // the survivors cannot be used: restore
)

// maxAttempts is the retry ceiling of a transient verdict.
func (v verdict) maxAttempts() int {
	switch v {
	case verdictAgent:
		return 2
	case verdictHostKey:
		return 1
	}
	return len(probeBackoff)
}

// classifyProbe sorts a login-check failure by the stage it reached, not by
// error kind alone. The static guard only checks that a held key's line is
// present; it never evaluates from= or command=, so nothing after a
// successful login is waved through as a blip: a key that logs in but
// cannot run SSHepherd's command captures every later session.
func classifyProbe(stage probeStage, err error) verdict {
	if stage == stageAuthed || sshconn.AuthExhausted(err) {
		return verdictRejected
	}
	switch kind := fleet.ErrorKindOf(err); {
	case strings.HasPrefix(string(kind), "host_key"):
		return verdictHostKey
	case kind == fleet.ErrorKindAuth:
		return verdictRejected
	case kind == fleet.ErrorKindAgent:
		return verdictAgent
	}
	return verdictTransient
}

// The login-check schedule, all inside the session budget. Numbers are
// fixed so the behaviour is predictable and documented once.
const (
	// probeExecDeadline bounds session open, exec and output after the
	// connect returns; on expiry the verdict is REJECTED.
	probeExecDeadline = 15 * time.Second
	// restoreReserve is kept back after the probe's own time, for a REJECTED
	// restore over the open write connection (the busy-lock waits of
	// 1 + 3 + 6 s, plus the restore and keys2 commands).
	restoreReserve = 20 * time.Second
	// minProbeDial is the least dial time an attempt starts with.
	minProbeDial = 1 * time.Second
	// defaultDialBound is 3×DialTimeout when the Dialer sets none.
	defaultDialBound = 30 * time.Second
)

// probeBackoff is the wait before each login-check attempt.
var probeBackoff = [...]time.Duration{0, 2 * time.Second, 5 * time.Second, 10 * time.Second}
```

`classifyProbe` and the constants become reachable in Task 12; deadcode runs at the lane's end.

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite ./internal/sshconn`
Expected: `ok`.

### Task 12: the login check retries inside one budget rule; UNPROVEN keeps the file

**Files:**
- Modify: `internal/sshwrite/probe.go` (add the loop), `internal/sshwrite/sshwrite.go` (delete `probeOrRestore`, `probe`, `probeCmd`, `probeOutput`), `internal/sshwrite/session.go` (`run`, new `rollback`, `restoreFile`, `restoreKeys2`)
- Test: `internal/sshwrite/probe_test.go`, `internal/sshwrite/sshwrite_test.go` (`TestApplyLoginProbeFailureRestores`, `TestApplyDisablesKeys2BeforeTheProbe`)

- [ ] **Step 1: Write the failing tests**

Add to `internal/sshwrite/probe_test.go` (imports gain `context`, `slices`, `strings`, `time`, `internal/config`):

```go
var goodWrite = []execResp{{code: 0}, {code: 0, stdout: "x\n"}}

func unprovenFrom(t *testing.T, err error) *fleet.UnprovenError {
	t.Helper()
	var un *fleet.UnprovenError
	if !errors.As(err, &un) {
		t.Fatalf("err = %v, want *fleet.UnprovenError", err)
	}
	return un
}

func TestApplyProbeRetryAndUnproven(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "w"}
	dial := kinded(fleet.ErrorKindDial, "dial tcp 10.0.0.1:22: i/o timeout")
	setup := func(c *seamedConnect) (*FleetWriter, *scriptedExec, *fakeClock) {
		s := &scriptedExec{responses: goodWrite}
		w, clk := seamedWriter(s, c), newClock()
		w.now, w.sleep = clk.now, clk.sleep
		return w, s, clk
	}
	t.Run("a dial failure every attempt is UNPROVEN and restores nothing", func(t *testing.T) {
		c := &seamedConnect{probeErr: dial}
		w, s, clk := setup(c)
		err := w.Apply(ctx, srv, req("x\n"))
		un := unprovenFrom(t, err)
		if un.Attempts != 4 || un.HostKey {
			t.Errorf("unproven = %+v", un)
		}
		if len(c.opts) != 5 || len(s.cmds) != 2 {
			t.Errorf("connects = %d, cmds = %q; want 5 and no restore", len(c.opts), s.cmds)
		}
		if want := []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}; !slices.Equal(clk.slept, want) {
			t.Errorf("waits = %v, want %v", clk.slept, want)
		}
		if got := fleet.ErrorKindOf(err); got != fleet.ErrorKindDial {
			t.Errorf("kind = %q, want the last failure's", got)
		}
		if !strings.Contains(err.Error(), "after 4 attempts") {
			t.Errorf("err = %q", err)
		}
	})
	t.Run("dial fails twice then succeeds", func(t *testing.T) {
		c := &seamedConnect{onlyErrs: []error{dial, dial, nil}}
		w, s, _ := setup(c)
		if err := w.Apply(ctx, srv, req("x\n")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if c.onlySeen != 3 || s.cmds[len(s.cmds)-1] != probeCmd {
			t.Errorf("only connects = %d, cmds = %q", c.onlySeen, s.cmds)
		}
	})
	t.Run("auth on the first attempt restores with no retry", func(t *testing.T) {
		c := &seamedConnect{probeErr: kinded(fleet.ErrorKindAuth, "unable to authenticate")}
		w, _, clk := setup(c)
		var lo *LockoutError
		if err := w.Apply(ctx, srv, req("x\n")); !errors.As(err, &lo) {
			t.Fatalf("err = %v, want *LockoutError", err)
		}
		if c.onlySeen != 1 || len(clk.slept) != 0 {
			t.Errorf("only connects = %d, waits = %v", c.onlySeen, clk.slept)
		}
	})
	t.Run("MaxAuthTries restores with no retry", func(t *testing.T) {
		c := &seamedConnect{probeErr: &sshconn.Error{Kind: fleet.ErrorKindHandshake, Err: errors.New("too many"), AuthExhausted: true}}
		w, _, _ := setup(c)
		var lo *LockoutError
		if err := w.Apply(ctx, srv, req("x\n")); !errors.As(err, &lo) || c.onlySeen != 1 {
			t.Fatalf("err = %v, only connects = %d", err, c.onlySeen)
		}
	})
	t.Run("an agent failure is retried once", func(t *testing.T) {
		c := &seamedConnect{probeErr: kinded(fleet.ErrorKindAgent, "none of the 1 surviving keys is offered")}
		w, _, _ := setup(c)
		err := w.Apply(ctx, srv, req("x\n"))
		if un := unprovenFrom(t, err); un.Attempts != 2 || c.onlySeen != 2 {
			t.Errorf("unproven = %+v, only connects = %d", un, c.onlySeen)
		}
		if !strings.Contains(err.Error(), "unlock the agent") {
			t.Errorf("err = %q", err)
		}
	})
	t.Run("a host-key alarm is not retried", func(t *testing.T) {
		c := &seamedConnect{probeErr: kinded(fleet.ErrorKindHostKeyChanged, "host key changed")}
		w, s, _ := setup(c)
		err := w.Apply(ctx, srv, req("x\n"))
		un := unprovenFrom(t, err)
		if !un.HostKey || un.Attempts != 1 || c.onlySeen != 1 || len(s.cmds) != 2 {
			t.Errorf("unproven = %+v, only connects = %d, cmds = %q", un, c.onlySeen, s.cmds)
		}
		if got := fleet.ErrorKindOf(err); !fleet.HostKeyAlert(got) {
			t.Errorf("kind = %q, want an alert kind", got)
		}
	})
	t.Run("a wait the context ends stops the retries", func(t *testing.T) {
		c := &seamedConnect{probeErr: dial}
		w, _, _ := setup(c)
		w.sleep = func(context.Context, time.Duration) error { return errors.New("context ended") }
		un := unprovenFrom(t, w.Apply(ctx, srv, req("x\n")))
		if un.Attempts != 1 || c.onlySeen != 1 {
			t.Errorf("unproven = %+v, only connects = %d; want the one finished attempt", un, c.onlySeen)
		}
	})
	t.Run("the probe dial carries the session deadline", func(t *testing.T) {
		c := &seamedConnect{}
		w, _, _ := setup(c)
		if err := w.Apply(ctx, srv, req("x\n")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := c.opts[1].SessionTimeout; got != probeExecDeadline {
			t.Errorf("SessionTimeout = %v, want %v", got, probeExecDeadline)
		}
	})
}

// TestProbeExecDeadlineRestores: a login that succeeds and then hangs is a
// REJECTED probe, bounded by its own 15 s context.
func TestProbeExecDeadlineRestores(t *testing.T) {
	var bound time.Duration
	s := &scriptedExec{responses: goodWrite}
	c := &seamedConnect{}
	w := seamedWriter(s, c)
	w.exec = func(ctx context.Context, cl *ssh.Client, cmd string, in io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
		if cmd == probeCmd {
			dl, _ := ctx.Deadline()
			bound = time.Until(dl)
			return 0, nil, nil, kinded(fleet.ErrorKindTimeout, "run remote command: context deadline exceeded")
		}
		return s.exec(ctx, cl, cmd, in)
	}
	var lo *LockoutError
	if err := w.Apply(context.Background(), config.Server{Name: "w"}, req("x\n")); !errors.As(err, &lo) || lo.Restore != nil {
		t.Fatalf("err = %v, want a restored *LockoutError", err)
	}
	if bound <= 0 || bound > probeExecDeadline {
		t.Errorf("exec bound = %v, want within %v", bound, probeExecDeadline)
	}
}

// TestProbeBudget is the spec's arithmetic table: every attempt, including
// the first, starts only while avail ≥ minProbeDial.
func TestProbeBudget(t *testing.T) {
	dial := kinded(fleet.ErrorKindDial, "dial timeout")
	type outcome struct {
		c      *seamedConnect
		bounds []time.Duration
		err    error
	}
	// run performs a write costing writeCost, with every probe dial burning
	// its full bound on the fake clock and then failing.
	run := func(t *testing.T, writeCost time.Duration, errs []error, fallback error) (outcome, *fakeClock, time.Time) {
		t.Helper()
		clk := newClock()
		start := clk.t
		var o outcome
		o.c = &seamedConnect{probeErr: fallback, onlyErrs: errs, onlyHook: func(ctx context.Context) {
			dl, _ := ctx.Deadline()
			d := time.Until(dl).Round(time.Second)
			o.bounds = append(o.bounds, d)
			clk.t = clk.t.Add(d)
		}}
		s := &scriptedExec{responses: goodWrite}
		w := seamedWriter(s, o.c)
		w.now, w.sleep = clk.now, clk.sleep
		w.exec = func(ctx context.Context, cl *ssh.Client, cmd string, in io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
			clk.t = clk.t.Add(writeCost / 2)
			return s.exec(ctx, cl, cmd, in)
		}
		o.err = w.Apply(context.Background(), config.Server{Name: "w"}, req("x\n"))
		return o, clk, start
	}
	t.Run("W≈0: three attempts, the third cut to 18 s", func(t *testing.T) {
		o, _, _ := run(t, 0, nil, dial)
		if un := unprovenFrom(t, o.err); un.Attempts != 3 {
			t.Errorf("attempts = %d, want 3", un.Attempts)
		}
		if want := []time.Duration{30 * time.Second, 30 * time.Second, 18 * time.Second}; !slices.Equal(o.bounds, want) {
			t.Errorf("dial bounds = %v, want %v", o.bounds, want)
		}
	})
	t.Run("W≈20 s: two attempts", func(t *testing.T) {
		o, _, _ := run(t, 20*time.Second, nil, dial)
		if un := unprovenFrom(t, o.err); un.Attempts != 2 || o.c.onlySeen != 2 {
			t.Errorf("attempts = %d, only connects = %d", un.Attempts, o.c.onlySeen)
		}
	})
	t.Run("W > 84 s: no attempt, no first-attempt exception", func(t *testing.T) {
		o, _, _ := run(t, 85*time.Second, nil, dial)
		un := unprovenFrom(t, o.err)
		if un.Attempts != 0 || o.c.onlySeen != 0 {
			t.Errorf("attempts = %d, only connects = %d", un.Attempts, o.c.onlySeen)
		}
		if !strings.Contains(o.err.Error(), "session budget ran out before the login check could start") {
			t.Errorf("err = %q", o.err)
		}
	})
	t.Run("a REJECTED verdict on the last attempt leaves the reserve", func(t *testing.T) {
		o, clk, start := run(t, 0, []error{dial, dial, kinded(fleet.ErrorKindAuth, "refused")}, nil)
		var lo *LockoutError
		if !errors.As(o.err, &lo) {
			t.Fatalf("err = %v", o.err)
		}
		if used := clk.t.Sub(start); 120*time.Second-used < restoreReserve {
			t.Errorf("%v used of 120 s, want at least %v left for the restore", used, restoreReserve)
		}
	})
}
```

In `internal/sshwrite/sshwrite_test.go`, update the existing tests to the new verdicts:

- `TestApplyLoginProbeFailureRestores`: `probeErr := kinded(fleet.ErrorKindAuth, "ssh: unable to authenticate")`; change the "probe session refused" row to `probe: &execResp{err: fmt.Errorf("open session: %w", &ssh.OpenChannelError{})}`, and add `{name: "no exit status after login", probe: &execResp{err: &ssh.ExitMissingError{}}, restore: execResp{code: 0}, restored: true, wantIn: "lockout prevented"}`. (Imports gain `fmt`.)
- `TestApplyDisablesKeys2BeforeTheProbe`, "probe failure restores both files": `probeErr: kinded(fleet.ErrorKindAuth, "denied")`.

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run 'TestApplyProbeRetryAndUnproven|TestProbeExecDeadlineRestores|TestProbeBudget'`
Expected: FAIL: `err = … want *fleet.UnprovenError` (today's single-shot probe restores on any failure). The two `TestApplyLoginProbeFailureRestores` rows edited above (`OpenChannelError`, `no exit status after login`) pin behaviour the single-shot probe already has; this `-run` does not select them and they pass before Step 3. They guard `classifyProbe`'s wiring.

- [ ] **Step 3: Implement**

Add to `internal/sshwrite/probe.go` (imports gain `context`, `errors`, `fmt`, `internal/config`):

```go
const (
	probeCmd    = `echo sshepherd-probe-ok`
	probeOutput = "sshepherd-probe-ok\n"
)

// errBudget is an UnprovenError's cause when no attempt could start.
var errBudget = errors.New("session budget exhausted before the login check")

// dialBound is 3×DialTimeout, the most one login-check dial may take.
func (w *FleetWriter) dialBound() time.Duration {
	if w.Dialer != nil && w.Dialer.DialTimeout > 0 {
		return 3 * w.Dialer.DialTimeout
	}
	return defaultDialBound
}

// probeOnce logs in offering only the given keys and runs probeCmd: a key
// that authenticates but whose line forces a command would leave sshepherd
// unable to manage the server, so the command must run and print
// probeOutput, not just a handshake. The dial is bounded by bound, the
// exec by probeExecDeadline (which starts when the connect returns).
func (w *FleetWriter) probeOnce(ctx context.Context, srv config.Server, only []string, bound time.Duration) (probeStage, error) {
	dialCtx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	probe, err := w.connectFn()(dialCtx, srv, sshconn.ConnectOptions{Only: only, SessionTimeout: probeExecDeadline})
	if err != nil {
		return stageDial, err
	}
	defer func() { _ = probe.Close() }() // errcheck: the verdict is already decided
	execCtx, cancelExec := context.WithTimeout(ctx, probeExecDeadline)
	defer cancelExec()
	code, stdout, _, err := w.execFn()(execCtx, probe.Client, probeCmd, nil)
	switch {
	case err != nil:
		return stageAuthed, fmt.Errorf("probe command: %w", err)
	case code != 0 || stdout.String() != probeOutput:
		return stageAuthed, fmt.Errorf("probe command did not run as sent (exit %d) — a forced command= on the surviving key?", code)
	}
	return stageAuthed, nil
}

// probeResult is a finished login check: err nil means proven.
type probeResult struct {
	err      error
	verdict  verdict
	attempts int
}

// avail is the dial time an attempt may use: the probe's whole life must
// end by deadline − restoreReserve, so the dial ends by that less the exec's
// own deadline.
func (s *writeSession) avail() time.Duration {
	return s.remaining() - probeExecDeadline - restoreReserve
}

// probeWithRetries runs the login check. An attempt, the first included,
// starts only while avail ≥ minProbeDial at the moment it would start,
// after its wait; a wait that would leave too little is not taken.
func (s *writeSession) probeWithRetries() probeResult {
	log := s.w.log()
	res := probeResult{err: errBudget}
	for attempt := 0; attempt < res.verdict.maxAttempts(); attempt++ {
		wait := probeBackoff[attempt]
		if s.avail()-wait < minProbeDial {
			break
		}
		if wait > 0 {
			if err := s.w.sleepFn()(s.ctx, wait); err != nil {
				break
			}
		}
		stage, err := s.w.probeOnce(s.ctx, s.srv, s.req.Survivors, min(s.w.dialBound(), s.avail()))
		res.attempts, res.err = attempt+1, err
		if err == nil {
			return res
		}
		res.verdict = classifyProbe(stage, err)
		log.Debug("login check failed", "server", s.srv.Name, "attempt", attempt+1, "stage", stage.String(), "kind", string(fleet.ErrorKindOf(err)))
		if res.verdict == verdictRejected {
			return res
		}
	}
	return res
}

// proveOrRestore runs the login check and acts on it: a REJECTED verdict
// restores over the still-open connection; anything else that never got
// past authentication keeps the file (*fleet.UnprovenError), because
// restoring could reinstall a key the manifest removed.
func (s *writeSession) proveOrRestore(keys2Name string) error {
	res := s.probeWithRetries()
	switch {
	case res.err == nil:
		s.w.log().Debug("login probe ok", "server", s.srv.Name, "attempts", res.attempts)
		return nil
	case res.verdict == verdictRejected:
		return s.rollback(keys2Name, res.err)
	}
	return &fleet.UnprovenError{Path: s.path, Attempts: res.attempts, HostKey: res.verdict == verdictHostKey, Last: sshconn.SanitizedError{Err: res.err}}
}
```

In `internal/sshwrite/sshwrite.go` delete `probeCmd`/`probeOutput`, `probeOrRestore` and `probe`.

In `internal/sshwrite/session.go`, `run` calls `s.proveOrRestore(keys2Name)`, and add (Tasks 13–15 extend these):

```go
// rollback restores after a REJECTED login check and returns the verdict.
func (s *writeSession) rollback(keys2Name string, probeErr error) error {
	s.w.log().Warn(fmt.Sprintf("%s: post-write login probe failed; restoring the previous file", s.srv.Name))
	lo := &LockoutError{Path: s.path, Probe: sshconn.SanitizedError{Err: probeErr}}
	lo.Restore = s.restoreFile()
	if keys2Name != "" {
		lo.RestoreKeys2 = s.restoreKeys2(keys2Name)
	}
	return lo
}

// restoreFile puts the previous authorized_keys back.
func (s *writeSession) restoreFile() error {
	code, _, stderr, err := s.exec(restoreCmdFor(s.path, s.req.Expect.Absent, SnapshotOf(false, s.req.Content)), nil)
	switch {
	case err != nil:
		return sshconn.SanitizedError{Err: err}
	case code != 0:
		return restoreExitError(code, s.srv.Name, stderr)
	}
	return nil
}

// restoreKeys2 moves back the copy this run made.
func (s *writeSession) restoreKeys2(name string) error {
	code, _, stderr, err := s.exec(restoreKeys2Cmd(name), nil)
	switch {
	case err != nil:
		return sshconn.SanitizedError{Err: fmt.Errorf("restore authorized_keys2 on %s: %w", s.srv.Name, err)}
	case code == changedExit:
		return fmt.Errorf("restore authorized_keys2 on %s refused: it was recreated meanwhile (the disabled copy is at %s)", s.srv.Name, name)
	case code != 0:
		return stageFailure("restore authorized_keys2", s.srv.Name, code, stderr)
	}
	return nil
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite`
Expected: `ok`.

### Task 13: the restore retries a busy lock

**Files:**
- Modify: `internal/sshwrite/session.go` (`restoreFile`, new `waitLock`, `lockBackoff`, `attemptsText`), `internal/sshwrite/sshwrite.go` (`restoreExitError`)
- Create: `internal/sshwrite/session_test.go`
- Test: `internal/sshwrite/sshwrite_test.go` (`TestApplyLoginProbeFailureRestores`)

- [ ] **Step 1: Write the failing tests**

`internal/sshwrite/session_test.go`:

```go
package sshwrite

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

const busyOwner = "sshepherd-lock 1192\nv1 ci-runner-3 4121 99 1000\n"

func rejected() *seamedConnect {
	return &seamedConnect{probeErr: kinded(fleet.ErrorKindAuth, "ssh: unable to authenticate")}
}

func lockoutOf(t *testing.T, err error) *LockoutError {
	t.Helper()
	var lo *LockoutError
	if !errors.As(err, &lo) {
		t.Fatalf("err = %v, want *LockoutError", err)
	}
	return lo
}

func TestApplyRestoreRetriesBusyLock(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	restoreCmd := restoreCmdFor(sshconn.DefaultAuthorizedKeysPath, false, SnapshotOf(false, []byte("x\n")))
	count := func(s *scriptedExec) int {
		n := 0
		for _, c := range s.cmds {
			if c == restoreCmd {
				n++
			}
		}
		return n
	}
	t.Run("a busy lock that frees is retried", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: lockedExit}, {code: lockedExit}, {code: 0}}}
		w, clk := seamedWriter(s, rejected()), newClock()
		w.now, w.sleep = clk.now, clk.sleep
		lo := lockoutOf(t, w.Apply(ctx, srv, req("x\n")))
		if lo.Restore != nil || count(s) != 3 {
			t.Errorf("Restore = %v, restores = %d", lo.Restore, count(s))
		}
		if want := []time.Duration{time.Second, 3 * time.Second}; !slices.Equal(clk.slept, want) {
			t.Errorf("waits = %v, want %v", clk.slept, want)
		}
	})
	t.Run("a lock that never frees names its owner", func(t *testing.T) {
		busy := execResp{code: lockedExit, stdout: busyOwner}
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, busy, busy, busy, busy}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, req("x\n")))
		want := "restore on web-1 refused: another apply holds the lock (held by ci-runner-3 pid 4121 for 3m12s) after 4 attempts"
		if lo.Restore == nil || lo.Restore.Error() != want {
			t.Errorf("Restore = %v, want %q", lo.Restore, want)
		}
		if count(s) != 4 {
			t.Errorf("restores = %d, want 4", count(s))
		}
		if fleet.IsRefusal(lo) {
			t.Error("an unrestored lockout must never read as a refusal")
		}
	})
	t.Run("any other restore exit is final", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: 1, stderr: "mv: denied"}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || count(s) != 1 {
			t.Errorf("Restore = %v, restores = %d", lo.Restore, count(s))
		}
	})
	t.Run("the budget stops the waits", func(t *testing.T) {
		clk := newClock()
		c := rejected()
		c.onlyHook = func(context.Context) { clk.t = clk.t.Add(119500 * time.Millisecond) }
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: lockedExit, stdout: busyOwner}}}
		w := seamedWriter(s, c)
		w.now, w.sleep = clk.now, clk.sleep
		lo := lockoutOf(t, w.Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || !strings.Contains(lo.Restore.Error(), "after 1 attempt") || len(clk.slept) != 0 {
			t.Errorf("Restore = %v, waits = %v", lo.Restore, clk.slept)
		}
	})
	t.Run("a wait the context ends stops the retries", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: lockedExit, stdout: busyOwner}}}
		w := seamedWriter(s, rejected())
		waits := 0
		w.sleep = func(context.Context, time.Duration) error {
			waits++
			return errors.New("context ended")
		}
		lo := lockoutOf(t, w.Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || !strings.Contains(lo.Restore.Error(), "after 1 attempt") || count(s) != 1 || waits != 1 {
			t.Errorf("Restore = %v, restores = %d, waits = %d", lo.Restore, count(s), waits)
		}
	})
	t.Run("a failed keys2 move-back does not make the lockout unrestored", func(t *testing.T) {
		r := req("x\n")
		r.DisableKeys2 = true
		const moved = "sshepherd-keys2 authorized_keys2" + fleet.Keys2DisabledSuffix + "\n"
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: 0, stdout: moved}, {code: 0}, {code: changedExit}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, r))
		if lo.Restore != nil || lo.RestoreKeys2 == nil {
			t.Fatalf("Restore = %v, RestoreKeys2 = %v", lo.Restore, lo.RestoreKeys2)
		}
		if !strings.Contains(lo.Error(), "restored previous file") || !strings.Contains(lo.Error(), "restoring authorized_keys2 failed") {
			t.Errorf("err = %q", lo)
		}
	})
}
```

In `TestApplyLoginProbeFailureRestores`, delete the row `{name: "restore refused: locked", …}` (the busy lock now retries; `TestApplyRestoreRetriesBusyLock` owns it).

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run TestApplyRestoreRetriesBusyLock`
Expected: FAIL: `Restore = restore on web-1 refused: another apply holds the lock`, one restore, no waits.

- [ ] **Step 3: Implement**

In `internal/sshwrite/session.go` (imports gain `strconv`):

```go
// lockBackoff is the wait before each retry of a busy lock.
var lockBackoff = [...]time.Duration{time.Second, 3 * time.Second, 6 * time.Second}

// attemptsText is "1 attempt" or "N attempts".
func attemptsText(n int) string {
	if n == 1 {
		return "1 attempt"
	}
	return strconv.Itoa(n) + " attempts"
}

// waitLock waits before the next try at a busy lock; false when the
// schedule or the budget has run out.
func (s *writeSession) waitLock(attempt int) bool {
	if attempt >= len(lockBackoff) || s.remaining() <= lockBackoff[attempt] {
		return false
	}
	return s.w.sleepFn()(s.ctx, lockBackoff[attempt]) == nil
}

// restoreFile puts the previous authorized_keys back, retrying a busy lock
// on the lockBackoff schedule. Any other exit is final.
func (s *writeSession) restoreFile() error {
	script := restoreCmdFor(s.path, s.req.Expect.Absent, SnapshotOf(false, s.req.Content))
	for attempt := 0; ; attempt++ {
		code, stdout, stderr, err := s.exec(script, nil)
		switch {
		case err != nil:
			return sshconn.SanitizedError{Err: err}
		case code == lockedExit:
			if !s.waitLock(attempt) {
				info := parseLockOwner(stdout.String())
				return fmt.Errorf("restore on %s refused: another apply holds the lock (held by %s) after %s", s.srv.Name, heldText(info.owner, info.age), attemptsText(attempt+1))
			}
		case code != 0:
			return restoreExitError(code, s.srv.Name, stderr)
		default:
			return nil
		}
	}
}
```

Delete the `case lockedExit:` branch from `restoreExitError` in `sshwrite.go` (`restoreFile` handles 47; a dead branch would miss coverage), and add to its comment that 47 is handled by the retry.

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite`
Expected: `ok`.

### Task 14: reconnect and re-check after a dropped connection

**Files:**
- Modify: `internal/sshwrite/session.go` (`writeAndVerify`, `verify`, `restoreFile`, new `reconnect`, `recheckAfterDrop`, `lockedRead`, `reconnectFailed`, `unknownStateError`), `internal/sshwrite/sshwrite.go` (new `lockedReadCmdFor`)
- Test: `internal/sshwrite/session_test.go`, `internal/sshwrite/sshwrite_test.go` (`TestApplyStageFailures`, `TestScriptsAreSingleLineAndQuotePathOnce`), `internal/sshwrite/fuzz_test.go` (`FuzzWriteCmds`)

- [ ] **Step 1: Write the failing tests**

In `TestApplyStageFailures`, delete the rows `"write transport error"` and `"verify transport error"` (a drop now reconnects; the test below owns them). Add `lockedReadCmdFor` to `TestScriptsAreSingleLineAndQuotePathOnce`'s map as `"locked read": lockedReadCmdFor(hostile),` and to `FuzzWriteCmds`'s `builders` map as `"locked read": lockedReadCmdFor,`.

Add to `internal/sshwrite/session_test.go` (imports gain `os`, `path/filepath`):

```go
func TestLockedReadCmdThroughRealSh(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("reads under the lock and releases it", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "bytes\n")
			code, out := runShOut(t, sh, lockedReadCmdFor(target), home, nil)
			if code != 0 || out != "bytes\n" {
				t.Fatalf("exit = %d, out = %q", code, out)
			}
			assertNoResidue(t, target)
		})
		t.Run("a held lock exits 47", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "bytes\n")
			if err := os.Mkdir(target+lockSuffix, 0o700); err != nil {
				t.Fatal(err)
			}
			if code, _ := runShOut(t, sh, lockedReadCmdFor(target), home, nil); code != lockedExit {
				t.Fatalf("exit = %d, want %d", code, lockedExit)
			}
		})
		t.Run("an absent file in an existing directory is 44", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			if code, _ := runShOut(t, sh, lockedReadCmdFor(target), home, nil); code != sshconn.FileAbsentExit {
				t.Fatalf("exit = %d, want 44", code)
			}
			assertNoResidue(t, target)
		})
		t.Run("an absent directory is 44, not a lock failure", func(t *testing.T) {
			home := t.TempDir()
			if code, _ := runShOut(t, sh, lockedReadCmdFor(filepath.Join(home, "no", "auth")), home, nil); code != sshconn.FileAbsentExit {
				t.Fatalf("exit = %d, want 44", code)
			}
		})
	})
}

func TestApplyReconnectAfterDrop(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	const content = "rendered\n"
	drop := execResp{err: errors.New("EOF")}
	read := lockedReadCmdFor(sshconn.DefaultAuthorizedKeysPath)
	stages := []struct {
		name string
		head []execResp // what ran before the locked read
	}{
		{"write dropped", []execResp{drop}},
		{"verify dropped", []execResp{{code: 0}, drop}},
	}
	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			script := func(after ...execResp) *scriptedExec {
				return &scriptedExec{responses: append(append([]execResp{}, st.head...), after...)}
			}
			t.Run("the render is in place: the login check runs", func(t *testing.T) {
				s := script(execResp{stdout: content})
				c := &seamedConnect{}
				if err := seamedWriter(s, c).Apply(ctx, srv, req(content)); err != nil {
					t.Fatalf("Apply: %v", err)
				}
				if s.cmds[len(st.head)] != read || s.cmds[len(s.cmds)-1] != probeCmd || c.fullSeen != 2 {
					t.Errorf("cmds = %q, full connects = %d", s.cmds, c.fullSeen)
				}
				if c.opts[0].RequireOffer || !c.opts[1].RequireOffer {
					t.Errorf("RequireOffer on the write connect = %v, on the reconnect = %v; want false, true", c.opts[0].RequireOffer, c.opts[1].RequireOffer)
				}
			})
			t.Run("the snapshot still matches: original untouched", func(t *testing.T) {
				err := seamedWriter(script(execResp{stdout: "old\n"}), &seamedConnect{}).Apply(ctx, srv, req(content))
				want := "connection dropped before the rename; original untouched (re-checked under the lock)"
				if err == nil || err.Error() != want {
					t.Fatalf("err = %v, want %q", err, want)
				}
			})
			t.Run("other bytes are an unknown state", func(t *testing.T) {
				err := seamedWriter(script(execResp{stdout: "other\n"}), &seamedConnect{}).Apply(ctx, srv, req(content))
				want := "connection dropped; the file is in an unknown state (previous version at ~/.ssh/authorized_keys.sshepherd.bak) — run sshepherd audit"
				if err == nil || err.Error() != want {
					t.Fatalf("err = %v, want %q", err, want)
				}
			})
			t.Run("a busy lock is waited out", func(t *testing.T) {
				s := script(execResp{code: lockedExit}, execResp{code: lockedExit}, execResp{stdout: content})
				w, clk := seamedWriter(s, &seamedConnect{}), newClock()
				w.now, w.sleep = clk.now, clk.sleep
				if err := w.Apply(ctx, srv, req(content)); err != nil {
					t.Fatalf("Apply: %v", err)
				}
				if want := []time.Duration{time.Second, 3 * time.Second}; !slices.Equal(clk.slept, want) {
					t.Errorf("waits = %v, want %v", clk.slept, want)
				}
			})
			t.Run("a lock that never frees is an unknown state", func(t *testing.T) {
				busy := execResp{code: lockedExit}
				err := seamedWriter(script(busy, busy, busy, busy), &seamedConnect{}).Apply(ctx, srv, req(content))
				if err == nil || !strings.Contains(err.Error(), "unknown state") {
					t.Fatalf("err = %v", err)
				}
			})
			t.Run("a read that also drops is an unknown state", func(t *testing.T) {
				err := seamedWriter(script(drop), &seamedConnect{}).Apply(ctx, srv, req(content))
				if err == nil || !strings.Contains(err.Error(), "unknown state") {
					t.Fatalf("err = %v", err)
				}
			})
			t.Run("a refused reconnect is an unrestored lockout", func(t *testing.T) {
				c := &seamedConnect{fullErrs: []error{kinded(fleet.ErrorKindAuth, "unable to authenticate")}}
				err := seamedWriter(script(), c).Apply(ctx, srv, req(content))
				lo := lockoutOf(t, err)
				if !errors.Is(lo.Restore, fleet.ErrNoSession) {
					t.Fatalf("Restore = %v", lo.Restore)
				}
				if !strings.Contains(err.Error(), "a fresh login offering the keys you hold was refused") {
					t.Errorf("err = %q", err)
				}
			})
			t.Run("a reconnect that fails otherwise keeps its kind", func(t *testing.T) {
				c := &seamedConnect{fullErrs: []error{kinded(fleet.ErrorKindHostKeyChanged, "host key changed")}}
				err := seamedWriter(script(), c).Apply(ctx, srv, req(content))
				if err == nil || !strings.Contains(err.Error(), "unknown state") || fleet.ErrorKindOf(err) != fleet.ErrorKindHostKeyChanged {
					t.Fatalf("err = %v (kind %q)", err, fleet.ErrorKindOf(err))
				}
			})
			t.Run("a reconnect with nothing to offer proves nothing", func(t *testing.T) {
				c := &seamedConnect{fullErrs: []error{kinded(fleet.ErrorKindAgent, "no key to offer (agent locked, or keys removed since the plan)")}}
				err := seamedWriter(script(), c).Apply(ctx, srv, req(content))
				var lo *LockoutError
				if errors.As(err, &lo) || err == nil || !strings.Contains(err.Error(), "unknown state") || fleet.ErrorKindOf(err) != fleet.ErrorKindAgent {
					t.Fatalf("err = %v (kind %q), want an unknown state, never a lockout", err, fleet.ErrorKindOf(err))
				}
			})
		})
	}
	t.Run("a session that never opened did not start the upload", func(t *testing.T) {
		never := execResp{err: &sshconn.Error{Kind: fleet.ErrorKindRemote, Err: sshconn.ErrSessionNotOpened}}
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
	t.Run("a verify that read different bytes never reconnects", func(t *testing.T) {
		c := &seamedConnect{}
		err := seamedWriter(&scriptedExec{responses: []execResp{{code: 0}, {stdout: "tampered\n"}}}, c).Apply(ctx, srv, req(content))
		if err == nil || !strings.Contains(err.Error(), "differ") || c.fullSeen != 1 {
			t.Fatalf("err = %v, full connects = %d", err, c.fullSeen)
		}
	})
}

func TestApplyRestoreOverDeadConnection(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	drop := execResp{err: errors.New("EOF")}
	t.Run("retried over the one reconnect", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {stdout: "x\n"}, drop, {code: 0}}}
		c := rejected()
		lo := lockoutOf(t, seamedWriter(s, c).Apply(ctx, srv, req("x\n")))
		if lo.Restore != nil || c.fullSeen != 2 {
			t.Errorf("Restore = %v, full connects = %d", lo.Restore, c.fullSeen)
		}
	})
	t.Run("a failed reconnect leaves the lockout unrestored", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {stdout: "x\n"}, drop}}
		c := rejected()
		c.fullErrs = []error{kinded(fleet.ErrorKindDial, "refused")}
		lo := lockoutOf(t, seamedWriter(s, c).Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil {
			t.Error("Restore = nil, want the failure")
		}
	})
	t.Run("only one reconnect per write", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{drop, {stdout: "x\n"}, drop}} // write dropped, render in place, restore dropped
		c := rejected()
		lo := lockoutOf(t, seamedWriter(s, c).Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || c.fullSeen != 2 {
			t.Errorf("Restore = %v, full connects = %d", lo.Restore, c.fullSeen)
		}
	})
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run 'TestLockedReadCmd|TestApplyReconnectAfterDrop|TestApplyRestoreOverDeadConnection'`
Expected: FAIL to build: `undefined: lockedReadCmdFor`.

- [ ] **Step 3: Implement**

Add to `internal/sshwrite/sshwrite.go`, after `restoreCmdFor`:

```go
// lockedReadCmdFor re-reads path under the per-target lock, after a dropped
// connection: the dropped script may still be running and holding it (47).
// A missing directory reads as an absent file (44), since the lock could
// not be taken there.
func lockedReadCmdFor(path string) string {
	read := strings.TrimPrefix(sshconn.AuthorizedKeysCmdFor(path), sshconn.PathAssign(path))
	return sshconn.PathAssign(path) + `; set -f; if [ ! -d "$(dirname "$p")" ]; then exit 44; fi; ` + lockPrologue() + read
}
```

(`AuthorizedKeysCmdFor` starts with `PathAssign(path)` and continues `; if …`, so `read` keeps the separator and the path enters the script once.)

In `internal/sshwrite/session.go` (imports gain `errors`, `internal/fleet`), change the two transport-error branches to the re-check:

```go
	code, stdout, stderr, err := s.exec(writeCmdFor(s.path, s.req.Expect, len(s.req.Content)), bytes.NewReader(s.req.Content))
	if err != nil {
		// A session that never opened cannot have started the script.
		return s.recheckAfterDrop(fmt.Errorf("write on %s: %w", s.srv.Name, err), !errors.Is(err, sshconn.ErrSessionNotOpened))
	}
```

```go
	code, stdout, stderr, err := s.exec(sshconn.AuthorizedKeysCmdFor(s.path), nil)
	if err != nil {
		return s.recheckAfterDrop(fmt.Errorf("verify on %s: %w", s.srv.Name, err), true)
	}
```

Add:

```go
// errReconnectSpent: this write already used its one reconnect.
var errReconnectSpent = errors.New("the one reconnect of this write is spent")

// reconnect replaces the connection, once per write. RequireOffer: with
// nothing to offer (a locked agent) the failure is agent-kind, so it can
// never read as a refused login.
func (s *writeSession) reconnect() error {
	if s.reconnected {
		return errReconnectSpent
	}
	s.reconnected = true
	_ = s.conn.Close() // already dead, or about to be replaced
	conn, err := s.w.connectFn()(s.ctx, s.srv, sshconn.ConnectOptions{RequireOffer: true})
	if err != nil {
		return err //nolint:wrapcheck // already an *sshconn.Error carrying its kind
	}
	s.conn = conn
	return nil
}

// unknownStateError is a dropped connection that could not be settled. Its
// message is fixed; Unwrap keeps a failed reconnect's kind for error_kind.
type unknownStateError struct {
	path  string
	cause error
}

func (e *unknownStateError) Error() string {
	return fmt.Sprintf("connection dropped; the file is in an unknown state (previous version at %s%s) — run sshepherd audit", e.path, bakSuffix)
}

func (e *unknownStateError) Unwrap() error { return e.cause }

// recheckAfterDrop settles a transport error on the write connection (stage
// 1 or verify): one fresh connection, then a re-read under the lock. nil
// means the rename happened and the run continues over the new connection.
// started is false only when the stage-1 session never opened.
func (s *writeSession) recheckAfterDrop(cause error, started bool) error {
	s.w.log().Debug("connection dropped; re-checking", "server", s.srv.Name, "cause", sshconn.SanitizeRemote(cause.Error()))
	if err := s.reconnect(); err != nil {
		return s.reconnectFailed(err, started)
	}
	read, ok := s.lockedRead()
	switch {
	case !ok:
		return &unknownStateError{path: s.path}
	case !read.FileAbsent && bytes.Equal(read.Content, s.req.Content):
		return nil
	case SnapshotOf(read.FileAbsent, read.Content) == s.req.Expect:
		return errors.New("connection dropped before the rename; original untouched (re-checked under the lock)")
	}
	return &unknownStateError{path: s.path}
}

// reconnectFailed maps a failed reconnect: a login refused after the upload
// started may mean the new file locked the operator out; anything else
// leaves the file's state unknown.
func (s *writeSession) reconnectFailed(err error, started bool) error {
	clean := sshconn.SanitizedError{Err: err}
	if started && fleet.ErrorKindOf(err) == fleet.ErrorKindAuth {
		return &LockoutError{Path: s.path, Probe: clean, Restore: fleet.ErrNoSession}
	}
	return &unknownStateError{path: s.path, cause: clean}
}

// lockedRead re-reads the file under the lock, waiting out a busy lock on
// the lockBackoff schedule; false when it could not be read.
func (s *writeSession) lockedRead() (fleet.ReadResult, bool) {
	script := lockedReadCmdFor(s.path)
	for attempt := 0; ; attempt++ {
		code, stdout, stderr, err := s.exec(script, nil)
		if err != nil {
			return fleet.ReadResult{}, false
		}
		if code != lockedExit {
			res, err := sshconn.FinishRead(code, stdout, stderr, s.srv.Name, s.w.log())
			return res, err == nil
		}
		if !s.waitLock(attempt) {
			return fleet.ReadResult{}, false
		}
	}
}
```

Replace `restoreFile` so a transport error uses the one reconnect:

```go
// restoreFile puts the previous authorized_keys back, retrying a busy lock
// on the lockBackoff schedule and a dead connection over the one reconnect.
// Any other exit is final.
func (s *writeSession) restoreFile() error {
	script := restoreCmdFor(s.path, s.req.Expect.Absent, SnapshotOf(false, s.req.Content))
	for attempt := 0; ; {
		code, stdout, stderr, err := s.exec(script, nil)
		switch {
		case err != nil:
			if rerr := s.reconnect(); rerr != nil {
				return sshconn.SanitizedError{Err: fmt.Errorf("%w (and no reconnect: %w)", err, rerr)}
			}
		case code == lockedExit:
			if !s.waitLock(attempt) {
				info := parseLockOwner(stdout.String())
				return fmt.Errorf("restore on %s refused: another apply holds the lock (held by %s) after %s", s.srv.Name, heldText(info.owner, info.age), attemptsText(attempt+1))
			}
			attempt++
		case code != 0:
			return restoreExitError(code, s.srv.Name, stderr)
		default:
			return nil
		}
	}
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite`
Expected: `ok`.

### Task 15: `SkipWrite` and the warn-only headless proof

**Files:**
- Modify: `internal/sshwrite/session.go` (`run`, `rollback`, new `checkUnchanged`), `internal/sshwrite/probe.go` (`proveOrRestore`, new `headlessProof`), `internal/sshwrite/sshwrite.go` (`Apply`'s doc comment, package comment)
- Test: `internal/sshwrite/session_test.go`, `internal/sshwrite/probe_test.go`, `internal/sshwrite/sshwrite_test.go` (`TestApplyHermeticProbeReadsWrittenFile`)

- [ ] **Step 1: Write the failing tests**

In `TestApplyHermeticProbeReadsWrittenFile`, add the row for a written file that drops the survivor (auth REJECTED → restore, spec "Integration"; this table is hermetic). It needs a second key line:

```go
	otherLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, sshtest.Key(2)).PublicKey())))
```

and the row `{"the written file drops the survivor", otherLine, true, fleet.ErrorKindAuth, ""},`. This row pins behaviour already present (a refused login restores, since Task 12), so Step 2's `-run` does not select it and it passes before Step 3.

Add to `internal/sshwrite/session_test.go`:

```go
func TestApplySkipWrite(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	const moved = "sshepherd-keys2 authorized_keys2" + fleet.Keys2DisabledSuffix + "\n"
	r := req("x\n")
	r.DisableKeys2, r.SkipWrite = true, true
	t.Run("the first command is the read, and no write script runs", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "x\n"}, {stdout: moved}}}
		if err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if s.cmds[0] != sshconn.AuthorizedKeysCmdFor(sshconn.DefaultAuthorizedKeysPath) || s.cmds[1] != disableKeys2Cmd() || s.cmds[2] != probeCmd {
			t.Errorf("cmds = %q", s.cmds)
		}
	})
	t.Run("a mismatch is a refusal", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "changed\n"}}}
		err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r)
		var chg *ChangedError
		if !errors.As(err, &chg) || !fleet.IsRefusal(err) || len(s.cmds) != 1 {
			t.Fatalf("err = %v, cmds = %q", err, s.cmds)
		}
	})
	t.Run("an absent file is a refusal", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: sshconn.FileAbsentExit}}}
		if err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r); !fleet.IsRefusal(err) {
			t.Fatalf("err = %v, want a refusal", err)
		}
	})
	t.Run("a read that drops changes nothing and reports the failure", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{err: errors.New("EOF")}}}
		c := &seamedConnect{}
		err := seamedWriter(s, c).Apply(ctx, srv, r)
		if err == nil || fleet.IsRefusal(err) || c.fullSeen != 1 {
			t.Fatalf("err = %v, full connects = %d (no reconnect: nothing was written)", err, c.fullSeen)
		}
	})
	t.Run("a remote read error reports the failure", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 1, stderr: "denied"}}}
		if err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r); err == nil || fleet.IsRefusal(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a REJECTED login restores only keys2", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "x\n"}, {stdout: moved}, {code: 0}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, r))
		if lo.Restore != nil || lo.RestoreKeys2 != nil {
			t.Fatalf("lockout = %+v", lo)
		}
		last := s.cmds[len(s.cmds)-1]
		if last != restoreKeys2Cmd("authorized_keys2"+fleet.Keys2DisabledSuffix) || strings.Contains(strings.Join(s.cmds, "\n"), bakSuffix) {
			t.Errorf("cmds = %q, want only the keys2 move-back and no .bak", s.cmds)
		}
	})
	t.Run("an UNPROVEN login keeps keys2 disabled", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "x\n"}, {stdout: moved}}}
		c := &seamedConnect{probeErr: kinded(fleet.ErrorKindDial, "refused")}
		err := seamedWriter(s, c).Apply(ctx, srv, r)
		unprovenFrom(t, err)
		if len(s.cmds) != 2 {
			t.Errorf("cmds = %q, want no move-back", s.cmds)
		}
	})
}
```

Add to `internal/sshwrite/probe_test.go`:

```go
func TestApplyHeadlessProof(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	withProof := func() (Request, *[]string) {
		r := req("x\n", "SHA256:agent")
		var got []string
		r.HeadlessProof, r.OnWarning = []string{"SHA256:file"}, func(cause string) { got = append(got, cause) }
		return r, &got
	}
	t.Run("a passing proof is silent, one extra Only connect", func(t *testing.T) {
		r, got := withProof()
		c := &seamedConnect{}
		if err := seamedWriter(&scriptedExec{responses: goodWrite}, c).Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(c.opts) != 3 || !slices.Equal(c.opts[2].Only, []string{"SHA256:file"}) || len(*got) != 0 {
			t.Errorf("connects = %+v, warnings = %q", c.opts, *got)
		}
	})
	t.Run("a failed proof warns once and never restores", func(t *testing.T) {
		r, got := withProof()
		c := &seamedConnect{onlyErrs: []error{nil, kinded(fleet.ErrorKindAuth, "ssh: unable to authenticate")}}
		s := &scriptedExec{responses: goodWrite}
		if err := seamedWriter(s, c).Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v, want nil: the proof only warns", err)
		}
		if len(*got) != 1 || !strings.Contains((*got)[0], "unable to authenticate") {
			t.Errorf("warnings = %q", *got)
		}
		if len(s.cmds) != 3 { // write, verify, the probe's command
			t.Errorf("cmds = %q, want no restore", s.cmds)
		}
	})
	t.Run("skipped when the budget is too low", func(t *testing.T) {
		r, got := withProof()
		clk := newClock()
		c := &seamedConnect{onlyHook: func(context.Context) { clk.t = clk.t.Add(105 * time.Second) }}
		w := seamedWriter(&scriptedExec{responses: goodWrite}, c)
		w.now, w.sleep = clk.now, clk.sleep
		if err := w.Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if c.onlySeen != 1 || len(*got) != 0 {
			t.Errorf("only connects = %d, warnings = %q", c.onlySeen, *got)
		}
	})
	t.Run("no proof requested means no extra connect", func(t *testing.T) {
		c := &seamedConnect{}
		if err := seamedWriter(&scriptedExec{responses: goodWrite}, c).Apply(ctx, srv, req("x\n")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(c.opts) != 2 {
			t.Errorf("connects = %d, want 2", len(c.opts))
		}
	})
	t.Run("a nil OnWarning is tolerated", func(t *testing.T) {
		r, _ := withProof()
		r.OnWarning = nil
		c := &seamedConnect{onlyErrs: []error{nil, kinded(fleet.ErrorKindAuth, "x")}}
		if err := seamedWriter(&scriptedExec{responses: goodWrite}, c).Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	})
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/sshwrite -run 'TestApplySkipWrite|TestApplyHeadlessProof'`
Expected: FAIL: the first command is the write script, and there is no third `Only` connect.

- [ ] **Step 3: Implement**

In `internal/sshwrite/session.go`, `run` and `rollback` become:

```go
func (s *writeSession) run() error {
	write := s.writeAndVerify
	if s.req.SkipWrite {
		write = s.checkUnchanged
	}
	if err := write(); err != nil {
		return err
	}
	keys2Name, keys2Err := s.disableKeys2()
	if err := s.proveOrRestore(keys2Name); err != nil {
		return err
	}
	return keys2Err
}

// checkUnchanged replaces the guarded write when authorized_keys already
// holds the render (SkipWrite): nothing is locked, backed up, uploaded or
// renamed, so .bak is not rotated. The byte compare doubles as the
// compare-and-swap, catching a CRC collision too. Nothing was written, so a
// transport error needs no re-check.
func (s *writeSession) checkUnchanged() error {
	code, stdout, stderr, err := s.exec(sshconn.AuthorizedKeysCmdFor(s.path), nil)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("read on %s: %w", s.srv.Name, err)}
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, s.srv.Name, s.w.log())
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("read on %s: %w", s.srv.Name, err)}
	}
	if res.FileAbsent || !bytes.Equal(res.Content, s.req.Content) {
		return fleet.Refused(&ChangedError{Path: s.path}) //nolint:wrapcheck // Refused is the refusal marker itself; the message is the typed error's
	}
	return nil
}

// rollback restores after a REJECTED login check: the previous file (unless
// this run never wrote it) and the authorized_keys2 copy this run made.
func (s *writeSession) rollback(keys2Name string, probeErr error) error {
	s.w.log().Warn(fmt.Sprintf("%s: post-write login probe failed; restoring the previous file", s.srv.Name))
	lo := &LockoutError{Path: s.path, Probe: sshconn.SanitizedError{Err: probeErr}}
	if !s.req.SkipWrite {
		lo.Restore = s.restoreFile()
	}
	if keys2Name != "" {
		lo.RestoreKeys2 = s.restoreKeys2(keys2Name)
	}
	return lo
}
```

In `internal/sshwrite/probe.go`, the `res.err == nil` case of `proveOrRestore` also runs the proof:

```go
	case res.err == nil:
		s.w.log().Debug("login probe ok", "server", s.srv.Name, "attempts", res.attempts)
		s.headlessProof()
		return nil
```

and add:

```go
// headlessProof is D9b's warn-only check: one more login offering only the
// unrestricted --identity survivors, for a run whose production order proves
// the agent key first. A failure only warns; it can never roll back a write
// the login check proved or reinstall a revoked key. It needs no restore
// reserve, since it never restores.
func (s *writeSession) headlessProof() {
	if len(s.req.HeadlessProof) == 0 {
		return
	}
	room := s.remaining() - probeExecDeadline
	if room < minProbeDial {
		s.w.log().Debug("headless proof skipped: session budget too low", "server", s.srv.Name)
		return
	}
	_, err := s.w.probeOnce(s.ctx, s.srv, s.req.HeadlessProof, min(s.w.dialBound(), room))
	if err != nil && s.req.OnWarning != nil {
		s.req.OnWarning(sshconn.SanitizedError{Err: err}.Error())
	}
}
```

Replace `Apply`'s doc comment in `internal/sshwrite/sshwrite.go`:

```go
// Apply makes srv's authorized_keys equal req.Content: the guarded write
// script (content on stdin) or, for req.SkipWrite, a byte compare; a
// read-back verify; then a login check on a fresh connection offering only
// req.Survivors that must run a probe command. classifyProbe sorts a failed
// check by the stage it reached: a REJECTED login restores the previous
// file (*LockoutError, its Restore set when that failed too); one that
// never got past authentication keeps the file (*fleet.UnprovenError). A
// transport error during the write or verify opens one fresh connection and
// re-reads under the lock.
//
// ctx bounds and may interrupt only the connect: canceled there, Apply
// returns an error wrapping fleet.ErrWriteNotStarted and nothing changed.
// Once the write script starts, every stage runs to completion under the
// session budget — a started write always finishes, verifies and, if need
// be, rolls back. Refusals (fleet.IsRefusal: the typed refusal errors,
// wrapped by fleet.Refused) mean nothing changed. All errors pass the
// sanitized-error path: remote text never reaches a terminal raw.
```

Update the package comment's "a post-write login probe that restores the previous file when the surviving keys cannot log in" to "a post-write login check that restores the previous file when the surviving keys are refused".

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/fleet ./internal/audit ./internal/sshconn/... ./internal/sshwrite`
Expected: `ok`.

- [ ] **Step 5: Hand back** (lane `probe`; the integrator commits `feat(sshwrite): sort login-check failures by stage, retry inside the budget, re-check dropped writes (P08 W5, WP-1, WP-2, WP-6)`)

Run `make check` and `make integration`, then the conventions' hand-back steps.

**docsDelta (lane `probe`):**

- README **Safety model → One guarded write per server**, last sentence: replace "and a dropped connection leaves the original untouched (`upload incomplete … original left untouched`)." with: "If the connection drops during the upload or the verify, SSHepherd opens one fresh connection, takes the file's lock and re-reads it. The render in place means the rename happened, so the run continues; the planned bytes mean `connection dropped before the rename; original untouched (re-checked under the lock)`; anything else, or a lock that never frees, is `connection dropped; the file is in an unknown state (previous version at <path>.sshepherd.bak) — run sshepherd audit`. If that fresh login is refused with an authentication error after the upload started, the server is reported `LOCKOUT — NOT RESTORED: connection dropped after the upload started and a fresh login offering the keys you hold was refused (…)` and the run exits `2`; the previous version is at `<path>.sshepherd.bak`."
- README **Safety model → Verify, then prove you can still log in**, replace everything from "If the probe fails, the previous file" to the end of the paragraph with: "The check is sorted by how far it got. A login that never finished authentication proves nothing about the server: a dial or handshake failure is retried (up to 4 attempts, waits 0/2/5/10 s, all inside the 2-minute session budget), a locked or emptied agent once, and a host-key alarm not at all; then the new file is **kept** and the server reports `written and verified, but the login check could not reach the server after 4 attempts (…) — kept the new file; run sshepherd audit to confirm`, because undoing could reinstall a key the manifest removed. A login that was refused (every surviving key you hold offered and refused, or `MaxAuthTries`), or anything that goes wrong after it succeeded (a forced `command=`, a session that will not open, a probe command that hangs past 15 s), restores the previous file (and a disabled `authorized_keys2`) over the still-open session: `lockout prevented — restored previous file (…)`. The restore takes the lock again, waits out a busy lock (1, 3 and 6 s, naming the lock's owner and age if it never frees) and refuses to replace a file that changed since this apply wrote it (a concurrent apply); over a dropped connection it is retried once over a fresh login. If the restore fails or is refused, the message says so and names the `.bak` path."

---

## Round 3 — lane `report` (Tasks 16–21)

Owns: `internal/apply/*`, `internal/workflow/*`, `cmd/sshepherd/apply.go`, `cmd/sshepherd/editrun.go`, `cmd/sshepherd/run.go`, `cmd/sshepherd/failure_exit_test.go`, `cmd/sshepherd/testdata/help/apply.golden`, `cmd/sshepherd/testdata/help/revoke.golden`, `cmd/sshepherd/testdata/help/rotate.golden`. Findings: WP-1, WP-2 (the notice), WP-6, WP-8 (`KeysUnchanged`), D9b, D9c, D10, D10a, D10b.

This lane changes an exit-code footer, so it must apply its `docsDelta` to its worktree's `README.md` before `make check` (`TestHelpExamplesAndExitCodes` reads it).

### Task 16: the two new outcomes and the exit-2 set

**Files:**
- Modify: `internal/apply/plan.go:36-45` (outcomes), `:86-127` (`ServerPlan`), `:251-297` (`planWrite`), `:601-615` (`ExitCode`)
- Modify: `internal/apply/exec.go:90-121` (`applyOne`)
- Test: `internal/apply/plan_test.go`, `internal/apply/exec_test.go`

- [ ] **Step 1: Write the failing tests**

In `internal/apply/plan_test.go`'s `TestExitCode`, add above the table:

```go
	unproven := func(kind fleet.ErrorKind) ServerPlan {
		return ServerPlan{Class: ClassChange, Outcome: OutcomeUnproven,
			OutcomeErr: &fleet.UnprovenError{Attempts: 1, Last: &hintedErr{kind: kind, err: errors.New("x")}}}
	}
	rolled := func(revoked ...string) ServerPlan {
		return ServerPlan{Class: ClassChange, Outcome: OutcomeFailed, RolledBack: true, RevokedRemovals: revoked}
	}
```

and these rows (the file imports `errors` and `fleet` already):

```go
		{"lockout not restored", []ServerPlan{ch(OutcomeLockoutUnrestored)}, 2},
		{"applied plus lockout", []ServerPlan{ch(OutcomeApplied), ch(OutcomeLockoutUnrestored)}, 2},
		{"unproven (dial)", []ServerPlan{unproven(fleet.ErrorKindDial)}, 1},
		{"unproven, host key changed", []ServerPlan{unproven(fleet.ErrorKindHostKeyChanged)}, 2},
		{"unproven, host key revoked", []ServerPlan{unproven(fleet.ErrorKindHostKeyRevoked)}, 2},
		{"unproven, host key unknown", []ServerPlan{unproven(fleet.ErrorKindHostKeyUnknown)}, 1},
		{"unproven, key type unrecorded", []ServerPlan{unproven(fleet.ErrorKindHostKeyTypeUnrecorded)}, 1},
		{"rollback put back a revoked key", []ServerPlan{rolled("SHA256:x")}, 2},
		{"rollback, no revoked key among the removals", []ServerPlan{rolled()}, 1},
		{"revoked removals but no rollback", []ServerPlan{{Class: ClassChange, Outcome: OutcomeFailed, RevokedRemovals: []string{"SHA256:x"}}}, 1},
		{"a refused plan never exits 2", []ServerPlan{{Class: ClassRefused, Outcome: OutcomeLockoutUnrestored}}, 1},
```

Add to `internal/apply/plan_test.go` (imports gain `slices` if absent):

```go
// TestPlanRevokedRemovals (D10a): only key tombstones count, in Remove
// order; an access tombstone removed nothing that sshd would still honour.
func TestPlanRevokedRemovals(t *testing.T) {
	const accessOnly = `  - {user: bob, servers: [web-1], date: "2026-11-01"}
`
	parse := func(t *testing.T, revoked string) *config.Config {
		t.Helper()
		cfg, err := config.Parse([]byte(`serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 10) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
revoked:
` + revoked))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		return cfg
	}
	bobLine := testkeys.Line(t, 10) + "\n"
	t.Run("key tombstones in Remove order; an access tombstone does not count", func(t *testing.T) {
		// The tombstones are listed opposite to the file: the result must
		// follow Remove, which follows the file.
		cfg := parse(t, `  - {fingerprint: "`+fp(t, 9)+`", date: "2026-11-01"}
  - {fingerprint: "`+fp(t, 8)+`", date: "2026-11-01"}
`+accessOnly)
		stale := testkeys.Line(t, 8) + "\n" + bobLine + testkeys.Line(t, 9) + "\n"
		p := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg)+stale, false, false)
		if len(p.Remove) != 3 {
			t.Fatalf("Remove = %+v, want all three stale keys", p.Remove)
		}
		if want := []string{fp(t, 8), fp(t, 9)}; !slices.Equal(p.RevokedRemovals, want) {
			t.Errorf("RevokedRemovals = %v, want %v (Remove order, no access-tombstoned key)", p.RevokedRemovals, want)
		}
	})
	t.Run("only an access-tombstoned key removed: a rollback is exit 1", func(t *testing.T) {
		cfg := parse(t, accessOnly)
		p := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg)+bobLine, false, false)
		if len(p.Remove) != 1 || len(p.RevokedRemovals) != 0 {
			t.Fatalf("Remove = %+v, RevokedRemovals = %v", p.Remove, p.RevokedRemovals)
		}
		p.Outcome, p.RolledBack = OutcomeFailed, true
		if got := ExitCode([]ServerPlan{p}); got != 1 {
			t.Errorf("ExitCode = %d, want 1", got)
		}
	})
}
```

Add to `internal/apply/exec_test.go`:

```go
func TestExecuteFailureOutcomes(t *testing.T) {
	held := testKey(t, 1)
	plans := []ServerPlan{changePlan("unproven", held), changePlan("unrestored", held), changePlan("reconnect", held), changePlan("rolledback", held), changePlan("keys2", held)}
	w := &fakeWriter{errs: map[string]error{
		"unproven":   &fleet.UnprovenError{Attempts: 4, Last: errors.New("dial")},
		"unrestored": &fleet.LockoutError{Probe: errors.New("auth"), Restore: errors.New("denied")},
		"reconnect":  &fleet.LockoutError{Probe: errors.New("auth"), Restore: fleet.ErrNoSession},
		"rolledback": &fleet.LockoutError{Probe: errors.New("auth")},
		"keys2":      &fleet.LockoutError{Probe: errors.New("auth"), RestoreKeys2: errors.New("kept")},
	}}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 2, Held: agentHeld(held.Fingerprint)})
	for name, want := range map[string]struct {
		outcome Outcome
		rolled  bool
	}{
		"unproven":   {OutcomeUnproven, false},
		"unrestored": {OutcomeLockoutUnrestored, false},
		"reconnect":  {OutcomeLockoutUnrestored, false},
		"rolledback": {OutcomeFailed, true},
		"keys2":      {OutcomeFailed, true},
	} {
		if got := planFor(t, plans, name); got.Outcome != want.outcome || got.RolledBack != want.rolled || got.OutcomeErr == nil {
			t.Errorf("%s = %s rolled %v err %v", name, got.Outcome, got.RolledBack, got.OutcomeErr)
		}
	}
}
```

In `TestExecuteOutcomes`, change the `"lockout"` error to `&fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("auth failed")}` and assert `RolledBack`:

```go
	if got := planFor(t, plans, "lockout"); got.Outcome != OutcomeFailed || !got.RolledBack {
		t.Errorf("lockout = %s rolled %v, want failed and rolled back", got.Outcome, got.RolledBack)
	}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestExitCode|TestPlanRevokedRemovals|TestExecute'`
Expected: FAIL to build: `undefined: OutcomeUnproven`, `OutcomeLockoutUnrestored`, `unknown field RolledBack`, `RevokedRemovals`.

- [ ] **Step 3: Implement**

In `internal/apply/plan.go`:

```go
// The phase-2 outcomes for a ClassChange server.
const (
	OutcomePending Outcome = "pending" // not written: dry-run, declined, phase 2 not run, or interrupted before the write (OutcomeErr set)
	OutcomeApplied Outcome = "applied" // written, byte-verified, and the surviving keys proved they can log in
	OutcomeRefused Outcome = "refused" // refused at the server before any change (symlink, unsafe path, changed since plan, locked)
	OutcomeFailed  Outcome = "failed"  // write or verify failed, or a rejected login check restored the previous file
	// OutcomeUnproven: written and verified, but the login check never got
	// past authentication; the file is kept.
	OutcomeUnproven Outcome = "unproven"
	// OutcomeLockoutUnrestored: a rejected login check whose restore failed,
	// or a refused reconnect after the upload started — the operator may be
	// locked out.
	OutcomeLockoutUnrestored Outcome = "lockout_unrestored"
)
```

Add to `ServerPlan`, after `OutcomeErr error`:

```go
	// RevokedRemovals are the fingerprints in Remove on the manifest's
	// revoked: list (D10a), in Remove order.
	RevokedRemovals []string
	// RolledBack: a rejected login check restored the previous file, so the
	// keys in Remove are installed again.
	RolledBack bool
	// Warnings are the server's D9c warnings, in the order they arose.
	Warnings []string
```

In `planWrite`, directly after `p.Remove = r.Diff.Unauthorized`:

```go
		p.RevokedRemovals = revokedRemovals(cfg, p.Remove)
```

and add:

```go
// revokedRemovals returns the fingerprints of remove on the manifest's
// revoked: list. cfg is the rendered config, so revoke and rotate see the
// tombstones their own edit appended. Key tombstones only: Revoked ignores
// access tombstones.
func revokedRemovals(cfg *config.Config, remove []authkeys.Key) []string {
	var out []string
	for _, k := range remove {
		if _, ok := cfg.Revoked(k.Fingerprint); ok {
			out = append(out, k.Fingerprint)
		}
	}
	return out
}
```

Replace `ExitCode`:

```go
// ExitCode maps plans to the process exit code (monitoring-style, mirroring
// audit): 2 when any server needs a human now (needsHuman); 0 when every
// targeted server is converged — already, or applied and verified this run;
// 1 otherwise (pending under --dry-run or a declined prompt, refused,
// failed, unproven, unreachable). Tool errors (3) are the caller's domain.
func ExitCode(plans []ServerPlan) int {
	code := 0
	for _, p := range plans {
		switch {
		case needsHuman(p):
			return 2
		case p.Class == ClassConverged || (p.Class == ClassChange && p.Outcome == OutcomeApplied):
		default:
			code = 1
		}
	}
	return code
}

// needsHuman is the D28 exit-2 rule for a written server: an unrestored
// lockout (D10), a rollback that put back a key on the revoked: list
// (D10a), or a login check stopped at a host-key alarm audit would page on
// (D10b).
func needsHuman(p ServerPlan) bool {
	if p.Class != ClassChange {
		return false
	}
	switch p.Outcome {
	case OutcomeLockoutUnrestored:
		return true
	case OutcomeFailed:
		return p.RolledBack && len(p.RevokedRemovals) > 0
	case OutcomeUnproven:
		return fleet.HostKeyAlert(fleet.ErrorKindOf(p.OutcomeErr))
	}
	return false
}
```

In `internal/apply/exec.go`'s `applyOne`, the `default:` of the outcome switch becomes:

```go
	default:
		p.Outcome, p.RolledBack = failureOutcome(err)
	}
```

and add:

```go
// failureOutcome maps a started write's failure to its outcome, and whether
// the previous file was restored.
func failureOutcome(err error) (Outcome, bool) {
	var unproven *fleet.UnprovenError
	if errors.As(err, &unproven) {
		return OutcomeUnproven, false
	}
	var lockout *fleet.LockoutError
	if errors.As(err, &lockout) {
		if lockout.Restore != nil {
			return OutcomeLockoutUnrestored, false
		}
		return OutcomeFailed, true
	}
	return OutcomeFailed, false
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply`
Expected: `ok`.

### Task 17: the first-signal notice

**Files:**
- Modify: `internal/apply/exec.go:54-84` (`Execute`)
- Test: `internal/apply/exec_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/apply/exec_test.go` (imports gain `bytes`, `log/slog`, `time`):

```go
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// blockingWriter holds a write open until release closes.
type blockingWriter struct{ started, release chan struct{} }

func (w blockingWriter) Apply(context.Context, config.Server, fleet.WriteRequest) error {
	close(w.started)
	<-w.release
	return nil
}

func TestExecuteInterruptNotice(t *testing.T) {
	held := testKey(t, 1)
	t.Run("a started write gets the notice", func(t *testing.T) {
		var buf syncBuffer
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
		done := make(chan struct{})
		go func() {
			defer close(done)
			Execute(ctx, []ServerPlan{changePlan("web-1", held)}, w, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint),
				Logger: slog.New(slog.NewTextHandler(&buf, nil))})
		}()
		<-w.started
		cancel()
		const want = "finishing 1 in-flight write (write, verify, login check"
		for deadline := time.Now().Add(5 * time.Second); !strings.Contains(buf.String(), want); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("no notice; log:\n%s", buf.String())
			}
		}
		close(w.release)
		<-done
	})
	t.Run("nothing in flight, no notice", func(t *testing.T) {
		var buf syncBuffer
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		Execute(ctx, []ServerPlan{{Server: config.Server{Name: "c"}, Class: ClassConverged}}, &fakeWriter{},
			ExecOptions{Parallel: 1, Logger: slog.New(slog.NewTextHandler(&buf, nil))})
		time.Sleep(20 * time.Millisecond) // the callback runs on its own goroutine
		if strings.Contains(buf.String(), "in-flight") {
			t.Errorf("log = %s", buf.String())
		}
	})
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run TestExecuteInterruptNotice`
Expected: FAIL: `no notice; log:` after the 5 s wait.

- [ ] **Step 3: Implement**

In `Execute` (imports gain `sync/atomic`), after `sem := …`:

```go
	var inflight atomic.Int32
	stop := context.AfterFunc(ctx, func() { interruptNotice(log, int(inflight.Load())) })
	defer stop()
```

and around the write:

```go
			inflight.Add(1)
			defer inflight.Add(-1)
			applyOne(ctx, &plans[i], w, held, opts.PerServerTimeout, log)
```

Add:

```go
// interruptNotice tells the operator what the first Ctrl-C will not stop.
func interruptNotice(log *slog.Logger, n int) {
	if n > 0 {
		log.Warn(fmt.Sprintf("interrupt: finishing %s (write, verify, login check — up to 2m); a second Ctrl-C abandons their login check and rollback",
			Plural(n, "in-flight write", "in-flight writes")))
	}
}
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/apply -run TestExecute`
Expected: `ok`.

### Task 18: the request's new fields

**Files:**
- Modify: `internal/apply/plan.go` (`KeysUnchanged`), `internal/apply/exec.go` (`applyOne`, new `requestFor`, `headlessProofFor`, `headlessWarning`)
- Test: `internal/apply/exec_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/apply/exec_test.go`:

```go
func TestKeysUnchanged(t *testing.T) {
	cfg := serialCfg(t)
	body := authkeys.Header(7) + "\n" + web1Body(t, cfg)
	keys2 := planWeb1(t, cfg, body, true, false)
	if !keys2.DisableKeys2() || !keys2.KeysUnchanged() {
		t.Fatalf("keys2-only plan: disable %v, unchanged %v", keys2.DisableKeys2(), keys2.KeysUnchanged())
	}
	t.Run("the request carries SkipWrite", func(t *testing.T) {
		w := &fakeWriter{}
		plans := []ServerPlan{keys2}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(fp(t, 1))})
		if !w.calls["web-1"].SkipWrite {
			t.Error("SkipWrite = false for a plan that only disables authorized_keys2")
		}
	})
	t.Run("a Reserial header change means the file is written", func(t *testing.T) {
		plans := []ServerPlan{keys2}
		if err := Reserial(plans, 8); err != nil {
			t.Fatal(err)
		}
		if plans[0].KeysUnchanged() {
			t.Error("KeysUnchanged = true after the header changed")
		}
	})
	t.Run("without keys2 a change is never skipped", func(t *testing.T) {
		p := keys2
		p.AuthorizedKeys2 = false
		if p.KeysUnchanged() {
			t.Error("KeysUnchanged = true with nothing to disable")
		}
	})
	t.Run("different bytes are written", func(t *testing.T) {
		p := planWeb1(t, cfg, body+testkeys.Line(t, 9)+"\n", true, false)
		if p.KeysUnchanged() {
			t.Error("KeysUnchanged = true although the file differs")
		}
	})
}

func TestHeadlessProofFor(t *testing.T) {
	agent, plain, restricted := testKey(t, 1), testKey(t, 2), testKey(t, 3)
	restricted.Options = []string{`from="10.0.0.1"`}
	held := []fleet.HeldKey{
		{Fingerprint: agent.Fingerprint, Source: fleet.SourceAgent},
		fileHeld(plain.Fingerprint, "/k/ci"),
		fileHeld(restricted.Fingerprint, "/k/restricted"),
	}
	for _, tt := range []struct {
		name  string
		fps   []string
		keys  []authkeys.Key
		proof []string
		paths []string
	}{
		{"agent first, one unrestricted key file", []string{agent.Fingerprint, plain.Fingerprint}, []authkeys.Key{agent, plain},
			[]string{plain.Fingerprint}, []string{"/k/ci"}},
		{"a key file first: production already proves it", []string{plain.Fingerprint, agent.Fingerprint}, []authkeys.Key{plain, agent}, nil, nil},
		{"only a restricted key file", []string{agent.Fingerprint, restricted.Fingerprint}, []authkeys.Key{agent, restricted}, nil, nil},
		{"agent only", []string{agent.Fingerprint}, []authkeys.Key{agent}, nil, nil},
		{"nothing to offer", nil, nil, nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			proof, paths := headlessProofFor(tt.fps, tt.keys, held)
			if !slices.Equal(proof, tt.proof) || !slices.Equal(paths, tt.paths) {
				t.Errorf("got %v %v, want %v %v", proof, paths, tt.proof, tt.paths)
			}
		})
	}
}

// warningWriter calls OnWarning like the transport does.
type warningWriter struct {
	mu    sync.Mutex
	calls []fleet.WriteRequest
}

func (w *warningWriter) Apply(_ context.Context, _ config.Server, req fleet.WriteRequest) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, req)
	req.OnWarning("ssh: unable to authenticate")
	return nil
}

func TestApplyOneHeadlessWarning(t *testing.T) {
	agent, plain := testKey(t, 1), testKey(t, 2)
	plans := []ServerPlan{changePlan("web-1", agent, plain)}
	var buf syncBuffer
	w := &warningWriter{}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Logger: slog.New(slog.NewTextHandler(&buf, nil)),
		Held: []fleet.HeldKey{{Fingerprint: agent.Fingerprint, Source: fleet.SourceAgent}, fileHeld(plain.Fingerprint, "/k/ci")}})
	if got := w.calls[0].HeadlessProof; !slices.Equal(got, []string{plain.Fingerprint}) {
		t.Fatalf("HeadlessProof = %v", got)
	}
	want := "your --identity key /k/ci could not log in on its own (ssh: unable to authenticate); a headless run with only that key would fail"
	if got := planFor(t, plans, "web-1").Warnings; !slices.Equal(got, []string{want}) {
		t.Errorf("Warnings = %q", got)
	}
	if !strings.Contains(buf.String(), "web-1: "+want) {
		t.Errorf("log = %s", buf.String())
	}
}

func TestHeadlessWarningPlural(t *testing.T) {
	want := "your --identity keys /a, /b could not log in on their own (x); a headless run with only those keys would fail"
	if got := headlessWarning([]string{"/a", "/b"}, "x"); got != want {
		t.Errorf("got %q", got)
	}
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestKeysUnchanged|TestHeadless|TestApplyOneHeadlessWarning'`
Expected: FAIL to build: `keys2.KeysUnchanged undefined (type ServerPlan has no field or method KeysUnchanged)`, `undefined: headlessProofFor`, `undefined: headlessWarning`.

- [ ] **Step 3: Implement**

In `internal/apply/plan.go`, after `DisableKeys2`:

```go
// KeysUnchanged reports a plan whose only work is moving
// authorized_keys2 aside: the render equals the phase-1 snapshot, so the
// file is not rewritten and .bak is not rotated. It is evaluated after the
// commit, because Reserial may have re-rendered the header.
func (p ServerPlan) KeysUnchanged() bool {
	return p.DisableKeys2() && authkeys.ManagedSnapshot(false, p.Rendered) == p.Expect
}
```

In `internal/apply/exec.go`, replace `applyOne`'s `fps := …` line and the `w.Apply` call:

```go
	req := requestFor(p, surviving, held, log)
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	start := time.Now()
	err := w.Apply(ctx, p.Server, req)
```

and add:

```go
// requestFor builds one server's write request. OnWarning runs on this
// server's goroutine, its only writer.
func requestFor(p *ServerPlan, surviving []authkeys.Key, held []fleet.HeldKey, log *slog.Logger) fleet.WriteRequest {
	fps := probeOrderFor(p.Desired, surviving)
	proof, paths := headlessProofFor(fps, surviving, held)
	return fleet.WriteRequest{
		Content: p.Rendered, Expect: p.Expect, Survivors: fps,
		DisableKeys2: p.DisableKeys2(), SkipWrite: p.KeysUnchanged(), HeadlessProof: proof,
		OnWarning: func(cause string) {
			text := headlessWarning(paths, collapse(cause))
			p.Warnings = append(p.Warnings, text)
			log.Warn(p.Server.Name + ": " + text)
		},
	}
}

// headlessProofFor is D9b's condition: the production order proves an agent
// key first, and a surviving key file's line is unrestricted (OfferRank 0).
// It returns those key files' fingerprints and paths, in production order.
func headlessProofFor(fps []string, surviving []authkeys.Key, held []fleet.HeldKey) (proof, paths []string) {
	src := sourceMap(held)
	if len(fps) == 0 || src[fps[0]] != fleet.SourceAgent {
		return nil, nil
	}
	unrestricted := make(map[string]bool, len(surviving))
	for _, k := range surviving {
		if authkeys.OfferRank(k.Options) == 0 {
			unrestricted[k.Fingerprint] = true
		}
	}
	for _, fp := range fps {
		if unrestricted[fp] && src[fp] != fleet.SourceAgent {
			proof, paths = append(proof, fp), append(paths, src[fp])
		}
	}
	return proof, paths
}

// headlessWarning is the D9b warning's text, on stderr and in JSON alike.
func headlessWarning(paths []string, cause string) string {
	if len(paths) == 1 {
		return fmt.Sprintf("your --identity key %s could not log in on its own (%s); a headless run with only that key would fail", paths[0], cause)
	}
	return fmt.Sprintf("your --identity keys %s could not log in on their own (%s); a headless run with only those keys would fail", strings.Join(paths, ", "), cause)
}
```

(imports gain `strings`.) In `internal/apply/report.go`, replace `oneLine` so the two surfaces share one rule:

```go
// collapse folds whitespace runs to single spaces so hostile error text
// cannot forge report rows or a Summary line (terminal escapes are already
// stripped upstream).
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// oneLine is collapse for an error's text.
func oneLine(err error) string { return collapse(err.Error()) }
```

- [ ] **Step 4: Run the tests to see them pass**

Run: `GOTOOLCHAIN=go1.27.3 go test -race ./internal/apply`
Expected: `ok`.

### Task 19: the text report

**Files:**
- Modify: `internal/apply/report.go:316-349` (`summaryCounts`, `countSummary`), `:351-395` (`RenderSummary`)
- Modify: `cmd/sshepherd/apply.go:180`, `cmd/sshepherd/editrun.go:574` (the callers)
- Create: `internal/apply/testdata/summary_unproven.golden`, `summary_unproven_hostkey.golden`, `summary_lockout.golden`, `summary_restored_revoked.golden` (through `-update`)
- Test: `internal/apply/report_test.go`

- [ ] **Step 1: Write the failing tests**

In `internal/apply/report_test.go` change every `RenderSummary(&buf, plans, RenderOptions{})` and `RenderSummary(&buf, nil, RenderOptions{})` to pass `nil` as a second argument (`RenderSummary(&buf, nil, plans, RenderOptions{})`, `RenderSummary(&buf, nil, nil, RenderOptions{})`):

```bash
sed -i.bak 's/RenderSummary(&buf, plans, RenderOptions{})/RenderSummary(\&buf, nil, plans, RenderOptions{})/; s/RenderSummary(&buf, nil, RenderOptions{})/RenderSummary(\&buf, nil, nil, RenderOptions{})/' internal/apply/report_test.go && rm internal/apply/report_test.go.bak
```

Add:

```go
func appliedPlan(name string) ServerPlan {
	return ServerPlan{Server: config.Server{Name: name}, Class: ClassChange, Outcome: OutcomeApplied}
}

func unprovenPlan(name string, attempts int, hostKey bool, last error) ServerPlan {
	return ServerPlan{Server: config.Server{Name: name}, Class: ClassChange, Outcome: OutcomeUnproven,
		OutcomeErr: &fleet.UnprovenError{Path: "~/.ssh/authorized_keys", Attempts: attempts, HostKey: hostKey, Last: last}}
}

func TestRenderSummaryUnprovenGolden(t *testing.T) {
	plans := []ServerPlan{appliedPlan("web-1"), unprovenPlan("web-2", 4, false,
		&hintedErr{kind: fleet.ErrorKindDial, hint: testDialHint, err: errors.New("dial tcp 10.0.0.2:22: i/o timeout")})}
	var buf bytes.Buffer
	RenderSummary(&buf, nil, plans, RenderOptions{})
	for _, want := range []string{
		"web-2: UNPROVEN: written and verified, but the login check could not reach the server after 4 attempts (dial tcp 10.0.0.2:22: i/o timeout) — kept the new file; run sshepherd audit to confirm\n",
		"Summary: 1/2 servers converged (1 applied) · 1 unproven  → exit 1\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "summary_unproven.golden", buf.Bytes())
}

func TestRenderSummaryUnprovenHostKeyGolden(t *testing.T) {
	plans := []ServerPlan{unprovenPlan("web-1", 1, true, &hintedErr{kind: fleet.ErrorKindHostKeyChanged, err: errors.New("host key changed")})}
	var buf bytes.Buffer
	RenderSummary(&buf, nil, plans, RenderOptions{})
	for _, want := range []string{
		"web-1: UNPROVEN: written and verified, but the login check stopped at a host-key alarm (host key changed) — kept the new file; check known_hosts, then run sshepherd audit\n",
		"→ exit 2\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "summary_unproven_hostkey.golden", buf.Bytes())
}

func TestRenderSummaryLockoutGolden(t *testing.T) {
	plans := []ServerPlan{
		appliedPlan("web-1"),
		unprovenPlan("web-2", 2, false, &hintedErr{kind: fleet.ErrorKindAgent, err: errors.New("none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)")}),
		{Server: config.Server{Name: "web-3"}, Class: ClassChange, Outcome: OutcomeLockoutUnrestored,
			OutcomeErr: &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("ssh: unable to authenticate"), Restore: errors.New("restore on web-3 failed (exit 1): mv: denied")}},
	}
	var buf bytes.Buffer
	RenderSummary(&buf, nil, plans, RenderOptions{})
	for _, want := range []string{
		"web-3: LOCKOUT — NOT RESTORED: post-write login offering only the surviving keys you hold failed (ssh: unable to authenticate) AND restoring the previous file failed (restore on web-3 failed (exit 1): mv: denied) — the previous version is at ~/.ssh/authorized_keys.sshepherd.bak; repair it over a session that is still open\n",
		"Summary: 1/3 servers converged (1 applied) · 1 unproven · 1 lockout not restored  → exit 2\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "summary_lockout.golden", buf.Bytes())
}

// rolledBackPlans: a rollback that put back alice (on the revoked: list)
// and bob, beside two applied servers.
func rolledBackPlans(t *testing.T) []ServerPlan {
	t.Helper()
	alice, bob := testKey(t, 2), testKey(t, 3)
	return []ServerPlan{appliedPlan("a"), appliedPlan("b"), {
		Server: config.Server{Name: "web-1"}, Class: ClassChange, Outcome: OutcomeFailed, RolledBack: true,
		Remove: []authkeys.Key{alice, bob}, RevokedRemovals: []string{alice.Fingerprint},
		OutcomeErr: &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("ssh: unable to authenticate")},
	}}
}

func TestRenderSummaryRestoredRevokedGolden(t *testing.T) {
	var buf bytes.Buffer
	RenderSummary(&buf, &config.Config{}, rolledBackPlans(t), RenderOptions{Former: planCfg(t)})
	for _, want := range []string{
		"web-1: FAILED: lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate); it still grants alice (" + fp(t, 2) + ", on the revoked: list) and bob (" + fp(t, 3) + "), which the manifest removed — fix the surviving key and re-run\n",
		"Summary: 2/3 servers converged (2 applied) · 1 failed  → exit 2\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "summary_restored_revoked.golden", buf.Bytes())
}

func TestRollbackDetail(t *testing.T) {
	k1, k2, k3 := testKey(t, 1), testKey(t, 2), testKey(t, 3)
	k9 := testKey(t, 9)
	k9.Comment = "stray"
	cfg := planCfg(t) // op owns k1, alice k2, bob k3
	for _, tt := range []struct {
		name string
		p    ServerPlan
		want string
	}{
		{"no rollback", ServerPlan{Remove: []authkeys.Key{k1}}, ""},
		{"nothing removed", ServerPlan{RolledBack: true}, ""},
		{"one key", ServerPlan{RolledBack: true, Remove: []authkeys.Key{k2}},
			"; it still grants alice (" + k2.Fingerprint + "), which the manifest removed — fix the surviving key and re-run"},
		{"three keys, a former owner by name", ServerPlan{RolledBack: true, Remove: []authkeys.Key{k1, k2, k3}, RevokedRemovals: []string{k3.Fingerprint}},
			"; it still grants op (" + k1.Fingerprint + "), alice (" + k2.Fingerprint + ") and bob (" + k3.Fingerprint + ", on the revoked: list), which the manifest removed — fix the surviving key and re-run"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := rollbackDetail(cfg, nil, tt.p); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
	t.Run("a key neither config owns", func(t *testing.T) {
		p := ServerPlan{RolledBack: true, Remove: []authkeys.Key{k9}}
		if got := rollbackDetail(cfg, nil, p); !strings.Contains(got, audit.UnknownLabel(k9)+" (") {
			t.Errorf("got %s", got)
		}
	})
	t.Run("the former owner, when only former has it", func(t *testing.T) {
		p := ServerPlan{RolledBack: true, Remove: []authkeys.Key{k2}}
		if got := rollbackDetail(&config.Config{}, cfg, p); !strings.Contains(got, "alice (") {
			t.Errorf("got %s", got)
		}
	})
}

func TestRenderSummaryExitTwoLinesAreBoldRed(t *testing.T) {
	boldRed := "\x1b[" + codeBoldRed + "m"
	for _, tt := range []struct {
		name  string
		plan  ServerPlan
		label string
		red   bool
	}{
		{"revoked rollback", ServerPlan{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeFailed, RolledBack: true, RevokedRemovals: []string{"x"}, OutcomeErr: errors.New("e")}, "FAILED:", true},
		{"plain failure", ServerPlan{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeFailed, OutcomeErr: errors.New("e")}, "FAILED:", false},
		{"host-key unproven", unprovenPlan("a", 1, true, &hintedErr{kind: fleet.ErrorKindHostKeyRevoked, err: errors.New("e")}), "UNPROVEN:", true},
		{"dial unproven", unprovenPlan("a", 1, false, &hintedErr{kind: fleet.ErrorKindDial, err: errors.New("e")}), "UNPROVEN:", false},
		{"lockout", ServerPlan{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeLockoutUnrestored, OutcomeErr: errors.New("e")}, "LOCKOUT — NOT RESTORED:", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			RenderSummary(&buf, &config.Config{}, []ServerPlan{tt.plan}, RenderOptions{Color: true})
			if got := strings.Contains(buf.String(), boldRed+tt.label); got != tt.red {
				t.Errorf("bold red = %v, want %v:\n%q", got, tt.red, buf.String())
			}
		})
	}
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestRenderSummary|TestRollbackDetail'`
Expected: FAIL to build: `too many arguments in call to RenderSummary`, `undefined: rollbackDetail`.

- [ ] **Step 3: Implement**

In `internal/apply/report.go`, extend the tally:

```go
type summaryCounts struct {
	converged, applied, pending, refused, failed, unreachable, unproven, lockout int
}
```

and in `countSummary`'s inner switch:

```go
			case OutcomeUnproven:
				c.unproven++
			case OutcomeLockoutUnrestored:
				c.lockout++
```

Replace `RenderSummary`:

```go
// RenderSummary writes the phase-2 outcome lines (one per written, refused,
// failed, unproven, or interrupted-before-writing server) and the final
// Summary. "Converged" counts servers that needed nothing and servers
// applied-and-verified this run. cfg names the keys a rollback put back.
func RenderSummary(w io.Writer, cfg *config.Config, plans []ServerPlan, opts RenderOptions) {
	if len(plans) == 0 {
		return // Render already printed the 0-servers summary
	}
	pal := palette{on: opts.Color}
	// The summary keeps its own dedupe set: a hint seen in the plan report
	// prints again at most once here.
	var hints audit.Hints
	for _, p := range plans {
		if p.Class == ClassChange {
			renderOutcome(w, cfg, p, pal, opts, &hints)
		}
	}
	c := countSummary(plans)
	line := fmt.Sprintf("Summary: %d/%d servers converged", c.converged, len(plans))
	if c.applied > 0 {
		line += fmt.Sprintf(" (%d applied)", c.applied)
	}
	for _, seg := range []struct {
		n     int
		label string
	}{{c.pending, "pending"}, {c.failed, "failed"}, {c.refused, "refused"}, {c.unreachable, "unreachable"}, {c.unproven, "unproven"}, {c.lockout, "lockout not restored"}} {
		if seg.n > 0 {
			line += fmt.Sprintf(" · %d %s", seg.n, seg.label)
		}
	}
	fmt.Fprintf(w, "%s  → exit %d\n", line, ExitCode(plans))
}

// renderOutcome is one change server's outcome line.
func renderOutcome(w io.Writer, cfg *config.Config, p ServerPlan, pal palette, opts RenderOptions, hints *audit.Hints) {
	label, code := outcomeLabel(p)
	switch {
	case p.Outcome == OutcomeApplied:
		fmt.Fprintf(w, "%s: %s\n", p.Server.Name, pal.paint(codeGreen, "applied · verified"))
	case label != "":
		fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(code, label), collapse(outcomeText(cfg, opts.Former, p)))
		hints.Write(w, p.OutcomeErr)
	case p.OutcomeErr != nil:
		fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeYellow, "NOT STARTED:"), oneLine(p.OutcomeErr))
	}
}

// outcomeLabel is an outcome line's word and color; bold red marks every
// line that exits 2.
func outcomeLabel(p ServerPlan) (label, code string) {
	switch p.Outcome {
	case OutcomeRefused:
		return "REFUSED:", codeBoldRed
	case OutcomeLockoutUnrestored:
		return "LOCKOUT — NOT RESTORED:", codeBoldRed
	case OutcomeFailed:
		if needsHuman(p) {
			return "FAILED:", codeBoldRed
		}
		return "FAILED:", codeRed
	case OutcomeUnproven:
		if needsHuman(p) {
			return "UNPROVEN:", codeBoldRed
		}
		return "UNPROVEN:", codeYellow
	}
	return "", ""
}

// outcomeText is a failed server's message: the error, plus the keys a
// rollback put back. The JSON report's error is the same text.
func outcomeText(cfg, former *config.Config, p ServerPlan) string {
	return p.OutcomeErr.Error() + rollbackDetail(cfg, former, p)
}

// rollbackDetail names each key a rollback reinstated, marking the ones on
// the manifest's revoked: list; "" when there is no rollback or nothing was
// removed.
func rollbackDetail(cfg, former *config.Config, p ServerPlan) string {
	if !p.RolledBack || len(p.Remove) == 0 {
		return ""
	}
	parts := make([]string, 0, len(p.Remove))
	for _, k := range p.Remove {
		mark := ""
		if slices.Contains(p.RevokedRemovals, k.Fingerprint) {
			mark = ", on the revoked: list"
		}
		parts = append(parts, fmt.Sprintf("%s (%s%s)", rollbackLabel(cfg, former, k), k.Fingerprint, mark))
	}
	list := parts[len(parts)-1]
	if n := len(parts); n > 1 {
		list = strings.Join(parts[:n-1], ", ") + " and " + parts[n-1]
	}
	return fmt.Sprintf("; it still grants %s, which the manifest removed — fix the surviving key and re-run", list)
}

// rollbackLabel names a removed key: its owner in the rendered config, its
// former owner, or the unknown-key label (a key nobody owned).
func rollbackLabel(cfg, former *config.Config, k authkeys.Key) string {
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		return u.Name
	}
	if former != nil {
		if u, ok := former.OwnerOf(k.Fingerprint); ok {
			return u.Name
		}
	}
	return audit.UnknownLabel(k)
}
```

(`report.go` imports gain `slices`.) Update the callers: `cmd/sshepherd/apply.go:180` → `apply.RenderSummary(pa.stdout, pa.cfg, out.Plans, pa.ropts)`; `cmd/sshepherd/editrun.go:574` → `apply.RenderSummary(stdout, ep.edited, plans, ropts)`.

- [ ] **Step 4: Create the goldens and read them back**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestRenderSummary|TestRollbackDetail' -update`, then `git status --short internal/apply/testdata` (only the four new `summary_*.golden` files, listed as untracked: a new golden never appears in `git diff`), and read each new golden line by line against the `want` strings above.

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply ./cmd/sshepherd`
Expected: `ok`.

### Task 20: the JSON report

**Files:**
- Modify: `internal/apply/json.go:66-76` (`jsonSummary`), `:131-150` (`jsonServer`), `:243-262` (`RenderJSON`), `:365-420` (`jsonServerFor`), `:434` (`jsonErrorFor`)
- Create: `internal/apply/testdata/json_failures.golden.json`; every existing `json_*.golden.json` gains the two summary counts
- Test: `internal/apply/json_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/apply/json_test.go`. Change the one existing `jsonErrorFor(tt.p)` call (line 661) to `jsonErrorFor(nil, JSONOptions{}, tt.p)`.

```go
func TestRenderJSONFailuresGolden(t *testing.T) {
	alice, bob := testKey(t, 2), testKey(t, 3)
	server := func(n string) config.Server {
		return config.Server{Name: n, Host: "10.0.0.1", Port: 22, User: "deploy"}
	}
	plans := []ServerPlan{
		{Server: server("applied"), Class: ClassChange, Outcome: OutcomeApplied,
			Warnings: []string{"your --identity key /k/ci could not log in on its own (ssh: unable to authenticate); a headless run with only that key would fail"}},
		{Server: server("dial"), Class: ClassChange, Outcome: OutcomeUnproven,
			OutcomeErr: &fleet.UnprovenError{Attempts: 4, Last: &hintedErr{kind: fleet.ErrorKindDial, err: errors.New("dial tcp 10.0.0.1:22: i/o timeout")}}},
		{Server: server("alarm"), Class: ClassChange, Outcome: OutcomeUnproven,
			OutcomeErr: &fleet.UnprovenError{Attempts: 1, HostKey: true, Last: &hintedErr{kind: fleet.ErrorKindHostKeyChanged, err: errors.New("host key changed")}}},
		{Server: server("unrestored"), Class: ClassChange, Outcome: OutcomeLockoutUnrestored,
			OutcomeErr: &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("refused"), Restore: errors.New("denied")}},
		{Server: server("rollback"), Class: ClassChange, Outcome: OutcomeFailed, RolledBack: true,
			Remove: []authkeys.Key{alice, bob}, RevokedRemovals: []string{alice.Fingerprint},
			OutcomeErr: &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("refused")}},
	}
	out := renderJSONCfg(t, &config.Config{}, plans, JSONOptions{Command: "revoke", Former: planCfg(t)})
	checkGolden(t, "json_failures.golden.json", out)

	var doc struct {
		Summary struct {
			Unproven          int `json:"unproven"`
			LockoutUnrestored int `json:"lockout_unrestored"`
			ExitCode          int `json:"exit_code"`
		} `json:"summary"`
		Servers []struct {
			Name                string   `json:"name"`
			Outcome             string   `json:"outcome"`
			Error               string   `json:"error"`
			ErrorKind           string   `json:"error_kind"`
			RestoredRevokedKeys []string `json:"restored_revoked_keys"`
			Warnings            []string `json:"warnings"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Summary.Unproven != 2 || doc.Summary.LockoutUnrestored != 1 || doc.Summary.ExitCode != 2 {
		t.Errorf("summary = %+v", doc.Summary)
	}
	byName := map[string]int{}
	for i, s := range doc.Servers {
		byName[s.Name] = i
	}
	applied, dial, alarm, unrestored, rollback := doc.Servers[byName["applied"]], doc.Servers[byName["dial"]], doc.Servers[byName["alarm"]], doc.Servers[byName["unrestored"]], doc.Servers[byName["rollback"]]
	if len(applied.Warnings) != 1 || dial.Warnings != nil {
		t.Errorf("warnings: applied %v, dial %v (must be omitted when empty)", applied.Warnings, dial.Warnings)
	}
	if dial.Outcome != "unproven" || dial.ErrorKind != "dial" {
		t.Errorf("dial = %+v", dial)
	}
	if alarm.Outcome != "unproven" || alarm.ErrorKind != "host_key_changed" {
		t.Errorf("alarm = %+v", alarm)
	}
	if unrestored.Outcome != "lockout_unrestored" {
		t.Errorf("unrestored = %+v", unrestored)
	}
	if want := []string{alice.Fingerprint}; !slices.Equal(rollback.RestoredRevokedKeys, want) || dial.RestoredRevokedKeys != nil {
		t.Errorf("restored_revoked_keys: rollback %v, dial %v", rollback.RestoredRevokedKeys, dial.RestoredRevokedKeys)
	}
	if !strings.Contains(rollback.Error, "alice ("+alice.Fingerprint+", on the revoked: list)") {
		t.Errorf("rollback error = %q", rollback.Error)
	}
}
```

- [ ] **Step 2: Run the test to see it fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run TestRenderJSONFailuresGolden`
Expected: FAIL to build: `too many arguments in call to jsonErrorFor`.

- [ ] **Step 3: Implement**

In `jsonSummary`, after `Unreachable`:

```go
	// Unproven and LockoutUnrestored are additive (schema stays 1).
	Unproven          int `json:"unproven"`
	LockoutUnrestored int `json:"lockout_unrestored"`
```

In `jsonServer`, after `Serial`:

```go
	// RestoredRevokedKeys and Warnings are additive-optional (schema stays
	// 1): a rollback that reinstated keys on the revoked: list (D10a), and
	// the D9c headless-proof warning; each omitted when empty.
	RestoredRevokedKeys []string `json:"restored_revoked_keys,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
```

In `RenderJSON`, the summary literal gains `Unproven: c.unproven, LockoutUnrestored: c.lockout,`, and its comment becomes "a document is written for exit 0, 1 or 2 (consumers must treat an unknown outcome as not converged)".

In `jsonServerFor`, after `Serial: jsonSerialFor(p),` in the literal, add the two fields:

```go
		RestoredRevokedKeys: cleanAll(rolledBackRevoked(p)),
		Warnings:            cleanAll(p.Warnings),
```

and change the error line to `s.Error, s.ErrorKind, s.Hint = jsonErrorFor(cfg, opts, p)`. Add:

```go
// rolledBackRevoked is D10a's list: the removed keys on the revoked: list
// that a rollback put back.
func rolledBackRevoked(p ServerPlan) []string {
	if p.RolledBack {
		return p.RevokedRemovals
	}
	return nil
}
```

(`cleanAll` returns a non-nil empty slice; `omitempty` omits it by length.)

Change `jsonErrorFor`'s signature and its message line:

```go
func jsonErrorFor(cfg *config.Config, opts JSONOptions, p ServerPlan) (msg *string, kind, hint string) {
```

```go
		if p.OutcomeErr != nil {
			m := cleanLine(outcomeText(cfg, opts.Former, p))
```

Add to `jsonErrorFor`'s doc comment: "A rollback's error names the keys it put back (rollbackDetail), the same text as the report line."

- [ ] **Step 4: Regenerate and read the goldens back**

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply -run 'TestRenderJSON' -update`, then `git diff internal/apply/testdata` and confirm every existing `json_*.golden.json` changes only by the two lines `"unproven": 0,` and `"lockout_unrestored": 0,` before `"exit_code"`. `json_failures.golden.json` is new and untracked, so `git diff` does not show it: open the file itself and read it line by line.

Run: `GOTOOLCHAIN=go1.27.3 go test ./internal/apply`
Expected: `ok`.

### Task 21: exit codes reach the process; footers; the workflow contract

**Files:**
- Modify: `internal/workflow/workflow.go:119-126` (`Outcome.ExitCode`'s comment), `cmd/sshepherd/apply.go` (`plainApply.finish`, `runWorkflow`, `newWriter`), `cmd/sshepherd/run.go:207-218` (`exitCodesWrite`)
- Create: `cmd/sshepherd/failure_exit_test.go`
- Modify: `cmd/sshepherd/testdata/help/{apply,revoke,rotate}.golden` (through `-update`)
- Test: `internal/workflow/workflow_test.go`

- [ ] **Step 1: Write the failing tests**

In `internal/workflow/workflow_test.go`'s `TestOutcomeExitCode`, add above the table:

```go
	lockout := []apply.ServerPlan{{Class: apply.ClassChange, Outcome: apply.OutcomeLockoutUnrestored}}
```

and the rows:

```go
		{"confirmed, lockout not restored", Outcome{Stage: StageConfirmed, Plans: lockout}, 2},
		{"a withheld run stays 1", Outcome{Stage: StageWithheld, Plans: lockout}, 1},
```

`cmd/sshepherd/failure_exit_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

type staticWriter struct{ err error }

func (w staticWriter) Apply(context.Context, config.Server, fleet.WriteRequest) error { return w.err }

// useWriter makes every write of the run return err.
func useWriter(t *testing.T, err error) {
	t.Helper()
	saved := newWriter
	newWriter = func(*sshconn.Dialer, *slog.Logger) apply.Writer { return staticWriter{err: err} }
	t.Cleanup(func() { newWriter = saved })
}

var (
	errRefusedLogin  = errors.New("ssh: unable to authenticate")
	lockoutError     = &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errRefusedLogin, Restore: errors.New("restore failed")}
	rolledBackError  = &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errRefusedLogin}
	hostKeyChanged   = &fleet.UnprovenError{Path: "~/.ssh/authorized_keys", Attempts: 1, HostKey: true, Last: &sshconn.Error{Kind: fleet.ErrorKindHostKeyChanged, Err: errors.New("host key changed")}}
	unprovenDialFail = &fleet.UnprovenError{Path: "~/.ssh/authorized_keys", Attempts: 4, Last: &sshconn.Error{Kind: fleet.ErrorKindDial, Err: errors.New("dial timeout")}}
)

// applyDrift is a hermetic fleet with one unauthorized key installed (seed
// 9), and the manifest extended by extra; it returns the plain apply args.
func applyDrift(t *testing.T, extra string) []string {
	t.Helper()
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	target := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(target, append(fileBytes(t, target), []byte(testkeys.Line(t, 9)+" stray\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, append(fileBytes(t, cfg), extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}
}

func revokedNine(t *testing.T) string {
	t.Helper()
	return "revoked:\n  - {fingerprint: \"" + fpOf(t, 9) + "\", date: \"2026-11-01\"}\n"
}

type failDoc struct {
	Summary struct {
		ExitCode int `json:"exit_code"`
	} `json:"summary"`
	Servers []struct {
		Outcome             string   `json:"outcome"`
		ErrorKind           string   `json:"error_kind"`
		RestoredRevokedKeys []string `json:"restored_revoked_keys"`
	} `json:"servers"`
}

// runApplyFailure runs a plain apply in text, then in JSON, and checks the
// exit and the document. One fleet serves both: the static writer changes
// nothing on the server, so the first run's serial bump (saved once) leaves
// the second run planning the same write.
func runApplyFailure(t *testing.T, args []string, want int) (string, failDoc) {
	t.Helper()
	var out, errBuf bytes.Buffer
	if code := run(args, &out, &errBuf); code != want {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, want, out.String(), errBuf.String())
	}
	text := out.String()
	out.Reset()
	if code := run(append([]string{args[0], "--json"}, args[1:]...), &out, &errBuf); code != want {
		t.Fatalf("--json exit = %d, want %d\n%s", code, want, errBuf.String())
	}
	var doc failDoc
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if doc.Summary.ExitCode != want {
		t.Errorf("summary.exit_code = %d, want %d", doc.Summary.ExitCode, want)
	}
	return text, doc
}

func TestApplyLockoutUnrestoredExits2(t *testing.T) {
	useWriter(t, lockoutError)
	text, doc := runApplyFailure(t, applyDrift(t, ""), 2)
	if !strings.Contains(text, "LOCKOUT — NOT RESTORED:") || doc.Servers[0].Outcome != "lockout_unrestored" {
		t.Errorf("text:\n%s\ndoc: %+v", text, doc)
	}
}

func TestApplyRollbackRestoresRevokedKeyExits2(t *testing.T) {
	useWriter(t, rolledBackError)
	text, doc := runApplyFailure(t, applyDrift(t, revokedNine(t)), 2)
	if !strings.Contains(text, "on the revoked: list") || len(doc.Servers[0].RestoredRevokedKeys) != 1 {
		t.Errorf("text:\n%s\ndoc: %+v", text, doc)
	}
}

func TestApplyRollbackOfOrdinaryKeyExits1(t *testing.T) {
	useWriter(t, rolledBackError)
	text, _ := runApplyFailure(t, applyDrift(t, ""), 1)
	if !strings.Contains(text, "it still grants") || strings.Contains(text, "on the revoked: list") {
		t.Errorf("text:\n%s", text)
	}
}

func TestApplyProbeHostKeyChangedExits2(t *testing.T) {
	useWriter(t, hostKeyChanged)
	_, doc := runApplyFailure(t, applyDrift(t, ""), 2)
	if doc.Servers[0].Outcome != "unproven" || doc.Servers[0].ErrorKind != "host_key_changed" {
		t.Errorf("doc: %+v", doc)
	}
}

func TestApplyUnprovenDialExits1(t *testing.T) {
	useWriter(t, unprovenDialFail)
	text, _ := runApplyFailure(t, applyDrift(t, ""), 1)
	if !strings.Contains(text, "UNPROVEN:") {
		t.Errorf("text:\n%s", text)
	}
}

// TestRevokeRotateFailureExits covers the shared run body: an edit that
// saves its manifest needs a fresh fleet per run.
func TestRevokeRotateFailureExits(t *testing.T) {
	cmds := map[string]func(t *testing.T) []string{
		"revoke": func(t *testing.T) []string {
			_, kh, cfg := twoUserFleet(t)
			return []string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}
		},
		"rotate": func(t *testing.T) []string {
			_, kh, cfg := twoUserFleet(t)
			return []string{"rotate", "bob", "--old", fpOf(t, 2), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)), "--yes", "--config", cfg, "--known-hosts", kh}
		},
	}
	for cmdName, argsFor := range cmds {
		for _, tt := range []struct {
			name string
			err  error
			want int
		}{
			{"lockout not restored", lockoutError, 2},
			{"rollback put back a revoked key", rolledBackError, 2},
			{"host key changed at the login check", hostKeyChanged, 2},
			{"unproven", unprovenDialFail, 1},
		} {
			t.Run(cmdName+"/"+tt.name, func(t *testing.T) {
				useWriter(t, tt.err)
				var out, errBuf bytes.Buffer
				if code := run(argsFor(t), &out, &errBuf); code != tt.want {
					t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, out.String(), errBuf.String())
				}
				out.Reset()
				if code := run(append(argsFor(t), "--json"), &out, &errBuf); code != tt.want {
					t.Fatalf("--json exit = %d, want %d\n%s", code, tt.want, errBuf.String())
				}
				var doc failDoc
				if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Summary.ExitCode != tt.want {
					t.Errorf("doc = %+v (%v)\n%s", doc, err, out.String())
				}
			})
		}
	}
}
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd ./internal/workflow -run 'Failure|LockoutUnrestored|RollbackRestores|RollbackOfOrdinary|ProbeHostKey|UnprovenDial|RevokeRotateFailure|TestOutcomeExitCode'`
Expected: FAIL to build: `undefined: newWriter`.

- [ ] **Step 3: Implement**

In `cmd/sshepherd/apply.go`, add above `runWorkflow`:

```go
// newWriter builds a run's write transport; a test seam.
var newWriter = func(d *sshconn.Dialer, log *slog.Logger) apply.Writer {
	return &sshwrite.FleetWriter{Dialer: d, Log: log}
}
```

In `runWorkflow`'s request: `Writer: newWriter(pre.dialer(s.preferKeys), log),`.

In `plainApply.finish`, replace the last four lines:

```go
	return exitFor(out.ExitCode())
}
```

In `internal/workflow/workflow.go`:

```go
// ExitCode is 2 when a human must act now on a written server (apply.ExitCode:
// an unrestored lockout, a rollback that put back a revoked key, a host-key
// alarm at the login check); else 1 when the run was withheld or declined or
// any server did not converge, else 0.
func (o Outcome) ExitCode() int {
```

(A withheld or declined run returns 1 first, as today: no write ran.)

In `cmd/sshepherd/run.go`, the footer's `1` and `2` rows:

```go
  1  pending changes, unreachable, refused or failed servers (a newer
     manifest's serial, a policy conflict), a write whose login check could
     not prove access (unproven), or a declined prompt; with --sweep, a server
     the sweep could not read
  2  a human must act now: a lockout not restored (the restore after a
     rejected login check failed, or the reconnect after the upload started
     was refused), a rollback that put back a key on the revoked: list, a
     changed or @revoked host key at the post-write login check, or
     revoke/rotate --sweep found a revoked key still installed
```

Also in `newApplyCmd`'s `Long`, replace "fresh login offering only the surviving keys must succeed, or the\nprevious file is restored." with:

```go
			"fresh login offering only the surviving keys must succeed: a refused\n" +
			"login restores the previous file, and a login that never got past\n" +
			"authentication (network, agent, host key) keeps the new file and reports\n" +
			"UNPROVEN. --yes skips only the confirmation: an\n" +
```

(keep the sentence's tail: `"encrypted --identity key may still prompt for its passphrase.\n"` unchanged.)

Regenerate the footers:

```bash
GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd -run TestHelpGolden -update
```

Then read `git diff cmd/sshepherd/testdata/help` line by line: only the `apply`, `revoke` and `rotate` goldens change, in the footer rows above and `apply`'s `Long`.

- [ ] **Step 4: Apply the docsDelta to the worktree README and run the tests**

Apply this lane's `docsDelta` Exit-codes items to `README.md`, then:

Run: `GOTOOLCHAIN=go1.27.3 go test ./cmd/sshepherd ./internal/workflow`
Expected: `ok` (`TestHelpGolden`, `TestHelpExamplesAndExitCodes`, `TestHelpMatchesREADMETables` included).

- [ ] **Step 5: Hand back** (lane `report`; the integrator commits `feat(apply): unproven and lockout outcomes, the exit-2 set, reports and footers (P08 W5, WP-1, WP-6, D9c, D10)`)

Run `make check` and `make integration`, then the conventions' hand-back steps (the README is filtered out of the patch; the integrator applies this `docsDelta`'s Exit-codes items **before** its `make check`, see "Integrator").

**docsDelta (lane `report`)** — every sample below is re-copied from the regenerated goldens, never from this plan:

- **Exit codes** table: in the `1` row, `apply` cell: add "a write whose login check could not prove access (`unproven`), other than the host-key alarms in row `2`", and `revoke`/`rotate`: add "unproven, as for `apply`". In the `2` row, replace the `apply` cell `—` with "**Lockout not restored** (`lockout_unrestored`: the restore after a rejected login check failed, a restore over a dropped connection could not be retried, or the reconnect after the upload started was refused); a **rollback that put back a key on the manifest's `revoked:` list** (`failed`); the post-write login check **stopped at a changed or `@revoked` host key** (`unproven`)", and make the `revoke`/`rotate` cell "As for `apply`, or `--sweep` found a revoked key still installed".
- **Exit codes**, the `apply`, `revoke` and `rotate --help` block: re-copy from `cmd/sshepherd/testdata/help/apply.golden`.
- **`sshepherd apply` → JSON**: replace "exactly when the run exits `0`, `1` or (for `revoke`/`rotate --sweep`) `2`" with "exactly when the run exits `0`, `1` or `2` (`2`: a lockout not restored, a rollback that put back a key on the `revoked:` list, a changed or `@revoked` host key at the login check, or a `--sweep` hit)"; add to the `outcome` list "`unproven` (written and verified, login not proven; its `error_kind` is the last login failure's, and one of `host_key_changed`, `host_key_revoked` means exit 2), `lockout_unrestored`"; add "Treat an unknown `outcome` value as not converged." and "`summary` also counts `unproven` and `lockout_unrestored`. A `failed` server whose rollback put back removed keys names each in `error`, and `restored_revoked_keys` lists those on the `revoked:` list (omitted when empty). `warnings` lists per-server warnings (omitted when empty), today the `--identity` headless-proof warning." Re-copy the JSON samples of this section and of `sshepherd revoke` from `json_mixed.golden.json` and `json_revoke.golden.json` (each `summary` gains the two counts).
- **`sshepherd apply` summary sample**: re-copy the current example from the goldens and append three more console blocks, copied from `summary_unproven.golden`, `summary_lockout.golden` and `summary_restored_revoked.golden`.
- **Ctrl-C / SIGTERM**: after "already being written finish their write, verify and login probe (bounded by a 2-minute session budget)" add ", and a notice says so (`interrupt: finishing 2 in-flight writes (write, verify, login check — up to 2m); a second Ctrl-C abandons their login check and rollback`)". The notice's real text is `TestExecuteInterruptNotice`'s format with `n = 2`.
- **Safety model → Backups**: change "is replaced on every apply" to "is replaced by every write that rewrites `authorized_keys`", and add "`.bak` is not rotated by a write that only moves `authorized_keys2` aside: `authorized_keys` is compared and left alone when it already matches."
- **Safety model → Verify, then prove you can still log in**: change the kept-file sentence's label to name `UNPROVEN:` and add: "That is exit `1`, except that a login check stopped by a changed or `@revoked` host key is exit `2`. A restore that fails or is refused is reported `LOCKOUT — NOT RESTORED:` and is exit `2`. A rollback puts back the keys the plan removed; the `FAILED:` line names each one and marks those on the manifest's `revoked:` list, and a key on that list makes it exit `2`. In a run that mixes agent and `--identity` keys, after a passing login check one more login offers only the unrestricted key files; a failure there never undoes the write and only warns, on stderr as `warn: web-1: your --identity key /k/ci could not log in on its own (…); a headless run with only that key would fail` and in the JSON `warnings` array."
- **Container usage**: add "SIGKILL cannot be handled, so give a write time to finish: `docker stop -t 150`, or Kubernetes `terminationGracePeriodSeconds: 150`, more than the 2-minute session budget."

---

## Round 4 — lane `itest` (Tasks 22–24)

Owns: `internal/sshwrite/integration_test.go`, `cmd/sshepherd/e2e_test.go`, `scripts/integration.sh`. Findings: WP-1, WP-7, WP-8 (the real-sshd proof).

### Task 22: fixtures for MaxAuthTries and the rollback E2E

**Files:**
- Modify: `scripts/integration.sh`

- [ ] **Step 1: Add the users and the Match block**

In `scripts/integration.sh`'s `FIXTURE_A` (a single-quoted bash string, so use only double quotes inside), add `maxauth e2eroll` to both `for u in writer virgin sym …; do` lists (the `mkuser` loop and the `chown` loop). Add `maxauth` to the `for u in cas locked verifyfail …` list that copies the agent key alone. After the `cat /seed/key.pub /seed/stale.pub > /home/nrb/.ssh/authorized_keys` line add:

```bash
    # e2eroll: the agent key + the stale key the rollback E2E revokes.
    cat /seed/key.pub /seed/stale.pub > /home/e2eroll/.ssh/authorized_keys
```

After the `sshd_expect "persourcepenalties no"` line of `FIXTURE_A` add:

```bash
    # maxauth: refuses after two failed keys, for the MaxAuthTries login-check
    # test. A Match block must end the file, so it is appended (sshd_set
    # prepends).
    printf "Match User maxauth\n  MaxAuthTries 2\n" >> /etc/ssh/sshd_config
    sshd -T -C user=maxauth,host=x,addr=127.0.0.1 | grep -Eqix "maxauthtries 2" || { echo "sshd -T lacks MaxAuthTries 2 for maxauth" >&2; exit 1; }
```

- [ ] **Step 2: Check the script parses**

Run: `bash -n scripts/integration.sh`
Expected: no output, exit 0.

### Task 23: the real-sshd cases

**Files:**
- Modify: `internal/sshwrite/integration_test.go`

- [ ] **Step 1: Add the tests**

Add to `internal/sshwrite/integration_test.go` (imports gain `fmt`, `net`, `os`, `internal/fleet`, `internal/keyfile` and `internal/sshconn/sshtest` where absent):

```go
// closedPort returns a TCP port on 127.0.0.1 nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// TestIntegrationProbeTransientKeepsFile: the write lands, every login
// check dial is refused: UNPROVEN, and the new file stays.
func TestIntegrationProbeTransientKeepsFile(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "probeok", Host: host, Port: port, User: "probeok"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	closed := closedPort(t)
	w.sleep = func(context.Context, time.Duration) error { return nil } // no 17 s of real waits
	w.connect = func(ctx context.Context, s config.Server, o sshconn.ConnectOptions) (*sshconn.Conn, error) {
		if len(o.Only) > 0 {
			s.Port = closed
		}
		return w.Dialer.ConnectWith(ctx, s, o)
	}
	content := itRendered(t)
	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content))
	var un *fleet.UnprovenError
	if !errors.As(err, &un) || un.Attempts != 4 || fleet.ErrorKindOf(err) != fleet.ErrorKindDial {
		t.Fatalf("Apply = %v, want UNPROVEN after 4 dial attempts", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(content) {
		t.Errorf("file = %q, want the new file kept", got)
	}
}

// TestIntegrationStaleLockReportsOwnerAndAge: a held lock's record reaches
// the refusal; the printed removal script clears it; nothing else does.
func TestIntegrationStaleLockReportsOwnerAndAge(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "locked", Host: host, Port: port, User: "locked"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	lock := `"$HOME/.ssh/authorized_keys.sshepherd.lock"`
	remoteOut(t, w.Dialer, srv, `mkdir `+lock+` && printf 'v1 ci-runner-3 4121 99 %s\n' "$(($(date +%s) - 192))" > `+lock+`/owner`)
	t.Cleanup(func() { remoteOut(t, w.Dialer, srv, `rm -f `+lock+`/owner; rmdir `+lock+` 2>/dev/null || :`) })

	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t)))
	var locked *LockedError
	if !errors.As(err, &locked) || !locked.Known || locked.Owner != "ci-runner-3 pid 4121" {
		t.Fatalf("Apply = %v, want a known *LockedError", err)
	}
	if locked.Age < 190*time.Second || locked.Age > 5*time.Minute {
		t.Errorf("Age = %v, want about 192s", locked.Age)
	}
	if !strings.Contains(locked.RemoveCmd, srv.User+"@"+srv.Host) {
		t.Errorf("RemoveCmd = %q", locked.RemoveCmd)
	}
	if out := remoteOut(t, w.Dialer, srv, `if [ -d `+lock+` ]; then echo held; fi`); strings.TrimSpace(out) != "held" {
		t.Fatal("the lock must never be removed automatically")
	}
	remoteOut(t, w.Dialer, srv, lockRemovalScript(sshconn.DefaultAuthorizedKeysPath))
	if out := remoteOut(t, w.Dialer, srv, `if [ -d `+lock+` ]; then echo held; fi`); strings.TrimSpace(out) == "held" {
		t.Error("the printed removal script did not clear the lock")
	}
}

// TestIntegrationKeys2DisabledNeverOverwritten: an earlier disabled copy
// survives the next disable, and the new copy gets its own name.
func TestIntegrationKeys2DisabledNeverOverwritten(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itDrifted(t))})
	disabled := `"$HOME/.ssh/authorized_keys2` + fleet.Keys2DisabledSuffix + `"`
	t.Cleanup(func() {
		remoteOut(t, w.Dialer, srv, `rm -f "$HOME"/.ssh/authorized_keys2`+fleet.Keys2DisabledSuffix+`*`)
	})
	line := testkeys.Line(t, 9) + " revoked@example"
	remoteOut(t, w.Dialer, srv, `printf 'earlier\n' > `+disabled+` && printf '%s\n' '`+line+`' > "$HOME/.ssh/authorized_keys2"`)

	req := itRequest(t, w.Dialer, srv, itRendered(t))
	req.DisableKeys2 = true
	if err := w.Apply(itCtx(t), srv, req); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat `+disabled); got != "earlier\n" {
		t.Errorf("earlier copy = %q, want it kept", got)
	}
	ls := remoteOut(t, w.Dialer, srv, `ls -a "$HOME/.ssh"`)
	var stamped string
	for f := range strings.FieldsSeq(ls) {
		if name, ok := parseKeys2Name("sshepherd-keys2 " + f); ok && name != "" && name != "authorized_keys2"+fleet.Keys2DisabledSuffix {
			stamped = name
		}
	}
	if stamped == "" {
		t.Fatalf("no timestamped copy in %q", ls)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/`+stamped+`"`); got != line+"\n" {
		t.Errorf("new copy = %q", got)
	}
}

// TestIntegrationProbeHostKeyChangedKeepsFileExits2: the login check meets
// a changed host key (its known_hosts records another key): UNPROVEN, not
// retried, the file kept, and the kind is one the exit-2 rule reads.
func TestIntegrationProbeHostKeyChangedKeepsFileExits2(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "probefrom", Host: host, Port: port, User: "probefrom"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	swappedFile := sshtest.KnownHostsFile(t, fmt.Sprintf("[%s]:%d %s", host, port, testkeys.Line(t, 7)))
	swapped := &sshconn.Dialer{KnownHostsPath: swappedFile, Creds: w.Dialer.Creds, DialTimeout: w.Dialer.DialTimeout}
	onlyDials := 0
	w.connect = func(ctx context.Context, s config.Server, o sshconn.ConnectOptions) (*sshconn.Conn, error) {
		if len(o.Only) > 0 {
			onlyDials++
			return swapped.ConnectWith(ctx, s, o)
		}
		return w.Dialer.ConnectWith(ctx, s, o)
	}
	content := itRendered(t)
	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content))
	var un *fleet.UnprovenError
	if !errors.As(err, &un) || !un.HostKey || onlyDials != 1 {
		t.Fatalf("Apply = %v, only dials = %d; want a host-key UNPROVEN with no retry", err, onlyDials)
	}
	if !fleet.HostKeyAlert(fleet.ErrorKindOf(err)) {
		t.Errorf("kind = %q, want one apply.ExitCode maps to 2", fleet.ErrorKindOf(err))
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(content) {
		t.Errorf("file = %q, want the new file kept", got)
	}
}

// TestIntegrationProbeMaxAuthTriesRestores: more refused survivors than
// sshd's MaxAuthTries: the disconnect is REJECTED, with no retry, and the
// previous file comes back.
func TestIntegrationProbeMaxAuthTriesRestores(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "maxauth", Host: host, Port: port, User: "maxauth"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	var files []keyfile.Identity
	var survivors []string
	for i := byte(0); i < 4; i++ {
		k := sshtest.Key(100 + i)
		files = append(files, sshtest.Identity(t, "/k/refused", k))
		survivors = append(survivors, sshtest.Fingerprint(t, k))
	}
	agentFP := itSurvivors(t)[0]
	w.Dialer.Creds = &sshconn.Credentials{Files: files, AgentSock: os.Getenv("SSH_AUTH_SOCK")}
	w.Dialer.PreferKeys = func(config.Server) []string { return []string{agentFP} } // the write login must not exhaust MaxAuthTries
	onlyDials := 0
	w.connect = func(ctx context.Context, s config.Server, o sshconn.ConnectOptions) (*sshconn.Conn, error) {
		if len(o.Only) > 0 {
			onlyDials++
		}
		return w.Dialer.ConnectWith(ctx, s, o)
	}
	req := Request{Content: itRendered(t), Expect: itSnapshot(t, w.Dialer, srv), Survivors: survivors}
	err := w.Apply(itCtx(t), srv, req)
	var lo *LockoutError
	if !errors.As(err, &lo) || lo.Restore != nil || onlyDials != 1 {
		t.Fatalf("Apply = %v, only dials = %d; want a restored *LockoutError with no retry", err, onlyDials)
	}
	if !sshconn.AuthExhausted(lo.Probe) || fleet.ErrorKindOf(lo.Probe) != fleet.ErrorKindHandshake {
		t.Errorf("probe = %v (kind %q), want the MaxAuthTries signal", lo.Probe, fleet.ErrorKindOf(lo.Probe))
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != before {
		t.Errorf("file = %q, want the previous version restored", got)
	}
}
```

In `TestIntegrationInterruptedWriteLeavesOriginal`, replace the `if err := w.Apply(…); err == nil { … }` check with:

```go
	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content))
	if err == nil || !strings.Contains(err.Error(), "connection dropped before the rename; original untouched") {
		t.Fatalf("Apply over a dropped connection = %v, want the re-check's verdict", err)
	}
```

In `TestIntegrationConcurrentApplyLocked`, add after the `*LockedError` check:

```go
	if locked.Known || locked.Owner != ownerUnknown {
		t.Errorf("bare lock = %+v, want the unknown owner", locked)
	}
```

- [ ] **Step 2: Compile under the tag**

Run: `GOTOOLCHAIN=go1.27.3 go vet -tags=integration ./internal/sshwrite`
Expected: no output.

- [ ] **Step 3: Run against the matrix default**

Run: `make integration`
Expected: `ok` for `internal/sshwrite`, including the five new tests; they fail against the round-3 tree only where they need Task 22's `maxauth` user.

### Task 24: the rollback that puts back a revoked key, end to end

**Files:**
- Modify: `cmd/sshepherd/e2e_test.go`

- [ ] **Step 1: Add the test**

Add to `cmd/sshepherd/e2e_test.go` (imports gain `internal/authkeys` if absent):

```go
// TestE2ERevokeRollbackRestoresRevokedKey: revoke drops tmp's key and, in
// the same edit, the surviving op line carries a from= no client matches,
// so the login check is refused. The rollback puts the revoked key back:
// exit 2, the JSON and the text report's FAILED line name the key, and the
// next audit agrees (D10a, D2).
func TestE2ERevokeRollbackRestoresRevokedKey(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	k, err := authkeys.ParseLine(stale)
	if err != nil || k == nil {
		t.Fatalf("parse the stale key: %v", err)
	}
	body := `
users:
  - {name: op, keys: ["from=\"10.255.255.1\" ` + pub + `"]}
  - {name: tmp, keys: ["` + stale + `"]}
servers:
  - {name: roll, host: ` + host + `, port: ` + port + `, user: e2eroll}
access:
  - {user: op, servers: [roll]}
  - {user: tmp, servers: [roll]}
`
	m := writeE2EManifest(t, t.TempDir(), "roll.yaml", body)
	code, out, stderr := runBin(t, bin, "revoke", "tmp", "--json", "--yes", "--config", m, "--known-hosts", kh)
	if code != 2 {
		t.Fatalf("revoke exit = %d, want 2 (stderr: %s)\n%s", code, stderr, out)
	}
	var doc struct {
		Summary struct {
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
		Servers []struct {
			Outcome             string   `json:"outcome"`
			Error               string   `json:"error"`
			RestoredRevokedKeys []string `json:"restored_revoked_keys"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || len(doc.Servers) != 1 {
		t.Fatalf("json: %v\n%s", err, out)
	}
	s := doc.Servers[0]
	if s.Outcome != "failed" || doc.Summary.ExitCode != 2 || len(s.RestoredRevokedKeys) != 1 || s.RestoredRevokedKeys[0] != k.Fingerprint {
		t.Errorf("doc = %+v", doc)
	}
	if !strings.Contains(s.Error, "tmp ("+k.Fingerprint+", on the revoked: list)") {
		t.Errorf("error = %q, want the tombstoned key named", s.Error)
	}
	if got := e2eRemoteCat(t, host, port, kh, "e2eroll"); !strings.Contains(got, strings.Fields(stale)[1]) {
		t.Errorf("the rollback did not put the file back:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 2 {
		t.Errorf("audit after the rollback exit = %d, want 2 (a revoked key is installed) (stderr: %s)\n%s", code, stderr, out)
	}
	// The rollback put the file back, so a fresh copy of the manifest drives
	// the same revoke in text mode: the FAILED line names the key too.
	m2 := writeE2EManifest(t, t.TempDir(), "roll-text.yaml", body)
	code, out, stderr = runBin(t, bin, "revoke", "tmp", "--yes", "--config", m2, "--known-hosts", kh)
	if code != 2 {
		t.Fatalf("text revoke exit = %d, want 2 (stderr: %s)\n%s", code, stderr, out)
	}
	if !strings.Contains(out, "FAILED:") || !strings.Contains(out, "tmp ("+k.Fingerprint+", on the revoked: list)") {
		t.Errorf("text report does not name the tombstoned key:\n%s", out)
	}
}
```

- [ ] **Step 2: Run the E2E**

Run: `make integration`
Expected: `ok` for `cmd/sshepherd`, including `TestE2ERevokeRollbackRestoresRevokedKey`.

- [ ] **Step 3: Hand back** (lane `itest`; the integrator commits `test(integration): real-sshd login-check, lock and keys2 cases; rollback E2E (P08 W5, WP-1, WP-7, WP-8)`)

Run `make check`, `make integration IT_DISTRO=alpine`, then the conventions' hand-back steps.

**docsDelta (lane `itest`):** CLAUDE.md, Testing bullet "End-to-end (E2E)": add "`TestE2ERevokeRollbackRestoresRevokedKey` drives a refused login check to a rollback that puts a revoked key back (exit 2)." No README change.

---

## Integrator: before round 1, round 3, and the wave's last commit

**Before round 1** (one commit, `docs(plan): write-path failure semantics plan and approved spec (P08)`; the scout requires both committed):

- Commit this plan at `docs/superpowers/plans/2026-11-08-write-failure-semantics.md`.
- Copy the approved spec over `docs/superpowers/specs/2026-11-08-write-failure-semantics-design.md` and apply "Spec amendments" below to it.

**Spec amendments** (each closes a gap the review found; none changes a decision's meaning):

1. §1 "Locked agent, in full": after item 3, add: "4. The reconnect after a dropped write (section 4) sets `ConnectOptions.RequireOffer`: with no key to offer, `ConnectWith` returns an `agent`-kind error before dialing, so a locked agent can never read as a refused reconnect."
2. §4 reconnect table, row 3: replace "the reconnect fails with a non-auth kind, or the bytes are anything else" with "the reconnect fails with a non-auth kind (an empty offer is `agent`, section 1), the reconnect is refused when the stage-1 session never opened (`sshconn.ErrSessionNotOpened`: nothing was uploaded), or the bytes are anything else".
3. §6, the warn line: replace `` `web-1: warning: your --identity key /k/ci `` with `` `warn: web-1: your --identity key /k/ci `` (the `warn: ` is `clog`'s level prefix, printed once), and in D9c replace "without the `web-1: warning: ` prefix" with "without the `web-1: ` prefix".
4. D9b's README cell: replace "`<server>: warning: your --identity key <path>" with "`warn: <server>: your --identity key <path>".
5. Testing → Integration: replace "(the sshd host key swapped between write and probe, through the same harness as the `host_key_changed` E2E case)" with "(the probe's dials use a `known_hosts` recording another key, as the `host_key_changed` E2E case does)".
6. Testing → `internal/sshconn` item 3: append "`TestConnectRequireOfferEmptyIsAgent`: `RequireOffer` with no key to offer → `agent`, no dial; without it the dial happens. `TestExecMarksASessionThatNeverOpened`: the marker on a dead connection only." Testing → `internal/sshwrite` item 9: append "A session that never opened in stage 1, then a refused reconnect → unknown state, not a lockout; a reconnect with nothing to offer → unknown state, kind `agent`."

**Round 3, lane `report`** (also the runner's `handoffs` entry): before `make check`, apply the lane's Exit-codes `docsDelta` to `README.md` (the table rows, and the `apply`/`revoke`/`rotate --help` block copied from `cmd/sshepherd/testdata/help/apply.golden`). `TestHelpExamplesAndExitCodes` requires README to contain `exitCodesWrite` verbatim, and the patch carries no README change. Apply the rest of that `docsDelta` as usual.

**After lane `itest`, in the last commit of the wave:**

- Set the spec's Status to `Implemented (W5, 2026-11-08).`
- CLAUDE.md **Status**: replace the paragraph beginning "The write-failure semantics spec (P08: …" with: "Write-failure semantics (P08, specced in `docs/superpowers/specs/2026-11-08-write-failure-semantics-design.md`): the post-write login check is sorted by the stage it reached (`classifyProbe`); a login that never got past authentication is retried and then reported UNPROVEN with the file kept, a refused login or anything after a successful one restores it. Exit 2 now also covers an unrestored lockout, a rollback that puts back a key on the `revoked:` list and a post-write changed or `@revoked` host key. Locks record owner and age and print their removal command (never removed automatically); a dropped connection reconnects once and re-checks under the lock; moved-aside `authorized_keys2` copies are never overwritten and a keys2-only write leaves `authorized_keys` and `.bak` alone; a mixed-source run proves an unrestricted `--identity` key on its own, warn-only; a serial bump that would overflow the read limit withholds the run."
- CLAUDE.md **Status**, fuzz sentence: "every one of the 19 `Fuzz*` targets" becomes "every one of the 20 `Fuzz*` targets".
- `docs/superpowers/plans/2026-11-07-review-remediation.md`: mark P08-impl done in its wave table.

---

## Self-review

**Spec coverage.**

| Spec | Tasks |
|---|---|
| §1 classifyProbe table, stage record | 11 |
| §1 locked agent (1, 2, 3) | 3 (none and partial), 2 (signer) |
| §1/§4 a locked agent at the reconnect (`RequireOffer`, spec amendment 1) | 3, 14 |
| §4 row 4's "the exec had started" boundary (`ErrSessionNotOpened`, spec amendment 2) | 4, 14 |
| §1 MaxAuthTries, `auth` needs a verified host key | 1, 2, 11 |
| §1 probe exec deadline, `SessionTimeout` | 4, 12 |
| §1 retry policy, budget arithmetic, explicit deadline, `sleep` seam | 10, 12 |
| §1 UNPROVEN error and messages | 9, 12 |
| §1 rollback naming the keys; `RevokedRemovals`, `RolledBack`, `rollbackDetail` | 16, 19, 20 |
| §2 split `Restore`/`RestoreKeys2`, move, `BackupSuffix` | 9, 12 |
| §2 restore retry on 47 with owner and age | 13 |
| §2 outcomes, exit set, `HostKeyAlert` | 9, 16 |
| §2 text and JSON | 19, 20 |
| §2 command layer, footers | 19, 21 |
| §3 lock owner record, busy output, strict parse, message, never automatic | 5, 6 |
| §4 first-signal notice | 17 |
| §4 container note | docsDelta (report) |
| §4 reconnect-and-recheck table; restore over a dead connection | 14 |
| §5 keys2 retention | 7 |
| §5 `KeysUnchanged`, `SkipWrite` | 18, 15 |
| §6 headless proof, D9c | 15, 18, 20 |
| §7 `ReserialOversize`, `question`, `dryRunBump` | 8 |
| Testing: sshconn 1–5 | 1, 2, 3, 4, 11 |
| Testing: sshwrite 1–10 | 11, 12, 13, 5–7, 15, 14 |
| Testing: apply 1–7 | 16, 17, 18, 8, 19, 20 |
| Testing: command layer | 8, 21 |
| Testing: integration and E2E | 15 (hermetic drop-the-survivor), 23, 24; the UNPROVEN E2E gap is plan decision 16 |

**Spec test names → this plan's.** The spec's Testing list is covered under these names:

| Spec | Plan |
|---|---|
| `TestWriteCmdThroughRealSh` (lock cases: dash, bash, busybox) | `TestLockOwnerRecordThroughRealSh` (Task 5), which uses the same `forEachShell` matrix |
| `TestExecuteOutcomes` additions | `TestExecuteFailureOutcomes` (Task 16); `TestExecuteOutcomes` keeps the `RolledBack` assertion |
| "Retry and UNPROVEN (extends `TestApplyLoginProbeFailureRestores`)" | `TestApplyProbeRetryAndUnproven` (Task 12), with the two row changes in `TestApplyLoginProbeFailureRestores` |
| `TestIntegrationProbeHostKeyChangedKeepsFileExits2` (sshd host key swapped) | same name; the probe's `known_hosts` is swapped instead (decision 17, spec amendment 5) |

`TestIntegrationLoginProbeRestores` and `TestProbeOfferEqualsProductionOffer` exist at `4390667` and the spec only requires they stay green.

**Placeholder scan.** No TBD; `docsDelta` items that name a golden are copied at hand-back, by convention.

**Type consistency.** `fleet.UnprovenError{Path, Attempts, HostKey, Last}`, `fleet.LockoutError{Path, Probe, Restore, RestoreKeys2}`, `verdict`/`probeStage`, `writeSession`, `lockInfo{owner, age, known}`, `LockedError{Path, Owner, Age, Known, RemoveCmd}`, `dialFacts{user, addr, hk, rec, asked, missing}`, `hostKeyState{verdict, verified}`, `ConnectOptions.{SessionTimeout, RequireOffer}`, `sshconn.ErrSessionNotOpened`, `recheckAfterDrop(cause, started)`, `reconnectFailed(err, started)` and `RenderSummary(w, cfg, plans, opts)` are used with these names and shapes throughout.

---

## Review log

Two independent reviews of the draft, each issue checked against the code at `4390667`, the spec and the runner in the remediation plan. All 19 issues were confirmed and applied; none was rejected. The code added in this revision was written read-only and has not been compiled or run; the lanes' failing-first runs are its first execution.

| Review | Issue | Result |
|---|---|---|
| 0.1 | README lacks the refused reconnect | Applied (lane `probe` docsDelta). |
| 0.2 | Decision 11 widens exit 2 | Applied: `ErrSessionNotOpened` (Task 4), `started` (Task 14), rows for stage 1 and verify; decision 11 rewritten; spec amendment 2. |
| 0.3 | Locked agent at the reconnect | Applied: `RequireOffer`, `emptyOffer` (Task 3), reconnect and test (Task 14); decision 18; spec amendment 1. |
| 0.4 | `TestPlanRevokedRemovals` vacuous | Applied (Task 16). Remove follows the file (`authkeys` diff); tombstones are listed opposite; bob's key is in the removal. |
| 0.5 | E2E never asserts the FAILED line | Applied (Task 24): a fresh manifest on the same user, since the rollback restored the file, so no new fixture. |
| 0.6 | D9b's stderr line | Applied, first option: `warn: web-1: your --identity key …` (decision 5, Task 18, README, spec amendments 3 and 4). |
| 0.7 | Two docsDelta wordings | Applied. |
| 0.8 | Names and method differ from the spec | Applied: mapping table in Self-review, decision 17, spec amendment 5. |
| 1.1 | Integrator gate fails on lane `report` | Applied: Integrator "Round 3", how-it-is-cut item 2, `handoffs` line in Wave lanes. |
| 1.2 | revive on `UnprovenError:` | Applied (Task 9). Confirmed in revive v1.17.1's `exported` rule; the only exported type with that form. |
| 1.3 | Signer test misses `SignWithAlgorithm` | Applied (Task 2): both paths in one test. |
| 1.4 | Trap-before-owner order unpinned | Applied (Task 5), also for the restore script's `lockPrologue()`, which the reviewer's fix did not reach. |
| 1.5 | Untested branches | Applied: `TestSleepCtx` (Task 10), a seamed sleep error in the probe retries (Task 12) and in `waitLock` (Task 13). |
| 1.6 | G703 on `os.WriteFile` | Applied (Task 23); `path/filepath` was dropped from the added imports only, since the file already uses it. |
| 1.7 | `git diff` cannot show new goldens | Applied (Tasks 19, 20). |
| 1.8 | Wrong Expected text | Applied (Tasks 3, 6, 18). Corrected for Task 3: the test fatals on the kind first, so `accepted == 1` is never printed. |
| 1.9 | Unlabelled pin tests | Applied (Tasks 12, 15). |
| 1.10 | Wall-clock convention | Applied: scoped to `internal/sshwrite`; the sshconn test now uses a 2 s dial bound and a 2.3 s handler (Task 4). |
| 1.11 | Plan location | Applied: header, Integrator, Wave lanes. |

---

## Wave lanes (for the runner)

- **`plan`** (the runner's `args.plan`): `docs/superpowers/plans/2026-11-08-write-failure-semantics.md`, committed with the spec before round 1.
- **`handoffs`** (the runner's `args.handoffs`), one entry: "P08 lane report: before make check, apply that lane's Exit-codes docsDelta to README.md (the table rows and the apply/revoke/rotate --help block copied from cmd/sshepherd/testdata/help/apply.golden). TestHelpExamplesAndExitCodes requires README to contain exitCodesWrite verbatim, and the patch carries no README change."

Rounds run in sequence; lanes inside a round own disjoint files and build only on the previous rounds' commits. Globs are shell `case` patterns (`*` crosses `/`). `README.md` and `CLAUDE.md` belong to no lane: each lane hands its README/CLAUDE.md text over as `docsDelta` (and, for lane `report`, applies it locally only to pass `make check`). The integrator commits once per lane, in the order the rounds list them.

```json
{
  "rounds": [
    [
      {
        "pkg": "P08",
        "lane": "conn",
        "kind": "fix",
        "ids": ["WP-1"],
        "tasks": "Tasks 1-4",
        "files": [
          "internal/sshconn/connect.go",
          "internal/sshconn/errors.go",
          "internal/sshconn/session.go",
          "internal/sshconn/handshake_test.go"
        ],
        "needsIntegration": true
      },
      {
        "pkg": "P08",
        "lane": "scripts",
        "kind": "fix",
        "ids": ["WP-7", "WP-8"],
        "tasks": "Tasks 5-7",
        "files": [
          "internal/sshwrite/sshwrite.go",
          "internal/sshwrite/sshwrite_test.go",
          "internal/sshwrite/lock.go",
          "internal/sshwrite/lock_test.go",
          "internal/sshwrite/fuzz_test.go",
          "internal/sshwrite/testdata/fuzz/FuzzParseLockOwner/*"
        ],
        "needsIntegration": true
      },
      {
        "pkg": "P08",
        "lane": "reserial",
        "kind": "fix",
        "ids": ["W4-reserial"],
        "tasks": "Task 8",
        "files": [
          "internal/apply/serialbump.go",
          "internal/apply/serialbump_test.go",
          "internal/apply/json.go",
          "cmd/sshepherd/apply.go",
          "cmd/sshepherd/apply_serial_test.go"
        ],
        "needsIntegration": false
      }
    ],
    [
      {
        "pkg": "P08",
        "lane": "probe",
        "kind": "fix",
        "ids": ["WP-1", "WP-2", "WP-6", "WP-8"],
        "tasks": "Tasks 9-15",
        "files": [
          "internal/fleet/*",
          "internal/audit/errors.go",
          "internal/sshconn/errors.go",
          "internal/sshconn/handshake_test.go",
          "internal/sshwrite/sshwrite*.go",
          "internal/sshwrite/session*.go",
          "internal/sshwrite/probe*.go",
          "internal/sshwrite/fuzz_test.go"
        ],
        "needsIntegration": true
      }
    ],
    [
      {
        "pkg": "P08",
        "lane": "report",
        "kind": "fix",
        "ids": ["WP-1", "WP-2", "WP-6", "WP-8"],
        "tasks": "Tasks 16-21",
        "files": [
          "internal/apply/*",
          "internal/workflow/*",
          "cmd/sshepherd/apply.go",
          "cmd/sshepherd/editrun.go",
          "cmd/sshepherd/run.go",
          "cmd/sshepherd/failure_exit_test.go",
          "cmd/sshepherd/testdata/help/apply.golden",
          "cmd/sshepherd/testdata/help/revoke.golden",
          "cmd/sshepherd/testdata/help/rotate.golden"
        ],
        "needsIntegration": true
      }
    ],
    [
      {
        "pkg": "P08",
        "lane": "itest",
        "kind": "fix",
        "ids": ["WP-1", "WP-7", "WP-8"],
        "tasks": "Tasks 22-24",
        "files": [
          "internal/sshwrite/integration_test.go",
          "cmd/sshepherd/e2e_test.go",
          "scripts/integration.sh"
        ],
        "needsIntegration": true
      }
    ]
  ],
  "mergeOrder": ["P08"]
}
```
