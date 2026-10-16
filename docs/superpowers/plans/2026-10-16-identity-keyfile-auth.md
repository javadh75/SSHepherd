# `--identity` Key-File Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add repeatable `--identity PATH` key files (with `--identity-passphrase-file FILE`, `--identity-passphrase KEY=FILE` and a foreground-only `/dev/tty` prompt) to `audit`, `adopt` and `apply`, in union with `ssh-agent`, so SSHepherd runs headless (CI, cron, containers) without weakening apply's self-lockout guard or its post-write login probe.

**Architecture:** A new pure-ish `internal/keyfile` reads each key/passphrase file once through a descriptor-checked `FS` (OpenSSH's permission rule, bounded reads), classifies the container before any prompt, resolves passphrases (per-key file → default file → terminal) and fingerprints the decrypted key. `internal/sshconn.Credentials` is the run's single credential source (key files + agent): `Signers` (fetched before the dial) and `Held` (plain keys with their source; certificates offered but never held). `sshread.CheckCredentials` replaces the agent preflight; `internal/apply`'s guard, survivor order and probe reason over every held key; `cmd/sshepherd` declares the flags per command and enforces the order of operations (flags → manifest → empty-fleet return → known_hosts → key files → credentials check).

**Tech Stack:** Go 1.26, `golang.org/x/crypto/ssh` (+`agent`), `golang.org/x/sys/unix` (termios, `TIOCGPGRP`), `golang.org/x/term`, Cobra/pflag, goleak, native fuzzing, golden files (`-update`), the dockerized-sshd integration harness (`scripts/integration.sh`).

**Spec (binding, owner-approved, final):** [`docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md`](../specs/2026-10-16-identity-keyfile-auth-design.md). Work on `master` (trunk-based); every commit is green on its own.

**Provenance:** every code block, patch, golden and expected output below was produced from a full prototype of this plan and then replayed task by task from the current `master` (`e50a9b1`): each task's failing step fails as stated, each passing step passes, the gate (`gofmt`, `go vet` incl. `-tags integration`, `golangci-lint`, `go test -race ./...`) is green at every group boundary, the final `make check` pieces (`deadcode`, `go mod tidy -diff`, coverage 89.6%) pass, and `make integration` (real sshd, `SSH_AUTH_SOCK` unset) passes all new tests. A review pass (2026-10-16) re-replayed the whole plan after adding the pseudo-terminal prompter tests (K6), the encrypted embedded-key mismatch test (K7), the TCP-level "signers before the dial" check (T2) and the manifest/`--server`-before-prompt check (C1): same result, the pty tests verified on macOS and in a Linux container.

---

## Execution model

Parallel agents each execute **one group**. Groups in the same stage touch **disjoint files**; every cross-group type, function and user-visible string is pinned in [Interfaces](#interfaces) — code against that section, never against another group's in-progress work.

| Stage | Group | Tasks | Owns |
| ----- | ----- | ----- | ---- |
| 1 | **K** | K1–K8 | `internal/keyfile/**` (new), `.gitleaks.toml`, `go.mod`/`go.sum` (x/sys promoted) |
| 1 (parallel with K) | **T** | T1–T3 | `internal/sshconn/**` (incl. `sshtest`), `internal/sshread/**` |
| 2 | **W** | W1–W3 | `internal/apply/**`, `internal/sshwrite/**`, a bridge edit in `cmd/sshepherd/apply.go`, one README sample line |
| 3 | **C** | C1–C4 | `cmd/sshepherd/**`, `README.md`, `scripts/integration.sh`, `Makefile`, `CLAUDE.md`, the two amended specs, `go.mod` (pflag promoted); C2 also removes T's transitional code in `internal/sshconn` and `internal/sshread` |

**Cross-stage bridges (keep every commit green):**

1. **The K/T contract file.** T imports `internal/keyfile` for `keyfile.Identity` only. `internal/keyfile/identity.go` is pinned byte-for-byte below; K1 creates it, and T1 creates the identical file if K has not landed in T's tree. Identical additions merge cleanly.
2. **Transitional agent-only fields (T → C2).** `sshconn.Dialer.AgentSock` and `sshread.Client.AgentSock` stay (used only when `Creds` is nil), and `sshread.CheckAgent` / `sshconn.AgentFingerprints` stay exported, so `cmd/sshepherd` and `internal/sshwrite` compile unchanged after stage 1. C2 removes them all.
3. **The W1 bridge.** `apply.Build` / `apply.ExecOptions` change signature in W1; W1 adds a 9-line `agentHeld` adapter to `cmd/sshepherd/apply.go`, which C1 replaces with `Credentials.Held`.
4. **`deadcode`** (whole-program reachability from `main`) reports `internal/keyfile` and parts of `sshconn.Credentials` from K/T until C1 wires them, exactly as the apply slice's plan allowed between its tasks. Run the per-task gate below; run full `make check` in C4.

## Conventions for every task

- **The gate** (before every commit):
  ```bash
  test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
  ```
- **Patches.** Edits to existing files are given as unified diffs; apply each from the repository root with the `git apply <<'PATCH' … PATCH` block shown (copy the block verbatim — tabs are significant). If a patch does not apply, you are not on the expected base: stop and re-check the previous task, never hand-merge.
- **New files** are given in full; create them exactly.
- **Goldens:** regenerate with `-update`, then compare with the content shown. An unexpected golden diff is a failing test.
- **Tests and `HOME`:** a test must not depend on the developer's `~/.ssh/known_hosts` or agent. C1's final run uses an empty `HOME` to prove it.
- **`-race` timing:** x/crypto marshals bcrypt keys with 16 rounds (about a second per marshal or decrypt under `-race`), so keyfile tests share one encrypted fixture and use legacy PEM (cheap KDF) wherever the container does not matter. Keep it that way: `internal/keyfile` runs in about 15 s under `-race`.
- **Commit messages** end with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` (each commit step shows the exact command).
- **Never** put a passphrase, key bytes or passphrase-file contents in a log line, error or report; wrap x/crypto errors, never format key material.


## Interfaces

Everything here is pinned. Groups code against it; changing anything here is a cross-group change.

### `internal/keyfile` (Group K)

The cross-group contract file, **byte-identical** in K1 and (if needed) T1 — `internal/keyfile/identity.go`:

```go
// Package keyfile loads the private key files named by --identity. Each
// file is opened once and checked on that descriptor (OpenSSH's permission
// rule, bounded reads); the container is classified before any prompt;
// passphrases resolve from a per-key file, then the default file, then the
// controlling terminal; and every key is fingerprinted from its decrypted
// form. Passphrases, passphrase-file contents and key bytes never reach a
// log line or an error message.
package keyfile

import "golang.org/x/crypto/ssh"

// Identity is one loaded --identity key. Path is the cleaned absolute path
// the operator named; Fingerprint is ssh.FingerprintSHA256 of the DECRYPTED
// key's public half (never a label read before decryption).
type Identity struct {
	Path        string
	Fingerprint string
	Signer      ssh.Signer
}
```

The rest of the exported surface (K):

```go
type Spec struct{ Path string } // cleaned absolute path (Resolve builds it)

type Passphrases struct {
	Default string            // passphrase file path, "" if none
	PerKey  map[string]string // key path -> passphrase file path
}

type Prompter interface { // /dev/tty in production (NewTTY), fakes in tests
	Available() bool
	ReadPassphrase(ctx context.Context, prompt string) ([]byte, error)
}

type FileInfo struct {
	Mode fs.FileMode // full mode, type bits included (fstat of the OPEN descriptor)
	UID  int         // owner
}

type FS interface {
	Open(path string) (io.ReadCloser, FileInfo, error) // one open; FileInfo of that descriptor
	Stat(path string) (FileInfo, error)                // diagnostics only (the EACCES message)
	UID() int                                          // current uid
}

type OSFS struct{} // the real FS (unix); refuses off unix
type TTY struct{ /* unexported */ }
func NewTTY() *TTY // implements Prompter

// Resolve: lexical validation of the three flags (exit 3 in the CLI).
func Resolve(identities []string, defaultFile string, perKey []string, home, cwd string) ([]Spec, Passphrases, error)

// Load: reads, classifies, unlocks; identities in flag order, de-duplicated by
// decrypted fingerprint. log receives the info lines (nil discards).
func Load(ctx context.Context, specs []Spec, pp Passphrases, p Prompter, fsys FS, log *slog.Logger) ([]Identity, error)
```

### `internal/sshconn` (Group T)

```go
const SourceAgent = "agent"

type HeldKey struct {
	Fingerprint string
	Source      string // the --identity path (cleaned, absolute) or SourceAgent
}
func (k HeldKey) Label() string // "SHA256:… (/home/ci/.ssh/ci)" / "SHA256:… (agent)"

type Credentials struct { // use by pointer: one per run
	Files     []keyfile.Identity
	AgentSock string       // "" = no agent
	Log       *slog.Logger // optional
	// unexported: sync.Once for the one-time degraded-agent warning
}
func (c *Credentials) Signers(ctx context.Context) ([]ssh.Signer, func(), error)
func (c *Credentials) Held(ctx context.Context) ([]HeldKey, error)

type Dialer struct {
	KnownHostsPath string
	KnownHosts     *KnownHosts
	Creds          *Credentials // NEW
	AgentSock      string       // TRANSITIONAL (T2 → removed in C2): used only when Creds is nil
	DialTimeout    time.Duration
	PreferKeys     func(srv config.Server) []string
	Log            *slog.Logger
}
// ConnectOptions, ConnectWith, Conn.SessionKeyFP: unchanged signatures.
// TRANSITIONAL until C2: func AgentFingerprints(ctx context.Context, sock string) ([]string, error)
```

`sshtest` additions (T1):

```go
func AgentKeys(tb testing.TB, keys ...agent.AddedKey) string                // keyring incl. certificates
func UserCert(tb testing.TB, priv, ca any, principal string) *ssh.Certificate // server: list the cert in Authorized
func Identity(tb testing.TB, path string, priv any) keyfile.Identity         // file-key auth, no agent, no disk
func WriteKeyFile(tb testing.TB, dir, name string, priv any, passphrase []byte) string // OpenSSH key 0600 (+ .pub)
```

### `internal/sshread` (Group T)

```go
func CheckCredentials(ctx context.Context, creds *sshconn.Credentials, needHeld bool) error

type Client struct {
	KnownHostsPath string
	KnownHosts     *sshconn.KnownHosts
	Creds          *sshconn.Credentials // NEW
	AgentSock      string               // TRANSITIONAL (T3 → removed in C2)
	DialTimeout    time.Duration
	PreferKeys     func(srv config.Server) []string
	Log            *slog.Logger
}
// TRANSITIONAL until C2 (then unexported checkAgent): func CheckAgent(ctx context.Context, sock string) error
```

### `internal/apply` (Group W)

```go
func Build(cfg *config.Config, results []audit.ServerResult, held []sshconn.HeldKey) ([]ServerPlan, error)

type ExecOptions struct {
	Parallel         int
	PerServerTimeout time.Duration
	Held             []sshconn.HeldKey // replaces AgentFPs: the post-prompt listing
	Logger           *slog.Logger
}

// ServerPlan gains:
//	AgentOnly string // the agent-only-survivor warning text ("" = none)
// Survivors(desired []authkeys.Key, held map[string]bool) []authkeys.Key is unchanged.
```

`internal/sshwrite`: no API change (wording only).

### `cmd/sshepherd` (Group C, package-internal)

```go
type identityFlags struct{ paths []string; defaultFile string; perKey []string }
func (f *identityFlags) register(cmd *cobra.Command)
type identities struct{ specs []keyfile.Spec; pp keyfile.Passphrases }
func validateFlags(parallel int, idf *identityFlags) (identities, error) // step 1
var newPrompter = func() keyfile.Prompter { return keyfile.NewTTY() }   // test seam
func (ids identities) credentials(ctx context.Context, log *slog.Logger) (*sshconn.Credentials, error) // step 5
func checkCredentials(ctx context.Context, creds *sshconn.Credentials, needHeld bool) error            // step 6
```

### Pinned user-visible strings (asserted across groups)

| String | Produced by | Asserted by |
| ------ | ----------- | ----------- |
| `identity loaded` (log message, attrs `path`, `fp`) | K7 | C1, C3 |
| `KEY is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase KEY=FILE)` | K7 | C1, README |
| `permissions 0644 for FILE are too open (chmod 600 FILE)` | K3 | C1, README |
| `cannot read key file FILE as uid N (owner M, mode 0600) — see README 'Container usage'` (`passphrase file` for a passphrase file) | K3 | K3, README |
| `passphrase flags need --identity`; `… matches no --identity (--identity paths: …)`; `… is given twice`; `want KEY=FILE` | K5 | C1 |
| today's agent messages verbatim (contain `SSH_AUTH_SOCK`), prefixed `agent preflight:` | T3 / C1 | existing tests, C3 |
| `ssh-agent unusable (…) — continuing with the --identity keys only` | T1 | T1, T2 |
| `none of the N keys you hold (identity files + agent) would remain …` / `… lock this session out (held: …)` | W1 | existing E2E (`lock this session out`), README |
| `rotating an --identity key? pass the new key with another --identity …` | W1 | C3 |
| `only SHA256:… (agent) keeps access; none of your --identity keys survives — a run without this agent will be locked out` | W1/W2 | W2 golden, README |
| `post-write login offering only the surviving keys you hold failed` | W3 | W2 (summary golden literal), README |


## File structure

| Path | Group/Task | Responsibility |
| ---- | ---------- | -------------- |
| `internal/keyfile/identity.go` | K1 (contract) | Package doc + `Identity` |
| `internal/keyfile/types.go` | K1 | `Spec`, `Passphrases`, `Prompter` |
| `internal/keyfile/classify.go` | K2 | Container classification before any prompt (PuTTY, PKCS#8, DSA, OpenSSH header: cipher/KDF/rounds/key count/`ssh-dss`/`sk-*`, legacy PEM headers) |
| `internal/keyfile/read.go` | K3 | `FS`, `FileInfo`, size caps, one-open descriptor-checked reads, permission rule, EACCES message, read-once passphrase files, `.pub` label |
| `internal/keyfile/osfs_unix.go`, `osfs_other.go` | K4 | `OSFS` |
| `internal/keyfile/resolve.go` | K5 | Lexical flag validation (`Resolve`) |
| `internal/keyfile/line.go`, `tty_unix.go`, `termios_{linux,darwin}.go`, `tty_other.go` | K6 | `/dev/tty` prompter (tested headless plus on a pseudo-terminal: `tty_pty_test.go`, `pty_{linux,darwin}_test.go`) |
| `internal/keyfile/keyfile.go` | K7 | `Load`: resolution order, wrong-passphrase semantics, fingerprints, de-dup, cert note, wipe |
| `internal/keyfile/testdata/` | K8 | ssh-keygen throwaway fixtures (+README), `.ppk` header |
| `internal/keyfile/*_test.go` | K2–K8 | fakes (`fakefs_test.go`, prompter in `load_test.go`), generators (`keygen_test.go`), unit + fuzz tests |
| `.gitleaks.toml` | K8 | Path-scoped allowlist for `internal/keyfile/testdata/` |
| `internal/sshconn/credentials.go` | T1 | `Credentials`, `HeldKey`, `SourceAgent` |
| `internal/sshconn/sshtest/sshtest.go` | T1 | `AgentKeys`, `UserCert`, `Identity`, `WriteKeyFile` |
| `internal/sshconn/connect.go` | T2, C2 | `Dialer.Creds`, signers before the dial; C2 drops `AgentSock` |
| `internal/sshconn/session.go` | C2 | `AgentFingerprints` removed |
| `internal/sshread/sshread.go` | T3, C2 | `CheckCredentials`, `Client.Creds`; C2: `CheckAgent` → `checkAgent`, `AgentSock` dropped |
| `internal/apply/plan.go`, `exec.go` | W1 | Held keys with sources, refusal text, rotation hint, `AgentOnly`, `probeOrder` |
| `internal/apply/report.go` (+goldens) | W2 | Render `AgentOnly` |
| `internal/sshwrite/sshwrite.go` | W3 | Source-neutral wording |
| `cmd/sshepherd/identity.go` | C1 | Flags, `validateFlags`, prompter seam, `credentials`, `checkCredentials` |
| `cmd/sshepherd/{audit,adopt,apply}.go` | C1 (W1 bridge) | Order of operations, one `Credentials` per run |
| `cmd/sshepherd/help_readme_test.go` | C1 | `--help` ↔ README flag tables |
| `cmd/sshepherd/identity_integration_test.go`, `scripts/integration.sh` | C3 | Real sshd, no agent: audit, encrypted apply, rotation, E2E loop |
| `README.md` | W2 (one sample line), C1 | Flags, **Authentication**, CI recipes, Container usage, safety-model wording |
| `Makefile` | C3 | `FuzzClassify`, `FuzzDecrypt` in `make fuzz` |
| `CLAUDE.md`, audit + apply specs | C4 | Status paragraph; "amended by" notes |


## Tasks


### Group K — `internal/keyfile` (stage 1)


#### Task K1 (Group K · stage 1): `internal/keyfile` contract and package skeleton

**Files:**
- Create: `internal/keyfile/identity.go`
- Create: `internal/keyfile/types.go`
- Create: `internal/keyfile/leak_test.go`

Creates the package with its exported value types only. `identity.go` is the
**cross-group contract**: Group T (running in parallel) creates a byte-identical
copy if it gets there first, so the two branches merge without conflict. Do not
change a byte of it.

- [ ] **Step 1: Create the contract file (exactly this content — Group T relies on it byte for byte):** `internal/keyfile/identity.go`

```go
// Package keyfile loads the private key files named by --identity. Each
// file is opened once and checked on that descriptor (OpenSSH's permission
// rule, bounded reads); the container is classified before any prompt;
// passphrases resolve from a per-key file, then the default file, then the
// controlling terminal; and every key is fingerprinted from its decrypted
// form. Passphrases, passphrase-file contents and key bytes never reach a
// log line or an error message.
package keyfile

import "golang.org/x/crypto/ssh"

// Identity is one loaded --identity key. Path is the cleaned absolute path
// the operator named; Fingerprint is ssh.FingerprintSHA256 of the DECRYPTED
// key's public half (never a label read before decryption).
type Identity struct {
	Path        string
	Fingerprint string
	Signer      ssh.Signer
}
```

- [ ] **Step 2: Create the remaining exported value types:** `internal/keyfile/types.go`

```go
package keyfile

import "context"

// Spec names one --identity key file by its cleaned absolute path
// (Resolve builds it).
type Spec struct{ Path string }

// Passphrases names the passphrase files of a run: Default for any
// encrypted key, PerKey (key path -> passphrase file path) for one key.
// Paths are cleaned and absolute (Resolve builds them); "" means none.
type Passphrases struct {
	Default string
	PerKey  map[string]string
}

// Prompter asks the operator for a passphrase: the controlling terminal in
// production (NewTTY), a fake in tests. Available reports whether a prompt
// can be answered at all; ReadPassphrase returns ctx.Err() (wrapped) when
// ctx ends mid-prompt.
type Prompter interface {
	Available() bool
	ReadPassphrase(ctx context.Context, prompt string) ([]byte, error)
}
```

- [ ] **Step 3: Every package gets the goleak `TestMain`:** `internal/keyfile/leak_test.go`

```go
package keyfile

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
```

- [ ] **Step 4: Run**

```bash
go vet ./internal/keyfile && go test ./internal/keyfile
```

Expected: PASS — `ok  github.com/javadh75/SSHepherd/internal/keyfile ... [no tests to run]` (types only; behavior lands test-first from K2 on).

- [ ] **Step 5: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/keyfile/identity.go internal/keyfile/types.go internal/keyfile/leak_test.go
git commit -m "$(cat <<'EOF'
feat(keyfile): package contract — Identity, Spec, Passphrases, Prompter

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task K2 (Group K · stage 1): Container classification before any prompt

**Files:**
- Create: `internal/keyfile/classify.go`
- Create: `internal/keyfile/keygen_test.go`
- Create: `internal/keyfile/classify_test.go`

`classify` inspects the key bytes itself — x/crypto's API cannot tell a PuTTY
file from encrypted PKCS#8 from a 4096-round bcrypt key — and refuses unsupported
containers with a conversion hint **before** anyone is asked for a passphrase.
Every file-controlled string in an error is `%q`-quoted. Formats x/crypto cannot
produce (other ciphers, >2048 rounds, multi-key files, `ssh-dss`/`sk-*` public
sections) are built at test time by rewriting a real key's header
(`editOpenSSH`). `sharedEncrypted` caches one bcrypt key: x/crypto always uses
16 rounds, about a second per marshal/decrypt under `-race`.

- [ ] **Step 1: Write the key-fixture generators (test-only):** `internal/keyfile/keygen_test.go`

```go
package keyfile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// edKey is a deterministic ed25519 key.
func edKey(seed byte) ed25519.PrivateKey {
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	return ed25519.NewKeyFromSeed(raw)
}

// opensshPEM marshals priv as an OpenSSH key, encrypted (aes256-ctr,
// bcrypt, 16 rounds — x/crypto's choice) when pass is non-nil.
func opensshPEM(t testing.TB, priv any, pass []byte) []byte {
	t.Helper()
	var (
		block *pem.Block
		err   error
	)
	if pass == nil {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", pass)
	}
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// editOpenSSH rewrites an OpenSSH key's header — the formats x/crypto
// cannot produce (other ciphers, many rounds, several keys, a mismatched
// or hardware public section) are made from a real key this way.
func editOpenSSH(t testing.TB, data []byte, edit func(h *opensshHeader)) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	var h opensshHeader
	if err := ssh.Unmarshal(block.Bytes[len(opensshMagic):], &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	edit(&h)
	block.Bytes = append([]byte(opensshMagic), ssh.Marshal(h)...)
	return pem.EncodeToMemory(block)
}

// withRounds sets the bcrypt rounds of an encrypted OpenSSH key's header.
func withRounds(t testing.TB, data []byte, rounds uint32) []byte {
	t.Helper()
	return editOpenSSH(t, data, func(h *opensshHeader) {
		var o bcryptOpts
		if err := ssh.Unmarshal([]byte(h.KdfOpts), &o); err != nil {
			t.Fatalf("kdf opts: %v", err)
		}
		o.Rounds = rounds
		h.KdfOpts = string(ssh.Marshal(o))
	})
}

// pubBlob marshals a public-key wire blob of an arbitrary type name.
func pubBlob(typ string) []byte {
	return ssh.Marshal(struct {
		Type string
		Key  []byte
	}{typ, make([]byte, 32)})
}

// dssBlob marshals an ssh-dss public-key wire blob.
func dssBlob() []byte {
	one := big.NewInt(1)
	return ssh.Marshal(struct {
		Type       string
		P, Q, G, Y *big.Int
	}{"ssh-dss", one, one, one, one})
}

// ecKey is a fresh P-256 key (legacy PEM fixtures).
func ecKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	return k
}

// legacyPEM marshals k as SEC1 "EC PRIVATE KEY", encrypted with
// AES-256-CBC (RFC 1423) when pass is non-nil.
func legacyPEM(t testing.TB, k *ecdsa.PrivateKey, pass []byte) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("marshal ec: %v", err)
	}
	if pass == nil {
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	//nolint:staticcheck // SA1019: legacy encrypted PEM is exactly the format under test
	block, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, pass, x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt pem: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// sharedPass unlocks sharedEncrypted.
const sharedPass = "right"

// encryptedOnce caches one bcrypt-encrypted OpenSSH key. x/crypto always
// marshals with 16 bcrypt rounds — about a second per marshal or decrypt
// under -race — so tests share this one key, and prefer legacy PEM (whose
// KDF is cheap) wherever the container does not matter.
var encryptedOnce struct {
	sync.Once
	data []byte
}

// sharedEncrypted is edKey(2) as an aes256-ctr/bcrypt OpenSSH key
// encrypted with sharedPass.
func sharedEncrypted(t testing.TB) []byte {
	t.Helper()
	encryptedOnce.Do(func() { encryptedOnce.data = opensshPEM(t, edKey(2), []byte(sharedPass)) })
	return bytes.Clone(encryptedOnce.data)
}
```

- [ ] **Step 2: Write the failing tests:** `internal/keyfile/classify_test.go`

```go
package keyfile

import (
	"encoding/pem"
	"strings"
	"testing"
)

func TestClassifyAccepts(t *testing.T) {
	ed := edKey(1)
	tests := []struct {
		name      string
		data      []byte
		format    format
		encrypted bool
	}{
		{"openssh unencrypted", opensshPEM(t, ed, nil), formatOpenSSH, false},
		{"openssh aes256-ctr bcrypt", sharedEncrypted(t), formatOpenSSH, true},
		{"openssh aes256-cbc", editOpenSSH(t, sharedEncrypted(t), func(h *opensshHeader) { h.CipherName = "aes256-cbc" }), formatOpenSSH, true},
		{"openssh bcrypt at the 2048-round cap", withRounds(t, sharedEncrypted(t), 2048), formatOpenSSH, true},
		{"legacy EC PEM", legacyPEM(t, ecKey(t), nil), formatPEM, false},
		{"legacy EC PEM encrypted", legacyPEM(t, ecKey(t), []byte("pw")), formatPEM, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cls, err := classify("/k", tt.data)
			if err != nil {
				t.Fatalf("classify: %v", err)
			}
			if cls.format != tt.format || cls.encrypted != tt.encrypted {
				t.Errorf("classification = %+v, want format %d encrypted %v", cls, tt.format, tt.encrypted)
			}
			if tt.format == formatOpenSSH && cls.pub == nil {
				t.Error("OpenSSH classification lacks the embedded public key")
			}
		})
	}
}

func TestClassifyRefusesBeforeAnyPrompt(t *testing.T) {
	ed := edKey(1)
	enc := sharedEncrypted(t)
	plain := opensshPEM(t, ed, nil)
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{"PuTTY", []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"), []string{"is a PuTTY key", "puttygen /k -O private-openssh"}},
		{"not PEM at all", []byte("hello"), []string{"no PEM block", "ssh-keygen -p -f /k"}},
		{"encrypted PKCS#8", pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{0x30, 0}}), []string{"encrypted PKCS#8", "ssh-keygen -p -f /k"}},
		{"legacy encrypted PKCS#8 header", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00000000000000000000000000000000"}, Bytes: []byte{0}}), []string{"encrypted PKCS#8"}},
		{"DSA PEM", pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte{0x30, 0}}), []string{"ssh-dss is disabled by default in OpenSSH"}},
		{"unknown block", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE\x1b[31m", Bytes: []byte{0}}), []string{`unsupported key block "CERTIFICATE\x1b[31m"`}},
		{"gcm cipher", editOpenSSH(t, enc, func(h *opensshHeader) { h.CipherName = "aes256-gcm@openssh.com" }), []string{`cipher "aes256-gcm@openssh.com" is not supported`, "ssh-keygen -p -f /k"}},
		{"chacha cipher", editOpenSSH(t, enc, func(h *opensshHeader) { h.CipherName = "chacha20-poly1305@openssh.com" }), []string{`cipher "chacha20-poly1305@openssh.com"`}},
		{"unknown KDF", editOpenSSH(t, enc, func(h *opensshHeader) { h.KdfName = "scrypt" }), []string{`KDF "scrypt" is not supported`}},
		{"cipher without KDF", editOpenSSH(t, enc, func(h *opensshHeader) { h.KdfName = "none" }), []string{"cipher without a KDF"}},
		{"KDF without cipher", editOpenSSH(t, enc, func(h *opensshHeader) { h.CipherName = "none" }), []string{"KDF without a cipher"}},
		{"malformed KDF options", editOpenSSH(t, enc, func(h *opensshHeader) { h.KdfOpts = "x" }), []string{"malformed bcrypt KDF options"}},
		{"rounds over 2048", withRounds(t, enc, 2049), []string{"bcrypt KDF rounds 2049 exceed the supported maximum of 2048", "ssh-keygen -p -a 100 -f /k"}},
		{"two keys", editOpenSSH(t, plain, func(h *opensshHeader) { h.NumKeys = 2 }), []string{"holds 2 keys"}},
		{"ssh-dss public section", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = dssBlob() }), []string{"ssh-dss is disabled by default"}},
		{"sk-ed25519 hardware key", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = pubBlob("sk-ssh-ed25519@openssh.com") }), []string{"hardware keys must be used via ssh-agent"}},
		{"sk-ecdsa hardware key", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = pubBlob("sk-ecdsa-sha2-nistp256@openssh.com") }), []string{"hardware keys must be used via ssh-agent"}},
		{"garbage public section", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = []byte{1, 2} }), []string{"malformed embedded public key"}},
		{"unknown public key type", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = pubBlob("ssh-foo") }), []string{`unsupported embedded public key "ssh-foo"`}},
		{"bad magic", pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("openssh-key-v0\x00")}), []string{"malformed OpenSSH private key"}},
		{"legacy PEM unknown cipher", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "BF-CBC,0000000000000000"}, Bytes: []byte{0}}), []string{`PEM encryption "BF-CBC,0000000000000000" is not supported`}},
		{"legacy PEM no DEK-Info", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{0}}), []string{"PEM encryption"}},
		{"legacy PEM bad IV", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00"}, Bytes: []byte{0}}), []string{"bad IV"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := classify("/k", tt.data)
			if err == nil {
				t.Fatal("classify accepted it")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err = %q, want it to contain %q", err, w)
				}
			}
			if strings.ContainsRune(err.Error(), '\x1b') {
				t.Errorf("err %q carries a raw escape byte", err)
			}
		})
	}
}
```

- [ ] **Step 3: Run**

```bash
go test ./internal/keyfile -run Classify
```

Expected: FAIL — build failure: `undefined: classify` (and `undefined: opensshHeader`).

- [ ] **Step 4: Implement:** `internal/keyfile/classify.go`

```go
package keyfile

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// format is a key file's container.
type format int

const (
	formatOpenSSH format = iota + 1 // "OPENSSH PRIVATE KEY" (openssh-key-v1)
	formatPEM                       // legacy PEM: PKCS#1 RSA, SEC1 EC, unencrypted PKCS#8
)

// maxBcryptRounds is x/crypto's cap on the bcrypt KDF's rounds.
const maxBcryptRounds = 2048

// opensshMagic opens every openssh-key-v1 payload.
const opensshMagic = "openssh-key-v1\x00"

// opensshHeader mirrors the openssh-key-v1 layout (PROTOCOL.key) up to the
// encrypted private section, so the container can be judged before any
// passphrase is asked for — x/crypto's API cannot tell these cases apart.
type opensshHeader struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
	Rest         []byte `ssh:"rest"`
}

// bcryptOpts is the bcrypt KDF's option string.
type bcryptOpts struct {
	Salt   []byte
	Rounds uint32
}

// classification is what classify learned without a passphrase.
type classification struct {
	format    format
	encrypted bool
	pub       ssh.PublicKey // OpenSSH's embedded public key; nil for PEM
	rounds    uint32        // bcrypt rounds (OpenSSH, encrypted); 0 otherwise
}

// classify judges a key file's container before any prompt: formats
// x/crypto cannot use (or that sshepherd refuses) are refused with a
// conversion hint, so an operator never types a passphrase for a key that
// was never going to work. Every file-controlled string in an error is
// %q-quoted.
func classify(path string, data []byte) (classification, error) {
	if bytes.HasPrefix(data, []byte("PuTTY-User-Key-File-")) {
		return classification{}, fmt.Errorf("%s is a PuTTY key — convert it with `puttygen %s -O private-openssh -o NEWFILE`", path, path)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return classification{}, refuse(path, "not a private key file (no PEM block found)")
	}
	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		return classifyOpenSSH(path, block.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		return classification{}, refuse(path, "encrypted PKCS#8 keys are not supported")
	case "DSA PRIVATE KEY":
		return classification{}, dsaRefusal(path)
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
		return classifyPEM(path, block)
	default:
		return classification{}, refuse(path, fmt.Sprintf("unsupported key block %q", block.Type))
	}
}

// refuse is the generic refusal, carrying the rewrite hint.
func refuse(path, reason string) error {
	return fmt.Errorf("%s: %s — rewrite it in a supported format with `ssh-keygen -p -f %s`", path, reason, path)
}

func dsaRefusal(path string) error {
	return fmt.Errorf("%s: DSA (ssh-dss) keys are not supported — ssh-dss is disabled by default in OpenSSH; generate a new key with `ssh-keygen -t ed25519`", path)
}

func classifyOpenSSH(path string, payload []byte) (classification, error) {
	var h opensshHeader
	if !bytes.HasPrefix(payload, []byte(opensshMagic)) || ssh.Unmarshal(payload[len(opensshMagic):], &h) != nil {
		return classification{}, refuse(path, "malformed OpenSSH private key")
	}
	cls := classification{format: formatOpenSSH, encrypted: h.CipherName != "none"}
	if err := checkOpenSSHEncryption(path, h, &cls); err != nil {
		return classification{}, err
	}
	if h.NumKeys != 1 {
		return classification{}, refuse(path, fmt.Sprintf("the file holds %d keys; exactly one is supported", h.NumKeys))
	}
	var typed struct {
		Type string
		Rest []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(h.PubKey, &typed) != nil {
		return classification{}, refuse(path, "malformed embedded public key")
	}
	switch {
	case typed.Type == "ssh-dss":
		return classification{}, dsaRefusal(path)
	case strings.HasPrefix(typed.Type, "sk-"):
		return classification{}, fmt.Errorf("%s: %q is a hardware (FIDO) key — hardware keys must be used via ssh-agent", path, typed.Type)
	}
	pub, err := ssh.ParsePublicKey(h.PubKey)
	if err != nil {
		return classification{}, refuse(path, fmt.Sprintf("unsupported embedded public key %q", typed.Type))
	}
	cls.pub = pub
	return cls, nil
}

// checkOpenSSHEncryption validates the cipher/KDF pair x/crypto can
// decrypt: none/none, or aes256-ctr|aes256-cbc with bcrypt at most
// maxBcryptRounds rounds.
func checkOpenSSHEncryption(path string, h opensshHeader, cls *classification) error {
	switch h.CipherName {
	case "none", "aes256-ctr", "aes256-cbc":
	default:
		return refuse(path, fmt.Sprintf("cipher %q is not supported (supported: aes256-ctr, aes256-cbc)", h.CipherName))
	}
	switch h.KdfName {
	case "none":
		if h.CipherName != "none" {
			return refuse(path, "malformed OpenSSH private key (cipher without a KDF)")
		}
		return nil
	case "bcrypt":
	default:
		return refuse(path, fmt.Sprintf("KDF %q is not supported (supported: bcrypt)", h.KdfName))
	}
	if h.CipherName == "none" {
		return refuse(path, "malformed OpenSSH private key (KDF without a cipher)")
	}
	var opts bcryptOpts
	if ssh.Unmarshal([]byte(h.KdfOpts), &opts) != nil {
		return refuse(path, "malformed bcrypt KDF options")
	}
	if opts.Rounds > maxBcryptRounds {
		return fmt.Errorf("%s: bcrypt KDF rounds %d exceed the supported maximum of %d — re-encrypt with fewer rounds: `ssh-keygen -p -a 100 -f %s`", path, opts.Rounds, maxBcryptRounds, path)
	}
	cls.rounds = opts.Rounds
	return nil
}

// pemIVSize maps the legacy PEM ciphers x509 decrypts to their IV size.
var pemIVSize = map[string]int{
	"DES-CBC":      8,
	"DES-EDE3-CBC": 8,
	"AES-128-CBC":  16,
	"AES-192-CBC":  16,
	"AES-256-CBC":  16,
}

// classifyPEM checks a legacy PEM key; an encrypted one must name a cipher
// and IV x509 can use, so a later decryption failure can only mean a wrong
// passphrase.
func classifyPEM(path string, block *pem.Block) (classification, error) {
	cls := classification{format: formatPEM}
	if !strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return cls, nil
	}
	if block.Type == "PRIVATE KEY" {
		return classification{}, refuse(path, "encrypted PKCS#8 keys are not supported")
	}
	alg, ivHex, ok := strings.Cut(block.Headers["DEK-Info"], ",")
	size, known := pemIVSize[alg]
	if !ok || !known {
		return classification{}, refuse(path, fmt.Sprintf("PEM encryption %q is not supported", block.Headers["DEK-Info"]))
	}
	if iv, err := hex.DecodeString(ivHex); err != nil || len(iv) != size {
		return classification{}, refuse(path, "malformed PEM encryption header (bad IV)")
	}
	cls.encrypted = true
	return cls, nil
}
```

- [ ] **Step 5: Run**

```bash
go test ./internal/keyfile -run Classify -v 2>&1 | tail -3
```

Expected: PASS — `ok  github.com/javadh75/SSHepherd/internal/keyfile`.

- [ ] **Step 6: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/keyfile/classify.go internal/keyfile/keygen_test.go internal/keyfile/classify_test.go
git commit -m "$(cat <<'EOF'
feat(keyfile): classify key containers before any prompt

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task K3 (Group K · stage 1): Descriptor-checked reads, the permission rule, passphrase files

**Files:**
- Create: `internal/keyfile/read.go`
- Create: `internal/keyfile/fakefs_test.go`
- Create: `internal/keyfile/read_test.go`

Every file (key or passphrase) is opened **once**; the permission rule runs on
the `FileInfo` of that open descriptor (fstat) and the bytes are read from the same
descriptor — no stat-then-open race. OpenSSH's `sshkey_perm_ok`, regular files
only: own + `mode & 077 != 0` is refused; another uid's file is accepted; FIFOs,
sockets and char devices are exempt. Passphrase files are read once each (a pipe
can only be read once) with exactly one trailing `\n`/`\r\n` stripped; empty
is an error, never an empty passphrase.

- [ ] **Step 1: Write the in-memory FS fake (counts opens per path; `fifo` files are one-shot):** `internal/keyfile/fakefs_test.go`

```go
package keyfile

import (
	"bytes"
	"io"
	"io/fs"
)

// fakeFile is one file in fakeFS.
type fakeFile struct {
	data    []byte
	info    FileInfo
	openErr error
	pipe    bool // readable once: later opens see EOF at once, like a drained FIFO
}

// fakeFS is an in-memory FS that counts opens per path.
type fakeFS struct {
	uid   int
	files map[string]*fakeFile
	opens map[string]int
}

func newFS() *fakeFS {
	return &fakeFS{uid: 1000, files: map[string]*fakeFile{}, opens: map[string]int{}}
}

// regular adds a regular file owned by the current uid with mode perm.
func (f *fakeFS) regular(path string, data []byte, perm fs.FileMode) *fakeFS {
	f.files[path] = &fakeFile{data: data, info: FileInfo{Mode: perm, UID: f.uid}}
	return f
}

// key adds a 0600 key file owned by the current uid.
func (f *fakeFS) key(path string, data []byte) *fakeFS { return f.regular(path, data, 0o600) }

// fifo adds a one-shot named pipe (mode 0440, owned by the caller — what
// macOS reports for <(...)).
func (f *fakeFS) fifo(path string, data []byte) *fakeFS {
	f.files[path] = &fakeFile{data: data, info: FileInfo{Mode: fs.ModeNamedPipe | 0o440, UID: f.uid}, pipe: true}
	return f
}

func (f *fakeFS) Open(path string) (io.ReadCloser, FileInfo, error) {
	ff, ok := f.files[path]
	if !ok {
		return nil, FileInfo{}, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	if ff.openErr != nil {
		return nil, FileInfo{}, &fs.PathError{Op: "open", Path: path, Err: ff.openErr}
	}
	f.opens[path]++
	if ff.pipe && f.opens[path] > 1 {
		return io.NopCloser(bytes.NewReader(nil)), ff.info, nil
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(ff.data))), ff.info, nil
}

func (f *fakeFS) Stat(path string) (FileInfo, error) {
	ff, ok := f.files[path]
	if !ok {
		return FileInfo{}, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	return ff.info, nil
}

func (f *fakeFS) UID() int { return f.uid }
```

- [ ] **Step 2: Write the failing tests:** `internal/keyfile/read_test.go`

```go
package keyfile

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestPermissionRule(t *testing.T) {
	tests := []struct {
		name    string
		info    FileInfo
		wantErr string
	}{
		{"own regular 0644 refused", FileInfo{Mode: 0o644, UID: 1000}, "permissions 0644 for /k are too open (chmod 600 /k)"},
		{"own regular 0640 refused", FileInfo{Mode: 0o640, UID: 1000}, "permissions 0640 for /k are too open"},
		{"own regular 0600 ok", FileInfo{Mode: 0o600, UID: 1000}, ""},
		{"own regular 0400 ok", FileInfo{Mode: 0o400, UID: 1000}, ""},
		{"other-uid regular 0644 ok (root-owned secret mount)", FileInfo{Mode: 0o644, UID: 0}, ""},
		{"own FIFO 0440 ok (macOS <(...))", FileInfo{Mode: fs.ModeNamedPipe | 0o440, UID: 1000}, ""},
		{"own char device 0620 ok (/dev/stdin on a tty)", FileInfo{Mode: fs.ModeDevice | fs.ModeCharDevice | 0o620, UID: 1000}, ""},
		{"own socket 0777 ok", FileInfo{Mode: fs.ModeSocket | 0o777, UID: 1000}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := permOK("/k", tt.info, 1000)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("permOK = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("permOK = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestReadCheckedErrors(t *testing.T) {
	t.Run("EACCES names uid, owner and mode", func(t *testing.T) {
		f := newFS()
		f.files["/k"] = &fakeFile{openErr: fs.ErrPermission, info: FileInfo{Mode: 0o600, UID: 0}}
		_, err := readChecked(f, "/k", maxKeyFile, "key file")
		want := "cannot read key file /k as uid 1000 (owner 0, mode 0600) — see README 'Container usage'"
		if err == nil || !strings.Contains(err.Error(), want) || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("err = %v, want %q wrapping fs.ErrPermission", err, want)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		_, err := readChecked(newFS(), "/nope", maxKeyFile, "key file")
		if err == nil || err.Error() != "key file /nope: file does not exist" {
			t.Fatalf("err = %v, want the bare not-exist message", err)
		}
	})
	t.Run("key file over 64 KiB", func(t *testing.T) {
		f := newFS().key("/big", bytes.Repeat([]byte("a"), maxKeyFile+1))
		_, err := readChecked(f, "/big", maxKeyFile, "key file")
		if err == nil || !strings.Contains(err.Error(), "larger than 65536 bytes") {
			t.Fatalf("err = %v, want the size cap", err)
		}
	})
	t.Run("exactly 64 KiB is fine", func(t *testing.T) {
		f := newFS().key("/edge", bytes.Repeat([]byte("a"), maxKeyFile))
		if b, err := readChecked(f, "/edge", maxKeyFile, "key file"); err != nil || len(b) != maxKeyFile {
			t.Fatalf("readChecked = (%d bytes, %v), want the whole file", len(b), err)
		}
	})
	t.Run("passphrase file over 4 KiB", func(t *testing.T) {
		f := newFS().key("/pw", bytes.Repeat([]byte("p"), maxPassphraseFile+1))
		_, err := readChecked(f, "/pw", maxPassphraseFile, "passphrase file")
		if err == nil || !strings.Contains(err.Error(), "passphrase file /pw is larger than 4096 bytes") {
			t.Fatalf("err = %v, want the passphrase size cap", err)
		}
	})
}

func TestReadPassphrases(t *testing.T) {
	t.Run("strips exactly one trailing newline", func(t *testing.T) {
		f := newFS().key("/a", []byte("pa\n\n")).key("/b", []byte("pb\r\n")).key("/c", []byte("pc"))
		cache, err := readPassphrases(f, Passphrases{Default: "/a", PerKey: map[string]string{"/k1": "/b", "/k2": "/c"}})
		if err != nil {
			t.Fatalf("readPassphrases: %v", err)
		}
		for path, want := range map[string]string{"/a": "pa\n", "/b": "pb", "/c": "pc"} {
			if got := string(cache[path]); got != want {
				t.Errorf("%s = %q, want %q", path, got, want)
			}
		}
	})
	t.Run("one FILE in two mappings and as the default is read once", func(t *testing.T) {
		f := newFS().fifo("/dev/fd/63", []byte("shared\n"))
		cache, err := readPassphrases(f, Passphrases{Default: "/dev/fd/63", PerKey: map[string]string{"/k1": "/dev/fd/63", "/k2": "/dev/fd/63"}})
		if err != nil || string(cache["/dev/fd/63"]) != "shared" {
			t.Fatalf("readPassphrases = (%q, %v), want the pipe's content", cache["/dev/fd/63"], err)
		}
		if n := f.opens["/dev/fd/63"]; n != 1 {
			t.Errorf("opens = %d, want exactly 1 (a pipe can be read once)", n)
		}
	})
	t.Run("empty after stripping is refused, naming the file", func(t *testing.T) {
		f := newFS().key("/empty", []byte("\n"))
		_, err := readPassphrases(f, Passphrases{Default: "/empty"})
		if err == nil || err.Error() != "passphrase file /empty is empty" {
			t.Fatalf("err = %v, want the empty-file refusal", err)
		}
	})
	t.Run("errors for every file are joined", func(t *testing.T) {
		f := newFS().regular("/open", []byte("x"), 0o644)
		_, err := readPassphrases(f, Passphrases{Default: "/missing", PerKey: map[string]string{"/k": "/open"}})
		if err == nil || !strings.Contains(err.Error(), "/missing") || !strings.Contains(err.Error(), "permissions 0644 for /open") {
			t.Fatalf("err = %v, want both failures", err)
		}
	})
}

func TestReadPublicAndExists(t *testing.T) {
	line := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDuMHZjvr0ZLvHjYpgGLg6Pz6LKS3Y8VTVFJ81a3aG3F label\n")
	f := newFS().key("/ok.pub", line).key("/junk.pub", []byte("not a key"))
	if readPublic(f, "/ok.pub") == nil {
		t.Error("readPublic(valid) = nil")
	}
	if readPublic(f, "/junk.pub") != nil || readPublic(f, "/absent.pub") != nil {
		t.Error("an unparseable or absent .pub must be ignored (nil)")
	}
	if !exists(f, "/ok.pub") || exists(f, "/absent.pub") {
		t.Error("exists disagrees with the FS")
	}
}
```

- [ ] **Step 3: Run**

```bash
go test ./internal/keyfile -run "Permission|ReadChecked|ReadPassphrases|ReadPublic"
```

Expected: FAIL — build failure: `undefined: FileInfo`, `undefined: permOK`, `undefined: readChecked`.

- [ ] **Step 4: Implement:** `internal/keyfile/read.go`

```go
package keyfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"

	"golang.org/x/crypto/ssh"
)

const (
	// maxKeyFile caps a key file read (64 KiB): an RSA-16384 key is ~12 KiB,
	// so anything larger is a mistake (or /dev/zero).
	maxKeyFile = 64 << 10
	// maxPassphraseFile caps a passphrase file read (4 KiB).
	maxPassphraseFile = 4 << 10
)

// FileInfo is what the permission rule needs from fstat of an open
// descriptor: the full mode (type bits included) and the owner's uid.
type FileInfo struct {
	Mode fs.FileMode
	UID  int
}

// FS is the file access Load needs. Open returns a reader over one opened
// descriptor plus the FileInfo of THAT descriptor (fstat), so a file is
// opened once, checked on the descriptor and read from the same one (no
// stat-then-open race). Stat is used only to explain an unreadable file.
// UID is the current process's uid. OSFS is the real implementation.
type FS interface {
	Open(path string) (io.ReadCloser, FileInfo, error)
	Stat(path string) (FileInfo, error)
	UID() int
}

// readChecked opens path once, applies the permission rule to that
// descriptor, and reads at most limit bytes from it.
func readChecked(fsys FS, path string, limit int, what string) ([]byte, error) {
	r, info, err := fsys.Open(path)
	if err != nil {
		return nil, openError(fsys, path, what, err)
	}
	defer func() { _ = r.Close() }() // errcheck: read-only file, close error uninteresting
	if err := permOK(path, info, fsys.UID()); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil {
		return nil, fmt.Errorf("read %s %s: %w", what, path, err)
	}
	if len(b) > limit {
		clear(b)
		return nil, fmt.Errorf("%s %s is larger than %d bytes — refusing to read it", what, path, limit)
	}
	return b, nil
}

// openError explains a failed open; EACCES names the uid we run as and the
// file's owner and mode, the usual container mismatch.
func openError(fsys FS, path, what string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		msg := fmt.Sprintf("cannot read %s %s as uid %d", what, path, fsys.UID())
		if info, serr := fsys.Stat(path); serr == nil {
			msg += fmt.Sprintf(" (owner %d, mode %04o)", info.UID, info.Mode.Perm())
		}
		return fmt.Errorf("%s — see README 'Container usage': %w", msg, fs.ErrPermission)
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err // the path is already in the message
	}
	return fmt.Errorf("%s %s: %w", what, path, err)
}

// permOK is OpenSSH's sshkey_perm_ok, for regular files only: a regular
// file the current uid owns must not be group/other accessible. A regular
// file owned by another uid (a root-owned secret mount) is accepted, as ssh
// accepts it. FIFOs, sockets and character devices (/dev/fd/N, <(...),
// /dev/stdin) are exempt: their mode bits do not describe a file at rest.
func permOK(path string, info FileInfo, uid int) error {
	if !info.Mode.IsRegular() || info.UID != uid {
		return nil
	}
	if perm := info.Mode.Perm(); perm&0o077 != 0 {
		return fmt.Errorf("permissions %04o for %s are too open (chmod 600 %s)", perm, path, path)
	}
	return nil
}

// readPassphrases reads every distinct passphrase file exactly once (a
// pipe can only be read once), strips exactly one trailing \n or \r\n, and
// refuses a file that is then empty. Read errors are joined; the files
// that did read are cached anyway, so the caller can wipe them.
func readPassphrases(fsys FS, pp Passphrases) (map[string][]byte, error) {
	var paths []string
	if pp.Default != "" {
		paths = append(paths, pp.Default)
	}
	perKey := make([]string, 0, len(pp.PerKey))
	for _, f := range pp.PerKey {
		perKey = append(perKey, f)
	}
	sort.Strings(perKey) // deterministic error order
	paths = append(paths, perKey...)

	cache := make(map[string][]byte, len(paths))
	seen := make(map[string]bool, len(paths))
	var errs []error
	for _, p := range paths {
		if seen[p] {
			continue // one FILE in two mappings (or also the default): read once
		}
		seen[p] = true
		b, err := readChecked(fsys, p, maxPassphraseFile, "passphrase file")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		b = stripNewline(b)
		if len(b) == 0 {
			errs = append(errs, fmt.Errorf("passphrase file %s is empty", p))
			continue
		}
		cache[p] = b
	}
	return cache, errors.Join(errs...)
}

// stripNewline removes exactly one trailing "\n" or "\r\n".
func stripNewline(b []byte) []byte {
	if bytes.HasSuffix(b, []byte("\r\n")) {
		return b[:len(b)-2]
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// readPublic parses a sibling public key file; nil when it is absent or
// unparseable (it is only a label, never the fingerprint).
func readPublic(fsys FS, path string) ssh.PublicKey {
	r, _, err := fsys.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(io.LimitReader(r, maxKeyFile))
	if err != nil {
		return nil
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil
	}
	return pub
}

// exists reports whether path can be stat'ed.
func exists(fsys FS, path string) bool {
	_, err := fsys.Stat(path)
	return err == nil
}
```

- [ ] **Step 5: Run**

```bash
go test ./internal/keyfile
```

Expected: PASS.

- [ ] **Step 6: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/keyfile/read.go internal/keyfile/fakefs_test.go internal/keyfile/read_test.go
git commit -m "$(cat <<'EOF'
feat(keyfile): descriptor-checked reads, OpenSSH permission rule, read-once passphrase files

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task K4 (Group K · stage 1): `OSFS` — the real filesystem

**Files:**
- Create: `internal/keyfile/osfs_unix.go`
- Create: `internal/keyfile/osfs_other.go`
- Create: `internal/keyfile/osfs_test.go`

`os.Open` + `f.Stat()` (fstat of that descriptor) + the owner uid from
`syscall.Stat_t`. Off unix the type exists but refuses (`--identity` is unix-only:
ownership and modes cannot be checked there), so the module still cross-compiles.

- [ ] **Step 1: Write the failing test (real temp files, a real FIFO, a real EACCES):** `internal/keyfile/osfs_test.go`

```go
//go:build unix

package keyfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestOSFS exercises the real FS against real files: fstat of the open
// descriptor, ownership, the FIFO exemption and EACCES.
func TestOSFS(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, info, err := OSFS{}.Open(key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = r.Close()
	if !info.Mode.IsRegular() || info.Mode.Perm() != 0o600 || info.UID != os.Getuid() {
		t.Errorf("info = %+v, want a regular 0600 file owned by uid %d", info, os.Getuid())
	}
	if (OSFS{}).UID() != os.Getuid() {
		t.Errorf("UID = %d, want %d", (OSFS{}).UID(), os.Getuid())
	}
	if _, err := (OSFS{}).Stat(filepath.Join(dir, "nope")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(missing) = %v, want ErrNotExist", err)
	}
	if _, _, err := (OSFS{}).Open(filepath.Join(dir, "nope")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open(missing) = %v, want ErrNotExist", err)
	}

	t.Run("loose own file refused through the real FS", func(t *testing.T) {
		loose := filepath.Join(dir, "loose")
		if err := os.WriteFile(loose, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(loose, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readChecked(OSFS{}, loose, maxKeyFile, "key file"); err == nil || !strings.Contains(err.Error(), "are too open") {
			t.Fatalf("err = %v, want the permission refusal", err)
		}
	})
	t.Run("FIFO is exempt", func(t *testing.T) {
		fifo := filepath.Join(dir, "fifo")
		if err := syscall.Mkfifo(fifo, 0o644); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
			if err != nil {
				done <- err
				return
			}
			_, err = w.WriteString("secret\n")
			_ = w.Close()
			done <- err
		}()
		b, err := readChecked(OSFS{}, fifo, maxPassphraseFile, "passphrase file")
		if werr := <-done; werr != nil {
			t.Fatalf("writer: %v", werr)
		}
		if err != nil || string(b) != "secret\n" {
			t.Fatalf("readChecked(fifo) = (%q, %v), want the pipe content", b, err)
		}
	})
	t.Run("EACCES through the real FS", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root reads everything")
		}
		locked := filepath.Join(dir, "locked")
		if err := os.WriteFile(locked, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		_, err := readChecked(OSFS{}, locked, maxKeyFile, "key file")
		if err == nil || !strings.Contains(err.Error(), "mode 0000") || !strings.Contains(err.Error(), "Container usage") {
			t.Fatalf("err = %v, want the targeted EACCES message", err)
		}
	})
}
```

- [ ] **Step 2: Run**

```bash
go test ./internal/keyfile -run TestOSFS
```

Expected: FAIL — build failure: `undefined: OSFS`.

- [ ] **Step 3: Implement (unix):** `internal/keyfile/osfs_unix.go`

```go
//go:build unix

package keyfile

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// OSFS is the real FS: os.Open plus fstat of the opened descriptor.
type OSFS struct{}

var _ FS = OSFS{}

// Open opens path once and returns it with the fstat of that descriptor.
func (OSFS) Open(path string) (io.ReadCloser, FileInfo, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own --identity / passphrase-file path
	if err != nil {
		return nil, FileInfo{}, fmt.Errorf("open: %w", err)
	}
	fi, err := f.Stat() // fstat: the descriptor we will read, not the path
	if err != nil {
		_ = f.Close()
		return nil, FileInfo{}, fmt.Errorf("fstat %s: %w", path, err)
	}
	return f, infoOf(fi), nil
}

// Stat stats path (diagnostics only — never used to decide what to read).
func (OSFS) Stat(path string) (FileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, fmt.Errorf("stat: %w", err)
	}
	return infoOf(fi), nil
}

// UID is the process's real uid.
func (OSFS) UID() int { return os.Getuid() }

func infoOf(fi fs.FileInfo) FileInfo {
	info := FileInfo{Mode: fi.Mode(), UID: -1}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		info.UID = int(st.Uid)
	}
	return info
}
```

- [ ] **Step 4: And the non-unix stub:** `internal/keyfile/osfs_other.go`

```go
//go:build !unix

package keyfile

import (
	"errors"
	"io"
)

// OSFS is unavailable off unix: key-file ownership and modes cannot be
// checked there, so --identity is refused rather than read unchecked.
type OSFS struct{}

var _ FS = OSFS{}

var errUnsupportedOS = errors.New("--identity key files are supported on unix only")

// Open always fails off unix.
func (OSFS) Open(string) (io.ReadCloser, FileInfo, error) { return nil, FileInfo{}, errUnsupportedOS }

// Stat always fails off unix.
func (OSFS) Stat(string) (FileInfo, error) { return FileInfo{}, errUnsupportedOS }

// UID is unknown off unix.
func (OSFS) UID() int { return -1 }
```

- [ ] **Step 5: Run**

```bash
go test ./internal/keyfile && GOOS=windows go vet ./internal/keyfile
```

Expected: PASS, and the windows vet prints nothing.

- [ ] **Step 6: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/keyfile/osfs_unix.go internal/keyfile/osfs_other.go internal/keyfile/osfs_test.go
git commit -m "$(cat <<'EOF'
feat(keyfile): OSFS — fstat of the opened descriptor, unix ownership

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task K5 (Group K · stage 1): `Resolve` — lexical flag validation

**Files:**
- Create: `internal/keyfile/resolve.go`
- Create: `internal/keyfile/resolve_test.go`

Pure: `~/` from `home`, relative against `cwd`, `filepath.Clean`; no symlink
resolution, case sensitive. `KEY=FILE` splits at the **first** `=`. Duplicate
`--identity` paths are dropped silently; an unmatched `KEY` lists the cleaned
`--identity` paths; a duplicate `KEY` and passphrase flags without `--identity`
are errors. The command layer (C1) maps every error to exit 3 before the
manifest loads.

- [ ] **Step 1: Write the failing tests:** `internal/keyfile/resolve_test.go`

```go
package keyfile

import (
	"reflect"
	"strings"
	"testing"
)

func TestResolve(t *testing.T) {
	const home, cwd = "/home/op", "/work"
	tests := []struct {
		name       string
		ids        []string
		def        string
		perKey     []string
		wantSpecs  []Spec
		wantPP     Passphrases
		wantErrSub string
	}{
		{name: "no flags", wantSpecs: nil},
		{name: "lexical: ~/ expands, relative joins cwd, Clean", ids: []string{"~/.ssh/ci", "keys/../keys/ci_new", "/abs/./k"},
			wantSpecs: []Spec{{"/home/op/.ssh/ci"}, {"/work/keys/ci_new"}, {"/abs/k"}}},
		{name: "duplicate cleaned path de-duplicated silently, first order kept", ids: []string{"/k", "/x/../k", "/j"},
			wantSpecs: []Spec{{"/k"}, {"/j"}}},
		{name: "default file is cleaned", ids: []string{"/k"}, def: "~/pw",
			wantSpecs: []Spec{{"/k"}}, wantPP: Passphrases{Default: "/home/op/pw"}},
		{name: "mapping split at the FIRST =", ids: []string{"/k"}, perKey: []string{"/k=/dev/fd/63=x"},
			wantSpecs: []Spec{{"/k"}}, wantPP: Passphrases{PerKey: map[string]string{"/k": "/dev/fd/63=x"}}},
		{name: "mapping matches lexically before de-dup", ids: []string{"~/.ssh/ci", "/home/op/.ssh/ci"}, perKey: []string{"/home/op/.ssh/./ci=pw"},
			wantSpecs: []Spec{{"/home/op/.ssh/ci"}}, wantPP: Passphrases{PerKey: map[string]string{"/home/op/.ssh/ci": "/work/pw"}}},
		{name: "passphrase flags need --identity (default)", def: "/pw", wantErrSub: "passphrase flags need --identity"},
		{name: "passphrase flags need --identity (per key)", perKey: []string{"/k=/pw"}, wantErrSub: "passphrase flags need --identity"},
		{name: "unmatched KEY lists the cleaned paths", ids: []string{"~/.ssh/a", "b"}, perKey: []string{"/c=/pw"},
			wantErrSub: "--identity-passphrase: /c matches no --identity (--identity paths: /home/op/.ssh/a, /work/b)"},
		{name: "symlinks are not resolved: a different spelling does not match", ids: []string{"/link/k"}, perKey: []string{"/real/k=/pw"},
			wantErrSub: "matches no --identity"},
		{name: "matching is case sensitive", ids: []string{"/K"}, perKey: []string{"/k=/pw"}, wantErrSub: "matches no --identity"},
		{name: "same KEY twice", ids: []string{"/k"}, perKey: []string{"/k=/a", "/k=/b"}, wantErrSub: "--identity-passphrase: /k is given twice"},
		{name: "missing =", ids: []string{"/k"}, perKey: []string{"/k"}, wantErrSub: `--identity-passphrase "/k": want KEY=FILE`},
		{name: "empty FILE", ids: []string{"/k"}, perKey: []string{"/k="}, wantErrSub: "want KEY=FILE"},
		{name: "empty KEY", ids: []string{"/k"}, perKey: []string{"=/pw"}, wantErrSub: "want KEY=FILE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			specs, pp, err := Resolve(tt.ids, tt.def, tt.perKey, home, cwd)
			if tt.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrSub) {
					t.Fatalf("err = %v, want %q", err, tt.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if !reflect.DeepEqual(specs, tt.wantSpecs) {
				t.Errorf("specs = %v, want %v", specs, tt.wantSpecs)
			}
			if !reflect.DeepEqual(pp, tt.wantPP) {
				t.Errorf("passphrases = %+v, want %+v", pp, tt.wantPP)
			}
		})
	}
}

func TestResolveUnknownHome(t *testing.T) {
	if _, _, err := Resolve([]string{"~/k"}, "", nil, "", "/work"); err == nil || !strings.Contains(err.Error(), "home directory unknown") {
		t.Fatalf("err = %v, want the unknown-home error", err)
	}
	if _, _, err := Resolve([]string{"/k"}, "~/pw", nil, "", "/work"); err == nil {
		t.Fatal("unexpandable default file accepted")
	}
	if _, _, err := Resolve([]string{"/k"}, "", []string{"~/k=/pw"}, "", "/work"); err == nil {
		t.Fatal("unexpandable mapping key accepted")
	}
	if _, _, err := Resolve([]string{"/k"}, "", []string{"/k=~/pw"}, "", "/work"); err == nil {
		t.Fatal("unexpandable mapping file accepted")
	}
}
```

- [ ] **Step 2: Run**

```bash
go test ./internal/keyfile -run Resolve
```

Expected: FAIL — build failure: `undefined: Resolve`.

- [ ] **Step 3: Implement:** `internal/keyfile/resolve.go`

```go
package keyfile

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Resolve validates the three identity flags and builds Load's inputs.
// Path matching is lexical: "~/" expands from home, a relative path is
// joined to cwd, and the result is filepath.Clean-ed — no symlink
// resolution, case sensitive. A --identity-passphrase mapping (split at the
// FIRST "=") attaches to its exact --identity path; duplicate --identity
// paths are then dropped silently. home and cwd are injected
// (os.UserHomeDir, os.Getwd) so the rule is testable.
func Resolve(identities []string, defaultFile string, perKey []string, home, cwd string) ([]Spec, Passphrases, error) {
	var pp Passphrases
	if len(identities) == 0 {
		if defaultFile != "" || len(perKey) > 0 {
			return nil, pp, errors.New("passphrase flags need --identity")
		}
		return nil, pp, nil
	}
	var specs []Spec
	seen := make(map[string]bool, len(identities))
	for _, raw := range identities {
		p, err := cleanPath(raw, home, cwd)
		if err != nil {
			return nil, pp, fmt.Errorf("--identity: %w", err)
		}
		if !seen[p] {
			seen[p] = true
			specs = append(specs, Spec{Path: p})
		}
	}
	if defaultFile != "" {
		p, err := cleanPath(defaultFile, home, cwd)
		if err != nil {
			return nil, pp, fmt.Errorf("--identity-passphrase-file: %w", err)
		}
		pp.Default = p
	}
	for _, kv := range perKey {
		key, file, err := splitMapping(kv, home, cwd)
		if err != nil {
			return nil, pp, err
		}
		if _, dup := pp.PerKey[key]; dup {
			return nil, pp, fmt.Errorf("--identity-passphrase: %s is given twice", key)
		}
		if !seen[key] {
			return nil, pp, fmt.Errorf("--identity-passphrase: %s matches no --identity (--identity paths: %s)", key, joinPaths(specs))
		}
		if pp.PerKey == nil {
			pp.PerKey = make(map[string]string)
		}
		pp.PerKey[key] = file
	}
	return specs, pp, nil
}

// splitMapping splits KEY=FILE at the first "=" and cleans both halves.
func splitMapping(kv, home, cwd string) (key, file string, err error) {
	k, f, ok := strings.Cut(kv, "=")
	if !ok || k == "" || f == "" {
		return "", "", fmt.Errorf("--identity-passphrase %q: want KEY=FILE", kv)
	}
	if key, err = cleanPath(k, home, cwd); err != nil {
		return "", "", fmt.Errorf("--identity-passphrase: %w", err)
	}
	if file, err = cleanPath(f, home, cwd); err != nil {
		return "", "", fmt.Errorf("--identity-passphrase: %w", err)
	}
	return key, file, nil
}

// cleanPath is the lexical rule: ~/ expansion, absolute against cwd, Clean.
func cleanPath(p, home, cwd string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home == "" {
			return "", fmt.Errorf("cannot expand %s: home directory unknown", p)
		}
		p = filepath.Join(home, p[1:])
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p), nil
}

func joinPaths(specs []Spec) string {
	paths := make([]string, 0, len(specs))
	for _, s := range specs {
		paths = append(paths, s.Path)
	}
	return strings.Join(paths, ", ")
}
```

- [ ] **Step 4: Run**

```bash
go test ./internal/keyfile
```

Expected: PASS.

- [ ] **Step 5: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/keyfile/resolve.go internal/keyfile/resolve_test.go
git commit -m "$(cat <<'EOF'
feat(keyfile): Resolve — lexical --identity / passphrase flag validation

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task K6 (Group K · stage 1): The `/dev/tty` prompter

**Files:**
- Create: `internal/keyfile/line.go`
- Create: `internal/keyfile/line_test.go`
- Create: `internal/keyfile/tty_unix.go`
- Create: `internal/keyfile/termios_linux.go`
- Create: `internal/keyfile/termios_darwin.go`
- Create: `internal/keyfile/tty_other.go`
- Create: `internal/keyfile/tty_test.go`
- Create: `internal/keyfile/tty_pty_test.go`
- Create: `internal/keyfile/pty_linux_test.go`
- Create: `internal/keyfile/pty_darwin_test.go`
- Modify: `go.mod`

`Available()` is true only when `/dev/tty` opens, stdin is a terminal and the
process is in the terminal's foreground process group (`TIOCGPGRP == getpgrp`).
`ReadPassphrase` clears `ECHO` (keeping `ICANON|ISIG`, so Ctrl-C still raises
SIGINT → ctx cancel), reads one line in a goroutine and, on `ctx.Done()`,
restores the termios, prints a newline, closes the tty and returns `ctx.Err()`.
The tty is driven through the `*os.File` (`SyscallConn().Control` for ioctls) —
never `Fd()`, which would switch it to blocking mode and let a closed descriptor
number be reused under a pending raw read. Real-terminal paths are kept out of the
goleak-checked tests; the headless verdicts and `readLine` are unit-tested, and
the real prompter is driven against a pseudo-terminal (`TTY.path` = the pty
slave): echo is off while it reads, the line comes back without being echoed,
echo is restored after a read **and after a ctx cancel** (the first Ctrl-C), and
a terminal that is not the process's controlling tty is never `Available`. This
makes `golang.org/x/sys` a direct dependency.

- [ ] **Step 1: Write the failing tests:** `internal/keyfile/line_test.go`

```go
package keyfile

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadLine(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"secret\n", "secret", false},
		{"secret\r\n", "secret", false},
		{"secret", "secret", false},
		{"\n", "", false},
		{"first\nsecond\n", "first", false},
		{strings.Repeat("x", 9), "", true},
	}
	for _, tt := range tests {
		got, err := readLine(strings.NewReader(tt.in), 8)
		if (err != nil) != tt.wantErr || string(got) != tt.want {
			t.Errorf("readLine(%q) = (%q, %v), want (%q, err=%v)", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadLineReadError(t *testing.T) {
	if _, err := readLine(io.MultiReader(bytes.NewReader([]byte("ab")), failingReader{}), 8); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want the read error", err)
	}
}
```

- [ ] **Step 2: Create the file:** `internal/keyfile/tty_test.go`

```go
//go:build linux || darwin

package keyfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The controlling-terminal paths cannot run under go test (no controlling
// tty); these pin the headless verdicts. tty_pty_test.go drives the real
// prompter on a pseudo-terminal.
func TestTTYHeadless(t *testing.T) {
	notTTY, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = notTTY.Close() }()
	if (&TTY{path: "/dev/tty", stdin: notTTY}).Available() {
		t.Error("Available with a non-terminal stdin, want false")
	}
	if (&TTY{path: "/dev/tty"}).Available() {
		t.Error("Available with no stdin, want false")
	}
	if NewTTY().path != "/dev/tty" {
		t.Error("NewTTY must prompt on /dev/tty")
	}
	missing := &TTY{path: filepath.Join(t.TempDir(), "no-tty"), stdin: notTTY}
	if _, err := missing.ReadPassphrase(context.Background(), "p: "); err == nil {
		t.Error("ReadPassphrase on a missing tty succeeded")
	}
	regular := &TTY{path: notTTY.Name(), stdin: notTTY}
	if _, err := regular.ReadPassphrase(context.Background(), "p: "); err == nil {
		t.Error("ReadPassphrase on a regular file succeeded, want not-a-terminal")
	}
}
```

- [ ] **Step 3: Drive the real prompter on a pseudo-terminal (echo off while reading, restored after a read and after a cancel; a non-controlling terminal is headless):** `internal/keyfile/tty_pty_test.go`

```go
//go:build linux || darwin

package keyfile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ptyRig drives the real prompter against a pseudo-terminal: the master is
// the operator's keyboard and screen, the slave stands in for /dev/tty.
type ptyRig struct {
	master *os.File
	slave  *os.File // held open by the test: termios is read through it
	tty    *TTY
	mu     sync.Mutex
	screen bytes.Buffer
	done   chan struct{}
}

func newPTYRig(t *testing.T) *ptyRig {
	t.Helper()
	master, name := openPTY(t)
	slave, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		t.Skipf("open pty slave: %v", err)
	}
	r := &ptyRig{master: master, slave: slave, tty: &TTY{path: name, stdin: slave}, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		buf := make([]byte, 256)
		for {
			n, err := master.Read(buf)
			r.mu.Lock()
			r.screen.Write(buf[:n])
			r.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
		<-r.done
	})
	return r
}

// withFD runs fn on f's descriptor through SyscallConn — never Fd(), which
// would switch f to blocking mode (and a blocked Read would then outlive
// Close, failing goleak).
func withFD(t *testing.T, f *os.File, fn func(fd int)) {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}
	if err := rc.Control(func(fd uintptr) { fn(int(fd)) }); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// echo reports whether the slave's ECHO flag is set.
func (r *ptyRig) echo(t *testing.T) bool {
	t.Helper()
	var (
		tio *unix.Termios
		err error
	)
	withFD(t, r.slave, func(fd int) { tio, err = unix.IoctlGetTermios(fd, ioctlGetTermios) })
	if err != nil {
		t.Fatalf("tcgetattr: %v", err)
	}
	return tio.Lflag&unix.ECHO != 0
}

// waitEchoOff waits until the prompter has turned echo off (its prompt is
// up and the read is about to start).
func (r *ptyRig) waitEchoOff(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.echo(t) {
		if time.Now().After(deadline) {
			t.Fatal("echo never turned off")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *ptyRig) screenText() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.screen.String()
}

type readResult struct {
	line []byte
	err  error
}

func (r *ptyRig) read(ctx context.Context) <-chan readResult {
	ch := make(chan readResult, 1)
	go func() {
		line, err := r.tty.ReadPassphrase(ctx, "Enter passphrase for /k: ")
		ch <- readResult{line, err}
	}()
	return ch
}

func TestTTYReadPassphraseOnPTY(t *testing.T) {
	r := newPTYRig(t)
	if !r.echo(t) {
		t.Fatal("a fresh pty has echo off")
	}
	if r.tty.Available() {
		t.Error("Available on a terminal that is not this process's controlling tty, want false (headless)")
	}
	ch := r.read(context.Background())
	r.waitEchoOff(t)
	if _, err := io.WriteString(r.master, "s3cret\n"); err != nil {
		t.Fatal(err)
	}
	res := <-ch
	if res.err != nil || string(res.line) != "s3cret" {
		t.Fatalf("ReadPassphrase = (%q, %v), want s3cret", res.line, res.err)
	}
	if !r.echo(t) {
		t.Error("echo not restored after the read")
	}
	if s := r.screenText(); strings.Contains(s, "s3cret") {
		t.Errorf("the passphrase was echoed: %q", s)
	}
}

func TestTTYCanceledPromptRestoresEcho(t *testing.T) {
	r := newPTYRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch := r.read(ctx)
	r.waitEchoOff(t)
	cancel() // what the first Ctrl-C does through signal.NotifyContext
	select {
	case res := <-ch:
		if !errors.Is(res.err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPassphrase did not return on cancel")
	}
	if !r.echo(t) {
		t.Error("a canceled prompt left the terminal without echo")
	}
	// Where closing the tty cannot end a blocked read, this line does, so
	// the abandoned reader exits before goleak looks.
	_, _ = io.WriteString(r.master, "\n")
}
```

- [ ] **Step 4: Open a pty on Linux (`/dev/ptmx`, unlock, `/dev/pts/N`; skipped where the container has no ptys):** `internal/keyfile/pty_linux_test.go`

```go
package keyfile

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal pair: the master (the test's keyboard
// and screen) and the slave's device path (what the prompter opens).
func openPTY(t *testing.T) (master *os.File, slave string) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	var (
		n      int
		ctlErr error
	)
	withFD(t, m, func(fd int) {
		if ctlErr = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); ctlErr != nil {
			return
		}
		n, ctlErr = unix.IoctlGetInt(fd, unix.TIOCGPTN)
	})
	if ctlErr != nil {
		_ = m.Close()
		t.Fatalf("pty setup: %v", ctlErr)
	}
	return m, fmt.Sprintf("/dev/pts/%d", n)
}
```

- [ ] **Step 5: And on macOS (grant, unlock, `TIOCPTYGNAME`):** `internal/keyfile/pty_darwin_test.go`

```go
package keyfile

import (
	"bytes"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal pair: the master (the test's keyboard
// and screen) and the slave's device path (what the prompter opens).
func openPTY(t *testing.T) (master *os.File, slave string) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	name := make([]byte, 128)
	var ctlErr error
	withFD(t, m, func(fd int) {
		if ctlErr = unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); ctlErr != nil {
			return
		}
		if ctlErr = unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); ctlErr != nil {
			return
		}
		//nolint:staticcheck // SA1019: TIOCPTYGNAME fills a 128-byte buffer and x/sys has no wrapper for it
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
			ctlErr = errno
		}
	})
	if ctlErr != nil {
		_ = m.Close()
		t.Fatalf("pty setup: %v", ctlErr)
	}
	return m, string(name[:bytes.IndexByte(name, 0)])
}
```

- [ ] **Step 6: Run**

```bash
go test ./internal/keyfile -run "ReadLine|TTY"
```

Expected: FAIL — build failure: `undefined: readLine`, `undefined: TTY`, `undefined: ioctlGetTermios`.

- [ ] **Step 7: Implement the line reader:** `internal/keyfile/line.go`

```go
package keyfile

import (
	"errors"
	"fmt"
	"io"
)

// readLine reads one line byte by byte (a terminal in canonical mode hands
// over whole lines; byte reads never consume past the newline), dropping
// the newline and one trailing \r. More than limit bytes is an error, with
// what was read wiped.
func readLine(r io.Reader, limit int) ([]byte, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			if len(line) >= limit {
				clear(line)
				return nil, fmt.Errorf("passphrase longer than %d bytes", limit)
			}
			line = append(line, b[0])
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			clear(line)
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line, nil
}
```

- [ ] **Step 8: The prompter (linux + darwin):** `internal/keyfile/tty_unix.go`

```go
//go:build linux || darwin

package keyfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// TTY prompts on the controlling terminal, never on stdout (audit --json
// stays clean) and regardless of -q. Build it with NewTTY.
type TTY struct {
	path  string   // "/dev/tty"
	stdin *os.File // must be a terminal too (apply's confirmation contract)
}

var _ Prompter = (*TTY)(nil)

// NewTTY returns the /dev/tty prompter.
func NewTTY() *TTY { return &TTY{path: "/dev/tty", stdin: os.Stdin} }

// Available is true only when /dev/tty opens, stdin is a terminal, and this
// process is in the terminal's foreground process group. Anything else is
// headless — docker run -t, a pty-allocating CI executor, or `cmd &` — and
// fails with the no-passphrase-source error instead of hanging or being
// stopped by SIGTTIN.
func (t *TTY) Available() bool {
	if t.stdin == nil || !term.IsTerminal(int(t.stdin.Fd())) {
		return false
	}
	f, err := os.OpenFile(t.path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	return foreground(f)
}

// foreground reports tcgetpgrp(tty) == getpgrp().
func foreground(f *os.File) bool {
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	fg := false
	_ = rc.Control(func(fd uintptr) {
		pgrp, err := unix.IoctlGetInt(int(fd), unix.TIOCGPGRP)
		fg = err == nil && pgrp == unix.Getpgrp()
	})
	return fg
}

// ReadPassphrase writes prompt to the terminal, turns echo off, and reads
// one line. On ctx.Done() it restores the terminal state, prints a newline,
// closes the tty and returns ctx.Err() (wrapped) at once — the first Ctrl-C
// always works and never leaves the shell without echo. The tty is driven
// through the *os.File (SyscallConn for the ioctls), never a raw fd, so
// closing it cannot race a read onto a reused descriptor.
func (t *TTY) ReadPassphrase(ctx context.Context, prompt string) ([]byte, error) {
	f, err := os.OpenFile(t.path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", t.path, err)
	}
	restore, err := echoOff(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	done := func() {
		restore()
		_, _ = f.WriteString("\n") // the user's Enter was not echoed
		_ = f.Close()
	}
	if _, err := f.WriteString(prompt); err != nil {
		done()
		return nil, fmt.Errorf("write prompt: %w", err)
	}
	type result struct {
		line []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := readLine(f, maxPassphraseFile)
		ch <- result{line, err}
	}()
	select {
	case r := <-ch:
		done()
		return r.line, r.err
	case <-ctx.Done():
		done() // closing the tty ends the read where the platform allows; the result is dropped
		return nil, fmt.Errorf("passphrase prompt: %w", ctx.Err())
	}
}

// echoOff clears ECHO (keeping canonical mode and signals, so Ctrl-C still
// interrupts) and returns the restore func.
func echoOff(f *os.File) (func(), error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("tty: %w", err)
	}
	var old *unix.Termios
	var ctlErr error
	if err := rc.Control(func(fd uintptr) {
		old, ctlErr = unix.IoctlGetTermios(int(fd), ioctlGetTermios)
		if ctlErr != nil {
			return
		}
		noEcho := *old
		noEcho.Lflag &^= unix.ECHO
		noEcho.Lflag |= unix.ICANON | unix.ISIG
		ctlErr = unix.IoctlSetTermios(int(fd), ioctlSetTermios, &noEcho)
	}); err != nil {
		return nil, fmt.Errorf("tty: %w", err)
	}
	if ctlErr != nil {
		if errors.Is(ctlErr, syscall.ENOTTY) {
			return nil, fmt.Errorf("%s is not a terminal: %w", f.Name(), ctlErr)
		}
		return nil, fmt.Errorf("tty: %w", ctlErr)
	}
	return func() {
		_ = rc.Control(func(fd uintptr) { _ = unix.IoctlSetTermios(int(fd), ioctlSetTermios, old) })
	}, nil
}
```

- [ ] **Step 9: Per-OS termios ioctl numbers:** `internal/keyfile/termios_linux.go`

```go
package keyfile

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)
```

- [ ] **Step 10: Create the file:** `internal/keyfile/termios_darwin.go`

```go
package keyfile

import "golang.org/x/sys/unix"

const (
	ioctlGetTermios = unix.TIOCGETA
	ioctlSetTermios = unix.TIOCSETA
)
```

- [ ] **Step 11: Every other platform: never available.** `internal/keyfile/tty_other.go`

```go
//go:build !(linux || darwin)

package keyfile

import (
	"context"
	"errors"
)

// TTY is never available on this platform: encrypted keys need a
// passphrase file here.
type TTY struct{}

var _ Prompter = (*TTY)(nil)

// NewTTY returns the (unavailable) terminal prompter.
func NewTTY() *TTY { return &TTY{} }

// Available is always false on this platform.
func (*TTY) Available() bool { return false }

// ReadPassphrase always fails on this platform.
func (*TTY) ReadPassphrase(context.Context, string) ([]byte, error) {
	return nil, errors.New("terminal passphrase prompts are not supported on this platform")
}
```

- [ ] **Step 12: Promote `golang.org/x/sys` to a direct dependency:**

```bash
go mod tidy && git diff go.mod
```

Expected: `golang.org/x/sys v0.47.0` moves from the indirect block into the main `require` block; `go.sum` is unchanged.

- [ ] **Step 13: Run**

```bash
go test ./internal/keyfile && GOOS=linux go vet ./internal/keyfile && GOOS=windows go vet ./internal/keyfile && GOOS=freebsd go vet ./internal/keyfile
```

Expected: PASS; the three cross-OS vets print nothing.

- [ ] **Step 14: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/keyfile/line.go internal/keyfile/line_test.go internal/keyfile/tty_unix.go internal/keyfile/termios_linux.go internal/keyfile/termios_darwin.go internal/keyfile/tty_other.go internal/keyfile/tty_test.go internal/keyfile/tty_pty_test.go internal/keyfile/pty_linux_test.go internal/keyfile/pty_darwin_test.go go.mod go.sum
git commit -m "$(cat <<'EOF'
feat(keyfile): /dev/tty prompter — foreground-only, echo off, ctx-cancellable

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task K7 (Group K · stage 1): `Load` — passphrase resolution, fingerprints, de-dup

**Files:**
- Create: `internal/keyfile/keyfile.go`
- Create: `internal/keyfile/load_test.go`

Per key, in flag order: read → classify → parse; an encrypted key tries its
`PerKey` file (wrong ⇒ error, **no fallback**), then `Default` (wrong ⇒ falls
through), then the prompter (3 attempts), else the "no passphrase source" error.
"Wrong" is `x509.IncorrectPasswordError` for OpenSSH keys and **any** decryption
failure for legacy PEM (about 1 in 256 wrong passphrases yields valid padding —
`paddingFooler` finds one at test time). All non-interactive errors for all keys
are joined and **nothing prompts while any exists**. The fingerprint is always the
decrypted key's; a disagreeing embedded/sibling public key is refused. De-dup is
by decrypted fingerprint (first path wins, info line). `KEY-cert.pub` gets an info
note. Passphrase caches are `clear()`ed on return (best effort, documented).

- [ ] **Step 1: Write the failing tests (the fake prompter, the log capture and the remaining fixture helpers live here):** `internal/keyfile/load_test.go`

```go
package keyfile

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakePrompter answers prompts from a script.
type fakePrompter struct {
	avail    bool
	answers  []string
	prompts  []string
	onPrompt func() // runs before answering (e.g. cancel the ctx)
}

func (p *fakePrompter) Available() bool { return p.avail }

func (p *fakePrompter) ReadPassphrase(ctx context.Context, prompt string) ([]byte, error) {
	p.prompts = append(p.prompts, prompt)
	if p.onPrompt != nil {
		p.onPrompt()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(p.answers) == 0 {
		return nil, errors.New("fake prompter: no answer scripted")
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return []byte(a), nil
}

// logBuffer captures log output at debug level.
func logBuffer() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// fpOf is the SHA256 fingerprint of priv's public key.
func fpOf(t testing.TB, priv any) string {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return ssh.FingerprintSHA256(s.PublicKey())
}

// pubLine is priv's authorized_keys line (a sibling .pub file's content).
func pubLine(t testing.TB, priv any) []byte {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return ssh.MarshalAuthorizedKey(s.PublicKey())
}

// paddingFooler finds a wrong passphrase under which data's legacy PEM
// still decrypts with valid padding (about 1 in 256 do), yielding garbage —
// the case x509.DecryptPEMBlock cannot detect.
func paddingFooler(t testing.TB, data []byte, right string) string {
	t.Helper()
	block, _ := pem.Decode(data)
	for i := range 100000 {
		cand := "wrong-" + big.NewInt(int64(i)).String()
		if cand == right {
			continue
		}
		//nolint:staticcheck // SA1019: probing the legacy format's undetectable wrong passwords
		if _, err := x509.DecryptPEMBlock(block, []byte(cand)); err == nil {
			return cand
		}
	}
	t.Fatal("no padding-fooling passphrase found")
	return ""
}

// pubWire is priv's public key in wire format (an OpenSSH header's PubKey).
func pubWire(t testing.TB, priv any) []byte {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s.PublicKey().Marshal()
}

// load runs Load over fsys with the given passphrases and prompter.
func load(t *testing.T, fsys *fakeFS, pp Passphrases, p Prompter, paths ...string) ([]Identity, string, error) {
	t.Helper()
	specs := make([]Spec, 0, len(paths))
	for _, p := range paths {
		specs = append(specs, Spec{Path: p})
	}
	log, buf := logBuffer()
	ids, err := Load(context.Background(), specs, pp, p, fsys, log)
	return ids, buf.String(), err
}

func TestLoadUnencrypted(t *testing.T) {
	ed := edKey(1)
	f := newFS().key("/k", opensshPEM(t, ed, nil))
	p := &fakePrompter{avail: true}
	ids, logs, err := load(t, f, Passphrases{}, p, "/k")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(ids) != 1 || ids[0].Path != "/k" || ids[0].Fingerprint != fpOf(t, ed) {
		t.Fatalf("ids = %+v, want /k with the decrypted fingerprint", ids)
	}
	if len(p.prompts) != 0 {
		t.Errorf("prompted %d times for an unencrypted key", len(p.prompts))
	}
	if !strings.Contains(logs, "identity loaded") || !strings.Contains(logs, fpOf(t, ed)) {
		t.Errorf("logs = %q, want the identity-loaded line with its fingerprint", logs)
	}
}

func TestLoadNoSpecs(t *testing.T) {
	ids, err := Load(context.Background(), nil, Passphrases{}, nil, newFS(), nil)
	if ids != nil || err != nil {
		t.Fatalf("Load(nil) = (%v, %v), want (nil, nil)", ids, err)
	}
}

func TestLoadPassphraseResolution(t *testing.T) {
	// The resolution order is container-independent, so the table runs on
	// legacy PEM (cheap KDF); the OpenSSH-specific wrong-passphrase signal
	// is pinned by TestLoadOpenSSHPassphrase.
	k := ecKey(t)
	enc := legacyPEM(t, k, []byte("right"))
	tests := []struct {
		name        string
		files       map[string]string // passphrase files
		pp          Passphrases
		prompter    *fakePrompter
		wantErr     []string
		wantPrompts int
	}{
		{name: "per-key ok", files: map[string]string{"/pk": "right\n"}, pp: Passphrases{PerKey: map[string]string{"/k": "/pk"}}, prompter: &fakePrompter{avail: true}},
		{name: "per-key wrong is exit 3 with no fallback", files: map[string]string{"/pk": "wrong\n", "/def": "right\n"},
			pp: Passphrases{Default: "/def", PerKey: map[string]string{"/k": "/pk"}}, prompter: &fakePrompter{avail: true, answers: []string{"right"}},
			wantErr: []string{"/k: the passphrase in /pk (--identity-passphrase) does not unlock it"}},
		{name: "default ok", files: map[string]string{"/def": "right"}, pp: Passphrases{Default: "/def"}, prompter: &fakePrompter{}},
		{name: "default wrong falls through to the prompt", files: map[string]string{"/def": "wrong"}, pp: Passphrases{Default: "/def"},
			prompter: &fakePrompter{avail: true, answers: []string{"right"}}, wantPrompts: 1},
		{name: "default wrong and headless names the default", files: map[string]string{"/def": "wrong"}, pp: Passphrases{Default: "/def"},
			prompter: &fakePrompter{}, wantErr: []string{"/k is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase KEY=FILE)", "the default passphrase file /def did not unlock it"}},
		{name: "prompt ok", prompter: &fakePrompter{avail: true, answers: []string{"right"}}, wantPrompts: 1},
		{name: "prompt wrong then right", prompter: &fakePrompter{avail: true, answers: []string{"no", "right"}}, wantPrompts: 2},
		{name: "prompt wrong three times", prompter: &fakePrompter{avail: true, answers: []string{"a", "b", "c", "right"}}, wantPrompts: 3,
			wantErr: []string{"/k: 3 incorrect passphrase attempts"}},
		{name: "headless, no source", prompter: &fakePrompter{}, wantErr: []string{"/k is encrypted and no passphrase source is available"}},
		{name: "nil prompter is headless", prompter: nil, wantErr: []string{"no passphrase source is available"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFS().key("/k", enc)
			for path, content := range tt.files {
				f.key(path, []byte(content))
			}
			var p Prompter
			if tt.prompter != nil {
				p = tt.prompter
			}
			ids, _, err := load(t, f, tt.pp, p, "/k")
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("Load succeeded, want %q", tt.wantErr)
				}
				for _, w := range tt.wantErr {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("err = %q, want it to contain %q", err, w)
					}
				}
			} else if err != nil || len(ids) != 1 || ids[0].Fingerprint != fpOf(t, k) {
				t.Fatalf("Load = (%+v, %v), want the decrypted key", ids, err)
			}
			if tt.prompter != nil && len(tt.prompter.prompts) != tt.wantPrompts {
				t.Errorf("prompts = %d, want %d", len(tt.prompter.prompts), tt.wantPrompts)
			}
		})
	}
}

func TestLoadOpenSSHPassphrase(t *testing.T) {
	enc := sharedEncrypted(t)
	t.Run("x509.IncorrectPasswordError is a wrong passphrase", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/pk", []byte("wrong"))
		_, _, err := load(t, f, Passphrases{PerKey: map[string]string{"/k": "/pk"}}, nil, "/k")
		if err == nil || !strings.Contains(err.Error(), "does not unlock it") {
			t.Fatalf("err = %v, want the wrong-passphrase verdict", err)
		}
	})
	t.Run("prompt unlocks, labelled with the embedded public key", func(t *testing.T) {
		p := &fakePrompter{avail: true, answers: []string{sharedPass}}
		ids, _, err := load(t, newFS().key("/k", enc), Passphrases{}, p, "/k")
		if err != nil || len(ids) != 1 || ids[0].Fingerprint != fpOf(t, edKey(2)) {
			t.Fatalf("Load = (%+v, %v)", ids, err)
		}
		want := "waiting for passphrase for /k on the terminal\nEnter passphrase for /k (" + fpOf(t, edKey(2)) + "): "
		if len(p.prompts) != 1 || p.prompts[0] != want {
			t.Errorf("prompts = %q, want [%q]", p.prompts, want)
		}
	})
	t.Run("the embedded public key is only a label: a mismatch is refused after decryption", func(t *testing.T) {
		// x/crypto never compares the header's public key with the
		// decrypted one; Load does, and the fingerprint is the decrypted
		// key's, never the label's.
		bad := editOpenSSH(t, enc, func(h *opensshHeader) { h.PubKey = pubWire(t, edKey(13)) })
		p := &fakePrompter{avail: true, answers: []string{sharedPass}}
		ids, _, err := load(t, newFS().key("/k", bad), Passphrases{}, p, "/k")
		if err == nil || ids != nil || !strings.Contains(err.Error(), "/k: embedded public key does not match the private key") {
			t.Fatalf("Load = (%+v, %v), want the mismatch refusal", ids, err)
		}
		if len(p.prompts) != 1 || !strings.Contains(p.prompts[0], "("+fpOf(t, edKey(13))+")") {
			t.Errorf("prompts = %q, want one prompt labelled with the embedded (pre-decryption) key", p.prompts)
		}
	})
}

func TestLoadPromptText(t *testing.T) {
	k := ecKey(t)
	f := newFS().key("/k", legacyPEM(t, k, []byte("right")))
	p := &fakePrompter{avail: true, answers: []string{"no", "right"}}
	if _, _, err := load(t, f, Passphrases{}, p, "/k"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// No .pub sibling: no label.
	if want := "waiting for passphrase for /k on the terminal\nEnter passphrase for /k: "; p.prompts[0] != want {
		t.Errorf("first prompt = %q, want %q", p.prompts[0], want)
	}
	if p.prompts[1] != "Bad passphrase, try again for /k: " {
		t.Errorf("retry prompt = %q", p.prompts[1])
	}
}

func TestLoadPromptCanceled(t *testing.T) {
	f := newFS().key("/k", sharedEncrypted(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &fakePrompter{avail: true, onPrompt: cancel}
	_, err := Load(ctx, []Spec{{"/k"}}, Passphrases{}, p, f, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled (the interrupted path)", err)
	}
}

func TestLoadPipeDefaultForTwoKeys(t *testing.T) {
	a, b := ecKey(t), ecKey(t)
	f := newFS().key("/a", legacyPEM(t, a, []byte("shared"))).key("/b", legacyPEM(t, b, []byte("shared"))).
		fifo("/dev/fd/63", []byte("shared\n"))
	ids, _, err := load(t, f, Passphrases{Default: "/dev/fd/63"}, &fakePrompter{}, "/a", "/b")
	if err != nil || len(ids) != 2 {
		t.Fatalf("Load = (%d ids, %v), want both keys unlocked by the one pipe", len(ids), err)
	}
	if n := f.opens["/dev/fd/63"]; n != 1 {
		t.Errorf("pipe opened %d times, want 1", n)
	}
}

func TestLoadEmptyPassphraseFileNeverTried(t *testing.T) {
	f := newFS().key("/k", sharedEncrypted(t)).key("/empty", []byte("\r\n"))
	_, _, err := load(t, f, Passphrases{Default: "/empty"}, &fakePrompter{avail: true, answers: []string{""}}, "/k")
	if err == nil || !strings.Contains(err.Error(), "passphrase file /empty is empty") {
		t.Fatalf("err = %v, want the empty-file exit (never tried as an empty passphrase)", err)
	}
}

func TestLoadJoinsEveryKeyError(t *testing.T) {
	f := newFS().
		regular("/loose", opensshPEM(t, edKey(8), nil), 0o644).
		key("/ppk", []byte("PuTTY-User-Key-File-3: ssh-ed25519\n")).
		key("/enc", sharedEncrypted(t))
	p := &fakePrompter{avail: true, answers: []string{sharedPass}}
	_, _, err := load(t, f, Passphrases{}, p, "/loose", "/missing", "/ppk", "/enc")
	if err == nil {
		t.Fatal("Load succeeded")
	}
	for _, w := range []string{"permissions 0644 for /loose", "key file /missing", "/ppk is a PuTTY key"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("err = %q, want it to contain %q", err, w)
		}
	}
	if len(p.prompts) != 0 {
		t.Errorf("prompted %d times although the run was already failing", len(p.prompts))
	}
}

func TestLoadRefusesBeforePrompt(t *testing.T) {
	// An encrypted key in a refused container: the operator is never asked.
	enc := withRounds(t, sharedEncrypted(t), 4096)
	p := &fakePrompter{avail: true, answers: []string{sharedPass}}
	_, _, err := load(t, newFS().key("/k", enc), Passphrases{}, p, "/k")
	if err == nil || !strings.Contains(err.Error(), "exceed the supported maximum") || len(p.prompts) != 0 {
		t.Fatalf("err = %v, prompts = %d; want the rounds refusal and no prompt", err, len(p.prompts))
	}
}

func TestLoadLegacyPEM(t *testing.T) {
	k := ecKey(t)
	enc := legacyPEM(t, k, []byte("right"))
	fooler := paddingFooler(t, enc, "right")
	t.Run("unencrypted", func(t *testing.T) {
		ids, _, err := load(t, newFS().key("/k", legacyPEM(t, k, nil)), Passphrases{}, nil, "/k")
		if err != nil || len(ids) != 1 || ids[0].Fingerprint != fpOf(t, k) {
			t.Fatalf("Load = (%+v, %v)", ids, err)
		}
	})
	t.Run("valid-padding wrong default falls through like any wrong passphrase", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/def", []byte(fooler))
		p := &fakePrompter{avail: true, answers: []string{"right"}}
		ids, _, err := load(t, f, Passphrases{Default: "/def"}, p, "/k")
		if err != nil || len(ids) != 1 || len(p.prompts) != 1 {
			t.Fatalf("Load = (%d ids, %v), prompts %d; want fall-through to one prompt", len(ids), err, len(p.prompts))
		}
	})
	t.Run("valid-padding wrong per-key is a wrong passphrase, not a hard error", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/pk", []byte(fooler))
		_, _, err := load(t, f, Passphrases{PerKey: map[string]string{"/k": "/pk"}}, nil, "/k")
		if err == nil || !strings.Contains(err.Error(), "does not unlock it") {
			t.Fatalf("err = %v, want the wrong-passphrase verdict", err)
		}
	})
	t.Run("stale sibling .pub refused", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/pk", []byte("right")).key("/k.pub", pubLine(t, edKey(11)))
		_, _, err := load(t, f, Passphrases{PerKey: map[string]string{"/k": "/pk"}}, nil, "/k")
		if err == nil || !strings.Contains(err.Error(), "/k: /k.pub does not match the private key") {
			t.Fatalf("err = %v, want the stale .pub refusal", err)
		}
	})
	t.Run("matching sibling .pub labels the prompt", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/k.pub", pubLine(t, k))
		p := &fakePrompter{avail: true, answers: []string{"right"}}
		if _, _, err := load(t, f, Passphrases{}, p, "/k"); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !strings.Contains(p.prompts[0], "("+fpOf(t, k)+")") {
			t.Errorf("prompt = %q, want the .pub fingerprint as a label", p.prompts[0])
		}
	})
}

func TestLoadMismatchedOpenSSHPublicSection(t *testing.T) {
	bad := editOpenSSH(t, opensshPEM(t, edKey(12), nil), func(h *opensshHeader) {
		h.PubKey = pubWire(t, edKey(13))
	})
	_, _, err := load(t, newFS().key("/k", bad), Passphrases{}, nil, "/k")
	if err == nil || !strings.Contains(err.Error(), "/k: embedded public key does not match the private key") {
		t.Fatalf("err = %v, want the mismatch refusal", err)
	}
}

func TestLoadDedupByDecryptedFingerprint(t *testing.T) {
	// One key, two containers (plain and encrypted): the second path is
	// the same key once decrypted.
	k := ecKey(t)
	f := newFS().key("/a", legacyPEM(t, k, nil)).key("/b", legacyPEM(t, k, []byte("pw"))).key("/pw", []byte("pw"))
	ids, logs, err := load(t, f, Passphrases{PerKey: map[string]string{"/b": "/pw"}}, nil, "/a", "/b")
	if err != nil || len(ids) != 1 || ids[0].Path != "/a" {
		t.Fatalf("Load = (%+v, %v), want only the first path", ids, err)
	}
	if !strings.Contains(logs, "identity /b is the same key as /a") {
		t.Errorf("logs = %q, want the dropped-path info line", logs)
	}
}

func TestLoadCertificateNote(t *testing.T) {
	f := newFS().key("/k", opensshPEM(t, edKey(15), nil)).key("/k-cert.pub", []byte("ssh-ed25519-cert-v01@openssh.com AAAA"))
	_, logs, err := load(t, f, Passphrases{}, nil, "/k")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.Contains(logs, "certificate /k-cert.pub not used; authenticating with the plain key") {
		t.Errorf("logs = %q, want the certificate note", logs)
	}
}

func TestLoadNeverLeaksPassphrases(t *testing.T) {
	const marker = "Zq8vL2pX9mR4kT7w" // 16 high-entropy bytes
	for name, data := range map[string][]byte{"openssh": sharedEncrypted(t), "legacy pem": legacyPEM(t, ecKey(t), []byte("other"))} {
		t.Run(name, func(t *testing.T) {
			f := newFS().key("/k", data).key("/pk", []byte(marker+"\n"))
			_, logs, err := load(t, f, Passphrases{PerKey: map[string]string{"/k": "/pk"}}, nil, "/k")
			if err == nil {
				t.Fatal("wrong passphrase accepted")
			}
			if strings.Contains(err.Error(), marker) || strings.Contains(logs, marker) {
				t.Fatalf("passphrase leaked: err %q, logs %q", err, logs)
			}
		})
	}
}
```

- [ ] **Step 2: Run**

```bash
go test ./internal/keyfile -run Load
```

Expected: FAIL — build failure: `undefined: Load`.

- [ ] **Step 3: Implement:** `internal/keyfile/keyfile.go`

```go
package keyfile

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"golang.org/x/crypto/ssh"
)

// promptAttempts matches ssh's NumberOfPasswordPrompts default.
const promptAttempts = 3

// candidate is one key file on its way to an Identity.
type candidate struct {
	path    string
	data    []byte
	cls     classification
	pub     ssh.PublicKey // pre-decryption public key: a label, never the fingerprint
	pubName string        // where pub came from, for the mismatch refusal
	signer  ssh.Signer
	// defaultTried records that the default passphrase file was tried and
	// did not unlock this key (the no-source message says so).
	defaultTried bool
}

// label is the pre-decryption fingerprint shown in the prompt, or "".
func (c *candidate) label() string {
	if c.pub == nil {
		return ""
	}
	return ssh.FingerprintSHA256(c.pub)
}

type loader struct {
	fsys  FS
	pp    Passphrases
	cache map[string][]byte
	p     Prompter
	log   *slog.Logger
}

// Load reads, classifies and unlocks every spec (flag order) and returns
// the identities de-duplicated by decrypted fingerprint (first path wins).
// Every passphrase file is read exactly once, before any key is tried, and
// wiped (best effort) when Load returns. Non-interactive errors for every
// key are returned together (errors.Join), and nothing prompts while any
// exists; a prompt failure (exhausted attempts, ctx canceled) returns at
// once. log receives the info lines (loaded keys, duplicates, unused
// certificates); nil discards.
func Load(ctx context.Context, specs []Spec, pp Passphrases, p Prompter, fsys FS, log *slog.Logger) ([]Identity, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	cache, err := readPassphrases(fsys, pp)
	defer wipe(cache)
	l := &loader{fsys: fsys, pp: pp, cache: cache, p: p, log: log}
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	cands, needPrompt, cerrs := l.prepareAll(specs)
	errs = append(errs, cerrs...)
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	for _, c := range needPrompt {
		if err := l.prompt(ctx, c); err != nil {
			return nil, err
		}
	}
	return l.finish(cands), nil
}

// prepareAll runs every non-interactive step for every key: read,
// classify, parse, passphrase files. It returns the candidates in flag
// order, those still needing a prompt, and every error.
func (l *loader) prepareAll(specs []Spec) (cands, needPrompt []*candidate, errs []error) {
	promptable := l.p != nil && l.p.Available()
	for _, s := range specs {
		c, err := l.prepare(s.Path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		cands = append(cands, c)
		if c.signer != nil {
			continue
		}
		err = l.unlockFromFiles(c)
		switch {
		case errors.Is(err, errUnavailable):
			// its passphrase file failed to read; that error is already reported
		case err != nil:
			errs = append(errs, err)
		case c.signer != nil:
		case promptable:
			needPrompt = append(needPrompt, c)
		default:
			errs = append(errs, noSourceError(c, l.pp.Default))
		}
	}
	return cands, needPrompt, errs
}

// prepare reads and classifies one key file and parses it when it is not
// encrypted (signer set); an encrypted key comes back without a signer.
func (l *loader) prepare(path string) (*candidate, error) {
	data, err := readChecked(l.fsys, path, maxKeyFile, "key file")
	if err != nil {
		return nil, err
	}
	cls, err := classify(path, data)
	if err != nil {
		return nil, err
	}
	c := &candidate{path: path, data: data, cls: cls}
	if cls.format == formatOpenSSH {
		c.pub, c.pubName = cls.pub, "embedded public key"
	} else if pub := readPublic(l.fsys, path+".pub"); pub != nil {
		c.pub, c.pubName = pub, path+".pub"
	}
	if cls.encrypted {
		return c, nil
	}
	raw, err := ssh.ParseRawPrivateKey(data)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		c.cls.encrypted = true
		return c, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%s: cannot parse the private key: %w — rewrite it with `ssh-keygen -p -f %s`", path, err, path)
	}
	return c, l.accept(c, raw)
}

// errUnavailable marks a passphrase attempt skipped because its file
// could not be read (readPassphrases already reported why).
var errUnavailable = errors.New("passphrase file unavailable")

// unlockFromFiles tries the passphrase files in resolution order: the
// per-key mapping (wrong is a configuration error: no fallback), then the
// default (wrong falls through to the prompt). On return without error and
// without a signer, the key still needs a prompt.
func (l *loader) unlockFromFiles(c *candidate) error {
	if file, ok := l.pp.PerKey[c.path]; ok {
		pass, ok := l.cache[file]
		if !ok {
			return errUnavailable
		}
		raw, err := ssh.ParseRawPrivateKeyWithPassphrase(c.data, pass)
		switch {
		case err == nil:
			return l.accept(c, raw)
		case wrongPassphrase(c, err):
			return fmt.Errorf("%s: the passphrase in %s (--identity-passphrase) does not unlock it", c.path, file)
		default:
			return decryptError(c, err)
		}
	}
	if l.pp.Default == "" {
		return nil
	}
	pass, ok := l.cache[l.pp.Default]
	if !ok {
		return errUnavailable
	}
	raw, err := ssh.ParseRawPrivateKeyWithPassphrase(c.data, pass)
	switch {
	case err == nil:
		return l.accept(c, raw)
	case wrongPassphrase(c, err):
		c.defaultTried = true // a shared guess, not a claim about this key
		return nil
	default:
		return decryptError(c, err)
	}
}

// prompt asks on the terminal, up to promptAttempts times.
func (l *loader) prompt(ctx context.Context, c *candidate) error {
	for attempt := range promptAttempts {
		pass, err := l.p.ReadPassphrase(ctx, promptText(c, attempt))
		if err != nil {
			return fmt.Errorf("passphrase for %s: %w", c.path, err)
		}
		raw, err := ssh.ParseRawPrivateKeyWithPassphrase(c.data, pass)
		clear(pass)
		switch {
		case err == nil:
			return l.accept(c, raw)
		case !wrongPassphrase(c, err):
			return decryptError(c, err)
		}
	}
	return fmt.Errorf("%s: %d incorrect passphrase attempts", c.path, promptAttempts)
}

// promptText is the terminal prompt: the waiting line first, then ssh's
// own wording (with the pre-decryption fingerprint as a label when known).
func promptText(c *candidate, attempt int) string {
	if attempt > 0 {
		return fmt.Sprintf("Bad passphrase, try again for %s: ", c.path)
	}
	head := fmt.Sprintf("waiting for passphrase for %s on the terminal\n", c.path)
	if fp := c.label(); fp != "" {
		return head + fmt.Sprintf("Enter passphrase for %s (%s): ", c.path, fp)
	}
	return head + fmt.Sprintf("Enter passphrase for %s: ", c.path)
}

// accept builds the signer from a parsed private key and refuses a key
// whose pre-decryption public key disagrees with it.
func (l *loader) accept(c *candidate, raw any) error {
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return fmt.Errorf("%s: unsupported private key: %w", c.path, err)
	}
	if c.pub != nil && ssh.FingerprintSHA256(c.pub) != ssh.FingerprintSHA256(signer.PublicKey()) {
		return fmt.Errorf("%s: %s does not match the private key — refusing the key (regenerate the public half with `ssh-keygen -y -f %s`)", c.path, c.pubName, c.path)
	}
	c.signer = signer
	return nil
}

// finish de-duplicates by decrypted fingerprint (first path wins) and logs
// each loaded key once.
func (l *loader) finish(cands []*candidate) []Identity {
	out := make([]Identity, 0, len(cands))
	for _, c := range cands {
		fp := ssh.FingerprintSHA256(c.signer.PublicKey())
		if i := slices.IndexFunc(out, func(id Identity) bool { return id.Fingerprint == fp }); i >= 0 {
			l.log.Info(fmt.Sprintf("identity %s is the same key as %s (%s); using %s", c.path, out[i].Path, fp, out[i].Path))
			continue
		}
		if exists(l.fsys, c.path+"-cert.pub") {
			l.log.Info(fmt.Sprintf("certificate %s-cert.pub not used; authenticating with the plain key", c.path))
		}
		l.log.Info("identity loaded", "path", c.path, "fp", fp)
		out = append(out, Identity{Path: c.path, Fingerprint: fp, Signer: c.signer})
	}
	return out
}

// wrongPassphrase reports whether a decryption failure means "wrong
// passphrase". OpenSSH keys carry a reliable check value, so only
// x509.IncorrectPasswordError counts. Legacy encrypted PEM cannot always
// detect a wrong password (about 1 in 256 yields valid padding and
// garbage), and classify already validated its headers, so any failure
// counts.
func wrongPassphrase(c *candidate, err error) bool {
	if c.cls.format == formatPEM {
		return true
	}
	return errors.Is(err, x509.IncorrectPasswordError)
}

func decryptError(c *candidate, err error) error {
	return fmt.Errorf("%s: cannot decrypt the private key: %w", c.path, err)
}

// noSourceError is the headless verdict for an encrypted key.
func noSourceError(c *candidate, defaultFile string) error {
	msg := fmt.Sprintf("%s is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase KEY=FILE)", c.path)
	if c.defaultTried {
		msg += fmt.Sprintf("; the default passphrase file %s did not unlock it", defaultFile)
	}
	return errors.New(msg)
}

// wipe clears the cached passphrases — best effort: Go cannot guarantee no
// copies, and bcrypt intermediates are not zeroed.
func wipe(cache map[string][]byte) {
	for _, b := range cache {
		clear(b)
	}
}
```

- [ ] **Step 4: Run**

```bash
go test -race -cover ./internal/keyfile
```

Expected: PASS — `ok ... coverage: 8x.x% of statements` (≈15s under `-race`: the bcrypt fixture is shared).

- [ ] **Step 5: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/keyfile/keyfile.go internal/keyfile/load_test.go
git commit -m "$(cat <<'EOF'
feat(keyfile): Load — passphrase resolution, decrypted fingerprints, de-dup, cert note

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task K8 (Group K · stage 1): ssh-keygen fixtures, fuzz targets, gitleaks allowlist

**Files:**
- Create: `internal/keyfile/testdata/README.md`
- Create: `internal/keyfile/testdata/throwaway.ppk`
- Create: `internal/keyfile/testdata/throwaway_* (generated)`
- Create: `internal/keyfile/fixtures_test.go`
- Create: `internal/keyfile/fuzz_test.go`
- Modify: `.gitleaks.toml`

Interop fixtures from the **real** `ssh-keygen` (throwaway keys, committed under
`internal/keyfile/testdata` behind a path-scoped gitleaks allowlist) and the two
fuzz targets: `FuzzClassify` (header classification only, fast) and
`FuzzDecrypt` (the whole `Load` with an injected 16-byte marker passphrase that
must never reach an error or the log; bcrypt rounds clamped to 16). The `make fuzz`
lines are added by C3.

- [ ] **Step 1: Write the failing interop test:** `internal/keyfile/fixtures_test.go`

```go
package keyfile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The committed throwaway keys under testdata/ were produced by the real
// ssh-keygen (see testdata/README): they pin interop with OpenSSH's own
// output, which x/crypto's marshalers only approximate.
const fixturePassphrase = "throwaway-fixture"

func fingerprint(pub ssh.PublicKey) string { return ssh.FingerprintSHA256(pub) }

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

func TestLoadSSHKeygenFixtures(t *testing.T) {
	tests := []struct {
		key       string
		encrypted bool
	}{
		{"throwaway_ed25519", false},
		{"throwaway_ed25519_enc", true},
		{"throwaway_rsa_pem", false},
		{"throwaway_rsa_pem_enc", true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			f := newFS().key("/k", readFixture(t, tt.key)).key("/k.pub", readFixture(t, tt.key+".pub")).
				key("/pw", []byte(fixturePassphrase+"\n"))
			pp := Passphrases{}
			if tt.encrypted {
				pp.Default = "/pw"
			}
			ids, _, err := load(t, f, pp, nil, "/k")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			pub := readPublic(f, "/k.pub")
			if pub == nil || len(ids) != 1 || ids[0].Fingerprint != fingerprint(pub) {
				t.Fatalf("ids = %+v, want the fingerprint of %s.pub", ids, tt.key)
			}
		})
	}
	t.Run("throwaway.ppk", func(t *testing.T) {
		_, _, err := load(t, newFS().key("/k", readFixture(t, "throwaway.ppk")), Passphrases{}, nil, "/k")
		if err == nil {
			t.Fatal("PuTTY key accepted")
		}
	})
}
```

- [ ] **Step 2: Write the fuzz targets (their seeds include every file under `testdata/`):** `internal/keyfile/fuzz_test.go`

```go
package keyfile

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fuzzSeeds are key files of every container the classifier knows.
func fuzzSeeds(f *testing.F) [][]byte {
	f.Helper()
	ed := edKey(1)
	seeds := [][]byte{
		opensshPEM(f, ed, nil),
		sharedEncrypted(f), // the marker is the wrong passphrase for it
		legacyPEM(f, ecKey(f), nil),
		legacyPEM(f, ecKey(f), []byte(leakMarker)),
		[]byte("PuTTY-User-Key-File-3: ssh-ed25519\n"),
		pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte{0x30, 0}}),
	}
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("testdata: %v", err)
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			b, err := os.ReadFile(filepath.Join("testdata", e.Name()))
			if err != nil {
				f.Fatal(err)
			}
			seeds = append(seeds, b)
		}
	}
	return seeds
}

// FuzzClassify: the container/header classifier (no KDF — fast) never
// panics, and an accepted OpenSSH key always carries its public key and a
// bcrypt round count within x/crypto's cap.
func FuzzClassify(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cls, err := classify("/k", data)
		if err != nil {
			if strings.ContainsRune(err.Error(), '\x1b') {
				t.Fatalf("error carries a raw escape byte: %q", err)
			}
			return
		}
		if cls.format == formatOpenSSH && cls.pub == nil {
			t.Fatal("accepted OpenSSH key without a public key")
		}
		if cls.rounds > maxBcryptRounds {
			t.Fatalf("accepted %d rounds", cls.rounds)
		}
	})
}

// leakMarker is the injected high-entropy passphrase whose bytes must never
// appear in an error or a log line.
const leakMarker = "Zq8vL2pX9mR4kT7w"

// fuzzMaxRounds clamps the KDF work per input: x/crypto's own marshaler
// uses 16, and more only slows the fuzzer down.
const fuzzMaxRounds = 16

// FuzzDecrypt runs the whole Load over arbitrary key bytes with the marker
// as both the per-key and the default passphrase: whatever the bytes, the
// marker never reaches an error or the log.
func FuzzDecrypt(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if bytes.Contains(data, []byte(leakMarker)) {
			t.Skip("the input itself carries the marker")
		}
		if cls, err := classify("/k", data); err == nil && cls.rounds > fuzzMaxRounds {
			t.Skip("bcrypt rounds clamped")
		}
		fsys := newFS().key("/k", data).key("/pw", []byte(leakMarker+"\n"))
		log, buf := logBuffer()
		for _, pp := range []Passphrases{{PerKey: map[string]string{"/k": "/pw"}}, {Default: "/pw"}} {
			_, err := Load(context.Background(), []Spec{{"/k"}}, pp, nil, fsys, log)
			if err != nil && strings.Contains(err.Error(), leakMarker) {
				t.Fatalf("passphrase leaked into the error: %q", err)
			}
		}
		if strings.Contains(buf.String(), leakMarker) {
			t.Fatalf("passphrase leaked into the log: %q", buf.String())
		}
	})
}
```

- [ ] **Step 3: Run**

```bash
go test ./internal/keyfile -run TestLoadSSHKeygenFixtures
```

Expected: FAIL — `fixture throwaway_ed25519: open testdata/throwaway_ed25519: no such file or directory`.

- [ ] **Step 4: Document the fixtures:** `internal/keyfile/testdata/README.md`

````markdown
# keyfile test fixtures

Throwaway keys produced by the real `ssh-keygen`, used only as parser and
interop fixtures and as fuzz seeds. They authorize nothing anywhere;
`.gitleaks.toml` allowlists this directory (and only it). Regenerate with:

```sh
cd internal/keyfile/testdata
rm -f throwaway_*
ssh-keygen -q -t ed25519 -N '' -C throwaway -f throwaway_ed25519
ssh-keygen -q -t ed25519 -N 'throwaway-fixture' -a 16 -C throwaway -f throwaway_ed25519_enc
ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -C throwaway -f throwaway_rsa_pem
ssh-keygen -q -t rsa -b 2048 -m PEM -N 'throwaway-fixture' -C throwaway -f throwaway_rsa_pem_enc
```

`throwaway.ppk` is a hand-written PuTTY header (not a usable key): only its
`PuTTY-User-Key-File-` prefix matters to the classifier.
````

- [ ] **Step 5: Create the PuTTY header fixture (hand-written, not a usable key):** `internal/keyfile/testdata/throwaway.ppk`

```text
PuTTY-User-Key-File-3: ssh-ed25519
Encryption: none
Comment: throwaway
Public-Lines: 2
AAAAC3NzaC1lZDI1NTE5AAAAIN1ZsrE7MKi8
B3t0dGhyb3dhd2F5
Private-Lines: 1
AAAAIHRocm93YXdheS1ub3QtYS1yZWFsLWtleQ==
Private-MAC: 00
```

- [ ] **Step 6: Generate the throwaway keys with the real `ssh-keygen` (the exact commands the testdata README records):**

```bash
cd internal/keyfile/testdata && \
ssh-keygen -q -t ed25519 -N '' -C throwaway -f throwaway_ed25519 && \
ssh-keygen -q -t ed25519 -N 'throwaway-fixture' -a 16 -C throwaway -f throwaway_ed25519_enc && \
ssh-keygen -q -t rsa -b 2048 -m PEM -N '' -C throwaway -f throwaway_rsa_pem && \
ssh-keygen -q -t rsa -b 2048 -m PEM -N 'throwaway-fixture' -C throwaway -f throwaway_rsa_pem_enc && \
ls
```

Expected: `README.md throwaway.ppk throwaway_ed25519 throwaway_ed25519.pub throwaway_ed25519_enc throwaway_ed25519_enc.pub throwaway_rsa_pem throwaway_rsa_pem.pub throwaway_rsa_pem_enc throwaway_rsa_pem_enc.pub`

- [ ] **Step 7: Run**

```bash
go test ./internal/keyfile
```

Expected: PASS.

- [ ] **Step 8: Run**

```bash
gitleaks dir --redact . 2>&1 | tail -1
```

Expected: Before the allowlist: `WRN leaks found: 4` (the four private keys).

- [ ] **Step 9: Add the path-scoped allowlist:** `.gitleaks.toml`

```bash
git apply <<'PATCH'
diff --git a/.gitleaks.toml b/.gitleaks.toml
--- a/.gitleaks.toml
+++ b/.gitleaks.toml
@@ -11,3 +11,10 @@ useDefault = true
 description = "SSH public-key SHA256 fingerprints are public material"
 regexTarget = "line"
 regexes = ['''SHA256:[A-Za-z0-9+/]{43}''']
+
+# internal/keyfile/testdata holds throwaway private keys generated by
+# ssh-keygen solely as parser/interop fixtures (and fuzz seeds/crashers);
+# they authorize nothing anywhere. Scoped to that directory only.
+[[allowlists]]
+description = "throwaway ssh-keygen fixtures for internal/keyfile tests"
+paths = ['''^internal/keyfile/testdata/''']
PATCH
```

- [ ] **Step 10: Run**

```bash
gitleaks dir --redact . 2>&1 | tail -1
```

Expected: `INF no leaks found`.

- [ ] **Step 11: Run**

```bash
go test -run='^$' -fuzz=FuzzClassify -fuzztime=10s ./internal/keyfile && go test -run='^$' -fuzz=FuzzDecrypt -fuzztime=10s ./internal/keyfile
```

Expected: Both `PASS` (no crashers; nothing new under `testdata/fuzz/`).

- [ ] **Step 12: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/keyfile/testdata internal/keyfile/fixtures_test.go internal/keyfile/fuzz_test.go .gitleaks.toml
git commit -m "$(cat <<'EOF'
test(keyfile): ssh-keygen interop fixtures, FuzzClassify/FuzzDecrypt, gitleaks allowlist

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


### Group T — transport: `internal/sshconn`, `internal/sshread` (stage 1, parallel with K)


#### Task T1 (Group T · stage 1): `sshconn.Credentials` — union, `Signers`, `Held`

**Files:**
- Create: `internal/sshconn/credentials.go`
- Create: `internal/sshconn/credentials_test.go`
- Modify: `internal/sshconn/sshtest/sshtest.go`

One credential source per run: key files (flag order) in union with the agent.
`Signers` returns file signers, then agent plain keys, then agent certificates,
de-duplicated by fingerprint (file wins), plus a closer for the agent connection.
`Held` returns plain keys with their sources (certificates excluded) and re-lists
the agent on every call. With key files present, agent failure degrades (one
warning per run, `sync.Once` shared by both methods; `Held` returns a nil error);
without key files it is today's `ErrorKindAgent` error. An unset `SSH_AUTH_SOCK`
with key files is silent. Agent keys arrive as `*agent.Key` whatever their type,
so certificates are detected by re-parsing the wire form (`isCert`).

`sshtest` gains `AgentKeys` (certificates in the keyring), `UserCert`,
`Identity` (a `keyfile.Identity` with no disk) and `WriteKeyFile` (an OpenSSH key
file, mode 0600, optionally encrypted).

**Stage-1 prerequisite:** this task imports `internal/keyfile`. If Group K's
`internal/keyfile/identity.go` is not in your tree yet, create it now with exactly
the content pinned in [Interfaces](#interfaces) (byte-identical to K1, so the
merge is clean) and include it in this commit.

- [ ] **Step 1: Check the contract file (create it from the Interfaces section if this prints `MISSING`):**

```bash
test -f internal/keyfile/identity.go && echo present || echo MISSING
```

Expected: `present` (or create it, then re-run).

- [ ] **Step 2: Extend the hermetic test peers (test-support package, used by the tests below):** `internal/sshconn/sshtest/sshtest.go`

```bash
git apply <<'PATCH'
diff --git a/internal/sshconn/sshtest/sshtest.go b/internal/sshconn/sshtest/sshtest.go
--- a/internal/sshconn/sshtest/sshtest.go
+++ b/internal/sshconn/sshtest/sshtest.go
@@ -1,13 +1,16 @@
 // Package sshtest runs hermetic, in-process SSH peers for unit tests: an
-// x/crypto/ssh server on 127.0.0.1 and an agent.NewKeyring served on a unix
-// socket. Every goroutine they start is torn down by tb.Cleanup, so the
+// x/crypto/ssh server on 127.0.0.1, an agent.NewKeyring served on a unix
+// socket, and file-key helpers (Identity, WriteKeyFile) for auth with no
+// agent at all. Every goroutine they start is torn down by tb.Cleanup, so the
 // goleak TestMain in each consuming package stays green.
 package sshtest
 
 import (
 	"context"
 	"crypto/ed25519"
+	"crypto/rand"
 	"encoding/binary"
+	"encoding/pem"
 	"errors"
 	"io"
 	"net"
@@ -21,6 +24,8 @@ import (
 	"golang.org/x/crypto/ssh"
 	"golang.org/x/crypto/ssh/agent"
 	"golang.org/x/crypto/ssh/knownhosts"
+
+	"github.com/javadh75/SSHepherd/internal/keyfile"
 )
 
 // Key returns a deterministic ed25519 private key derived from seed.
@@ -108,10 +113,21 @@ func (t *tracker) serve(fn func(net.Conn)) {
 
 // Agent serves an in-memory keyring holding keys and returns its socket.
 func Agent(tb testing.TB, keys ...any) string {
+	tb.Helper()
+	added := make([]agent.AddedKey, 0, len(keys))
+	for _, k := range keys {
+		added = append(added, agent.AddedKey{PrivateKey: k})
+	}
+	return AgentKeys(tb, added...)
+}
+
+// AgentKeys serves an in-memory keyring holding exactly keys (certificates
+// included, via AddedKey.Certificate) and returns its socket.
+func AgentKeys(tb testing.TB, keys ...agent.AddedKey) string {
 	tb.Helper()
 	keyring := agent.NewKeyring()
 	for _, k := range keys {
-		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
+		if err := keyring.Add(k); err != nil {
 			tb.Fatalf("sshtest: keyring add: %v", err)
 		}
 	}
@@ -129,6 +145,59 @@ func Agent(tb testing.TB, keys ...any) string {
 	return sock
 }
 
+// UserCert returns a user certificate for priv's public key, signed by ca,
+// valid for principal — an agent-held certificate for tests (servers
+// accept it by listing the certificate itself in ServerConfig.Authorized).
+func UserCert(tb testing.TB, priv, ca any, principal string) *ssh.Certificate {
+	tb.Helper()
+	cert := &ssh.Certificate{
+		Key:             Signer(tb, priv).PublicKey(),
+		CertType:        ssh.UserCert,
+		KeyId:           "sshtest",
+		ValidPrincipals: []string{principal},
+		ValidBefore:     ssh.CertTimeInfinity,
+	}
+	if err := cert.SignCert(rand.Reader, Signer(tb, ca)); err != nil {
+		tb.Fatalf("sshtest: sign cert: %v", err)
+	}
+	return cert
+}
+
+// Identity returns priv as a loaded --identity key named path — file-key
+// auth with no agent and no disk.
+func Identity(tb testing.TB, path string, priv any) keyfile.Identity {
+	tb.Helper()
+	s := Signer(tb, priv)
+	return keyfile.Identity{Path: path, Fingerprint: ssh.FingerprintSHA256(s.PublicKey()), Signer: s}
+}
+
+// WriteKeyFile writes priv as an OpenSSH private key file (mode 0600)
+// named name in dir — encrypted with passphrase unless it is nil — plus its
+// .pub, and returns the key's path.
+func WriteKeyFile(tb testing.TB, dir, name string, priv any, passphrase []byte) string {
+	tb.Helper()
+	var (
+		block *pem.Block
+		err   error
+	)
+	if passphrase == nil {
+		block, err = ssh.MarshalPrivateKey(priv, "sshtest")
+	} else {
+		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "sshtest", passphrase)
+	}
+	if err != nil {
+		tb.Fatalf("sshtest: marshal key: %v", err)
+	}
+	path := filepath.Join(dir, name)
+	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
+		tb.Fatalf("sshtest: write key: %v", err)
+	}
+	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(Signer(tb, priv).PublicKey()), 0o600); err != nil {
+		tb.Fatalf("sshtest: write pub: %v", err)
+	}
+	return path
+}
+
 // Handler runs one exec request: cmd is the raw command string the client
 // sent; the return value is the exit status. ctx is canceled when the
 // client closes the channel.
PATCH
```

- [ ] **Step 3: Write the failing tests:** `internal/sshconn/credentials_test.go`

```go
package sshconn

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// deadSock is an agent socket path nothing listens on.
func deadSock(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "dead.sock")
}

// warnLog captures warnings.
func warnLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

func signerFPs(signers []ssh.Signer) []string {
	out := make([]string, 0, len(signers))
	for _, s := range signers {
		out = append(out, ssh.FingerprintSHA256(s.PublicKey()))
	}
	return out
}

func TestSignersUnionOrderAndDedup(t *testing.T) {
	a, b, c, ca := sshtest.Key(1), sshtest.Key(2), sshtest.Key(3), sshtest.Key(9)
	cert := sshtest.UserCert(t, c, ca, "deploy")
	sock := sshtest.AgentKeys(t,
		agent.AddedKey{PrivateKey: c, Certificate: cert}, // a certificate listed first by the agent
		agent.AddedKey{PrivateKey: b},
		agent.AddedKey{PrivateKey: a}, // also a key file: offered once, as the file
	)
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/a", a), sshtest.Identity(t, "/k/a-again", a)}, AgentSock: sock}
	signers, release, err := creds.Signers(context.Background())
	if err != nil {
		t.Fatalf("Signers: %v", err)
	}
	defer release()
	want := []string{sshtest.Fingerprint(t, a), sshtest.Fingerprint(t, b), ssh.FingerprintSHA256(cert)}
	if got := signerFPs(signers); !slices.Equal(got, want) {
		t.Errorf("Signers = %v, want file keys, then agent plain keys, then certificates: %v", got, want)
	}
	if !isCert(signers[2].PublicKey()) {
		t.Error("the agent certificate must still be offered for login")
	}

	held, err := creds.Held(context.Background())
	if err != nil {
		t.Fatalf("Held: %v", err)
	}
	wantHeld := []HeldKey{{sshtest.Fingerprint(t, a), "/k/a"}, {sshtest.Fingerprint(t, b), SourceAgent}}
	if !slices.Equal(held, wantHeld) {
		t.Errorf("Held = %v, want %v (no certificate, file source wins)", held, wantHeld)
	}
}

func TestHeldExcludesAgentCertificates(t *testing.T) {
	c, ca := sshtest.Key(3), sshtest.Key(9)
	cert := sshtest.UserCert(t, c, ca, "deploy")
	creds := &Credentials{AgentSock: sshtest.AgentKeys(t, agent.AddedKey{PrivateKey: c, Certificate: cert})}
	signers, release, err := creds.Signers(context.Background())
	if err != nil || len(signers) != 1 {
		t.Fatalf("Signers = (%d, %v), want the certificate offered", len(signers), err)
	}
	release()
	held, err := creds.Held(context.Background())
	if err != nil || len(held) != 0 {
		t.Errorf("Held = (%v, %v), want empty: certificates never count", held, err)
	}
}

func TestBrokenAgentDegradesOnce(t *testing.T) {
	log, buf := warnLog()
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/ci", sshtest.Key(1))}, AgentSock: deadSock(t), Log: log}
	for range 2 {
		signers, release, err := creds.Signers(context.Background())
		if err != nil || len(signers) != 1 {
			t.Fatalf("Signers = (%d, %v), want the file key alone", len(signers), err)
		}
		release()
		held, err := creds.Held(context.Background())
		if err != nil || len(held) != 1 || held[0].Source != "/k/ci" {
			t.Fatalf("Held = (%v, %v), want the file key alone and a nil error (fail-safe)", held, err)
		}
	}
	if n := strings.Count(buf.String(), "ssh-agent unusable"); n != 1 {
		t.Errorf("warnings = %d, want exactly one per run:\n%s", n, buf.String())
	}
}

func TestUnsetAgentWithFileKeyIsSilent(t *testing.T) {
	log, buf := warnLog()
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/ci", sshtest.Key(1))}, Log: log}
	signers, release, err := creds.Signers(context.Background())
	if err != nil || len(signers) != 1 {
		t.Fatalf("Signers = (%d, %v), want the file key", len(signers), err)
	}
	release()
	if held, err := creds.Held(context.Background()); err != nil || len(held) != 1 {
		t.Fatalf("Held = (%v, %v)", held, err)
	}
	if buf.Len() != 0 {
		t.Errorf("an unset SSH_AUTH_SOCK must not warn: %q", buf.String())
	}
}

func TestNoKeysAtAllIsAnAgentError(t *testing.T) {
	for name, sock := range map[string]string{"dead socket": deadSock(t), "unset": ""} {
		t.Run(name, func(t *testing.T) {
			creds := &Credentials{AgentSock: sock}
			_, _, err := creds.Signers(context.Background())
			if err == nil || kindOf(t, err) != audit.ErrorKindAgent {
				t.Fatalf("Signers err = %v, want ErrorKindAgent", err)
			}
			if _, err := creds.Held(context.Background()); err == nil {
				t.Fatal("Held with no keys at all returned no error")
			}
		})
	}
}

func TestHeldKeyLabel(t *testing.T) {
	if got := (HeldKey{Fingerprint: "SHA256:x", Source: SourceAgent}).Label(); got != "SHA256:x (agent)" {
		t.Errorf("Label = %q", got)
	}
}
```

- [ ] **Step 4: Run**

```bash
go test ./internal/sshconn -run "Signers|Held|BrokenAgent|UnsetAgent|NoKeysAtAll"
```

Expected: FAIL — build failure: `undefined: Credentials`, `undefined: HeldKey`, `undefined: SourceAgent`.

- [ ] **Step 5: Implement:** `internal/sshconn/credentials.go`

```go
package sshconn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/keyfile"
)

// SourceAgent is HeldKey.Source for a key the ssh-agent holds.
const SourceAgent = "agent"

// agentTimeout bounds agent I/O when the caller's ctx has no deadline.
const agentTimeout = 3 * time.Second

// HeldKey is one plain key the run can authenticate with: its SHA256
// fingerprint and where it comes from — the --identity path, or
// SourceAgent.
type HeldKey struct {
	Fingerprint string
	Source      string
}

// Label renders the key with its source, as refusals list it:
// "SHA256:… (/home/op/.ssh/ci)" or "SHA256:… (agent)".
func (k HeldKey) Label() string { return k.Fingerprint + " (" + k.Source + ")" }

// Credentials is the run's one credential source, shared by the read
// client, the writer and the login probe: --identity key files (in flag
// order) in union with the ssh-agent at AgentSock ("" = no agent), like
// ssh -i. Use it by pointer: the degraded-agent warning is logged once per
// run across Signers and Held.
type Credentials struct {
	Files     []keyfile.Identity
	AgentSock string
	Log       *slog.Logger // optional; nil discards

	warnOnce sync.Once
}

func (c *Credentials) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.DiscardHandler)
}

// warnAgent logs the one-time "agent unusable, continuing with key files"
// warning. Only called when key files are present.
func (c *Credentials) warnAgent(err error) {
	c.warnOnce.Do(func() {
		c.log().Warn(fmt.Sprintf("ssh-agent unusable (%v) — continuing with the --identity keys only", err))
	})
}

// dialAgent connects to the agent with ctx's deadline (or agentTimeout)
// applied to the socket, so a wedged agent cannot hang a worker.
func (c *Credentials) dialAgent(ctx context.Context) (agent.ExtendedAgent, net.Conn, error) {
	if c.AgentSock == "" {
		return nil, nil, errors.New("no SSH agent: SSH_AUTH_SOCK is not set")
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(agentTimeout)
	}
	d := net.Dialer{Deadline: dl}
	conn, err := d.DialContext(ctx, "unix", c.AgentSock)
	if err != nil {
		return nil, nil, fmt.Errorf("connect ssh-agent: %w", err)
	}
	_ = conn.SetDeadline(dl)
	return agent.NewClient(conn), conn, nil
}

// fileSigners returns the key-file signers in flag order, de-duplicated by
// fingerprint, and the set of their fingerprints.
func (c *Credentials) fileSigners() ([]ssh.Signer, map[string]bool) {
	out := make([]ssh.Signer, 0, len(c.Files))
	seen := make(map[string]bool, len(c.Files))
	for _, id := range c.Files {
		fp := ssh.FingerprintSHA256(id.Signer.PublicKey())
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, id.Signer)
	}
	return out, seen
}

// Signers returns every signer to offer, in order: key files (flag order),
// then agent signers (agent order, plain keys before certificates),
// de-duplicated by fingerprint (the file signer wins). The closer releases
// the agent connection, which agent signers sign through: keep it open
// until the handshake is over. Agent failure with key files present is
// logged once and the file signers are returned; with no key files it is
// an ErrorKindAgent error, as before this slice.
func (c *Credentials) Signers(ctx context.Context) ([]ssh.Signer, func(), error) {
	noop := func() {}
	out, seen := c.fileSigners()
	if c.AgentSock == "" && len(out) > 0 {
		return out, noop, nil // no agent configured: nothing to warn about
	}
	ag, conn, err := c.dialAgent(ctx)
	if err == nil {
		var signers []ssh.Signer
		signers, err = ag.Signers()
		if err != nil {
			_ = conn.Close()
			err = fmt.Errorf("agent signers: %w", err)
		} else {
			closer := func() { _ = conn.Close() }
			return appendAgentSigners(out, seen, signers), closer, nil
		}
	}
	if len(out) == 0 {
		return nil, noop, classify(audit.ErrorKindAgent, err)
	}
	c.warnAgent(err)
	return out, noop, nil
}

// appendAgentSigners appends the agent's plain keys, then its
// certificates, skipping fingerprints already offered.
func appendAgentSigners(out []ssh.Signer, seen map[string]bool, signers []ssh.Signer) []ssh.Signer {
	var certs []ssh.Signer
	for _, s := range signers {
		fp := ssh.FingerprintSHA256(s.PublicKey())
		if seen[fp] {
			continue
		}
		seen[fp] = true
		if isCert(s.PublicKey()) {
			certs = append(certs, s)
			continue
		}
		out = append(out, s)
	}
	return append(out, certs...)
}

// isCert reports whether pub is a certificate. Agent keys arrive as
// *agent.Key whatever their type, so the wire form is re-parsed.
func isCert(pub ssh.PublicKey) bool {
	parsed, err := ssh.ParsePublicKey(pub.Marshal())
	if err != nil {
		return false
	}
	_, ok := parsed.(*ssh.Certificate)
	return ok
}

// Held lists the plain keys of the current union with their sources — the
// self-lockout guard's and the login probe's ground truth. Agent
// certificates are excluded: they log in through cert-authority lines,
// which the guard cannot prove survive. The agent is re-listed on every
// call, so the post-prompt re-check sees keys that expired meanwhile.
// Agent failure with key files present returns the file keys with a nil
// error (agent keys simply stop counting — fail-safe) and the one-time
// warning; with no key files it is returned.
func (c *Credentials) Held(ctx context.Context) ([]HeldKey, error) {
	var held []HeldKey
	seen := make(map[string]bool, len(c.Files))
	for _, id := range c.Files {
		fp := ssh.FingerprintSHA256(id.Signer.PublicKey())
		if !seen[fp] {
			seen[fp] = true
			held = append(held, HeldKey{Fingerprint: fp, Source: id.Path})
		}
	}
	if c.AgentSock == "" && len(held) > 0 {
		return held, nil
	}
	keys, err := c.listAgent(ctx)
	if err != nil {
		if len(held) == 0 {
			return nil, err
		}
		c.warnAgent(err)
		return held, nil
	}
	for _, k := range keys {
		if isCert(k) {
			continue
		}
		fp := ssh.FingerprintSHA256(k)
		if !seen[fp] {
			seen[fp] = true
			held = append(held, HeldKey{Fingerprint: fp, Source: SourceAgent})
		}
	}
	return held, nil
}

// listAgent lists the agent's keys over one short-lived connection.
func (c *Credentials) listAgent(ctx context.Context) ([]*agent.Key, error) {
	ag, conn, err := c.dialAgent(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("list SSH agent keys at %s: %w", c.AgentSock, err)
	}
	return keys, nil
}
```

- [ ] **Step 6: Run**

```bash
go test -race ./internal/sshconn/...
```

Expected: PASS.

- [ ] **Step 7: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/sshconn/credentials.go internal/sshconn/credentials_test.go internal/sshconn/sshtest/sshtest.go internal/keyfile/identity.go
git commit -m "$(cat <<'EOF'
feat(sshconn): Credentials — key files in union with the agent; Held with sources

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task T2 (Group T · stage 1): `Dialer.Creds` — signers fetched before the dial

**Files:**
- Create: `internal/sshconn/connect_creds_test.go`
- Modify: `internal/sshconn/connect.go`
- Modify: `internal/sshconn/connect_test.go`

`ConnectWith` now calls `Credentials.Signers` **before** the TCP dial (an agent
problem fails or degrades without touching the server) and defers the closer
until it returns; the `PublicKeysCallback` only returns the pre-fetched, ordered,
wrapped list. `orderSigners`, `wrapSigners` and the session-key recorder are
unchanged: ties keep `Signers` order (file keys before agent keys).

**Transitional:** `Dialer.AgentSock` stays (used only when `Creds` is nil, as an
agent-only `Credentials`) so `cmd/sshepherd` and `internal/sshwrite` keep
compiling until C1/W3 move to `Creds`; C2 deletes it.

- [ ] **Step 1: Write the failing tests:** `internal/sshconn/connect_creds_test.go`

```go
package sshconn

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// credServer is a hermetic server accepting exactly authorized.
func credServer(t *testing.T, authorized ...ssh.PublicKey) (*sshtest.Server, string, config.Server) {
	t.Helper()
	host := sshtest.Signer(t, sshtest.Key(40))
	s := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{host}, Authorized: authorized})
	kh := sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey()))
	return s, kh, config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
}

func TestFileOnlyAuthWithNoAgent(t *testing.T) {
	key := sshtest.Key(1)
	s, kh, srv := credServer(t, sshtest.Signer(t, key).PublicKey())
	d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/keys/ci", key)}}, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("Connect with a key file and no agent: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got, want := conn.SessionKeyFP(), sshtest.Fingerprint(t, key); got != want {
		t.Errorf("SessionKeyFP = %s, want the file key %s (the recorder sees file keys)", got, want)
	}
	if got := s.Attempts(); len(got) != 1 {
		t.Errorf("attempts = %v, want exactly the file key", got)
	}
}

func TestAgentCertificateStillLogsIn(t *testing.T) {
	c, ca := sshtest.Key(3), sshtest.Key(9)
	cert := sshtest.UserCert(t, c, ca, "deploy")
	_, kh, srv := credServer(t, cert)
	creds := &Credentials{AgentSock: sshtest.AgentKeys(t, agent.AddedKey{PrivateKey: c, Certificate: cert})}
	d := &Dialer{KnownHostsPath: kh, Creds: creds, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("certificate login: %v", err)
	}
	_ = conn.Close()
}

func TestBrokenAgentWithFileKeyConnects(t *testing.T) {
	key := sshtest.Key(1)
	log, buf := warnLog()
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/ci", key)}, AgentSock: deadSock(t), Log: log}
	_, kh, srv := credServer(t, sshtest.Signer(t, key).PublicKey())
	d := &Dialer{KnownHostsPath: kh, Creds: creds, DialTimeout: 5 * time.Second}
	for range 2 {
		conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
		if err != nil {
			t.Fatalf("Connect despite a broken agent: %v", err)
		}
		_ = conn.Close()
	}
	if n := strings.Count(buf.String(), "ssh-agent unusable"); n != 1 {
		t.Errorf("warnings = %d, want exactly one per run:\n%s", n, buf.String())
	}
}

func TestConnectWithoutKeysFailsBeforeDialing(t *testing.T) {
	// A bare TCP listener counts connections: Signers runs before the dial,
	// so an agent failure with no key files never opens a TCP connection
	// (key offers alone could not tell "never dialed" from "dialed, offered
	// nothing").
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
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
	srv := config.Server{Name: "web-1", Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, User: "deploy"}
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: deadSock(t)}, DialTimeout: time.Second}
	if _, err := d.Connect(ctxTimeout(t, 5*time.Second), srv); err == nil || kindOf(t, err) != audit.ErrorKindAgent {
		t.Fatalf("Connect err = %v, want ErrorKindAgent", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("%d TCP connections although nothing could authenticate, want none (signers come before the dial)", n)
	}
}

func TestOnlyAcrossSources(t *testing.T) {
	file, ag := sshtest.Key(1), sshtest.Key(2)
	s, kh, srv := credServer(t, sshtest.Signer(t, file).PublicKey(), sshtest.Signer(t, ag).PublicKey())
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/f", file)}, AgentSock: sshtest.Agent(t, ag)}
	d := &Dialer{KnownHostsPath: kh, Creds: creds, DialTimeout: 5 * time.Second}
	for _, only := range []string{sshtest.Fingerprint(t, ag), sshtest.Fingerprint(t, file)} {
		before := len(s.Attempts())
		conn, err := d.ConnectWith(ctxTimeout(t, 10*time.Second), srv, ConnectOptions{Only: []string{only}})
		if err != nil {
			t.Fatalf("ConnectWith Only %s: %v", only, err)
		}
		if got := conn.SessionKeyFP(); got != only {
			t.Errorf("logged in with %s, want %s", got, only)
		}
		_ = conn.Close()
		if got := s.Attempts()[before:]; !slices.Equal(got, []string{only}) {
			t.Errorf("attempts = %v, want exactly [%s]", got, only)
		}
	}
}

func TestPreferTiesKeepFileFirst(t *testing.T) {
	file, ag := sshtest.Key(1), sshtest.Key(2)
	s, kh, srv := credServer(t, sshtest.Signer(t, ag).PublicKey())
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/f", file)}, AgentSock: sshtest.Agent(t, ag)}
	d := &Dialer{KnownHostsPath: kh, Creds: creds, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_ = conn.Close()
	want := []string{sshtest.Fingerprint(t, file), sshtest.Fingerprint(t, ag)}
	if got := s.Attempts(); !slices.Equal(got, want) {
		t.Errorf("attempts = %v, want the file key before the agent key: %v", got, want)
	}
}
```

- [ ] **Step 2: Move the existing fixtures to `Creds`:** `internal/sshconn/connect_test.go`

```bash
git apply <<'PATCH'
diff --git a/internal/sshconn/connect_test.go b/internal/sshconn/connect_test.go
--- a/internal/sshconn/connect_test.go
+++ b/internal/sshconn/connect_test.go
@@ -60,7 +60,7 @@ func newFixture(t *testing.T, sc sshtest.ServerConfig, agentKeys ...any) fixture
 }
 
 func (f fixture) dialer(kh string) *Dialer {
-	return &Dialer{KnownHostsPath: kh, AgentSock: f.agent, DialTimeout: 5 * time.Second}
+	return &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: f.agent}, DialTimeout: 5 * time.Second}
 }
 
 func ctxTimeout(t *testing.T, d time.Duration) context.Context {
@@ -277,7 +277,7 @@ func TestConnectDialRefusedMentionsBastion(t *testing.T) {
 	}
 	port := l.Addr().(*net.TCPAddr).Port
 	_ = l.Close() // nothing listens there now
-	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), AgentSock: sshtest.Agent(t, sshtest.Key(1)), DialTimeout: time.Second}
+	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: time.Second}
 	_, err = d.Connect(ctxTimeout(t, 5*time.Second), config.Server{Name: "x", Host: "127.0.0.1", Port: port, User: "u"})
 	if err == nil {
 		t.Fatal("dial to a closed port succeeded")
@@ -408,7 +408,7 @@ func TestDialerParsesKnownHostsOnce(t *testing.T) {
 		if err != nil {
 			t.Fatal(err)
 		}
-		d := &Dialer{KnownHostsPath: "/nonexistent", KnownHosts: snap, AgentSock: f.agent, DialTimeout: time.Second}
+		d := &Dialer{KnownHostsPath: "/nonexistent", KnownHosts: snap, Creds: &Credentials{AgentSock: f.agent}, DialTimeout: time.Second}
 		conn, err := d.Connect(ctxTimeout(t, 10*time.Second), f.cfgSrv)
 		if err != nil {
 			t.Fatalf("Connect with preloaded snapshot: %v", err)
PATCH
```

- [ ] **Step 3: Run**

```bash
go test ./internal/sshconn
```

Expected: FAIL — build failure: `unknown field Creds in struct literal of type Dialer`.

- [ ] **Step 4: Implement:** `internal/sshconn/connect.go`

```bash
git apply <<'PATCH'
diff --git a/internal/sshconn/connect.go b/internal/sshconn/connect.go
--- a/internal/sshconn/connect.go
+++ b/internal/sshconn/connect.go
@@ -14,7 +14,6 @@ import (
 	"time"
 
 	"golang.org/x/crypto/ssh"
-	"golang.org/x/crypto/ssh/agent"
 
 	"github.com/javadh75/SSHepherd/internal/audit"
 	"github.com/javadh75/SSHepherd/internal/config"
@@ -28,33 +27,41 @@ type Dialer struct {
 	// KnownHosts is an optional pre-parsed snapshot (typically the
 	// preflight's). Nil loads KnownHostsPath once, on first Connect, and
 	// reuses that snapshot for every later connection through this Dialer.
-	KnownHosts  *KnownHosts
+	KnownHosts *KnownHosts
+	// Creds is the run's credential source (key files + agent), shared
+	// with every other Dialer and the read client of the run.
+	Creds *Credentials
+	// AgentSock is transitional: used only when Creds is nil, as an
+	// agent-only Credentials. Removed once every caller sets Creds.
 	AgentSock   string
 	DialTimeout time.Duration
-	// PreferKeys optionally returns the agent-key fingerprints to offer
-	// first when connecting to srv — the keys the manifest grants there,
-	// operators first (audit.GrantedFingerprints). Remaining agent keys
-	// follow in agent order. Without it an agent holding many keys offers
-	// them in agent order, and sshd's MaxAuthTries (default 6) can
-	// disconnect before the granted key is tried.
+	// PreferKeys optionally returns the fingerprints to offer first when
+	// connecting to srv — the keys the manifest grants there, operators
+	// first (audit.GrantedFingerprints). Remaining keys follow in
+	// Credentials.Signers order (key files, then the agent). Without it a
+	// many-key union is offered in that order, and sshd's MaxAuthTries
+	// (default 6) can disconnect before the granted key is tried.
 	PreferKeys func(srv config.Server) []string
 	Log        *slog.Logger // optional stage-level telemetry; nil discards
 
 	khOnce sync.Once
 	kh     *KnownHosts
 	khErr  error
+
+	credsOnce sync.Once
+	creds     *Credentials
 }
 
-// ConnectOptions tunes one connection's agent-key offering.
+// ConnectOptions tunes one connection's key offering.
 type ConnectOptions struct {
 	// Prefer lists fingerprints to offer first, in order; nil falls back to
 	// Dialer.PreferKeys(srv).
 	Prefer []string
-	// Only, when non-empty, offers exactly the agent keys with these
-	// fingerprints (in this order) and nothing else — the IdentitiesOnly
-	// posture. A login that succeeds therefore proves the server accepts
-	// one of them (apply's post-write login probe); none held by the agent
-	// is an auth failure, never a fallback to other keys.
+	// Only, when non-empty, offers exactly the held keys (key files or
+	// agent) with these fingerprints (in this order) and nothing else — the
+	// IdentitiesOnly posture. A login that succeeds therefore proves the
+	// server accepts one of them (apply's post-write login probe); none
+	// held is an auth failure, never a fallback to other keys.
 	Only []string
 }
 
@@ -67,6 +74,18 @@ func (d *Dialer) log() *slog.Logger {
 	return slog.New(slog.DiscardHandler)
 }
 
+// credentials returns Creds, or the transitional agent-only Credentials
+// built once from AgentSock.
+func (d *Dialer) credentials() *Credentials {
+	d.credsOnce.Do(func() {
+		d.creds = d.Creds
+		if d.creds == nil {
+			d.creds = &Credentials{AgentSock: d.AgentSock, Log: d.Log}
+		}
+	})
+	return d.creds
+}
+
 // knownHosts returns the run's single known_hosts snapshot.
 func (d *Dialer) knownHosts() (*KnownHosts, error) {
 	d.khOnce.Do(func() {
@@ -85,8 +104,8 @@ type Conn struct {
 	session *sessionKey
 }
 
-// SessionKeyFP returns the SHA256 fingerprint of the agent key whose
-// signature completed this connection's handshake — the key this session
+// SessionKeyFP returns the SHA256 fingerprint of the key (file or agent)
+// whose signature completed this connection's handshake — the key this session
 // logged in with. Empty when unknown (test fakes, or nothing signed).
 func (c *Conn) SessionKeyFP() string {
 	if c.session == nil {
@@ -111,16 +130,18 @@ func (d *Dialer) Connect(ctx context.Context, srv config.Server) (*Conn, error)
 	return d.ConnectWith(ctx, srv, ConnectOptions{})
 }
 
-// ConnectWith dials srv and completes an agent-authenticated handshake
-// under strict known_hosts verification (agent-only auth, no TOFU), with
-// host-key algorithms ordered from what known_hosts records for srv. The
-// ctx deadline bounds agent I/O, dial, and handshake, and is installed as
-// the socket deadline, so it keeps bounding whatever sessions the caller
-// runs on the returned connection; ctx cancellation aborts the handshake.
-// Callers without a ctx deadline get a hard floor: 3×DialTimeout (30s when
-// DialTimeout is zero). The agent connection lives only until ConnectWith
-// returns — signing happens during auth, never after. Every error is an
-// *Error carrying its audit.ErrorKind.
+// ConnectWith dials srv and completes a public-key handshake under strict
+// known_hosts verification (no TOFU), offering the Credentials' signers
+// (key files, then agent), with host-key algorithms ordered from what
+// known_hosts records for srv. The signers are fetched BEFORE the TCP dial,
+// so an agent problem fails (or, with key files, degrades) without touching
+// the server. The ctx deadline bounds agent I/O, dial, and handshake, and
+// is installed as the socket deadline, so it keeps bounding whatever
+// sessions the caller runs on the returned connection; ctx cancellation
+// aborts the handshake. Callers without a ctx deadline get a hard floor:
+// 3×DialTimeout (30s when DialTimeout is zero). The agent connection lives
+// only until ConnectWith returns — signing happens during auth, never
+// after. Every error is an *Error carrying its audit.ErrorKind.
 func (d *Dialer) ConnectWith(ctx context.Context, srv config.Server, opts ConnectOptions) (*Conn, error) {
 	if _, ok := ctx.Deadline(); !ok {
 		fallback := 3 * d.DialTimeout
@@ -134,14 +155,11 @@ func (d *Dialer) ConnectWith(ctx context.Context, srv config.Server, opts Connec
 	dl, _ := ctx.Deadline() // always present: the floor above guarantees it
 	log := d.log()
 
-	agentDialer := net.Dialer{}
-	agentConn, err := agentDialer.DialContext(ctx, "unix", d.AgentSock)
+	signers, release, err := d.credentials().Signers(ctx)
 	if err != nil {
-		return nil, classify(audit.ErrorKindAgent, fmt.Errorf("connect ssh-agent: %w", err))
+		return nil, err // already classified (ErrorKindAgent)
 	}
-	defer func() { _ = agentConn.Close() }() // errcheck: auth is complete (or failed) by return; close error uninteresting
-	_ = agentConn.SetDeadline(dl)            // ag.Signers does I/O mid-handshake; a wedged agent must not hang a worker
-	ag := agent.NewClient(agentConn)
+	defer release() // agent signers sign mid-handshake; release once auth is over
 
 	kh, err := d.knownHosts()
 	if err != nil {
@@ -174,13 +192,8 @@ func (d *Dialer) ConnectWith(ctx context.Context, srv config.Server, opts Connec
 		prefer = d.PreferKeys(srv)
 	}
 	rec := &sessionKey{}
-	auth := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
-		signers, err := ag.Signers()
-		if err != nil {
-			return nil, fmt.Errorf("agent signers: %w", err)
-		}
-		return wrapSigners(orderSigners(signers, prefer, only), rec), nil
-	})
+	offered := wrapSigners(orderSigners(signers, prefer, only), rec)
+	auth := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) { return offered, nil })
 
 	dialer := net.Dialer{Timeout: d.DialTimeout}
 	log.Debug("dialing", "server", srv.Name, "addr", addr)
@@ -230,8 +243,8 @@ func (d *Dialer) ConnectWith(ctx context.Context, srv config.Server, opts Connec
 
 // orderSigners applies the per-connection key offering: with only set,
 // exactly those keys in that order; otherwise prefer's keys first (in
-// prefer order), then every other agent key in agent order. Fingerprints the
-// agent does not hold are skipped.
+// prefer order), then every other key in Signers order (key files before
+// agent keys). Fingerprints nobody holds are skipped.
 func orderSigners(signers []ssh.Signer, prefer, only []string) []ssh.Signer {
 	byFP := make(map[string]ssh.Signer, len(signers))
 	for _, s := range signers {
PATCH
```

- [ ] **Step 5: Run**

```bash
go test -race ./internal/sshconn/... && go build ./...
```

Expected: PASS; the build is clean (callers still use the transitional `AgentSock`).

- [ ] **Step 6: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/sshconn/connect.go internal/sshconn/connect_test.go internal/sshconn/connect_creds_test.go
git commit -m "$(cat <<'EOF'
feat(sshconn): Dialer.Creds — signers before the dial, file keys first

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task T3 (Group T · stage 1): `sshread.CheckCredentials` and `Client.Creds`

**Files:**
- Create: `internal/sshread/checkcreds_test.go`
- Modify: `internal/sshread/sshread.go`
- Modify: `internal/sshread/sshread_test.go`
- Modify: `internal/sshread/hermetic_test.go`
- Modify: `internal/sshread/integration_test.go`

`CheckCredentials(ctx, creds, needHeld)` replaces `CheckAgent` as the
preflight. With no key files the agent is required and the messages are
`CheckAgent`'s **verbatim**; `needHeld` (apply) additionally requires a non-empty
held set, so a certificate-only operator is refused with a certificate-specific
message; audit/adopt count signers (a certificate-only agent passes, as today).
`Client.Creds` is handed to the one `Dialer`.

**Transitional:** `Client.AgentSock` and the exported `CheckAgent` stay until C2
(it becomes the unexported `checkAgent`). `TestClientBadKnownHostsPath` now uses a
working agent: signers are fetched first, so a broken agent would fail before the
known_hosts load.

- [ ] **Step 1: Write the failing tests:** `internal/sshread/checkcreds_test.go`

```go
package sshread

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

func TestCheckCredentials(t *testing.T) {
	file := []keyfile.Identity{sshtest.Identity(t, "/k/ci", sshtest.Key(1))}
	dead := filepath.Join(t.TempDir(), "dead.sock")
	c, ca := sshtest.Key(3), sshtest.Key(9)
	certOnly := sshtest.AgentKeys(t, agent.AddedKey{PrivateKey: c, Certificate: sshtest.UserCert(t, c, ca, "deploy")})
	tests := []struct {
		name     string
		creds    *sshconn.Credentials
		needHeld bool
		wantErr  string // "" = ok
	}{
		{"no identity, no agent: today's message", &sshconn.Credentials{}, false, "no SSH agent: SSH_AUTH_SOCK is not set (start ssh-agent and ssh-add a key)"},
		{"no identity, dead agent: today's message", &sshconn.Credentials{AgentSock: dead}, true, "SSH agent unreachable at " + dead},
		{"no identity, empty agent: today's message", &sshconn.Credentials{AgentSock: sshtest.Agent(t)}, false, "has no keys loaded (run ssh-add to load your key)"},
		{"no identity, agent with a key", &sshconn.Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(2))}, true, ""},
		{"cert-only agent is enough to read", &sshconn.Credentials{AgentSock: certOnly}, false, ""},
		{"cert-only agent is refused for apply", &sshconn.Credentials{AgentSock: certOnly}, true, "are all certificates"},
		{"file key, no agent: read", &sshconn.Credentials{Files: file}, false, ""},
		{"file key, no agent: apply", &sshconn.Credentials{Files: file}, true, ""},
		{"file key, dead agent: read degrades", &sshconn.Credentials{Files: file, AgentSock: dead}, false, ""},
		{"file key, dead agent: apply degrades", &sshconn.Credentials{Files: file, AgentSock: dead}, true, ""},
		{"file key, cert-only agent: apply holds the file key", &sshconn.Credentials{Files: file, AgentSock: certOnly}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckCredentials(context.Background(), tt.creds, tt.needHeld)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckCredentials = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CheckCredentials = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
```

- [ ] **Step 2: Move the existing tests to `Creds`, fix the known_hosts test, and add the headless read test:** `internal/sshread/sshread_test.go`, `internal/sshread/hermetic_test.go`, `internal/sshread/integration_test.go`

```bash
git apply <<'PATCH'
diff --git a/internal/sshread/sshread_test.go b/internal/sshread/sshread_test.go
--- a/internal/sshread/sshread_test.go
+++ b/internal/sshread/sshread_test.go
@@ -16,6 +16,7 @@ import (
 	"golang.org/x/crypto/ssh/agent"
 
 	"github.com/javadh75/SSHepherd/internal/config"
+	"github.com/javadh75/SSHepherd/internal/sshconn"
 )
 
 func TestCheckAgent(t *testing.T) {
@@ -128,7 +129,7 @@ func serveAgent(t *testing.T, withKey bool) string {
 
 func TestClientBadAgentSock(t *testing.T) {
 	c := &Client{
-		AgentSock:      filepath.Join(t.TempDir(), "nope.sock"),
+		Creds:          &sshconn.Credentials{AgentSock: filepath.Join(t.TempDir(), "nope.sock")},
 		KnownHostsPath: filepath.Join(t.TempDir(), "kh"),
 		DialTimeout:    time.Second,
 	}
@@ -140,28 +141,15 @@ func TestClientBadAgentSock(t *testing.T) {
 }
 
 func TestClientBadKnownHostsPath(t *testing.T) {
-	sock := filepath.Join(t.TempDir(), "agent.sock")
-	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
-	if err != nil {
-		t.Fatalf("listen: %v", err)
-	}
-	defer l.Close()
-	go func() {
-		for {
-			c, err := l.Accept()
-			if err != nil {
-				return
-			}
-			c.Close()
-		}
-	}()
+	// The signers are fetched before anything else (a working agent), so
+	// the first failure is the known_hosts load.
 	c := &Client{
-		AgentSock:      sock,
+		Creds:          &sshconn.Credentials{AgentSock: serveAgent(t, true)},
 		KnownHostsPath: filepath.Join(t.TempDir(), "does-not-exist"),
 		DialTimeout:    time.Second,
 	}
 	srv := config.Server{Name: "s", Host: "127.0.0.1", Port: 1, User: "u"}
-	_, err = c.ReadAuthorizedKeys(context.Background(), srv)
+	_, err := c.ReadAuthorizedKeys(context.Background(), srv)
 	if err == nil || !strings.Contains(err.Error(), "known_hosts") {
 		t.Errorf("err = %v, want known_hosts load error", err)
 	}
@@ -236,7 +224,7 @@ func TestClientDeadline(t *testing.T) {
 	}
 
 	t.Run("ctx deadline bounds the handshake", func(t *testing.T) {
-		c := &Client{AgentSock: agentSock, KnownHostsPath: kh, DialTimeout: 5 * time.Second}
+		c := &Client{Creds: &sshconn.Credentials{AgentSock: agentSock}, KnownHostsPath: kh, DialTimeout: 5 * time.Second}
 		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
 		defer cancel()
 		start := time.Now()
@@ -251,7 +239,7 @@ func TestClientDeadline(t *testing.T) {
 	})
 
 	t.Run("deadline floor kicks in without a ctx deadline", func(t *testing.T) {
-		c := &Client{AgentSock: agentSock, KnownHostsPath: kh, DialTimeout: 100 * time.Millisecond}
+		c := &Client{Creds: &sshconn.Credentials{AgentSock: agentSock}, KnownHostsPath: kh, DialTimeout: 100 * time.Millisecond}
 		start := time.Now()
 		_, err := c.ReadAuthorizedKeys(context.Background(), srv) // no deadline: floor = 300ms
 		elapsed := time.Since(start)
diff --git a/internal/sshread/hermetic_test.go b/internal/sshread/hermetic_test.go
--- a/internal/sshread/hermetic_test.go
+++ b/internal/sshread/hermetic_test.go
@@ -11,6 +11,8 @@ import (
 	"golang.org/x/crypto/ssh"
 
 	"github.com/javadh75/SSHepherd/internal/config"
+	"github.com/javadh75/SSHepherd/internal/keyfile"
+	"github.com/javadh75/SSHepherd/internal/sshconn"
 	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
 )
 
@@ -28,7 +30,7 @@ func hermeticClient(t *testing.T, home string) (*Client, *sshtest.Server, config
 	})
 	c := &Client{
 		KnownHostsPath: sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey())),
-		AgentSock:      sshtest.Agent(t, sshtest.Key(2), user),
+		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(2), user)},
 		DialTimeout:    5 * time.Second,
 	}
 	return c, srv, config.Server{Name: "web-1", Host: srv.Host, Port: srv.Port, User: "deploy"}
@@ -119,3 +121,21 @@ func TestClientSharesOneSnapshotAndPrefersGrantedKeys(t *testing.T) {
 		t.Errorf("auth attempts = %v, want only the granted key, once per read", got)
 	}
 }
+
+// TestReadWithKeyFileNoAgent: the Client's Creds carry an --identity key
+// and no agent at all — the headless read path.
+func TestReadWithKeyFileNoAgent(t *testing.T) {
+	home := shortTempDir(t)
+	writeHomeFile(t, home, ".ssh/authorized_keys", "key-line\n")
+	c, _, srv := hermeticClient(t, home)
+	c.Creds = &sshconn.Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/keys/ci", sshtest.Key(1))}}
+	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
+	defer cancel()
+	res, err := c.ReadAuthorizedKeys(ctx, srv)
+	if err != nil {
+		t.Fatalf("ReadAuthorizedKeys with a key file and no agent: %v", err)
+	}
+	if res.SessionKeyFP != sshtest.Fingerprint(t, sshtest.Key(1)) {
+		t.Errorf("SessionKeyFP = %q, want the key file's fingerprint", res.SessionKeyFP)
+	}
+}
diff --git a/internal/sshread/integration_test.go b/internal/sshread/integration_test.go
--- a/internal/sshread/integration_test.go
+++ b/internal/sshread/integration_test.go
@@ -13,6 +13,7 @@ import (
 
 	"github.com/javadh75/SSHepherd/internal/audit"
 	"github.com/javadh75/SSHepherd/internal/config"
+	"github.com/javadh75/SSHepherd/internal/sshconn"
 )
 
 // itClient builds a Client from the environment exported by
@@ -29,7 +30,7 @@ func itClient(t *testing.T) (*Client, string, int) {
 	}
 	return &Client{
 		KnownHostsPath: os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS"),
-		AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
+		Creds:          &sshconn.Credentials{AgentSock: os.Getenv("SSH_AUTH_SOCK")},
 		DialTimeout:    10 * time.Second,
 	}, host, port
 }
PATCH
```

- [ ] **Step 3: Run**

```bash
go test ./internal/sshread
```

Expected: FAIL — build failure: `undefined: CheckCredentials`, `unknown field Creds in struct literal of type Client`.

- [ ] **Step 4: Implement:** `internal/sshread/sshread.go`

```bash
git apply <<'PATCH'
diff --git a/internal/sshread/sshread.go b/internal/sshread/sshread.go
--- a/internal/sshread/sshread.go
+++ b/internal/sshread/sshread.go
@@ -1,5 +1,6 @@
 // Package sshread is the real KeyReader: it connects to a server over SSH
-// (agent auth, strict known_hosts) and reads the remote authorized_keys.
+// (key files and/or agent, strict known_hosts) and reads the remote
+// authorized_keys.
 // The connection glue lives in internal/sshconn (shared with the write
 // path); this package keeps the read decision logic and its public API.
 package sshread
@@ -29,6 +30,42 @@ func LoadKnownHosts(path string) (*sshconn.KnownHosts, error) {
 	return sshconn.LoadKnownHosts(path) // sshconn labels the error with the path (wrapcheck-exempt package)
 }
 
+// CheckCredentials verifies, before any server is dialed, that the run has
+// something to authenticate with, so a missing or empty agent fails once
+// with a clear message instead of once per server with a cryptic "no
+// supported methods remain". With no key files the agent is required and
+// the messages are CheckAgent's, verbatim. needHeld (apply) additionally
+// requires a non-empty held set — plain keys, since certificates never
+// count toward the self-lockout guard — so a certificate-only operator is
+// refused with a certificate-specific message; audit/adopt (needHeld
+// false) count signers, so a certificate-only agent passes, as before.
+func CheckCredentials(ctx context.Context, creds *sshconn.Credentials, needHeld bool) error {
+	if len(creds.Files) == 0 {
+		if err := CheckAgent(ctx, creds.AgentSock); err != nil {
+			return err
+		}
+	}
+	if !needHeld {
+		signers, release, err := creds.Signers(ctx)
+		if err != nil {
+			return err
+		}
+		release()
+		if len(signers) == 0 {
+			return errors.New("no keys to authenticate with")
+		}
+		return nil
+	}
+	held, err := creds.Held(ctx)
+	if err != nil {
+		return err
+	}
+	if len(held) == 0 {
+		return errors.New("the keys you hold (identity files + agent) are all certificates — certificates never count toward apply's self-lockout guard, so no write could be proven safe (ssh-add a plain key, or pass --identity PATH)")
+	}
+	return nil
+}
+
 // CheckAgent verifies a usable SSH agent — reachable and holding at least
 // one key — before any server is dialed, so a missing or empty agent fails
 // once with a clear message instead of once per server with a cryptic
@@ -62,11 +99,16 @@ type Client struct {
 	KnownHostsPath string
 	// KnownHosts optionally supplies the preflight's parsed snapshot
 	// (LoadKnownHosts); nil parses KnownHostsPath once, on first read.
-	KnownHosts  *sshconn.KnownHosts
+	KnownHosts *sshconn.KnownHosts
+	// Creds is the run's credential source (key files + agent); one per
+	// run, shared with the writer and the probe.
+	Creds *sshconn.Credentials
+	// AgentSock is transitional: used only when Creds is nil (an
+	// agent-only Credentials). Removed once every caller sets Creds.
 	AgentSock   string
 	DialTimeout time.Duration
-	// PreferKeys optionally names the agent keys to offer first per server
-	// (see sshconn.Dialer.PreferKeys) — typically audit.GrantedFingerprints.
+	// PreferKeys optionally names the keys to offer first per server (see
+	// sshconn.Dialer.PreferKeys) — typically audit.GrantedFingerprints.
 	PreferKeys func(srv config.Server) []string
 	Log        *slog.Logger // optional stage-level telemetry; nil discards
 
@@ -103,6 +145,7 @@ func (c *Client) getDialer() *sshconn.Dialer {
 		c.dialer = &sshconn.Dialer{
 			KnownHostsPath: c.KnownHostsPath,
 			KnownHosts:     c.KnownHosts,
+			Creds:          c.Creds,
 			AgentSock:      c.AgentSock,
 			DialTimeout:    c.DialTimeout,
 			PreferKeys:     c.PreferKeys,
PATCH
```

- [ ] **Step 5: Run**

```bash
go test -race ./internal/sshread && go vet -tags integration ./internal/sshread && go build ./... && go test ./...
```

Expected: PASS everywhere — the transitional fields keep `cmd/sshepherd` and `internal/sshwrite` green.

- [ ] **Step 6: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/sshread/sshread.go internal/sshread/sshread_test.go internal/sshread/hermetic_test.go internal/sshread/integration_test.go internal/sshread/checkcreds_test.go
git commit -m "$(cat <<'EOF'
feat(sshread): CheckCredentials preflight and Client.Creds

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


### Group W — write path: `internal/apply`, `internal/sshwrite` (stage 2)


#### Task W1 (Group W · stage 2): Held keys with sources: guard, refusal text, survivor order, agent-only warning

**Files:**
- Create: `internal/apply/identity_test.go`
- Modify: `internal/apply/plan.go`
- Modify: `internal/apply/exec.go`
- Modify: `internal/apply/plan_test.go`
- Modify: `internal/apply/exec_test.go`
- Modify: `cmd/sshepherd/apply.go`

`apply.Build` takes `[]sshconn.HeldKey` and `ExecOptions.AgentFPs` becomes
`ExecOptions.Held`. Guard logic is unchanged; wording becomes source-neutral and
refusals list every held key with its source; a run holding any `--identity`
key gets the rotation hint. `ServerPlan.AgentOnly` carries the agent-only-survivor
warning (some held key is a file, every survivor here is an agent key) — never a
refusal. The probe order (`probeOrder`) is unrestricted first, then key files
before agent keys, then fingerprint — deterministic across runs, and when an
`--identity` key survives, the probe proves that key.

**Bridge:** `cmd/sshepherd/apply.go` gets a tiny `agentHeld` adapter so it keeps
compiling against the new signatures; C1 replaces it with `Credentials.Held`.

- [ ] **Step 1: Move the existing tests to held keys (helpers `agentHeld`, `fileHeld`, `buildPlansHeld`; neutral wording):** `internal/apply/plan_test.go`, `internal/apply/exec_test.go`

```bash
git apply <<'PATCH'
diff --git a/internal/apply/plan_test.go b/internal/apply/plan_test.go
--- a/internal/apply/plan_test.go
+++ b/internal/apply/plan_test.go
@@ -9,6 +9,7 @@ import (
 	"github.com/javadh75/SSHepherd/internal/audit"
 	"github.com/javadh75/SSHepherd/internal/authkeys"
 	"github.com/javadh75/SSHepherd/internal/config"
+	"github.com/javadh75/SSHepherd/internal/sshconn"
 	"github.com/javadh75/SSHepherd/internal/sshwrite"
 	"github.com/javadh75/SSHepherd/internal/testkeys"
 )
@@ -27,17 +28,38 @@ func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (a
 }
 
 // buildPlans runs the real pipeline (audit.Run + Build) over a fake fleet —
-// exactly what the command does, minus SSH.
+// exactly what the command does, minus SSH — with agentFPs held by the
+// agent.
 func buildPlans(t *testing.T, cfg *config.Config, r audit.KeyReader, agentFPs []string) []ServerPlan {
+	t.Helper()
+	return buildPlansHeld(t, cfg, r, agentHeld(agentFPs...))
+}
+
+// buildPlansHeld is buildPlans with an explicit held set (any sources).
+func buildPlansHeld(t *testing.T, cfg *config.Config, r audit.KeyReader, held []sshconn.HeldKey) []ServerPlan {
 	t.Helper()
 	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 4})
-	plans, err := Build(cfg, results, agentFPs)
+	plans, err := Build(cfg, results, held)
 	if err != nil {
 		t.Fatalf("Build: %v", err)
 	}
 	return plans
 }
 
+// agentHeld labels fingerprints as agent-held keys.
+func agentHeld(fps ...string) []sshconn.HeldKey {
+	held := make([]sshconn.HeldKey, 0, len(fps))
+	for _, fp := range fps {
+		held = append(held, sshconn.HeldKey{Fingerprint: fp, Source: sshconn.SourceAgent})
+	}
+	return held
+}
+
+// fileHeld labels a fingerprint as held through an --identity file.
+func fileHeld(fp, path string) sshconn.HeldKey {
+	return sshconn.HeldKey{Fingerprint: fp, Source: path}
+}
+
 // planFor pulls one server's plan out by name.
 func planFor(t *testing.T, plans []ServerPlan, name string) ServerPlan {
 	t.Helper()
@@ -269,7 +291,7 @@ func TestGuardRefusesLockout(t *testing.T) {
 	if p.Class != ClassRefused {
 		t.Fatalf("Class = %s, want refused (predicted lockout)", p.Class)
 	}
-	for _, want := range []string{"none of the 2 keys in this agent", "lock this session out", "operator: true"} {
+	for _, want := range []string{"none of the 2 keys you hold (identity files + agent)", "lock this session out", "operator: true"} {
 		if !strings.Contains(p.Refusal, want) {
 			t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, want)
 		}
@@ -329,7 +351,7 @@ func TestGuardEmptyAgentRefuses(t *testing.T) {
 		t.Run(name, func(t *testing.T) {
 			r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": read}}
 			p := planFor(t, buildPlans(t, cfg, r, nil), "web-1")
-			if p.Class != ClassRefused || !strings.Contains(p.Refusal, "the agent holds no keys") {
+			if p.Class != ClassRefused || !strings.Contains(p.Refusal, "you hold no plain keys") {
 				t.Fatalf("plan = %s/%q, want the empty-agent refusal", p.Class, p.Refusal)
 			}
 		})
@@ -358,7 +380,7 @@ access:
 	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "cert-authority") {
 		t.Fatalf("plan = %s/%q, want a lockout refusal naming the cert-authority line", p.Class, p.Refusal)
 	}
-	if got := Survivors(p.Desired, heldSet([]string{fp(t, 1), fp(t, 2)})); len(got) != 1 || got[0].Fingerprint != fp(t, 2) {
+	if got := Survivors(p.Desired, heldSet(agentHeld(fp(t, 1), fp(t, 2)))); len(got) != 1 || got[0].Fingerprint != fp(t, 2) {
 		t.Errorf("Survivors = %v, want only alice's bare key", got)
 	}
 }
diff --git a/internal/apply/exec_test.go b/internal/apply/exec_test.go
--- a/internal/apply/exec_test.go
+++ b/internal/apply/exec_test.go
@@ -74,7 +74,7 @@ func TestExecuteOutcomes(t *testing.T) {
 		"locked":  &sshwrite.LockedError{Path: "~/.ssh/authorized_keys"},
 		"lockout": &sshwrite.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("auth failed")},
 	}}
-	Execute(context.Background(), plans, w, ExecOptions{Parallel: 2, AgentFPs: []string{held.Fingerprint}})
+	Execute(context.Background(), plans, w, ExecOptions{Parallel: 2, Held: agentHeld(held.Fingerprint)})
 
 	if got := planFor(t, plans, "ok-1"); got.Outcome != OutcomeApplied {
 		t.Errorf("ok-1 Outcome = %s, want applied", got.Outcome)
@@ -87,7 +87,7 @@ func TestExecuteOutcomes(t *testing.T) {
 		t.Errorf("writer Expect = %+v, want the plan's phase-1 snapshot (compare-and-swap)", r.Expect)
 	}
 	if len(r.Survivors) != 1 || r.Survivors[0] != held.Fingerprint {
-		t.Errorf("writer Survivors = %v, want the agent-held desired key for the login probe", r.Survivors)
+		t.Errorf("writer Survivors = %v, want the held desired key for the login probe", r.Survivors)
 	}
 	if got := planFor(t, plans, "boom"); got.Outcome != OutcomeFailed || got.OutcomeErr == nil {
 		t.Errorf("boom = %s/%v, want failed with the error retained", got.Outcome, got.OutcomeErr)
@@ -130,7 +130,7 @@ func TestExecuteGuardRecheck(t *testing.T) {
 		t.Run(tt.name, func(t *testing.T) {
 			plans := []ServerPlan{changePlan("s", tt.desired...)}
 			w := &fakeWriter{}
-			Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, AgentFPs: tt.fresh})
+			Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(tt.fresh...)})
 			if tt.wantFail {
 				if plans[0].Outcome != OutcomeFailed || len(w.calls) != 0 {
 					t.Fatalf("outcome = %s, calls = %d — the re-check must block the write", plans[0].Outcome, len(w.calls))
@@ -157,7 +157,7 @@ func TestExecuteInterrupted(t *testing.T) {
 		cancel()
 		plans := []ServerPlan{changePlan("a", held), changePlan("b", held)}
 		w := &fakeWriter{}
-		Execute(ctx, plans, w, ExecOptions{Parallel: 2, AgentFPs: []string{held.Fingerprint}})
+		Execute(ctx, plans, w, ExecOptions{Parallel: 2, Held: agentHeld(held.Fingerprint)})
 		if len(w.calls) != 0 {
 			t.Fatalf("wrote %d servers after cancellation, want 0", len(w.calls))
 		}
@@ -175,7 +175,7 @@ func TestExecuteInterrupted(t *testing.T) {
 		defer cancel()
 		plans := []ServerPlan{changePlan("a", held), changePlan("b", held), changePlan("c", held)}
 		w := &fakeWriter{onCall: func(string) { cancel() }} // Ctrl-C during the first write
-		Execute(ctx, plans, w, ExecOptions{Parallel: 1, AgentFPs: []string{held.Fingerprint}})
+		Execute(ctx, plans, w, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint)})
 		if len(w.calls) != 1 {
 			t.Fatalf("wrote %d servers, want exactly the one already in flight", len(w.calls))
 		}
@@ -192,7 +192,7 @@ func TestExecuteInterrupted(t *testing.T) {
 	t.Run("writer reporting not-started stays pending", func(t *testing.T) {
 		plans := []ServerPlan{changePlan("a", held)}
 		w := &fakeWriter{errs: map[string]error{"a": fmt.Errorf("a: %w", sshwrite.ErrNotStarted)}}
-		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, AgentFPs: []string{held.Fingerprint}})
+		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint)})
 		if plans[0].Outcome != OutcomePending || Interrupted(plans) != 1 {
 			t.Errorf("outcome = %s, want pending + interrupted", plans[0].Outcome)
 		}
@@ -209,7 +209,7 @@ func TestExecuteProbesUnrestrictedSurvivorsFirst(t *testing.T) {
 	plain := testKey(t, 2)
 	plans := []ServerPlan{changePlan("s", restricted, plain)}
 	w := &fakeWriter{}
-	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, AgentFPs: []string{restricted.Fingerprint, plain.Fingerprint}})
+	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(restricted.Fingerprint, plain.Fingerprint)})
 	got := w.calls["s"].Survivors
 	if fmt.Sprint(got) != fmt.Sprint([]string{plain.Fingerprint, restricted.Fingerprint}) {
 		t.Errorf("Survivors = %v, want the unrestricted key first", got)
@@ -225,7 +225,7 @@ func TestExecuteRequestsKeys2Disable(t *testing.T) {
 	k2.AuthorizedKeys2 = true
 	plans := []ServerPlan{plain, k2}
 	w := &fakeWriter{}
-	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, AgentFPs: []string{held.Fingerprint}})
+	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint)})
 	if w.calls["plain"].DisableKeys2 || !w.calls["k2"].DisableKeys2 {
 		t.Errorf("DisableKeys2 = plain:%v k2:%v, want false/true", w.calls["plain"].DisableKeys2, w.calls["k2"].DisableKeys2)
 	}
PATCH
```

- [ ] **Step 2: Write the new failing tests (headless rotation, sources in refusals, the agent-only warning, cert-only operator, re-check across sources, probe order):** `internal/apply/identity_test.go`

```go
package apply

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// rotationCfg: user ci holds only ci_new (seed 5) and is granted web-1;
// web-1 still carries ci_old (seed 4) — the headless self-rotation.
func rotationCfg(t *testing.T) (*config.Config, *fakeReader) {
	t.Helper()
	y := `
users:
  - {name: ci, keys: ["` + testkeys.Line(t, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: ci, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("rotationCfg: %v", err)
	}
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 4) + " ci_old\n"), SessionKeyFP: fp(t, 4)},
	}}
	return cfg, r
}

func TestHeadlessRotationPlan(t *testing.T) {
	cfg, r := rotationCfg(t)
	oldKey, newKey := fileHeld(fp(t, 4), "/k/ci_old"), fileHeld(fp(t, 5), "/k/ci_new")

	t.Run("old and new held: change, probe proves the new key", func(t *testing.T) {
		p := planFor(t, buildPlansHeld(t, cfg, r, []sshconn.HeldKey{oldKey, newKey}), "web-1")
		if p.Class != ClassChange {
			t.Fatalf("Class = %s (%s), want change", p.Class, p.Refusal)
		}
		if !strings.Contains(p.Note, "removes the key this session logged in with; ci remains") {
			t.Errorf("Note = %q, want the rotate note", p.Note)
		}
		if p.AgentOnly != "" {
			t.Errorf("AgentOnly = %q, want none (an --identity key survives)", p.AgentOnly)
		}
		plans := []ServerPlan{p}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: []sshconn.HeldKey{oldKey, newKey}})
		if got := w.calls["web-1"].Survivors; !slices.Equal(got, []string{fp(t, 5)}) {
			t.Errorf("probe Survivors = %v, want ci_new only", got)
		}
	})
	t.Run("only the old key held: refused, naming the fix", func(t *testing.T) {
		p := planFor(t, buildPlansHeld(t, cfg, r, []sshconn.HeldKey{oldKey}), "web-1")
		if p.Class != ClassRefused {
			t.Fatalf("Class = %s, want refused", p.Class)
		}
		for _, want := range []string{
			"none of the 1 keys you hold (identity files + agent) would remain in web-1's authorized_keys",
			"(held: " + fp(t, 4) + " (/k/ci_old))",
			"rotating an --identity key? pass the new key with another --identity",
		} {
			if !strings.Contains(p.Refusal, want) {
				t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, want)
			}
		}
	})
}

func TestRefusalListsSources(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	held := []sshconn.HeldKey{fileHeld(fp(t, 9), "/k/x"), fileHeld(fp(t, 9), "/k/x-again"), agentHeld(fp(t, 8))[0], agentHeld(fp(t, 9))[0]}
	p := planFor(t, buildPlansHeld(t, cfg, r, held), "web-1")
	want := "none of the 2 keys you hold (identity files + agent) would remain in web-1's authorized_keys — applying would lock this session out (held: " +
		fp(t, 9) + " (/k/x), " + fp(t, 8) + " (agent))"
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, want) {
		t.Fatalf("Refusal = %q, want it to contain %q", p.Refusal, want)
	}
}

func TestAgentOnlySurvivorWarning(t *testing.T) {
	cfg := planCfg(t) // op (seed 1) is an operator: desired everywhere
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	tests := []struct {
		name string
		held []sshconn.HeldKey
		want string
	}{
		{"identity given, only an agent key survives", []sshconn.HeldKey{fileHeld(fp(t, 9), "/k/ci"), agentHeld(fp(t, 1))[0]},
			"only " + fp(t, 1) + " (agent) keeps access; none of your --identity keys survives — a run without this agent will be locked out"},
		{"two agent survivors", []sshconn.HeldKey{fileHeld(fp(t, 9), "/k/ci"), agentHeld(fp(t, 1))[0], agentHeld(fp(t, 2))[0]},
			"only " + fp(t, 1) + " (agent), " + fp(t, 2) + " (agent) keep access"},
		{"no --identity: no warning", agentHeld(fp(t, 1)), ""},
		{"an --identity key survives: no warning", []sshconn.HeldKey{fileHeld(fp(t, 2), "/k/alice"), agentHeld(fp(t, 1))[0]}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := planFor(t, buildPlansHeld(t, cfg, r, tt.held), "web-1")
			if p.Class != ClassChange {
				t.Fatalf("Class = %s (%s), want change — the warning never refuses", p.Class, p.Refusal)
			}
			if tt.want == "" && p.AgentOnly != "" || tt.want != "" && !strings.Contains(p.AgentOnly, tt.want) {
				t.Errorf("AgentOnly = %q, want %q", p.AgentOnly, tt.want)
			}
		})
	}
}

func TestCertOnlyOperatorRefused(t *testing.T) {
	// A certificate-only agent lists no plain keys (sshconn excludes
	// certificates from Held), so even an additive write is refused.
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	p := planFor(t, buildPlansHeld(t, cfg, r, nil), "web-1")
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "you hold no plain keys (identity files + agent; certificates do not count)") {
		t.Fatalf("plan = %s/%q, want the no-plain-keys refusal", p.Class, p.Refusal)
	}
}

func TestExecuteRecheckAcrossSources(t *testing.T) {
	file, ag := testKey(t, 1), testKey(t, 2)
	fileKey := fileHeld(file.Fingerprint, "/k/ci")
	t.Run("agent broke during the prompt, a file key survives: written", func(t *testing.T) {
		plans := []ServerPlan{changePlan("s", file, ag)}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: []sshconn.HeldKey{fileKey}})
		if plans[0].Outcome != OutcomeApplied || !slices.Equal(w.calls["s"].Survivors, []string{file.Fingerprint}) {
			t.Fatalf("outcome = %s, survivors = %v; want applied, proven by the file key", plans[0].Outcome, w.calls["s"].Survivors)
		}
	})
	t.Run("the only survivor was an agent key: refused", func(t *testing.T) {
		plans := []ServerPlan{changePlan("s", ag)}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: []sshconn.HeldKey{fileKey}})
		if plans[0].Outcome != OutcomeFailed || len(w.calls) != 0 {
			t.Fatalf("outcome = %s, calls = %d; want the guard re-check to block the write", plans[0].Outcome, len(w.calls))
		}
		if !strings.Contains(plans[0].OutcomeErr.Error(), "is still held (identity files + agent") {
			t.Errorf("err = %v, want the neutral re-check wording", plans[0].OutcomeErr)
		}
	})
}

func TestProbeOrder(t *testing.T) {
	keys := []authkeys.Key{testKey(t, 1), testKey(t, 2), testKey(t, 3), testKey(t, 4)}
	restrictedFile := keys[3]
	restrictedFile.Options = []string{`from="10.0.0.1"`}
	desired := []authkeys.Key{keys[0], keys[1], keys[2], restrictedFile}
	src := map[string]string{
		keys[0].Fingerprint: sshconn.SourceAgent,
		keys[1].Fingerprint: "/k/b",
		keys[2].Fingerprint: "/k/c",
		keys[3].Fingerprint: "/k/d",
	}
	files := []string{keys[1].Fingerprint, keys[2].Fingerprint}
	slices.Sort(files)
	want := append(append(files, keys[0].Fingerprint), keys[3].Fingerprint)
	if got := probeOrder(desired, src); !slices.Equal(got, want) {
		t.Errorf("probeOrder = %v, want unrestricted files (by fingerprint), unrestricted agent, then restricted: %v", got, want)
	}
	// Deterministic whatever the desired order.
	rev := slices.Clone(desired)
	slices.Reverse(rev)
	if got := probeOrder(rev, src); !slices.Equal(got, want) {
		t.Errorf("probeOrder(reversed) = %v, want %v", got, want)
	}
}
```

- [ ] **Step 3: Run**

```bash
go test ./internal/apply
```

Expected: FAIL — build failure: `unknown field Held in struct literal of type ExecOptions`, `p.AgentOnly undefined (type ServerPlan has no field or method AgentOnly)`.

- [ ] **Step 4: Implement:** `internal/apply/plan.go`, `internal/apply/exec.go`

```bash
git apply <<'PATCH'
diff --git a/internal/apply/plan.go b/internal/apply/plan.go
--- a/internal/apply/plan.go
+++ b/internal/apply/plan.go
@@ -91,9 +91,13 @@ type ServerPlan struct {
 	Rewrites  []RewriteRow
 	Normalize Normalize
 
-	Note       string // guard note: session key removed, another survives
-	Warning    string // restrictive-options warning
-	FileAbsent bool   // phase-1 diagnostic, carried into the report
+	Note    string // guard note: session key removed, another survives
+	Warning string // restrictive-options warning
+	// AgentOnly warns that --identity keys were given but only agent keys
+	// survive here: a later run without this agent (the next headless CI
+	// job) would be locked out. Not a refusal — union semantics.
+	AgentOnly  string
+	FileAbsent bool // phase-1 diagnostic, carried into the report
 	// AuthorizedKeys2 carries the phase-1 finding that an unmanaged,
 	// non-empty ~/.ssh/authorized_keys2 exists: sshd may accept keys from it
 	// whatever apply writes, so a change plan also disables it (see
@@ -115,14 +119,15 @@ func (p ServerPlan) DisableKeys2() bool {
 	return p.Class == ClassChange && p.AuthorizedKeys2
 }
 
-// Build computes the plan for every phase-1 result. agentFPs is the set of
-// SHA256 fingerprints the operator's agent held at preflight — the
-// self-lockout guard's ground truth. Pure; the only possible error is a
-// render failure, impossible for a validated manifest (a tool bug, exit 3).
-func Build(cfg *config.Config, results []audit.ServerResult, agentFPs []string) ([]ServerPlan, error) {
+// Build computes the plan for every phase-1 result. held is what the run
+// could authenticate with at preflight (sshconn.Credentials.Held: key files
+// and plain agent keys, with their sources) — the self-lockout guard's
+// ground truth. Pure; the only possible error is a render failure,
+// impossible for a validated manifest (a tool bug, exit 3).
+func Build(cfg *config.Config, results []audit.ServerResult, held []sshconn.HeldKey) ([]ServerPlan, error) {
 	plans := make([]ServerPlan, 0, len(results))
 	for _, r := range results {
-		p, err := planOne(cfg, r, agentFPs)
+		p, err := planOne(cfg, r, held)
 		if err != nil {
 			return nil, err
 		}
@@ -136,7 +141,7 @@ func Build(cfg *config.Config, results []audit.ServerResult, agentFPs []string)
 // only so tests can lower it.
 var maxRender = sshconn.MaxRemoteOutput
 
-func planOne(cfg *config.Config, r audit.ServerResult, agentFPs []string) (ServerPlan, error) {
+func planOne(cfg *config.Config, r audit.ServerResult, held []sshconn.HeldKey) (ServerPlan, error) {
 	p := ServerPlan{
 		Server: r.Server, Outcome: OutcomePending, FileAbsent: r.FileAbsent,
 		AuthorizedKeys2: r.AuthorizedKeys2,
@@ -213,13 +218,13 @@ func planOne(cfg *config.Config, r audit.ServerResult, agentFPs []string) (Serve
 		p.Normalize = normalize(r, entries, explained)
 	}
 
-	v := guardCheck(cfg, r, entries, agentFPs)
+	v := guardCheck(cfg, r, entries, held)
 	if v.Refusal != "" {
 		p.Class = ClassRefused
 		p.Refusal = v.Refusal
 		return p, nil
 	}
-	p.Note, p.Warning = v.Note, v.Warning
+	p.Note, p.Warning, p.AgentOnly = v.Note, v.Warning, v.AgentOnly
 	p.Class = ClassChange
 	return p, nil
 }
@@ -344,53 +349,38 @@ func matchedOrderDiffers(r audit.ServerResult, entries []authkeys.RenderEntry) b
 
 // guardVerdict is the self-lockout guard's decision for one server.
 type guardVerdict struct {
-	Refusal string
-	Note    string
-	Warning string
+	Refusal   string
+	Note      string
+	Warning   string
+	AgentOnly string
 }
 
 // guardCheck enforces the invariant "after the write, this operator can
-// still log in": the rendered desired set must intersect the agent-held
-// keys. Deliberately not the operator spec's literal "never remove the
-// session key" — which key signs a handshake is an accident of agent order
-// and server choice, and the literal rule would randomly block rotate (see
-// the 2026-07-19 spec's guard section; owner-approved refinement). Removing
-// the very key that authenticated is allowed when another agent-held key
-// survives — that is what rotate is — with a loud per-server note.
-func guardCheck(cfg *config.Config, r audit.ServerResult, entries []authkeys.RenderEntry, agentFPs []string) guardVerdict {
-	held := heldSet(agentFPs)
-	// No agent keys means nothing could ever prove this session keeps
+// still log in": the rendered desired set must intersect the keys the run
+// holds (key files + plain agent keys; certificates never count).
+// Deliberately not the operator spec's literal "never remove the session
+// key" — which key signs a handshake is an accident of key order and server
+// choice, and the literal rule would randomly block rotate (see the
+// 2026-07-19 spec's guard section; owner-approved refinement). Removing the
+// very key that authenticated is allowed when another held key survives —
+// that is what rotate is — with a loud per-server note.
+func guardCheck(cfg *config.Config, r audit.ServerResult, entries []authkeys.RenderEntry, held []sshconn.HeldKey) guardVerdict {
+	set := heldSet(held)
+	// Nothing held means nothing could ever prove this session keeps
 	// access (and the post-write login probe would have nothing to offer):
 	// refuse. Unreachable from the CLI, whose preflight requires a
-	// non-empty agent, but phase 2 re-lists the agent after the prompt.
-	if len(held) == 0 {
-		return guardVerdict{Refusal: "the agent holds no keys — refusing to write (nothing could prove this session keeps access)"}
+	// non-empty held set, but phase 2 re-lists after the prompt.
+	if len(set) == 0 {
+		return guardVerdict{Refusal: "you hold no plain keys (identity files + agent; certificates do not count) — refusing to write (nothing could prove this session keeps access)"}
 	}
 
 	keys := make([]authkeys.Key, 0, len(entries))
 	for _, e := range entries {
 		keys = append(keys, e.Key)
 	}
-	surviving := Survivors(keys, held)
-	restrictive := 0
-	for _, k := range surviving {
-		if hasRestrictiveOption(k.Options) {
-			restrictive++
-		}
-	}
+	surviving := Survivors(keys, set)
 	if len(surviving) == 0 {
-		// len(held), not len(agentFPs): an agent can list one key twice and
-		// the message must count distinct keys.
-		refusal := fmt.Sprintf(
-			"none of the %d keys in this agent would remain in %s's authorized_keys — applying would lock this session out. Add one of your keys to the manifest (or mark its user operator: true)",
-			len(held), r.Server.Name)
-		for _, k := range keys {
-			if held[k.Fingerprint] {
-				refusal += " (an agent key stays only as a cert-authority/principals= line, which accepts certificates, not the bare key)"
-				break
-			}
-		}
-		return guardVerdict{Refusal: refusal}
+		return guardVerdict{Refusal: lockoutRefusal(r.Server.Name, keys, held, set)}
 	}
 
 	var v guardVerdict
@@ -400,23 +390,102 @@ func guardCheck(cfg *config.Config, r audit.ServerResult, entries []authkeys.Ren
 				survivorLabel(cfg, surviving[0]))
 		}
 	}
+	restrictive := 0
+	for _, k := range surviving {
+		if hasRestrictiveOption(k.Options) {
+			restrictive++
+		}
+	}
 	if restrictive == len(surviving) {
-		v.Warning = "every remaining agent-held key carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked"
+		v.Warning = "every remaining key you hold carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked"
 	}
+	v.AgentOnly = agentOnlyWarning(surviving, held)
 	return v
 }
 
-// heldSet indexes an agent fingerprint listing.
-func heldSet(agentFPs []string) map[string]bool {
-	held := make(map[string]bool, len(agentFPs))
-	for _, fp := range agentFPs {
-		held[fp] = true
+// lockoutRefusal explains a predicted lockout, listing every held key with
+// its source so a mismatch (the wrong --identity, a stray agent) is
+// visible at a glance.
+func lockoutRefusal(server string, keys []authkeys.Key, held []sshconn.HeldKey, set map[string]bool) string {
+	// len(set), not len(held): one key can be held twice (an --identity
+	// file the agent also holds), and the message counts distinct keys.
+	refusal := fmt.Sprintf(
+		"none of the %d keys you hold (identity files + agent) would remain in %s's authorized_keys — applying would lock this session out (held: %s). Add one of your keys to the manifest (or mark its user operator: true)",
+		len(set), server, heldList(held))
+	for _, k := range keys {
+		if set[k.Fingerprint] {
+			refusal += " (a key you hold stays only as a cert-authority/principals= line, which accepts certificates, not the bare key)"
+			break
+		}
+	}
+	if slices.ContainsFunc(held, isFileKey) {
+		refusal += "; rotating an --identity key? pass the new key with another --identity, so the guard and the post-write login probe can use it"
+	}
+	return refusal
+}
+
+// agentOnlyWarning is set when --identity keys were given (some held key
+// is a file) but every survivor here is an agent key: the guard passes on
+// a credential the next run without this agent will not have.
+func agentOnlyWarning(surviving []authkeys.Key, held []sshconn.HeldKey) string {
+	if !slices.ContainsFunc(held, isFileKey) {
+		return ""
+	}
+	src := sourceMap(held)
+	labels := make([]string, 0, len(surviving))
+	for _, k := range surviving {
+		if src[k.Fingerprint] != sshconn.SourceAgent {
+			return ""
+		}
+		labels = append(labels, k.Fingerprint+" ("+sshconn.SourceAgent+")")
+	}
+	verb := "keeps"
+	if len(labels) > 1 {
+		verb = "keep"
+	}
+	return fmt.Sprintf("only %s %s access; none of your --identity keys survives — a run without this agent will be locked out",
+		strings.Join(labels, ", "), verb)
+}
+
+// isFileKey reports whether k came from an --identity file.
+func isFileKey(k sshconn.HeldKey) bool { return k.Source != sshconn.SourceAgent }
+
+// heldSet indexes the held keys' fingerprints.
+func heldSet(held []sshconn.HeldKey) map[string]bool {
+	set := make(map[string]bool, len(held))
+	for _, k := range held {
+		set[k.Fingerprint] = true
+	}
+	return set
+}
+
+// sourceMap maps each held fingerprint to its first source.
+func sourceMap(held []sshconn.HeldKey) map[string]string {
+	src := make(map[string]string, len(held))
+	for _, k := range held {
+		if _, ok := src[k.Fingerprint]; !ok {
+			src[k.Fingerprint] = k.Source
+		}
+	}
+	return src
+}
+
+// heldList renders the held keys, distinct, in listing order:
+// "SHA256:… (/path), SHA256:… (agent)".
+func heldList(held []sshconn.HeldKey) string {
+	seen := make(map[string]bool, len(held))
+	parts := make([]string, 0, len(held))
+	for _, k := range held {
+		if !seen[k.Fingerprint] {
+			seen[k.Fingerprint] = true
+			parts = append(parts, k.Label())
+		}
 	}
-	return held
+	return strings.Join(parts, ", ")
 }
 
-// Survivors returns the desired keys that keep an agent-held login: held
-// by the agent, and on a line that accepts the bare key — cert-authority
+// Survivors returns the desired keys that keep a login this run can make:
+// held (key file or agent), and on a line that accepts the bare key — cert-authority
 // lines accept only certificates the key signed, and principals= belongs to
 // them. These are the keys the guard counts and the post-write login probe
 // offers.
@@ -479,7 +548,7 @@ func fpInEntries(entries []authkeys.RenderEntry, fp string) bool {
 	return false
 }
 
-// survivorLabel names the agent-held key that keeps this session's access:
+// survivorLabel names the held key that keeps this session's access:
 // the owning user, or the fingerprint for a key the manifest cannot name
 // (unreachable in practice — surviving keys are desired, hence owned).
 func survivorLabel(cfg *config.Config, k authkeys.Key) string {
diff --git a/internal/apply/exec.go b/internal/apply/exec.go
--- a/internal/apply/exec.go
+++ b/internal/apply/exec.go
@@ -1,16 +1,19 @@
 package apply
 
 import (
+	"cmp"
 	"context"
 	"errors"
 	"fmt"
 	"log/slog"
 	"slices"
+	"strings"
 	"sync"
 	"time"
 
 	"github.com/javadh75/SSHepherd/internal/authkeys"
 	"github.com/javadh75/SSHepherd/internal/config"
+	"github.com/javadh75/SSHepherd/internal/sshconn"
 	"github.com/javadh75/SSHepherd/internal/sshwrite"
 )
 
@@ -23,13 +26,13 @@ type Writer interface {
 type ExecOptions struct {
 	Parallel         int           // max concurrent server writes (>= 1)
 	PerServerTimeout time.Duration // bounds each server's connect; a started write always finishes
-	// AgentFPs is the agent's key listing taken AFTER the confirmation
-	// prompt — not the one Build saw: keys can expire (ssh-add -t), be
-	// deleted, or the agent be locked while the prompt waits. The guard is
-	// re-run per plan against it, and its surviving keys are what the
-	// post-write login probe offers.
-	AgentFPs []string
-	Logger   *slog.Logger // optional per-server telemetry; nil discards
+	// Held is the held-key listing (sshconn.Credentials.Held) taken AFTER
+	// the confirmation prompt — not the one Build saw: agent keys can
+	// expire (ssh-add -t), be deleted, or the agent be locked or vanish
+	// while the prompt waits. The guard is re-run per plan against it, and
+	// its surviving keys are what the post-write login probe offers.
+	Held   []sshconn.HeldKey
+	Logger *slog.Logger // optional per-server telemetry; nil discards
 }
 
 func (o ExecOptions) logger() *slog.Logger {
@@ -56,7 +59,7 @@ func Execute(ctx context.Context, plans []ServerPlan, w Writer, opts ExecOptions
 		opts.Parallel = 1
 	}
 	log := opts.logger()
-	held := heldSet(opts.AgentFPs)
+	held := opts.Held
 	sem := make(chan struct{}, opts.Parallel)
 	var wg sync.WaitGroup
 	for i := range plans {
@@ -84,37 +87,18 @@ func Execute(ctx context.Context, plans []ServerPlan, w Writer, opts ExecOptions
 }
 
 // applyOne writes one server. The guard re-check is authoritative: Build
-// refused guard failures against the pre-prompt agent listing, and this
-// re-runs the same check against the fresh one, so no code path reaches a
-// write without the invariant holding right now.
-func applyOne(ctx context.Context, p *ServerPlan, w Writer, held map[string]bool, timeout time.Duration, log *slog.Logger) {
-	surviving := Survivors(p.Desired, held)
+// refused guard failures against the pre-prompt listing, and this re-runs
+// the same check against the fresh one, so no code path reaches a write
+// without the invariant holding right now.
+func applyOne(ctx context.Context, p *ServerPlan, w Writer, held []sshconn.HeldKey, timeout time.Duration, log *slog.Logger) {
+	surviving := Survivors(p.Desired, heldSet(held))
 	if len(surviving) == 0 {
 		p.Outcome = OutcomeFailed
-		p.OutcomeErr = errors.New("guard re-check failed — none of this server's surviving keys is still held by the agent (a key expired or was removed after the plan?) — refusing to write")
+		p.OutcomeErr = errors.New("guard re-check failed — none of this server's surviving keys is still held (identity files + agent; a key expired or was removed after the plan?) — refusing to write")
 		log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, p.OutcomeErr))
 		return
 	}
-	// The post-write probe runs a command, so offer unrestricted survivors
-	// first: sshd authenticates with the first acceptable key, and one
-	// whose line forces command= (deliberately, say) would fail the probe
-	// and roll back a write that a plain survivor proves safe.
-	surviving = slices.Clone(surviving)
-	slices.SortStableFunc(surviving, func(a, b authkeys.Key) int {
-		ra, rb := hasRestrictiveOption(a.Options), hasRestrictiveOption(b.Options)
-		switch {
-		case ra == rb:
-			return 0
-		case rb:
-			return -1
-		default:
-			return 1
-		}
-	})
-	fps := make([]string, 0, len(surviving))
-	for _, k := range surviving {
-		fps = append(fps, k.Fingerprint)
-	}
+	fps := probeOrder(surviving, sourceMap(held))
 	if timeout > 0 {
 		var cancel context.CancelFunc
 		ctx, cancel = context.WithTimeout(ctx, timeout)
@@ -139,6 +123,38 @@ func applyOne(ctx context.Context, p *ServerPlan, w Writer, held map[string]bool
 	log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, err))
 }
 
+// probeOrder orders the survivors the post-write probe offers,
+// deterministically across runs: unrestricted first — the probe runs a
+// command, sshd authenticates with the first acceptable key, and one whose
+// line forces command= (deliberately, say) would fail the probe and roll
+// back a write a plain survivor proves safe — then key files before agent
+// keys (so when an --identity key survives, the probe proves THAT key: the
+// one the next headless run will have), then fingerprint.
+func probeOrder(surviving []authkeys.Key, src map[string]string) []string {
+	surviving = slices.Clone(surviving)
+	rank := func(k authkeys.Key) int {
+		r := 0
+		if hasRestrictiveOption(k.Options) {
+			r += 2
+		}
+		if src[k.Fingerprint] == sshconn.SourceAgent {
+			r++
+		}
+		return r
+	}
+	slices.SortFunc(surviving, func(a, b authkeys.Key) int {
+		if c := cmp.Compare(rank(a), rank(b)); c != 0 {
+			return c
+		}
+		return strings.Compare(a.Fingerprint, b.Fingerprint)
+	})
+	fps := make([]string, 0, len(surviving))
+	for _, k := range surviving {
+		fps = append(fps, k.Fingerprint)
+	}
+	return fps
+}
+
 // Interrupted counts the change plans phase 2 never started because the
 // run was interrupted.
 func Interrupted(plans []ServerPlan) int {
PATCH
```

- [ ] **Step 5: Bridge the command (replaced in C1):** `cmd/sshepherd/apply.go`

```bash
git apply <<'PATCH'
diff --git a/cmd/sshepherd/apply.go b/cmd/sshepherd/apply.go
--- a/cmd/sshepherd/apply.go
+++ b/cmd/sshepherd/apply.go
@@ -104,7 +104,7 @@ func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
 			if err := interrupted(cmd.Context()); err != nil {
 				return err // nothing written: phase 2 never started
 			}
-			plans, err := apply.Build(cfg, results, pre.agentFPs)
+			plans, err := apply.Build(cfg, results, agentHeld(pre.agentFPs))
 			if err != nil {
 				return fmt.Errorf("plan: %w", err) // wrapcheck: wrap at package boundary
 			}
@@ -176,7 +176,7 @@ func writePhase(ctx context.Context, log *slog.Logger, pre preflight, preferKeys
 	apply.Execute(ctx, plans, writer, apply.ExecOptions{
 		Parallel:         parallel,
 		PerServerTimeout: perServerTimeout,
-		AgentFPs:         freshFPs,
+		Held:             agentHeld(freshFPs),
 		Logger:           log,
 	})
 	if n := apply.Interrupted(plans); n > 0 {
@@ -184,6 +184,16 @@ func writePhase(ctx context.Context, log *slog.Logger, pre preflight, preferKeys
 	}
 }
 
+// agentHeld labels an agent fingerprint listing as held agent keys —
+// a bridge until the --identity wiring replaces it with Credentials.Held.
+func agentHeld(fps []string) []sshconn.HeldKey {
+	held := make([]sshconn.HeldKey, 0, len(fps))
+	for _, fp := range fps {
+		held = append(held, sshconn.HeldKey{Fingerprint: fp, Source: sshconn.SourceAgent})
+	}
+	return held
+}
+
 // preflight is what apply's pre-dial checks hand to both phases.
 type preflight struct {
 	khPath   string
PATCH
```

- [ ] **Step 6: Run**

```bash
go test -race ./internal/apply ./cmd/... && go build ./...
```

Expected: PASS.

- [ ] **Step 7: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/apply/plan.go internal/apply/exec.go internal/apply/plan_test.go internal/apply/exec_test.go internal/apply/identity_test.go cmd/sshepherd/apply.go
git commit -m "$(cat <<'EOF'
feat(apply): guard and probe over held keys with sources; agent-only-survivor warning

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task W2 (Group W · stage 2): Plan report: the agent-only warning, neutral goldens

**Files:**
- Create: `internal/apply/identity_report_test.go`
- Create: `internal/apply/testdata/plan_identity.golden`
- Modify: `internal/apply/report.go`
- Modify: `internal/apply/report_test.go`
- Modify: `internal/apply/testdata/summary_interrupted.golden`
- Modify: `README.md`

The plan report renders `ServerPlan.AgentOnly` as a yellow `warning:` line after
the restrictive-options warning. Goldens are **regenerated, never hand-edited**;
the README's summary sample is re-copied from the regenerated golden in the same
commit (project rule: sample output must be real).

- [ ] **Step 1: Write the failing golden test:** `internal/apply/identity_report_test.go`

```go
package apply

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// identityPlans: the identity-era plan surface — web-1 refused with every
// held key and its source listed; web-2 written, but only an agent key
// survives there while an --identity key was given.
func identityPlans(t *testing.T) (*config.Config, []ServerPlan) {
	t.Helper()
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: ci, keys: ["` + testkeys.Line(t, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: ci, servers: [web-1]}
  - {user: alice, servers: [web-2]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("identityPlans: %v", err)
	}
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 4) + " ci_old\n")},
		"web-2": {FileAbsent: true},
	}}
	held := []sshconn.HeldKey{fileHeld(fp(t, 4), "/home/ci/.ssh/ci_old"), agentHeld(fp(t, 2))[0]}
	return cfg, buildPlansHeld(t, cfg, r, held)
}

func TestRenderPlanIdentityGolden(t *testing.T) {
	cfg, plans := identityPlans(t)
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		fmt.Sprintf("(held: %s (/home/ci/.ssh/ci_old), %s (agent))", fp(t, 4), fp(t, 2)),
		"warning: only " + fp(t, 2) + " (agent) keeps access; none of your --identity keys survives",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	checkGolden(t, "plan_identity.golden", buf.Bytes())
}
```

- [ ] **Step 2: Neutral wording in the existing report tests (the lockout literal mirrors `sshwrite.LockoutError`, reworded in W3):** `internal/apply/report_test.go`

```bash
git apply <<'PATCH'
diff --git a/internal/apply/report_test.go b/internal/apply/report_test.go
--- a/internal/apply/report_test.go
+++ b/internal/apply/report_test.go
@@ -205,14 +205,14 @@ func TestRenderGuardNoteAndWarning(t *testing.T) {
 		Server: config.Server{Name: "w", User: "u", Host: "h", Port: 22},
 		Class:  ClassChange, Outcome: OutcomePending,
 		Note:    "removes the key this session logged in with; op remains",
-		Warning: "every remaining agent-held key carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked",
+		Warning: "every remaining key you hold carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked",
 	}}
 	var buf bytes.Buffer
 	Render(&buf, mixedCfg(t), plans, RenderOptions{})
 	if !strings.Contains(buf.String(), "note: removes the key this session logged in with") {
 		t.Errorf("report lacks the rotate note:\n%s", buf.String())
 	}
-	if !strings.Contains(buf.String(), "warning: every remaining agent-held key") {
+	if !strings.Contains(buf.String(), "warning: every remaining key you hold") {
 		t.Errorf("report lacks the restrictive-options warning:\n%s", buf.String())
 	}
 }
@@ -305,7 +305,7 @@ func TestRenderSummaryInterruptedGolden(t *testing.T) {
 		{Server: config.Server{Name: "a"}, Class: ClassChange, Outcome: OutcomeApplied},
 		{Server: config.Server{Name: "b"}, Class: ClassChange, Outcome: OutcomePending, OutcomeErr: errInterrupted},
 		{Server: config.Server{Name: "c"}, Class: ClassChange, Outcome: OutcomeFailed,
-			OutcomeErr: errors.New("lockout prevented — restored previous file (post-write login offering only the surviving agent keys failed: ssh: unable to authenticate)")},
+			OutcomeErr: errors.New("lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate)")},
 	}
 	var buf bytes.Buffer
 	RenderSummary(&buf, plans, RenderOptions{})
PATCH
```

- [ ] **Step 3: Run**

```bash
go test ./internal/apply -run "Render"
```

Expected: FAIL — `report lacks "warning: only SHA256:… (agent) keeps access…"` and `read golden (run with -update first)` for `plan_identity.golden`, and `summary_interrupted.golden` differs.

- [ ] **Step 4: Implement:** `internal/apply/report.go`

```bash
git apply <<'PATCH'
diff --git a/internal/apply/report.go b/internal/apply/report.go
--- a/internal/apply/report.go
+++ b/internal/apply/report.go
@@ -126,6 +126,9 @@ func renderChange(w io.Writer, cfg *config.Config, p ServerPlan, pal palette) {
 	if p.Warning != "" {
 		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), p.Warning)
 	}
+	if p.AgentOnly != "" {
+		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), p.AgentOnly)
+	}
 	for _, rw := range p.Rewrites {
 		if len(rw.Loosens) == 0 {
 			continue
PATCH
```

- [ ] **Step 5: Regenerate the two goldens, then **read** them:**

```bash
go test ./internal/apply -run "TestRenderPlanIdentityGolden|TestRenderSummaryInterruptedGolden" -update && git status --short internal/apply/testdata
```

Expected: ` M internal/apply/testdata/summary_interrupted.golden` and `?? internal/apply/testdata/plan_identity.golden`.

- [ ] **Step 6: Check the golden.** `plan_identity.golden` must be exactly:

```text
web-1 (deploy@10.0.0.1:22)  REFUSED: none of the 2 keys you hold (identity files + agent) would remain in web-1's authorized_keys — applying would lock this session out (held: SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o (/home/ci/.ssh/ci_old), SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 (agent)). Add one of your keys to the manifest (or mark its user operator: true); rotating an --identity key? pass the new key with another --identity, so the guard and the post-write login probe can use it

web-2 (deploy@10.0.0.2:22)
  +  alice  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  add (authorized, missing)
  note: the audited file is absent yet login succeeded — sshd may consult
        another key source; creating the file is purely additive
  warning: only SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 (agent) keeps access; none of your --identity keys survives — a run without this agent will be locked out
  → 1 keys desired · 1 add · 0 remove · 0 rewrite

```

- [ ] **Step 7: Check the golden.** `summary_interrupted.golden` must be exactly:

```text
a: applied · verified
b: NOT STARTED: interrupted before the write started
c: FAILED: lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate)
Summary: 1/3 servers converged (1 applied) · 1 pending · 1 failed  → exit 1
```

- [ ] **Step 8: Re-copy the summary sample into the README (`### sshepherd apply`, the summary block):** `README.md`

````bash
git apply <<'PATCH'
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -553,7 +553,7 @@ After the writes, a summary reports each server's outcome:
 ```console
 a: applied · verified
 b: NOT STARTED: interrupted before the write started
-c: FAILED: lockout prevented — restored previous file (post-write login offering only the surviving agent keys failed: ssh: unable to authenticate)
+c: FAILED: lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate)
 Summary: 1/3 servers converged (1 applied) · 1 pending · 1 failed  → exit 1
 ```
 
PATCH
````

- [ ] **Step 9: Run**

```bash
go test -race ./internal/apply
```

Expected: PASS.

- [ ] **Step 10: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/apply/report.go internal/apply/report_test.go internal/apply/identity_report_test.go internal/apply/testdata README.md
git commit -m "$(cat <<'EOF'
feat(apply): render the agent-only-survivor warning; neutral goldens

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task W3 (Group W · stage 2): `sshwrite`: neutral probe/lockout wording, a key-file survivor proven with no agent

**Files:**
- Modify: `internal/sshwrite/sshwrite.go`
- Modify: `internal/sshwrite/sshwrite_test.go`
- Modify: `internal/sshwrite/integration_test.go`

No API change: `FleetWriter` already dials through `Dialer`, which now carries
`Creds`. The probe offers `Request.Survivors` (file keys first, from W1) through
the same `Credentials`. Wording becomes source-neutral; the hermetic tests move
to `Creds` and gain a write whose survivor is a key file with no agent at all.

- [ ] **Step 1: Update the tests:** `internal/sshwrite/sshwrite_test.go`, `internal/sshwrite/integration_test.go`

```bash
git apply <<'PATCH'
diff --git a/internal/sshwrite/sshwrite_test.go b/internal/sshwrite/sshwrite_test.go
--- a/internal/sshwrite/sshwrite_test.go
+++ b/internal/sshwrite/sshwrite_test.go
@@ -18,6 +18,7 @@ import (
 	"github.com/javadh75/SSHepherd/internal/audit"
 	"github.com/javadh75/SSHepherd/internal/authkeys"
 	"github.com/javadh75/SSHepherd/internal/config"
+	"github.com/javadh75/SSHepherd/internal/keyfile"
 	"github.com/javadh75/SSHepherd/internal/sshconn"
 	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
 )
@@ -756,7 +757,7 @@ func TestApplyRequiresSurvivors(t *testing.T) {
 	r := req("x\n")
 	r.Survivors = nil
 	err := seamedWriter(s, c).Apply(context.Background(), config.Server{Name: "w"}, r)
-	if err == nil || !strings.Contains(err.Error(), "no surviving agent key") {
+	if err == nil || !strings.Contains(err.Error(), "no surviving key you hold") {
 		t.Fatalf("err = %v, want the no-survivor refusal", err)
 	}
 	if len(c.opts) != 0 {
@@ -855,7 +856,7 @@ func hermetic(t *testing.T, home string, authorized []any, agentKeys ...any) (*F
 	})
 	d := &sshconn.Dialer{
 		KnownHostsPath: sshtest.KnownHostsFile(t, s.KnownHostsLine(hostKey.PublicKey())),
-		AgentSock:      sshtest.Agent(t, agentKeys...),
+		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, agentKeys...)},
 		DialTimeout:    5 * time.Second,
 	}
 	return &FleetWriter{Dialer: d}, config.Server{Name: "h1", Host: s.Host, Port: s.Port, User: "deploy"}
@@ -908,6 +909,24 @@ func TestApplyHermeticRealConnection(t *testing.T) {
 		}
 		assertNoResidue(t, target)
 	})
+	t.Run("a key-file survivor is proven with no agent at all", func(t *testing.T) {
+		home := t.TempDir()
+		// The server accepts op (the write login) and ci (the survivor);
+		// the run holds both as key files and has no agent.
+		ci := sshtest.Key(3)
+		w, srv := hermetic(t, home, []any{op, ci})
+		w.Dialer.Creds = &sshconn.Credentials{Files: []keyfile.Identity{
+			sshtest.Identity(t, "/k/op", op), sshtest.Identity(t, "/k/ci", ci),
+		}}
+		target := filepath.Join(home, ".ssh", "authorized_keys")
+		r := Request{Content: []byte(managed), Expect: Snapshot{Absent: true}, Survivors: []string{sshtest.Fingerprint(t, ci)}}
+		if err := w.Apply(ctxTimeout(t), srv, r); err != nil {
+			t.Fatalf("Apply with key files only: %v", err)
+		}
+		if got := readFile(t, target); got != managed {
+			t.Errorf("file = %q, want the render", got)
+		}
+	})
 	t.Run("changed since plan is refused over the wire", func(t *testing.T) {
 		home := t.TempDir()
 		w, srv := hermetic(t, home, []any{op}, op)
diff --git a/internal/sshwrite/integration_test.go b/internal/sshwrite/integration_test.go
--- a/internal/sshwrite/integration_test.go
+++ b/internal/sshwrite/integration_test.go
@@ -36,7 +36,7 @@ func itDialer(t *testing.T) (*sshconn.Dialer, string, int) {
 	}
 	return &sshconn.Dialer{
 		KnownHostsPath: os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS"),
-		AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
+		Creds:          &sshconn.Credentials{AgentSock: os.Getenv("SSH_AUTH_SOCK")},
 		DialTimeout:    10 * time.Second,
 	}, host, port
 }
@@ -89,7 +89,7 @@ func itRendered(t *testing.T) []byte {
 	return []byte(authkeys.ManagedHeader + "\n" + itPub(t) + "\n")
 }
 
-// itSurvivors lists the agent key's fingerprint — the key the post-write
+// itSurvivors lists the harness key's fingerprint — the key the post-write
 // login probe offers.
 func itSurvivors(t *testing.T) []string {
 	t.Helper()
PATCH
```

- [ ] **Step 2: Run**

```bash
go test ./internal/sshwrite
```

Expected: FAIL — `TestApplyRequiresSurvivors: err = write on w: no surviving agent key to prove the post-write login with — refusing to write, want the no-survivor refusal`.

- [ ] **Step 3: Implement:** `internal/sshwrite/sshwrite.go`

```bash
git apply <<'PATCH'
diff --git a/internal/sshwrite/sshwrite.go b/internal/sshwrite/sshwrite.go
--- a/internal/sshwrite/sshwrite.go
+++ b/internal/sshwrite/sshwrite.go
@@ -88,8 +88,9 @@ func SnapshotOf(absent bool, content []byte) Snapshot {
 }
 
 // Request is one server's write: the rendered bytes, the phase-1 snapshot
-// they replace, and the SHA256 fingerprints of the agent keys that must
-// still log in afterwards (the post-write probe offers exactly these).
+// they replace, and the SHA256 fingerprints of the held keys (key files or
+// agent) that must still log in afterwards (the post-write probe offers
+// exactly these, in this order).
 type Request struct {
 	Content   []byte
 	Expect    Snapshot
@@ -291,9 +292,9 @@ func (e *LockedError) Error() string {
 	return fmt.Sprintf("another apply is in progress on %s (lock directory %s%s; remove it only if no apply is running)", e.Path, e.Path, lockSuffix)
 }
 
-// LockoutError reports a write that verified but whose surviving agent keys
-// could not log in on a fresh connection; the previous file was restored
-// unless Restore says otherwise.
+// LockoutError reports a write that verified but whose surviving held keys
+// (key files or agent) could not log in on a fresh connection; the
+// previous file was restored unless Restore says otherwise.
 type LockoutError struct {
 	Path    string
 	Probe   error // why the post-write login failed
@@ -302,9 +303,9 @@ type LockoutError struct {
 
 func (e *LockoutError) Error() string {
 	if e.Restore == nil {
-		return fmt.Sprintf("lockout prevented — restored previous file (post-write login offering only the surviving agent keys failed: %v)", e.Probe)
+		return fmt.Sprintf("lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: %v)", e.Probe)
 	}
-	return fmt.Sprintf("post-write login offering only the surviving agent keys failed (%v) AND restoring the previous file failed (%v) — the previous version is at %s%s; repair it over a session that is still open", e.Probe, e.Restore, e.Path, bakSuffix)
+	return fmt.Sprintf("post-write login offering only the surviving keys you hold failed (%v) AND restoring the previous file failed (%v) — the previous version is at %s%s; repair it over a session that is still open", e.Probe, e.Restore, e.Path, bakSuffix)
 }
 
 func (e *LockoutError) Unwrap() []error { return []error{e.Probe, e.Restore} }
@@ -365,7 +366,7 @@ func (w *FleetWriter) log() *slog.Logger {
 // sanitized-error path: remote text never reaches a terminal raw.
 func (w *FleetWriter) Apply(ctx context.Context, srv config.Server, req Request) error {
 	if len(req.Survivors) == 0 {
-		return fmt.Errorf("write on %s: no surviving agent key to prove the post-write login with — refusing to write", srv.Name)
+		return fmt.Errorf("write on %s: no surviving key you hold to prove the post-write login with — refusing to write", srv.Name)
 	}
 	conn, err := w.connectForWrite(ctx, srv)
 	if err != nil {
@@ -410,7 +411,7 @@ func (w *FleetWriter) Apply(ctx context.Context, srv config.Server, req Request)
 	}
 
 	// Stage 3: prove the lockout guard's prediction — a fresh login offering
-	// only the surviving agent keys, running probeCmd. Every write is probed,
+	// only the surviving held keys (key files first), running probeCmd. Every write is probed,
 	// not only those that drop the session key: an options rewrite on the
 	// survivor (from= fails the handshake, command= the probe command), or
 	// sshd rejecting the survivor's algorithm, locks out just as surely, and
PATCH
```

- [ ] **Step 4: Run**

```bash
go test -race ./internal/sshwrite && go vet -tags integration ./internal/sshwrite
```

Expected: PASS.

- [ ] **Step 5: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/sshwrite/sshwrite.go internal/sshwrite/sshwrite_test.go internal/sshwrite/integration_test.go
git commit -m "$(cat <<'EOF'
feat(sshwrite): source-neutral probe and lockout wording; key-file survivor probe

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


### Group C — CLI, docs, integration (stage 3)


#### Task C1 (Group C · stage 3): CLI: the three flags, order of operations, one `Credentials` per run, README

**Files:**
- Create: `cmd/sshepherd/identity.go`
- Create: `cmd/sshepherd/identity_test.go`
- Create: `cmd/sshepherd/help_readme_test.go`
- Modify: `cmd/sshepherd/audit.go`
- Modify: `cmd/sshepherd/adopt.go`
- Modify: `cmd/sshepherd/apply.go`
- Modify: `cmd/sshepherd/audit_test.go`
- Modify: `cmd/sshepherd/adopt_test.go`
- Modify: `cmd/sshepherd/apply_test.go`
- Modify: `README.md`
- Modify: `go.mod`

Per command (`audit`, `adopt`, `apply`; not root-persistent; `import` unchanged):
`--identity PATH` (repeatable), `--identity-passphrase-file FILE`,
`--identity-passphrase KEY=FILE` (repeatable). Backticked usage words become the
`--help` varnames, and a new test compares `--help` with the README tables.

Order of operations in every connecting command:

1. flag validation (`validateFlags`: `--parallel` + `keyfile.Resolve`) — exit 3;
2. manifest load/validation; `apply --server` selection;
3. empty-fleet / zero-target early return — before any key is read (never prompts);
4. `known_hosts` preflight;
5. `keyfile.Load` (may prompt; Ctrl-C ⇒ the interrupted path);
6. `CheckCredentials` (`needHeld` for apply), then the fan-out.

One `Credentials` per run is shared by the reader, the writer and the probe;
`writePhase` re-lists `Held` after the prompt and uses whatever it returns (a
degraded file-only set is never replaced by `nil`). The agent preflight now runs
after the `known_hosts` preflight, so the three `…NoAgent` tests pass an empty
`--known-hosts` (on a CI box without `~/.ssh/known_hosts` they would otherwise fail
at the known_hosts step). Docs land in the same commit (project rule).

- [ ] **Step 1: Write the failing command tests (flag validation, first-`=` split, order of operations, `--yes` still prompts, interrupt at the prompt, hermetic audit/adopt/apply with key files and no agent):** `cmd/sshepherd/identity_test.go`

```go
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// emptyKnownHosts writes an empty (valid) known_hosts and returns its path.
func emptyKnownHosts(t *testing.T) string {
	t.Helper()
	return sshtest.KnownHostsFile(t)
}

// scriptedPrompter is the cmd-level prompter fake.
type scriptedPrompter struct {
	avail    bool
	answers  []string
	prompts  int
	onPrompt func()
}

func (p *scriptedPrompter) Available() bool { return p.avail }

func (p *scriptedPrompter) ReadPassphrase(ctx context.Context, _ string) ([]byte, error) {
	p.prompts++
	if p.onPrompt != nil {
		p.onPrompt()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(p.answers) == 0 {
		return nil, errors.New("no answer scripted")
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return []byte(a), nil
}

// usePrompter swaps the passphrase prompter for the test.
func usePrompter(t *testing.T, p keyfile.Prompter) {
	t.Helper()
	saved := newPrompter
	newPrompter = func() keyfile.Prompter { return p }
	t.Cleanup(func() { newPrompter = saved })
}

// neverPrompt fails the test if anything prompts.
func neverPrompt(t *testing.T) *scriptedPrompter {
	t.Helper()
	p := &scriptedPrompter{avail: true}
	usePrompter(t, p)
	t.Cleanup(func() {
		if p.prompts != 0 {
			t.Errorf("prompted %d times, want never", p.prompts)
		}
	})
	return p
}

// encryptedKey writes an encrypted OpenSSH key (passphrase "pw") and returns its path.
func encryptedKey(t *testing.T, seed byte) string {
	t.Helper()
	return sshtest.WriteKeyFile(t, t.TempDir(), "id_enc", sshtest.Key(seed), []byte("pw"))
}

// keyFleet runs one in-process server that accepts only key's public half
// (no agent anywhere: SSH_AUTH_SOCK is unset), with HOME=home for its
// shell, and returns the manifest granting that key, a known_hosts, and
// the server.
func keyFleet(t *testing.T, home string, seed byte) (cfg, kh string, srv *sshtest.Server) {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	user := sshtest.Key(seed)
	host := sshtest.Signer(t, sshtest.Key(40))
	srv = sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		Handle:     sshtest.ShellHandler(home),
	})
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, user).PublicKey())))
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = writeConfig(t, fmt.Sprintf(`
users:
  - {name: ci, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: ci, servers: [web-1]}
`, line, srv.Port))
	return cfg, sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey())), srv
}

func TestIdentityFlagValidation(t *testing.T) {
	// Validation is step 1: it fails before the (missing) manifest loads.
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"passphrase file without --identity", []string{"--identity-passphrase-file", "/pw"}, "passphrase flags need --identity"},
		{"mapping without --identity", []string{"--identity-passphrase", "/k=/pw"}, "passphrase flags need --identity"},
		{"unmatched KEY lists the cleaned paths", []string{"--identity", "/keys/./a", "--identity-passphrase", "/keys/b=/pw"},
			"--identity-passphrase: /keys/b matches no --identity (--identity paths: /keys/a)"},
		{"same KEY twice", []string{"--identity", "/k", "--identity-passphrase", "/k=/a", "--identity-passphrase", "/k=/b"}, "/k is given twice"},
		{"malformed mapping", []string{"--identity", "/k", "--identity-passphrase", "/k"}, "want KEY=FILE"},
	}
	for _, cmd := range []string{"audit", "adopt", "apply"} {
		for _, tt := range tests {
			t.Run(cmd+"/"+tt.name, func(t *testing.T) {
				var out, errBuf bytes.Buffer
				args := append([]string{cmd, "--config", "no-such-file.yaml"}, tt.args...)
				if code := run(args, &out, &errBuf); code != 3 {
					t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
				}
				if !strings.Contains(errBuf.String(), tt.want) || strings.Contains(errBuf.String(), "load manifest") {
					t.Errorf("stderr = %q, want the flag error %q before any manifest load", errBuf.String(), tt.want)
				}
			})
		}
	}
}

func TestIdentityFirstEqualsSplit(t *testing.T) {
	// KEY=FILE splits at the first "=": the FILE may contain "=", the KEY
	// may not (documented) — here the mapping names a file "pw=x".
	t.Setenv("SSH_AUTH_SOCK", "")
	key := encryptedKey(t, 7)
	pwFile := filepath.Join(t.TempDir(), "pw=x")
	if err := os.WriteFile(pwFile, []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	neverPrompt(t)
	path := writeConfig(t, `
servers:
  - {name: web-1, host: 127.0.0.1, port: `+fmt.Sprint(closedPort(t))+`, user: deploy}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path, "--known-hosts", emptyKnownHosts(t),
		"--identity", key, "--identity-passphrase", key + "=" + pwFile}, &out, &errBuf)
	if code != 1 { // unlocked, then the server is unreachable: drift, not a tool error
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "identity loaded") {
		t.Errorf("stderr = %q, want the identity-loaded line", errBuf.String())
	}
}

func TestIdentityOrderOfOperations(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Run("empty fleet never reads a key or prompts", func(t *testing.T) {
		key := encryptedKey(t, 7)
		path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
		for _, cmd := range []string{"audit", "adopt", "apply"} {
			neverPrompt(t)
			var out, errBuf bytes.Buffer
			if code := run([]string{cmd, "--config", path, "--identity", key}, &out, &errBuf); code != 0 {
				t.Fatalf("%s exit = %d, want 0 (stderr: %s)", cmd, code, errBuf.String())
			}
		}
	})
	t.Run("a missing key file is never opened when nothing is targeted", func(t *testing.T) {
		neverPrompt(t)
		path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--config", path, "--identity", "/nonexistent/key"}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
		}
	})
	t.Run("a manifest or --server error fails before any key is read", func(t *testing.T) {
		key := encryptedKey(t, 7)
		bad := writeConfig(t, "servers: [")
		for _, cmd := range []string{"audit", "adopt", "apply"} {
			neverPrompt(t)
			var out, errBuf bytes.Buffer
			code := run([]string{cmd, "--config", bad, "--known-hosts", emptyKnownHosts(t), "--identity", key}, &out, &errBuf)
			if code != 3 || !strings.Contains(errBuf.String(), "load manifest") {
				t.Fatalf("%s exit = %d, stderr = %q; want the manifest error before any prompt", cmd, code, errBuf.String())
			}
		}
		neverPrompt(t)
		path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
		var out, errBuf bytes.Buffer
		code := run([]string{"apply", "--config", path, "--known-hosts", emptyKnownHosts(t), "--server", "nope", "--identity", key}, &out, &errBuf)
		if code != 3 || !strings.Contains(errBuf.String(), `--server: unknown server "nope"`) {
			t.Fatalf("exit = %d, stderr = %q; want the --server error before any prompt", code, errBuf.String())
		}
	})
	t.Run("bad --known-hosts fails before any prompt", func(t *testing.T) {
		key := encryptedKey(t, 7)
		path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
		for _, cmd := range []string{"audit", "adopt", "apply"} {
			neverPrompt(t)
			var out, errBuf bytes.Buffer
			code := run([]string{cmd, "--config", path, "--known-hosts", "/nonexistent/kh", "--identity", key}, &out, &errBuf)
			if code != 3 || !strings.Contains(errBuf.String(), "known_hosts preflight") {
				t.Fatalf("%s exit = %d, stderr = %q; want the known_hosts error first", cmd, code, errBuf.String())
			}
		}
	})
	t.Run("headless encrypted key with no passphrase source", func(t *testing.T) {
		usePrompter(t, &scriptedPrompter{avail: false})
		key := encryptedKey(t, 7)
		path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
		var out, errBuf bytes.Buffer
		code := run([]string{"audit", "--config", path, "--known-hosts", emptyKnownHosts(t), "--identity", key}, &out, &errBuf)
		if code != 3 || !strings.Contains(errBuf.String(), "is encrypted and no passphrase source is available") {
			t.Fatalf("exit = %d, stderr = %q; want the no-source exit 3", code, errBuf.String())
		}
	})
	t.Run("--yes still allows the passphrase prompt", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), []byte("pw"))
		p := &scriptedPrompter{avail: true, answers: []string{"pw"}}
		usePrompter(t, p)
		var out, errBuf bytes.Buffer
		code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf)
		if code != 0 || p.prompts != 1 {
			t.Fatalf("exit = %d, prompts = %d (stderr: %s)\n%s", code, p.prompts, errBuf.String(), out.String())
		}
	})
}

func TestIdentityInterruptedAtPrompt(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	home := shortHome(t)
	cfg, kh, srv := keyFleet(t, home, 3)
	key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), []byte("pw"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	usePrompter(t, &scriptedPrompter{avail: true, onPrompt: cancel})
	var out, errBuf bytes.Buffer
	code := runContext(ctx, []string{"audit", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf)
	if code != 3 || !strings.Contains(errBuf.String(), "interrupted") {
		t.Fatalf("exit = %d, stderr = %q; want the interrupted exit 3", code, errBuf.String())
	}
	if len(srv.Attempts()) != 0 {
		t.Error("an interrupted prompt still connected")
	}
}

// TestIdentityHermetic drives audit, adopt and apply end to end with a key
// file and no agent at all.
func TestIdentityHermetic(t *testing.T) {
	t.Run("audit --identity, unencrypted key", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), nil)
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d (stderr: %s)\n%s", code, errBuf.String(), out.String())
		}
	})
	t.Run("adopt --identity", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), nil)
		var out, errBuf bytes.Buffer
		if code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
		}
	})
	t.Run("apply --identity, encrypted key, passphrase file", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		dir := t.TempDir()
		key := sshtest.WriteKeyFile(t, dir, "id", sshtest.Key(3), []byte("s3cret"))
		pw := filepath.Join(dir, "pw")
		if err := os.WriteFile(pw, []byte("s3cret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		neverPrompt(t)
		var out, errBuf bytes.Buffer
		code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh, "--identity", key, "--identity-passphrase-file", pw}, &out, &errBuf)
		if code != 0 || !strings.Contains(out.String(), "applied · verified") {
			t.Fatalf("exit = %d (stderr: %s)\n%s", code, errBuf.String(), out.String())
		}
		if strings.Contains(errBuf.String(), "s3cret") || strings.Contains(out.String(), "s3cret") {
			t.Error("the passphrase reached the output")
		}
	})
	t.Run("apply refuses a loose key file", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), nil)
		if err := os.Chmod(key, 0o644); err != nil {
			t.Fatal(err)
		}
		var out, errBuf bytes.Buffer
		code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf)
		if code != 3 || !strings.Contains(errBuf.String(), "are too open (chmod 600") {
			t.Fatalf("exit = %d, stderr = %q; want the permission refusal", code, errBuf.String())
		}
	})
}
```

- [ ] **Step 2: Write the `--help` ↔ README test:** `cmd/sshepherd/help_readme_test.go`

```go
package main

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// readmeFlagCells returns the first-column cells of the flag table under
// README's "### `sshepherd <name>`" heading, e.g. "`--identity PATH`".
func readmeFlagCells(t *testing.T, readme, name string) []string {
	t.Helper()
	_, section, ok := strings.Cut(readme, "### `sshepherd "+name+"`")
	if !ok {
		t.Fatalf("README has no `sshepherd %s` section", name)
	}
	if i := strings.Index(section, "\n#"); i >= 0 {
		section = section[:i]
	}
	var cells []string
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `-") {
			continue
		}
		cells = append(cells, strings.TrimSpace(strings.Split(line, "|")[1]))
	}
	return cells
}

// helpFlagCell renders a flag as the README's first column spells it: the
// shorthand, the long name, and the --help varname when the usage names
// one with backticks (cobra's UnquoteUsage).
func helpFlagCell(f *pflag.Flag) string {
	cell := "--" + f.Name
	if f.Shorthand != "" {
		cell = "-" + f.Shorthand + ", " + cell
	}
	if strings.Contains(f.Usage, "`") {
		varname, _ := pflag.UnquoteUsage(f)
		cell += " " + varname
	}
	return "`" + cell + "`"
}

// TestHelpMatchesREADMETables: every local flag of audit/adopt/apply
// appears in its README table spelled as --help renders it (varnames
// included), and the tables list nothing --help does not.
func TestHelpMatchesREADMETables(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	var out, errBuf bytes.Buffer
	root := newRootCmd(&app{}, &out, &errBuf)
	for _, name := range []string{"audit", "adopt", "apply"} {
		t.Run(name, func(t *testing.T) {
			var cmd *cobra.Command
			for _, c := range root.Commands() {
				if c.Name() == name {
					cmd = c
				}
			}
			if cmd == nil {
				t.Fatalf("no %s command", name)
			}
			var want []string
			cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
				if f.Name != "help" && !f.Hidden {
					want = append(want, helpFlagCell(f))
				}
			})
			got := readmeFlagCells(t, string(raw), name)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("README table for %s = %v\n--help flags        = %v", name, got, want)
			}
		})
	}
}

// TestHelpShowsIdentityVarnames pins the rendered --help lines.
func TestHelpShowsIdentityVarnames(t *testing.T) {
	for _, name := range []string{"audit", "adopt", "apply"} {
		var out, errBuf bytes.Buffer
		if code := run([]string{name, "--help"}, &out, &errBuf); code != 0 {
			t.Fatalf("%s --help exit = %d", name, code)
		}
		for _, want := range []string{"--identity PATH", "--identity-passphrase-file FILE", "--identity-passphrase KEY=FILE"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s --help lacks %q:\n%s", name, want, out.String())
			}
		}
	}
}
```

- [ ] **Step 3: Give the three no-agent tests a valid empty `--known-hosts`:** `cmd/sshepherd/audit_test.go`, `cmd/sshepherd/adopt_test.go`, `cmd/sshepherd/apply_test.go`

```bash
git apply <<'PATCH'
diff --git a/cmd/sshepherd/audit_test.go b/cmd/sshepherd/audit_test.go
--- a/cmd/sshepherd/audit_test.go
+++ b/cmd/sshepherd/audit_test.go
@@ -137,7 +137,7 @@ access:
   - {user: alice, servers: [web-1]}
 `)
 	var out, errBuf bytes.Buffer
-	code := run([]string{"audit", "--config", path}, &out, &errBuf)
+	code := run([]string{"audit", "--config", path, "--known-hosts", emptyKnownHosts(t)}, &out, &errBuf)
 	if code != 3 {
 		t.Fatalf("exit = %d, want 3", code)
 	}
diff --git a/cmd/sshepherd/adopt_test.go b/cmd/sshepherd/adopt_test.go
--- a/cmd/sshepherd/adopt_test.go
+++ b/cmd/sshepherd/adopt_test.go
@@ -326,7 +326,7 @@ servers:
   - {name: web-1, host: 10.0.0.1, user: deploy}
 `)
 	var out, errBuf bytes.Buffer
-	if code := run([]string{"adopt", "--config", path}, &out, &errBuf); code != 3 {
+	if code := run([]string{"adopt", "--config", path, "--known-hosts", emptyKnownHosts(t)}, &out, &errBuf); code != 3 {
 		t.Fatalf("exit = %d, want 3", code)
 	}
 	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
diff --git a/cmd/sshepherd/apply_test.go b/cmd/sshepherd/apply_test.go
--- a/cmd/sshepherd/apply_test.go
+++ b/cmd/sshepherd/apply_test.go
@@ -72,7 +72,7 @@ func TestApplyNoAgent(t *testing.T) {
 	t.Setenv("SSH_AUTH_SOCK", "")
 	path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
 	var out, errBuf bytes.Buffer
-	if code := run([]string{"apply", "--config", path}, &out, &errBuf); code != 3 {
+	if code := run([]string{"apply", "--config", path, "--known-hosts", emptyKnownHosts(t)}, &out, &errBuf); code != 3 {
 		t.Fatalf("exit = %d, want 3", code)
 	}
 	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
PATCH
```

- [ ] **Step 4: Run**

```bash
go test ./cmd/sshepherd
```

Expected: FAIL — build failure: `undefined: newPrompter`.

- [ ] **Step 5: Implement the shared flag/credential plumbing:** `cmd/sshepherd/identity.go`

```go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshread"
)

// identityFlags are the key-file flags audit, adopt and apply declare
// (per command, like --known-hosts; import makes no connection).
type identityFlags struct {
	paths       []string
	defaultFile string
	perKey      []string
}

// register declares the three flags on cmd. The backticked words are the
// --help varnames (PATH, FILE, KEY=FILE) the README tables mirror.
func (f *identityFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringArrayVar(&f.paths, "identity", nil,
		"private key `PATH` to authenticate with, in addition to ssh-agent (repeatable; ~/ expands from $HOME)")
	cmd.Flags().StringVar(&f.defaultFile, "identity-passphrase-file", "",
		"`FILE` holding the default passphrase for any encrypted --identity key")
	cmd.Flags().StringArrayVar(&f.perKey, "identity-passphrase", nil,
		"`KEY=FILE`: passphrase file for one --identity key (repeatable; split at the first =)")
}

// identities is a run's validated key-file inputs: step 1 of every
// connecting command's order of operations. Nothing is read yet.
type identities struct {
	specs []keyfile.Spec
	pp    keyfile.Passphrases
}

// resolve validates the flags lexically (keyfile.Resolve) — exit 3 before
// the manifest is even loaded.
func (f *identityFlags) resolve() (identities, error) {
	home, _ := os.UserHomeDir() // "" makes Resolve refuse a ~/ path with a clear error
	cwd, err := os.Getwd()
	if err != nil {
		return identities{}, fmt.Errorf("--identity: working directory: %w", err)
	}
	specs, pp, err := keyfile.Resolve(f.paths, f.defaultFile, f.perKey, home, cwd)
	if err != nil {
		return identities{}, fmt.Errorf("invalid flags: %w", err)
	}
	return identities{specs: specs, pp: pp}, nil
}

// validateFlags is step 1 of every connecting command's order of
// operations — --parallel and the identity flags — before the manifest is
// even loaded.
func validateFlags(parallel int, idf *identityFlags) (identities, error) {
	if parallel < 1 {
		return identities{}, fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
	}
	return idf.resolve()
}

// newPrompter builds the passphrase prompter; a test seam (the real one
// needs a controlling terminal).
var newPrompter = func() keyfile.Prompter { return keyfile.NewTTY() }

// credentials loads the key files (it may prompt on /dev/tty) and builds
// the run's one Credentials, shared by every reader, writer and probe:
// step 5, after the manifest, the empty-fleet return and the known_hosts
// preflight, so a typo there never costs the operator a passphrase. A
// Ctrl-C at the prompt is the interrupted path (exit 3, nothing
// connected).
func (ids identities) credentials(ctx context.Context, log *slog.Logger) (*sshconn.Credentials, error) {
	files, err := keyfile.Load(ctx, ids.specs, ids.pp, newPrompter(), keyfile.OSFS{}, log)
	if err != nil {
		if ctx.Err() != nil {
			return nil, interrupted(ctx)
		}
		// errors.Join puts one key per line; the log handler would fold
		// them into spaces, so separate them visibly.
		return nil, fmt.Errorf("identity: %s", strings.ReplaceAll(err.Error(), "\n", "; "))
	}
	return &sshconn.Credentials{Files: files, AgentSock: os.Getenv("SSH_AUTH_SOCK"), Log: log}, nil
}

// checkCredentials is step 6: something must be able to authenticate
// (needHeld: apply's guard needs plain keys). Without --identity the
// prefix and message are the agent preflight's, as before key files.
func checkCredentials(ctx context.Context, creds *sshconn.Credentials, needHeld bool) error {
	err := sshread.CheckCredentials(ctx, creds, needHeld)
	switch {
	case err == nil:
		return nil
	case len(creds.Files) == 0:
		return fmt.Errorf("agent preflight: %w", err)
	default:
		return fmt.Errorf("credentials preflight: %w", err)
	}
}
```

- [ ] **Step 6: Wire the three commands:** `cmd/sshepherd/audit.go`, `cmd/sshepherd/adopt.go`, `cmd/sshepherd/apply.go`

```bash
git apply <<'PATCH'
diff --git a/cmd/sshepherd/audit.go b/cmd/sshepherd/audit.go
--- a/cmd/sshepherd/audit.go
+++ b/cmd/sshepherd/audit.go
@@ -3,7 +3,6 @@ package main
 import (
 	"fmt"
 	"io"
-	"os"
 	"time"
 
 	"github.com/spf13/cobra"
@@ -34,14 +33,16 @@ func newAuditCmd(a *app, stdout io.Writer) *cobra.Command {
 		parallel   int
 		jsonOut    bool
 		comments   bool
+		idf        identityFlags
 	)
 	cmd := &cobra.Command{
 		Use:   "audit",
 		Short: "Report drift between the manifest and each server's authorized_keys (read-only)",
 		Args:  cobra.NoArgs,
 		RunE: func(cmd *cobra.Command, _ []string) error {
-			if parallel < 1 {
-				return fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
+			ids, err := validateFlags(parallel, &idf)
+			if err != nil {
+				return err
 			}
 			log := a.logger
 			cfg, err := config.Load(cfgPath)
@@ -64,9 +65,6 @@ func newAuditCmd(a *app, stdout io.Writer) *cobra.Command {
 			if len(cfg.Servers) == 0 {
 				return render(nil)
 			}
-			if err := sshread.CheckAgent(cmd.Context(), os.Getenv("SSH_AUTH_SOCK")); err != nil {
-				return fmt.Errorf("agent preflight: %w", err)
-			}
 			khPath, err := expandHome(knownHosts)
 			if err != nil {
 				return err
@@ -78,13 +76,20 @@ func newAuditCmd(a *app, stdout io.Writer) *cobra.Command {
 			if err != nil {
 				return fmt.Errorf("known_hosts preflight: %w", err)
 			}
+			creds, err := ids.credentials(cmd.Context(), log)
+			if err != nil {
+				return err
+			}
+			if err := checkCredentials(cmd.Context(), creds, false); err != nil {
+				return err
+			}
 			reader := &sshread.Client{
 				KnownHostsPath: khPath,
 				KnownHosts:     kh,
-				AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
+				Creds:          creds,
 				DialTimeout:    dialTimeout,
-				// Offer the keys granted on each server first, so a
-				// many-key agent cannot exhaust sshd's MaxAuthTries.
+				// Offer the keys granted on each server first, so many held
+				// keys cannot exhaust sshd's MaxAuthTries.
 				PreferKeys: func(srv config.Server) []string { return audit.GrantedFingerprints(cfg, srv.Name) },
 				Log:        log,
 			}
@@ -111,6 +116,7 @@ func newAuditCmd(a *app, stdout io.Writer) *cobra.Command {
 	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the report as machine-readable JSON on stdout")
 	cmd.Flags().BoolVar(&comments, "comments", false,
 		"also report comment drift on present keys (informational; never affects the exit code)")
+	idf.register(cmd)
 	return cmd
 }
 
diff --git a/cmd/sshepherd/adopt.go b/cmd/sshepherd/adopt.go
--- a/cmd/sshepherd/adopt.go
+++ b/cmd/sshepherd/adopt.go
@@ -113,16 +113,14 @@ func renderMergedManifest(mf *manifest.File, raw []byte, plan adopt.Plan, unread
 	return out, nil
 }
 
-// readFleet runs the agent/known_hosts preflights and reads every server's
-// authorized_keys via the same SSH path as audit. An empty fleet needs no
-// agent and returns nil results.
-func readFleet(ctx context.Context, log *slog.Logger, cfg *config.Config, knownHosts string, parallel int) ([]audit.ServerResult, error) {
+// readFleet runs the known_hosts and credentials preflights and reads every
+// server's authorized_keys via the same SSH path as audit. An empty fleet
+// needs no credentials (never reads a key, never prompts) and returns nil
+// results.
+func readFleet(ctx context.Context, log *slog.Logger, cfg *config.Config, knownHosts string, parallel int, ids identities) ([]audit.ServerResult, error) {
 	if len(cfg.Servers) == 0 {
 		return nil, nil
 	}
-	if err := sshread.CheckAgent(ctx, os.Getenv("SSH_AUTH_SOCK")); err != nil {
-		return nil, fmt.Errorf("agent preflight: %w", err)
-	}
 	khPath, err := expandHome(knownHosts)
 	if err != nil {
 		return nil, err
@@ -134,14 +132,21 @@ func readFleet(ctx context.Context, log *slog.Logger, cfg *config.Config, knownH
 	if err != nil {
 		return nil, fmt.Errorf("known_hosts preflight: %w", err)
 	}
+	creds, err := ids.credentials(ctx, log)
+	if err != nil {
+		return nil, err
+	}
+	if err := checkCredentials(ctx, creds, false); err != nil {
+		return nil, err
+	}
 	reader := &sshread.Client{
 		KnownHostsPath: khPath,
 		KnownHosts:     kh,
-		AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
+		Creds:          creds,
 		DialTimeout:    dialTimeout,
 		Log:            log,
-		// Offer granted keys (operators first) before the rest of the
-		// agent, so many-key agents do not trip sshd's MaxAuthTries.
+		// Offer granted keys (operators first) before the rest, so many
+		// held keys do not trip sshd's MaxAuthTries.
 		PreferKeys: func(srv config.Server) []string { return audit.GrantedFingerprints(cfg, srv.Name) },
 	}
 	results := audit.Run(ctx, cfg, reader, audit.Options{
@@ -226,6 +231,7 @@ func newAdoptCmd(a *app, stdout io.Writer) *cobra.Command {
 		force      bool
 		partial    bool
 		merge      bool
+		idf        identityFlags
 	)
 	cmd := &cobra.Command{
 		Use:   "adopt",
@@ -239,8 +245,9 @@ func newAdoptCmd(a *app, stdout io.Writer) *cobra.Command {
 			"manifest. Any unreadable server aborts the run unless --partial is set.",
 		Args: cobra.NoArgs,
 		RunE: func(cmd *cobra.Command, _ []string) error {
-			if parallel < 1 {
-				return fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
+			ids, err := validateFlags(parallel, &idf)
+			if err != nil {
+				return err
 			}
 			log := a.logger
 			var (
@@ -251,7 +258,6 @@ func newAdoptCmd(a *app, stdout io.Writer) *cobra.Command {
 			if merge {
 				// --merge needs the original bytes: they are the output when
 				// there is nothing to adopt, and the append base otherwise.
-				var err error
 				raw, err = os.ReadFile(cfgPath) // #nosec G304 -- path is the user's own --config flag
 				if err != nil {
 					return fmt.Errorf("load manifest: %w", err)
@@ -262,7 +268,6 @@ func newAdoptCmd(a *app, stdout io.Writer) *cobra.Command {
 				}
 				cfg = mf.Config()
 			} else {
-				var err error
 				cfg, err = config.Load(cfgPath)
 				if err != nil {
 					return fmt.Errorf("load manifest: %w", err) // wrapcheck: wrap at package boundary
@@ -276,7 +281,7 @@ func newAdoptCmd(a *app, stdout io.Writer) *cobra.Command {
 				log.Info(fmt.Sprintf("reading %d servers (parallelism %d)…", len(cfg.Servers), parallel))
 			}
 			start := time.Now()
-			results, err := readFleet(cmd.Context(), log, cfg, knownHosts, parallel)
+			results, err := readFleet(cmd.Context(), log, cfg, knownHosts, parallel, ids)
 			if err != nil {
 				return err
 			}
@@ -316,5 +321,6 @@ func newAdoptCmd(a *app, stdout io.Writer) *cobra.Command {
 	cmd.Flags().BoolVar(&force, "force", false, "allow --output to overwrite an existing file")
 	cmd.Flags().BoolVar(&partial, "partial", false, "proceed even if some servers cannot be read (their access will be missing from the output)")
 	cmd.Flags().BoolVar(&merge, "merge", false, "preserve the manifest text (comments intact) and append the additions instead of regenerating")
+	idf.register(cmd)
 	return cmd
 }
diff --git a/cmd/sshepherd/apply.go b/cmd/sshepherd/apply.go
--- a/cmd/sshepherd/apply.go
+++ b/cmd/sshepherd/apply.go
@@ -30,6 +30,7 @@ func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
 		serverSel  []string
 		dryRun     bool
 		yes        bool
+		idf        identityFlags
 	)
 	cmd := &cobra.Command{
 		Use:   "apply",
@@ -45,14 +46,17 @@ func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
 			"one-time .sshepherd.orig of the pre-SSHepherd file, and a read-back\n" +
 			"verify. A server whose file changed after the plan was read is refused\n" +
 			"(re-run apply). A self-lockout guard refuses any write that would leave\n" +
-			"no agent-held key on a server; after each write a fresh login offering\n" +
-			"only the surviving keys must succeed, or the previous file is restored.\n" +
+			"no key you hold (identity files + agent) on a server; after each write a\n" +
+			"fresh login offering only the surviving keys must succeed, or the\n" +
+			"previous file is restored. --yes skips only the confirmation: an\n" +
+			"encrypted --identity key may still prompt for its passphrase.\n" +
 			"Ctrl-C stops new writes; started ones finish. --dry-run previews the\n" +
 			"plan and never writes.",
 		Args: cobra.NoArgs,
 		RunE: func(cmd *cobra.Command, _ []string) error {
-			if parallel < 1 {
-				return fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
+			ids, err := validateFlags(parallel, &idf)
+			if err != nil {
+				return err
 			}
 			log := a.logger
 			cfg, err := config.Load(cfgPath)
@@ -74,12 +78,12 @@ func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
 				return nil
 			}
 
-			pre, err := applyPreflight(cmd.Context(), knownHosts)
+			pre, err := applyPreflight(cmd.Context(), log, knownHosts, ids)
 			if err != nil {
 				return err
 			}
-			// Offer each server's granted keys first (operators first), so a
-			// many-key agent cannot exhaust sshd's MaxAuthTries before the
+			// Offer each server's granted keys first (operators first), so
+			// many held keys cannot exhaust sshd's MaxAuthTries before the
 			// key that matters is tried.
 			preferKeys := func(s config.Server) []string { return audit.GrantedFingerprints(cfg, s.Name) }
 
@@ -87,7 +91,7 @@ func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
 			reader := &sshread.Client{
 				KnownHostsPath: pre.khPath,
 				KnownHosts:     pre.kh,
-				AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
+				Creds:          pre.creds,
 				DialTimeout:    dialTimeout,
 				PreferKeys:     preferKeys,
 				Log:            log,
@@ -104,7 +108,7 @@ func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
 			if err := interrupted(cmd.Context()); err != nil {
 				return err // nothing written: phase 2 never started
 			}
-			plans, err := apply.Build(cfg, results, agentHeld(pre.agentFPs))
+			plans, err := apply.Build(cfg, results, pre.held)
 			if err != nil {
 				return fmt.Errorf("plan: %w", err) // wrapcheck: wrap at package boundary
 			}
@@ -148,25 +152,29 @@ func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
 	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "plan and report only; never write")
 	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt (automation)")
 	cmd.MarkFlagsMutuallyExclusive("dry-run", "yes")
+	idf.register(cmd)
 	return cmd
 }
 
 // writePhase runs phase 2 over the drifted servers. The prompt can wait
-// indefinitely: keys may expire (ssh-add -t) or be removed meanwhile, so the
-// agent is re-listed first and the per-server guard re-check and the
-// post-write login probe use what it holds now. A failed listing leaves it
-// empty, which fails every write through the guard rather than guessing.
+// indefinitely: agent keys may expire (ssh-add -t) or be removed, or the
+// agent vanish, meanwhile — so the held keys are re-listed first and the
+// per-server guard re-check and the post-write login probe use what is
+// held now. A degraded listing (agent gone, key files left) is used as is,
+// never replaced; only a failed listing (no key files, agent gone) leaves
+// it empty, which fails every write through the guard rather than
+// guessing.
 func writePhase(ctx context.Context, log *slog.Logger, pre preflight, preferKeys func(config.Server) []string, plans []apply.ServerPlan, parallel int) {
-	freshFPs, err := sshconn.AgentFingerprints(ctx, os.Getenv("SSH_AUTH_SOCK"))
+	fresh, err := pre.creds.Held(ctx)
 	if err != nil {
-		log.Error(fmt.Sprintf("re-listing agent keys after confirmation: %v — no server will be written", err))
-		freshFPs = nil
+		log.Error(fmt.Sprintf("re-listing the keys you hold after confirmation: %v — no server will be written", err))
+		fresh = nil
 	}
 	writer := &sshwrite.FleetWriter{
 		Dialer: &sshconn.Dialer{
 			KnownHostsPath: pre.khPath,
 			KnownHosts:     pre.kh,
-			AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
+			Creds:          pre.creds,
 			DialTimeout:    dialTimeout,
 			PreferKeys:     preferKeys,
 			Log:            log,
@@ -176,7 +184,7 @@ func writePhase(ctx context.Context, log *slog.Logger, pre preflight, preferKeys
 	apply.Execute(ctx, plans, writer, apply.ExecOptions{
 		Parallel:         parallel,
 		PerServerTimeout: perServerTimeout,
-		Held:             agentHeld(freshFPs),
+		Held:             fresh,
 		Logger:           log,
 	})
 	if n := apply.Interrupted(plans); n > 0 {
@@ -184,43 +192,37 @@ func writePhase(ctx context.Context, log *slog.Logger, pre preflight, preferKeys
 	}
 }
 
-// agentHeld labels an agent fingerprint listing as held agent keys —
-// a bridge until the --identity wiring replaces it with Credentials.Held.
-func agentHeld(fps []string) []sshconn.HeldKey {
-	held := make([]sshconn.HeldKey, 0, len(fps))
-	for _, fp := range fps {
-		held = append(held, sshconn.HeldKey{Fingerprint: fp, Source: sshconn.SourceAgent})
-	}
-	return held
-}
-
 // preflight is what apply's pre-dial checks hand to both phases.
 type preflight struct {
-	khPath   string
-	kh       *sshconn.KnownHosts // parsed once, shared by the reader and the writer
-	agentFPs []string            // the plan-time guard's ground truth
+	khPath string
+	kh     *sshconn.KnownHosts  // parsed once, shared by the reader and the writer
+	creds  *sshconn.Credentials // the run's one credential source: reader, writer, probe
+	held   []sshconn.HeldKey    // the plan-time guard's ground truth
 }
 
-// applyPreflight runs apply's pre-dial checks: audit's agent and
-// known_hosts preflights, plus the agent-fingerprint capture that is the
-// self-lockout guard's ground truth. known_hosts is parsed exactly once per
-// run; both phases share the snapshot.
-func applyPreflight(ctx context.Context, knownHosts string) (preflight, error) {
+// applyPreflight runs apply's pre-dial checks in the order of operations:
+// known_hosts (parsed exactly once per run; both phases share the
+// snapshot), then the key files (may prompt), then the credentials check —
+// apply needs plain held keys — and the held-key capture that is the
+// self-lockout guard's ground truth.
+func applyPreflight(ctx context.Context, log *slog.Logger, knownHosts string, ids identities) (preflight, error) {
 	var pre preflight
-	if err := sshread.CheckAgent(ctx, os.Getenv("SSH_AUTH_SOCK")); err != nil {
-		return pre, fmt.Errorf("agent preflight: %w", err)
-	}
-	fps, err := sshconn.AgentFingerprints(ctx, os.Getenv("SSH_AUTH_SOCK"))
-	if err != nil {
-		return pre, fmt.Errorf("agent preflight: %w", err)
-	}
-	pre.agentFPs = fps
+	var err error
 	if pre.khPath, err = expandHome(knownHosts); err != nil {
 		return pre, err
 	}
 	if pre.kh, err = sshread.LoadKnownHosts(pre.khPath); err != nil {
 		return pre, fmt.Errorf("known_hosts preflight: %w", err)
 	}
+	if pre.creds, err = ids.credentials(ctx, log); err != nil {
+		return pre, err
+	}
+	if err := checkCredentials(ctx, pre.creds, true); err != nil {
+		return pre, err
+	}
+	if pre.held, err = pre.creds.Held(ctx); err != nil {
+		return pre, fmt.Errorf("agent preflight: %w", err)
+	}
 	return pre, nil
 }
 
PATCH
```

- [ ] **Step 7: The README test imports `pflag` directly; tidy promotes it:**

```bash
go mod tidy && git diff --stat go.mod
```

Expected: `go.mod | 2 +-` — `github.com/spf13/pflag v1.0.9` moves to the direct `require` block.

- [ ] **Step 8: Run**

```bash
go test ./cmd/sshepherd
```

Expected: FAIL — only `TestHelpMatchesREADMETables` (`README table for audit = [...] --help flags = [... --identity PATH ...]`).

- [ ] **Step 9: Document: requirements, the three flag rows per table, the new **Authentication** section (sources and union, certificates, passphrase resolution, prompting/headless, order of operations, key-file rules, formats, the agent-only warning and a sourced refusal — both copied from `plan_identity.golden` — headless rotation, CI recipes, container usage), exit code 3, the safety-model wording and the layout:** `README.md`

````bash
git apply <<'PATCH'
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -78,7 +78,8 @@ $ docker run --rm sshepherd:dev --version
 ```
 
 To run against a fleet from the container, mount your manifest and `known_hosts`
-and forward your SSH agent:
+and forward your SSH agent (or mount a key file and use `--identity` — see
+[Container usage](#container-usage)):
 
 ```console
 $ docker run --rm \
@@ -92,9 +93,10 @@ $ docker run --rm \
 
 SSHepherd deliberately has a narrow, strict connection posture:
 
-- **A running SSH agent** holding the key(s) that log into the fleet
-  (`SSH_AUTH_SOCK` must be set). Agent-only authentication — SSHepherd never reads,
-  asks for, or stores a private key.
+- **Credentials:** an SSH agent (`SSH_AUTH_SOCK`) holding the key(s) that log into
+  the fleet, and/or private key files passed with `--identity` (headless runs: CI,
+  cron, containers). Without `--identity` the agent is required, exactly as before;
+  see [Authentication](#authentication).
 - **A populated `known_hosts`** (default `~/.ssh/known_hosts`). Host-key checking is
   **strict, with no TOFU**: an unknown host is an error, not a prompt.
 - **Direct reachability.** Every server is dialed directly. Hosts reachable only
@@ -317,6 +319,9 @@ Report drift between the manifest and each server's `authorized_keys`. Read-only
 | `--parallel` | `32` | Max concurrent server audits |
 | `--json` | off | Machine-readable report on stdout (schema 1) |
 | `--comments` | off | Also report comment drift on present keys (informational) |
+| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
+| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
+| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |
 
 **Drift classes.** Besides missing, unauthorized and unparseable entries, three
 security-relevant classes make a server non-compliant (exit 1), always on:
@@ -506,6 +511,9 @@ they were found. The input file is never modified.
 | `--force` | off | Allow `--output` to overwrite an existing file |
 | `--partial` | off | Proceed even if some servers cannot be read |
 | `--merge` | off | Append discoveries to the existing manifest, comments intact |
+| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
+| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
+| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |
 
 Any unreadable server aborts the run unless `--partial` is set — adopting a
 half-read fleet would silently drop real access.
@@ -531,8 +539,13 @@ rendered desired state.
 | `--server` | all | Restrict the run to this server (repeatable; canary rollout) |
 | `--dry-run` | off | Plan and report only; never write |
 | `--yes` | off | Skip the confirmation prompt (automation) |
+| `--identity PATH` | none | Private key file to authenticate with, in addition to `ssh-agent` (repeatable); `~/` expands from `$HOME` |
+| `--identity-passphrase-file FILE` | none | Default passphrase file for any encrypted `--identity` key |
+| `--identity-passphrase KEY=FILE` | none | Passphrase file for one `--identity` key (repeatable); split at the **first** `=` — a key path containing `=` is unsupported |
 
-`--dry-run` and `--yes` are mutually exclusive.
+`--dry-run` and `--yes` are mutually exclusive. `--yes` skips only the `[y/N]`
+confirmation: an encrypted `--identity` key may still prompt for its passphrase on
+the terminal (see [Authentication](#authentication)).
 
 Rewrite rows show what changes on a key line, and a rewrite that **drops a
 restrictive option** (`from=`, `command=`, `restrict`, `no-*`, `expiry-time=`,
@@ -566,6 +579,190 @@ and exits `3`. In `audit` and `adopt`, an interrupt at any point closes in-fligh
 sessions and exits `3` without rendering a report or writing a manifest (servers cut
 short are never passed off as unreachable).
 
+## Authentication
+
+`audit`, `adopt` and `apply` authenticate with the union of two sources, like
+`ssh -i`:
+
+1. **`--identity` key files**, offered first, in flag order;
+2. **the SSH agent** at `SSH_AUTH_SOCK`, in agent order — plain keys, then
+   certificates.
+
+A key in both is offered once. With at least one `--identity`, a missing, empty or
+broken agent is not an error (a set-but-broken `SSH_AUTH_SOCK` logs one warning and
+the run continues with the key files). With no `--identity`, the agent is required
+and behaves exactly as before. Each loaded key is logged once:
+`identity loaded path=KEY fp=SHA256:…`.
+
+**Certificates are offered, never counted.** Agent-held certificates still log in,
+but they never count as a key you hold for `apply`'s self-lockout guard or its
+post-write login probe (a certificate logs in through a `cert-authority` line the
+guard cannot prove survives). A `KEY-cert.pub` next to an `--identity` key is not
+loaded (`certificate KEY-cert.pub not used; authenticating with the plain key`).
+`apply` with only certificates is refused before anything is read.
+
+**Passphrases.** An encrypted key is unlocked by the first source that applies:
+
+1. its `--identity-passphrase KEY=FILE` mapping — a wrong passphrase there is an
+   error (exit 3), never a fall-through;
+2. `--identity-passphrase-file FILE` — a shared default: if it does not unlock this
+   key, resolution continues;
+3. a prompt on the controlling terminal (`/dev/tty`, three attempts, like `ssh`);
+4. otherwise exit 3: `KEY is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase KEY=FILE)`.
+
+There is **no passphrase environment variable and no passphrase flag value** (both
+leak through `/proc/<pid>/environ`, `ps`, shell history or core dumps). Files, secret
+mounts, `/dev/fd/N` and `<(...)` work. Every passphrase file is read exactly once per
+run (a pipe can be read only once), exactly one trailing newline (`\n` or `\r\n`) is
+stripped, and a file that is then empty is an error, never an empty passphrase.
+Passphrases, passphrase-file contents and key bytes never appear in a log line, an
+error or a report. They are wiped from memory when loading finishes — best effort
+only: Go cannot guarantee no copies remain, and bcrypt intermediates are not zeroed.
+
+**Prompting and headless runs.** A prompt is shown only when `/dev/tty` opens,
+stdin is a terminal, and SSHepherd is the terminal's foreground process. Anything
+else — `docker run -t`, a pty-allocating CI executor, `sshepherd … &` — is headless
+and fails fast with the no-passphrase-source error instead of hanging. The prompt
+and its `waiting for passphrase for KEY on the terminal` line go to the terminal,
+never stdout (`audit --json` stays clean), and appear even under `-q`. `--yes` does
+not disable prompting. Ctrl-C at the prompt restores the terminal and exits `3`
+without connecting anywhere.
+
+**Order of operations.** Flags are validated first, then the manifest; an empty
+fleet (or no targeted server) returns before any key file is read; then
+`known_hosts` is loaded; only then are key files read (and maybe prompted for). A
+manifest typo or a bad `--known-hosts` therefore never costs you a passphrase.
+
+**Key-file rules.**
+
+- **Permissions**, as OpenSSH checks them: a regular file you own must not be
+  readable by group or others — `permissions 0644 for FILE are too open (chmod 600 FILE)`.
+  A regular file owned by another user (e.g. a root-owned secret mount) is accepted.
+  Pipes, sockets and character devices (`/dev/fd/N`, `<(...)`, `/dev/stdin`) are
+  exempt: their mode bits do not describe a file at rest. The same rule applies to
+  passphrase files.
+- **Unreadable** files name the mismatch:
+  `cannot read key file FILE as uid N (owner M, mode 0600) — see README 'Container usage'`.
+- **Size caps:** key files 64 KiB, passphrase files 4 KiB.
+- **Paths are matched lexically:** `~/` expands from `$HOME`, relative paths resolve
+  against the working directory, then `filepath.Clean` — no symlink resolution, case
+  sensitive. An `--identity-passphrase` KEY must name an `--identity` exactly as
+  cleaned (the error lists the cleaned paths); the same KEY twice is an error; a
+  path given twice to `--identity` is used once. Two paths holding the same key keep
+  the first (an info line names the dropped one).
+- **The fingerprint is always the decrypted key's.** A sibling `KEY.pub` (legacy PEM)
+  or the embedded public key (OpenSSH format) only labels the prompt; if it
+  disagrees with the private key, the key is refused.
+
+**Supported formats.** OpenSSH (`-----BEGIN OPENSSH PRIVATE KEY-----`), unencrypted
+or `aes256-ctr`/`aes256-cbc` with bcrypt (at most 2048 rounds), and legacy PEM RSA /
+EC (optionally encrypted) and unencrypted PKCS#8. Refused before any prompt, with a
+conversion hint:
+
+| Format | Hint |
+| ------ | ---- |
+| PuTTY `.ppk` | `puttygen KEY -O private-openssh -o NEWFILE` |
+| encrypted PKCS#8, other ciphers (e.g. `chacha20-poly1305`, `aes256-gcm`), multi-key files | `ssh-keygen -p -f KEY` |
+| bcrypt rounds above 2048 | `ssh-keygen -p -a 100 -f KEY` |
+| DSA (`ssh-dss`) | generate a new key (`ssh-dss` is disabled by default in OpenSSH) |
+| hardware keys (`sk-ssh-ed25519@openssh.com`, `sk-ecdsa-…`) | use them through `ssh-agent` |
+
+**The agent-only-survivor warning.** With `--identity` given, a server whose
+surviving keys are all agent keys gets a plan warning — the run passes the guard on
+a credential the next agent-less run will not have:
+
+```console
+web-2 (deploy@10.0.0.2:22)
+  +  alice  SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4  ssh-ed25519  add (authorized, missing)
+  note: the audited file is absent yet login succeeded — sshd may consult
+        another key source; creating the file is purely additive
+  warning: only SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 (agent) keeps access; none of your --identity keys survives — a run without this agent will be locked out
+  → 1 keys desired · 1 add · 0 remove · 0 rewrite
+```
+
+Guard refusals list every key you hold with its source:
+
+```console
+web-1 (deploy@10.0.0.1:22)  REFUSED: none of the 2 keys you hold (identity files + agent) would remain in web-1's authorized_keys — applying would lock this session out (held: SHA256:vxu9sT7+WkqIPG3kOwohja2DmYBjKw903FLEcS+Xb6o (/home/ci/.ssh/ci_old), SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4 (agent)). Add one of your keys to the manifest (or mark its user operator: true); rotating an --identity key? pass the new key with another --identity, so the guard and the post-write login probe can use it
+```
+
+**Headless key rotation.** Replace `ci_old` with `ci_new` in the manifest, then run
+with both keys: the write logs in with the old key, the guard sees the new key
+survive, and the post-write probe (which offers surviving key files first) proves
+the new key logs in. A later run needs only the new key.
+
+```console
+$ sshepherd apply --yes --identity ~/.ssh/ci_old --identity ~/.ssh/ci_new
+```
+
+### CI recipes
+
+The shell recipes unset `SSH_AUTH_SOCK` and the container recipes mount no agent, so
+a stray or forwarded agent can never satisfy the guard for a credential CI lacks.
+
+**GitHub Actions** (bash — `<(...)` needs bash or zsh, not POSIX `sh`; `env -u PW`
+keeps the secret out of SSHepherd's own environment):
+
+```yaml
+- name: apply
+  shell: bash
+  env:
+    PW: ${{ secrets.SSHEPHERD_KEY_PASSPHRASE }}
+  run: |
+    unset SSH_AUTH_SOCK
+    env -u PW sshepherd apply --yes --identity "$HOME/.ssh/ci" \
+      --identity-passphrase-file <(printf %s "$PW")
+```
+
+**GitLab CI** — a `type: file` variable is a path to a file holding the secret:
+
+```yaml
+apply:
+  script:
+    - unset SSH_AUTH_SOCK
+    - sshepherd apply --yes --identity "$SSHEPHERD_KEY" --identity-passphrase-file "$SSHEPHERD_KEY_PASSPHRASE"
+```
+
+**Kubernetes CronJob** — key and passphrase from a secret volume:
+
+```yaml
+containers:
+  - name: sshepherd
+    image: ghcr.io/javadh75/sshepherd:latest
+    args: ["apply", "--yes", "--identity", "/secrets/ci",
+           "--identity-passphrase-file", "/secrets/ci.pass",
+           "--config", "/config/sshepherd.yaml", "--known-hosts", "/config/known_hosts"]
+    volumeMounts:
+      - {name: secrets, mountPath: /secrets, readOnly: true}
+securityContext:
+  fsGroup: 65532
+volumes:
+  - name: secrets
+    secret: {secretName: sshepherd-ci, defaultMode: 0440}
+```
+
+**`docker run`** — bind-mount the files (or use a tmpfs); a host-side `<(...)` file
+descriptor is not passed into the container:
+
+```console
+$ docker run --rm --user "$(id -u)" \
+    -v "$PWD/sshepherd.yaml:/work/sshepherd.yaml:ro" \
+    -v "$HOME/.ssh/known_hosts:/work/known_hosts:ro" \
+    -v "$HOME/.ssh/ci:/work/ci:ro" -v "$HOME/.ssh/ci.pass:/work/ci.pass:ro" \
+    -w /work sshepherd:dev apply --yes --known-hosts /work/known_hosts \
+    --identity /work/ci --identity-passphrase-file /work/ci.pass
+```
+
+### Container usage
+
+The image runs as uid 65532. A mounted key (or passphrase file) must be either
+**owned by the container's uid with mode 0600** — run with `--user` matching the
+file's owner, or set Kubernetes `runAsUser` to it — or **owned by root and readable
+through group or other bits** — Kubernetes `fsGroup: 65532` with a secret
+`defaultMode: 0440`. A file owned by the container uid but group/other-readable is
+refused (`permissions … are too open`); a file the uid cannot read at all fails with
+`cannot read key file FILE as uid 65532 (owner M, mode …)`.
+
 ## Exit codes
 
 Monitoring-style, shared by `audit` and `apply` (code `2` is `audit`-only):
@@ -575,7 +772,7 @@ Monitoring-style, shared by `audit` and `apply` (code `2` is `audit`-only):
 | `0` | Compliant / converged — nothing to do |
 | `1` | Drift, unreachable servers, or pending changes — compliance not proven |
 | `2` | `audit` only: **critical** drift (a server is missing an operator key), or a server whose host key **changed** or is `@revoked` in `known_hosts` (possible impersonation) — `apply` never returns `2` |
-| `3` | Tool error — bad flags, unloadable manifest, failed preflight, interrupted `audit`/`adopt`, `apply` interrupted before any write |
+| `3` | Tool error — bad flags, unloadable manifest, failed preflight, an `--identity` key that cannot be read, is refused, or has no passphrase source, interrupted `audit`/`adopt`, `apply` interrupted before any write |
 
 ## Safety model
 
@@ -592,12 +789,14 @@ Output is deterministic, so a repeated `apply` is a byte-for-byte no-op.
 plan, you confirm once (interactive prompt on a TTY, or `--yes`), and only then does
 it write — and only to the servers that actually drifted.
 
-**Self-lockout guard.** Any write that would leave a server without a key held by
-your agent is refused. Lines with `cert-authority` or `principals=` do not count as
-surviving logins (they accept certificates, not the bare key), and an empty agent
-listing refuses every write. The guard runs again **after** the confirmation prompt
-against a fresh agent listing, so keys that expired or were removed while the prompt
-waited fail that server instead of locking you out.
+**Self-lockout guard.** Any write that would leave a server without a key you hold
+(identity files + agent) is refused; the refusal lists every held key with its
+source. Certificates never count as held, lines with `cert-authority` or
+`principals=` do not count as surviving logins (they accept certificates, not the
+bare key), and an empty held set refuses every write. The guard runs again **after**
+the confirmation prompt against a fresh listing, so agent keys that expired or were
+removed while the prompt waited fail that server instead of locking you out (a
+vanished agent simply stops counting; your key files still do).
 
 **Refusals, not guesses.** A server is skipped — loudly, with a `REFUSED:` line, and
 nothing changed — when:
@@ -644,8 +843,9 @@ reported `FAILED` (its `authorized_keys` was still written and verified).
 
 **Verify, then prove you can still log in.** After the rename the file is re-read in
 the same session and compared byte-exactly. Then SSHepherd opens a **fresh
-connection offering only the surviving agent keys** (unrestricted ones first) and
-runs a probe command over it, so a surviving key whose line forces a `command=` fails
+connection offering only the surviving keys you hold** (unrestricted ones first,
+then key files before agent keys, so a surviving `--identity` key is the one
+proven) and runs a probe command over it, so a surviving key whose line forces a `command=` fails
 the probe just like a refused login. If the probe fails, the previous file (and a
 disabled `authorized_keys2`) is restored over the still-open session and the server
 is reported `FAILED: lockout prevented — restored previous file (…)`. The restore
@@ -653,14 +853,14 @@ takes the lock again and refuses to replace a file that changed since this apply
 wrote it (a concurrent apply); if the restore fails or is refused, the message says
 so and names the `.bak` path.
 
-**Connection posture.** Agent-only authentication, strict `known_hosts` with no
-TOFU, per-server and dial timeouts, and bounded fan-out (`--parallel`, default 32,
+**Connection posture.** Key files and/or agent (see
+[Authentication](#authentication)), strict `known_hosts` with no TOFU, per-server and dial timeouts, and bounded fan-out (`--parallel`, default 32,
 tuned from the fan-out benchmarks). `known_hosts` is parsed once per run. Host-key
 algorithms are negotiated in the order `known_hosts` implies, so a host with an sshd
 `HostCertificate` still works when its plain key is pinned; certificate algorithms
-are offered only when a matching `@cert-authority` line exists. Agent keys granted
-on the server (operators first) are offered first, to avoid sshd `MaxAuthTries`
-lockouts with many-key agents. Remote commands always run under `/bin/sh`.
+are offered only when a matching `@cert-authority` line exists. Keys granted on the
+server (operators first) are offered first, to avoid sshd `MaxAuthTries` lockouts
+with many held keys. Remote commands always run under `/bin/sh`.
 
 **Output safety.** Terminal escapes from server-supplied text are stripped and
 newlines collapsed, so a hostile server cannot forge report rows or a summary line.
@@ -717,8 +917,9 @@ internal/authkeys/   authorized_keys parser and renderer
 internal/audit/      fan-out, diffing, text/JSON reports, exit codes
 internal/adopt/      pure fleet-discovery plan
 internal/apply/      pure plan computation, self-lockout guard, plan report
-internal/sshconn/    shared connection glue (dial, agent auth, host keys, error kinds)
-internal/sshconn/sshtest/  in-process SSH server + agent for hermetic tests
+internal/sshconn/    shared connection glue (dial, credentials: key files + agent, host keys, error kinds)
+internal/sshconn/sshtest/  in-process SSH server + agent + key-file helpers for hermetic tests
+internal/keyfile/    --identity key files: permission rule, format checks, passphrases, /dev/tty prompt
 internal/sshread/    remote read protocol
 internal/sshwrite/   remote write protocol (guarded script, CAS, lock, verify, probe)
 internal/sshcfg/     OpenSSH client-config parser
@@ -739,7 +940,10 @@ Each slice was specced and planned before it was built; the documents live in
 wildcard access, JSON output and exit codes, the comment-policy memo, the merge
 designs, and the apply slice. The review-hardening pass that added the guarded write,
 login probe, new drift classes and stricter validation is described in
-[`docs/superpowers/specs/2026-10-16-review-hardening-design.md`](docs/superpowers/specs/2026-10-16-review-hardening-design.md).
+[`docs/superpowers/specs/2026-10-16-review-hardening-design.md`](docs/superpowers/specs/2026-10-16-review-hardening-design.md). Key-file
+authentication (`--identity`, passphrase sources, certificates and the guard) is
+specced in
+[`docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md`](docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md).
 
 ## License
 
PATCH
````

- [ ] **Step 10: Run**

```bash
HOME=$(mktemp -d) GOCACHE=$(go env GOCACHE) GOMODCACHE=$(go env GOMODCACHE) GOPATH=$(go env GOPATH) go test -race ./...
```

Expected: PASS (an empty `HOME` proves nothing depends on the developer's `~/.ssh/known_hosts`).

- [ ] **Step 11: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add cmd/sshepherd/identity.go cmd/sshepherd/identity_test.go cmd/sshepherd/help_readme_test.go cmd/sshepherd/audit.go cmd/sshepherd/adopt.go cmd/sshepherd/apply.go cmd/sshepherd/audit_test.go cmd/sshepherd/adopt_test.go cmd/sshepherd/apply_test.go README.md go.mod go.sum
git commit -m "$(cat <<'EOF'
feat(cli): --identity, --identity-passphrase-file, --identity-passphrase on audit/adopt/apply

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task C2 (Group C · stage 3): Remove the transitional agent-only surface

**Files:**
- Modify: `internal/sshconn/connect.go`
- Modify: `internal/sshconn/session.go`
- Modify: `internal/sshconn/session_test.go`
- Modify: `internal/sshread/sshread.go`
- Modify: `internal/sshread/sshread_test.go`
- Modify: `cmd/sshepherd/e2e_test.go`

Every caller now sets `Creds`, so the stage-1 bridges go: `Dialer.AgentSock`,
`Client.AgentSock`, `sshconn.AgentFingerprints` (and its test), and the exported
`sshread.CheckAgent` (now the unexported `checkAgent` behind `CheckCredentials`).
A `Dialer` with nil `Creds` offers nothing (`ErrorKindAgent`).

- [ ] **Step 1: Update the tests first:** `internal/sshconn/session_test.go`, `internal/sshread/sshread_test.go`, `cmd/sshepherd/e2e_test.go`

```bash
git apply <<'PATCH'
diff --git a/internal/sshconn/session_test.go b/internal/sshconn/session_test.go
--- a/internal/sshconn/session_test.go
+++ b/internal/sshconn/session_test.go
@@ -1,17 +1,12 @@
 package sshconn
 
 import (
-	"context"
 	"crypto/ed25519"
 	"crypto/rand"
 	"io"
-	"net"
-	"os"
-	"path/filepath"
 	"testing"
 
 	"golang.org/x/crypto/ssh"
-	"golang.org/x/crypto/ssh/agent"
 )
 
 // seededSigner builds a deterministic ed25519 ssh.Signer.
@@ -90,74 +85,6 @@ func TestWrapSignersPreservesAlgorithmSigner(t *testing.T) {
 	}
 }
 
-// agentSocket serves a real in-memory agent holding the given private keys.
-func agentSocket(t *testing.T, keys ...ed25519.PrivateKey) string {
-	t.Helper()
-	keyring := agent.NewKeyring()
-	for _, k := range keys {
-		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
-			t.Fatalf("keyring add: %v", err)
-		}
-	}
-	dir, err := os.MkdirTemp("", "ag") // short path: unix sun_path is ~104 bytes on macOS
-	if err != nil {
-		t.Fatalf("mkdtemp: %v", err)
-	}
-	t.Cleanup(func() { _ = os.RemoveAll(dir) })
-	sock := filepath.Join(dir, "agent.sock")
-	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
-	if err != nil {
-		t.Fatalf("listen: %v", err)
-	}
-	t.Cleanup(func() { _ = l.Close() })
-	go func() {
-		for {
-			c, err := l.Accept()
-			if err != nil {
-				return
-			}
-			go func() {
-				_ = agent.ServeAgent(keyring, c) // returns on client close (EOF)
-				_ = c.Close()
-			}()
-		}
-	}()
-	return sock
-}
-
-func TestAgentFingerprints(t *testing.T) {
-	raw := make([]byte, ed25519.SeedSize)
-	raw[0] = 7
-	priv := ed25519.NewKeyFromSeed(raw)
-	pub, err := ssh.NewPublicKey(priv.Public())
-	if err != nil {
-		t.Fatalf("public key: %v", err)
-	}
-
-	t.Run("lists held keys", func(t *testing.T) {
-		got, err := AgentFingerprints(context.Background(), agentSocket(t, priv))
-		if err != nil {
-			t.Fatalf("AgentFingerprints: %v", err)
-		}
-		if len(got) != 1 || got[0] != ssh.FingerprintSHA256(pub) {
-			t.Errorf("fingerprints = %v, want [%s]", got, ssh.FingerprintSHA256(pub))
-		}
-	})
-	t.Run("empty agent is empty, not an error", func(t *testing.T) {
-		// CheckAgent owns the empty-agent verdict; the guard has its own
-		// empty-listing fallback and needs the distinction.
-		got, err := AgentFingerprints(context.Background(), agentSocket(t))
-		if err != nil || len(got) != 0 {
-			t.Errorf("got (%v, %v), want ([], nil)", got, err)
-		}
-	})
-	t.Run("dead socket errors", func(t *testing.T) {
-		if _, err := AgentFingerprints(context.Background(), filepath.Join(t.TempDir(), "nope.sock")); err == nil {
-			t.Error("dead socket produced no error")
-		}
-	})
-}
-
 func TestConnSessionKeyFPNilSafe(t *testing.T) {
 	c := &Conn{}
 	if got := c.SessionKeyFP(); got != "" {
diff --git a/internal/sshread/sshread_test.go b/internal/sshread/sshread_test.go
--- a/internal/sshread/sshread_test.go
+++ b/internal/sshread/sshread_test.go
@@ -21,26 +21,26 @@ import (
 
 func TestCheckAgent(t *testing.T) {
 	t.Run("unset", func(t *testing.T) {
-		if err := CheckAgent(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
-			t.Errorf("CheckAgent(\"\") = %v, want SSH_AUTH_SOCK error", err)
+		if err := checkAgent(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
+			t.Errorf("checkAgent(\"\") = %v, want SSH_AUTH_SOCK error", err)
 		}
 	})
 	t.Run("dead socket", func(t *testing.T) {
-		if err := CheckAgent(context.Background(), filepath.Join(t.TempDir(), "nope.sock")); err == nil {
-			t.Error("CheckAgent(dead) = nil, want error")
+		if err := checkAgent(context.Background(), filepath.Join(t.TempDir(), "nope.sock")); err == nil {
+			t.Error("checkAgent(dead) = nil, want error")
 		}
 	})
 	t.Run("agent with keys", func(t *testing.T) {
-		if err := CheckAgent(context.Background(), serveAgent(t, true)); err != nil {
-			t.Errorf("CheckAgent(agent with keys) = %v, want nil", err)
+		if err := checkAgent(context.Background(), serveAgent(t, true)); err != nil {
+			t.Errorf("checkAgent(agent with keys) = %v, want nil", err)
 		}
 	})
 	t.Run("empty agent", func(t *testing.T) {
 		// The socket answers the agent protocol but holds zero keys: every
 		// later per-server auth would fail. The preflight must say so once.
-		err := CheckAgent(context.Background(), serveAgent(t, false))
+		err := checkAgent(context.Background(), serveAgent(t, false))
 		if err == nil || !strings.Contains(err.Error(), "no keys") {
-			t.Errorf("CheckAgent(empty agent) = %v, want a no-keys error", err)
+			t.Errorf("checkAgent(empty agent) = %v, want a no-keys error", err)
 		}
 		if err != nil && !strings.Contains(err.Error(), "ssh-add") {
 			t.Errorf("err %q should tell the operator to run ssh-add", err)
@@ -51,9 +51,9 @@ func TestCheckAgent(t *testing.T) {
 		// context flows into DialContext instead of being dropped.
 		ctx, cancel := context.WithCancel(context.Background())
 		cancel()
-		err := CheckAgent(ctx, serveAgent(t, true))
+		err := checkAgent(ctx, serveAgent(t, true))
 		if !errors.Is(err, context.Canceled) {
-			t.Errorf("CheckAgent(canceled ctx) = %v, want context.Canceled", err)
+			t.Errorf("checkAgent(canceled ctx) = %v, want context.Canceled", err)
 		}
 	})
 	t.Run("unresponsive socket", func(t *testing.T) {
@@ -73,8 +73,8 @@ func TestCheckAgent(t *testing.T) {
 				c.Close()
 			}
 		}()
-		if err := CheckAgent(context.Background(), sock); err == nil {
-			t.Error("CheckAgent(unresponsive) = nil, want error")
+		if err := checkAgent(context.Background(), sock); err == nil {
+			t.Error("checkAgent(unresponsive) = nil, want error")
 		}
 	})
 }
diff --git a/cmd/sshepherd/e2e_test.go b/cmd/sshepherd/e2e_test.go
--- a/cmd/sshepherd/e2e_test.go
+++ b/cmd/sshepherd/e2e_test.go
@@ -174,7 +174,7 @@ func e2eRemoteCat(t *testing.T, host, port, kh, user string) string {
 	}
 	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
 	defer cancel()
-	d := &sshconn.Dialer{KnownHostsPath: kh, AgentSock: os.Getenv("SSH_AUTH_SOCK"), DialTimeout: 10 * time.Second}
+	d := &sshconn.Dialer{KnownHostsPath: kh, Creds: &sshconn.Credentials{AgentSock: os.Getenv("SSH_AUTH_SOCK")}, DialTimeout: 10 * time.Second}
 	conn, err := d.Connect(ctx, config.Server{Name: user, Host: host, Port: p, User: user})
 	if err != nil {
 		t.Fatalf("connect %s: %v", user, err)
PATCH
```

- [ ] **Step 2: Run**

```bash
go test ./internal/sshread
```

Expected: FAIL — build failure: `undefined: checkAgent`.

- [ ] **Step 3: Remove the transitional code:** `internal/sshconn/connect.go`, `internal/sshconn/session.go`, `internal/sshread/sshread.go`

```bash
git apply <<'PATCH'
diff --git a/internal/sshconn/connect.go b/internal/sshconn/connect.go
--- a/internal/sshconn/connect.go
+++ b/internal/sshconn/connect.go
@@ -29,11 +29,9 @@ type Dialer struct {
 	// reuses that snapshot for every later connection through this Dialer.
 	KnownHosts *KnownHosts
 	// Creds is the run's credential source (key files + agent), shared
-	// with every other Dialer and the read client of the run.
-	Creds *Credentials
-	// AgentSock is transitional: used only when Creds is nil, as an
-	// agent-only Credentials. Removed once every caller sets Creds.
-	AgentSock   string
+	// with every other Dialer and the read client of the run. Nil offers
+	// nothing: every connect fails with ErrorKindAgent.
+	Creds       *Credentials
 	DialTimeout time.Duration
 	// PreferKeys optionally returns the fingerprints to offer first when
 	// connecting to srv — the keys the manifest grants there, operators
@@ -47,9 +45,6 @@ type Dialer struct {
 	khOnce sync.Once
 	kh     *KnownHosts
 	khErr  error
-
-	credsOnce sync.Once
-	creds     *Credentials
 }
 
 // ConnectOptions tunes one connection's key offering.
@@ -74,16 +69,13 @@ func (d *Dialer) log() *slog.Logger {
 	return slog.New(slog.DiscardHandler)
 }
 
-// credentials returns Creds, or the transitional agent-only Credentials
-// built once from AgentSock.
+// credentials returns Creds, or an empty source (no key files, no agent)
+// when none is set.
 func (d *Dialer) credentials() *Credentials {
-	d.credsOnce.Do(func() {
-		d.creds = d.Creds
-		if d.creds == nil {
-			d.creds = &Credentials{AgentSock: d.AgentSock, Log: d.Log}
-		}
-	})
-	return d.creds
+	if d.Creds != nil {
+		return d.Creds
+	}
+	return &Credentials{Log: d.Log}
 }
 
 // knownHosts returns the run's single known_hosts snapshot.
diff --git a/internal/sshconn/session.go b/internal/sshconn/session.go
--- a/internal/sshconn/session.go
+++ b/internal/sshconn/session.go
@@ -1,18 +1,13 @@
 package sshconn
 
 import (
-	"context"
-	"fmt"
 	"io"
-	"net"
 	"sync"
-	"time"
 
 	"golang.org/x/crypto/ssh"
-	"golang.org/x/crypto/ssh/agent"
 )
 
-// sessionKey records which agent key completed the handshake. Mutex-guarded:
+// sessionKey records which key (file or agent) completed the handshake. Mutex-guarded:
 // the transport may try several signers; the last successful Sign is the one
 // the server accepted.
 type sessionKey struct {
@@ -80,27 +75,3 @@ func wrapSigners(signers []ssh.Signer, rec *sessionKey) []ssh.Signer {
 	}
 	return out
 }
-
-// AgentFingerprints lists the SHA256 fingerprints of every key the agent at
-// sock holds — captured once at apply's preflight as the self-lockout
-// guard's ground truth. An empty agent yields an empty list, not an error:
-// CheckAgent owns that verdict, and apply's guard refuses every write when
-// the listing is empty.
-func AgentFingerprints(ctx context.Context, sock string) ([]string, error) {
-	dialer := net.Dialer{Timeout: 3 * time.Second}
-	conn, err := dialer.DialContext(ctx, "unix", sock)
-	if err != nil {
-		return nil, fmt.Errorf("SSH agent unreachable at %s: %w", sock, err)
-	}
-	defer func() { _ = conn.Close() }()                   // errcheck: close error is uninteresting on a preflight
-	_ = conn.SetDeadline(time.Now().Add(3 * time.Second)) // a wedged agent must not hang the preflight
-	keys, err := agent.NewClient(conn).List()
-	if err != nil {
-		return nil, fmt.Errorf("list SSH agent keys at %s: %w", sock, err)
-	}
-	fps := make([]string, 0, len(keys))
-	for _, k := range keys {
-		fps = append(fps, ssh.FingerprintSHA256(k))
-	}
-	return fps, nil
-}
diff --git a/internal/sshread/sshread.go b/internal/sshread/sshread.go
--- a/internal/sshread/sshread.go
+++ b/internal/sshread/sshread.go
@@ -34,14 +34,14 @@ func LoadKnownHosts(path string) (*sshconn.KnownHosts, error) {
 // something to authenticate with, so a missing or empty agent fails once
 // with a clear message instead of once per server with a cryptic "no
 // supported methods remain". With no key files the agent is required and
-// the messages are CheckAgent's, verbatim. needHeld (apply) additionally
+// the messages are checkAgent's, verbatim. needHeld (apply) additionally
 // requires a non-empty held set — plain keys, since certificates never
 // count toward the self-lockout guard — so a certificate-only operator is
 // refused with a certificate-specific message; audit/adopt (needHeld
 // false) count signers, so a certificate-only agent passes, as before.
 func CheckCredentials(ctx context.Context, creds *sshconn.Credentials, needHeld bool) error {
 	if len(creds.Files) == 0 {
-		if err := CheckAgent(ctx, creds.AgentSock); err != nil {
+		if err := checkAgent(ctx, creds.AgentSock); err != nil {
 			return err
 		}
 	}
@@ -66,12 +66,12 @@ func CheckCredentials(ctx context.Context, creds *sshconn.Credentials, needHeld
 	return nil
 }
 
-// CheckAgent verifies a usable SSH agent — reachable and holding at least
+// checkAgent verifies a usable SSH agent — reachable and holding at least
 // one key — before any server is dialed, so a missing or empty agent fails
 // once with a clear message instead of once per server with a cryptic
 // "no supported methods remain" auth error. ctx cancellation aborts the
 // dial; the 3s timeout still bounds a wedged agent on its own.
-func CheckAgent(ctx context.Context, sock string) error {
+func checkAgent(ctx context.Context, sock string) error {
 	if sock == "" {
 		return errors.New("no SSH agent: SSH_AUTH_SOCK is not set (start ssh-agent and ssh-add a key)")
 	}
@@ -102,10 +102,7 @@ type Client struct {
 	KnownHosts *sshconn.KnownHosts
 	// Creds is the run's credential source (key files + agent); one per
 	// run, shared with the writer and the probe.
-	Creds *sshconn.Credentials
-	// AgentSock is transitional: used only when Creds is nil (an
-	// agent-only Credentials). Removed once every caller sets Creds.
-	AgentSock   string
+	Creds       *sshconn.Credentials
 	DialTimeout time.Duration
 	// PreferKeys optionally names the keys to offer first per server (see
 	// sshconn.Dialer.PreferKeys) — typically audit.GrantedFingerprints.
@@ -146,7 +143,6 @@ func (c *Client) getDialer() *sshconn.Dialer {
 			KnownHostsPath: c.KnownHostsPath,
 			KnownHosts:     c.KnownHosts,
 			Creds:          c.Creds,
-			AgentSock:      c.AgentSock,
 			DialTimeout:    c.DialTimeout,
 			PreferKeys:     c.PreferKeys,
 			Log:            c.Log,
PATCH
```

- [ ] **Step 4: Run**

```bash
go build ./... && go vet ./... && go vet -tags integration ./... && go test -race ./... && deadcode ./cmd/sshepherd
```

Expected: PASS; `deadcode` prints nothing.

- [ ] **Step 5: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add internal/sshconn/connect.go internal/sshconn/session.go internal/sshconn/session_test.go internal/sshread/sshread.go internal/sshread/sshread_test.go cmd/sshepherd/e2e_test.go
git commit -m "$(cat <<'EOF'
refactor(sshconn,sshread): drop the transitional agent-only fields and helpers

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task C3 (Group C · stage 3): Integration (real sshd, no agent), headless E2E, `make fuzz`

**Files:**
- Create: `cmd/sshepherd/identity_integration_test.go`
- Modify: `scripts/integration.sh`
- Modify: `Makefile`

`scripts/integration.sh` generates three headless keys never added to the agent
(`ci_old` unencrypted; `ci_new` and `enc` encrypted, `-a 16`, passphrase files
mode 0600), seeds four container users (`idaudit`, `idenc`, `rotate`, `e2eh`) and
exports `SSHEPHERD_IT_KEYS`. The new tests run the built binary with
`SSH_AUTH_SOCK` removed from its environment.

- [ ] **Step 1: Write the integration and E2E tests:** `cmd/sshepherd/identity_integration_test.go`

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
)

// itKeys returns the directory of the harness's headless key files
// (scripts/integration.sh): ci_old (unencrypted), ci_new and enc (encrypted,
// with ci_new.pass / enc.pass).
func itKeys(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("SSHEPHERD_IT_KEYS")
	if dir == "" {
		t.Skip("integration env not set; run via make integration")
	}
	return dir
}

// itPubLine reads a harness public key line.
func itPubLine(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name+".pub"))
	if err != nil {
		t.Fatalf("%s.pub: %v", name, err)
	}
	return strings.TrimSpace(string(b))
}

// runHeadless executes the binary with SSH_AUTH_SOCK removed from its
// environment: only --identity keys can authenticate.
func runHeadless(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, args...)
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "SSH_AUTH_SOCK=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	var out, errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	code := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return code, out.String(), errBuf.String()
}

func TestIntegrationIdentityAudit(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: ci, keys: ["`+itPubLine(t, keys, "ci_old")+`"]}
servers:
  - {name: idaudit, host: `+host+`, port: `+port+`, user: idaudit}
access:
  - {user: ci, servers: [idaudit]}
`)
	code, out, stderr := runHeadless(t, bin, "audit", "--config", m, "--known-hosts", kh, "--identity", filepath.Join(keys, "ci_old"))
	if code != 0 {
		t.Fatalf("headless audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
	if !strings.Contains(stderr, "identity loaded") {
		t.Errorf("stderr lacks the identity-loaded line:\n%s", stderr)
	}
	// Without the key file and without an agent there is nothing to log in with.
	if code, _, stderr := runHeadless(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 3 || !strings.Contains(stderr, "SSH_AUTH_SOCK") {
		t.Errorf("agent-less audit without --identity: exit %d, stderr %q; want 3 with agent guidance", code, stderr)
	}
}

func TestIntegrationIdentityApplyEncrypted(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: op, operator: true, keys: ["`+itPubLine(t, keys, "enc")+`"]}
servers:
  - {name: idenc, host: `+host+`, port: `+port+`, user: idenc}
`)
	args := []string{"apply", "--yes", "--config", m, "--known-hosts", kh,
		"--identity", filepath.Join(keys, "enc"), "--identity-passphrase-file", filepath.Join(keys, "enc.pass")}
	code, out, stderr := runHeadless(t, bin, args...)
	if code != 0 || !strings.Contains(out, "applied · verified") {
		t.Fatalf("headless encrypted apply exit = %d, want 0 + applied (stderr: %s)\n%s", code, stderr, out)
	}
	if strings.Contains(stderr+out, "enc-passphrase") {
		t.Error("the passphrase reached the output")
	}
	if code, out, stderr := runHeadless(t, bin, args...); code != 0 || !strings.Contains(out, "converged (no changes)") {
		t.Fatalf("re-apply exit = %d, want a converged no-op (stderr: %s)\n%s", code, stderr, out)
	}
}

// TestIntegrationHeadlessRotation is the motivating case: the manifest
// replaces ci_old with ci_new; one --identity is refused naming the fix;
// both keys rotate (the probe proves ci_new); ci_new alone is then a no-op.
func TestIntegrationHeadlessRotation(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: ci, operator: true, keys: ["`+itPubLine(t, keys, "ci_new")+`"]}
servers:
  - {name: rotate, host: `+host+`, port: `+port+`, user: rotate}
`)
	base := []string{"apply", "--yes", "--config", m, "--known-hosts", kh}
	oldKey := []string{"--identity", filepath.Join(keys, "ci_old")}
	newKey := []string{"--identity", filepath.Join(keys, "ci_new"), "--identity-passphrase", filepath.Join(keys, "ci_new") + "=" + filepath.Join(keys, "ci_new.pass")}

	t.Run("old key alone is refused, naming the fix", func(t *testing.T) {
		code, out, _ := runHeadless(t, bin, append(base, oldKey...)...)
		if code != 1 || !strings.Contains(out, "pass the new key with another --identity") {
			t.Fatalf("exit = %d, want 1 with the rotation hint\n%s", code, out)
		}
	})
	t.Run("old + new rotates; the probe proves the new key", func(t *testing.T) {
		code, out, stderr := runHeadless(t, bin, append(append(base, oldKey...), newKey...)...)
		if code != 0 || !strings.Contains(out, "applied · verified") {
			t.Fatalf("exit = %d, want 0 + applied (stderr: %s)\n%s", code, stderr, out)
		}
		if !strings.Contains(out, "removes the key this session logged in with") {
			t.Errorf("plan lacks the rotate note:\n%s", out)
		}
	})
	t.Run("new key alone is a no-op", func(t *testing.T) {
		code, out, stderr := runHeadless(t, bin, append(base, newKey...)...)
		if code != 0 || !strings.Contains(out, "converged (no changes)") {
			t.Fatalf("exit = %d, want a converged no-op (stderr: %s)\n%s", code, stderr, out)
		}
	})
}

// TestE2EHeadlessLoop: adopt → apply → audit with only --identity, no agent.
func TestE2EHeadlessLoop(t *testing.T) {
	bin, host, port, kh, _ := itE2E(t)
	keys := itKeys(t)
	dir := t.TempDir()
	id := []string{"--identity", filepath.Join(keys, "ci_old")}
	m0 := writeE2EManifest(t, dir, "m0.yaml", `
users:
  - {name: ci, operator: true, keys: ["`+itPubLine(t, keys, "ci_old")+`"]}
servers:
  - {name: e2eh, host: `+host+`, port: `+port+`, user: e2eh}
`)
	adopted := filepath.Join(dir, "adopted.yaml")
	code, out, stderr := runHeadless(t, bin, append([]string{"adopt", "--config", m0, "--known-hosts", kh, "-o", adopted}, id...)...)
	if code != 0 {
		t.Fatalf("headless adopt exit = %d (stderr: %s)", code, stderr)
	}
	if code, out, stderr = runHeadless(t, bin, append([]string{"apply", "--yes", "--config", m0, "--known-hosts", kh}, id...)...); code != 0 {
		t.Fatalf("headless apply (revoking the stale key) exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	if !strings.Contains(out, "remove (unauthorized)") {
		t.Errorf("apply did not remove the stale key:\n%s", out)
	}
	if code, out, stderr = runHeadless(t, bin, append([]string{"audit", "--config", m0, "--known-hosts", kh}, id...)...); code != 0 {
		t.Fatalf("headless audit exit = %d, want 0 — the loop must close (stderr: %s)\n%s", code, stderr, out)
	}
	if b, err := os.ReadFile(adopted); err != nil || !strings.Contains(string(b), "adopted from e2eh") {
		t.Errorf("adopted manifest lacks the stale key (%v):\n%s", err, b)
	}
}
```

- [ ] **Step 2: Run**

```bash
go vet -tags integration ./cmd/sshepherd && make integration 2>&1 | grep -E "Identity|Headless"
```

Expected: The four new tests `SKIP` (`integration env not set`: the harness does not export `SSHEPHERD_IT_KEYS` yet).

- [ ] **Step 3: Extend the harness:** `scripts/integration.sh`

```bash
git apply <<'PATCH'
diff --git a/scripts/integration.sh b/scripts/integration.sh
--- a/scripts/integration.sh
+++ b/scripts/integration.sh
@@ -19,12 +19,23 @@ ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/id_ed25519"
 chmod 644 "$WORKDIR/id_ed25519.pub"
 ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/stale"
 chmod 644 "$WORKDIR/stale.pub"
+# Headless --identity keys (never added to the agent): ci_old unencrypted,
+# ci_new and enc encrypted (passphrase files mode 0600, as the tool requires).
+ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/ci_old"
+ssh-keygen -q -t ed25519 -N 'ci-new-passphrase' -a 16 -f "$WORKDIR/ci_new"
+ssh-keygen -q -t ed25519 -N 'enc-passphrase' -a 16 -f "$WORKDIR/enc"
+printf '%s\n' 'ci-new-passphrase' >"$WORKDIR/ci_new.pass"
+printf '%s\n' 'enc-passphrase' >"$WORKDIR/enc.pass"
+chmod 600 "$WORKDIR/ci_new.pass" "$WORKDIR/enc.pass"
+chmod 644 "$WORKDIR/ci_old.pub" "$WORKDIR/ci_new.pub" "$WORKDIR/enc.pub"
 
 docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
 docker run -d --name "$CONTAINER" \
   -p "127.0.0.1:$PORT:22" \
   -v "$WORKDIR/id_ed25519.pub:/seed/key.pub:ro" \
   -v "$WORKDIR/stale.pub:/seed/stale.pub:ro" \
+  -v "$WORKDIR/ci_old.pub:/seed/ci_old.pub:ro" \
+  -v "$WORKDIR/enc.pub:/seed/enc.pub:ro" \
   alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 sh -c '
     set -e
     apk add --no-cache openssh >/dev/null
@@ -41,7 +52,7 @@ docker run -d --name "$CONTAINER" \
       chmod 700 "/home/$u/.ssh"
       chmod 600 "/home/$u/.ssh/"authorized_keys* 2>/dev/null || true
     done
-    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse; do
+    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse idaudit idenc rotate e2eh; do
       adduser -D -s /bin/sh "$u"
       sed -i "s|^$u:!|$u:*|" /etc/shadow   # unlock for pubkey login
       mkdir -p "/home/$u/.ssh"
@@ -52,6 +63,11 @@ docker run -d --name "$CONTAINER" \
       cp /seed/key.pub "/home/$u/.ssh/authorized_keys"
     done
     { cat /seed/key.pub; echo "this line is not a key"; } > /home/unparse/.ssh/authorized_keys
+    # Headless --identity users: only key files log in here, never the agent key.
+    cp /seed/ci_old.pub /home/idaudit/.ssh/authorized_keys
+    cp /seed/enc.pub /home/idenc/.ssh/authorized_keys
+    cp /seed/ci_old.pub /home/rotate/.ssh/authorized_keys
+    cat /seed/ci_old.pub /seed/stale.pub > /home/e2eh/.ssh/authorized_keys
     # writer + e2e: drifted seed (agent key + a stale key apply must remove).
     cat /seed/key.pub /seed/stale.pub > /home/writer/.ssh/authorized_keys
     cat /seed/key.pub /seed/stale.pub > /home/e2e/.ssh/authorized_keys
@@ -62,7 +78,7 @@ docker run -d --name "$CONTAINER" \
     # through it for login.
     cp /seed/key.pub /home/sym/.ssh/authorized_keys_real
     ln -s authorized_keys_real /home/sym/.ssh/authorized_keys
-    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse; do
+    for u in writer virgin sym e2e cas locked verifyfail drop lockout unparse idaudit idenc rotate e2eh; do
       chown -R "$u:$u" "/home/$u/.ssh"
       chmod 700 "/home/$u/.ssh"
       chmod 600 "/home/$u/.ssh/"authorized_keys* 2>/dev/null || true
@@ -103,5 +119,6 @@ SSHEPHERD_IT_HOST=127.0.0.1 \
 SSHEPHERD_IT_PORT="$PORT" \
 SSHEPHERD_IT_KNOWN_HOSTS="$WORKDIR/known_hosts" \
 SSHEPHERD_IT_PUB="$WORKDIR/id_ed25519.pub" \
+SSHEPHERD_IT_KEYS="$WORKDIR" \
   go test -race -tags=integration -run 'TestIntegration|TestE2E' -v \
   ./internal/sshread/ ./internal/sshwrite/ ./cmd/sshepherd/
PATCH
```

- [ ] **Step 4: Add the fuzz targets (also picked up by the scheduled CI job, which runs `make -k fuzz`):** `Makefile`

```bash
git apply <<'PATCH'
diff --git a/Makefile b/Makefile
--- a/Makefile
+++ b/Makefile
@@ -108,6 +108,8 @@ fuzz:
 	$(GO) test -run='^$$' -fuzz=FuzzWriteCmds -fuzztime=15s ./internal/sshwrite
 	$(GO) test -run='^$$' -fuzz=FuzzMergeRoundTrip -fuzztime=15s ./internal/manifest
 	$(GO) test -run='^$$' -fuzz=FuzzLoad -fuzztime=15s ./internal/config
+	$(GO) test -run='^$$' -fuzz=FuzzClassify -fuzztime=15s ./internal/keyfile
+	$(GO) test -run='^$$' -fuzz=FuzzDecrypt -fuzztime=15s ./internal/keyfile
 
 ## bench: run benchmarks
 bench:
PATCH
```

- [ ] **Step 5: Run**

```bash
make integration 2>&1 | grep -E "^(--- |ok|FAIL)" | grep -E "Identity|Headless|ok|FAIL"
```

Expected: `--- PASS: TestIntegrationIdentityAudit`, `--- PASS: TestIntegrationIdentityApplyEncrypted`, `--- PASS: TestIntegrationHeadlessRotation`, `--- PASS: TestE2EHeadlessLoop`, and `ok` for `internal/sshread`, `internal/sshwrite`, `cmd/sshepherd`.

- [ ] **Step 6: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add cmd/sshepherd/identity_integration_test.go scripts/integration.sh Makefile
git commit -m "$(cat <<'EOF'
test: headless --identity integration (audit, encrypted apply, rotation) and E2E loop; fuzz targets

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


#### Task C4 (Group C · stage 3): Status docs and the full gate

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/specs/2026-07-06-audit-slice-design.md`
- Modify: `docs/superpowers/specs/2026-07-19-apply-slice-design.md`

CLAUDE.md's Status paragraph and one-line "amended by" notes in the audit and
apply specs; then the full `make check` (now including `deadcode`, gosec,
govulncheck, gitleaks and the 80% coverage gate).

- [ ] **Step 1: Apply:** `CLAUDE.md`, `docs/superpowers/specs/2026-07-06-audit-slice-design.md`, `docs/superpowers/specs/2026-07-19-apply-slice-design.md`

```bash
git apply <<'PATCH'
diff --git a/CLAUDE.md b/CLAUDE.md
--- a/CLAUDE.md
+++ b/CLAUDE.md
@@ -306,3 +306,20 @@ collapse, proxy warnings) with shared naming in `internal/naming`. Tooling is
 pinned (tools, actions by SHA, images by digest), `make check` ends in the
 coverage gate, CI runs daily vuln/fuzz, and tagged releases publish a signed
 multi-arch image.
+**Key-file authentication** (specced in
+`docs/superpowers/specs/2026-10-16-identity-keyfile-auth-design.md`, planned in
+`docs/superpowers/plans/2026-10-16-identity-keyfile-auth.md`): `audit`,
+`adopt` and `apply` take repeatable `--identity PATH` plus
+`--identity-passphrase-file FILE` / `--identity-passphrase KEY=FILE`
+(TTY prompt as the last resort; no passphrase env var or flag value), in union
+with the agent (agent optional once a key file is given). The new
+`internal/keyfile` does the OpenSSH permission rule on the opened descriptor
+(pipes exempt), container classification before any prompt, read-once
+passphrase files and a foreground-only `/dev/tty` prompter; `sshconn.Credentials`
+is the run's one credential source (`Signers` before the dial, `Held` with
+sources, certificates offered but never held); `sshread.CheckCredentials`
+replaces the agent preflight. apply's guard, survivor order (key files before
+agent keys) and probe reason over every held key, refusals list each key with
+its source, and an agent-only-survivor warning flags a stray agent satisfying
+the guard for a headless run. Headless rotation (old + new `--identity`) is
+covered end to end by the integration suite.
diff --git a/docs/superpowers/specs/2026-07-06-audit-slice-design.md b/docs/superpowers/specs/2026-07-06-audit-slice-design.md
--- a/docs/superpowers/specs/2026-07-06-audit-slice-design.md
+++ b/docs/superpowers/specs/2026-07-06-audit-slice-design.md
@@ -3,6 +3,7 @@
 - **Date:** 2026-07-06 (updated 2026-07-09: auth/host-key/concurrency decisions; full review fixes — remote-read semantics, example corrections)
 - **Status:** Implemented (2026-07-09) — see `docs/superpowers/plans/2026-07-09-audit-slice.md` (all tasks executed; per-batch spec+quality reviews and a final whole-slice review passed)
 - **Scope:** First real vertical slice of SSHepherd — a read-only drift audit.
+- **Amended by:** [`--identity` key-file auth](2026-10-16-identity-keyfile-auth-design.md) (2026-10-16) — the planned `--identity` follow-up and its passphrase policy.
 
 ## Context & goal
 
diff --git a/docs/superpowers/specs/2026-07-19-apply-slice-design.md b/docs/superpowers/specs/2026-07-19-apply-slice-design.md
--- a/docs/superpowers/specs/2026-07-19-apply-slice-design.md
+++ b/docs/superpowers/specs/2026-07-19-apply-slice-design.md
@@ -37,6 +37,7 @@
     which apply reuses.
   - `cmd/sshepherd/manifest_out.go` `writeFileNoClobber` — the local
     temp-file+rename atomicity pattern, mirrored remotely.
+- **Amended by:** [`--identity` key-file auth](2026-10-16-identity-keyfile-auth-design.md) (2026-10-16) — the guard's "held keys" are no longer agent-only.
 
 ## Context & goal
 
PATCH
```

- [ ] **Step 2: Run**

```bash
make check
```

Expected: Ends with `coverage 8x.x% meets the 80% minimum` (the replay measured 89.6%).

- [ ] **Step 3: Run the gate, then commit**

```bash
test -z "$(gofmt -l .)" && go vet ./... && go vet -tags integration ./... && golangci-lint run ./... && go test -race ./...
git add CLAUDE.md docs/superpowers/specs/2026-07-06-audit-slice-design.md docs/superpowers/specs/2026-07-19-apply-slice-design.md
git commit -m "$(cat <<'EOF'
docs: --identity key-file auth implemented — CLAUDE.md status, spec amendments

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
)"
```


---

## Spec coverage (self-review)

| Spec requirement | Task(s) |
| ---------------- | ------- |
| Union with agent; agent optional with `--identity`; one warning for a broken-but-set agent; unchanged behavior without `--identity` | T1, T2, T3 (`CheckCredentials` verbatim path), C1 |
| No passphrase env var / flag value; files + TTY | K3, K6, K7, C1 (flags only take file paths) |
| Repeatable identities; default + per-key; first-`=` split; lexical matching; validation errors; silent de-dup | K5, C1 |
| Certificates: `-cert.pub` not loaded (info); agent certs offered, never held; cert-only apply refused | K7, T1, T3, W1 |
| Per-command flags with varnames; `--help` ↔ README test | C1 |
| Order of operations (validation → manifest → empty-fleet/zero-target → known_hosts → Load → CheckCredentials) | C1 (`TestIdentityOrderOfOperations`) |
| One open per file, fstat, permission rule (regular only, other-uid ok, FIFO/char/socket exempt), EACCES message, size caps | K3, K4 |
| Passphrase files read once before any key, newline strip, empty = error, wiped (best effort) | K3, K7 |
| Container classification before any prompt (PuTTY, encrypted PKCS#8, DSA, OpenSSH cipher/KDF/rounds/count/`ssh-dss`/`sk-*`, hints) | K2, K7 (`TestLoadRefusesBeforePrompt`) |
| Resolution order; per-key wrong = no fallback; default wrong falls through; 3 prompts; no-source message mentions the default | K7 |
| Wrong-passphrase semantics (OpenSSH check value vs legacy PEM any-failure incl. valid padding) | K7 (`paddingFooler`) |
| Fingerprint = decrypted key; mismatched embedded/`.pub` refused | K7 |
| De-dup by decrypted fingerprint with info line; joined non-interactive errors | K7 |
| `/dev/tty` prompter: availability (tty + stdin tty + foreground pgrp), cancellation restores termios, prompts to tty not stdout, regardless of `-q`; `--yes` still prompts | K6 (`TestTTYCanceledPromptRestoresEcho`, `TestTTYReadPassphraseOnPTY` on a real pty), C1 |
| `identity loaded path= fp=` logging; secrets never logged | K7, K8 (`FuzzDecrypt` marker), C1 |
| `Credentials`, `HeldKey`, `Signers` before dial, order, de-dup, degraded agent semantics, `Held` re-lists | T1, T2 |
| `Dialer.Creds`; `orderSigners`/recorder unchanged; ties keep file-first | T2 |
| `CheckCredentials` replaces `CheckAgent`; `AgentFingerprints` replaced by `Held` | T3, C1, C2 |
| No new `error_kind`; key-file problems exit 3 before any server | K7, C1 |
| `sshtest` file-key auth | T1 |
| Guard over `Held` at preflight and post-prompt; degraded set used as is | W1, C1 (`writePhase`) |
| Survivor order (unrestricted, file before agent, fingerprint); probe proves the `--identity` survivor | W1, W3 |
| Agent-only-survivor warning (not a refusal) | W1, W2 |
| Headless rotation (both keys pass; old only refused naming the fix) | W1 (unit), C3 (integration) |
| Source-neutral wording; refusals list sources; goldens/README regenerated | W1, W2, W3, C1 |
| `.gitleaks.toml` path-scoped allowlist | K8 |
| Fuzz: `FuzzClassify`, `FuzzDecrypt` (rounds clamped, marker leak property) in `make fuzz` and the scheduled job | K8, C3 |
| Integration (sshd, no agent): audit, encrypted apply + passphrase file, headless rotation incl. no-op re-run | C3 |
| E2E: adopt → apply → audit headless | C3 |
| goleak `TestMain` in `internal/keyfile` | K1 |
| Docs: flag tables, Authentication, CI recipes (each unsets `SSH_AUTH_SOCK`), Container usage, CLAUDE.md status, amended-by notes | C1, C4 |

### Spec ambiguities resolved by this plan

1. **`Load` takes a logger.** The spec's signature has none but requires info lines (loaded keys, duplicates, unused certificates); `Load` gains a trailing `log *slog.Logger` (nil discards).
2. **`FS` has `Stat` too.** The EACCES message needs the owner and mode of a file that could not be opened; `Stat` is used only for that diagnostic, never to decide what to read.
3. **Lexical matching lives in `keyfile.Resolve`** (pure, injected `home`/`cwd`, unit-tested in K5); the CLI only wires it.
4. **The "waiting for passphrase … on the terminal" line is part of the prompt text** written to `/dev/tty` (the spec sends it to the tty regardless of `-q`), not a log record. Retries use ssh's `Bad passphrase, try again for KEY: `; an empty answer counts as an attempt.
5. **"Verbatim" beats "neutral hints"** for the no-`--identity` agent messages (spec says both): they stay byte-identical with the `agent preflight:` prefix; with key files the prefix is `credentials preflight:`, and the new certificate-only refusal is source-neutral.
6. **Sibling `.pub` (legacy PEM)** is checked whether or not the key is encrypted; an unparseable `.pub` is ignored (it is only a label).
7. **Signers are fetched first in `ConnectWith`** — before the known_hosts snapshot and the dial; one existing test (`TestClientBadKnownHostsPath`) now uses a working agent.
8. **The agent preflight moves after `known_hosts`** (the spec's order), so the three existing `…NoAgent` tests pass an empty `--known-hosts`.
9. **Non-unix platforms:** `OSFS` refuses and the TTY is never available (the spec is silent; the module still cross-compiles).
10. **`HeldKey.Source` for a key file is the cleaned absolute path** (the spec's example abbreviates it as `~/.ssh/ci_new`).
11. **The rotation hint** is appended to any lockout refusal while some held key is an `--identity` file.
12. **The `--help` ↔ README test compares flag names and varnames** (descriptions are README prose, not `--help` text).
13. **Legacy PEM EC keys written by a LibreSSL `ssh-keygen`** (explicit curve parameters) fail to parse after decryption, so the spec's legacy any-failure rule reports them as a wrong passphrase; accepted (OpenSSH-format keys are unaffected), and the committed legacy fixture is RSA.
14. **Stage bridges** (transitional `AgentSock`/`CheckAgent`/`AgentFingerprints`, W1's `agentHeld`) exist only so each commit stays green while groups land in stages; C2 removes them.
