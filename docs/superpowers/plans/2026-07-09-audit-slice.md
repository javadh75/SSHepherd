# `sshepherd audit` (Drift/Compliance Slice) Implementation Plan

> **STATUS: EXECUTED 2026-07-09.** All 16 tasks implemented via subagent-driven development (4 batches, per-batch spec + quality reviews, final whole-slice review: SHIP). Kept for historical reference — the code on master is the source of truth, including review-driven evolutions not reflected in the snippets below (owner-labeled unauthorized keys, hardened sshread deadlines/output caps/host-key classification, integration-script fixes).

**Goal:** Implement `sshepherd audit` — a read-only, concurrent drift audit that diffs the YAML source of truth against each server's actual `authorized_keys`, per the spec in `docs/superpowers/specs/2026-07-06-audit-slice-design.md`.

**Architecture:** Four internal packages build bottom-up: `authkeys` gains whole-file parsing + a fingerprint diff; `config` loads/validates the YAML manifest; `audit` orchestrates a bounded worker pool against a `KeyReader` seam and renders the report; `sshread` is the thin real SSH implementation (agent auth, strict known_hosts, remote `cat` with exit-status semantics). `cmd/sshepherd` migrates to Cobra and wires it together. Everything except `sshread`'s network lines is unit-tested; `sshread` gets a dockerized-sshd integration test behind a build tag.

**Tech Stack:** Go 1.26, `golang.org/x/crypto/ssh` (+`agent`, `knownhosts`), `gopkg.in/yaml.v3`, `github.com/spf13/cobra`.

**Workflow notes (project conventions):**
- Solo dev, trunk-based: commit directly to `master` after each task. No branches/PRs.
- lefthook pre-commit runs `gofmt` + gitleaks automatically; pre-push runs vet/lint/test.
- `depguard` in `.golangci.yml` is **deny-only in lax mode** — adding cobra/yaml requires **no** `.golangci.yml` change (the spec's "update allowlist" note is satisfied vacuously; do not edit that file).
- Lint gotchas to respect in all code: wrap external errors with `%w` (`wrapcheck`/`errorlint`), thread `context.Context` (`contextcheck`/`noctx`), keep functions under gocyclo 15 (split helpers), `fmt.Fprint*` error returns may be ignored (errcheck excluded).

**Interface contracts used across tasks (single source of truth):**

```go
// internal/authkeys
type ParseError struct{ Line int; Err error }               // Line is 1-based
func ParseFile(data []byte) ([]Key, []ParseError)
type Result struct{ OK, Missing, Unauthorized []Key }
func Diff(desired, actual []Key) Result

// internal/config
type Config struct{ Users []User; Servers []Server; Access []Access }
type User struct{ Name, Description, Comment string; Keys []string }
type Server struct{ Name, Description, Host string; Port int; User string }
type Access struct{ User string; Servers []string }
func Load(path string) (*Config, error)
func Parse(data []byte) (*Config, error)
func (c *Config) DesiredFor(serverName string) []authkeys.Key
func (c *Config) OwnerOf(fingerprint string) (User, bool)

// internal/audit
type ReadResult struct{ Content []byte; FileAbsent bool }
type KeyReader interface {
    ReadAuthorizedKeys(ctx context.Context, srv config.Server) (ReadResult, error)
}
type ServerResult struct {
    Server         config.Server
    Err            error
    FileAbsent     bool
    NoUsersGranted bool
    ParseErrs      []authkeys.ParseError
    Diff           authkeys.Result
}
func (r ServerResult) Compliant() bool
type Options struct{ Parallel int; PerServerTimeout time.Duration }
func Run(ctx context.Context, cfg *config.Config, reader KeyReader, opts Options) []ServerResult
func Render(w io.Writer, cfg *config.Config, results []ServerResult)
func ExitCode(results []ServerResult) int   // 0 or 1

// internal/sshread
type Client struct{ KnownHostsPath, AgentSock string; DialTimeout time.Duration }
func (c *Client) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (audit.ReadResult, error)
func CheckAgent(sock string) error

// internal/testkeys (test helper package)
func Line(tb testing.TB, seed byte) string   // deterministic valid ssh-ed25519 line
```

---

### Task 1: `internal/testkeys` — deterministic test key helper

Multiple packages (config, audit, cmd) need distinct valid public keys in tests.
One tiny shared helper avoids three copies of the same ed25519-from-seed trick
(authkeys' own tests keep their local helper; don't churn them).

**Files:**
- Create: `internal/testkeys/testkeys.go`

- [x] **Step 1: Write the helper** (no TDD cycle — it *is* test infrastructure; its consumers' tests exercise it)

```go
// Package testkeys generates deterministic SSH public keys for tests.
// Public keys are not secret, so fixed seeds are fine and keep tests hermetic.
package testkeys

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Line returns a valid ssh-ed25519 authorized_keys line derived from seed.
// Different seeds yield different keys; the same seed always yields the same key.
func Line(tb testing.TB, seed byte) string {
	tb.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(raw).Public())
	if err != nil {
		tb.Fatalf("testkeys: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}
```

- [x] **Step 2: Verify it compiles and existing suite stays green**

Run: `go build ./... && go test ./...`
Expected: PASS (nothing imports it yet; `unused` linter does not flag exported identifiers).

- [x] **Step 3: Commit**

```bash
git add internal/testkeys/testkeys.go
git commit -m "test: add internal/testkeys deterministic key helper"
```

---

### Task 2: `authkeys.ParseFile` + `ParseError`

**Files:**
- Modify: `internal/authkeys/authkeys.go` (append after `ParseLine`)
- Modify: `internal/authkeys/authkeys_test.go` (append)

- [x] **Step 1: Write the failing tests** (append to `authkeys_test.go`)

```go
func TestParseFileMixed(t *testing.T) {
	line := testKeyLine(t)
	data := []byte("# header comment\n\n" + line + " alice@laptop\ngarbage line here\n" + line + "\n")
	keys, errs := ParseFile(data)
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}
	if keys[0].Comment != "alice@laptop" {
		t.Errorf("keys[0].Comment = %q, want alice@laptop", keys[0].Comment)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly 1", errs)
	}
	if errs[0].Line != 4 {
		t.Errorf("errs[0].Line = %d, want 4 (1-based)", errs[0].Line)
	}
	if !strings.Contains(errs[0].Error(), "line 4") {
		t.Errorf("Error() = %q, want it to mention line 4", errs[0].Error())
	}
}

func TestParseFileEmpty(t *testing.T) {
	keys, errs := ParseFile(nil)
	if len(keys) != 0 || len(errs) != 0 {
		t.Errorf("ParseFile(nil) = %d keys, %d errs; want 0, 0", len(keys), len(errs))
	}
}

func TestParseFileCRLF(t *testing.T) {
	data := []byte(testKeyLine(t) + "\r\n")
	keys, errs := ParseFile(data)
	if len(errs) != 0 {
		t.Fatalf("CRLF input produced errors: %v", errs)
	}
	if len(keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(keys))
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/authkeys/ -run TestParseFile -v`
Expected: FAIL — `undefined: ParseFile`

- [x] **Step 3: Implement** (append to `authkeys.go`)

```go
// ParseError describes a single unparseable line in an authorized_keys file.
type ParseError struct {
	Line int // 1-based line number
	Err  error
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

// ParseFile parses a whole authorized_keys file. Blank and comment lines are
// skipped. Every line that is neither is either a parsed Key or a ParseError
// carrying its 1-based line number, so a file can be partially usable while
// still reporting exactly what could not be read.
func ParseFile(data []byte) ([]Key, []ParseError) {
	var keys []Key
	var errs []ParseError
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		k, err := ParseLine(line)
		switch {
		case err != nil:
			errs = append(errs, ParseError{Line: i + 1, Err: err})
		case k != nil:
			keys = append(keys, *k)
		}
	}
	return keys, errs
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/authkeys/ -v`
Expected: PASS (all, including pre-existing tests)

- [x] **Step 5: Commit**

```bash
git add internal/authkeys/authkeys.go internal/authkeys/authkeys_test.go
git commit -m "feat(authkeys): whole-file parsing with line-numbered errors"
```

---

### Task 3: `authkeys.Diff`

**Files:**
- Modify: `internal/authkeys/authkeys.go` (append)
- Modify: `internal/authkeys/authkeys_test.go` (append)

- [x] **Step 1: Write the failing test.** Note: `testKeyLine` produces one fixed key; for a second distinct key add a tiny local variant helper (kept local — the shared `testkeys` package needs `testing.TB` import and this package predates it).

```go
// secondKeyLine builds a second, distinct deterministic key.
func secondKeyLine(t *testing.T) string {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(255 - i)
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		t.Fatalf("secondKeyLine: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

func mustKey(t *testing.T, line string) Key {
	t.Helper()
	k, err := ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("mustKey(%q): %v", line, err)
	}
	return *k
}

func TestDiff(t *testing.T) {
	a := mustKey(t, testKeyLine(t))   // in both
	b := mustKey(t, secondKeyLine(t)) // desired only / actual only per case

	tests := []struct {
		name                       string
		desired, actual            []Key
		wantOK, wantMiss, wantUnau int
	}{
		{"all compliant", []Key{a}, []Key{a}, 1, 0, 0},
		{"missing", []Key{a, b}, []Key{a}, 1, 1, 0},
		{"unauthorized", []Key{a}, []Key{a, b}, 1, 0, 1},
		{"empty desired", nil, []Key{a}, 0, 0, 1},
		{"empty actual", []Key{a}, nil, 0, 1, 0},
		{"duplicate actual deduped", []Key{a}, []Key{a, a}, 1, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Diff(tt.desired, tt.actual)
			if len(r.OK) != tt.wantOK || len(r.Missing) != tt.wantMiss || len(r.Unauthorized) != tt.wantUnau {
				t.Errorf("Diff = OK:%d Missing:%d Unauthorized:%d, want %d/%d/%d",
					len(r.OK), len(r.Missing), len(r.Unauthorized),
					tt.wantOK, tt.wantMiss, tt.wantUnau)
			}
		})
	}
}

func TestDiffPreservesOrder(t *testing.T) {
	a := mustKey(t, testKeyLine(t))
	b := mustKey(t, secondKeyLine(t))
	r := Diff([]Key{b, a}, nil)
	if r.Missing[0].Fingerprint != b.Fingerprint {
		t.Error("Missing does not preserve desired order")
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/authkeys/ -run TestDiff -v`
Expected: FAIL — `undefined: Diff`

- [x] **Step 3: Implement** (append to `authkeys.go`)

```go
// Result is the outcome of diffing a desired key set against an actual one.
type Result struct {
	OK           []Key // fingerprint present in both
	Missing      []Key // desired but not installed
	Unauthorized []Key // installed but not desired
}

// Diff compares key sets by SHA256 fingerprint. Order is deterministic without
// sorting: OK and Missing follow desired order, Unauthorized follows actual
// order. Duplicate fingerprints in actual are collapsed (first occurrence wins).
func Diff(desired, actual []Key) Result {
	actualByFP := make(map[string]Key, len(actual))
	var actualOrder []string
	for _, k := range actual {
		if _, dup := actualByFP[k.Fingerprint]; !dup {
			actualByFP[k.Fingerprint] = k
			actualOrder = append(actualOrder, k.Fingerprint)
		}
	}
	desiredFP := make(map[string]bool, len(desired))
	var r Result
	for _, k := range desired {
		desiredFP[k.Fingerprint] = true
		if _, ok := actualByFP[k.Fingerprint]; ok {
			r.OK = append(r.OK, k)
		} else {
			r.Missing = append(r.Missing, k)
		}
	}
	for _, fp := range actualOrder {
		if !desiredFP[fp] {
			r.Unauthorized = append(r.Unauthorized, actualByFP[fp])
		}
	}
	return r
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/authkeys/ -v`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add internal/authkeys/authkeys.go internal/authkeys/authkeys_test.go
git commit -m "feat(authkeys): fingerprint-based desired/actual diff"
```

---

### Task 4: `FuzzParseFile` + Makefile fuzz target

**Files:**
- Modify: `internal/authkeys/fuzz_test.go` (append)
- Modify: `Makefile` (fuzz target, lines 66-68)

- [x] **Step 1: Add the fuzz target** (append to `fuzz_test.go`)

```go
// FuzzParseFile asserts whole-file parsing never panics on arbitrary input and
// reports coherent results: every error has a valid 1-based line number and
// every parsed key is self-consistent.
func FuzzParseFile(f *testing.F) {
	seeds := []string{
		"",
		"\n\n\n",
		"# only comments\n# more\n",
		"garbage\nmore garbage\n",
		"line1\r\nline2\r\n",
	}
	if line, err := deterministicKeyLine(); err == nil {
		seeds = append(seeds,
			line+"\n",
			"# c\n"+line+" alice@laptop\nnot a key\n"+line+"\n",
		)
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		keys, errs := ParseFile([]byte(in))
		for _, k := range keys {
			if k.Type == "" || k.Fingerprint == "" {
				t.Errorf("parsed key missing Type/Fingerprint for input %q", in)
			}
		}
		for _, e := range errs {
			if e.Line < 1 {
				t.Errorf("ParseError.Line = %d, want >= 1", e.Line)
			}
		}
	})
}
```

- [x] **Step 2: Run the new fuzzer briefly to prove it executes**

Run: `go test -run='^$' -fuzz=FuzzParseFile -fuzztime=10s ./internal/authkeys`
Expected: `elapsed: 10s ... PASS` (no crashers)

- [x] **Step 3: Update the Makefile fuzz target.** Replace:

```makefile
## fuzz: short fuzz run of the authorized_keys parser
fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzParseLine -fuzztime=30s ./internal/authkeys
```

with:

```makefile
## fuzz: short fuzz run of the authorized_keys parsers
fuzz:
	$(GO) test -run='^$$' -fuzz=FuzzParseLine -fuzztime=15s ./internal/authkeys
	$(GO) test -run='^$$' -fuzz=FuzzParseFile -fuzztime=15s ./internal/authkeys
```

- [x] **Step 4: Verify**

Run: `make fuzz`
Expected: both fuzzers run 15s each, PASS.

- [x] **Step 5: Commit**

```bash
git add internal/authkeys/fuzz_test.go Makefile
git commit -m "test(authkeys): fuzz whole-file parser; run both fuzzers in make fuzz"
```

---

### Task 5: `internal/config` — types, parsing, validation

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Modify: `go.mod` / `go.sum` (via `go get`)

- [x] **Step 1: Add the yaml dependency**

Run: `go get gopkg.in/yaml.v3 && go mod tidy`
Expected: `gopkg.in/yaml.v3` appears in go.mod.

- [x] **Step 2: Write the failing tests**

```go
package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// manifest builds a minimal valid YAML manifest with the given key lines.
func manifest(keyA, keyB string) string {
	return fmt.Sprintf(`
users:
  - name: alice
    description: "Platform team lead"
    comment: "alice@sshepherd"
    keys:
      - "%s"
  - name: bob
    keys:
      - "%s"
servers:
  - name: web-1
    description: "Primary web frontend"
    host: 10.0.0.1
    user: deploy
  - name: web-2
    host: 10.0.0.2
    port: 2222
    user: deploy
access:
  - user: alice
    servers: [web-1, web-2]
  - user: bob
    servers: [web-1]
`, keyA, keyB)
}

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(manifest(testkeys.Line(t, 1), testkeys.Line(t, 2))))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Users) != 2 || len(cfg.Servers) != 2 || len(cfg.Access) != 2 {
		t.Fatalf("counts = %d users, %d servers, %d access; want 2/2/2",
			len(cfg.Users), len(cfg.Servers), len(cfg.Access))
	}
	if cfg.Servers[0].Port != 22 {
		t.Errorf("web-1 Port = %d, want default 22", cfg.Servers[0].Port)
	}
	if cfg.Servers[1].Port != 2222 {
		t.Errorf("web-2 Port = %d, want 2222", cfg.Servers[1].Port)
	}
	if cfg.Users[0].Comment != "alice@sshepherd" {
		t.Errorf("alice Comment = %q", cfg.Users[0].Comment)
	}
}

func TestParseEmptyManifest(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse(empty): %v", err)
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("empty manifest has %d servers", len(cfg.Servers))
	}
}

func TestParseInvalid(t *testing.T) {
	kA := func(t *testing.T) string { return testkeys.Line(t, 1) }
	tests := []struct {
		name, yaml, wantErr string
	}{
		{"yaml syntax", "users: [", "parse manifest"},
		{"unknown field", "userz:\n  - name: x\n", "field userz not found"},
		{"dup user name", `
users:
  - {name: alice, keys: ["` + "KEYA" + `"]}
  - {name: alice, keys: ["` + "KEYB" + `"]}
`, "duplicate user"},
		{"dup server name", `
servers:
  - {name: s, host: h, user: u}
  - {name: s, host: h2, user: u}
`, "duplicate server"},
		{"bad key", `
users:
  - {name: alice, keys: ["not a key"]}
`, "not a key"},
		{"dup key same user", `
users:
  - name: alice
    keys: ["KEYA", "KEYA"]
`, "duplicate key"},
		{"dup key across users", `
users:
  - {name: alice, keys: ["KEYA"]}
  - {name: bob, keys: ["KEYA"]}
`, "duplicate key"},
		{"access unknown user", `
access:
  - {user: ghost, servers: []}
`, "unknown user"},
		{"access unknown server", `
users:
  - {name: alice, keys: ["KEYA"]}
access:
  - {user: alice, servers: [nope]}
`, "unknown server"},
		{"server missing host", `
servers:
  - {name: s, user: u}
`, "host"},
		{"server bad port", `
servers:
  - {name: s, host: h, user: u, port: 70000}
`, "port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := strings.ReplaceAll(tt.yaml, "KEYA", kA(t))
			y = strings.ReplaceAll(y, "KEYB", testkeys.Line(t, 2))
			_, err := Parse([]byte(y))
			if err == nil {
				t.Fatal("Parse succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestAccessUnion(t *testing.T) {
	y := `
users:
  - {name: alice, keys: ["` + "KEYA" + `"]}
servers:
  - {name: s1, host: h1, user: u}
  - {name: s2, host: h2, user: u}
access:
  - {user: alice, servers: [s1]}
  - {user: alice, servers: [s2, s1]}
`
	cfg, err := Parse([]byte(strings.ReplaceAll(y, "KEYA", testkeys.Line(t, 1))))
	if err != nil {
		t.Fatalf("Parse: %v (multiple access entries for one user must union, not error)", err)
	}
	if got := len(cfg.DesiredFor("s2")); got != 1 {
		t.Errorf("DesiredFor(s2) = %d keys, want 1", got)
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("does-not-exist.yaml"); err == nil {
		t.Error("Load(missing) = nil error, want error")
	}
}
```

(`TestAccessUnion` references `DesiredFor` — implemented in Task 6; until then it fails to compile. To keep this task self-contained, implement `DesiredFor`'s storage in this task and the method itself in Task 6 — **or simpler: keep both tasks' order and only run the full file at Task 6**. Concretely: write all tests above EXCEPT `TestAccessUnion` now; `TestAccessUnion` is added in Task 6.)

- [x] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/config/ -v`
Expected: FAIL — `undefined: Parse`, `undefined: Load`

- [x] **Step 4: Implement `internal/config/config.go`**

```go
// Package config loads and validates the SSHepherd source-of-truth manifest:
// users (with their public keys), servers, and which users may access which
// servers. Validation is strict — a manifest that parses is safe to act on.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// User is a person (or role) and the public keys that identify them.
type User struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"` // docs only, never sent to a server
	Comment     string   `yaml:"comment"`     // written as the key comment by the apply slice
	Keys        []string `yaml:"keys"`
}

// Server is one machine in the fleet and the account we manage on it.
type Server struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"` // docs only
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"` // defaults to 22
	User        string `yaml:"user"`
}

// Access grants one user access to a list of servers.
type Access struct {
	User    string   `yaml:"user"`
	Servers []string `yaml:"servers"`
}

// Config is the parsed, validated manifest.
type Config struct {
	Users   []User   `yaml:"users"`
	Servers []Server `yaml:"servers"`
	Access  []Access `yaml:"access"`

	// Built during validation.
	keysByUser map[string][]authkeys.Key // user name -> parsed keys, manifest order
	owners     map[string]User           // fingerprint -> owning user
	grants     map[string][]string       // server name -> user names, access order
}

// Load reads and parses the manifest at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the user's own --config flag
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return Parse(data)
}

// Parse parses and validates a manifest. Unknown YAML fields are rejected so
// typos (e.g. "commment") fail loudly instead of being silently ignored.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	var errs []error
	errs = append(errs, c.validateUsers()...)
	errs = append(errs, c.validateServers()...)
	errs = append(errs, c.validateAccess()...)
	return errors.Join(errs...)
}

func (c *Config) validateUsers() []error {
	var errs []error
	c.keysByUser = make(map[string][]authkeys.Key)
	c.owners = make(map[string]User)
	seen := make(map[string]bool)
	for _, u := range c.Users {
		if u.Name == "" {
			errs = append(errs, errors.New("user with empty name"))
			continue
		}
		if seen[u.Name] {
			errs = append(errs, fmt.Errorf("duplicate user %q", u.Name))
			continue
		}
		seen[u.Name] = true
		for i, line := range u.Keys {
			k, err := authkeys.ParseLine(line)
			if err != nil {
				errs = append(errs, fmt.Errorf("user %q key %d: %w", u.Name, i+1, err))
				continue
			}
			if k == nil {
				errs = append(errs, fmt.Errorf("user %q key %d: blank entry is not a key", u.Name, i+1))
				continue
			}
			if owner, dup := c.owners[k.Fingerprint]; dup {
				errs = append(errs, fmt.Errorf("duplicate key %s: already owned by %q, repeated under %q",
					k.Fingerprint, owner.Name, u.Name))
				continue
			}
			c.owners[k.Fingerprint] = u
			c.keysByUser[u.Name] = append(c.keysByUser[u.Name], *k)
		}
	}
	return errs
}

func (c *Config) validateServers() []error {
	var errs []error
	seen := make(map[string]bool)
	for i := range c.Servers {
		s := &c.Servers[i]
		if s.Name == "" {
			errs = append(errs, errors.New("server with empty name"))
			continue
		}
		if seen[s.Name] {
			errs = append(errs, fmt.Errorf("duplicate server %q", s.Name))
			continue
		}
		seen[s.Name] = true
		if s.Host == "" {
			errs = append(errs, fmt.Errorf("server %q: host is required", s.Name))
		}
		if s.User == "" {
			errs = append(errs, fmt.Errorf("server %q: user is required", s.Name))
		}
		if s.Port == 0 {
			s.Port = 22
		}
		if s.Port < 1 || s.Port > 65535 {
			errs = append(errs, fmt.Errorf("server %q: port %d out of range", s.Name, s.Port))
		}
	}
	return errs
}

func (c *Config) validateAccess() []error {
	var errs []error
	users := make(map[string]bool, len(c.Users))
	for _, u := range c.Users {
		users[u.Name] = true
	}
	servers := make(map[string]bool, len(c.Servers))
	for _, s := range c.Servers {
		servers[s.Name] = true
	}
	c.grants = make(map[string][]string)
	granted := make(map[string]map[string]bool) // server -> user -> already granted
	for _, a := range c.Access {
		if !users[a.User] {
			errs = append(errs, fmt.Errorf("access: unknown user %q", a.User))
			continue
		}
		for _, srv := range a.Servers {
			if !servers[srv] {
				errs = append(errs, fmt.Errorf("access for %q: unknown server %q", a.User, srv))
				continue
			}
			if granted[srv] == nil {
				granted[srv] = make(map[string]bool)
			}
			if granted[srv][a.User] { // multiple entries union silently
				continue
			}
			granted[srv][a.User] = true
			c.grants[srv] = append(c.grants[srv], a.User)
		}
	}
	return errs
}
```

- [x] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS

- [x] **Step 6: Commit**

```bash
git add go.mod go.sum internal/config/
git commit -m "feat(config): YAML manifest parsing with strict validation"
```

---

### Task 6: `config.DesiredFor` + `config.OwnerOf`

**Files:**
- Modify: `internal/config/config.go` (append)
- Modify: `internal/config/config_test.go` (append `TestAccessUnion` from Task 5, plus below)

- [x] **Step 1: Write the failing tests** (append; also add `TestAccessUnion` from Task 5 now)

```go
func TestDesiredForAndOwnerOf(t *testing.T) {
	cfg, err := Parse([]byte(manifest(testkeys.Line(t, 1), testkeys.Line(t, 2))))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	web1 := cfg.DesiredFor("web-1") // alice + bob
	if len(web1) != 2 {
		t.Fatalf("DesiredFor(web-1) = %d keys, want 2", len(web1))
	}
	web2 := cfg.DesiredFor("web-2") // alice only
	if len(web2) != 1 {
		t.Fatalf("DesiredFor(web-2) = %d keys, want 1", len(web2))
	}
	if len(cfg.DesiredFor("nonexistent")) != 0 {
		t.Error("DesiredFor(nonexistent) should be empty")
	}

	owner, ok := cfg.OwnerOf(web2[0].Fingerprint)
	if !ok || owner.Name != "alice" {
		t.Errorf("OwnerOf = %q, %v; want alice, true", owner.Name, ok)
	}
	if _, ok := cfg.OwnerOf("SHA256:nope"); ok {
		t.Error("OwnerOf(unknown) = true, want false")
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/config/ -v`
Expected: FAIL — `undefined: cfg.DesiredFor` / `cfg.OwnerOf`

- [x] **Step 3: Implement** (append to `config.go`)

```go
// DesiredFor returns the desired key set for a server: the union of the keys
// of every user granted access to it, in manifest/access order (deterministic).
func (c *Config) DesiredFor(serverName string) []authkeys.Key {
	var keys []authkeys.Key
	for _, userName := range c.grants[serverName] {
		keys = append(keys, c.keysByUser[userName]...)
	}
	return keys
}

// OwnerOf resolves a key fingerprint to the user that owns it in the manifest.
func (c *Config) OwnerOf(fingerprint string) (User, bool) {
	u, ok := c.owners[fingerprint]
	return u, ok
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v`
Expected: PASS (including `TestAccessUnion`)

- [x] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "feat(config): desired-key computation and fingerprint ownership lookup"
```

---

### Task 7: `internal/audit` — seam types + single-server audit

**Files:**
- Create: `internal/audit/audit.go`
- Create: `internal/audit/audit_test.go`

- [x] **Step 1: Write the failing tests**

```go
package audit

import (
	"context"
	"errors"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeReader returns canned results per server name.
type fakeReader struct {
	byName map[string]ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return ReadResult{}, err
	}
	return f.byName[srv.Name], nil
}

// testConfig: alice(key1)->web-1; server orphan has no grants.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: orphan, host: 10.0.0.9, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("test config: %v", err)
	}
	return cfg
}

func TestAuditOneCompliant(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if !res.Compliant() {
		t.Errorf("want compliant, got %+v", res)
	}
	if len(res.Diff.OK) != 1 {
		t.Errorf("OK = %d, want 1", len(res.Diff.OK))
	}
}

func TestAuditOneDrift(t *testing.T) {
	cfg := testConfig(t)
	// web-1 has an unauthorized key installed and alice's key missing.
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 9) + "\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if res.Compliant() {
		t.Error("want non-compliant")
	}
	if len(res.Diff.Missing) != 1 || len(res.Diff.Unauthorized) != 1 {
		t.Errorf("Missing=%d Unauthorized=%d, want 1/1",
			len(res.Diff.Missing), len(res.Diff.Unauthorized))
	}
}

func TestAuditOneConnectionError(t *testing.T) {
	cfg := testConfig(t)
	boom := errors.New("dial tcp: connection refused")
	r := &fakeReader{errs: map[string]error{"web-1": boom}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if res.Compliant() {
		t.Error("errored server must be non-compliant")
	}
	if !errors.Is(res.Err, boom) {
		t.Errorf("Err = %v, want the reader error", res.Err)
	}
}

func TestAuditOneFileAbsent(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1": {FileAbsent: true},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if !res.FileAbsent {
		t.Error("FileAbsent not propagated")
	}
	if len(res.Diff.Missing) != 1 {
		t.Errorf("Missing = %d, want 1 (desired key not installed)", len(res.Diff.Missing))
	}
}

func TestAuditOneParseErrors(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\ngarbage\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[0], 0)
	if len(res.ParseErrs) != 1 {
		t.Fatalf("ParseErrs = %d, want 1", len(res.ParseErrs))
	}
	if res.Compliant() {
		t.Error("unparseable file must be non-compliant")
	}
}

func TestAuditOneNoUsersGranted(t *testing.T) {
	cfg := testConfig(t)
	r := &fakeReader{byName: map[string]ReadResult{
		"orphan": {Content: []byte(testkeys.Line(t, 9) + "\n")},
	}}
	res := auditOne(context.Background(), cfg, r, cfg.Servers[1], 0)
	if !res.NoUsersGranted {
		t.Error("NoUsersGranted = false, want true")
	}
	if len(res.Diff.Unauthorized) != 1 {
		t.Errorf("Unauthorized = %d, want 1", len(res.Diff.Unauthorized))
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/audit/ -v`
Expected: FAIL — undefined types.

- [x] **Step 3: Implement `internal/audit/audit.go`**

```go
// Package audit orchestrates the drift audit: it fans out over the fleet,
// fetches each server's actual authorized_keys through the KeyReader seam,
// diffs against the manifest's desired state, and renders a report.
package audit

import (
	"context"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// ReadResult is the outcome of reading a server's authorized_keys.
// FileAbsent means login succeeded but the audited file does not exist —
// a strong signal sshd consults a different key source on that host.
type ReadResult struct {
	Content    []byte
	FileAbsent bool
}

// KeyReader fetches a server's current authorized_keys. Implementations must
// honor ctx cancellation/deadlines.
type KeyReader interface {
	ReadAuthorizedKeys(ctx context.Context, srv config.Server) (ReadResult, error)
}

// ServerResult is the audit outcome for one server.
type ServerResult struct {
	Server         config.Server
	Err            error // connection/auth/host-key/read failure: server unauditable
	FileAbsent     bool
	NoUsersGranted bool
	ParseErrs      []authkeys.ParseError
	Diff           authkeys.Result
}

// Compliant reports whether this server fully matches the source of truth.
// An unauditable or partially-unreadable server is never compliant.
func (r ServerResult) Compliant() bool {
	return r.Err == nil &&
		len(r.ParseErrs) == 0 &&
		len(r.Diff.Missing) == 0 &&
		len(r.Diff.Unauthorized) == 0
}

// auditOne audits a single server. It is self-contained and shares no mutable
// state, so Run can execute many of these concurrently.
func auditOne(ctx context.Context, cfg *config.Config, reader KeyReader, srv config.Server, timeout time.Duration) ServerResult {
	res := ServerResult{Server: srv}
	desired := cfg.DesiredFor(srv.Name)
	res.NoUsersGranted = len(desired) == 0

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	read, err := reader.ReadAuthorizedKeys(ctx, srv)
	if err != nil {
		res.Err = err
		return res
	}
	res.FileAbsent = read.FileAbsent

	actual, parseErrs := authkeys.ParseFile(read.Content)
	res.ParseErrs = parseErrs
	res.Diff = authkeys.Diff(desired, actual)
	return res
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test -race ./internal/audit/ -v`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add internal/audit/
git commit -m "feat(audit): KeyReader seam and single-server drift audit"
```

---

### Task 8: `audit.Run` — bounded concurrent fan-out

**Files:**
- Modify: `internal/audit/audit.go` (append)
- Modify: `internal/audit/audit_test.go` (append)

- [x] **Step 1: Write the failing tests** (append; add imports `"strings"`, `"sync/atomic"`, `"time"`, `"fmt"`)

```go
// gateReader tracks concurrency and can block until released or ctx expiry.
type gateReader struct {
	inflight, maxSeen atomic.Int32
	block             map[string]bool // server names that hang until ctx is done
	delay             time.Duration
}

func (g *gateReader) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (ReadResult, error) {
	cur := g.inflight.Add(1)
	defer g.inflight.Add(-1)
	for {
		prev := g.maxSeen.Load()
		if cur <= prev || g.maxSeen.CompareAndSwap(prev, cur) {
			break
		}
	}
	if g.block[srv.Name] {
		<-ctx.Done()
		return ReadResult{}, fmt.Errorf("read %s: %w", srv.Name, ctx.Err())
	}
	if g.delay > 0 {
		time.Sleep(g.delay)
	}
	return ReadResult{}, nil
}

// fleetConfig builds a config with n servers named srv-00 .. srv-N, no users.
func fleetConfig(t *testing.T, n int) *config.Config {
	t.Helper()
	var sb strings.Builder
	sb.WriteString("servers:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "  - {name: srv-%02d, host: 10.0.0.%d, user: deploy}\n", i, i+1)
	}
	cfg, err := config.Parse([]byte(sb.String()))
	if err != nil {
		t.Fatalf("fleetConfig: %v", err)
	}
	return cfg
}

func TestRunPoolCap(t *testing.T) {
	cfg := fleetConfig(t, 20)
	g := &gateReader{delay: 20 * time.Millisecond}
	Run(context.Background(), cfg, g, Options{Parallel: 3})
	if max := g.maxSeen.Load(); max > 3 {
		t.Errorf("max concurrent reads = %d, want <= 3", max)
	}
}

func TestRunDeterministicOrder(t *testing.T) {
	cfg := fleetConfig(t, 10)
	g := &gateReader{delay: time.Millisecond}
	results := Run(context.Background(), cfg, g, Options{Parallel: 8})
	if len(results) != 10 {
		t.Fatalf("results = %d, want 10", len(results))
	}
	for i, r := range results {
		want := fmt.Sprintf("srv-%02d", i)
		if r.Server.Name != want {
			t.Fatalf("results[%d] = %s, want %s (sorted by name)", i, r.Server.Name, want)
		}
	}
}

func TestRunHangingServerDoesNotPoisonOthers(t *testing.T) {
	cfg := fleetConfig(t, 5)
	g := &gateReader{block: map[string]bool{"srv-02": true}}
	results := Run(context.Background(), cfg, g, Options{
		Parallel:         5,
		PerServerTimeout: 50 * time.Millisecond,
	})
	var hung, fine int
	for _, r := range results {
		if r.Server.Name == "srv-02" {
			if r.Err == nil {
				t.Error("hanging server should have timed out with an error")
			}
			hung++
		} else if r.Err == nil {
			fine++
		}
	}
	if hung != 1 || fine != 4 {
		t.Errorf("hung=%d fine=%d, want 1/4", hung, fine)
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test -race ./internal/audit/ -run TestRun -v`
Expected: FAIL — `undefined: Run`, `undefined: Options`

- [x] **Step 3: Implement** (append to `audit.go`; add imports `"sort"`, `"sync"`)

```go
// Options tunes the fleet fan-out.
type Options struct {
	Parallel         int           // max concurrent server audits (>= 1)
	PerServerTimeout time.Duration // overall deadline per server; 0 = none
}

// Run audits every server concurrently through a bounded worker pool and
// returns results sorted by server name, so output is deterministic no matter
// the completion order.
func Run(ctx context.Context, cfg *config.Config, reader KeyReader, opts Options) []ServerResult {
	if opts.Parallel < 1 {
		opts.Parallel = 1
	}
	results := make([]ServerResult, len(cfg.Servers))
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	for i, srv := range cfg.Servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = auditOne(ctx, cfg, reader, srv, opts.PerServerTimeout)
		}()
	}
	wg.Wait()
	sort.Slice(results, func(a, b int) bool {
		return results[a].Server.Name < results[b].Server.Name
	})
	return results
}
```

- [x] **Step 4: Run tests to verify they pass (race detector mandatory here)**

Run: `go test -race ./internal/audit/ -v`
Expected: PASS, no race reports.

- [x] **Step 5: Commit**

```bash
git add internal/audit/
git commit -m "feat(audit): bounded concurrent fleet fan-out with deterministic results"
```

---

### Task 9: Report rendering + exit code (golden tests)

**Files:**
- Create: `internal/audit/report.go`
- Create: `internal/audit/report_test.go`
- Create: `internal/audit/testdata/report_drift.golden` (generated via `-update`)
- Create: `internal/audit/testdata/report_compliant.golden` (generated via `-update`)

Report format decisions (locks the spec's illustrative example into concrete rules):
- Full SHA256 fingerprints (greppable/auditable), aligned with `text/tabwriter`.
- Key label: owner's `Name`, plus ` (comment)` when `Comment` is set; `(unknown)` for unauthorized keys.
- Line order per server: OK (desired order) → Missing (desired order) → Unauthorized (actual order) → parse errors → notes → counts.
- Report → stdout; the caller decides what goes to stderr.

- [x] **Step 1: Write the failing golden tests**

```go
package audit

import (
	"bytes"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"testing"

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

// reportConfig: alice(k1)+bob(k2) -> web-1; nothing -> web-2.
func reportConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, comment: "alice@sshepherd", keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("reportConfig: %v", err)
	}
	return cfg
}

func TestRenderDrift(t *testing.T) {
	cfg := reportConfig(t)
	// web-1: alice ok, bob missing, one unauthorized, one parse error.
	// web-2: unreachable.
	reader := &fakeReader{
		byName: map[string]ReadResult{
			"web-1": {Content: []byte(
				testkeys.Line(t, 1) + " alice@laptop\n" +
					testkeys.Line(t, 9) + " who@is-this\n" +
					"garbage entry\n")},
		},
		errs: map[string]error{
			"web-2": errors.New("dial tcp 10.0.0.2:22: connection refused"),
		},
	}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results)
	checkGolden(t, "report_drift.golden", buf.Bytes())
	if ExitCode(results) != 1 {
		t.Errorf("ExitCode = %d, want 1", ExitCode(results))
	}
}

func TestRenderCompliant(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results)
	checkGolden(t, "report_compliant.golden", buf.Bytes())
	if ExitCode(results) != 0 {
		t.Errorf("ExitCode = %d, want 0", ExitCode(results))
	}
}

func TestRenderEmptyFleet(t *testing.T) {
	var buf bytes.Buffer
	Render(&buf, &config.Config{}, nil)
	if !bytes.Contains(buf.Bytes(), []byte("0 servers")) {
		t.Errorf("empty-fleet output = %q, want a '0 servers' note", buf.String())
	}
	if ExitCode(nil) != 0 {
		t.Errorf("ExitCode(nil) = %d, want 0", ExitCode(nil))
	}
}

func TestRenderFileAbsentDiagnostic(t *testing.T) {
	cfg := reportConfig(t)
	reader := &fakeReader{byName: map[string]ReadResult{
		"web-1": {FileAbsent: true},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results)
	out := buf.String()
	if !strings.Contains(out, "another key source") {
		t.Errorf("file-absent diagnostic missing from:\n%s", out)
	}
}
```

(Add `"context"` and `"strings"` to the test file's imports.)

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/audit/ -run TestRender -v`
Expected: FAIL — `undefined: Render`, `undefined: ExitCode`

- [x] **Step 3: Implement `internal/audit/report.go`**

```go
package audit

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// ExitCode maps audit results to the process exit code: 0 only when every
// server is compliant. An empty fleet is trivially compliant.
func ExitCode(results []ServerResult) int {
	for _, r := range results {
		if !r.Compliant() {
			return 1
		}
	}
	return 0
}

// Render writes the human-readable audit report. The report is the command's
// stdout product; diagnostics beyond the report belong on stderr (caller's
// concern).
func Render(w io.Writer, cfg *config.Config, results []ServerResult) {
	if len(results) == 0 {
		fmt.Fprintln(w, "Summary: 0 servers configured — nothing to audit")
		return
	}
	for _, r := range results {
		renderServer(w, cfg, r)
		fmt.Fprintln(w)
	}
	renderSummary(w, results)
}

func renderServer(w io.Writer, cfg *config.Config, r ServerResult) {
	head := fmt.Sprintf("%s (%s@%s:%d)", r.Server.Name, r.Server.User, r.Server.Host, r.Server.Port)
	if r.Err != nil {
		fmt.Fprintf(w, "%s  ERROR: %v\n", head, r.Err)
		return
	}
	fmt.Fprintln(w, head)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range r.Diff.OK {
		fmt.Fprintf(tw, "  ✓\t%s\t%s\t%s\tpresent & authorized\n", label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, k := range r.Diff.Missing {
		fmt.Fprintf(tw, "  ✗\t%s\t%s\t%s\tauthorized but MISSING\n", label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, k := range r.Diff.Unauthorized {
		fmt.Fprintf(tw, "  ⚠\t(unknown)\t%s\t%s\tinstalled but UNAUTHORIZED\n", k.Fingerprint, k.Type)
	}
	_ = tw.Flush()

	for _, pe := range r.ParseErrs {
		fmt.Fprintf(w, "  ⚠ line %d: unparseable entry\n", pe.Line)
	}
	if r.FileAbsent {
		fmt.Fprintln(w, "  note: login succeeded but the audited authorized_keys file is absent —")
		fmt.Fprintln(w, "        sshd likely consults another key source (custom AuthorizedKeysFile,")
		fmt.Fprintln(w, "        AuthorizedKeysCommand, or CA certificates); this server may not be")
		fmt.Fprintln(w, "        auditable via this file")
	} else if emptyFile(r) {
		fmt.Fprintln(w, "  note: login succeeded but the audited authorized_keys file is empty —")
		fmt.Fprintln(w, "        sshd likely consults another key source; see file-absent guidance")
	}
	if r.NoUsersGranted {
		fmt.Fprintln(w, "  note: no users granted access in the manifest")
	}

	fmt.Fprintf(w, "  → %d authorized · %d present · %d missing · %d unauthorized\n",
		len(r.Diff.OK)+len(r.Diff.Missing), len(r.Diff.OK),
		len(r.Diff.Missing), len(r.Diff.Unauthorized))
}

// emptyFile reports the paradox case: connection fine, file present, zero
// entries parsed and nothing unparseable — yet our login key got us in.
func emptyFile(r ServerResult) bool {
	return len(r.Diff.OK) == 0 && len(r.Diff.Unauthorized) == 0 &&
		len(r.ParseErrs) == 0 && !r.NoUsersGranted
}

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

func renderSummary(w io.Writer, results []ServerResult) {
	var compliant, drift, unreachable int
	for _, r := range results {
		switch {
		case r.Err != nil:
			unreachable++
		case r.Compliant():
			compliant++
		default:
			drift++
		}
	}
	fmt.Fprintf(w, "Summary: %d/%d servers compliant · %d with drift · %d unreachable  → exit %d\n",
		compliant, len(results), drift, unreachable, ExitCode(results))
}
```

- [x] **Step 4: Generate goldens, inspect them, then verify tests pass**

```bash
mkdir -p internal/audit/testdata
go test ./internal/audit/ -run TestRender -update
cat internal/audit/testdata/report_drift.golden   # eyeball: matches spec's report shape
go test -race ./internal/audit/ -v
```
Expected: final run PASS. The drift golden must show web-1 with ✓ alice / ✗ bob / ⚠ unknown / ⚠ line 3, web-2 ERROR line, and `Summary: 0/2 servers compliant · 1 with drift · 1 unreachable  → exit 1`.

- [x] **Step 5: Commit**

```bash
git add internal/audit/
git commit -m "feat(audit): report rendering with golden tests and exit-code mapping"
```

---

### Task 10: Fan-out + parser benchmarks

**Files:**
- Create: `internal/audit/bench_test.go`
- Modify: `internal/authkeys/authkeys_test.go` (append benchmarks)

- [x] **Step 1: Write the benchmarks**

`internal/audit/bench_test.go`:

```go
package audit

import (
	"context"
	"testing"
)

// BenchmarkRunFanout measures orchestration overhead with instant fakes:
// the baseline CLAUDE.md asks for on the fleet fan-out hot path.
func BenchmarkRunFanout(b *testing.B) {
	cfg := fleetConfig(b, 100)
	r := &gateReader{}
	opts := Options{Parallel: 10}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Run(context.Background(), cfg, r, opts)
	}
}
```

`fleetConfig` currently takes `*testing.T`; change its signature in `audit_test.go` to accept `testing.TB` (and `t.Helper()`/`t.Fatalf` work unchanged):

```go
func fleetConfig(t testing.TB, n int) *config.Config {
```

Append to `internal/authkeys/authkeys_test.go`:

```go
func BenchmarkParseFile(b *testing.B) {
	line, err := deterministicKeyLine()
	if err != nil {
		b.Fatal(err)
	}
	data := []byte(strings.Repeat(line+" user@host\n# comment\n", 100))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ParseFile(data)
	}
}

func BenchmarkDiff(b *testing.B) {
	line, err := deterministicKeyLine()
	if err != nil {
		b.Fatal(err)
	}
	k, _ := ParseLine(line)
	desired := make([]Key, 0, 50)
	for i := 0; i < 50; i++ {
		kk := *k
		kk.Fingerprint = fmt.Sprintf("SHA256:fake%04d", i)
		desired = append(desired, kk)
	}
	actual := append([]Key{}, desired[:25]...)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Diff(desired, actual)
	}
}
```

(Add `"fmt"` to that file's imports.)

- [x] **Step 2: Run them**

Run: `make bench`
Expected: all benchmarks execute with ns/op + B/op output, no failures.

- [x] **Step 3: Commit**

```bash
git add internal/audit/bench_test.go internal/audit/audit_test.go internal/authkeys/authkeys_test.go
git commit -m "test: benchmarks for fleet fan-out, ParseFile, and Diff"
```

---

### Task 11: `sshread` pure helpers — exit-status interpretation, agent check, host-key hint

**Files:**
- Create: `internal/sshread/sshread.go` (helpers only in this task)
- Create: `internal/sshread/sshread_test.go`

- [x] **Step 1: Write the failing tests**

```go
package sshread

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
)

func TestInterpretExit(t *testing.T) {
	tests := []struct {
		name       string
		code       int
		stderr     string
		wantAbsent bool
		wantErr    bool
	}{
		{"success", 0, "", false, false},
		{"file absent", fileAbsentExit, "", true, false},
		{"cat failure", 1, "cat: permission denied", false, true},
		{"other failure", 127, "sh: not found", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			absent, err := interpretExit(tt.code, tt.stderr)
			if absent != tt.wantAbsent {
				t.Errorf("absent = %v, want %v", absent, tt.wantAbsent)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.stderr != "" && !strings.Contains(err.Error(), strings.TrimSpace(tt.stderr)) {
				t.Errorf("err %q should include remote stderr", err)
			}
		})
	}
}

func TestCheckAgent(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		if err := CheckAgent(""); err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
			t.Errorf("CheckAgent(\"\") = %v, want SSH_AUTH_SOCK error", err)
		}
	})
	t.Run("dead socket", func(t *testing.T) {
		if err := CheckAgent(filepath.Join(t.TempDir(), "nope.sock")); err == nil {
			t.Error("CheckAgent(dead) = nil, want error")
		}
	})
	t.Run("live socket", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "agent.sock")
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		if err := CheckAgent(sock); err != nil {
			t.Errorf("CheckAgent(live) = %v, want nil", err)
		}
	})
}

func TestHostKeyHint(t *testing.T) {
	srv := config.Server{Name: "web-1", Host: "10.0.0.1", Port: 22, User: "deploy"}

	t.Run("unknown host gets keyscan hint", func(t *testing.T) {
		err := hostKeyHint(&knownhosts.KeyError{}, srv, "/kh")
		if !strings.Contains(err.Error(), "ssh-keyscan -p 22 10.0.0.1") {
			t.Errorf("hint = %q, want exact-host keyscan command", err)
		}
	})
	t.Run("changed key gets warning", func(t *testing.T) {
		err := hostKeyHint(&knownhosts.KeyError{Want: make([]knownhosts.KnownKey, 1)}, srv, "/kh")
		if !strings.Contains(err.Error(), "HOST KEY CHANGED") {
			t.Errorf("hint = %q, want changed-key warning", err)
		}
	})
	t.Run("unrelated error passes through", func(t *testing.T) {
		orig := net.ErrClosed
		if got := hostKeyHint(orig, srv, "/kh"); got != orig {
			t.Errorf("unrelated error was wrapped: %v", got)
		}
	})
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/sshread/ -v`
Expected: FAIL — undefined identifiers.

- [x] **Step 3: Implement the helpers** (`internal/sshread/sshread.go`)

```go
// Package sshread is the real KeyReader: it connects to a server over SSH
// (agent auth, strict known_hosts) and reads the remote authorized_keys.
// It is deliberately thin — decision logic lives in small pure helpers so the
// unit-test path stays hermetic; only the network glue needs the integration
// suite.
package sshread

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
)

// authorizedKeysCmd reads the default authorized_keys, using a distinctive
// exit code to signal "file does not exist" (vs. cat failing for other
// reasons). The path is fixed — no user input reaches the remote command.
const authorizedKeysCmd = `if [ -e ~/.ssh/authorized_keys ]; then cat ~/.ssh/authorized_keys; else exit 44; fi`

// fileAbsentExit is the sentinel exit status in authorizedKeysCmd.
const fileAbsentExit = 44

// interpretExit maps the remote command's exit status to read semantics.
func interpretExit(code int, stderr string) (fileAbsent bool, err error) {
	switch code {
	case 0:
		return false, nil
	case fileAbsentExit:
		return true, nil
	default:
		return false, fmt.Errorf("remote read failed (exit %d): %s", code, strings.TrimSpace(stderr))
	}
}

// CheckAgent verifies a usable SSH agent before any server is dialed, so a
// missing agent fails once with a clear message instead of once per server.
func CheckAgent(sock string) error {
	if sock == "" {
		return errors.New("no SSH agent: SSH_AUTH_SOCK is not set (start ssh-agent and ssh-add a key)")
	}
	conn, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		return fmt.Errorf("SSH agent unreachable at %s: %w", sock, err)
	}
	_ = conn.Close()
	return nil
}

// hostKeyHint augments knownhosts verification failures with actionable
// remediation. known_hosts entries are keyed by the exact host form used, so
// the hint names the configured host:port verbatim.
func hostKeyHint(err error, srv config.Server, knownHostsPath string) error {
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		return err
	}
	if len(ke.Want) == 0 {
		return fmt.Errorf(
			"%w\n  hint: host is not in %s; if you trust it, run: ssh-keyscan -p %d %s >> %s",
			err, knownHostsPath, srv.Port, srv.Host, knownHostsPath)
	}
	return fmt.Errorf("%w\n  hint: HOST KEY CHANGED for %s:%d — investigate before trusting this host",
		err, srv.Host, srv.Port)
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test -race ./internal/sshread/ -v`
Expected: PASS

- [x] **Step 5: Commit**

```bash
git add internal/sshread/
git commit -m "feat(sshread): exit-status semantics, agent preflight, host-key hints"
```

---

### Task 12: `sshread.Client` — the real SSH reader

**Files:**
- Modify: `internal/sshread/sshread.go` (append)
- Modify: `internal/sshread/sshread_test.go` (append cheap error-path tests)

- [x] **Step 1: Write the failing tests** (unit-testable error paths only; happy path is Task 15's integration test)

```go
func TestClientBadAgentSock(t *testing.T) {
	c := &Client{
		AgentSock:      filepath.Join(t.TempDir(), "nope.sock"),
		KnownHostsPath: filepath.Join(t.TempDir(), "kh"),
		DialTimeout:    time.Second,
	}
	srv := config.Server{Name: "s", Host: "127.0.0.1", Port: 1, User: "u"}
	_, err := c.ReadAuthorizedKeys(context.Background(), srv)
	if err == nil || !strings.Contains(err.Error(), "agent") {
		t.Errorf("err = %v, want agent connection error", err)
	}
}

func TestClientBadKnownHostsPath(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c := &Client{
		AgentSock:      sock,
		KnownHostsPath: filepath.Join(t.TempDir(), "does-not-exist"),
		DialTimeout:    time.Second,
	}
	srv := config.Server{Name: "s", Host: "127.0.0.1", Port: 1, User: "u"}
	_, err = c.ReadAuthorizedKeys(context.Background(), srv)
	if err == nil || !strings.Contains(err.Error(), "known_hosts") {
		t.Errorf("err = %v, want known_hosts load error", err)
	}
}
```

(Add `"context"` and `"time"` to the test file's imports.)

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/sshread/ -run TestClient -v`
Expected: FAIL — `undefined: Client`

- [x] **Step 3: Implement** (append to `sshread.go`; add imports `"bytes"`, `"context"`, `"strconv"`, `"golang.org/x/crypto/ssh"`, `"golang.org/x/crypto/ssh/agent"`, and `"github.com/javadh75/SSHepherd/internal/audit"`)

```go
// Client reads remote authorized_keys over SSH. It implements audit.KeyReader.
type Client struct {
	KnownHostsPath string
	AgentSock      string
	DialTimeout    time.Duration
}

var _ audit.KeyReader = (*Client)(nil)

// ReadAuthorizedKeys connects to srv (agent auth, strict known_hosts) and
// reads ~/.ssh/authorized_keys via a one-shot session. The ctx deadline (set
// by the audit orchestrator) bounds the whole exchange, not just the dial.
func (c *Client) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (audit.ReadResult, error) {
	var zero audit.ReadResult

	agentConn, err := net.Dial("unix", c.AgentSock)
	if err != nil {
		return zero, fmt.Errorf("connect ssh-agent: %w", err)
	}
	defer func() { _ = agentConn.Close() }() // errcheck: close error is uninteresting on a read path
	ag := agent.NewClient(agentConn)

	hostKeys, err := knownhosts.New(c.KnownHostsPath)
	if err != nil {
		return zero, fmt.Errorf("load known_hosts %s: %w", c.KnownHostsPath, err)
	}

	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	dialer := net.Dialer{Timeout: c.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return zero, fmt.Errorf("dial %s: %w", addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl) // bounds handshake + session I/O, not just dial
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            srv.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)},
		HostKeyCallback: hostKeys,
		Timeout:         c.DialTimeout,
	})
	if err != nil {
		_ = conn.Close()
		return zero, fmt.Errorf("ssh %s@%s: %w", srv.User, addr, hostKeyHint(err, srv, c.KnownHostsPath))
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		return zero, fmt.Errorf("open session on %s: %w", addr, err)
	}
	defer func() { _ = sess.Close() }()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	code := 0
	if runErr := sess.Run(authorizedKeysCmd); runErr != nil {
		var exitErr *ssh.ExitError
		if !errors.As(runErr, &exitErr) {
			return zero, fmt.Errorf("remote read on %s: %w", addr, runErr)
		}
		code = exitErr.ExitStatus()
	}
	absent, err := interpretExit(code, stderr.String())
	if err != nil {
		return zero, fmt.Errorf("remote read on %s: %w", addr, err)
	}
	if absent {
		return audit.ReadResult{FileAbsent: true}, nil
	}
	return audit.ReadResult{Content: stdout.Bytes()}, nil
}
```

- [x] **Step 4: Run tests + full unit suite**

Run: `go test -race ./... && go vet ./...`
Expected: PASS everywhere.

- [x] **Step 5: Commit**

```bash
git add internal/sshread/
git commit -m "feat(sshread): native SSH client — agent auth, strict known_hosts, ctx-bounded read"
```

---

### Task 13: Migrate `cmd/sshepherd` to Cobra (behavior-preserving)

The three existing tests in `run_test.go` define the contract: `--version` → 0
with "sshepherd" on stdout; no args → 2 with "no command" on stderr; unknown
flag → 2. Keep them green through the migration; do not modify them.

**Files:**
- Modify: `cmd/sshepherd/run.go` (full rewrite)
- Modify: `go.mod` / `go.sum` (via `go get`)
- Unchanged: `cmd/sshepherd/main.go`, `cmd/sshepherd/run_test.go`

- [x] **Step 1: Add the cobra dependency**

Run: `go get github.com/spf13/cobra && go mod tidy`

- [x] **Step 2: Rewrite `cmd/sshepherd/run.go`**

```go
package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// version is the binary version, overridden at build time via
// -ldflags "-X main.version=<v>". Defaults to "dev" for local builds.
var version = "dev"

// errNonCompliant signals exit code 1: the audit ran but the fleet is not
// (provably) compliant. Everything else non-nil maps to usage/config exit 2.
var errNonCompliant = errors.New("fleet not compliant")

// run is the testable entrypoint: it builds the Cobra tree, executes it
// against the provided streams, and maps errors to process exit codes.
func run(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd(stdout, stderr)
	root.SetArgs(args)
	err := root.Execute()
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errNonCompliant):
		return 1 // report already rendered; nothing more to say
	default:
		fmt.Fprintln(stderr, "sshepherd:", err)
		return 2
	}
}

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "sshepherd",
		Short:         "Manage SSH authorized_keys across a fleet of servers",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true, // run() prints errors with consistent formatting
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("no command given (try --help)")
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("sshepherd {{.Version}}\n")
	return root
}
```

- [x] **Step 3: Run the existing tests unchanged**

Run: `go test ./cmd/... -v`
Expected: PASS — all three pre-existing tests, no edits to the test file.

- [x] **Step 4: Sanity-run the binary**

```bash
go run ./cmd/sshepherd --version   # -> "sshepherd dev", exit 0
go run ./cmd/sshepherd; echo $?    # -> "no command" on stderr, prints 2
```

- [x] **Step 5: Commit**

```bash
git add go.mod go.sum cmd/sshepherd/run.go
git commit -m "refactor(cmd): migrate CLI to cobra, preserving exit-code contract"
```

---

### Task 14: `sshepherd audit` subcommand

**Files:**
- Create: `cmd/sshepherd/audit.go`
- Create: `cmd/sshepherd/audit_test.go`
- Modify: `cmd/sshepherd/run.go` (one line: register the subcommand)

- [x] **Step 1: Write the failing tests**

```go
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshepherd.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestAuditMissingConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", "no-such-file.yaml"}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, errBuf.String())
	}
}

func TestAuditInvalidConfig(t *testing.T) {
	path := writeConfig(t, "users: [\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestAuditEmptyFleet(t *testing.T) {
	// No servers -> exit 0 and a "0 servers" note; must not require an agent.
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "0 servers") {
		t.Errorf("stdout = %q, want '0 servers' note", out.String())
	}
}

func TestAuditNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr = %q, want agent guidance", errBuf.String())
	}
}

func TestAuditInvalidParallel(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path, "--parallel", "0"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/... -run TestAudit -v`
Expected: FAIL — `unknown command "audit"` surfaces as exit 2 in some cases, so specifically `TestAuditEmptyFleet` fails (wants 0). Confirm at least one test fails before implementing.

- [x] **Step 3: Implement `cmd/sshepherd/audit.go`**

```go
package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshread"
)

const (
	defaultParallel   = 10
	dialTimeout       = 10 * time.Second
	perServerTimeout  = 30 * time.Second
	defaultKnownHosts = "~/.ssh/known_hosts"
)

func newAuditCmd(stdout io.Writer) *cobra.Command {
	var (
		cfgPath    string
		knownHosts string
		parallel   int
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Report drift between the manifest and each server's authorized_keys (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if parallel < 1 {
				return fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err) // wrapcheck: wrap at package boundary
			}
			if len(cfg.Servers) == 0 {
				audit.Render(stdout, cfg, nil)
				return nil
			}
			if err := sshread.CheckAgent(os.Getenv("SSH_AUTH_SOCK")); err != nil {
				return fmt.Errorf("agent preflight: %w", err)
			}
			khPath, err := expandHome(knownHosts)
			if err != nil {
				return err
			}
			reader := &sshread.Client{
				KnownHostsPath: khPath,
				AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
				DialTimeout:    dialTimeout,
			}
			results := audit.Run(cmd.Context(), cfg, reader, audit.Options{
				Parallel:         parallel,
				PerServerTimeout: perServerTimeout,
			})
			audit.Render(stdout, cfg, results)
			if audit.ExitCode(results) != 0 {
				return errNonCompliant
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "sshepherd.yaml", "path to the manifest")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&parallel, "parallel", defaultParallel, "max concurrent server audits")
	return cmd
}

// expandHome resolves a leading "~/" against the current user's home dir.
func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	return filepath.Join(home, path[2:]), nil
}
```

And register it in `newRootCmd` in `run.go`, after `root.SetVersionTemplate(...)`:

```go
	root.AddCommand(newAuditCmd(stdout))
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test -race ./cmd/... -v`
Expected: PASS (new audit tests + the three original tests).

- [x] **Step 5: Commit**

```bash
git add cmd/sshepherd/
git commit -m "feat(cmd): sshepherd audit subcommand — flags, agent preflight, wiring"
```

---

### Task 15: Integration test — dockerized sshd

Covers the real `sshread.Client` happy paths the unit suite can't: reading a
seeded file, and the file-absent paradox (login OK via `authorized_keys2`,
default file missing). Env-driven so the Go test is docker-free; the script
owns container + agent lifecycle.

**Files:**
- Create: `scripts/integration.sh` (mode 0755)
- Create: `internal/sshread/integration_test.go`
- Modify: `Makefile` (add `integration` target + `.PHONY`)
- Modify: `.github/workflows/ci.yml` (add job)

- [x] **Step 1: Write the tagged Go test** (`internal/sshread/integration_test.go`)

```go
//go:build integration

package sshread

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
)

// itClient builds a Client from the environment exported by
// scripts/integration.sh; skips when not running under it.
func itClient(t *testing.T) (*Client, string, int) {
	t.Helper()
	host := os.Getenv("SSHEPHERD_IT_HOST")
	if host == "" {
		t.Skip("integration env not set; run via make integration")
	}
	port, err := strconv.Atoi(os.Getenv("SSHEPHERD_IT_PORT"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PORT: %v", err)
	}
	return &Client{
		KnownHostsPath: os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS"),
		AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
		DialTimeout:    10 * time.Second,
	}, host, port
}

func TestIntegrationReadPresent(t *testing.T) {
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{
		Name: "it", Host: host, Port: port, User: "present",
	})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if res.FileAbsent {
		t.Fatal("FileAbsent = true for a seeded file")
	}
	if !strings.Contains(string(res.Content), "ssh-ed25519") {
		t.Errorf("content = %q, want the seeded key", res.Content)
	}
}

func TestIntegrationFileAbsent(t *testing.T) {
	// User "absent" logs in via authorized_keys2 (custom AuthorizedKeysFile),
	// so the default file genuinely does not exist: the paradox case.
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{
		Name: "it", Host: host, Port: port, User: "absent",
	})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if !res.FileAbsent {
		t.Error("FileAbsent = false, want true")
	}
	if len(res.Content) != 0 {
		t.Errorf("content = %q, want empty", res.Content)
	}
}

func TestIntegrationUnknownHostKey(t *testing.T) {
	c, host, port := itClient(t)
	empty := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c.KnownHostsPath = empty
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.ReadAuthorizedKeys(ctx, config.Server{
		Name: "it", Host: host, Port: port, User: "present",
	})
	if err == nil || !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Errorf("err = %v, want strict-host-key failure with keyscan hint", err)
	}
}
```

- [x] **Step 2: Write `scripts/integration.sh`**

```bash
#!/usr/bin/env bash
# Spins up a throwaway sshd container, seeds keys, starts a dedicated
# ssh-agent, and runs the build-tagged integration tests against it.
set -euo pipefail

PORT="${SSHEPHERD_IT_PORT:-42222}"
CONTAINER=sshepherd-it
WORKDIR="$(mktemp -d)"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  [ -n "${SSH_AGENT_PID:-}" ] && kill "$SSH_AGENT_PID" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$WORKDIR/id_ed25519"
chmod 644 "$WORKDIR/id_ed25519.pub"

docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
docker run -d --name "$CONTAINER" \
  -p "127.0.0.1:$PORT:22" \
  -v "$WORKDIR/id_ed25519.pub:/seed/key.pub:ro" \
  alpine:3.24 sh -c '
    set -e
    apk add --no-cache openssh >/dev/null
    ssh-keygen -A
    for u in present absent; do
      adduser -D -s /bin/sh "$u"
      sed -i "s|^$u:!|$u:*|" /etc/shadow   # unlock for pubkey login
      mkdir -p "/home/$u/.ssh"
    done
    cp /seed/key.pub /home/present/.ssh/authorized_keys
    cp /seed/key.pub /home/absent/.ssh/authorized_keys2   # default file stays absent
    for u in present absent; do
      chown -R "$u:$u" "/home/$u/.ssh"
      chmod 700 "/home/$u/.ssh"
      chmod 600 "/home/$u/.ssh/"authorized_keys* 2>/dev/null || true
    done
    echo "AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2" >> /etc/ssh/sshd_config
    exec /usr/sbin/sshd -D -e
  '

echo "waiting for sshd on 127.0.0.1:$PORT ..."
for _ in $(seq 1 60); do
  if ssh-keyscan -p "$PORT" 127.0.0.1 >"$WORKDIR/known_hosts" 2>/dev/null \
     && [ -s "$WORKDIR/known_hosts" ]; then
    break
  fi
  sleep 1
done
if [ ! -s "$WORKDIR/known_hosts" ]; then
  echo "sshd never came up; container logs:" >&2
  docker logs "$CONTAINER" >&2
  exit 1
fi

eval "$(ssh-agent -s)" >/dev/null
ssh-add "$WORKDIR/id_ed25519" 2>/dev/null

SSHEPHERD_IT_HOST=127.0.0.1 \
SSHEPHERD_IT_PORT="$PORT" \
SSHEPHERD_IT_KNOWN_HOSTS="$WORKDIR/known_hosts" \
  go test -race -tags=integration -run TestIntegration -v ./internal/sshread/
```

Run: `chmod +x scripts/integration.sh`

- [x] **Step 3: Add the Makefile target.** In the `.PHONY` line add `integration` (after `test`), and after the `test:` target add:

```makefile
## integration: run integration tests against a throwaway sshd container
integration:
	./scripts/integration.sh
```

- [x] **Step 4: Run it locally**

Run: `make integration`
Expected: container starts, all three `TestIntegration*` PASS, container removed. (First run pulls `alpine:3.24` and apk-installs openssh — allow ~a minute.)

- [x] **Step 5: Add the CI job.** Append to `.github/workflows/ci.yml` (same indent level as the `docker:` job):

```yaml
  integration:
    name: Integration (sshd container)
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.26"
          cache: true

      - name: Run integration tests
        run: make integration
```

- [x] **Step 6: Commit**

```bash
git add scripts/integration.sh internal/sshread/integration_test.go Makefile .github/workflows/ci.yml
git commit -m "test: dockerized-sshd integration suite for sshread"
```

---

### Task 16: Full gate + coverage check

**Files:**
- None expected; fix whatever the gate finds.

- [x] **Step 1: Run the complete local gate**

Run: `make check && make coverage`
Expected: tidy/fmt/vet/lint/gosec/govulncheck/gitleaks/test all pass; coverage ≥ 80%.

- [x] **Step 2: If coverage is below 80%,** the shortfall is almost certainly `sshread.Client`'s network lines (integration-only). Options in order of preference: (a) add unit tests for any still-uncovered pure logic; (b) verify `interpretExit`/`CheckAgent`/`hostKeyHint` branches are all exercised; (c) only if genuinely stuck, note the number and ask the user before touching `COVERAGE_MIN`.

- [x] **Step 3: Run lint explicitly and fix findings**

Run: `golangci-lint run`
Expected: clean. Likely candidates: missing `%w` wraps (`wrapcheck`), `gocritic` style nits. Fix, don't suppress.

- [x] **Step 4: Smoke the real binary end-to-end against an empty fleet**

```bash
go build -o bin/sshepherd ./cmd/sshepherd
printf 'users:\n  - {name: me, keys: ["%s"]}\n' "$(cat ~/.ssh/id_ed25519.pub 2>/dev/null || ssh-keygen -q -t ed25519 -N '' -f /tmp/smoke_key >/dev/null && cat /tmp/smoke_key.pub)" > /tmp/smoke.yaml
./bin/sshepherd audit --config /tmp/smoke.yaml && echo "exit 0 ok"
./bin/sshepherd --version
```
Expected: "Summary: 0 servers configured — nothing to audit", exit 0; version prints.

- [x] **Step 5: Commit any gate fixes**

```bash
git add -A
git commit -m "chore: green full quality gate for audit slice"
```

---

## Spec coverage checklist (self-review record)

| Spec requirement | Task(s) |
|---|---|
| YAML schema users/servers/access + description/comment fields | 5 |
| Validation rules (uniqueness, refs, key parsing, dup keys, union) | 5, 6 |
| `ParseFile` + `ParseError` with line numbers | 2 |
| Fingerprint `Diff` with deterministic order | 3 |
| `KeyReader` seam + `ReadResult` | 7 |
| Bounded pool, `--parallel`, sorted deterministic results | 8, 14 |
| Per-server 30s deadline / 10s dial timeout | 8 (timeout plumbing), 12, 14 (constants) |
| Remote read semantics: absent-file sentinel, exit-status helper | 11, 12, 15 |
| File-absent/empty diagnostics, no-users-granted note, parse-error lines | 9 |
| Report format, stdout/stderr split, summary, exit codes 0/1/2 | 9, 13, 14 |
| Empty fleet → exit 0 without agent | 9, 14 |
| Agent-only auth + startup agent check | 11, 12, 14 |
| Strict known_hosts + exact host:port keyscan hint | 11, 12, 15 |
| Cobra migration preserving `--version` / exit codes | 13 |
| Unit/golden/fuzz/bench/race/integration tests | 2-4, 8-11, 15 |
| Coverage ≥ 80% | 16 |
| depguard: nothing to change (deny-only lax mode) | header note |
