# `sshepherd adopt` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A new `sshepherd adopt` subcommand that reads every fleet server's real `authorized_keys` and emits a complete manifest in which every installed key is accounted for — unknown keys become generated users, known users' keys found beyond their grants extend their access.

**Architecture:** Reuse `audit.Run` + `sshread.Client` untouched for fleet I/O; each server's `Diff.Unauthorized` is exactly the key set to attribute. A new pure package `internal/adopt` turns those results into a plan (new users, access extensions, warnings, unreadable-server issues); the cmd layer renders it with the same `manifestOut` types `import` uses and enforces the strict/`--partial` gate. One substrate change: `authkeys.Key` retains the raw key line.

**Tech Stack:** Go 1.26, Cobra, `gopkg.in/yaml.v3`, `golang.org/x/crypto/ssh` (unchanged), `go.uber.org/goleak` (already a dep). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-10-adopt-fleet-discovery-design.md` — read it first; it locks all semantics.

---

## File structure

| File | Status | Responsibility |
|---|---|---|
| `internal/authkeys/authkeys.go` | modify | `Key.Raw` — the original line, whitespace-trimmed |
| `internal/authkeys/authkeys_test.go` | modify | tests for `Raw` |
| `cmd/sshepherd/manifest_out.go` | create | shared render types (`manifestOut`/`userOut`/`serverOut`/`accessOut`+`Except`), `encodeManifest`, `writeFileNoClobber` (moved from import.go) |
| `cmd/sshepherd/manifest_out_test.go` | create | `except:` round-trip test |
| `cmd/sshepherd/import.go` | modify | shrink: types/helpers move out; `generateManifest` uses `encodeManifest` |
| `internal/adopt/adopt.go` | create | pure attribution: `Build`, `Plan`, `NewUser`, `Extension`, `Issue`, `sanitizeName` |
| `internal/adopt/adopt_test.go` | create | table-driven attribution tests |
| `internal/adopt/leak_test.go` | create | goleak `TestMain` |
| `internal/adopt/fuzz_test.go` | create | `FuzzSanitizeName` |
| `cmd/sshepherd/adopt.go` | create | Cobra command, preflights, strict gate, `generateAdoptManifest` |
| `cmd/sshepherd/adopt_test.go` | create | golden + run()-level tests |
| `cmd/sshepherd/testdata/adopt_*.golden` | create | golden manifests |
| `cmd/sshepherd/run.go` | modify | register command; `errFleetUnreadable` → exit 1 |
| `CLAUDE.md`, spec Status line | modify | mark slice implemented |

Dependency direction: `cmd/sshepherd` → `internal/adopt` → `internal/audit`/`internal/config`. No cycles (`adopt` never imports `sshread`).

**Commit-greenness note:** `make check` runs `deadcode ./cmd/sshepherd` (reachability from `main`), so any function in package `main` must be wired into the command tree within the same commit — that is why Task 9 lands render + command + registration together (with TDD steps inside the task).

**Conventions used below (established in this repo):**
- Run tests with `go test ./<pkg>/ -run <Name> -v`; full suite `go test ./...`.
- Golden files regenerate with `go test ./cmd/sshepherd/ -run Golden -update`.
- Every error returned across a package boundary is wrapped (`wrapcheck`).
- Test keys come from `internal/testkeys` — `testkeys.Line(t, seed)` is deterministic per seed.

---

### Task 1: `authkeys.Key` retains the raw line

**Files:**
- Modify: `internal/authkeys/authkeys.go`
- Test: `internal/authkeys/authkeys_test.go`

- [x] **Step 1: Write the failing test**

Append to `internal/authkeys/authkeys_test.go` (it is `package authkeys`; add `"github.com/javadh75/SSHepherd/internal/testkeys"` to its imports if not already there):

```go
func TestParseLineRaw(t *testing.T) {
	base := testkeys.Line(t, 1)
	tests := []struct {
		name, line, want string
	}{
		{"bare key", base, base},
		{"options and comment",
			`no-port-forwarding,command="true" ` + base + " alice@laptop",
			`no-port-forwarding,command="true" ` + base + " alice@laptop"},
		{"surrounding whitespace trimmed",
			"  " + base + " alice@laptop\t",
			base + " alice@laptop"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := ParseLine(tt.line)
			if err != nil || k == nil {
				t.Fatalf("ParseLine(%q) = %v, %v", tt.line, k, err)
			}
			if k.Raw != tt.want {
				t.Errorf("Raw = %q, want %q", k.Raw, tt.want)
			}
		})
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/authkeys/ -run TestParseLineRaw -v`
Expected: FAIL — `k.Raw undefined (type *Key has no field or method Raw)` (compile error).

- [x] **Step 3: Implement**

In `internal/authkeys/authkeys.go`, extend the `Key` struct:

```go
// Key is a single parsed authorized_keys entry.
type Key struct {
	Type        string   // key algorithm, e.g. "ssh-ed25519"
	Comment     string   // trailing comment, conventionally user@host
	Options     []string // leading options, e.g. ["no-port-forwarding"]
	Fingerprint string   // SHA256 fingerprint, e.g. "SHA256:abc..."
	Raw         string   // the original line, whitespace-trimmed: options, key material, comment
}
```

And in `ParseLine`, extend the return:

```go
	return &Key{
		Type:        pub.Type(),
		Comment:     comment,
		Options:     options,
		Fingerprint: ssh.FingerprintSHA256(pub),
		Raw:         strings.TrimSpace(line),
	}, nil
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/authkeys/ -v`
Expected: PASS, including all pre-existing tests (nothing compares `Key` structs wholesale — verified; comparisons are by fingerprint).

- [x] **Step 5: Commit**

```bash
git add internal/authkeys/
git commit -m "feat(authkeys): Key retains the raw authorized_keys line

adopt must emit real key lines into generated manifests; the future
apply slice needs the material too.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: shared manifest render types (`manifest_out.go`) + `accessOut.Except`

Pure refactor plus one new field. Existing golden files must stay byte-identical.

**Files:**
- Create: `cmd/sshepherd/manifest_out.go`
- Create: `cmd/sshepherd/manifest_out_test.go`
- Modify: `cmd/sshepherd/import.go`

- [x] **Step 1: Write the failing test**

Create `cmd/sshepherd/manifest_out_test.go`:

```go
package main

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// Adopt must copy an existing wildcard entry's except: carve-out through to
// the generated manifest; entries without except must not emit the key.
func TestEncodeManifestExceptRoundTrip(t *testing.T) {
	m := manifestOut{
		Users: []userOut{
			{Name: "alice", Keys: []string{testkeys.Line(t, 1)}},
			{Name: "bob", Keys: []string{testkeys.Line(t, 2)}},
		},
		Servers: []serverOut{
			{Name: "db-1", Host: "10.0.0.2", User: "deploy"},
			{Name: "web-1", Host: "10.0.0.1", User: "deploy"},
		},
		Access: []accessOut{
			{User: "alice", Servers: []string{"*"}, Except: []string{"db-1"}},
			{User: "bob", Servers: []string{"web-1"}},
		},
	}
	got, err := encodeManifest("# header\n", m)
	if err != nil {
		t.Fatalf("encodeManifest: %v", err)
	}
	if !strings.HasPrefix(string(got), "# header\n") {
		t.Errorf("output %q lacks the header", got)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("round-trip rejected by config.Parse: %v", err)
	}
	if len(c.Access) != 2 || len(c.Access[0].Except) != 1 || c.Access[0].Except[0] != "db-1" {
		t.Errorf("Access = %+v, want alice's except [db-1] preserved", c.Access)
	}
	if strings.Contains(string(got), "except: []") {
		t.Errorf("output %q emits an explicit empty except for bob", got)
	}
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/sshepherd/ -run TestEncodeManifestExceptRoundTrip -v`
Expected: FAIL — `undefined: encodeManifest` and `unknown field Except` (compile errors).

- [x] **Step 3: Create `cmd/sshepherd/manifest_out.go`**

Move the output types and `writeFileNoClobber` out of `import.go` verbatim, add `Except`, add `encodeManifest`:

```go
package main

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// serverOut/userOut/accessOut mirror the config types for output: omitempty
// keeps default ports and never-set fields out of the generated YAML. Shared
// by every command that emits a manifest (import, adopt).
type serverOut struct {
	Name string `yaml:"name"`
	Host string `yaml:"host"`
	Port int    `yaml:"port,omitempty"`
	User string `yaml:"user"`
}

type userOut struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Comment     string   `yaml:"comment,omitempty"`
	Operator    bool     `yaml:"operator,omitempty"`
	Keys        []string `yaml:"keys"`
}

type accessOut struct {
	User    string   `yaml:"user"`
	Servers []string `yaml:"servers"`
	Except  []string `yaml:"except,omitempty"`
}

type manifestOut struct {
	Users   []userOut   `yaml:"users"`
	Servers []serverOut `yaml:"servers"`
	Access  []accessOut `yaml:"access"`
}

// encodeManifest renders a manifest preceded by a raw header comment block
// (the header must supply its own trailing newline).
func encodeManifest(header string, m manifestOut) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	return buf.Bytes(), nil
}

// writeFileNoClobber writes data to path with owner-only permissions,
// refusing to replace an existing file unless force is set.
func writeFileNoClobber(path string, data []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0o600) // #nosec G304 -- path is the user's own -o flag
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; pass --force to overwrite", path)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	// The mode above only applies at creation; a --force overwrite via
	// O_TRUNC would keep the existing file's permissions, so pin them.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
```

- [x] **Step 4: Shrink `cmd/sshepherd/import.go`**

Delete from `import.go`: the `serverOut`/`userOut`/`accessOut`/`manifestOut` type block (lines 18–44) and the whole `writeFileNoClobber` function. Replace the tail of `generateManifest` (from `var buf bytes.Buffer` through `return buf.Bytes(), notes, nil`) with:

```go
	header := fmt.Sprintf("# generated by sshepherd import from %s — review before use\n", src)
	data, err := encodeManifest(header, m)
	if err != nil {
		return nil, nil, err
	}
	return data, notes, nil
}
```

Then remove now-unused imports from `import.go` (`bytes` and `gopkg.in/yaml.v3` — run `goimports -w cmd/sshepherd/import.go`).

- [x] **Step 5: Run the full package tests — goldens must not change**

Run: `go test ./cmd/sshepherd/ -v`
Expected: PASS, all existing golden tests byte-identical (do NOT run with `-update`; a diff here means the refactor changed output and must be fixed).

- [x] **Step 6: Commit**

```bash
git add cmd/sshepherd/
git commit -m "refactor(cmd): shared manifest render types; accessOut gains except

adopt will render manifests too; except: must round-trip so existing
wildcard carve-outs survive adoption.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: `internal/adopt` — the name sanitizer

**Files:**
- Create: `internal/adopt/adopt.go`
- Create: `internal/adopt/adopt_test.go`
- Create: `internal/adopt/leak_test.go`

- [x] **Step 1: Write the failing test**

Create `internal/adopt/adopt_test.go`:

```go
package adopt

import "testing"

func TestSanitizeName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"alice@laptop.local", "alice-laptop-local"},
		{"Alice@Laptop", "alice-laptop"},
		{"deploy", "deploy"},
		{"alice smith@host", "alice-smith-host"},
		{"a__b..c", "a-b-c"},
		{"@@@", ""},
		{"", ""},
		{"-alice-", "alice"},
		{"Röot@höst", "r-ot-h-st"},
		{"UPPER-09", "upper-09"},
	}
	for _, tt := range tests {
		if got := sanitizeName(tt.in); got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
```

Create `internal/adopt/leak_test.go` (project policy: every test package):

```go
package adopt

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
```

- [x] **Step 2: Run test to verify it fails**

Run: `go test ./internal/adopt/ -v`
Expected: FAIL — package does not exist yet / `undefined: sanitizeName`.

- [x] **Step 3: Implement**

Create `internal/adopt/adopt.go`:

```go
// Package adopt turns audit results into manifest additions: unknown keys
// found on the fleet become new users with access to the servers where they
// were found; keys of known users found beyond their grants become access
// extensions. Pure logic — no I/O; the cmd layer owns SSH and rendering.
package adopt

import "strings"

// sanitizeName derives a manifest user name from a key comment: lowercase,
// every run of characters outside [a-z0-9] collapses to a single '-',
// leading and trailing '-' trimmed. Returns "" when nothing usable remains —
// the caller falls back to a numbered name.
func sanitizeName(comment string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(comment) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			if pendingDash && b.Len() > 0 {
				b.WriteByte('-')
			}
			pendingDash = false
			b.WriteRune(r)
		default:
			pendingDash = true
		}
	}
	return b.String()
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adopt/ -v`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/adopt/
git commit -m "feat(adopt): name sanitizer for adopted users

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: `adopt.Build` — unknown keys become new users

Core grouping and naming. Test inputs are built by running the real `audit.Run` over a fake `KeyReader`, so adopt tests consume exactly what the command will.

**Files:**
- Modify: `internal/adopt/adopt.go`
- Test: `internal/adopt/adopt_test.go`

- [x] **Step 1: Write the failing tests**

Append to `internal/adopt/adopt_test.go` — first the shared test harness:

```go
// fakeReader returns canned authorized_keys content per server name.
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

// runAudit produces ServerResults through the real audit pipeline so adopt
// tests consume exactly what the adopt command consumes.
func runAudit(t *testing.T, cfg *config.Config, r audit.KeyReader) []audit.ServerResult {
	t.Helper()
	return audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 4})
}

func parseConfig(t *testing.T, y string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("test config: %v", err)
	}
	return cfg
}

// testCfg: one operator, three servers, no other users.
// Server name order (= audit result order) is db-1, web-1, web-2.
func testCfg(t *testing.T) *config.Config {
	t.Helper()
	return parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
`)
}
```

(New imports for the test file: `context`, `reflect`, plus `github.com/javadh75/SSHepherd/internal/audit`, `.../internal/config`, `.../internal/testkeys`.)

Then the behavior tests:

```go
func TestBuildUnknownKeyBecomesOneUser(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " alice@laptop.local"
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n")},
		"web-1": {Content: []byte(op + "\n" + stranger + "\n")},
		"web-2": {Content: []byte(op + "\n" + stranger + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 {
		t.Fatalf("NewUsers = %+v, want exactly one", p.NewUsers)
	}
	u := p.NewUsers[0]
	if u.Name != "alice-laptop-local" {
		t.Errorf("Name = %q, want alice-laptop-local", u.Name)
	}
	if u.Line != stranger {
		t.Errorf("Line = %q, want the raw line as found", u.Line)
	}
	if !reflect.DeepEqual(u.FoundOn, []string{"web-1", "web-2"}) {
		t.Errorf("FoundOn = %v, want [web-1 web-2]", u.FoundOn)
	}
	if len(p.Extensions) != 0 || len(p.Issues) != 0 || len(p.Warnings) != 0 {
		t.Errorf("Extensions/Issues/Warnings = %+v/%+v/%+v, want none",
			p.Extensions, p.Issues, p.Warnings)
	}
}

// The operator's key is desired everywhere, so it never surfaces as
// unauthorized — a fully compliant fleet yields an empty plan.
func TestBuildCompliantFleetEmptyPlan(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	content := audit.ReadResult{Content: []byte(op + "\n")}
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1": content, "web-1": content, "web-2": content,
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers)+len(p.Extensions)+len(p.Warnings)+len(p.Issues) != 0 {
		t.Errorf("plan = %+v, want empty", p)
	}
}

// A file-absent server contributes nothing and is not an error.
func TestBuildFileAbsentServer(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {FileAbsent: true},
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 0 || len(p.Issues) != 0 {
		t.Errorf("plan = %+v, want empty (absent file is fine)", p)
	}
}

func TestBuildAnonymousKeysNumberedInDiscoveryOrder(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	anonA, anonB := testkeys.Line(t, 8), testkeys.Line(t, 9)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + anonA + "\n")},
		"web-1": {Content: []byte(op + "\n" + anonB + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 2 {
		t.Fatalf("NewUsers = %+v, want two", p.NewUsers)
	}
	// db-1 sorts before web-1, so anonA is discovered first.
	if p.NewUsers[0].Name != "adopted-key-1" || p.NewUsers[0].Line != anonA {
		t.Errorf("first = %+v, want adopted-key-1 = anonA", p.NewUsers[0])
	}
	if p.NewUsers[1].Name != "adopted-key-2" || p.NewUsers[1].Line != anonB {
		t.Errorf("second = %+v, want adopted-key-2 = anonB", p.NewUsers[1])
	}
}

func TestBuildNameCollisions(t *testing.T) {
	// Existing manifest user "carol" + two distinct stranger keys whose
	// comments both sanitize to "carol" -> carol-2, carol-3.
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: carol, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: carol, servers: [web-1]}
`)
	op, carol := testkeys.Line(t, 1), testkeys.Line(t, 2)
	k1 := testkeys.Line(t, 7) + " carol@a"
	k2 := testkeys.Line(t, 8) + " Carol"
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(op + "\n" + carol + "\n" + k1 + "\n" + k2 + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 2 {
		t.Fatalf("NewUsers = %+v, want two", p.NewUsers)
	}
	if p.NewUsers[0].Name != "carol-a" {
		t.Errorf("first = %q, want carol-a", p.NewUsers[0].Name)
	}
	if p.NewUsers[1].Name != "carol-2" {
		t.Errorf("second = %q, want carol-2 (collides with manifest user carol)", p.NewUsers[1].Name)
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adopt/ -v`
Expected: FAIL — `undefined: Build` (compile error).

- [x] **Step 3: Implement the types and `Build`**

Add to `internal/adopt/adopt.go` (imports become `fmt`, `sort`, `strings`, plus the two internal packages):

```go
import (
	"fmt"
	"sort"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
)

// NewUser is one unknown key adopted into a generated user.
type NewUser struct {
	Name     string
	Line     string   // raw authorized_keys line; first occurrence wins
	FoundOn  []string // sorted names of servers where the key was found
	Wildcard bool     // grant renders as ["*"]: the key covers the whole fleet
}

// Extension grants an existing user the servers their key was found on
// beyond the manifest's current grants.
type Extension struct {
	User    string
	Servers []string // sorted
}

// Issue is a server whose keys could not be (fully) read; the cmd layer
// enforces the strict/--partial gate on these.
type Issue struct {
	Server string
	Detail string
}

// Plan is everything adopt would add to the manifest, plus warnings for the
// operator and issues for the strict gate.
type Plan struct {
	NewUsers   []NewUser
	Extensions []Extension
	Warnings   []string
	Issues     []Issue
}

// pending accumulates one unknown key during the sweep.
type pending struct {
	line    string
	comment string
	foundOn []string
}

// Build attributes every unauthorized key in results: keys owned by a
// manifest user extend that user's access; unknown keys become new users.
// results must be sorted by server name (audit.Run guarantees this) and keys
// are processed in file order, so the output is deterministic.
func Build(cfg *config.Config, results []audit.ServerResult) Plan {
	var p Plan
	byFP := make(map[string]*pending)
	var order []string // fingerprints in discovery order
	for _, r := range results {
		for _, k := range r.Diff.Unauthorized {
			if _, known := cfg.OwnerOf(k.Fingerprint); known {
				continue // Task 6 extends the owner's access
			}
			if pd, seen := byFP[k.Fingerprint]; seen {
				pd.foundOn = append(pd.foundOn, r.Server.Name)
				continue
			}
			byFP[k.Fingerprint] = &pending{line: k.Raw, comment: k.Comment, foundOn: []string{r.Server.Name}}
			order = append(order, k.Fingerprint)
		}
	}
	p.NewUsers = nameUsers(cfg, byFP, order)
	return p
}

// nameUsers turns accumulated unknown keys into named users, resolving
// collisions against manifest names and each other with numeric suffixes.
func nameUsers(cfg *config.Config, byFP map[string]*pending, order []string) []NewUser {
	taken := make(map[string]bool, len(cfg.Users))
	for _, u := range cfg.Users {
		taken[u.Name] = true
	}
	var users []NewUser
	anon := 0
	for _, fp := range order {
		pd := byFP[fp]
		base := sanitizeName(pd.comment)
		if base == "" {
			anon++
			base = fmt.Sprintf("adopted-key-%d", anon)
		}
		name := base
		for n := 2; taken[name]; n++ {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		taken[name] = true
		sort.Strings(pd.foundOn)
		users = append(users, NewUser{Name: name, Line: pd.line, FoundOn: pd.foundOn})
	}
	return users
}
```

(Note: a server with `Err != nil` has a zero `Diff`, so the sweep naturally skips it; Task 7 records the issue.)

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adopt/ -v`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/adopt/
git commit -m "feat(adopt): unknown fleet keys become generated users

Grouped by fingerprint across servers, named from the key comment,
deterministic discovery order.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: wildcard compaction + divergence warnings

**Files:**
- Modify: `internal/adopt/adopt.go`
- Test: `internal/adopt/adopt_test.go`

- [x] **Step 1: Write the failing tests**

Append to `internal/adopt/adopt_test.go`:

```go
func TestBuildWildcardCompaction(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	everywhere := testkeys.Line(t, 7) + " carol@laptop"
	content := audit.ReadResult{Content: []byte(op + "\n" + everywhere + "\n")}
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1": content, "web-1": content, "web-2": content,
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || !p.NewUsers[0].Wildcard {
		t.Fatalf("NewUsers = %+v, want one wildcard user", p.NewUsers)
	}
	if !reflect.DeepEqual(p.NewUsers[0].FoundOn, []string{"db-1", "web-1", "web-2"}) {
		t.Errorf("FoundOn = %v, want all three servers (for the description)", p.NewUsers[0].FoundOn)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "wildcard") {
		t.Errorf("Warnings = %v, want one wildcard-compaction note", p.Warnings)
	}
}

// A single-server fleet says nothing about "everywhere" — no compaction.
func TestBuildNoCompactionSingleServer(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 7) + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || p.NewUsers[0].Wildcard {
		t.Fatalf("NewUsers = %+v, want one non-wildcard user", p.NewUsers)
	}
}

// Same fingerprint, different comment on the second server: first copy wins,
// a warning names the divergence.
func TestBuildDivergentCopiesFirstWins(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	first := testkeys.Line(t, 7) + " carol@a"
	second := testkeys.Line(t, 7) + " carol@b"
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + first + "\n")},
		"web-1": {Content: []byte(op + "\n" + second + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || p.NewUsers[0].Line != first {
		t.Fatalf("NewUsers = %+v, want one user keeping the db-1 copy", p.NewUsers)
	}
	if p.NewUsers[0].Name != "carol-a" {
		t.Errorf("Name = %q, want carol-a (first-seen comment names the user)", p.NewUsers[0].Name)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "web-1") {
		t.Errorf("Warnings = %v, want one divergence note naming web-1", p.Warnings)
	}
}
```

(Add `strings` to the test file's imports.)

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adopt/ -run 'TestBuildWildcard|TestBuildNoCompaction|TestBuildDivergent' -v`
Expected: FAIL — `Wildcard` always false, no warnings emitted.

- [x] **Step 3: Implement**

In `Build`'s sweep, replace the seen-branch:

```go
			if pd, seen := byFP[k.Fingerprint]; seen {
				if pd.line != k.Raw {
					p.Warnings = append(p.Warnings, fmt.Sprintf(
						"key %s on %s differs from its first-seen copy (options/comment); keeping %q",
						k.Fingerprint, r.Server.Name, pd.line))
				}
				pd.foundOn = append(pd.foundOn, r.Server.Name)
				continue
			}
```

`nameUsers` needs to append compaction warnings, so change its signature to return them and compact inside the construction loop — full replacement:

```go
// nameUsers turns accumulated unknown keys into named users, resolving
// collisions against manifest names and each other with numeric suffixes.
// A key found on every server of a 2+-server fleet compacts to a wildcard
// grant, mirroring import's rule, with the same review warning.
func nameUsers(cfg *config.Config, byFP map[string]*pending, order []string) ([]NewUser, []string) {
	taken := make(map[string]bool, len(cfg.Users))
	for _, u := range cfg.Users {
		taken[u.Name] = true
	}
	var users []NewUser
	var warnings []string
	anon := 0
	for _, fp := range order {
		pd := byFP[fp]
		base := sanitizeName(pd.comment)
		if base == "" {
			anon++
			base = fmt.Sprintf("adopted-key-%d", anon)
		}
		name := base
		for n := 2; taken[name]; n++ {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		taken[name] = true
		sort.Strings(pd.foundOn)
		nu := NewUser{Name: name, Line: pd.line, FoundOn: pd.foundOn}
		if len(cfg.Servers) >= 2 && len(pd.foundOn) == len(cfg.Servers) {
			nu.Wildcard = true
			warnings = append(warnings, fmt.Sprintf(
				"access for %q covers every server; emitted as wildcard %q (includes servers added later)", name, "*"))
		}
		users = append(users, nu)
	}
	return users, warnings
}
```

And the call site in `Build`:

```go
	var nameWarnings []string
	p.NewUsers, nameWarnings = nameUsers(cfg, byFP, order)
	p.Warnings = append(p.Warnings, nameWarnings...)
	return p
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adopt/ -v`
Expected: PASS (all tasks so far).

- [x] **Step 5: Commit**

```bash
git add internal/adopt/
git commit -m "feat(adopt): wildcard compaction and divergent-copy warnings

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: extensions for known users + `except` carve-outs

**Files:**
- Modify: `internal/adopt/adopt.go`
- Test: `internal/adopt/adopt_test.go`

- [x] **Step 1: Write the failing tests**

Append to `internal/adopt/adopt_test.go`:

```go
// extCfg: alice (two keys) granted web-1 only; bob wildcard except db-1.
func extCfg(t *testing.T) *config.Config {
	t.Helper()
	return parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: alice, keys: ["`+testkeys.Line(t, 2)+`", "`+testkeys.Line(t, 3)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 4)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: ["*"], except: [db-1]}
`)
}

func TestBuildExtendsKnownUser(t *testing.T) {
	cfg := extCfg(t)
	op, al := testkeys.Line(t, 1), testkeys.Line(t, 2)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + al + "\n")},
		"web-1": {Content: []byte(op + "\n" + al + "\n")}, // granted: not an extension
		"web-2": {Content: []byte(op + "\n" + al + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	want := []Extension{{User: "alice", Servers: []string{"db-1", "web-2"}}}
	if !reflect.DeepEqual(p.Extensions, want) {
		t.Errorf("Extensions = %+v, want %+v", p.Extensions, want)
	}
	if len(p.NewUsers) != 0 {
		t.Errorf("NewUsers = %+v, want none (the key is alice's)", p.NewUsers)
	}
}

// Two different keys of the same user on one ungranted server extend it once.
func TestBuildExtensionDedupesServers(t *testing.T) {
	cfg := extCfg(t)
	op, al1, al2 := testkeys.Line(t, 1), testkeys.Line(t, 2), testkeys.Line(t, 3)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n")},
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n" + al1 + "\n" + al2 + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	want := []Extension{{User: "alice", Servers: []string{"web-2"}}}
	if !reflect.DeepEqual(p.Extensions, want) {
		t.Errorf("Extensions = %+v, want %+v (web-2 once, not twice)", p.Extensions, want)
	}
}

// An except: carve-out is a deliberate "must not be here": never re-granted,
// warned instead.
func TestBuildRespectsExceptCarveOut(t *testing.T) {
	cfg := extCfg(t)
	op, bo := testkeys.Line(t, 1), testkeys.Line(t, 4)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + bo + "\n")}, // bob is excepted from db-1
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 {
		t.Errorf("Extensions = %+v, want none (db-1 is bob's except carve-out)", p.Extensions)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "bob") ||
		!strings.Contains(p.Warnings[0], "db-1") {
		t.Errorf("Warnings = %v, want one naming bob and db-1", p.Warnings)
	}
}

// Extensions come out in manifest user order regardless of discovery order.
func TestBuildExtensionsManifestOrder(t *testing.T) {
	op, al, bo := testkeys.Line(t, 1), testkeys.Line(t, 2), testkeys.Line(t, 4)
	// bob's key on web-1 is discovered before alice's on web-2, but alice
	// precedes bob in the manifest. Explicit grants only (no wildcard), so
	// both users have exactly one ungranted server to be found on.
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: alice, keys: ["`+testkeys.Line(t, 2)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 4)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: [web-2]}
`)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(op + "\n" + al + "\n" + bo + "\n")},
		"web-2": {Content: []byte(op + "\n" + al + "\n" + bo + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	want := []Extension{
		{User: "alice", Servers: []string{"web-2"}},
		{User: "bob", Servers: []string{"web-1"}},
	}
	if !reflect.DeepEqual(p.Extensions, want) {
		t.Errorf("Extensions = %+v, want %+v (manifest user order)", p.Extensions, want)
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adopt/ -run TestBuildExt -v` and `go test ./internal/adopt/ -run TestBuildRespects -v`
Expected: FAIL — known keys currently produce nothing (`Extensions` empty) and `TestBuildRespectsExceptCarveOut` sees no warning.

- [x] **Step 3: Implement**

Add `"slices"` to `adopt.go` imports. In `Build`, replace the known-key branch and add the post-sweep assembly:

```go
func Build(cfg *config.Config, results []audit.ServerResult) Plan {
	var p Plan
	byFP := make(map[string]*pending)
	var order []string // fingerprints in discovery order
	extByUser := make(map[string]map[string]bool)
	for _, r := range results {
		for _, k := range r.Diff.Unauthorized {
			if owner, known := cfg.OwnerOf(k.Fingerprint); known {
				if hasExceptCarveOut(cfg, owner.Name, r.Server.Name) {
					p.Warnings = append(p.Warnings, fmt.Sprintf(
						"key of %q found on %q, which their except: list deliberately excludes — not re-granted; audit flags this drift",
						owner.Name, r.Server.Name))
					continue
				}
				if extByUser[owner.Name] == nil {
					extByUser[owner.Name] = make(map[string]bool)
				}
				extByUser[owner.Name][r.Server.Name] = true
				continue
			}
			if pd, seen := byFP[k.Fingerprint]; seen {
				if pd.line != k.Raw {
					p.Warnings = append(p.Warnings, fmt.Sprintf(
						"key %s on %s differs from its first-seen copy (options/comment); keeping %q",
						k.Fingerprint, r.Server.Name, pd.line))
				}
				pd.foundOn = append(pd.foundOn, r.Server.Name)
				continue
			}
			byFP[k.Fingerprint] = &pending{line: k.Raw, comment: k.Comment, foundOn: []string{r.Server.Name}}
			order = append(order, k.Fingerprint)
		}
	}
	for _, u := range cfg.Users { // manifest order keeps output deterministic
		srvSet := extByUser[u.Name]
		if len(srvSet) == 0 {
			continue
		}
		srvs := make([]string, 0, len(srvSet))
		for s := range srvSet {
			srvs = append(srvs, s)
		}
		sort.Strings(srvs)
		p.Extensions = append(p.Extensions, Extension{User: u.Name, Servers: srvs})
	}
	var nameWarnings []string
	p.NewUsers, nameWarnings = nameUsers(cfg, byFP, order)
	p.Warnings = append(p.Warnings, nameWarnings...)
	return p
}

// hasExceptCarveOut reports whether user's access deliberately excludes
// server via a wildcard except: list. Such a server is never re-granted by
// adopt — the carve-out is a statement of intent; the installed key is drift.
func hasExceptCarveOut(cfg *config.Config, user, server string) bool {
	for _, a := range cfg.Access {
		if a.User != user || !slices.Contains(a.Servers, "*") {
			continue
		}
		if slices.Contains(a.Except, server) {
			return true
		}
	}
	return false
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adopt/ -v`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/adopt/
git commit -m "feat(adopt): extend known users' access; respect except carve-outs

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: issues for the strict gate

**Files:**
- Modify: `internal/adopt/adopt.go`
- Test: `internal/adopt/adopt_test.go`

- [x] **Step 1: Write the failing tests**

Append to `internal/adopt/adopt_test.go` (add `"errors"` to imports):

```go
func TestBuildUnreachableServerIsAnIssue(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@x"
	r := &fakeReader{
		byName: map[string]audit.ReadResult{
			"web-1": {Content: []byte(op + "\n" + stranger + "\n")},
			"web-2": {Content: []byte(op + "\n")},
		},
		errs: map[string]error{"db-1": errors.New("dial tcp: connection refused")},
	}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Issues) != 1 || p.Issues[0].Server != "db-1" ||
		!strings.Contains(p.Issues[0].Detail, "connection refused") {
		t.Fatalf("Issues = %+v, want db-1 with the dial error", p.Issues)
	}
	// Readable servers are still attributed.
	if len(p.NewUsers) != 1 || p.NewUsers[0].Name != "carol-x" {
		t.Errorf("NewUsers = %+v, want carol-x from web-1", p.NewUsers)
	}
	if got := p.UnreadableServers(); !reflect.DeepEqual(got, []string{"db-1"}) {
		t.Errorf("UnreadableServers = %v, want [db-1]", got)
	}
}

// Unparseable lines are issues too (they might be real access we would
// silently drop), but the lines that did parse are still attributed.
func TestBuildParseErrorsAreIssues(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@x"
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\ngarbage-line\nmore garbage\n" + stranger + "\n")},
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Issues) != 2 {
		t.Fatalf("Issues = %+v, want two (one per bad line)", p.Issues)
	}
	if p.Issues[0].Server != "db-1" || p.Issues[1].Server != "db-1" {
		t.Errorf("Issues = %+v, want both on db-1", p.Issues)
	}
	if got := p.UnreadableServers(); !reflect.DeepEqual(got, []string{"db-1"}) {
		t.Errorf("UnreadableServers = %v, want [db-1] (deduped)", got)
	}
	if len(p.NewUsers) != 1 || p.NewUsers[0].Name != "carol-x" {
		t.Errorf("NewUsers = %+v, want carol-x (parsed lines still adopted)", p.NewUsers)
	}
}
```

- [x] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/adopt/ -run 'Issue|ParseErrors' -v`
Expected: FAIL — `p.Issues` empty, `UnreadableServers` undefined (compile error first).

- [x] **Step 3: Implement**

At the top of `Build`'s sweep loop body, before the `Unauthorized` loop:

```go
	for _, r := range results {
		if r.Err != nil {
			p.Issues = append(p.Issues, Issue{Server: r.Server.Name, Detail: r.Err.Error()})
			continue
		}
		for _, pe := range r.ParseErrs {
			p.Issues = append(p.Issues, Issue{Server: r.Server.Name, Detail: pe.Error()})
		}
		for _, k := range r.Diff.Unauthorized {
```

And add the method:

```go
// UnreadableServers lists the distinct servers with issues, in result order.
func (p Plan) UnreadableServers() []string {
	var names []string
	seen := make(map[string]bool)
	for _, is := range p.Issues {
		if !seen[is.Server] {
			seen[is.Server] = true
			names = append(names, is.Server)
		}
	}
	return names
}
```

- [x] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/adopt/ -v`
Expected: PASS.

- [x] **Step 5: Commit**

```bash
git add internal/adopt/
git commit -m "feat(adopt): surface unreadable servers for the strict gate

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: fuzz the name sanitizer

**Files:**
- Create: `internal/adopt/fuzz_test.go`

- [x] **Step 1: Write the fuzz test**

Create `internal/adopt/fuzz_test.go`:

```go
package adopt

import (
	"regexp"
	"testing"
)

// validName: alnum runs joined by single dashes; no leading/trailing dash.
var validName = regexp.MustCompile(`^[a-z0-9](?:-?[a-z0-9])*$`)

func FuzzSanitizeName(f *testing.F) {
	for _, seed := range []string{
		"", "alice@laptop.local", "Röot@höst", "a--b", "@@@", "ADMIN",
		"user name with spaces", "\x00\x1b[31m", "🐑@flock", "-alice-",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, comment string) {
		got := sanitizeName(comment)
		if got == "" {
			return // caller falls back to adopted-key-N
		}
		if !validName.MatchString(got) {
			t.Errorf("sanitizeName(%q) = %q: not a clean name", comment, got)
		}
		if again := sanitizeName(got); again != got {
			t.Errorf("not idempotent: sanitizeName(%q) = %q, re-sanitized to %q", comment, got, again)
		}
	})
}
```

- [x] **Step 2: Run the seeds as unit tests**

Run: `go test ./internal/adopt/ -run FuzzSanitizeName -v`
Expected: PASS (seeds only).

- [x] **Step 3: Run a short fuzz burst**

Run: `go test ./internal/adopt/ -fuzz FuzzSanitizeName -fuzztime 15s`
Expected: no crashers (`elapsed: 15s, execs: ...` then ok). If a crasher appears, fix `sanitizeName` and keep the generated corpus file under `internal/adopt/testdata/fuzz/` in the commit.

- [x] **Step 4: Commit**

```bash
git add internal/adopt/
git commit -m "test(adopt): fuzz the name sanitizer

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: the `adopt` command — rendering, wiring, strict gate

One commit (the `deadcode` check requires render + command + registration together), TDD inside: golden/render tests first, then run()-level tests, then the implementation.

**Files:**
- Create: `cmd/sshepherd/adopt.go`
- Create: `cmd/sshepherd/adopt_test.go`
- Create: `cmd/sshepherd/testdata/adopt_mixed.golden`, `adopt_noop.golden`, `adopt_partial.golden` (via `-update`)
- Modify: `cmd/sshepherd/run.go`

- [x] **Step 1: Write the failing golden/render tests**

Create `cmd/sshepherd/adopt_test.go`:

```go
package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeReader returns canned authorized_keys content per server name.
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

// adoptPlan runs the real pipeline (audit.Run + adopt.Build) over a fake
// fleet — exactly what the command does, minus SSH.
func adoptPlan(t *testing.T, cfg *config.Config, r audit.KeyReader) adopt.Plan {
	t.Helper()
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 4})
	return adopt.Build(cfg, results)
}

// mixedCfg exercises every attribution path at once: an operator, a user to
// extend (alice), a wildcard-except user (bob), a fleet-wide stranger
// (compacts), and an anonymous stranger.
func mixedCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(mixedCfgYAML(t)))
	if err != nil {
		t.Fatalf("test config: %v", err)
	}
	return cfg
}

func mixedCfgYAML(t *testing.T) string {
	t.Helper()
	return `
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, description: hand-written, keys: ["` + testkeys.Line(t, 2) + `", "` + testkeys.Line(t, 3) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: db-1, host: 10.0.0.3, port: 2222, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: ["*"], except: [db-1]}
`
}

func mixedReader(t *testing.T) *fakeReader {
	t.Helper()
	op, al := testkeys.Line(t, 1), testkeys.Line(t, 2)
	bo := testkeys.Line(t, 4)
	carol := testkeys.Line(t, 7) + " carol@laptop"
	anon := testkeys.Line(t, 8)
	return &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + bo + "\n" + carol + "\n" + anon + "\n")},
		"web-1": {Content: []byte(op + "\n" + al + "\n" + carol + "\n")},
		"web-2": {Content: []byte(op + "\n" + al + "\n" + carol + "\n")},
	}}
}

func TestGenerateAdoptManifestMixedGolden(t *testing.T) {
	cfg := mixedCfg(t)
	plan := adoptPlan(t, cfg, mixedReader(t))
	got, err := generateAdoptManifest(cfg, plan, "sshepherd.yaml", nil)
	if err != nil {
		t.Fatalf("generateAdoptManifest: %v", err)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	// web-2 desired: op(1) + bob wildcard(1) + alice extension(2) + carol(1) = 5.
	if n := len(c.DesiredFor("web-2")); n != 5 {
		t.Errorf("DesiredFor(web-2) = %d keys, want 5", n)
	}
	// db-1 desired: op(1) + carol wildcard(1) + adopted-key-1(1) = 3
	// (bob stays excepted; alice's extension is web-2 only).
	if n := len(c.DesiredFor("db-1")); n != 3 {
		t.Errorf("DesiredFor(db-1) = %d keys, want 3", n)
	}
	// bob's carve-out and carol's compaction each warn.
	if len(plan.Warnings) != 2 {
		t.Errorf("Warnings = %v, want two (except carve-out + wildcard note)", plan.Warnings)
	}
	checkGolden(t, "adopt_mixed.golden", got)
}

func TestGenerateAdoptManifestNoopGolden(t *testing.T) {
	cfg := mixedCfg(t)
	op, al := testkeys.Line(t, 1), testkeys.Line(t, 2)
	al2, bo := testkeys.Line(t, 3), testkeys.Line(t, 4)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n")},
		"web-1": {Content: []byte(op + "\n" + al + "\n" + al2 + "\n" + bo + "\n")},
		"web-2": {Content: []byte(op + "\n" + bo + "\n")},
	}}
	plan := adoptPlan(t, cfg, r)
	if len(plan.NewUsers)+len(plan.Extensions) != 0 {
		t.Fatalf("plan = %+v, want nothing to adopt", plan)
	}
	got, err := generateAdoptManifest(cfg, plan, "sshepherd.yaml", nil)
	if err != nil {
		t.Fatalf("generateAdoptManifest: %v", err)
	}
	if _, err := config.Parse(got); err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	// Content-identical re-render: port 2222 kept, port 22 omitted,
	// alice's description and bob's except preserved.
	for _, want := range []string{"port: 2222", "description: hand-written", "except:"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	checkGolden(t, "adopt_noop.golden", got)
}

func TestGenerateAdoptManifestPartialGolden(t *testing.T) {
	cfg := mixedCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@laptop"
	r := &fakeReader{
		byName: map[string]audit.ReadResult{
			"web-1": {Content: []byte(op + "\n" + stranger + "\n")},
			"web-2": {Content: []byte(op + "\n")},
		},
		errs: map[string]error{"db-1": errors.New("dial tcp 10.0.0.3:2222: connection refused")},
	}
	plan := adoptPlan(t, cfg, r)
	got, err := generateAdoptManifest(cfg, plan, "sshepherd.yaml", plan.UnreadableServers())
	if err != nil {
		t.Fatalf("generateAdoptManifest: %v", err)
	}
	if !strings.Contains(string(got), "# WARNING: server db-1 unreadable — its access is NOT represented") {
		t.Errorf("output lacks the unreadable-server comment block:\n%s", got)
	}
	if _, err := config.Parse(got); err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	checkGolden(t, "adopt_partial.golden", got)
}
```

- [x] **Step 2: Write the failing run()-level tests**

Append to `cmd/sshepherd/adopt_test.go`:

```go
func TestAdoptMissingConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", "no-such-file.yaml"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, errBuf.String())
	}
}

func TestAdoptInvalidParallel(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path, "--parallel", "0"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestAdoptNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr = %q, want agent guidance", errBuf.String())
	}
}

// An empty fleet needs no agent and emits a valid manifest with a note.
func TestAdoptEmptyFleet(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if _, err := config.Parse(out.Bytes()); err != nil {
		t.Errorf("stdout is not a valid manifest: %v", err)
	}
	if !strings.HasPrefix(out.String(), "# generated by sshepherd adopt from "+path) {
		t.Errorf("stdout = %q, want the adopt header", out.String())
	}
	if !strings.Contains(errBuf.String(), "nothing to adopt") {
		t.Errorf("stderr = %q, want a nothing-to-adopt note", errBuf.String())
	}
}

func TestAdoptOutputFileNoClobber(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	src := writeConfig(t, "")
	dst := filepath.Join(t.TempDir(), "adopted.yaml")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", src, "-o", dst}, &out, &errBuf); code != 0 {
		t.Fatalf("first write: exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty when -o is used", out.String())
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("output file: %v", err)
	}
	errBuf.Reset()
	if code := run([]string{"adopt", "--config", src, "-o", dst}, &out, &errBuf); code != 2 {
		t.Fatalf("overwrite without --force: exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "--force") {
		t.Errorf("stderr = %q, want --force hint", errBuf.String())
	}
	if code := run([]string{"adopt", "--config", src, "-o", dst, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("overwrite with --force: exit = %d, want 0", code)
	}
}

// fakeAgent satisfies the agent preflight without a real ssh-agent.
func fakeAgent(t *testing.T) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
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
			_ = c.Close()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
}

// closedPort returns a localhost port that was just released, so dialing it
// fails fast with ECONNREFUSED.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// The strict gate: an unreachable server aborts with exit 1 and no output;
// --partial proceeds and marks the gap in the manifest itself.
func TestAdoptUnreachableStrictGateAndPartial(t *testing.T) {
	fakeAgent(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: `+strconv.Itoa(closedPort(t))+`, user: deploy}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"adopt", "--config", path, "--known-hosts", kh}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want no output under the strict gate", out.String())
	}
	if !strings.Contains(errBuf.String(), "--partial") || !strings.Contains(errBuf.String(), "web-1") {
		t.Errorf("stderr = %q, want the per-server error and a --partial hint", errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	code = run([]string{"adopt", "--config", path, "--known-hosts", kh, "--partial"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("--partial exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "# WARNING: server web-1 unreadable") {
		t.Errorf("stdout = %q, want the unreadable-server comment", out.String())
	}
	if _, err := config.Parse(out.Bytes()); err != nil {
		t.Errorf("stdout is not a valid manifest: %v", err)
	}
}
```

- [x] **Step 3: Run tests to verify they fail**

Run: `go test ./cmd/sshepherd/ -run Adopt -v`
Expected: FAIL — `undefined: generateAdoptManifest` (compile error).

- [x] **Step 4: Implement `cmd/sshepherd/adopt.go`**

```go
package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshread"
)

// generateAdoptManifest renders the input manifest plus the adoption plan:
// existing sections verbatim, then new users, extensions, and new grants.
// unreadable (only non-empty under --partial) names servers whose access is
// missing from the output, as manifest comments so the gap survives stderr.
func generateAdoptManifest(cfg *config.Config, plan adopt.Plan, src string, unreadable []string) ([]byte, error) {
	m := manifestOut{Users: []userOut{}, Servers: []serverOut{}, Access: []accessOut{}}
	for _, u := range cfg.Users {
		m.Users = append(m.Users, userOut{
			Name: u.Name, Description: u.Description, Comment: u.Comment,
			Operator: u.Operator, Keys: u.Keys,
		})
	}
	for _, nu := range plan.NewUsers {
		m.Users = append(m.Users, userOut{
			Name:        nu.Name,
			Description: "adopted from " + strings.Join(nu.FoundOn, ", "),
			Keys:        []string{nu.Line},
		})
	}
	for _, s := range cfg.Servers {
		so := serverOut{Name: s.Name, Host: s.Host, User: s.User}
		if s.Port != 22 { // validation defaulted 0 to 22 already
			so.Port = s.Port
		}
		m.Servers = append(m.Servers, so)
	}
	for _, a := range cfg.Access {
		m.Access = append(m.Access, accessOut{User: a.User, Servers: a.Servers, Except: a.Except})
	}
	for _, e := range plan.Extensions {
		m.Access = append(m.Access, accessOut{User: e.User, Servers: e.Servers})
	}
	for _, nu := range plan.NewUsers {
		servers := nu.FoundOn
		if nu.Wildcard {
			servers = []string{"*"}
		}
		m.Access = append(m.Access, accessOut{User: nu.Name, Servers: servers})
	}
	var header strings.Builder
	fmt.Fprintf(&header, "# generated by sshepherd adopt from %s — review before use\n", src)
	for _, srv := range unreadable {
		fmt.Fprintf(&header, "# WARNING: server %s unreadable — its access is NOT represented\n", srv)
	}
	return encodeManifest(header.String(), m)
}

func newAdoptCmd(stdout io.Writer) *cobra.Command {
	var (
		cfgPath    string
		knownHosts string
		outPath    string
		parallel   int
		force      bool
		partial    bool
	)
	cmd := &cobra.Command{
		Use:   "adopt",
		Short: "Generate a manifest that adopts every key already installed on the fleet",
		Long: "Connects to every server in the manifest (same SSH path as audit), reads\n" +
			"the actual authorized_keys, and emits a complete new manifest in which\n" +
			"every installed key is accounted for: keys of known users found beyond\n" +
			"their grants extend that user's access; unknown keys become new users\n" +
			"with access to exactly the servers where they were found. The input\n" +
			"file is never modified — review the output, then adopt it as your\n" +
			"manifest. Any unreadable server aborts the run unless --partial is set.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if parallel < 1 {
				return fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err) // wrapcheck: wrap at package boundary
			}
			stderr := cmd.ErrOrStderr()
			var results []audit.ServerResult
			if len(cfg.Servers) > 0 {
				if err := sshread.CheckAgent(os.Getenv("SSH_AUTH_SOCK")); err != nil {
					return fmt.Errorf("agent preflight: %w", err)
				}
				khPath, err := expandHome(knownHosts)
				if err != nil {
					return err
				}
				// Preflight known_hosts once: a bad path fails with a single
				// clear error instead of N identical per-server errors.
				if err := sshread.PreflightKnownHosts(khPath); err != nil {
					return fmt.Errorf("known_hosts preflight: %w", err)
				}
				reader := &sshread.Client{
					KnownHostsPath: khPath,
					AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
					DialTimeout:    dialTimeout,
				}
				results = audit.Run(cmd.Context(), cfg, reader, audit.Options{
					Parallel:         parallel,
					PerServerTimeout: perServerTimeout,
				})
			}
			plan := adopt.Build(cfg, results)
			unreadable := plan.UnreadableServers()
			if len(unreadable) > 0 {
				level := "warning"
				if !partial {
					level = "error"
				}
				for _, is := range plan.Issues {
					fmt.Fprintf(stderr, "%s: server %s: %s\n", level, is.Server, is.Detail)
				}
				if !partial {
					// A draft generated from a partial read under-represents
					// reality; a later apply would revoke the unseen keys.
					fmt.Fprintf(stderr,
						"adopt: %d server(s) could not be fully read — nothing written; fix the errors above or re-run with --partial\n",
						len(unreadable))
					return errFleetUnreadable
				}
			}
			manifest, err := generateAdoptManifest(cfg, plan, cfgPath, unreadable)
			if err != nil {
				return err
			}
			for _, w := range plan.Warnings {
				fmt.Fprintln(stderr, "warning:", w)
			}
			if len(plan.NewUsers) == 0 && len(plan.Extensions) == 0 {
				fmt.Fprintln(stderr, "nothing to adopt: the manifest already accounts for every key found")
			}
			// Self-check: never emit a manifest our own loader would reject.
			if _, err := config.Parse(manifest); err != nil {
				return fmt.Errorf("bug: generated manifest fails validation: %w", err)
			}
			if outPath == "" {
				if _, err := stdout.Write(manifest); err != nil {
					return fmt.Errorf("write stdout: %w", err)
				}
				return nil
			}
			return writeFileNoClobber(outPath, manifest, force)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "sshepherd.yaml", "path to the manifest")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&parallel, "parallel", defaultParallel, "max concurrent server reads")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "write the manifest to this file instead of stdout")
	cmd.Flags().BoolVar(&force, "force", false, "allow --output to overwrite an existing file")
	cmd.Flags().BoolVar(&partial, "partial", false, "proceed even if some servers cannot be read (their access will be missing from the output)")
	return cmd
}
```

- [x] **Step 5: Wire into `cmd/sshepherd/run.go`**

Add the sentinel next to `errNonCompliant`:

```go
// errFleetUnreadable signals exit code 1 for adopt's strict gate: some
// servers could not be read and --partial was not given. Per-server details
// are already on stderr.
var errFleetUnreadable = errors.New("fleet not fully readable")
```

Extend the switch in `run`:

```go
	case errors.Is(err, errNonCompliant), errors.Is(err, errFleetUnreadable):
		return 1 // report already rendered; nothing more to say
```

(Replacing the existing `case errors.Is(err, errNonCompliant):` line.)

And register the command in `newRootCmd`, after the import line:

```go
	root.AddCommand(newAdoptCmd(stdout))
```

- [x] **Step 6: Generate the golden files, then verify**

Run: `go test ./cmd/sshepherd/ -run Golden -update`
Expected: PASS; `git status` shows three new files under `cmd/sshepherd/testdata/`.

Open each `adopt_*.golden` and eyeball it against the spec: header first; `adopt_mixed.golden` must show `alice` with her original `web-1` grant *plus* a separate `{user: alice, servers: [web-2]}` entry, `bob` keeping `except: [db-1]`, a `carol-laptop` user with `description: adopted from db-1, web-1, web-2` and a `["*"]` grant, and an `adopted-key-1` user granted `[db-1]`.

- [x] **Step 7: Run the full package tests**

Run: `go test ./cmd/sshepherd/ -v`
Expected: PASS — including the pre-existing import/audit tests.

- [x] **Step 8: Lint and vet**

Run: `gofmt -l ./cmd/sshepherd ./internal/adopt && go vet ./... && golangci-lint run`
Expected: no output from gofmt, no findings. If `cyclop`/`gocyclo` flags `RunE`'s complexity, extract the preflight-and-read block (agent check through `audit.Run`) into a helper `func readFleet(ctx context.Context, cfg *config.Config, knownHosts string, parallel int) ([]audit.ServerResult, error)` in `adopt.go` and re-run.

- [x] **Step 9: Commit**

```bash
git add cmd/sshepherd/ 
git commit -m "feat(cmd): sshepherd adopt — discover fleet keys into the manifest

Reads every server's authorized_keys through the audit pipeline and
emits a complete manifest: unknown keys become users, known users'
keys found beyond their grants extend access. Strict by default;
--partial proceeds past unreadable servers and marks the gap in the
output itself. Exit 1 via errFleetUnreadable mirrors audit's drift
exit.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: full verification, docs, status

**Files:**
- Modify: `CLAUDE.md` (Status section)
- Modify: `docs/superpowers/specs/2026-07-10-adopt-fleet-discovery-design.md` (Status line)

- [x] **Step 1: Full check**

Run: `make check`
Expected: every stage passes (fmt, vet, lint, deadcode, gosec, govulncheck, gitleaks, tests). `deadcode` must be clean — `generateAdoptManifest` and `newAdoptCmd` are reachable from `main` via `newRootCmd`.

- [x] **Step 2: Coverage gate**

Run: `make coverage`
Expected: total ≥ 80% (the gate fails otherwise). If `internal/adopt` drags the number down, the uncovered lines will be in `Build` branches — add the missing table case rather than trivia tests.

- [x] **Step 3: Race + fuzz smoke**

Run: `go test -race ./... && go test ./internal/adopt/ -fuzz FuzzSanitizeName -fuzztime 10s`
Expected: PASS, no crashers.

- [x] **Step 4: Update docs**

In the spec `docs/superpowers/specs/2026-07-10-adopt-fleet-discovery-design.md`, change the Status line to:

```markdown
- **Status:** Implemented (2026-07-10) — see docs/superpowers/plans/2026-07-10-adopt-fleet-discovery.md
```

In `CLAUDE.md`, extend the Status section's slice list: after the sentence describing operator users / wildcard access, append:

```markdown
A third slice, **`adopt`**, reads every server's actual `authorized_keys`
through the audit pipeline and generates a complete manifest — unknown keys
become users, known users' keys found beyond their grants extend access
(specced in `docs/superpowers/specs/2026-07-10-adopt-fleet-discovery-design.md`).
```

- [x] **Step 5: Commit**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-07-10-adopt-fleet-discovery-design.md
git commit -m "docs: mark adopt slice implemented

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Deferred (tracked in the spec, not this plan)

- Integration/E2E container-fleet flow for adopt (the SSH read path is
  unchanged and covered by audit's integration suite; adopt joins the E2E
  script when that harness next runs).
- In-place merging, comment-preserving YAML, identity-merge heuristics,
  non-default `authorized_keys` paths — all explicitly out of scope.
