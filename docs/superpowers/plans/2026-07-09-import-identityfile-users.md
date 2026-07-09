# Import IdentityFile → users:/access: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `sshepherd import` derives populated `users:` and `access:` sections from the config's `IdentityFile` directives (and ssh's default identities), instead of emitting them empty.

**Architecture:** `internal/sshcfg` learns the `identityfile` keyword (accumulating, OpenSSH-style). A new `internal/identity` package expands paths, reads only `.pub` files, and groups hosts per key into `User` values. `cmd/sshepherd/import.go` glues them and gains `--servers-only`.

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3`, Cobra, existing `internal/authkeys` + `internal/testkeys`.

**Spec:** docs/superpowers/specs/2026-07-09-import-identityfile-users-design.md

**Conventions:** Solo dev, trunk-based — commit directly to `master`. Run `make check` before the final commit. All warnings are values returned to the caller (no printing from internal packages), matching `sshcfg`.

---

## File structure

- Modify `internal/sshcfg/sshcfg.go` — `Host.Identities`, parse + accumulate `identityfile`.
- Modify `internal/sshcfg/sshcfg_test.go`, `internal/sshcfg/fuzz_test.go` — new cases/seeds.
- Create `internal/identity/identity.go` — token expansion, default scan, `.pub` reading, user naming/grouping.
- Create `internal/identity/identity_test.go` — hermetic table-driven tests over `t.TempDir()`.
- Modify `cmd/sshepherd/import.go` — `userOut`/`accessOut`, `generateManifest` signature, `--servers-only`, `localUsername`, help text.
- Modify `cmd/sshepherd/import_test.go` — hermetic `$HOME`, new golden + command tests.
- Create `cmd/sshepherd/testdata/import_manifest_users.golden` (via `-update`).
- Modify `CLAUDE.md`, both spec docs — status updates.

---

### Task 1: `internal/sshcfg` — parse `IdentityFile` (accumulating)

OpenSSH accumulates `IdentityFile` across all matching blocks (unlike `HostName`/`Port`/`User`, which are first-obtained-wins). Values are stored raw — no expansion in the parser.

**Files:**
- Modify: `internal/sshcfg/sshcfg.go`
- Test: `internal/sshcfg/sshcfg_test.go`, `internal/sshcfg/fuzz_test.go`

- [ ] **Step 1: Write the failing tests**

Add these cases to the `tests` table in `TestLoadResolution` (`internal/sshcfg/sshcfg_test.go`, after the "setting with no value warns" case):

```go
{
	name: "IdentityFile accumulates across matching blocks",
	config: "Host a\n  User u\n  IdentityFile ~/.ssh/first\n" +
		"Host *\n  IdentityFile %d/.ssh/second\n",
	want: []Host{{Alias: "a", HostName: "a", User: "u",
		Identities: []string{"~/.ssh/first", "%d/.ssh/second"}}},
},
{
	name:   "IdentityFile repeats dedupe",
	config: "Host a\n  User u\n  IdentityFile k\n  IdentityFile k\n",
	want:   []Host{{Alias: "a", HostName: "a", User: "u", Identities: []string{"k"}}},
},
{
	name:   "IdentityFile key=value form",
	config: "Host a\n  User u\n  IdentityFile=~/.ssh/k\n",
	want:   []Host{{Alias: "a", HostName: "a", User: "u", Identities: []string{"~/.ssh/k"}}},
},
{
	name: "IdentityFile inside Match block is skipped",
	config: "Host a\n  User u\nMatch host a\n  IdentityFile ~/.ssh/hidden\n" +
		"Host b\n  User v\n  IdentityFile ~/.ssh/k\n",
	want: []Host{
		{Alias: "a", HostName: "a", User: "u"},
		{Alias: "b", HostName: "b", User: "v", Identities: []string{"~/.ssh/k"}},
	},
	warning: "Match block skipped",
},
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/sshcfg/ -run TestLoadResolution -v`
Expected: the three new subtests FAIL (`Host` has no `Identities` field → compile error first; after adding the field it fails on empty `Identities`).

- [ ] **Step 3: Implement**

In `internal/sshcfg/sshcfg.go`:

Add the field to `Host`:

```go
// Host is one concrete host resolved from the config.
type Host struct {
	Alias      string
	HostName   string   // resolved HostName; falls back to Alias
	Port       int      // 0 when the config never set one (i.e. ssh's default 22)
	User       string   // "" when the config never set one
	Identities []string // raw IdentityFile values in file order; unlike the fields above, ssh accumulates these
}
```

In `parseBytes`, extend the settings case:

```go
		case "hostname", "user", "port", "identityfile":
```

In `resolveHost`, add a case to the `switch s.key` (needs `"slices"` added to the imports):

```go
			case "identityfile":
				if !slices.Contains(h.Identities, s.value) {
					h.Identities = append(h.Identities, s.value)
				}
```

Update the package comment in `internal/sshcfg/line.go` first sentence to mention identities:

```go
// Package sshcfg reads the subset of OpenSSH client configuration needed to
// import a fleet: Host blocks (with pattern matching and Include expansion)
// resolved to per-alias HostName/Port/User values using OpenSSH's
// first-obtained-wins rule, plus IdentityFile values, which ssh accumulates
// across matching blocks instead. It is a converter's reader, not a full
// ssh_config implementation: Match blocks are skipped with a warning and
// every other keyword is ignored.
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sshcfg/ -v`
Expected: PASS (all subtests, including pre-existing ones — `reflect.DeepEqual` still matches old cases because their `Identities` is nil).

- [ ] **Step 5: Add a fuzz seed and run the corpus**

In `internal/sshcfg/fuzz_test.go`, append to `seeds`:

```go
		"Host a\n  User u\n  IdentityFile ~/.ssh/k\nHost *\n  IdentityFile %d/k2\nIdentityFile\n",
```

Run: `go test ./internal/sshcfg/ -run FuzzParse -v` (executes seeds without fuzzing)
Expected: PASS. Optionally: `go test ./internal/sshcfg/ -fuzz FuzzParse -fuzztime 10s` — no crashes.

- [ ] **Step 6: Commit**

```bash
git add internal/sshcfg/
git commit -m "feat(sshcfg): parse IdentityFile, accumulating across blocks like OpenSSH"
```

---

### Task 2: `internal/identity` — token expansion

New package. `expand` resolves the host-independent subset of `IdentityFile` syntax: leading `~`, `%d` (home), `%u` (local user), `%%`. Anything else errors (callers warn and skip).

**Files:**
- Create: `internal/identity/identity.go`
- Create: `internal/identity/identity_test.go`

- [ ] **Step 1: Write the failing test**

`internal/identity/identity_test.go`:

```go
package identity

import (
	"strings"
	"testing"
)

func TestExpand(t *testing.T) {
	r := Resolver{Home: "/home/j", LocalUser: "javad"}
	tests := []struct {
		in, want, wantErr string
	}{
		{in: "~", want: "/home/j"},
		{in: "~/.ssh/id_ed25519", want: "/home/j/.ssh/id_ed25519"},
		{in: "%d/.ssh/key", want: "/home/j/.ssh/key"},
		{in: "/keys/%u/id", want: "/keys/javad/id"},
		{in: "/k/100%%", want: "/k/100%"},
		{in: "/abs/plain", want: "/abs/plain"},
		{in: "%h/key", wantErr: "unsupported token %h"},
		{in: "/key%", wantErr: "dangling %"},
	}
	for _, tt := range tests {
		got, err := r.expand(tt.in)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expand(%q) err = %v, want containing %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("expand(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/identity/ -v`
Expected: FAIL — package doesn't compile (`Resolver` undefined).

- [ ] **Step 3: Implement**

`internal/identity/identity.go`:

```go
// Package identity resolves the public keys behind ssh_config identities:
// explicit IdentityFile values, plus OpenSSH's default identity files for
// hosts that set none. It reads only .pub files — never private keys — and
// groups hosts by key so `sshepherd import` can emit users: and access:
// entries mirroring exactly which key the config uses where.
package identity

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Resolver locates public keys on the machine running import.
type Resolver struct {
	Home      string // for ~ / %d expansion and the default-identity scan
	LocalUser string // for %u expansion and generated user names
}

// expand resolves the host-independent subset of IdentityFile syntax: a
// leading tilde plus the %d (home), %u (local user) and %% tokens. Any other
// token depends on the connection and cannot be resolved statically.
func (r Resolver) expand(raw string) (string, error) {
	if raw == "~" {
		return r.Home, nil
	}
	if strings.HasPrefix(raw, "~/") {
		raw = filepath.Join(r.Home, raw[2:])
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			b.WriteByte(raw[i])
			continue
		}
		i++
		if i == len(raw) {
			return "", fmt.Errorf("dangling %% at end of value")
		}
		switch raw[i] {
		case 'd':
			b.WriteString(r.Home)
		case 'u':
			b.WriteString(r.LocalUser)
		case '%':
			b.WriteByte('%')
		default:
			return "", fmt.Errorf("unsupported token %%%c", raw[i])
		}
	}
	return b.String(), nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/identity/ -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/identity/
git commit -m "feat(identity): new package with IdentityFile token expansion"
```

---

### Task 3: `internal/identity` — `Resolve` for explicit identities

Core resolution: read each explicit identity's `.pub`, dedupe by fingerprint, name users `<LocalUser>-<basename>` (numeric suffix on collision), group granted aliases. Callers pass only hosts that became server entries. All failures are warnings.

**Review follow-ups folded into this task** (from Task 2's code review): `expand` must reject `~user/path` syntax (OpenSSH expands other users' homes; we can't statically — silent passthrough would surface as a confusing "no such file" later) and must not mangle multi-byte runes in the unsupported-token error. In `expand`, after the `~/` join, add:

```go
	if strings.HasPrefix(raw, "~") { // "~" and "~/" handled above; ~user is not supported
		return "", fmt.Errorf("unsupported ~user syntax")
	}
```

and change the `default:` case to decode a full rune (add `"unicode/utf8"` to imports):

```go
		default:
			r, _ := utf8.DecodeRuneInString(raw[i:])
			return "", fmt.Errorf("unsupported token %%%c", r)
```

Add to the `TestExpand` table:

```go
		{in: "~x/key", wantErr: "unsupported ~user"},
		{in: "~/%u/key", want: "/home/j/javad/key"},
		{in: "/a/~/b", want: "/a/~/b"},
		{in: "/kéys/%u", want: "/kéys/javad"},
		{in: "/key/%é", wantErr: "unsupported token %é"},
		{in: "", want: ""},
```

**Files:**
- Modify: `internal/identity/identity.go`
- Test: `internal/identity/identity_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/identity/identity_test.go` (add `"os"`, `"path/filepath"`, `"reflect"`, and the two project imports to the import block):

```go
import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// writePub writes <dir>/<name>.pub and returns the key line. It never writes
// a private key: Resolve must work from .pub files alone.
func writePub(t *testing.T, dir, name string, seed byte, comment string) string {
	t.Helper()
	line := testkeys.Line(t, seed)
	if comment != "" {
		line += " " + comment
	}
	path := filepath.Join(dir, name+".pub")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return line
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestResolveExplicitIdentity(t *testing.T) {
	home := t.TempDir()
	key := writePub(t, home, ".ssh/work", 1, "javad@laptop")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "web-1", User: "deploy", Identities: []string{"~/.ssh/work"}},
		{Alias: "web-2", User: "deploy", Identities: []string{"~/.ssh/work"}},
	})
	want := []User{{
		Name:    "javad-work",
		Source:  "~/.ssh/work",
		Comment: "javad@laptop",
		Key:     key,
		Servers: []string{"web-1", "web-2"},
	}}
	if !reflect.DeepEqual(users, want) {
		t.Errorf("users = %+v, want %+v", users, want)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestResolveMissingPub(t *testing.T) {
	r := Resolver{Home: t.TempDir(), LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/nope"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	if !hasWarning(warnings, "skipped") || !hasWarning(warnings, `no access derived for host "a"`) {
		t.Errorf("warnings = %v, want a skip note and a no-access note", warnings)
	}
}

func TestResolveInvalidPub(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "bad.pub"), []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/bad"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	if !hasWarning(warnings, "not a valid public key") {
		t.Errorf("warnings = %v, want an invalid-key note", warnings)
	}
}

func TestResolveFingerprintDedup(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, ".ssh/a", 1, "")
	writePub(t, home, ".ssh/b", 1, "") // same key material, different file
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "h1", User: "u", Identities: []string{"~/.ssh/a"}},
		{Alias: "h2", User: "u", Identities: []string{"~/.ssh/b"}},
	})
	if len(users) != 1 || users[0].Name != "javad-a" ||
		!reflect.DeepEqual(users[0].Servers, []string{"h1", "h2"}) {
		t.Errorf("users = %+v, want one javad-a granted [h1 h2]", users)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestResolveNameCollision(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, "one/id", 1, "")
	writePub(t, home, "two/id", 2, "")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "h1", User: "u", Identities: []string{"~/one/id"}},
		{Alias: "h2", User: "u", Identities: []string{"~/two/id"}},
	})
	if len(users) != 2 || users[0].Name != "javad-id" || users[1].Name != "javad-id-2" {
		t.Errorf("users = %+v, want names javad-id and javad-id-2", users)
	}
	if !hasWarning(warnings, "javad-id-2") {
		t.Errorf("warnings = %v, want a collision note mentioning javad-id-2", warnings)
	}
}

func TestResolveUnsupportedToken(t *testing.T) {
	r := Resolver{Home: t.TempDir(), LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"%h/key"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	if !hasWarning(warnings, "unsupported token") || !hasWarning(warnings, "no access derived") {
		t.Errorf("warnings = %v, want token + no-access notes", warnings)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/identity/ -v`
Expected: FAIL — `User` and `Resolve` undefined.

- [ ] **Step 3: Implement**

Append to `internal/identity/identity.go` (add `"os"`, `"slices"`, and `github.com/javadh75/SSHepherd/internal/authkeys`, `github.com/javadh75/SSHepherd/internal/sshcfg` to imports):

```go
// User is one generated manifest user: a single public key and the host
// aliases that use it, in first-appearance order.
type User struct {
	Name    string   // <LocalUser>-<key file basename>, -2/-3/… on collision
	Source  string   // IdentityFile value as written (defaults: ~/.ssh/<name>)
	Default bool     // found by the default-identity scan, not an explicit IdentityFile
	Comment string   // trailing comment of the .pub, "" when none
	Key     string   // the full public key line from the .pub
	Servers []string // granted aliases, appearance order
}

// candidate is one identity to try: the expanded private-key path plus the
// value it came from (for warnings and descriptions).
type candidate struct {
	path   string
	source string
	isDflt bool
}

// resolution accumulates users and warnings across hosts.
type resolution struct {
	r             Resolver
	users         []User
	warnings      []string
	byFingerprint map[string]int  // fingerprint -> index into users
	taken         map[string]bool // user names already assigned
	failed        map[string]bool // expanded paths already warned about
}

// Resolve maps hosts to generated users. Callers pass only hosts that became
// server entries, so every returned user is granted at least one server.
// Failures are warnings, never errors: a host whose identities cannot be
// resolved derives no access and keeps its server entry.
func (r Resolver) Resolve(hosts []sshcfg.Host) ([]User, []string) {
	res := &resolution{
		r:             r,
		byFingerprint: map[string]int{},
		taken:         map[string]bool{},
		failed:        map[string]bool{},
	}
	for _, h := range hosts {
		granted := false
		for _, c := range res.candidates(h) {
			if res.grant(c, h.Alias) {
				granted = true
			}
		}
		if !granted {
			res.warnf("no access derived for host %q", h.Alias)
		}
	}
	return res.users, res.warnings
}

func (res *resolution) warnf(format string, args ...any) {
	res.warnings = append(res.warnings, fmt.Sprintf(format, args...))
}

// candidates returns the host's explicit identities, expanded. Unsupported
// tokens warn and skip that path.
func (res *resolution) candidates(h sshcfg.Host) []candidate {
	var out []candidate
	for _, raw := range h.Identities {
		p, err := res.r.expand(raw)
		if err != nil {
			res.warnf("host %q: IdentityFile %q: %v, skipped", h.Alias, raw, err)
			continue
		}
		out = append(out, candidate{path: p, source: raw})
	}
	return out
}

// grant reads the candidate's .pub, creating or reusing its user (keys are
// deduplicated by fingerprint), and grants alias. Returns false when the key
// could not be resolved.
func (res *resolution) grant(c candidate, alias string) bool {
	if res.failed[c.path] {
		return false
	}
	pubPath := c.path + ".pub"
	data, err := os.ReadFile(pubPath) // #nosec G304 -- path comes from the user's own ssh config
	if err != nil {
		res.failed[c.path] = true
		res.warnf("identity %s: %v, skipped (only .pub files are read)", c.source, err)
		return false
	}
	line := strings.TrimSpace(string(data))
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		res.failed[c.path] = true
		res.warnf("identity %s: %s is not a valid public key, skipped", c.source, pubPath)
		return false
	}
	i, ok := res.byFingerprint[k.Fingerprint]
	if !ok {
		i = len(res.users)
		res.byFingerprint[k.Fingerprint] = i
		res.users = append(res.users, User{
			Name:    res.name(filepath.Base(c.path)),
			Source:  c.source,
			Default: c.isDflt,
			Comment: k.Comment,
			Key:     line,
		})
	}
	u := &res.users[i]
	if !slices.Contains(u.Servers, alias) {
		u.Servers = append(u.Servers, alias)
	}
	return true
}

// name assigns <LocalUser>-<base>, appending -2, -3, … when a different key
// already claimed the name.
func (res *resolution) name(base string) string {
	name := res.r.LocalUser + "-" + base
	if !res.taken[name] {
		res.taken[name] = true
		return name
	}
	for n := 2; ; n++ {
		cand := fmt.Sprintf("%s-%d", name, n)
		if !res.taken[cand] {
			res.taken[cand] = true
			res.warnf("user name %q already taken by another key, using %q", name, cand)
			return cand
		}
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/identity/ -v`
Expected: PASS (all of Task 2 + Task 3 tests).

- [ ] **Step 5: Commit**

```bash
git add internal/identity/
git commit -m "feat(identity): resolve explicit IdentityFile values to manifest users"
```

---

### Task 4: `internal/identity` — default-identity scan

Hosts with no `IdentityFile` fall back to OpenSSH's default identity list, keeping each name whose `.pub` exists in `<Home>/.ssh`.

**Files:**
- Modify: `internal/identity/identity.go`
- Test: `internal/identity/identity_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/identity/identity_test.go`:

```go
func TestResolveDefaultScan(t *testing.T) {
	home := t.TempDir()
	rsa := writePub(t, home, ".ssh/id_rsa", 3, "")
	ed := writePub(t, home, ".ssh/id_ed25519", 4, "javad@laptop")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{{Alias: "plain", User: "u"}})
	want := []User{
		{Name: "javad-id_rsa", Source: "~/.ssh/id_rsa", Default: true,
			Key: rsa, Servers: []string{"plain"}},
		{Name: "javad-id_ed25519", Source: "~/.ssh/id_ed25519", Default: true,
			Comment: "javad@laptop", Key: ed, Servers: []string{"plain"}},
	}
	if !reflect.DeepEqual(users, want) {
		t.Errorf("users = %+v, want %+v (ssh try order: id_rsa first)", users, want)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestResolveDefaultScanNothingFound(t *testing.T) {
	r := Resolver{Home: t.TempDir(), LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{{Alias: "plain", User: "u"}})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	if !hasWarning(warnings, `no access derived for host "plain"`) {
		t.Errorf("warnings = %v, want a no-access note", warnings)
	}
}

func TestResolveExplicitSuppressesDefaults(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, ".ssh/id_ed25519", 4, "")
	writePub(t, home, ".ssh/work", 5, "")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/work"}},
	})
	if len(users) != 1 || users[0].Name != "javad-work" {
		t.Errorf("users = %+v, want only javad-work (defaults suppressed)", users)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}
```

**Review follow-ups folded into this task** (test gaps from Task 3's code review) — also add:

```go
func TestResolveServersDedupWithinHost(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, ".ssh/a", 1, "")
	writePub(t, home, ".ssh/b", 1, "") // same key, second path
	r := Resolver{Home: home, LocalUser: "javad"}
	users, _ := r.Resolve([]sshcfg.Host{
		{Alias: "h1", User: "u", Identities: []string{"~/.ssh/a", "~/.ssh/b"}},
	})
	if len(users) != 1 || !reflect.DeepEqual(users[0].Servers, []string{"h1"}) {
		t.Errorf("users = %+v, want one user granted [h1] exactly once", users)
	}
}

func TestResolveFailedPathWarnsOnce(t *testing.T) {
	r := Resolver{Home: t.TempDir(), LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "h1", User: "u", Identities: []string{"~/.ssh/nope"}},
		{Alias: "h2", User: "u", Identities: []string{"~/.ssh/nope"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	skips := 0
	for _, w := range warnings {
		if strings.Contains(w, "only .pub files are read") {
			skips++
		}
	}
	if skips != 1 {
		t.Errorf("warnings = %v, want exactly one skip note for the shared path", warnings)
	}
	if !hasWarning(warnings, `no access derived for host "h1"`) || !hasWarning(warnings, `no access derived for host "h2"`) {
		t.Errorf("warnings = %v, want no-access notes for both hosts", warnings)
	}
}

func TestResolveEmptyPub(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "empty.pub"), []byte("\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/empty"}},
	})
	if len(users) != 0 || !hasWarning(warnings, "not a valid public key") {
		t.Errorf("users = %+v, warnings = %v; want none + invalid-key note", users, warnings)
	}
}

func TestResolveMixedHost(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, ".ssh/good", 1, "")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/missing", "~/.ssh/good"}},
	})
	if len(users) != 1 || !reflect.DeepEqual(users[0].Servers, []string{"a"}) {
		t.Errorf("users = %+v, want one user granted [a]", users)
	}
	if !hasWarning(warnings, "skipped") || hasWarning(warnings, "no access derived") {
		t.Errorf("warnings = %v, want a skip note but NO no-access note", warnings)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/identity/ -run TestResolveDefault -v`
Expected: `TestResolveDefaultScan` FAILs (no users derived). `TestResolveDefaultScanNothingFound` may already pass — that's fine; it pins the behavior.

- [ ] **Step 3: Implement**

In `internal/identity/identity.go`, add the default list (top-level, near `User`):

```go
// defaultIdentityNames is OpenSSH's default identity list in its try order
// (ssh_config(5), IdentityFile), used when a host sets no IdentityFile.
var defaultIdentityNames = []string{
	"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss", "id_dsa",
}
```

Extend `candidates` with the fallback (new first branch):

```go
func (res *resolution) candidates(h sshcfg.Host) []candidate {
	if len(h.Identities) == 0 {
		var out []candidate
		for _, name := range defaultIdentityNames {
			p := filepath.Join(res.r.Home, ".ssh", name)
			if _, err := os.Stat(p + ".pub"); err == nil {
				out = append(out, candidate{path: p, source: "~/.ssh/" + name, isDflt: true})
			}
		}
		return out
	}
	var out []candidate
	for _, raw := range h.Identities {
		p, err := res.r.expand(raw)
		if err != nil {
			res.warnf("host %q: IdentityFile %q: %v, skipped", h.Alias, raw, err)
			continue
		}
		out = append(out, candidate{path: p, source: raw})
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/identity/ -v`
Expected: PASS.

- [ ] **Step 5: Add a fuzz target for `expand`** (house policy: fuzz all parsers; the package's parsing surface is complete as of this task)

Append to `internal/identity/identity_test.go`:

```go
// FuzzExpand asserts expand never panics and never returns both a value and
// an error, for arbitrary input.
func FuzzExpand(f *testing.F) {
	for _, s := range []string{"~", "~/.ssh/k", "%d/%u", "%%", "%h", "~x", "a%"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		r := Resolver{Home: "/h", LocalUser: "u"}
		got, err := r.expand(in)
		if err != nil && got != "" {
			t.Errorf("expand(%q) returned both %q and error %v", in, got, err)
		}
	})
}
```

Run: `go test ./internal/identity/ -run FuzzExpand -v` (seeds only), then optionally `go test ./internal/identity/ -fuzz FuzzExpand -fuzztime 10s`.
Expected: PASS, no crashes.

- [ ] **Step 6: Commit**

```bash
git add internal/identity/
git commit -m "feat(identity): fall back to OpenSSH default identities when none set"
```

---

### Task 5: `import.go` — emit `users:`/`access:` in the manifest

`generateManifest` grows a `users []identity.User` parameter. `nil` users reproduces today's servers-only output byte-for-byte (the existing golden must not change).

**Files:**
- Modify: `cmd/sshepherd/import.go`
- Test: `cmd/sshepherd/import_test.go`
- Create: `cmd/sshepherd/testdata/import_manifest_users.golden` (via `-update`)

- [ ] **Step 1: Write the failing tests**

In `cmd/sshepherd/import_test.go`, update the two existing `generateManifest` calls to pass `nil` users:

```go
	got, skipped, err := generateManifest(hosts, nil, "~/.ssh/config")
```

```go
	got, skipped, err := generateManifest(nil, nil, "x")
```

Add the new golden test (add `"github.com/javadh75/SSHepherd/internal/identity"` and `"github.com/javadh75/SSHepherd/internal/testkeys"` to imports):

```go
func TestGenerateManifestUsersGolden(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
		{Alias: "ci", HostName: "ci.internal", Port: 2222, User: "git"},
	}
	users := []identity.User{
		{Name: "javad-id_ed25519", Source: "~/.ssh/id_ed25519", Default: true,
			Comment: "javad@laptop", Key: testkeys.Line(t, 1) + " javad@laptop",
			Servers: []string{"web-1"}},
		{Name: "javad-work", Source: "~/.ssh/work",
			Key: testkeys.Line(t, 2), Servers: []string{"web-1", "ci"}},
	}
	got, skipped, err := generateManifest(hosts, users, "~/.ssh/config")
	if err != nil || len(skipped) != 0 {
		t.Fatalf("generateManifest: skipped %v, err %v", skipped, err)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	if n := len(c.DesiredFor("web-1")); n != 2 {
		t.Errorf("DesiredFor(web-1) = %d keys, want 2", n)
	}
	checkGolden(t, "import_manifest_users.golden", got)
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/sshepherd/ -run TestGenerateManifest -v`
Expected: FAIL — compile error (`generateManifest` takes two args).

- [ ] **Step 3: Implement**

In `cmd/sshepherd/import.go`, add `"github.com/javadh75/SSHepherd/internal/identity"` to imports and replace the output types and `generateManifest`:

```go
// serverOut/userOut/accessOut mirror the config types for output: omitempty
// keeps default ports and never-set fields out of the generated YAML.
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
	Keys        []string `yaml:"keys"`
}

type accessOut struct {
	User    string   `yaml:"user"`
	Servers []string `yaml:"servers"`
}

type manifestOut struct {
	Users   []userOut   `yaml:"users"`
	Servers []serverOut `yaml:"servers"`
	Access  []accessOut `yaml:"access"`
}

// generateManifest renders hosts and derived identity users as a manifest.
// src is the config path as the user typed it (kept in the header comment;
// the expanded form would leak the local home directory into a committed
// file). Hosts with no resolved User cannot form a valid server entry and are
// returned as skip notes instead. users may be nil (--servers-only).
func generateManifest(hosts []sshcfg.Host, users []identity.User, src string) ([]byte, []string, error) {
	m := manifestOut{Users: []userOut{}, Servers: []serverOut{}, Access: []accessOut{}}
	var skipped []string
	for _, h := range hosts {
		if h.User == "" {
			skipped = append(skipped, fmt.Sprintf(
				"host %q: no User resolved, skipped (the manifest requires user)", h.Alias))
			continue
		}
		s := serverOut{Name: h.Alias, Host: h.HostName, User: h.User}
		if h.Port != 0 && h.Port != 22 {
			s.Port = h.Port
		}
		m.Servers = append(m.Servers, s)
	}
	for _, u := range users {
		desc := "imported from " + u.Source
		if u.Default {
			desc += " (default identity)"
		}
		m.Users = append(m.Users, userOut{
			Name:        u.Name,
			Description: desc,
			Comment:     u.Comment,
			Keys:        []string{u.Key},
		})
		m.Access = append(m.Access, accessOut{User: u.Name, Servers: u.Servers})
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# generated by sshepherd import from %s — review before use\n", src)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		return nil, nil, fmt.Errorf("encode manifest: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, nil, fmt.Errorf("encode manifest: %w", err)
	}
	return buf.Bytes(), skipped, nil
}
```

In `newImportCmd`'s `RunE`, update the call site for now (full wiring is Task 6):

```go
			manifest, skipped, err := generateManifest(hosts, nil, src)
```

- [ ] **Step 4: Generate the golden file, inspect, verify**

Run: `go test ./cmd/sshepherd/ -run TestGenerateManifestUsersGolden -update`
Then read `cmd/sshepherd/testdata/import_manifest_users.golden` and check: header comment, two users (first with `description: imported from ~/.ssh/id_ed25519 (default identity)` and a `comment:`), two servers, two access entries in user order.

Run: `go test ./cmd/sshepherd/ -v`
Expected: PASS — including `TestGenerateManifestGolden` against the **unchanged** `import_manifest.golden` (confirm with `git diff --stat cmd/sshepherd/testdata/import_manifest.golden` → empty).

- [ ] **Step 5: Commit**

```bash
git add cmd/sshepherd/import.go cmd/sshepherd/import_test.go cmd/sshepherd/testdata/import_manifest_users.golden
git commit -m "feat(cmd): generateManifest emits users/access from resolved identities"
```

---

### Task 6: `import.go` — wire identity resolution, `--servers-only`, hermetic tests

The command derives users by default. Existing command tests must pin `$HOME` to a temp dir or the default scan reads the developer's real `~/.ssh` (nondeterministic).

Note on the spec's "never emit a grantless user" rule: RunE passes only server-worthy hosts (`h.User != ""`) to `Resolve`, so a grantless user can never be *created* — the skipped host already produced its own "no User resolved, skipped" warning. No separate drop step is needed.

**Files:**
- Modify: `cmd/sshepherd/import.go`
- Test: `cmd/sshepherd/import_test.go`

- [ ] **Step 1: Write the failing tests**

In `cmd/sshepherd/import_test.go`, add the helper and update `TestImportBasic`:

```go
// hermeticHome points HOME at a temp dir so import's default-identity scan
// never sees the developer's real ~/.ssh.
func hermeticHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestImportBasic(t *testing.T) {
	home := hermeticHome(t)
	key := testkeys.Line(t, 9)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	path := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if _, err := config.Parse(out.Bytes()); err != nil {
		t.Errorf("stdout is not a valid manifest: %v", err)
	}
	if !strings.Contains(out.String(), "name: web-1") {
		t.Errorf("stdout = %q, want server web-1", out.String())
	}
	if !strings.Contains(out.String(), "(default identity)") {
		t.Errorf("stdout = %q, want a default-identity user", out.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty for a clean import", errBuf.String())
	}
}
```

Add `hermeticHome(t)` as the first line of `TestImportWarningsGoToStderrOnly` and `TestImportOutputFile` (no other changes to those tests).

Add the new command tests:

```go
func TestImportDerivesUsersAndAccess(t *testing.T) {
	home := hermeticHome(t)
	key := testkeys.Line(t, 7)
	keyPath := filepath.Join(home, "work")
	if err := os.WriteFile(keyPath+".pub", []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	cfg := writeSSHConfig(t, "Host web-1\n  User deploy\n  IdentityFile "+keyPath+"\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	c, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("stdout is not a valid manifest: %v", err)
	}
	if n := len(c.DesiredFor("web-1")); n != 1 {
		t.Errorf("DesiredFor(web-1) = %d keys, want 1", n)
	}
	if wantName := "name: " + localUsername() + "-work"; !strings.Contains(out.String(), wantName) {
		t.Errorf("stdout = %q, want %q", out.String(), wantName)
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty", errBuf.String())
	}
}

func TestImportServersOnly(t *testing.T) {
	hermeticHome(t)
	cfg := writeSSHConfig(t, "Host web-1\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "users: []") || !strings.Contains(out.String(), "access: []") {
		t.Errorf("stdout = %q, want empty users and access", out.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty (no identity scan with --servers-only)", errBuf.String())
	}
}

func TestImportNoIdentitiesWarns(t *testing.T) {
	hermeticHome(t) // empty home: no default keys to find
	cfg := writeSSHConfig(t, "Host web-1\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "no access derived") {
		t.Errorf("stderr = %q, want a no-access warning", errBuf.String())
	}
	if !strings.Contains(out.String(), "users: []") {
		t.Errorf("stdout = %q, want empty users", out.String())
	}
	if _, err := config.Parse(out.Bytes()); err != nil {
		t.Errorf("stdout is not a valid manifest: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/sshepherd/ -run TestImport -v`
Expected: FAIL — `localUsername` undefined; `--servers-only` unknown flag; `TestImportBasic` missing users; `TestImportNoIdentitiesWarns` missing warning.

- [ ] **Step 3: Implement**

In `cmd/sshepherd/import.go` (add `"os/user"` and `"github.com/javadh75/SSHepherd/internal/identity"` to imports — the latter is already there from Task 5):

```go
// localUsername names generated users. Best-effort: os/user, then $USER.
func localUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if s := os.Getenv("USER"); s != "" {
		return s
	}
	return "user"
}
```

Update `newImportCmd` — new flag variable, help text, and RunE wiring:

```go
func newImportCmd(stdout io.Writer) *cobra.Command {
	var (
		outPath     string
		force       bool
		serversOnly bool
	)
	cmd := &cobra.Command{
		Use:   "import [ssh-config-path]",
		Short: "Convert an OpenSSH client config into a starter manifest",
		Long: "Reads an OpenSSH client config (default ~/.ssh/config), resolves each\n" +
			"concrete Host to the HostName/Port/User that ssh would use, and emits a\n" +
			"valid SSHepherd manifest. users: and access: are derived from each host's\n" +
			"IdentityFile (or ssh's default identities when none is set) by reading the\n" +
			"matching .pub files on this machine — run import where you actually ssh\n" +
			"from, and review the result before use. Private keys are never read.\n" +
			"Warnings about skipped entries go to stderr.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			src := defaultSSHConfig
			if len(args) == 1 {
				src = args[0]
			}
			srcPath, err := expandHome(src)
			if err != nil {
				return err
			}
			hosts, warnings, err := sshcfg.Load(srcPath)
			if err != nil {
				return fmt.Errorf("load ssh config: %w", err) // wrapcheck: wrap at package boundary
			}
			stderr := cmd.ErrOrStderr()
			for _, w := range warnings {
				fmt.Fprintln(stderr, "warning:", w)
			}
			var users []identity.User
			if !serversOnly {
				home, err := os.UserHomeDir()
				if err != nil {
					return fmt.Errorf("resolve home for identities: %w", err)
				}
				var withUser []sshcfg.Host
				for _, h := range hosts {
					if h.User != "" { // hosts skipped as servers must not derive grants
						withUser = append(withUser, h)
					}
				}
				r := identity.Resolver{Home: home, LocalUser: localUsername()}
				var idWarnings []string
				users, idWarnings = r.Resolve(withUser)
				for _, w := range idWarnings {
					fmt.Fprintln(stderr, "warning:", w)
				}
			}
			manifest, skipped, err := generateManifest(hosts, users, src)
			if err != nil {
				return err
			}
			for _, s := range skipped {
				fmt.Fprintln(stderr, "warning:", s)
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
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "write the manifest to this file instead of stdout")
	cmd.Flags().BoolVar(&force, "force", false, "allow --output to overwrite an existing file")
	cmd.Flags().BoolVar(&serversOnly, "servers-only", false, "emit only the servers section (skip deriving users/access)")
	return cmd
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./cmd/sshepherd/ -v`
Expected: PASS, all import tests.

Run: `go test -race ./...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add cmd/sshepherd/import.go cmd/sshepherd/import_test.go
git commit -m "feat(cmd): import derives users/access from identities; --servers-only opts out"
```

---

### Task 7: docs, status updates, full quality gate

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/specs/2026-07-09-import-ssh-config-design.md`
- Modify: `docs/superpowers/specs/2026-07-09-import-identityfile-users-design.md`

- [ ] **Step 1: Update the docs**

In `docs/superpowers/specs/2026-07-09-import-identityfile-users-design.md`, change the Status line:

```markdown
- **Status:** Implemented (2026-07-09) — see docs/superpowers/plans/2026-07-09-import-identityfile-users.md
```

In `docs/superpowers/specs/2026-07-09-import-ssh-config-design.md`, amend the first "Deliberately deferred" bullet:

```markdown
- Synthesizing `users:`/`access:` (e.g. from `IdentityFile` `.pub` files) —
  implemented later; see 2026-07-09-import-identityfile-users-design.md.
```

In `CLAUDE.md`, extend the Status paragraph's import sentence:

```markdown
**`import`** — an OpenSSH client config → manifest converter built on `internal/sshcfg`
(specced in `docs/superpowers/specs/2026-07-09-import-ssh-config-design.md`), which also
derives `users:`/`access:` from `IdentityFile` `.pub` files via `internal/identity`
(specced in `docs/superpowers/specs/2026-07-09-import-identityfile-users-design.md`).
```

- [ ] **Step 2: Run the full quality gate**

Run: `make check`
Expected: gofmt/goimports clean, `go vet` clean, golangci-lint clean, gosec clean (the one new file read is `#nosec G304`-annotated like its siblings), tests pass.

Run: `make coverage`
Expected: total ≥ 80% (`internal/identity` is fully table-tested; the gate must not drop).

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/
git commit -m "docs: mark IdentityFile users/access import slice implemented"
```
