# Operator Users, Wildcard Access & Critical Audit Severity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the operator's management keys a first-class manifest concept (`operator: true` — fleet-wide + protected), add `servers: ["*"]` / `except:` grants, render missing operator keys as CRITICAL in audit, and teach `sshepherd import --operator` to mark them.

**Architecture:** All grant logic stays in `internal/config` (operators expand inside `DesiredFor`, wildcards expand at validation time into the existing grants map), so `internal/audit` needs only rendering changes and `cmd/sshepherd` only flag/marshaling glue. Key-path → user matching lives in `internal/identity` next to the existing resolution code.

**Tech Stack:** Go 1.26, `gopkg.in/yaml.v3` (strict `KnownFields`), Cobra, table-driven tests + golden files (`-update`), `make check` gate.

**Spec:** `docs/superpowers/specs/2026-07-10-operator-users-wildcard-access-design.md`

Five tasks = five commits, each independently green. Work on `master` (trunk-based).

---

### Task 1: `internal/config` — the `operator` flag

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1.1: Write the failing tests**

Append to `internal/config/config_test.go`:

```go
func TestOperatorImplicitGrant(t *testing.T) {
	k1, k2 := testkeys.Line(t, 1), testkeys.Line(t, 2)
	y := `
users:
  - {name: op, operator: true, keys: ["` + k1 + `"]}
  - {name: alice, keys: ["` + k2 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
  - {name: s2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [s1]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Users[0].Operator {
		t.Error("op.Operator = false, want true")
	}
	// s2 has no access entries at all — the operator is still desired there.
	s2 := cfg.DesiredFor("s2")
	if len(s2) != 1 || s2[0].Fingerprint != mustFingerprint(t, k1) {
		t.Fatalf("DesiredFor(s2) = %d keys, want exactly the operator key", len(s2))
	}
	// s1: operator first, then alice via her grant.
	want := []string{mustFingerprint(t, k1), mustFingerprint(t, k2)}
	got := cfg.DesiredFor("s1")
	if len(got) != len(want) {
		t.Fatalf("DesiredFor(s1) = %d keys, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Fingerprint != want[i] {
			t.Errorf("DesiredFor(s1)[%d] = %s, want %s", i, got[i].Fingerprint, want[i])
		}
	}
}

func TestOperatorOrderingUsersOrderFirst(t *testing.T) {
	// alice appears first in users AND access, yet both operators must come
	// first (in users order) — a refactor to grant-order-only must fail here.
	k1, k2, k3 := testkeys.Line(t, 1), testkeys.Line(t, 2), testkeys.Line(t, 3)
	y := `
users:
  - {name: alice, keys: ["` + k1 + `"]}
  - {name: op-a, operator: true, keys: ["` + k2 + `"]}
  - {name: op-b, operator: true, keys: ["` + k3 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [s1]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{mustFingerprint(t, k2), mustFingerprint(t, k3), mustFingerprint(t, k1)}
	got := cfg.DesiredFor("s1")
	if len(got) != len(want) {
		t.Fatalf("DesiredFor(s1) = %d keys, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Fingerprint != want[i] {
			t.Errorf("DesiredFor(s1)[%d] = %s, want %s", i, got[i].Fingerprint, want[i])
		}
	}
}

func TestOperatorRedundantGrantNotDuplicated(t *testing.T) {
	k1 := testkeys.Line(t, 1)
	y := `
users:
  - {name: op, operator: true, keys: ["` + k1 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
access:
  - {user: op, servers: [s1]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v (a redundant grant for an operator must union silently)", err)
	}
	if got := len(cfg.DesiredFor("s1")); got != 1 {
		t.Errorf("DesiredFor(s1) = %d keys, want 1 (no duplicate emission)", got)
	}
}
```

And add one row to the `TestParseInvalid` table (after the `"comment with line break"` row):

```go
		{"keyless operator", `
users:
  - {name: op, operator: true}
`, "operator requires at least one valid key"},
```

- [ ] **Step 1.2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestOperator|TestParseInvalid' -v`
Expected: FAIL — the three new tests fail with `field operator not found in type config.User` (strict `KnownFields` rejects the unknown field), and the new table row fails the same way (error text mismatch).

- [ ] **Step 1.3: Implement**

In `internal/config/config.go`, make four edits.

(a) Add the field to `User` (between `Comment` and `Keys`):

```go
// User is a person (or role) and the public keys that identify them.
type User struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"` // docs only, never sent to a server
	Comment     string   `yaml:"comment"`     // written as the key comment by the apply slice
	Operator    bool     `yaml:"operator"`    // fleet-wide grant; protected from removal by apply/revoke
	Keys        []string `yaml:"keys"`
}
```

(b) Add the derived list to `Config` (inside the "Built during validation" block):

```go
	// Built during validation.
	keysByUser map[string][]authkeys.Key // user name -> parsed keys, manifest order
	owners     map[string]User           // fingerprint -> owning user
	grants     map[string][]string       // server name -> user names, access order
	operators  []string                  // operator user names, users order
```

(c) In `validateUsers`, after the `for i, line := range u.Keys { ... }` loop (still inside the user loop), add:

```go
		if u.Operator {
			if len(c.keysByUser[u.Name]) == 0 {
				errs = append(errs, fmt.Errorf("user %q: operator requires at least one valid key", u.Name))
				continue
			}
			c.operators = append(c.operators, u.Name)
		}
```

(d) Replace `DesiredFor`:

```go
// DesiredFor returns the desired key set for a server: operator users' keys
// first (users order — operators are implicitly granted every server), then
// the keys of every user granted access to it (access order). Deterministic;
// a user is never emitted twice.
func (c *Config) DesiredFor(serverName string) []authkeys.Key {
	var keys []authkeys.Key
	asOperator := make(map[string]bool, len(c.operators))
	for _, name := range c.operators {
		asOperator[name] = true
		keys = append(keys, c.keysByUser[name]...)
	}
	for _, userName := range c.grants[serverName] {
		if asOperator[userName] { // redundant grant for an operator: already emitted
			continue
		}
		keys = append(keys, c.keysByUser[userName]...)
	}
	return keys
}
```

- [ ] **Step 1.4: Run the package tests**

Run: `go test ./internal/config/ -v`
Expected: PASS (all tests, including every pre-existing one — zero-operator manifests are untouched).

- [ ] **Step 1.5: Full gate**

Run: `make check`
Expected: all green (fmt, vet, lint, deadcode, security, test).

- [ ] **Step 1.6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): operator users — fleet-wide protected keys in the manifest"
```

---

### Task 2: `internal/config` — wildcard grants with `except`

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 2.1: Write the failing tests**

Append to `internal/config/config_test.go`:

```go
func TestWildcardAccess(t *testing.T) {
	k1 := testkeys.Line(t, 1)
	// except lists s2 twice: duplicates are tolerated, not errors.
	y := `
users:
  - {name: alice, keys: ["` + k1 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
  - {name: s2, host: 10.0.0.2, user: deploy}
  - {name: s3, host: 10.0.0.3, user: deploy}
access:
  - {user: alice, servers: ["*"], except: [s2, s2]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for name, want := range map[string]int{"s1": 1, "s2": 0, "s3": 1} {
		if got := len(cfg.DesiredFor(name)); got != want {
			t.Errorf("DesiredFor(%s) = %d keys, want %d", name, got, want)
		}
	}
}
```

And add these rows to the `TestParseInvalid` table:

```go
		{"wildcard not alone", `
users:
  - {name: alice, keys: ["KEYA"]}
servers:
  - {name: s1, host: h, user: u}
access:
  - {user: alice, servers: ["*", s1]}
`, "must be the only servers entry"},
		{"except without wildcard", `
users:
  - {name: alice, keys: ["KEYA"]}
servers:
  - {name: s1, host: h, user: u}
  - {name: s2, host: h2, user: u}
access:
  - {user: alice, servers: [s1], except: [s2]}
`, "except requires servers"},
		{"unknown except server", `
users:
  - {name: alice, keys: ["KEYA"]}
servers:
  - {name: s1, host: h, user: u}
access:
  - {user: alice, servers: ["*"], except: [nope]}
`, "unknown except server"},
		{"wildcard grants nothing", `
users:
  - {name: alice, keys: ["KEYA"]}
servers:
  - {name: s1, host: h, user: u}
access:
  - {user: alice, servers: ["*"], except: [s1]}
`, "grants no servers"},
		{"wildcard empty fleet", `
users:
  - {name: alice, keys: ["KEYA"]}
access:
  - {user: alice, servers: ["*"]}
`, "grants no servers"},
		{"reserved server name", `
servers:
  - {name: "*", host: h, user: u}
`, "reserved"},
```

- [ ] **Step 2.2: Run tests to verify they fail**

Run: `go test ./internal/config/ -run 'TestWildcardAccess|TestParseInvalid' -v`
Expected: FAIL — `field except not found in type config.Access` for the except cases; the wildcard-only cases fail with `unknown server "*"` instead of the wanted messages.

- [ ] **Step 2.3: Implement**

In `internal/config/config.go`:

(a) Add `Except` to `Access`:

```go
// Access grants one user access to a list of servers. servers: ["*"] grants
// every server (including ones added later), minus the except names.
type Access struct {
	User    string   `yaml:"user"`
	Servers []string `yaml:"servers"`
	Except  []string `yaml:"except"` // only valid with servers: ["*"]
}
```

(b) Add `"slices"` to the imports.

(c) In `validateServers`, right after the empty-name check (`if s.Name == "" { ... continue }`), add:

```go
		if s.Name == "*" {
			errs = append(errs, fmt.Errorf("servers[%d]: name %q is reserved for wildcard grants", i, "*"))
			continue
		}
```

(d) In `validateAccess`, replace the body of the `for _, a := range c.Access` loop so the target list goes through expansion (the unknown-user check and the inner grant loop stay as they are):

```go
	for _, a := range c.Access {
		if !users[a.User] {
			errs = append(errs, fmt.Errorf("access: unknown user %q", a.User))
			continue
		}
		targets, tErrs := c.expandServers(a, servers)
		if len(tErrs) > 0 {
			errs = append(errs, tErrs...)
			continue
		}
		for _, srv := range targets {
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
```

(e) Add the expansion helper after `validateAccess`:

```go
// expandServers resolves an access entry's server list: ["*"] expands to
// every server (manifest order) minus the except names; explicit lists pass
// through untouched. Errors cover misused wildcard/except syntax; an entry
// that grants nothing is certainly a mistake.
func (c *Config) expandServers(a Access, servers map[string]bool) ([]string, []error) {
	if !slices.Contains(a.Servers, "*") {
		if len(a.Except) > 0 {
			return nil, []error{fmt.Errorf(`access for %q: except requires servers ["*"]`, a.User)}
		}
		return a.Servers, nil
	}
	if len(a.Servers) != 1 {
		return nil, []error{fmt.Errorf("access for %q: %q must be the only servers entry", a.User, "*")}
	}
	var errs []error
	excluded := make(map[string]bool, len(a.Except))
	for _, e := range a.Except {
		if !servers[e] {
			errs = append(errs, fmt.Errorf("access for %q: unknown except server %q", a.User, e))
			continue
		}
		excluded[e] = true // duplicates are tolerated, like grants unioning
	}
	if len(errs) > 0 {
		return nil, errs
	}
	var targets []string
	for i := range c.Servers {
		if !excluded[c.Servers[i].Name] {
			targets = append(targets, c.Servers[i].Name)
		}
	}
	if len(targets) == 0 {
		return nil, []error{fmt.Errorf("access for %q: wildcard grants no servers", a.User)}
	}
	return targets, nil
}
```

- [ ] **Step 2.4: Run the package tests**

Run: `go test ./internal/config/ -v`
Expected: PASS.

- [ ] **Step 2.5: Full gate**

Run: `make check`
Expected: all green.

- [ ] **Step 2.6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): wildcard access grants with except lists"
```

---

### Task 3: `internal/audit` — missing operator keys render as CRITICAL

**Files:**
- Modify: `internal/audit/report.go`
- Test: `internal/audit/report_test.go`
- Regenerate: `internal/audit/testdata/report_drift.golden`, `internal/audit/testdata/report_compliant.golden`
- Create (via `-update`): `internal/audit/testdata/report_critical.golden`

- [ ] **Step 3.1: Write the failing tests**

Append to `internal/audit/report_test.go`:

```go
// operatorConfig: op(k3) is an operator (desired everywhere); alice(k1) -> web-1.
func operatorConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: op, operator: true, comment: "op@sshepherd", keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("operatorConfig: %v", err)
	}
	return cfg
}

func TestRenderCriticalOperatorMissing(t *testing.T) {
	cfg := operatorConfig(t)
	// web-1: operator key missing (CRITICAL), alice present.
	// web-2: file absent — the operator key is desired and missing → CRITICAL too.
	reader := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"web-2": {FileAbsent: true},
	}}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results)
	out := buf.String()
	if got := strings.Count(out, "CRITICAL: operator key"); got != 2 {
		t.Errorf("CRITICAL rows = %d, want 2:\n%s", got, out)
	}
	if !strings.Contains(out, "(2 critical)") {
		t.Errorf("summary lacks the critical count:\n%s", out)
	}
	if ExitCode(results) != 1 {
		t.Errorf("ExitCode = %d, want 1 (severity is render-only)", ExitCode(results))
	}
	checkGolden(t, "report_critical.golden", buf.Bytes())
}

func TestRenderUnreachableServerNotCritical(t *testing.T) {
	cfg := operatorConfig(t)
	// web-1 fully compliant; web-2 unreachable — nothing knowable about its
	// keys, so it must stay a plain ERROR, not a critical finding.
	reader := &fakeReader{
		byName: map[string]ReadResult{
			"web-1": {Content: []byte(testkeys.Line(t, 3) + "\n" + testkeys.Line(t, 1) + "\n")},
		},
		errs: map[string]error{"web-2": errors.New("dial tcp 10.0.0.2:22: connection refused")},
	}
	results := Run(context.Background(), cfg, reader, Options{Parallel: 2})
	var buf bytes.Buffer
	Render(&buf, cfg, results)
	if strings.Contains(buf.String(), "CRITICAL") {
		t.Errorf("unreachable server must not render CRITICAL:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "(0 critical)") {
		t.Errorf("summary should show 0 critical:\n%s", buf.String())
	}
}
```

- [ ] **Step 3.2: Run tests to verify they fail**

Run: `go test ./internal/audit/ -run 'TestRenderCritical|TestRenderUnreachable' -v`
Expected: FAIL — `CRITICAL rows = 0, want 2`, missing `(2 critical)` / `(0 critical)` in the summary, and a missing-golden fatal.

- [ ] **Step 3.3: Implement**

In `internal/audit/report.go`:

(a) In `renderServer`, replace the `Diff.Missing` loop:

```go
	for _, k := range r.Diff.Missing {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			fmt.Fprintf(tw, "  ‼\t%s\t%s\t%s\tauthorized but MISSING (CRITICAL: operator key)\n",
				label(cfg, k), k.Fingerprint, k.Type)
			continue
		}
		fmt.Fprintf(tw, "  ✗\t%s\t%s\t%s\tauthorized but MISSING\n", label(cfg, k), k.Fingerprint, k.Type)
	}
```

(b) Change the `renderSummary` call in `Render` to `renderSummary(w, cfg, results)`, and replace `renderSummary` plus add the helper:

```go
// criticalDrift reports whether this server's drift includes a missing
// operator key — the drift class that threatens fleet access itself.
func criticalDrift(cfg *config.Config, r ServerResult) bool {
	if r.Err != nil {
		return false // unreachable: nothing knowable about its keys
	}
	for _, k := range r.Diff.Missing {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			return true
		}
	}
	return false
}

func renderSummary(w io.Writer, cfg *config.Config, results []ServerResult) {
	var compliant, drift, critical, unreachable int
	for _, r := range results {
		switch {
		case r.Err != nil:
			unreachable++
		case r.Compliant():
			compliant++
		default:
			drift++
			if criticalDrift(cfg, r) {
				critical++
			}
		}
	}
	fmt.Fprintf(w, "Summary: %d/%d servers compliant · %d with drift (%d critical) · %d unreachable  → exit %d\n",
		compliant, len(results), drift, critical, unreachable, ExitCode(results))
}
```

- [ ] **Step 3.4: Regenerate goldens and inspect the diff**

Run: `go test ./internal/audit/ -update`
Then: `git diff internal/audit/testdata/`
Expected: `report_critical.golden` is new; in `report_drift.golden` and `report_compliant.golden` the **only** change is the summary line gaining `(0 critical)`. Any other diff is a bug — stop and fix.

- [ ] **Step 3.5: Run the package tests without `-update`**

Run: `go test ./internal/audit/ -v`
Expected: PASS.

- [ ] **Step 3.6: Full gate**

Run: `make check`
Expected: all green.

- [ ] **Step 3.7: Commit**

```bash
git add internal/audit/report.go internal/audit/report_test.go internal/audit/testdata/
git commit -m "feat(audit): flag missing operator keys as CRITICAL"
```

---

### Task 4: `import --operator`

**Files:**
- Modify: `internal/identity/identity.go` (User.Operator, `claimName` extraction, `MarkOperators`)
- Modify: `cmd/sshepherd/import.go` (flag, conflict check, `userOut.Operator`, operator/wildcard emission)
- Test: `internal/identity/identity_test.go`, `cmd/sshepherd/import_test.go`
- Regenerate: `cmd/sshepherd/testdata/import_manifest_users.golden`
- Create (via `-update`): `cmd/sshepherd/testdata/import_manifest_operators.golden`

- [ ] **Step 4.1: Write the failing identity tests**

Append to `internal/identity/identity_test.go`:

```go
func TestMarkOperators(t *testing.T) {
	home := t.TempDir()
	r := Resolver{Home: home, LocalUser: "javad"}
	write := func(name, line string) string {
		t.Helper()
		p := filepath.Join(home, name)
		if err := os.WriteFile(p+".pub", []byte(line+"\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		return p
	}
	matched := write("work", testkeys.Line(t, 1))
	created := write("spare", testkeys.Line(t, 2)+" spare@laptop")

	users := []User{{Name: "javad-work", Source: "~/.ssh/work",
		Key: testkeys.Line(t, 1), Servers: []string{"web-1"}}}
	got, err := r.MarkOperators(users, []string{matched, created, created}) // repeat must dedupe
	if err != nil {
		t.Fatalf("MarkOperators: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("users = %d, want 2 (matched + created, repeat deduped)", len(got))
	}
	if !got[0].Operator || got[0].Name != "javad-work" || len(got[0].Servers) != 1 {
		t.Errorf("matched user = %+v, want operator javad-work keeping its servers", got[0])
	}
	u := got[1]
	if !u.Operator || u.Name != "javad-spare" || u.Source != created ||
		u.Comment != "spare@laptop" || len(u.Servers) != 0 {
		t.Errorf("created user = %+v, want grantless operator javad-spare", u)
	}
}

func TestMarkOperatorsPubSuffixAndTilde(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pub := filepath.Join(home, ".ssh", "id_ed25519.pub")
	if err := os.WriteFile(pub, []byte(testkeys.Line(t, 1)+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	r := Resolver{Home: home, LocalUser: "javad"}
	got, err := r.MarkOperators(nil, []string{"~/.ssh/id_ed25519.pub"})
	if err != nil {
		t.Fatalf("MarkOperators: %v", err)
	}
	if len(got) != 1 || got[0].Name != "javad-id_ed25519" || !got[0].Operator {
		t.Fatalf("users = %+v, want one operator javad-id_ed25519", got)
	}
}

func TestMarkOperatorsErrors(t *testing.T) {
	home := t.TempDir()
	bad := filepath.Join(home, "bad")
	if err := os.WriteFile(bad+".pub", []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("write bad pub: %v", err)
	}
	r := Resolver{Home: home, LocalUser: "javad"}
	for name, path := range map[string]string{
		"missing file":      filepath.Join(home, "nope"),
		"invalid key":       bad,
		"unsupported token": "%h/key",
	} {
		if _, err := r.MarkOperators(nil, []string{path}); err == nil {
			t.Errorf("%s: MarkOperators succeeded, want error (operator keys are named explicitly)", name)
		}
	}
}

func TestMarkOperatorsNameCollision(t *testing.T) {
	home := t.TempDir()
	p := filepath.Join(home, "work")
	if err := os.WriteFile(p+".pub", []byte(testkeys.Line(t, 2)+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	// A different key already claimed javad-work.
	users := []User{{Name: "javad-work", Source: "~/other/work",
		Key: testkeys.Line(t, 1), Servers: []string{"s"}}}
	r := Resolver{Home: home, LocalUser: "javad"}
	got, err := r.MarkOperators(users, []string{p})
	if err != nil {
		t.Fatalf("MarkOperators: %v", err)
	}
	if len(got) != 2 || got[1].Name != "javad-work-2" {
		t.Fatalf("users = %+v, want created operator javad-work-2", got)
	}
}
```

- [ ] **Step 4.2: Run tests to verify they fail**

Run: `go test ./internal/identity/ -run TestMarkOperators -v`
Expected: FAIL to compile — `r.MarkOperators undefined` and `unknown field Operator`.

- [ ] **Step 4.3: Implement the identity half**

In `internal/identity/identity.go`:

(a) Add to the `User` struct (after `Default`):

```go
	Operator bool     // marked via --operator: fleet-wide grant, no access entry
```

(b) Extract the collision loop from `resolution.name` into a shared helper, and rewrite `name` to use it:

```go
// claimName reserves name in taken, suffixing -2, -3, … when already claimed.
// The second return reports whether a suffix was needed.
func claimName(taken map[string]bool, name string) (string, bool) {
	if !taken[name] {
		taken[name] = true
		return name, false
	}
	for n := 2; ; n++ {
		cand := fmt.Sprintf("%s-%d", name, n)
		if !taken[cand] {
			taken[cand] = true
			return cand, true
		}
	}
}

// name assigns <LocalUser>-<base>, appending -2, -3, … when a different key
// already claimed the name.
func (res *resolution) name(base string) string {
	want := res.r.LocalUser + "-" + base
	got, collided := claimName(res.taken, want)
	if collided {
		res.warnf("user name %q already taken by another key, using %q", want, got)
	}
	return got
}
```

(c) Add `MarkOperators` at the end of the file:

```go
// MarkOperators flags the users owning the given key files as operators,
// appending a new grantless operator user for any key no resolved host uses
// (operator means "every server" regardless of what the config references).
// Paths expand like IdentityFile values and may name the private key or the
// .pub; only the .pub is ever read. Unlike Resolve, failures are errors, not
// warnings — the operator named these keys explicitly. Repeated paths that
// resolve to the same key dedupe silently.
func (r Resolver) MarkOperators(users []User, paths []string) ([]User, error) {
	byFP := make(map[string]int, len(users))
	taken := make(map[string]bool, len(users))
	for i, u := range users {
		k, err := authkeys.ParseLine(u.Key)
		if err != nil || k == nil {
			return nil, fmt.Errorf("user %q: invalid key line (bug: Resolve validated it): %v", u.Name, err)
		}
		byFP[k.Fingerprint] = i
		taken[u.Name] = true
	}
	seen := make(map[string]bool, len(paths))
	for _, raw := range paths {
		p, err := r.expand(raw)
		if err != nil {
			return nil, fmt.Errorf("operator key %q: %w", raw, err)
		}
		pubPath := p + ".pub"
		if strings.HasSuffix(p, ".pub") {
			pubPath = p
			p = strings.TrimSuffix(p, ".pub")
		}
		data, err := os.ReadFile(pubPath) // #nosec G304 -- path is the user's own --operator flag
		if err != nil {
			return nil, fmt.Errorf("operator key %q: %w (only .pub files are read)", raw, err)
		}
		line := strings.TrimSpace(string(data))
		if strings.ContainsAny(line, "\r\n") {
			return nil, fmt.Errorf("operator key %q: %s contains a line break", raw, pubPath)
		}
		k, err := authkeys.ParseLine(line)
		if err != nil {
			return nil, fmt.Errorf("operator key %q: %s is not a valid public key: %w", raw, pubPath, err)
		}
		if k == nil {
			return nil, fmt.Errorf("operator key %q: %s is not a valid public key", raw, pubPath)
		}
		if seen[k.Fingerprint] {
			continue
		}
		seen[k.Fingerprint] = true
		if i, ok := byFP[k.Fingerprint]; ok {
			users[i].Operator = true
			continue
		}
		name, _ := claimName(taken, r.LocalUser+"-"+filepath.Base(p))
		users = append(users, User{
			Name:     name,
			Source:   raw,
			Operator: true,
			Comment:  k.Comment,
			Key:      line,
		})
	}
	return users, nil
}
```

- [ ] **Step 4.4: Run the identity tests**

Run: `go test ./internal/identity/ -v`
Expected: PASS (new tests and every pre-existing one — `name` behavior is unchanged).

- [ ] **Step 4.5: Write the failing cmd tests**

In `cmd/sshepherd/import_test.go`:

(a) Update `TestGenerateManifestUsersGolden`: `javad-work` covers both servers, so with compaction it now emits `servers: ["*"]` plus a note. Replace the skipped/err assertion:

```go
	got, notes, err := generateManifest(hosts, users, "~/.ssh/config")
	if err != nil {
		t.Fatalf("generateManifest: %v", err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "wildcard") {
		t.Errorf("notes = %v, want one wildcard-compaction note for javad-work", notes)
	}
```

(keep the `config.Parse` + `DesiredFor(web-1)` + `checkGolden` assertions as they are).

(b) Append the new tests:

```go
func TestGenerateManifestOperatorGolden(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
		{Alias: "ci", HostName: "ci.internal", User: "git"},
	}
	users := []identity.User{
		// Matched operator (also a default identity): keeps its description
		// suffix, gains operator: true, loses its access entry.
		{Name: "javad-id_ed25519", Source: "~/.ssh/id_ed25519", Default: true, Operator: true,
			Key: testkeys.Line(t, 1), Servers: []string{"web-1", "ci"}},
		// Created by --operator: grantless, gets the (--operator) description.
		{Name: "javad-spare", Source: "~/.ssh/spare", Operator: true,
			Key: testkeys.Line(t, 2)},
		// Plain user, partial coverage: explicit list, no compaction.
		{Name: "javad-work", Source: "~/.ssh/work",
			Key: testkeys.Line(t, 3), Servers: []string{"web-1"}},
	}
	got, notes, err := generateManifest(hosts, users, "~/.ssh/config")
	if err != nil {
		t.Fatalf("generateManifest: %v", err)
	}
	if len(notes) != 0 {
		t.Errorf("notes = %v, want none (operators never compact; javad-work doesn't cover the fleet)", notes)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	if n := len(c.DesiredFor("ci")); n != 2 {
		t.Errorf("DesiredFor(ci) = %d keys, want 2 (both operators, no access entries)", n)
	}
	if strings.Contains(string(got), "user: javad-id_ed25519") {
		t.Errorf("operator must not get an access entry:\n%s", got)
	}
	if !strings.Contains(string(got), "(--operator)") {
		t.Errorf("created operator lacks the (--operator) description:\n%s", got)
	}
	checkGolden(t, "import_manifest_operators.golden", got)
}

func TestGenerateManifestNoCompactionSingleServer(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"}}
	users := []identity.User{{Name: "javad-work", Source: "~/.ssh/work",
		Key: testkeys.Line(t, 1), Servers: []string{"web-1"}}}
	got, notes, err := generateManifest(hosts, users, "x")
	if err != nil || len(notes) != 0 {
		t.Fatalf("notes %v, err %v — a single-server fleet says nothing about \"everywhere\"", notes, err)
	}
	if strings.Contains(string(got), `"*"`) {
		t.Errorf("single-server fleet compacted to wildcard:\n%s", got)
	}
}

func TestImportOperator(t *testing.T) {
	home := hermeticHome(t)
	referenced := filepath.Join(home, "work")
	if err := os.WriteFile(referenced+".pub", []byte(testkeys.Line(t, 1)+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	spare := filepath.Join(home, "spare")
	if err := os.WriteFile(spare+".pub", []byte(testkeys.Line(t, 2)+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	cfg := writeSSHConfig(t, "Host web-1\n  User deploy\n  IdentityFile "+referenced+"\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"import", cfg, "--operator", referenced, "--operator", spare}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	c, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("stdout is not a valid manifest: %v", err)
	}
	if n := len(c.DesiredFor("web-1")); n != 2 {
		t.Errorf("DesiredFor(web-1) = %d keys, want 2 (both operators)", n)
	}
	if !strings.Contains(out.String(), "operator: true") {
		t.Errorf("stdout = %q, want operator: true", out.String())
	}
	if strings.Contains(out.String(), "user: "+localUsername()+"-work") {
		t.Errorf("stdout = %q, an operator must not get an access entry", out.String())
	}
	if !strings.Contains(out.String(), "(--operator)") {
		t.Errorf("stdout = %q, want the (--operator) description on the created user", out.String())
	}
}

func TestImportOperatorConflictsServersOnly(t *testing.T) {
	hermeticHome(t)
	cfg := writeSSHConfig(t, "Host a\n  User u\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg, "--servers-only", "--operator", "x"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "--servers-only") {
		t.Errorf("stderr = %q, want a conflict message naming --servers-only", errBuf.String())
	}
}

func TestImportOperatorMissingKey(t *testing.T) {
	home := hermeticHome(t)
	cfg := writeSSHConfig(t, "Host a\n  User u\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"import", cfg, "--operator", filepath.Join(home, "nope")}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit = %d, want 2 (an explicitly named operator key must exist)", code)
	}
}
```

- [ ] **Step 4.6: Run tests to verify they fail**

Run: `go test ./cmd/sshepherd/ -run 'TestGenerateManifest|TestImportOperator' -v`
Expected: FAIL — `unknown flag: --operator` for the command tests; the compaction/operator manifest tests fail on missing `operator: true` / wildcard output.

- [ ] **Step 4.7: Implement the cmd half**

In `cmd/sshepherd/import.go`:

(a) `userOut` gains the field (between `Comment` and `Keys`, matching `config.User` order):

```go
type userOut struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Comment     string   `yaml:"comment,omitempty"`
	Operator    bool     `yaml:"operator,omitempty"`
	Keys        []string `yaml:"keys"`
}
```

(b) Replace the users loop in `generateManifest` (and rename the `skipped` local + return to `notes`, updating its doc comment — the slice now carries compaction notes as well as skip warnings):

```go
	// Resolve guarantees every derived user has ≥1 server; only users added
	// via --operator are grantless (their fleet-wide grant is implied).
	for _, u := range users {
		desc := "imported from " + u.Source
		switch {
		case u.Operator && len(u.Servers) == 0:
			desc += " (--operator)"
		case u.Default:
			desc += " (default identity)"
		}
		m.Users = append(m.Users, userOut{
			Name:        u.Name,
			Description: desc,
			Comment:     u.Comment,
			Operator:    u.Operator,
			Keys:        []string{u.Key},
		})
		if u.Operator {
			continue // fleet-wide grant is implied; no access entry
		}
		if len(m.Servers) >= 2 && len(u.Servers) == len(m.Servers) {
			// Grants only reference server-worthy hosts, so matching the count
			// means covering the fleet. "*" deliberately opts this user into
			// servers added later — flagged so review catches it.
			notes = append(notes, fmt.Sprintf(
				"access for %q covers every server; emitted as wildcard %q (includes servers added later)", u.Name, "*"))
			m.Access = append(m.Access, accessOut{User: u.Name, Servers: []string{"*"}})
			continue
		}
		m.Access = append(m.Access, accessOut{User: u.Name, Servers: u.Servers})
	}
```

(c) In `newImportCmd`: add the variable, the conflict check at the top of `RunE`, the `MarkOperators` call, and the flag registration:

```go
	var (
		outPath     string
		force       bool
		serversOnly bool
		operators   []string
	)
```

At the top of `RunE` (before loading the config):

```go
			if serversOnly && len(operators) > 0 {
				return fmt.Errorf("--operator conflicts with --servers-only (operators are users)")
			}
```

Inside the `if !serversOnly { ... }` block, immediately after the `idWarnings` loop:

```go
				if len(operators) > 0 {
					users, err = r.MarkOperators(users, operators)
					if err != nil {
						return fmt.Errorf("operator keys: %w", err)
					}
				}
```

With the flag registrations:

```go
	cmd.Flags().StringArrayVar(&operators, "operator", nil,
		"key file whose owner is an operator: granted every server and protected from removal (repeatable)")
```

Also extend the command's `Long` text with one sentence after the "Private keys are never read." line:

```
"Keys named via --operator become operator users: granted every server\n" +
"implicitly (no access entry) and protected from removal by future apply.\n" +
```

- [ ] **Step 4.8: Regenerate goldens and inspect**

Run: `go test ./cmd/sshepherd/ -update`
Then: `git diff cmd/sshepherd/testdata/`
Expected: `import_manifest_operators.golden` is new; in `import_manifest_users.golden` the only change is `javad-work`'s access entry becoming `servers: ["*"]`. `import_manifest.golden` (servers-only) must be untouched.

- [ ] **Step 4.9: Run the full test suite**

Run: `go test ./... -count=1`
Expected: PASS everywhere (in particular `TestImportBasic` still sees empty stderr — the ≥2-server guard keeps single-server imports compaction-free).

- [ ] **Step 4.10: Full gate**

Run: `make check`
Expected: all green (`deadcode` confirms `MarkOperators`/`claimName` are reachable from main).

- [ ] **Step 4.11: Commit**

```bash
git add internal/identity/ cmd/sshepherd/
git commit -m "feat(import): --operator marks management keys"
```

---

### Task 5: docs — mark the slice implemented

**Files:**
- Modify: `CLAUDE.md` (Status section)
- Modify: `docs/superpowers/specs/2026-07-10-operator-users-wildcard-access-design.md` (Status line)

- [ ] **Step 5.1: Update the spec status line**

In the spec, replace:

```markdown
- **Status:** Accepted (2026-07-10) — implementation pending
```

with:

```markdown
- **Status:** Implemented (2026-07-10) — see docs/superpowers/plans/2026-07-10-operator-users-wildcard-access.md
```

- [ ] **Step 5.2: Update CLAUDE.md Status**

Append to the `## Status` paragraph (after the sentence about the import slice):

```markdown
The manifest supports **operator users** (`operator: true` — fleet-wide,
protected management keys) and **wildcard access** (`servers: ["*"]` with
`except:`); audit renders missing operator keys as CRITICAL, and
`import --operator <key>` marks them at import time (specced in
`docs/superpowers/specs/2026-07-10-operator-users-wildcard-access-design.md`).
```

- [ ] **Step 5.3: Commit**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-07-10-operator-users-wildcard-access-design.md
git commit -m "docs: mark operator/wildcard slice implemented"
```

---

## Post-plan notes for the executor

- The lefthook pre-commit hook runs `gofmt` + `gitleaks --staged`; pre-push runs vet/lint/`go test -race`. `make check` per task supersedes both — if it passed, the hooks will.
- Golden files: always regenerate with `-update`, then **read the diff** before committing. A golden diff you didn't expect is a failing test with extra steps.
- YAML note: `"*"` must be quoted in manifests (bare `*` is YAML alias syntax and fails to parse — with a yaml-level error, which is acceptable).
- Deferred by spec (do NOT implement): apply/revoke protection enforcement, audit exit code for critical, `except` compaction in import, server groups/tags.
