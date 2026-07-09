# `sshepherd import` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A `sshepherd import [path]` subcommand that converts an OpenSSH client config (default `~/.ssh/config`) into a valid servers-only SSHepherd manifest.

**Architecture:** A new `internal/sshcfg` package parses the config bottom-up (line tokenizer → glob matcher → block parser with Include expansion → per-alias resolution with OpenSSH's first-obtained-wins rule). `cmd/sshepherd/import.go` maps resolved hosts to manifest YAML, round-trips it through `config.Parse` as a self-check, and writes stdout or `-o <file>`. Warnings go to stderr; stdout carries only YAML.

**Tech Stack:** Go 1.26, Cobra, `gopkg.in/yaml.v3`. **No new dependencies.** Spec: `docs/superpowers/specs/2026-07-09-import-ssh-config-design.md`.

**Conventions used throughout:**
- Run package tests with `go test ./internal/sshcfg/ -v` or `go test ./cmd/sshepherd/ -v` from the repo root.
- Commits go directly to `master` (solo, trunk-based). Every commit message ends with the `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>` trailer (omitted below for brevity — always add it).
- Warnings are plain strings formatted `<file>:<line>: <message>` when a location is known.

---

## File structure

| File | Responsibility |
|---|---|
| `internal/sshcfg/line.go` | Line tokenizer: keyword + args, `=` form, quotes, comments |
| `internal/sshcfg/match.go` | OpenSSH pattern matching: `*`/`?` glob, `!` negation, pattern lists |
| `internal/sshcfg/sshcfg.go` | Parser (blocks, Match skipping, Include) + resolution + public `Load` |
| `internal/sshcfg/line_test.go`, `match_test.go`, `sshcfg_test.go` | Unit tests per file |
| `internal/sshcfg/fuzz_test.go` | `FuzzParse`, `FuzzMatchGlob` with seed corpus |
| `cmd/sshepherd/import.go` | `newImportCmd`, `generateManifest`, `writeFileNoClobber` |
| `cmd/sshepherd/import_test.go` | Golden test for generation + command-level tests |
| `cmd/sshepherd/testdata/import_manifest.golden` | Golden manifest snapshot |
| `cmd/sshepherd/run.go` | +1 line: wire `newImportCmd` |

---

### Task 1: `internal/sshcfg` — line tokenizer

**Files:**
- Create: `internal/sshcfg/line.go`
- Test: `internal/sshcfg/line_test.go`

- [ ] **Step 1: Write the failing test**

```go
package sshcfg

import (
	"reflect"
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		in   string
		key  string
		args []string
		ok   bool
	}{
		{"", "", nil, false},
		{"   \t ", "", nil, false},
		{"# a comment", "", nil, false},
		{"Host web-1", "host", []string{"web-1"}, true},
		{"HOST web-1 web-2", "host", []string{"web-1", "web-2"}, true},
		{"  HostName 10.0.0.1", "hostname", []string{"10.0.0.1"}, true},
		{"HostName=example.com", "hostname", []string{"example.com"}, true},
		{"Port = 2222", "port", []string{"2222"}, true},
		{"User \"deploy user\"", "user", []string{"deploy user"}, true},
		{"Host \"web 1\" web-2", "host", []string{"web 1", "web-2"}, true},
		{"IdentityFile ~/.ssh/id_ed25519", "identityfile", []string{"~/.ssh/id_ed25519"}, true},
		{"Host", "host", nil, true},         // keyword with no args: caller warns
		{"Host web-1\r", "host", []string{"web-1"}, true}, // CRLF input
	}
	for _, tt := range tests {
		key, args, ok := parseLine(tt.in)
		if key != tt.key || ok != tt.ok || !reflect.DeepEqual(args, tt.args) {
			t.Errorf("parseLine(%q) = (%q, %v, %v), want (%q, %v, %v)",
				tt.in, key, args, ok, tt.key, tt.args, tt.ok)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshcfg/ -run TestParseLine -v`
Expected: FAIL — `undefined: parseLine` (compile error).

- [ ] **Step 3: Write the implementation**

```go
// Package sshcfg reads the subset of OpenSSH client configuration needed to
// import a fleet: Host blocks (with pattern matching and Include expansion)
// resolved to per-alias HostName/Port/User values using OpenSSH's
// first-obtained-wins rule. It is a converter's reader, not a full ssh_config
// implementation: Match blocks are skipped with a warning and every other
// keyword is ignored.
package sshcfg

import (
	"strings"
	"unicode"
)

// parseLine splits one config line into a lowercased keyword and its
// arguments. Both "Key value" and "Key=value" forms are accepted, arguments
// may be double-quoted, and blank/comment lines return ok=false.
func parseLine(s string) (key string, args []string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", nil, false
	}
	i := strings.IndexFunc(s, func(r rune) bool { return r == '=' || unicode.IsSpace(r) })
	if i < 0 {
		return strings.ToLower(s), nil, true
	}
	key = strings.ToLower(s[:i])
	rest := strings.TrimSpace(s[i:])
	rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
	return key, splitArgs(rest), true
}

// splitArgs splits on whitespace, honoring double quotes. An unterminated
// quote swallows the rest of the line as one argument.
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			args = append(args, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case unicode.IsSpace(r) && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return args
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshcfg/ -run TestParseLine -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/sshcfg/line.go internal/sshcfg/line_test.go
git commit -m "feat(sshcfg): ssh_config line tokenizer"
```

---

### Task 2: `internal/sshcfg` — pattern matching

**Files:**
- Create: `internal/sshcfg/match.go`
- Test: `internal/sshcfg/match_test.go`

- [ ] **Step 1: Write the failing test**

```go
package sshcfg

import "testing"

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "x", false},
		{"web-1", "web-1", true},
		{"web-1", "web-10", false},
		{"web-*", "web-1", true},
		{"web-*", "db-1", false},
		{"web-?", "web-1", true},
		{"web-?", "web-10", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "ac", false},
		{"*a*", "bab", true},
	}
	for _, tt := range tests {
		if got := matchGlob(tt.pattern, tt.s); got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

func TestMatchPatterns(t *testing.T) {
	tests := []struct {
		patterns []string
		alias    string
		want     bool
	}{
		{[]string{"web-*"}, "web-1", true},
		{[]string{"web-*", "!web-3"}, "web-1", true},
		{[]string{"web-*", "!web-3"}, "web-3", false},   // negation excludes
		{[]string{"!web-3", "web-*"}, "web-3", false},   // order irrelevant
		{[]string{"!web-3"}, "web-1", false},            // nothing positive matched
		{[]string{"a", "b"}, "b", true},
		{[]string{"*"}, "whatever", true},
	}
	for _, tt := range tests {
		if got := matchPatterns(tt.patterns, tt.alias); got != tt.want {
			t.Errorf("matchPatterns(%v, %q) = %v, want %v", tt.patterns, tt.alias, got, tt.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshcfg/ -run 'TestMatchGlob|TestMatchPatterns' -v`
Expected: FAIL — `undefined: matchGlob`.

- [ ] **Step 3: Write the implementation**

```go
package sshcfg

import "strings"

// matchGlob implements OpenSSH host-pattern matching: '*' matches any run of
// characters (including none), '?' matches exactly one. Case-sensitive,
// byte-wise (host aliases are ASCII in practice). Iterative with single-star
// backtracking, so it cannot blow the stack on hostile patterns.
func matchGlob(pattern, s string) bool {
	pi, si := 0, 0
	star, starSi := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star, starSi = pi, si
			pi++
		case star >= 0:
			starSi++
			si = starSi
			pi = star + 1
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// matchPatterns applies a Host line's pattern list to an alias: any matching
// negated ("!") pattern excludes the alias outright; otherwise at least one
// positive pattern must match. This is OpenSSH's rule.
func matchPatterns(patterns []string, alias string) bool {
	matched := false
	for _, p := range patterns {
		if neg := strings.TrimPrefix(p, "!"); neg != p {
			if matchGlob(neg, alias) {
				return false
			}
			continue
		}
		if matchGlob(p, alias) {
			matched = true
		}
	}
	return matched
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/sshcfg/ -run 'TestMatchGlob|TestMatchPatterns' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/sshcfg/match.go internal/sshcfg/match_test.go
git commit -m "feat(sshcfg): OpenSSH glob and pattern-list matching"
```

---

### Task 3: `internal/sshcfg` — parser core + resolution (no Include yet)

**Files:**
- Create: `internal/sshcfg/sshcfg.go`
- Test: `internal/sshcfg/sshcfg_test.go`

- [ ] **Step 1: Write the failing test**

Note the test helper `parseString` — Task 4's tests reuse it.

```go
package sshcfg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// parseString writes content to a temp config and loads it with the temp dir
// as the Include base, so include tests can drop sibling files.
func parseString(t *testing.T, content string) ([]Host, []string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	hosts, warnings, err := load(path, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return hosts, warnings
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestLoadResolution(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    []Host
		warning string // "" = expect no warnings
	}{
		{
			name:   "basic block",
			config: "Host web-1\n  HostName 10.0.0.1\n  Port 2222\n  User deploy\n",
			want:   []Host{{Alias: "web-1", HostName: "10.0.0.1", Port: 2222, User: "deploy"}},
		},
		{
			name:   "hostname falls back to alias",
			config: "Host bastion\n  User ops\n",
			want:   []Host{{Alias: "bastion", HostName: "bastion", User: "ops"}},
		},
		{
			name:   "Host * supplies defaults",
			config: "Host a\n  HostName 1.2.3.4\nHost *\n  User admin\n  Port 2200\n",
			want:   []Host{{Alias: "a", HostName: "1.2.3.4", Port: 2200, User: "admin"}},
		},
		{
			name:   "first-obtained-wins: specific block seen first",
			config: "Host a\n  User specific\nHost *\n  User general\n",
			want:   []Host{{Alias: "a", HostName: "a", User: "specific"}},
		},
		{
			name: "first-obtained-wins: leading global settings win",
			// OpenSSH semantics: settings before any Host line apply to every
			// host and, being first, beat later per-host values.
			config: "User admin\nHost a\n  User later\n  HostName h\n",
			want:   []Host{{Alias: "a", HostName: "h", User: "admin"}},
		},
		{
			name:   "pattern-only block yields no entry",
			config: "Host web-*\n  User deploy\n",
			want:   nil,
		},
		{
			name: "negated pattern excludes from defaults",
			config: "Host web-1 web-2\n  HostName 10.0.0.1\n" +
				"Host web-* !web-2\n  User deploy\n",
			want: []Host{
				{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
				{Alias: "web-2", HostName: "10.0.0.1"},
			},
		},
		{
			name:    "duplicate alias: first definition wins",
			config:  "Host a\n  User u1\nHost a\n  User u2\n",
			want:    []Host{{Alias: "a", HostName: "a", User: "u1"}},
			warning: "duplicate host",
		},
		{
			name: "Match block skipped until next Host",
			config: "Host a\n  User u\nMatch host a\n  Port 9\n" +
				"Host b\n  User v\n",
			want: []Host{
				{Alias: "a", HostName: "a", User: "u"},
				{Alias: "b", HostName: "b", User: "v"},
			},
			warning: "Match block skipped",
		},
		{
			name:    "Host with no patterns warns",
			config:  "Host\nHost a\n  User u\n",
			want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
			warning: "Host with no patterns",
		},
		{
			name:    "invalid port warns and is ignored",
			config:  "Host a\n  User u\n  Port notanum\n  Port 99999\n",
			want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
			warning: "invalid port",
		},
		{
			name:    "setting with no value warns",
			config:  "Host a\n  HostName\n  User u\n",
			want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
			warning: "no value",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hosts, warnings := parseString(t, tt.config)
			if !reflect.DeepEqual(hosts, tt.want) {
				t.Errorf("hosts = %+v, want %+v", hosts, tt.want)
			}
			if tt.warning == "" && len(warnings) > 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
			if tt.warning != "" && !hasWarning(warnings, tt.warning) {
				t.Errorf("warnings %v missing %q", warnings, tt.warning)
			}
		})
	}
}

func TestLoadMissingTopLevelFile(t *testing.T) {
	_, _, err := load(filepath.Join(t.TempDir(), "nope"), t.TempDir())
	if err == nil {
		t.Fatal("load of missing file: err = nil, want error")
	}
}

func TestWarningsCarryFileAndLine(t *testing.T) {
	_, warnings := parseString(t, "Host a\n  User u\nMatch all\n")
	if len(warnings) != 1 || !strings.Contains(warnings[0], "config:3:") {
		t.Errorf("warnings = %v, want one prefixed with \"config:3:\"", warnings)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/sshcfg/ -run 'TestLoad|TestWarnings' -v`
Expected: FAIL — `undefined: load`, `undefined: Host`.

- [ ] **Step 3: Write the implementation**

`internal/sshcfg/sshcfg.go` (the package doc comment already lives in `line.go`; start this file with `package sshcfg`). The `include` case is a stub until Task 4 — it must exist so the switch shape is final, but only warns:

```go
package sshcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Host is one concrete host resolved from the config.
type Host struct {
	Alias    string
	HostName string // resolved HostName; falls back to Alias
	Port     int    // 0 when the config never set one (i.e. ssh's default 22)
	User     string // "" when the config never set one
}

type setting struct{ key, value string }

// block is one Host block: the patterns on its Host line plus the settings
// that follow, in file order. A synthetic leading block with patterns ["*"]
// holds settings that appear before any Host line (they apply globally).
type block struct {
	file     string
	line     int
	patterns []string
	settings []setting
}

type parser struct {
	includeDir string
	glob       func(string) ([]string, error) // filepath.Glob; stubbed hermetic in fuzz
	blocks     []block
	warnings   []string
	skipping   bool // inside a Match block: drop lines until the next Host
}

func newParser(includeDir string) *parser {
	return &parser{
		includeDir: includeDir,
		glob:       filepath.Glob,
		blocks:     []block{{patterns: []string{"*"}}},
	}
}

func (p *parser) warnf(format string, args ...any) {
	p.warnings = append(p.warnings, fmt.Sprintf(format, args...))
}

// Load parses the OpenSSH client config at path, following Include directives
// (relative Include paths resolve against ~/.ssh, as OpenSSH does for user
// configs), and returns the concrete hosts in first-appearance order plus
// warnings for anything skipped. The only hard error is an unreadable
// top-level file.
func Load(path string) ([]Host, []string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve home for Include: %w", err)
	}
	return load(path, filepath.Join(home, ".ssh"))
}

func load(path, includeDir string) ([]Host, []string, error) {
	p := newParser(includeDir)
	if err := p.parseFile(path, 0); err != nil {
		return nil, nil, err
	}
	return p.resolveAll(), p.warnings, nil
}

// parseFile parses one file. The top-level file (depth 0) must be readable;
// an unreadable included file only warns, matching OpenSSH's tolerance.
func (p *parser) parseFile(path string, depth int) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from the user's own config/Include
	if err != nil {
		if depth == 0 {
			return fmt.Errorf("read ssh config: %w", err)
		}
		p.warnf("include %s: unreadable: %v", path, err)
		return nil
	}
	p.parseBytes(data, path, depth)
	return nil
}

func (p *parser) parseBytes(data []byte, path string, depth int) {
	for i, raw := range strings.Split(string(data), "\n") {
		line := i + 1
		key, args, ok := parseLine(raw)
		if !ok {
			continue
		}
		switch key {
		case "host":
			p.skipping = false
			if len(args) == 0 {
				p.warnf("%s:%d: Host with no patterns", path, line)
				continue
			}
			p.blocks = append(p.blocks, block{file: path, line: line, patterns: args})
		case "match":
			p.skipping = true
			p.warnf("%s:%d: Match block skipped (cannot be evaluated statically)", path, line)
		case "include":
			if p.skipping {
				continue
			}
			p.warnf("%s:%d: Include not yet supported", path, line) // Task 4 replaces this
		case "hostname", "user", "port":
			if p.skipping {
				continue
			}
			p.addSetting(key, args, path, line)
		}
		// Every other keyword has no manifest equivalent and is ignored.
	}
}

func (p *parser) addSetting(key string, args []string, path string, line int) {
	if len(args) == 0 {
		p.warnf("%s:%d: %s with no value", path, line, key)
		return
	}
	if key == "port" {
		if n, err := strconv.Atoi(args[0]); err != nil || n < 1 || n > 65535 {
			p.warnf("%s:%d: invalid port %q", path, line, args[0])
			return
		}
	}
	cur := &p.blocks[len(p.blocks)-1]
	cur.settings = append(cur.settings, setting{key: key, value: args[0]})
}

// resolveAll enumerates concrete aliases (no wildcard, not negated) in
// first-appearance order and resolves each against every block.
func (p *parser) resolveAll() []Host {
	var hosts []Host
	seen := make(map[string]bool)
	for _, b := range p.blocks {
		for _, pat := range b.patterns {
			if pat == "" || strings.ContainsAny(pat, "*?") || strings.HasPrefix(pat, "!") {
				continue // patterns contribute defaults, never entries
			}
			if seen[pat] {
				p.warnf("%s:%d: duplicate host %q: first definition wins", b.file, b.line, pat)
				continue
			}
			seen[pat] = true
			hosts = append(hosts, p.resolveHost(pat))
		}
	}
	return hosts
}

// resolveHost applies OpenSSH's first-obtained-wins rule: scanning blocks in
// file order, the first value seen for each key sticks.
func (p *parser) resolveHost(alias string) Host {
	h := Host{Alias: alias}
	for _, b := range p.blocks {
		if !matchPatterns(b.patterns, alias) {
			continue
		}
		for _, s := range b.settings {
			switch s.key {
			case "hostname":
				if h.HostName == "" {
					h.HostName = s.value
				}
			case "port":
				if h.Port == 0 {
					h.Port, _ = strconv.Atoi(s.value) // validated at parse time
				}
			case "user":
				if h.User == "" {
					h.User = s.value
				}
			}
		}
	}
	if h.HostName == "" {
		h.HostName = alias
	}
	return h
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/sshcfg/ -v`
Expected: PASS (all tasks so far).

- [ ] **Step 5: Commit**

```bash
git add internal/sshcfg/sshcfg.go internal/sshcfg/sshcfg_test.go
git commit -m "feat(sshcfg): parse Host blocks and resolve concrete hosts (first-obtained-wins)"
```

---

### Task 4: `internal/sshcfg` — Include support

**Files:**
- Modify: `internal/sshcfg/sshcfg.go` (replace the `include` stub)
- Test: `internal/sshcfg/sshcfg_test.go` (append)

- [ ] **Step 1: Write the failing tests**

Append to `sshcfg_test.go`:

```go
// writeFiles lays out a config tree in a temp dir and returns the dir.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func loadDir(t *testing.T, dir string) ([]Host, []string) {
	t.Helper()
	hosts, warnings, err := load(filepath.Join(dir, "config"), dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return hosts, warnings
}

func TestIncludeRelative(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"config": "Include sub\n",
		"sub":    "Host a\n  User u\n",
	})
	hosts, warnings := loadDir(t, dir)
	want := []Host{{Alias: "a", HostName: "a", User: "u"}}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %+v, want %+v", hosts, want)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestIncludeGlobSorted(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"config":       "Include conf.d/*\n",
		"conf.d/10-a":  "Host a\n  User u\n",
		"conf.d/20-b":  "Host b\n  User v\n",
	})
	hosts, _ := loadDir(t, dir)
	if len(hosts) != 2 || hosts[0].Alias != "a" || hosts[1].Alias != "b" {
		t.Errorf("hosts = %+v, want [a b] in glob order", hosts)
	}
}

func TestIncludeInsideHostBlock(t *testing.T) {
	// Included lines inline at position: bare settings join the enclosing
	// block; a Host line in the included file starts a new block.
	dir := writeFiles(t, map[string]string{
		"config": "Host a\n  Include extra\nHost c\n  User w\n",
		"extra":  "  User u\nHost b\n  User v\n",
	})
	hosts, _ := loadDir(t, dir)
	want := []Host{
		{Alias: "a", HostName: "a", User: "u"},
		{Alias: "b", HostName: "b", User: "v"},
		{Alias: "c", HostName: "c", User: "w"},
	}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %+v, want %+v", hosts, want)
	}
}

func TestIncludeNoMatchWarns(t *testing.T) {
	dir := writeFiles(t, map[string]string{"config": "Include missing-*\nHost a\n  User u\n"})
	hosts, warnings := loadDir(t, dir)
	if len(hosts) != 1 {
		t.Errorf("hosts = %+v, want just a", hosts)
	}
	if !hasWarning(warnings, "matched no files") {
		t.Errorf("warnings = %v, want 'matched no files'", warnings)
	}
}

func TestIncludeDirectoryWarns(t *testing.T) {
	dir := writeFiles(t, map[string]string{"config": "Include conf.d\nHost a\n  User u\n"})
	if err := os.MkdirAll(filepath.Join(dir, "conf.d"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, warnings := loadDir(t, dir)
	if !hasWarning(warnings, "unreadable") {
		t.Errorf("warnings = %v, want 'unreadable' for directory include", warnings)
	}
}

func TestIncludeDepthCapTerminates(t *testing.T) {
	// A self-including file must terminate at the depth cap, not hang.
	dir := writeFiles(t, map[string]string{"config": "Include config\nHost a\n  User u\n"})
	hosts, warnings := loadDir(t, dir)
	if len(hosts) != 1 || hosts[0].Alias != "a" {
		t.Errorf("hosts = %+v, want exactly one 'a'", hosts)
	}
	if !hasWarning(warnings, "depth") {
		t.Errorf("warnings = %v, want a depth-cap warning", warnings)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/sshcfg/ -run TestInclude -v`
Expected: FAIL — every test trips the `"Include not yet supported"` stub (wrong hosts and/or unexpected warnings).

- [ ] **Step 3: Implement Include**

In `parseBytes`, replace the `include` case stub:

```go
		case "include":
			if p.skipping {
				continue
			}
			if len(args) == 0 {
				p.warnf("%s:%d: Include with no path", path, line)
				continue
			}
			for _, pat := range args {
				p.include(pat, path, line, depth)
			}
```

Add the constant and the method:

```go
// maxIncludeDepth mirrors OpenSSH's cap on nested Include directives.
const maxIncludeDepth = 16

// include expands one Include pattern. Relative patterns resolve against
// includeDir (~/.ssh in production). Included content is inlined at the
// Include position, so settings can join the enclosing Host block. Reading
// errors only warn; nesting is capped like OpenSSH.
func (p *parser) include(pattern, fromPath string, line, depth int) {
	if depth+1 > maxIncludeDepth {
		p.warnf("%s:%d: Include depth exceeds %d, skipping %q", fromPath, line, maxIncludeDepth, pattern)
		return
	}
	if !filepath.IsAbs(pattern) {
		pattern = filepath.Join(p.includeDir, pattern)
	}
	matches, err := p.glob(pattern)
	if err != nil || len(matches) == 0 {
		p.warnf("%s:%d: Include %q matched no files", fromPath, line, pattern)
		return
	}
	for _, m := range matches {
		_ = p.parseFile(m, depth+1) // depth > 0 never returns an error
	}
}
```

- [ ] **Step 4: Run the full package to verify everything passes**

Run: `go test ./internal/sshcfg/ -v`
Expected: PASS, including all Task 3 tests (no regression).

- [ ] **Step 5: Commit**

```bash
git add internal/sshcfg/sshcfg.go internal/sshcfg/sshcfg_test.go
git commit -m "feat(sshcfg): follow Include directives (globs, ~/.ssh-relative, depth cap)"
```

---

### Task 5: `internal/sshcfg` — fuzz targets

**Files:**
- Create: `internal/sshcfg/fuzz_test.go`

- [ ] **Step 1: Write the fuzz targets**

The seed corpus lives in the `f.Add` calls (same convention as `internal/authkeys/fuzz_test.go`). The parse target is hermetic: `glob` is stubbed so fuzz-generated `Include` lines never touch the filesystem.

```go
package sshcfg

import "testing"

// FuzzParse asserts the safety property for arbitrary config input: parsing
// and resolving must never panic or hang, and every resolved host must be
// self-consistent. The glob hook is stubbed so Include lines in fuzz input
// cannot read the real filesystem.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"Host web-1\n  HostName 10.0.0.1\n  Port 2222\n  User deploy\n",
		"Host *\n  User admin\n",
		"Host web-* !web-3\n  User deploy\n",
		"Include conf.d/*\nMatch host web-1\n  Port 9\nHost a\n  User u\n",
		"HostName=x\nPort = 22\nUser \"a b\"\n",
		"Host a a a\nPort 99999\nPort notanum\nHost\n\r\n# c\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		p := newParser("/nonexistent")
		p.glob = func(string) ([]string, error) { return nil, nil }
		p.parseBytes([]byte(in), "fuzz", 0)
		for _, h := range p.resolveAll() {
			if h.Alias == "" {
				t.Errorf("empty alias for input %q", in)
			}
			if h.HostName == "" {
				t.Errorf("empty HostName (fallback to alias broken) for input %q", in)
			}
			if h.Port < 0 || h.Port > 65535 {
				t.Errorf("port %d out of range for input %q", h.Port, in)
			}
		}
	})
}

// FuzzMatchGlob asserts the backtracking matcher terminates without panicking
// on arbitrary pattern/input pairs.
func FuzzMatchGlob(f *testing.F) {
	f.Add("web-*", "web-1")
	f.Add("*?*?*", "aaaa")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, pattern, s string) {
		_ = matchGlob(pattern, s)
	})
}
```

- [ ] **Step 2: Run seeds as unit tests**

Run: `go test ./internal/sshcfg/ -run 'FuzzParse|FuzzMatchGlob' -v`
Expected: PASS (seed corpus only).

- [ ] **Step 3: Run a short real fuzz session for each target**

Run: `go test ./internal/sshcfg/ -fuzz FuzzParse -fuzztime 30s` then `go test ./internal/sshcfg/ -fuzz FuzzMatchGlob -fuzztime 15s`
Expected: `elapsed: ...s, execs: ...` and exit 0 — no crashers. If a crasher is found, fix the parser, keep the generated `testdata/fuzz/...` file, and commit it as a regression seed.

- [ ] **Step 4: Commit**

```bash
git add internal/sshcfg/fuzz_test.go
git commit -m "test(sshcfg): fuzz parse/resolve and glob matching"
```

---

### Task 6: `cmd/sshepherd` — manifest generation + golden test

**Files:**
- Create: `cmd/sshepherd/import.go` (generation half only)
- Create: `cmd/sshepherd/testdata/import_manifest.golden` (via `-update`)
- Test: `cmd/sshepherd/import_test.go`

- [ ] **Step 1: Write the failing test**

```go
package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
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

func TestGenerateManifestGolden(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web-1", HostName: "10.0.0.1", Port: 2222, User: "deploy"},
		{Alias: "web-2", HostName: "10.0.0.2", Port: 22, User: "deploy"}, // port 22 omitted
		{Alias: "bastion", HostName: "bastion", User: "ops"},             // port 0 omitted
		{Alias: "nouser", HostName: "10.0.0.9"},                          // skipped
	}
	got, skipped, err := generateManifest(hosts, "~/.ssh/config")
	if err != nil {
		t.Fatalf("generateManifest: %v", err)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "nouser") {
		t.Errorf("skipped = %v, want one note about nouser", skipped)
	}
	if _, err := config.Parse(got); err != nil {
		t.Errorf("generated manifest rejected by config.Parse: %v", err)
	}
	checkGolden(t, "import_manifest.golden", got)
}

func TestGenerateManifestEmpty(t *testing.T) {
	got, skipped, err := generateManifest(nil, "x")
	if err != nil || len(skipped) != 0 {
		t.Fatalf("generateManifest(nil) = skipped %v, err %v", skipped, err)
	}
	if _, err := config.Parse(got); err != nil {
		t.Errorf("empty manifest rejected by config.Parse: %v", err)
	}
	if !strings.Contains(string(got), "servers: []") {
		t.Errorf("output %q missing explicit empty servers list", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./cmd/sshepherd/ -run TestGenerateManifest -v`
Expected: FAIL — `undefined: generateManifest`.

- [ ] **Step 3: Write the implementation**

Create `cmd/sshepherd/import.go`:

```go
package main

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/javadh75/SSHepherd/internal/sshcfg"
)

// serverOut mirrors config.Server for output: omitempty keeps default ports
// and the never-set description out of the generated YAML.
type serverOut struct {
	Name string `yaml:"name"`
	Host string `yaml:"host"`
	Port int    `yaml:"port,omitempty"`
	User string `yaml:"user"`
}

type manifestOut struct {
	Users   []any       `yaml:"users"`
	Servers []serverOut `yaml:"servers"`
	Access  []any       `yaml:"access"`
}

// generateManifest renders hosts as a servers-only manifest. src is the
// config path as the user typed it (kept in the header comment; the expanded
// form would leak the local home directory into a committed file). Hosts with
// no resolved User cannot form a valid server entry and are returned as skip
// notes instead.
func generateManifest(hosts []sshcfg.Host, src string) ([]byte, []string, error) {
	m := manifestOut{Users: []any{}, Servers: []serverOut{}, Access: []any{}}
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

- [ ] **Step 4: Create the golden file, then verify**

```bash
mkdir -p cmd/sshepherd/testdata
go test ./cmd/sshepherd/ -run TestGenerateManifestGolden -update
go test ./cmd/sshepherd/ -run TestGenerateManifest -v
```

Expected: PASS. **Eyeball `cmd/sshepherd/testdata/import_manifest.golden`** — it must contain the header comment, `users: []`, three servers (only `web-1` with a `port:` line), and `access: []`, roughly:

```yaml
# generated by sshepherd import from ~/.ssh/config — review before use
users: []
servers:
  - name: web-1
    host: 10.0.0.1
    port: 2222
    user: deploy
  - name: web-2
    host: 10.0.0.2
    user: deploy
  - name: bastion
    host: bastion
    user: ops
access: []
```

(Exact indentation is whatever `yaml.v3` with `SetIndent(2)` produces — the golden file locks it in; the shape above is what to verify.)

- [ ] **Step 5: Commit**

```bash
git add cmd/sshepherd/import.go cmd/sshepherd/import_test.go cmd/sshepherd/testdata/import_manifest.golden
git commit -m "feat(cmd): manifest generation for sshepherd import, golden-tested"
```

---

### Task 7: `cmd/sshepherd` — the `import` command

**Files:**
- Modify: `cmd/sshepherd/import.go` (add command + file writing)
- Modify: `cmd/sshepherd/run.go:50` (wire the command)
- Test: `cmd/sshepherd/import_test.go` (append)

- [ ] **Step 1: Write the failing tests**

Append to `cmd/sshepherd/import_test.go`:

```go
func writeSSHConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write ssh config: %v", err)
	}
	return path
}

func TestImportMissingSource(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", "/no/such/ssh_config"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, errBuf.String())
	}
}

func TestImportBasic(t *testing.T) {
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
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty for a clean import", errBuf.String())
	}
}

func TestImportWarningsGoToStderrOnly(t *testing.T) {
	path := writeSSHConfig(t, "Host nouser\n  HostName 10.0.0.9\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (zero importable servers is still success)", code)
	}
	if !strings.Contains(out.String(), "servers: []") {
		t.Errorf("stdout = %q, want empty servers list", out.String())
	}
	if !strings.Contains(errBuf.String(), "nouser") {
		t.Errorf("stderr = %q, want a skip warning naming nouser", errBuf.String())
	}
	if strings.Contains(out.String(), "warning") {
		t.Errorf("stdout = %q, must not carry warnings", out.String())
	}
}

func TestImportOutputFile(t *testing.T) {
	src := writeSSHConfig(t, "Host a\n  User u\n")
	dst := filepath.Join(t.TempDir(), "sshepherd.yaml")

	var out, errBuf bytes.Buffer
	if code := run([]string{"import", src, "-o", dst}, &out, &errBuf); code != 0 {
		t.Fatalf("first write: exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty when -o is used", out.String())
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if _, err := config.Parse(data); err != nil {
		t.Errorf("written manifest invalid: %v", err)
	}

	// Second run must refuse to clobber...
	errBuf.Reset()
	if code := run([]string{"import", src, "-o", dst}, &out, &errBuf); code != 2 {
		t.Fatalf("overwrite without --force: exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "--force") {
		t.Errorf("stderr = %q, want --force hint", errBuf.String())
	}

	// ...and --force allows it.
	if code := run([]string{"import", src, "-o", dst, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("overwrite with --force: exit = %d, want 0", code)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/sshepherd/ -run TestImport -v`
Expected: FAIL — `unknown command "import"` surfaces as exit 2 where 0 is expected (`TestImportBasic` etc.).

- [ ] **Step 3: Implement the command**

Append to `cmd/sshepherd/import.go` (add `io`, `os`, `github.com/spf13/cobra`, and `github.com/javadh75/SSHepherd/internal/config` to the imports):

```go
const defaultSSHConfig = "~/.ssh/config"

func newImportCmd(stdout io.Writer) *cobra.Command {
	var (
		outPath string
		force   bool
	)
	cmd := &cobra.Command{
		Use:   "import [ssh-config-path]",
		Short: "Convert an OpenSSH client config into a starter manifest (servers only)",
		Long: "Reads an OpenSSH client config (default ~/.ssh/config), resolves each\n" +
			"concrete Host to the HostName/Port/User that ssh would use, and emits a\n" +
			"valid SSHepherd manifest with the servers section filled in. Users and\n" +
			"access are left empty: an SSH config says how to connect, not who may\n" +
			"log in where. Warnings about skipped entries go to stderr.",
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
			manifest, skipped, err := generateManifest(hosts, src)
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
	return cmd
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

Wire it in `cmd/sshepherd/run.go` — after `root.AddCommand(newAuditCmd(stdout))` add:

```go
	root.AddCommand(newImportCmd(stdout))
```

- [ ] **Step 4: Run the full cmd package to verify it passes**

Run: `go test ./cmd/sshepherd/ -v`
Expected: PASS — all import tests plus the existing audit/run tests (no regression).

- [ ] **Step 5: Smoke-test the real binary**

```bash
go build -o bin/sshepherd ./cmd/sshepherd
printf 'Host demo\n  HostName 10.0.0.1\n  User deploy\n' > /tmp/demo_ssh_config
./bin/sshepherd import /tmp/demo_ssh_config
./bin/sshepherd import --help
```

Expected: first command prints a manifest with server `demo` and exits 0; help shows the `-o/--output` and `--force` flags.

- [ ] **Step 6: Commit**

```bash
git add cmd/sshepherd/import.go cmd/sshepherd/import_test.go cmd/sshepherd/run.go
git commit -m "feat(cmd): sshepherd import — convert ssh_config to a servers-only manifest"
```

---

### Task 8: Full check, docs, wrap-up

**Files:**
- Modify: `CLAUDE.md` (Status section)
- Modify: `docs/superpowers/specs/2026-07-09-import-ssh-config-design.md` (Status line)

- [ ] **Step 1: Run the full local gate**

Run: `make check`
Expected: gofmt/goimports clean, `go vet` clean, `golangci-lint` clean, `gosec`/`govulncheck` clean, tests green **with `-race`**, coverage ≥ 80% (`make coverage`). Fix anything it flags before proceeding — common suspects: `errcheck` on `fmt.Fprintln`, `wrapcheck` on returned errors, `gocyclo` on `parseBytes` (extract a helper if flagged).

- [ ] **Step 2: Update docs**

- `CLAUDE.md` Status section: mention that `import` (ssh_config → manifest converter, `internal/sshcfg`) is implemented alongside `audit`.
- Spec header: change `- **Status:** Approved, awaiting implementation plan.` to `- **Status:** Implemented (2026-07-09) — see docs/superpowers/plans/2026-07-09-import-ssh-config.md`.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md docs/superpowers/specs/2026-07-09-import-ssh-config-design.md
git commit -m "docs: mark import slice implemented"
```
