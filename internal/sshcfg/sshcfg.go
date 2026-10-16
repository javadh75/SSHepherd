package sshcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Host is one concrete host resolved from the config.
type Host struct {
	Alias      string
	HostName   string   // resolved HostName; falls back to Alias
	Port       int      // 0 when the config never set one (i.e. ssh's default 22)
	User       string   // "" when the config never set one
	Identities []string // raw IdentityFile values in file order; unlike the fields above, ssh accumulates these
	// Proxy is the first-obtained ProxyJump/ProxyCommand as "<Keyword> <value>"
	// (e.g. "ProxyJump bastion"); "" when unset or set to none. SSHepherd
	// dials every server directly, so callers warn about these hosts.
	Proxy string
}

type setting struct{ key, value string }

// block is one Host block: the patterns on its Host line plus the settings
// that follow, in file order. A synthetic leading block with patterns ["*"]
// holds settings that appear before any Host line (they apply globally).
//
// guards carries the Include context: a block opened inside a file included
// from Host block X applies only to aliases X matches too (OpenSSH's
// SSHCONF_NEVERMATCH: a Host line in a file included from a non-matching
// context never matches). A continuation block resumes the enclosing block
// after an Include returns — settings following the Include line still
// belong to it, as OpenSSH restores the active state — and contributes
// settings only, never host entries.
type block struct {
	file         string
	line         int
	patterns     []string
	guards       [][]string
	continuation bool
	settings     []setting
}

// matches reports whether the block applies to alias: every enclosing
// Include context and the block's own patterns must match.
func (b *block) matches(alias string) bool {
	for _, g := range b.guards {
		if !matchPatterns(g, alias) {
			return false
		}
	}
	return matchPatterns(b.patterns, alias)
}

type parser struct {
	includeDir string
	home       string                         // for expanding a leading ~/ in Include
	glob       func(string) ([]string, error) // filepath.Glob; stubbed hermetic in fuzz
	blocks     []block
	guards     [][]string // Include context new Host blocks inherit (see block)
	warnings   []string
	skipping   bool // inside a Match block: drop lines until the next Host
}

func newParser(includeDir, home string) *parser {
	return &parser{
		includeDir: includeDir,
		home:       home,
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
	return load(path, filepath.Join(home, ".ssh"), home)
}

func load(path, includeDir, home string) ([]Host, []string, error) {
	p := newParser(includeDir, home)
	if err := p.parseFile(path); err != nil {
		return nil, nil, err
	}
	return p.resolveAll(), p.warnings, nil
}

// parseFile parses the top-level file, which must be readable — the one hard
// error. Included files are read by include(), where a failure only warns.
func (p *parser) parseFile(path string) error {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from the user's own config/Include
	if err != nil {
		return fmt.Errorf("read ssh config: %w", err)
	}
	p.parseBytes(data, path, 0)
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
				// Drop the block's orphaned settings too: letting them join
				// the previous (worst case: global) block would silently
				// apply them to every host.
				p.skipping = true
				continue
			}
			p.blocks = append(p.blocks, block{file: path, line: line, patterns: args, guards: p.guards})
		case "match":
			p.skipping = true
			p.warnf("%s:%d: Match block skipped (cannot be evaluated statically)", path, line)
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
		case "hostname", "user", "port", "identityfile", "proxyjump", "proxycommand":
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
	value := args[0]
	if key == "proxycommand" {
		value = strings.Join(args, " ") // a command line, not a single token
	}
	cur := &p.blocks[len(p.blocks)-1]
	cur.settings = append(cur.settings, setting{key: key, value: value})
}

// resolveAll enumerates concrete aliases (no wildcard, not negated) in
// first-appearance order and resolves each against every block.
func (p *parser) resolveAll() []Host {
	var hosts []Host
	seen := make(map[string]bool)
	for i := range p.blocks {
		b := &p.blocks[i]
		if b.continuation {
			continue // resumes an earlier block: settings only
		}
		for _, pat := range b.patterns {
			if pat == "" || strings.ContainsAny(pat, "*?") || strings.HasPrefix(pat, "!") {
				continue // patterns contribute defaults, never entries
			}
			if !b.matches(pat) {
				p.warnf("%s:%d: host %q is in a file included from a Host block that does not match it, so ssh never applies it: skipped",
					b.file, b.line, pat)
				continue
			}
			if seen[pat] {
				p.warnf("%s:%d: duplicate host %q: first definition wins", b.file, b.line, pat)
				continue
			}
			seen[pat] = true
			h, err := p.resolveHost(pat)
			if err != nil {
				p.warnf("%s:%d: host %q: %v, skipped", b.file, b.line, pat, err)
				continue
			}
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// resolveHost applies OpenSSH's first-obtained-wins rule: scanning blocks in
// file order, the first value seen for each key sticks. ProxyJump and
// ProxyCommand share one slot (ssh honors whichever comes first). The only
// error is a HostName token that cannot be expanded statically.
func (p *parser) resolveHost(alias string) (Host, error) {
	h := Host{Alias: alias}
	proxySet := false
	for i := range p.blocks {
		b := &p.blocks[i]
		if !b.matches(alias) {
			continue
		}
		for _, s := range b.settings {
			h.apply(s, &proxySet)
		}
	}
	if h.HostName == "" {
		h.HostName = alias
		return h, nil
	}
	name, err := expandHostName(h.HostName, alias)
	if err != nil {
		return Host{}, err
	}
	h.HostName = name
	return h, nil
}

// apply folds one matching setting into h under first-obtained-wins;
// proxySet tracks the shared ProxyJump/ProxyCommand slot (a "none" value
// claims it too, disabling later defaults).
func (h *Host) apply(s setting, proxySet *bool) {
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
	case "identityfile":
		if !slices.Contains(h.Identities, s.value) {
			h.Identities = append(h.Identities, s.value)
		}
	case "proxyjump", "proxycommand":
		if !*proxySet {
			*proxySet = true
			if !strings.EqualFold(s.value, "none") {
				h.Proxy = proxyKeyword[s.key] + " " + s.value
			}
		}
	}
}

// proxyKeyword restores the canonical spelling for Host.Proxy.
var proxyKeyword = map[string]string{"proxyjump": "ProxyJump", "proxycommand": "ProxyCommand"}

// expandHostName applies the tokens OpenSSH expands in HostName: %h (the
// alias as typed) and %%. Any other token is an error — recording it raw
// would put an undialable host into the manifest.
func expandHostName(raw, alias string) (string, error) {
	if !strings.Contains(raw, "%") {
		return raw, nil
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			b.WriteByte(raw[i])
			continue
		}
		i++
		if i == len(raw) {
			return "", fmt.Errorf("HostName %q: dangling %% at end of value", raw)
		}
		switch raw[i] {
		case 'h':
			b.WriteString(alias)
		case '%':
			b.WriteByte('%')
		default:
			tok, _ := utf8.DecodeRuneInString(raw[i:])
			return "", fmt.Errorf("HostName %q: unsupported token %%%c", raw, tok)
		}
	}
	return b.String(), nil
}

// maxIncludeDepth mirrors OpenSSH's cap on nested Include directives.
const maxIncludeDepth = 16

// include expands one Include pattern. A leading ~/ resolves against the home
// directory and other relative patterns against includeDir (~/.ssh in
// production), as in OpenSSH. Included content is inlined at the Include
// position, so settings can join the enclosing Host block; Host blocks it
// opens inherit the enclosing block as a guard, and once each file returns
// the enclosing block and Match-skip state are restored, as OpenSSH
// restores its active flag. Reading errors only warn; nesting is capped
// like OpenSSH.
func (p *parser) include(pattern, fromPath string, line, depth int) {
	if depth+1 > maxIncludeDepth {
		p.warnf("%s:%d: Include depth exceeds %d, skipping %q", fromPath, line, maxIncludeDepth, pattern)
		return
	}
	switch {
	case strings.HasPrefix(pattern, "~/"):
		pattern = filepath.Join(p.home, pattern[2:])
	case !filepath.IsAbs(pattern):
		pattern = filepath.Join(p.includeDir, pattern)
	}
	matches, err := p.glob(pattern)
	if err != nil {
		p.warnf("%s:%d: Include %q: %v", fromPath, line, pattern, err)
		return
	}
	if len(matches) == 0 {
		p.warnf("%s:%d: Include %q matched no files", fromPath, line, pattern)
		return
	}
	for _, m := range matches {
		data, err := os.ReadFile(m) // #nosec G304 -- path comes from the user's own config/Include
		if err != nil {
			p.warnf("%s:%d: Include %s: unreadable: %v", fromPath, line, m, err)
			continue
		}
		p.parseIncluded(data, m, fromPath, line, depth+1)
	}
}

// parseIncluded parses one included file within the enclosing block's
// context and restores that context afterwards (see include).
func (p *parser) parseIncluded(data []byte, path, fromPath string, line, depth int) {
	enc := p.blocks[len(p.blocks)-1]
	savedGuards, savedSkip := p.guards, p.skipping
	p.guards = append(slices.Clone(enc.guards), enc.patterns)
	n := len(p.blocks)
	p.parseBytes(data, path, depth)
	p.guards, p.skipping = savedGuards, savedSkip
	if len(p.blocks) > n {
		p.blocks = append(p.blocks, block{
			file: fromPath, line: line, patterns: enc.patterns,
			guards: enc.guards, continuation: true,
		})
	}
}
