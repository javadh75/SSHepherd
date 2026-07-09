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
			if len(args) == 0 {
				p.warnf("%s:%d: Include with no path", path, line)
				continue
			}
			for _, pat := range args {
				p.include(pat, path, line, depth)
			}
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
