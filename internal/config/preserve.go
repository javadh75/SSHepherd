package config

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The preserve: rule kinds: what a rule's pattern is matched against (spec
// 2026-11-08 S6). They are also the rule values audit reports.
const (
	PreserveCommand = "command"
	PreserveComment = "comment"
)

// PreserveRule keeps another tool's lines in a managed file: a key line
// whose command="…" value (Command) or comment (Comment) fully matches the
// RE2 pattern is kept by apply and listed by audit (spec S6, D24, D24a).
// Exactly one field is set. omitempty keeps the generated manifest from
// writing comment: "" beside command:.
type PreserveRule struct {
	Command string `yaml:"command,omitempty"`
	Comment string `yaml:"comment,omitempty"`
}

// maxPreservePattern caps a preserve: pattern's length in bytes.
const maxPreservePattern = 512

// minPreservePrefix is the shortest literal prefix a pattern may have
// (regexp.LiteralPrefix of the unanchored pattern): ".*", ".+" and "/.*"
// would keep any line.
const minPreservePrefix = 4

// preserveProbes are texts no preserve: pattern may match: an empty value,
// common key comments and common forced commands. A pattern that matches one
// is broad enough to keep a stranger's key. "" and "x" can never match a
// pattern that passed the literal-prefix rule (every match begins with that
// prefix); they stay because the design lists them and FuzzLoad's oracle
// reads this list.
var preserveProbes = []string{
	"", "x", "user@host", "alice@laptop.local", "root@ip-10-0-0-1.ec2.internal",
	"ed25519-key-20260101", strings.Repeat("a", 64), "/bin/sh", "/usr/bin/rrsync /srv",
}

// preserveRule is one compiled rule: kind is PreserveCommand or
// PreserveComment, re the pattern anchored as ^(?:…)$.
type preserveRule struct {
	kind string
	re   *regexp.Regexp
}

// validatePreserve compiles every server's preserve: rules into c.preserve
// and refuses a rule that could keep a stranger's key. A jump_only server
// has no managed file, so a rule there is an error too.
func (c *Config) validatePreserve() []error {
	var errs []error
	c.preserve = make(map[string][]preserveRule)
	for _, s := range c.Servers {
		if len(s.Preserve) == 0 {
			continue
		}
		if s.JumpOnly {
			errs = append(errs, fmt.Errorf("server %q: jump_only has no managed file; remove preserve", s.Name))
			continue
		}
		for i, r := range s.Preserve {
			rule, err := compilePreserve(r)
			if err != nil {
				errs = append(errs, fmt.Errorf("server %q: preserve[%d]: %w", s.Name, i, err))
				continue
			}
			c.preserve[s.Name] = append(c.preserve[s.Name], rule)
		}
	}
	return errs
}

// compilePreserve checks one rule, in order: exactly one field, at most
// maxPreservePattern bytes, valid RE2 alone and anchored, a literal prefix
// of at least minPreservePrefix bytes, no probe matched. The anchored form
// is compiled with Compile, never MustCompile: an unterminated \Q compiles
// alone but swallows the closing ")$" (gap 7).
func compilePreserve(r PreserveRule) (preserveRule, error) {
	kind, pattern := PreserveCommand, r.Command
	switch {
	case (r.Command == "") == (r.Comment == ""):
		return preserveRule{}, errors.New("set exactly one of command: or comment:") //nolint:revive,staticcheck // the trailing colon is the YAML key comment:, as the design spells it
	case r.Comment != "":
		kind, pattern = PreserveComment, r.Comment
	}
	if len(pattern) > maxPreservePattern {
		return preserveRule{}, fmt.Errorf("pattern is %d bytes, at most %d", len(pattern), maxPreservePattern)
	}
	open, err := regexp.Compile(pattern)
	if err != nil {
		return preserveRule{}, fmt.Errorf("pattern does not compile: %w", err)
	}
	if prefix, _ := open.LiteralPrefix(); len(prefix) < minPreservePrefix {
		return preserveRule{}, fmt.Errorf("pattern %q must start with at least %d literal bytes; a top-level alternation or (?i) usually has none: write two rules", pattern, minPreservePrefix)
	}
	re, err := regexp.Compile(`^(?:` + pattern + `)$`)
	if err != nil {
		return preserveRule{}, fmt.Errorf("pattern does not compile: %w", err)
	}
	for _, p := range preserveProbes {
		if re.MatchString(p) {
			return preserveRule{}, fmt.Errorf("pattern %q also matches %q; make it specific to the tool's lines", pattern, p)
		}
	}
	return preserveRule{kind: kind, re: re}, nil
}
