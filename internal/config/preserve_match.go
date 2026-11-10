package config

import "github.com/javadh75/SSHepherd/internal/authkeys"

// PreserveRuleFor reports the kind of the first preserve: rule of server
// that k's line matches (PreserveCommand: its dequoted command="…" value;
// PreserveComment: its comment), "" when none does. It judges one line;
// audit decides which fingerprints are kept (every line must match, and an
// owned, revoked or cert-only key never is; spec S6).
func (c *Config) PreserveRuleFor(server string, k authkeys.Key) string {
	for _, r := range c.preserve[server] {
		text, ok := k.Comment, true
		if r.kind == PreserveCommand {
			text, ok = authkeys.CommandOf(k.Options)
		}
		if ok && r.re.MatchString(text) {
			return r.kind
		}
	}
	return ""
}
