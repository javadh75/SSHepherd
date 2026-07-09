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
