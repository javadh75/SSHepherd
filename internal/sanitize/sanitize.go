// Package sanitize strips terminal-hostile runes from remote-controlled
// text. It is a stdlib-only leaf so every package that renders server
// output (sshconn, audit, apply) can share one rule without import cycles.
package sanitize

import (
	"strings"
	"unicode"
)

// Remote strips control characters (except newline and tab) and Unicode
// format (Cf) runes. unicode.IsControl covers C0, DEL and C1 — C1 CSI
// (U+009B) acts like ESC [ in some terminals; Cf covers bidi overrides
// such as U+202E that visually reorder text. encoding/json does not
// escape C1 or Cf, so JSON renderers need this too. internal/clog's
// sanitize applies the same class of defense on the log path (collapsing
// newlines besides); keep the two in mind together when changing either.
func Remote(s string) string {
	return strings.Map(func(r rune) rune {
		if (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}
