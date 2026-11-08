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

// MaxSnippet caps, in runes, the remote text one error line may carry.
const MaxSnippet = 256

// truncMark ends a RemoteSnippet that was cut at MaxSnippet runes.
const truncMark = "…(truncated)"

// snippetRune is the allow-list for RemoteSnippet: printable ASCII, plus
// Latin letters (U+00C0–U+024F) so ordinary localized diagnostics stay
// readable. Everything else — notably blank-looking symbols such as U+2800,
// U+3164 and U+115F that are neither space, control nor format runes —
// becomes '?'.
func snippetRune(r rune) bool {
	return (r >= 0x20 && r <= 0x7e) || (r >= 0xc0 && r <= 0x24f && unicode.IsLetter(r))
}

// RemoteSnippet renders remote-controlled text (stderr, transport
// disconnect reasons) for embedding in one error line: control and format
// runes are dropped (as Remote does), any Unicode whitespace run becomes
// one space (leading and trailing runs vanish), other runes outside
// snippetRune become '?', and the result is cut at MaxSnippet runes with
// "…(truncated)" appended — so a hostile server can neither pad a line to
// forge a report row nor flood logs and JSON with a megabyte per server.
func RemoteSnippet(s string) string {
	var b strings.Builder
	n, pendingSpace := 0, false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			pendingSpace = n > 0
			continue
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			continue
		case !snippetRune(r):
			r = '?'
		}
		need := 1
		if pendingSpace {
			need = 2
		}
		if n+need > MaxSnippet {
			b.WriteString(truncMark)
			return b.String()
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		b.WriteRune(r)
		n += need
	}
	return b.String()
}
