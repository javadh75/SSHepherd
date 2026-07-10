package clog

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// sanitize strips control characters from operator-facing log text so
// hostile input (server names, remote-supplied error text) cannot forge log
// lines or inject terminal escape sequences. Each newline or tab becomes a
// single space; every other control rune is dropped — unicode.IsControl
// covers C0, DEL, and C1, whose CSI (U+009B) acts like ESC [ in some
// terminals. Defense-in-depth behind sshread's sanitizeRemote: it also
// protects future log call sites that forget to sanitize. Invalid UTF-8
// never takes the fast path: strings.Map rewrites each invalid byte to
// U+FFFD, so a raw 0x9B (8-bit CSI on non-UTF-8 terminals) cannot pass
// through verbatim.
func sanitize(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl) {
		return s // fast path: log lines are almost always already clean
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, s)
}
