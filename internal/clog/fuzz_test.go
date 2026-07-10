package clog

import (
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzSanitize pins the security property: no control rune ever survives
// sanitization (terminal-escape / log-forging injection), and the function
// is idempotent.
func FuzzSanitize(f *testing.F) {
	f.Add("plain text")
	f.Add("evil\x1b[31mred")
	f.Add("line1\nline2\tend")
	f.Add("\u009b31m csi")
	f.Add("a\x00\x7f\rb")
	f.Add("evil\x9b31mred")
	f.Fuzz(func(t *testing.T, s string) {
		out := sanitize(s)
		for _, r := range out {
			if unicode.IsControl(r) {
				t.Fatalf("control rune %U survived: %q -> %q", r, s, out)
			}
		}
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 survived: %q -> %q", s, out)
		}
		if again := sanitize(out); again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, out, again)
		}
	})
}
