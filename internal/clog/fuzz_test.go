package clog

import (
	"testing"
	"unicode"
)

// FuzzSanitize pins the security property: no control rune ever survives
// sanitization (terminal-escape / log-forging injection), and the function
// is idempotent.
func FuzzSanitize(f *testing.F) {
	f.Add("plain text")
	f.Add("evil\x1b[31mred")
	f.Add("line1\nline2\tend")
	f.Add("31m csi")
	f.Add("a\x00\x7f\rb")
	f.Fuzz(func(t *testing.T, s string) {
		out := sanitize(s)
		for _, r := range out {
			if unicode.IsControl(r) {
				t.Fatalf("control rune %U survived: %q -> %q", r, s, out)
			}
		}
		if again := sanitize(out); again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, out, again)
		}
	})
}
