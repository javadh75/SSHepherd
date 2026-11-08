package sanitize

import (
	"testing"
	"unicode"
	"unicode/utf8"
)

func TestRemote(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"plain", "plain"},
		{"", ""},
		{"keep\nnewline\tand tab", "keep\nnewline\tand tab"},
		{"esc\x1b[31mred", "esc[31mred"},
		{"c1\u009bcsi", "c1csi"},
		{"del\x7f", "del"},
		{"nul\x00cr\r", "nulcr"},
		{"bidi\u202eevil", "bidievil"},
		{"zwj\u200d", "zwj"},
		{"bom\ufeff", "bom"},
		{"ünïcode ok", "ünïcode ok"},
	} {
		if got := Remote(tt.in); got != tt.want {
			t.Errorf("Remote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// FuzzRemote checks the safety property, not just idempotence: no control
// rune other than newline and tab, and no Unicode format (Cf) rune, survives
// Remote, the output is valid UTF-8, and a second pass changes nothing.
func FuzzRemote(f *testing.F) {
	f.Add("a\x1b\u009b\u202eb")
	f.Add("plain\n\ttext")
	f.Add("bom\ufeff zwj\u200d lre\u202a")
	f.Add("bad utf8 \xff\xfe")
	f.Fuzz(func(t *testing.T, s string) {
		out := Remote(s)
		for _, r := range out {
			if r == '\n' || r == '\t' {
				continue
			}
			if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
				t.Fatalf("hostile rune %U survived: %q -> %q", r, s, out)
			}
		}
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 survived: %q -> %q", s, out)
		}
		if Remote(out) != out {
			t.Fatalf("not idempotent: %q -> %q", s, out)
		}
	})
}
