package sanitize

import "testing"

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

func FuzzRemote(f *testing.F) {
	f.Add("a\x1b\u009b\u202eb")
	f.Add("plain\n\ttext")
	f.Fuzz(func(t *testing.T, s string) {
		out := Remote(s)
		if Remote(out) != out {
			t.Errorf("not idempotent on %q", s)
		}
	})
}
