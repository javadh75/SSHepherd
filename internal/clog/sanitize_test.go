package clog

import "testing"

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain passes through", in: "dial web-1 ok", want: "dial web-1 ok"},
		{name: "newline becomes space", in: "line1\nline2", want: "line1 line2"},
		{name: "tab becomes space", in: "a\tb", want: "a b"},
		{name: "CR stripped", in: "a\rb", want: "ab"},
		{name: "ESC stripped", in: "evil\x1b[31mred", want: "evil[31mred"},
		{name: "C1 CSI stripped", in: "evil\u009b31mred", want: "evil31mred"},
		{name: "DEL stripped", in: "a\x7fb", want: "ab"},
		{name: "NUL stripped", in: "a\x00b", want: "ab"},
		{name: "raw C1 byte becomes replacement rune", in: "a\x9bb", want: "a\ufffdb"},
		{name: "unicode preserved", in: "clé ✓ 键", want: "clé ✓ 键"},
		{name: "bidi override (Cf) stripped", in: "user\u202eevil\u202c", want: "userevil"},
		{name: "zero-width space (Cf) stripped", in: "a\u200bb", want: "ab"},
		{name: "multi-line hint collapses", in: "bad key\n  hint: run ssh-keyscan", want: "bad key   hint: run ssh-keyscan"},
	}
	for _, tt := range tests {
		if got := sanitize(tt.in); got != tt.want {
			t.Errorf("%s: sanitize(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
}
