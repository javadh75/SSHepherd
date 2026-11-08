package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRemoteSnippet(t *testing.T) {
	long := strings.Repeat("a", MaxSnippet+1)
	for _, tt := range []struct{ name, in, want string }{
		{"plain", "sh: cksum: not found", "sh: cksum: not found"},
		{"whitespace collapses to one line", "line1\n\tline2   end\n", "line1 line2 end"},
		{"leading whitespace dropped", " \n\tx", "x"},
		{"escapes and C1 stripped", "esc\x1b[31mred\u009b", "esc[31mred"},
		{"bidi stripped", "a\u202eb", "ab"},
		{"Latin letters kept", "Datei f\u00fcr J\u00fcrgen", "Datei f\u00fcr J\u00fcrgen"},
		{"Latin-1 symbols masked", "a\u00d7b\u00a0c", "a?b c"},
		{"blank-looking runes masked", "a\u2800\u3164\u115fb", "a???b"},
		{"invalid UTF-8 masked", "a\xffb", "a?b"},
		{"exactly the cap", long[:MaxSnippet], long[:MaxSnippet]},
		{"one over the cap", long, long[:MaxSnippet] + truncMark},
		{"a space that would cross the cap truncates", long[:MaxSnippet-1] + " b", long[:MaxSnippet-1] + truncMark},
		{"trailing space at the cap is dropped", long[:MaxSnippet] + " ", long[:MaxSnippet]},
	} {
		if got := RemoteSnippet(tt.in); got != tt.want {
			t.Errorf("%s: RemoteSnippet(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
	t.Run("1 MiB of braille padding", func(t *testing.T) {
		got := RemoteSnippet(strings.Repeat("\u2800", 1<<20/3) + "forged row")
		if n := utf8.RuneCountInString(got); n > MaxSnippet+utf8.RuneCountInString(truncMark) {
			t.Errorf("len = %d runes, want ≤ %d", n, MaxSnippet+utf8.RuneCountInString(truncMark))
		}
		if strings.ContainsRune(got, '\u2800') || !strings.HasSuffix(got, truncMark) {
			t.Errorf("got %q, want masked and truncated", got[:min(len(got), 64)])
		}
	})
}

func FuzzRemoteSnippet(f *testing.F) {
	f.Add("a\u2800\x1b\u202e\nb")
	f.Add(strings.Repeat("x", 300))
	f.Fuzz(func(t *testing.T, s string) {
		out := strings.TrimSuffix(RemoteSnippet(s), truncMark)
		if utf8.RuneCountInString(out) > MaxSnippet {
			t.Fatalf("over cap: %d runes", utf8.RuneCountInString(out))
		}
		for _, r := range out {
			if !snippetRune(r) {
				t.Fatalf("rune %U escaped the allow-list in %q", r, out)
			}
		}
	})
}
