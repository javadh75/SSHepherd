package adopt

import (
	"regexp"
	"testing"
)

// validName: alnum runs joined by single dashes; no leading/trailing dash.
var validName = regexp.MustCompile(`^[a-z0-9](?:-?[a-z0-9])*$`)

func FuzzSanitizeName(f *testing.F) {
	for _, seed := range []string{
		"", "alice@laptop.local", "Röot@höst", "a--b", "@@@", "ADMIN",
		"user name with spaces", "\x00\x1b[31m", "🐑@flock", "-alice-",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, comment string) {
		got := sanitizeName(comment)
		if got == "" {
			return // caller falls back to adopted-key-N
		}
		if !validName.MatchString(got) {
			t.Errorf("sanitizeName(%q) = %q: not a clean name", comment, got)
		}
		if len(got) > 64 {
			t.Errorf("sanitizeName(%q) = %q: %d chars, cap is 64", comment, got, len(got))
		}
		if again := sanitizeName(got); again != got {
			t.Errorf("not idempotent: sanitizeName(%q) = %q, re-sanitized to %q", comment, got, again)
		}
	})
}
