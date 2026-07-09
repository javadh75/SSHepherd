package sshcfg

import "testing"

// FuzzParse asserts the safety property for arbitrary config input: parsing
// and resolving must never panic or hang, and every resolved host must be
// self-consistent. The glob hook is stubbed so Include lines in fuzz input
// cannot read the real filesystem.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"Host web-1\n  HostName 10.0.0.1\n  Port 2222\n  User deploy\n",
		"Host *\n  User admin\n",
		"Host web-* !web-3\n  User deploy\n",
		"Include conf.d/*\nMatch host web-1\n  Port 9\nHost a\n  User u\n",
		"HostName=x\nPort = 22\nUser \"a b\"\n",
		"Host a a a\nPort 99999\nPort notanum\nHost\n\r\n# c\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		p := newParser("/nonexistent", "/nonexistent")
		p.glob = func(string) ([]string, error) { return nil, nil }
		p.parseBytes([]byte(in), "fuzz", 0)
		for _, h := range p.resolveAll() {
			if h.Alias == "" {
				t.Errorf("empty alias for input %q", in)
			}
			if h.HostName == "" {
				t.Errorf("empty HostName (fallback to alias broken) for input %q", in)
			}
			if h.Port < 0 || h.Port > 65535 {
				t.Errorf("port %d out of range for input %q", h.Port, in)
			}
		}
	})
}

// FuzzMatchGlob asserts the backtracking matcher terminates without panicking
// on arbitrary pattern/input pairs.
func FuzzMatchGlob(f *testing.F) {
	f.Add("web-*", "web-1")
	f.Add("*?*?*", "aaaa")
	f.Add("", "")
	f.Fuzz(func(_ *testing.T, pattern, s string) {
		_ = matchGlob(pattern, s)
	})
}
