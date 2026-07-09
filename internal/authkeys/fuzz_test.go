package authkeys

import "testing"

// FuzzParseLine asserts the core safety property: parsing arbitrary, possibly
// malicious authorized_keys input must never panic, and any key it does return
// must be self-consistent. authorized_keys lines are untrusted input, so this
// path is a prime crash/injection surface.
func FuzzParseLine(f *testing.F) {
	seeds := []string{
		"",
		"   ",
		"# comment",
		"this is not a key",
		"no-port-forwarding ssh-ed25519 AAAA",
	}
	if line, err := deterministicKeyLine(); err == nil {
		seeds = append(seeds, line, line+" bob@host")
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		k, err := ParseLine(line)
		if err == nil && k != nil && k.Type == "" {
			t.Errorf("parsed key has empty Type for input %q", line)
		}
	})
}

// FuzzParseFile asserts whole-file parsing never panics on arbitrary input and
// reports coherent results: every error has a valid 1-based line number and
// every parsed key is self-consistent.
func FuzzParseFile(f *testing.F) {
	seeds := []string{
		"",
		"\n\n\n",
		"# only comments\n# more\n",
		"garbage\nmore garbage\n",
		"line1\r\nline2\r\n",
	}
	if line, err := deterministicKeyLine(); err == nil {
		seeds = append(seeds,
			line+"\n",
			"# c\n"+line+" alice@laptop\nnot a key\n"+line+"\n",
		)
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, in string) {
		keys, errs := ParseFile([]byte(in))
		for _, k := range keys {
			if k.Type == "" || k.Fingerprint == "" {
				t.Errorf("parsed key missing Type/Fingerprint for input %q", in)
			}
		}
		for _, e := range errs {
			if e.Line < 1 {
				t.Errorf("ParseError.Line = %d, want >= 1", e.Line)
			}
		}
	})
}
