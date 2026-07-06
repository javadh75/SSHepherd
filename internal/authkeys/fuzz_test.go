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
