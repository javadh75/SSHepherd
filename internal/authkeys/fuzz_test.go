package authkeys

import (
	"slices"
	"strings"
	"testing"
)

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
		seeds = append(seeds, line, line+" bob@host",
			// declared type disagrees with the blob (KEY_TYPE_MISMATCH)
			"ssh-ed25519-cert-v01@openssh.com "+strings.Fields(line)[1],
			`command="a \" b" ssh-rsa `+strings.Fields(line)[1])
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

// FuzzRenderRoundTrip pins the writer/parser identity the apply slice hangs
// on (project rule: this is a writer whose output our own parser must
// accept): for any key ParseLine accepts and any comment the hardened
// manifest validation accepts (RenderTextIssue — the same predicate config
// uses, so the rule sets cannot drift), ParseLine(RenderLine(entry))
// succeeds and preserves fingerprint, options, and comment. Hostile
// comments (newlines, control bytes, edge whitespace) are validation's
// problem and never reach the renderer.
func FuzzRenderRoundTrip(f *testing.F) {
	seedLine := ""
	if line, err := deterministicKeyLine(); err == nil {
		seedLine = line
	}
	f.Add(seedLine, "alice@work")
	f.Add(seedLine+" inline@old", "")
	f.Add(`command="echo a,b c",restrict `+seedLine, "with spaces")
	f.Add("no-pty "+seedLine, "x\ny") // hostile comment: must be skipped by validation
	f.Fuzz(func(t *testing.T, line, comment string) {
		k, err := ParseLine(line)
		if err != nil || k == nil {
			t.Skip("not a key line")
		}
		if RenderTextIssue(comment) != "" {
			t.Skip("rejected by manifest validation before rendering")
		}
		out, err := RenderLine(RenderEntry{Key: *k, Comment: comment})
		if err != nil {
			t.Fatalf("RenderLine failed on a ParseLine-produced key: %v", err)
		}
		k2, err := ParseLine(out)
		if err != nil || k2 == nil {
			t.Fatalf("rendered line does not re-parse: %q (%v)", out, err)
		}
		if k2.Fingerprint != k.Fingerprint {
			t.Errorf("fingerprint %s came back %s", k.Fingerprint, k2.Fingerprint)
		}
		if !slices.Equal(k2.Options, k.Options) {
			t.Errorf("options %v came back %v", k.Options, k2.Options)
		}
		if k2.Comment != comment {
			t.Errorf("comment %q came back %q", comment, k2.Comment)
		}
	})
}
