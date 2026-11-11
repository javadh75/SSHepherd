package authkeys

import (
	"slices"
	"strings"
	"testing"
)

// FuzzParseLine asserts the core safety property: parsing arbitrary, possibly
// malicious authorized_keys input must never panic, and any key it does return
// must be self-consistent. authorized_keys lines are untrusted input, so this
// path is a prime crash/injection surface. Every line must also read the way
// sshd reads it (the sshdmodel oracle, review F009).
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
	seeds = append(seeds, sshdGrammarLines(f)...)
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		k, err := ParseLine(line)
		if err == nil && k != nil && k.Type == "" {
			t.Errorf("parsed key has empty Type for input %q", line)
		}
		agreeWithSSHD(t, line)
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

// FuzzParseHeader: ParseHeader never panics; the only lines it accepts are
// exactly Header(n) (so the .orig decision and the serial rows can never
// disagree with what Render writes); and any in-range serial rendered by
// RenderSerial parses back.
func FuzzParseHeader(f *testing.F) {
	f.Add(ManagedHeader, uint64(0))
	f.Add(Header(7), uint64(7))
	f.Add("# Managed by SSHepherd (serial 07). Manual edits will be overwritten by 'sshepherd apply'.", uint64(1<<63))
	f.Add(ManagedHeader+"\r", uint64(MaxHeaderSerial))
	f.Fuzz(func(t *testing.T, line string, n uint64) {
		s, managed := ParseHeader(line)
		if !managed && s != 0 {
			t.Fatalf("ParseHeader(%q) = (%d, false): an unmanaged line has no serial", line, s)
		}
		if managed && Header(s) != line {
			t.Fatalf("ParseHeader(%q) accepted a line Header(%d) = %q does not write", line, s, Header(s))
		}
		m := n % (MaxHeaderSerial + 1)
		out, err := RenderSerial(nil, m)
		if err != nil {
			t.Fatal(err)
		}
		if got, ok := ParseHeaderOf(out); got != m || !ok {
			t.Fatalf("ParseHeaderOf(RenderSerial(nil, %d)) = (%d, %v)", m, got, ok)
		}
	})
}

// FuzzScanFile (spec S6): ScanFile sees exactly ParseFile's keys, in order;
// it never captures the header or the marker, and every captured line is a
// comment without a trailing CR; and RenderKept of everything it scanned
// re-scans to the same lines and comments, the one-step fixed point that
// byte-exact convergence of a kept section rests on.
func FuzzScanFile(f *testing.F) {
	if line, err := deterministicKeyLine(); err == nil {
		f.Add("# gitea public key\ncommand=\"gitea serv key-1\" " + line + " g\n")
		f.Add(ManagedHeader + "\n" + line + "\n" + PreserveMarker + "\n# c\r\r\n" + line + "\n")
	}
	f.Add("# a\n\n# b\nnot a key\n")
	f.Fuzz(func(t *testing.T, in string) {
		scanned := ScanFile([]byte(in))
		keys, _ := ParseFile([]byte(in))
		if len(keys) != len(scanned) {
			t.Fatalf("ScanFile found %d keys, ParseFile %d", len(scanned), len(keys))
		}
		for i, s := range scanned {
			if s.Key.Raw != keys[i].Raw || s.Key.Fingerprint != keys[i].Fingerprint {
				t.Fatalf("key %d: %q, ParseFile %q", i, s.Key.Raw, keys[i].Raw)
			}
			for _, c := range s.Above {
				tr := strings.TrimSpace(c)
				if _, header := ParseHeader(tr); header || tr == PreserveMarker || !strings.HasPrefix(tr, "#") || strings.HasSuffix(c, "\r") {
					t.Fatalf("captured %q above line %d", c, s.Line)
				}
			}
		}
		out, err := RenderKept(nil, 0, scanned)
		if err != nil {
			t.Fatalf("RenderKept: %v", err)
		}
		again := ScanFile(out)
		if len(again) != len(scanned) {
			t.Fatalf("re-scan found %d lines, want %d:\n%q", len(again), len(scanned), out)
		}
		for i := range again {
			if again[i].Key.Raw != scanned[i].Key.Raw || !slices.Equal(again[i].Above, scanned[i].Above) {
				t.Fatalf("line %d changed on re-scan: %q %q, was %q %q", i, again[i].Key.Raw, again[i].Above, scanned[i].Key.Raw, scanned[i].Above)
			}
		}
	})
}
