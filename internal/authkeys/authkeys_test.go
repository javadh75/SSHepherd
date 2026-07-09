package authkeys

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// deterministicKeyLine builds a valid ssh-ed25519 authorized_keys entry from a
// fixed seed. Public keys are not secret, so a hard-coded seed is fine and keeps
// the test hermetic and reproducible.
func deterministicKeyLine() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

func testKeyLine(t *testing.T) string {
	t.Helper()
	line, err := deterministicKeyLine()
	if err != nil {
		t.Fatalf("deterministicKeyLine: %v", err)
	}
	return line
}

func TestParseLineValidKey(t *testing.T) {
	got, err := ParseLine(testKeyLine(t))
	if err != nil {
		t.Fatalf("ParseLine returned error: %v", err)
	}
	if got == nil {
		t.Fatal("ParseLine returned nil for a valid line")
	}
	if got.Type != "ssh-ed25519" {
		t.Errorf("Type = %q, want ssh-ed25519", got.Type)
	}
	if !strings.HasPrefix(got.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint = %q, want SHA256: prefix", got.Fingerprint)
	}
}

func TestParseLineComment(t *testing.T) {
	got, err := ParseLine(testKeyLine(t) + " alice@laptop")
	if err != nil {
		t.Fatalf("ParseLine returned error: %v", err)
	}
	if got.Comment != "alice@laptop" {
		t.Errorf("Comment = %q, want alice@laptop", got.Comment)
	}
}

func TestParseLineOptions(t *testing.T) {
	got, err := ParseLine("no-port-forwarding,no-agent-forwarding " + testKeyLine(t))
	if err != nil {
		t.Fatalf("ParseLine returned error: %v", err)
	}
	want := []string{"no-port-forwarding", "no-agent-forwarding"}
	if len(got.Options) != len(want) {
		t.Fatalf("Options = %v, want %v", got.Options, want)
	}
	for i := range want {
		if got.Options[i] != want[i] {
			t.Errorf("Options[%d] = %q, want %q", i, got.Options[i], want[i])
		}
	}
}

func TestParseLineBlankAndComment(t *testing.T) {
	for _, line := range []string{"", "   ", "\t", "# a comment", "   # indented comment"} {
		got, err := ParseLine(line)
		if err != nil {
			t.Errorf("ParseLine(%q) error = %v, want nil", line, err)
		}
		if got != nil {
			t.Errorf("ParseLine(%q) = %+v, want nil", line, got)
		}
	}
}

func TestParseLineGarbage(t *testing.T) {
	if _, err := ParseLine("this is not a key"); err == nil {
		t.Error("ParseLine(garbage) error = nil, want error")
	}
}

func TestParseFileMixed(t *testing.T) {
	line := testKeyLine(t)
	data := []byte("# header comment\n\n" + line + " alice@laptop\ngarbage line here\n" + line + "\n")
	keys, errs := ParseFile(data)
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}
	if keys[0].Comment != "alice@laptop" {
		t.Errorf("keys[0].Comment = %q, want alice@laptop", keys[0].Comment)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly 1", errs)
	}
	if errs[0].Line != 4 {
		t.Errorf("errs[0].Line = %d, want 4 (1-based)", errs[0].Line)
	}
	if !strings.Contains(errs[0].Error(), "line 4") {
		t.Errorf("Error() = %q, want it to mention line 4", errs[0].Error())
	}
}

func TestParseFileEmpty(t *testing.T) {
	keys, errs := ParseFile(nil)
	if len(keys) != 0 || len(errs) != 0 {
		t.Errorf("ParseFile(nil) = %d keys, %d errs; want 0, 0", len(keys), len(errs))
	}
}

func TestParseFileCRLF(t *testing.T) {
	data := []byte(testKeyLine(t) + "\r\n")
	keys, errs := ParseFile(data)
	if len(errs) != 0 {
		t.Fatalf("CRLF input produced errors: %v", errs)
	}
	if len(keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(keys))
	}
}

func mustKey(t *testing.T, line string) Key {
	t.Helper()
	k, err := ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("mustKey(%q): %v", line, err)
	}
	return *k
}

func TestDiff(t *testing.T) {
	a := mustKey(t, testKeyLine(t))      // in both
	b := mustKey(t, testkeys.Line(t, 2)) // desired only / actual only per case

	tests := []struct {
		name                       string
		desired, actual            []Key
		wantOK, wantMiss, wantUnau int
	}{
		{"all compliant", []Key{a}, []Key{a}, 1, 0, 0},
		{"missing", []Key{a, b}, []Key{a}, 1, 1, 0},
		{"unauthorized", []Key{a}, []Key{a, b}, 1, 0, 1},
		{"empty desired", nil, []Key{a}, 0, 0, 1},
		{"empty actual", []Key{a}, nil, 0, 1, 0},
		{"duplicate actual deduped", []Key{a}, []Key{a, a}, 1, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Diff(tt.desired, tt.actual)
			if len(r.OK) != tt.wantOK || len(r.Missing) != tt.wantMiss || len(r.Unauthorized) != tt.wantUnau {
				t.Errorf("Diff = OK:%d Missing:%d Unauthorized:%d, want %d/%d/%d",
					len(r.OK), len(r.Missing), len(r.Unauthorized),
					tt.wantOK, tt.wantMiss, tt.wantUnau)
			}
		})
	}
}

// fingerprints projects keys to their fingerprint sequence for order checks.
func fingerprints(keys []Key) []string {
	fps := make([]string, len(keys))
	for i, k := range keys {
		fps[i] = k.Fingerprint
	}
	return fps
}

func assertFingerprintOrder(t *testing.T, label string, got []Key, want []Key) {
	t.Helper()
	gotFPs, wantFPs := fingerprints(got), fingerprints(want)
	if len(gotFPs) != len(wantFPs) {
		t.Fatalf("%s = %d keys %v, want %d %v", label, len(gotFPs), gotFPs, len(wantFPs), wantFPs)
	}
	for i := range wantFPs {
		if gotFPs[i] != wantFPs[i] {
			t.Errorf("%s[%d] = %s, want %s (full got %v, want %v)",
				label, i, gotFPs[i], wantFPs[i], gotFPs, wantFPs)
		}
	}
}

func TestDiffPreservesOrder(t *testing.T) {
	a := mustKey(t, testKeyLine(t))
	b := mustKey(t, testkeys.Line(t, 2))
	c := mustKey(t, testkeys.Line(t, 3))
	d := mustKey(t, testkeys.Line(t, 4))
	e := mustKey(t, testkeys.Line(t, 5))

	// desired: c, a, b (c missing; a, b installed)
	// actual:  e, b, d, a (e, d unauthorized; b before a)
	r := Diff([]Key{c, a, b}, []Key{e, b, d, a})

	// OK follows desired order (a before b), not actual order (b before a) —
	// a refactor to map iteration or actual-order emission must fail here.
	assertFingerprintOrder(t, "OK", r.OK, []Key{a, b})
	assertFingerprintOrder(t, "Missing", r.Missing, []Key{c})
	// Unauthorized follows actual order (e before d).
	assertFingerprintOrder(t, "Unauthorized", r.Unauthorized, []Key{e, d})

	// Multi-key Missing ordering: desired order must be preserved exactly.
	r2 := Diff([]Key{d, b, a}, nil)
	assertFingerprintOrder(t, "Missing(all)", r2.Missing, []Key{d, b, a})
}
