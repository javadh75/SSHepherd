package authkeys

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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
