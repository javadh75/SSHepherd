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
