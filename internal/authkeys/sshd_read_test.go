package authkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// splitAt inserts sep into s after n bytes.
func splitAt(s string, n int, sep string) string { return s[:n] + sep + s[n:] }

// TestParseLineReadsLikeSSHD (review F002): sshd reads a line as a C string
// (it ends at the first NUL) and its base64 decoder (b64_pton) skips every
// isspace byte inside the key field; fields are split by space and tab only.
// A line sshd honors must yield its key, with the fingerprint of the key it
// logs in with, so the revoked, unknown, operator and protected checks run
// on it. A line sshd skips stays an error.
func TestParseLineReadsLikeSSHD(t *testing.T) {
	line := testkeys.Line(t, 9)
	typ, blob := strings.Fields(line)[0], strings.Fields(line)[1]
	want := mustKey(t, line).Fingerprint
	tests := []struct {
		name, line, comment string
		ok                  bool
	}{
		{"NUL after the blob", typ + " " + blob + "\x00junk attacker", "", true},
		{"NUL after the comment", typ + " " + blob + " carol\x00junk", "carol", true},
		{"NUL right after the type", typ + "\x00 " + blob, "", false},
		{"NUL inside the blob", splitAt(typ+" "+blob, len(typ)+31, "\x00"), "", false},
		{"VT inside the blob", typ + " " + splitAt(blob, 30, "\v") + " carol", "carol", true},
		{"FF inside the blob", typ + " " + splitAt(blob, 30, "\f") + " carol", "carol", true},
		{"CR inside the blob", typ + " " + splitAt(blob, 30, "\r") + " carol", "carol", true},
		{"CR, VT and FF at the blob's end", typ + " " + blob + "\r\v\f", "", true},
		{"several in a row", typ + " " + splitAt(blob, 10, "\v\f\r\v") + " carol", "carol", true},
		{"VT in the comment", typ + " " + blob + " car\vol", "car\vol", true},
		{"CR in the comment", typ + " " + blob + " alice@laptop\r" + line, "alice@laptop\r" + line, true},
		{"options then a VT blob", "no-pty " + typ + " " + splitAt(blob, 5, "\v"), "", true},
		{"VT between the fields", typ + "\v" + blob, "", false},
		{"VT before the type", "\v" + line, "", false},
		{"NBSP before the type", "\u00a0" + line, "", false},
		{"NBSP after the blob", line + "\u00a0", "", false},
		{"a non-base64 byte in the blob", typ + " " + splitAt(blob, 30, "!"), "", false},
		{"blob truncated", typ + " " + blob[:40], "", false},
		{"type only", typ, "", false},
		{"type and space only", typ + " ", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := ParseLine(tt.line)
			if !tt.ok {
				if err == nil || k != nil {
					t.Errorf("ParseLine(%q) = (%+v, %v), want an error (sshd skips the line)", tt.line, k, err)
				}
				return
			}
			if err != nil || k == nil {
				t.Fatalf("ParseLine(%q) = (%v, %v), want the key sshd honors", tt.line, k, err)
			}
			if k.Fingerprint != want || k.Type != typ {
				t.Errorf("ParseLine(%q) = %s %s, want %s %s", tt.line, k.Type, k.Fingerprint, typ, want)
			}
			if k.Comment != tt.comment {
				t.Errorf("Comment = %q, want %q", k.Comment, tt.comment)
			}
		})
	}
}

// TestParseFileHonorsSSHDLines: in a file, a NUL-tailed line and one with
// whitespace inside its blob are keys, not unparseable entries.
func TestParseFileHonorsSSHDLines(t *testing.T) {
	line := testkeys.Line(t, 9)
	typ, blob := strings.Fields(line)[0], strings.Fields(line)[1]
	data := typ + " " + blob + "\x00junk\n" + typ + " " + splitAt(blob, 20, "\v") + " x\r\n" + "garbage\n"
	keys, errs := ParseFile([]byte(data))
	if len(keys) != 2 || len(errs) != 1 || errs[0].Line != 3 {
		t.Fatalf("ParseFile = %d keys, errs %v; want 2 keys and line 3 unparseable", len(keys), errs)
	}
}

// TestParseLineTypeNames: sshd's sshkey_read takes the key type names and the
// RSA signature names (rsa-sha2-256, rsa-sha2-512) as a line's type token, but
// not a short name (ED25519, RSA: OpenSSH 10.5's ssh-keygen refuses them too).
// The fingerprint is the blob's.
func TestParseLineTypeNames(t *testing.T) {
	ed := strings.Fields(testkeys.Line(t, 9))[1]
	rsaLine := testkeys.RSALine(t, 3, 3072)
	rsa := strings.Fields(rsaLine)[1]
	ec := ecdsaLine(t)
	tests := []struct {
		name, line, wantType string
	}{
		{"ED25519 short name", "ED25519 " + ed, ""},
		{"lower-case short name", "ed25519 " + ed + " c", ""},
		{"RSA short name", "RSA " + rsa, ""},
		{"rsa-sha2-256 name", "rsa-sha2-256 " + rsa, "ssh-rsa"},
		{"rsa-sha2-512 after options", "no-pty rsa-sha2-512 " + rsa, "ssh-rsa"},
		{"ECDSA short name", "ECDSA " + strings.Fields(ec)[1], ""},
		{"short name over another type's blob", "RSA " + ed, ""},
		{"rsa-sha2-256 over an ed25519 blob", "rsa-sha2-256 " + ed, ""},
		{"cert short name", "ED25519-CERT " + ed, ""},
		{"ecdsa full name", ec, "ecdsa-sha2-nistp256"},
		{"ecdsa wrong curve name", "ecdsa-sha2-nistp384 " + strings.Fields(ec)[1], ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := ParseLine(tt.line)
			if tt.wantType == "" {
				if err == nil || k != nil {
					t.Errorf("ParseLine(%q) = (%+v, %v), want an error", tt.line, k, err)
				}
				return
			}
			if err != nil || k == nil || k.Type != tt.wantType {
				t.Errorf("ParseLine(%q) = (%+v, %v), want a %s key", tt.line, k, err, tt.wantType)
			}
		})
	}
}

// TestParseLineRejectsLooseBase64: b64_pton refuses padding whose spare bits
// are not zero, which Go's lenient decoder accepts; sshd skips such a line,
// so ParseLine must too.
func TestParseLineRejectsLooseBase64(t *testing.T) {
	line := testkeys.RSALine(t, 3, 3072) // a 407-byte blob: one '=' of padding
	blob := strings.Fields(line)[1]
	if !strings.HasSuffix(blob, "=") || strings.HasSuffix(blob, "==") {
		t.Fatalf("fixture %q does not end in exactly one '='", blob[len(blob)-4:])
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, blob[len(blob)-2])
	loose := blob[:len(blob)-2] + string(alphabet[last|1]) + "="
	if _, err := base64.StdEncoding.DecodeString(loose); err != nil {
		t.Fatalf("Go's lenient decoder refuses the fixture: %v", err)
	}
	if k, err := ParseLine("ssh-rsa " + loose); err == nil || k != nil {
		t.Errorf("ParseLine(non-zero padding bits) = (%+v, %v), want an error", k, err)
	}
	if k, err := ParseLine("ssh-rsa " + blob[:len(blob)-1]); err == nil || k != nil {
		t.Errorf("ParseLine(missing padding) = (%+v, %v), want an error", k, err)
	}
}

// ecdsaLine is a fresh ecdsa-sha2-nistp256 key line.
func ecdsaLine(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// TestRenderLineCanonicalizesSSHDLine: a key read from a line with a blob
// split by whitespace renders in canonical form.
func TestRenderLineCanonicalizesSSHDLine(t *testing.T) {
	line := testkeys.Line(t, 9)
	typ, blob := strings.Fields(line)[0], strings.Fields(line)[1]
	k := mustKey(t, "no-pty "+typ+" "+splitAt(blob, 30, "\v")+"\x00tail")
	got, err := RenderLine(RenderEntry{Key: k, Comment: "carol"})
	if err != nil || got != "no-pty "+line+" carol" {
		t.Errorf("RenderLine = %q, %v; want %q", got, err, "no-pty "+line+" carol")
	}
}
