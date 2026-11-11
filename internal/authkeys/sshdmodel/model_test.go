package sshdmodel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func ecLine(t *testing.T, curve elliptic.Curve) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// TestRead pins the model against the behaviour recorded from real sshd in
// review findings F002, F003 and F025, and auth-options.c's grammar.
func TestRead(t *testing.T) {
	line := testkeys.Line(t, 9)
	typ, blob := strings.Fields(line)[0], strings.Fields(line)[1]
	rsa := strings.Fields(testkeys.RSALine(t, 3, 3072))[1]
	ec := strings.Fields(ecLine(t, elliptic.P256()))[1]
	tests := []struct {
		name, line string
		ok         bool
		reason     string
	}{
		{"plain", line, true, ""},
		{"comment", line + " carol", true, ""},
		{"leading space and tab", " \t" + line, true, ""},
		{"blank", "", false, "blank or comment"},
		{"spaces", "   ", false, "blank or comment"},
		{"newline", "\n", false, "blank or comment"},
		{"a comment", "# " + line, false, "blank or comment"},
		{"indented comment", "  # x", false, "blank or comment"},
		{"NUL first", "\x00" + line, false, "blank or comment"},
		// F002
		{"NUL after the blob", typ + " " + blob + "\x00junk attacker", true, ""},
		{"VT in the blob", typ + " " + blob[:30] + "\v" + blob[30:], true, ""},
		{"FF in the blob", typ + " " + blob[:30] + "\f" + blob[30:], true, ""},
		{"CR in the blob", typ + " " + blob[:30] + "\r" + blob[30:], true, ""},
		{"LF at the blob's end", typ + " " + blob + "\n", true, ""},
		{"NUL in the blob", typ + " " + blob[:30] + "\x00" + blob[30:], false, "invalid format"},
		{"truncated blob", typ + " " + blob[:40], false, "invalid"},
		{"type only", typ, false, "invalid format"},
		{"type and space", typ + " ", false, "invalid format"},
		// type names
		{"short name", "ED25519 " + blob, false, "invalid format"},
		{"short name in lower case", "ed25519 " + blob, false, "invalid format"},
		{"RSA short name", "RSA " + rsa, false, "invalid format"},
		{"rsa-sha2-256", "rsa-sha2-256 " + rsa, true, ""},
		{"rsa-sha2-512 with options", "no-pty rsa-sha2-512 " + rsa, true, ""},
		{"full ECDSA name", "ecdsa-sha2-nistp256 " + ec, true, ""},
		{"ECDSA short name", "ECDSA " + ec, false, "invalid"},
		{"wrong curve", "ecdsa-sha2-nistp384 " + ec, false, "invalid format"},
		{"short name over another blob", "RSA " + blob, false, "invalid"},
		{"cert short name", "ED25519-CERT " + blob, false, "invalid"},
		{"unknown type", "garbage " + blob, false, "invalid"},
		// options
		{"options then key", "no-pty " + line, true, ""},
		{"tab after options", "no-pty\t" + line, true, ""},
		{"empty clauses", ",no-pty,,restrict, " + line, true, ""},
		{"names in any case", "NO-PTY,Restrict,Cert-Authority " + line, true, ""},
		{"every flag", "agent-forwarding,no-agent-forwarding,port-forwarding,x11-forwarding,pty,user-rc,no-user-rc " + line, true, ""},
		{"touch-required", "touch-required " + line, true, ""},
		{"no-touch-required", "no-touch-required " + line, true, ""},
		{"verify-required", "verify-required " + line, true, ""},
		{"no-verify-required", "no-verify-required " + line, true, ""},
		{"no-restrict", "no-restrict " + line, false, "unknown key option"},
		{"no-cert-authority", "no-cert-authority " + line, false, "unknown key option"},
		{"bogus", "bogus-opt " + line, false, "unknown key option"},
		{"U+0130 is not i", "restr\u0130ct " + line, false, "unknown key option"},
		{"flag with a value", `no-pty="x" ` + line, false, "unknown key option"},
		{"flag then junk", "no-ptyx " + line, false, "unknown key option"},
		{"a quote left open", `command="a ` + line, false, "invalid key option string"},
		{"escaped quote stays open", `command="a\" ` + line, false, "invalid key option string"},
		{"command", `command="echo \"x y\"" ` + line, true, ""},
		{"from and principals", `from="10.0.0.1",principals="a,b" ` + line, true, ""},
		{"no value", "command " + line, false, "unknown key option"},
		{"unquoted value", "command=x " + line, false, "missing start quote"},
		{"text after the value", `command="a"b ` + line, false, "unknown key option"},
		{"second command", `command="a",COMMAND="b" ` + line, false, `multiple "command" clauses`},
		{"second from", `from="a",from="b" ` + line, false, `multiple "from" clauses`},
		{"second principals", `principals="a",principals="b" ` + line, false, `multiple "principals" clauses`},
		{"repeated permitopen", `permitopen="a:1",permitopen="b:2" ` + line, true, ""},
		{"NUL inside a value", `command="a` + "\x00" + `" ` + line, false, "invalid key option string"},
		// F003 values
		{"permitopen host:port", `permitopen="db:22" ` + line, true, ""},
		{"permitopen host:*", `permitopen="db:*" ` + line, true, ""},
		{"permitopen slash", `permitopen="db/22" ` + line, true, ""},
		{"permitopen brackets", `permitopen="[::1]:22" ` + line, true, ""},
		{"permitopen empty host", `permitopen=":22" ` + line, true, ""},
		{"permitopen no port", `permitopen="db" ` + line, false, "invalid permission port"},
		{"permitopen brackets, no port", `permitopen="[::1]" ` + line, false, "invalid permission port"},
		{"permitopen port 0", `permitopen="db:0" ` + line, false, "invalid permission port"},
		{"permitopen port too big", `permitopen="db:65536" ` + line, false, "invalid permission port"},
		{"permitopen service name", `permitopen="db:ssh" ` + line, false, "invalid permission port"},
		{"permitopen open bracket", `permitopen="[::1" ` + line, false, "invalid permission hostname"},
		{"permitopen junk after bracket", `permitopen="[::1]x:22" ` + line, false, "invalid permission hostname"},
		{"permitopen long host", `permitopen="` + strings.Repeat("h", 1025) + `:22" ` + line, false, "invalid permission hostname"},
		{"permitlisten bare port", `permitlisten="8080" ` + line, true, ""},
		{"permitlisten star", `permitlisten="*" ` + line, true, ""},
		{"permitlisten host", `permitlisten="localhost:8080" ` + line, true, ""},
		{"permitlisten bad", `permitlisten="nope" ` + line, false, "invalid permission port"},
		{"environment", `environment="FOO=1" ` + line, true, ""},
		{"environment no equals", `environment="FOO" ` + line, false, "invalid environment string"},
		{"environment no name", `environment="=x" ` + line, false, "invalid environment string"},
		{"environment bad name", `environment="F-O=1" ` + line, false, "invalid environment string"},
		{"tunnel number", `tunnel="1" ` + line, true, ""},
		{"tunnel any", `tunnel="AnY" ` + line, true, ""},
		{"tunnel max", `tunnel="2147483645" ` + line, true, ""},
		{"tunnel too big", `tunnel="2147483646" ` + line, false, "invalid tun device"},
		{"tunnel word", `tunnel="abc" ` + line, false, "invalid tun device"},
		{"tunnel bad quote", `tunnel=1 ` + line, false, "missing start quote"},
		{"expiry", `expiry-time="20990101" ` + line, true, ""},
		{"expiry with time and Z", `expiry-time="209901011200Z" ` + line, true, ""},
		{"expiry UTC", `expiry-time="20990101000000utc" ` + line, true, ""},
		{"expiry bad", `expiry-time="2027" ` + line, false, "invalid expires time"},
		{"expiry not a date", `expiry-time="2027xx01" ` + line, false, "invalid expires time"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := Read(tt.line)
			if v.Accepted != tt.ok || !strings.Contains(v.Reason, tt.reason) {
				t.Fatalf("Read(%q) = %+v, want accepted=%v reason~%q", tt.line, v, tt.ok, tt.reason)
			}
			if Accepts(tt.line) != tt.ok {
				t.Errorf("Accepts disagrees with Read")
			}
			if tt.ok && !strings.HasPrefix(v.Fingerprint, "SHA256:") {
				t.Errorf("Fingerprint = %q", v.Fingerprint)
			}
		})
	}
}

func TestB64pton(t *testing.T) {
	for _, tt := range []struct {
		in, want string
		ok       bool
	}{
		{"", "", true},
		{"QUJD", "ABC", true},
		{"QU JD", "ABC", true},
		{"Q\tU\nJ\vD\f\r", "ABC", true},
		{"QUI=", "AB", true},
		{"QQ==", "A", true},
		{"QQ= =", "A", true},
		{"QQ==\n ", "A", true},
		{"QUI= \t", "AB", true},
		{"Q", "", false},
		{"QU", "", false},
		{"QUJ", "", false},
		{"=", "", false},
		{"Q=", "", false},
		{"QUJD=", "", false},
		{"QQ=", "", false},
		{"QQ=x", "", false},
		{"QQ==x", "", false},
		{"QUI=x", "", false},
		{"QUJ!", "", false},
		{"QR==", "", false}, // non-zero spare bits
		{"QUJ=", "", false},
	} {
		got, ok := b64pton(tt.in)
		if ok != tt.ok || (ok && string(got) != tt.want) {
			t.Errorf("b64pton(%q) = %q, %v; want %q, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
	// A long key round-trips.
	data := make([]byte, 1000)
	for i := range data {
		data[i] = byte(i)
	}
	got, ok := b64pton(base64.StdEncoding.EncodeToString(data))
	if !ok || string(got) != string(data) {
		t.Errorf("round-trip failed: ok=%v", ok)
	}
}

func TestStrtonum(t *testing.T) {
	for _, tt := range []struct {
		in     string
		n      int64
		wantOK bool
	}{
		{"22", 22, true},
		{"+22", 22, true},
		{" \t22", 22, true},
		{"-0", 0, true},
		{"", 0, false},
		{"+", 0, false},
		{"22 ", 0, false},
		{"2x", 0, false},
		{"-1", -1, false},
		{"65536", 65536, false},
		{"99999999999999999999", 0, false},
	} {
		n, ok := strtonum(tt.in, 0, 65535)
		if ok != tt.wantOK || n != tt.n {
			t.Errorf("strtonum(%q) = %d, %v; want %d, %v", tt.in, n, ok, tt.n, tt.wantOK)
		}
	}
}

func TestParseOptionsEdges(t *testing.T) {
	if got := ParseOptions("no-pty,"); got != "unexpected end-of-options" {
		t.Errorf("trailing comma at the string's end = %q", got)
	}
	if got := ParseOptions(""); got != "" {
		t.Errorf("empty = %q", got)
	}
	if got := ParseOptions(`command="a`); got != "missing end quote" {
		t.Errorf("open quote = %q", got)
	}
	if got := ParseOptions(`environment=x`); got != "missing start quote" {
		t.Errorf("unquoted environment = %q", got)
	}
}

func TestLookupName(t *testing.T) {
	if typ, nid := lookupName("ssh-mldsa-44@golang.org"); typ != keyUnspec || nid != -1 {
		t.Errorf("lookupName(unknown) = %d, %d", typ, nid)
	}
	if typ, nid := lookupName("ecdsa-sha2-nistp384"); typ != keyECDSA || nid != 384 {
		t.Errorf("lookupName(p384) = %d, %d", typ, nid)
	}
}
