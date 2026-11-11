package main

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fpOf is a test key's fingerprint.
func fpOf(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("fpOf(%d): %v", seed, err)
	}
	return k.Fingerprint
}

// certLine is an authorized_keys-format user certificate for key seed.
func certLine(t *testing.T, seed byte) string {
	t.Helper()
	cert := sshtest.UserCert(t, sshtest.Key(seed), sshtest.Key(50), "deploy")
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cert)))
}

func TestClassifyKeyArg(t *testing.T) {
	fp1 := fpOf(t, 1)
	files := map[string]string{
		"/home/u/.ssh/id.pub": testkeys.Line(t, 1) + " me@laptop\n",
		"ssh-keys/alice.pub":  testkeys.Line(t, 1) + "\n",
		"/k/two.pub":          testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n",
		"/k/none.pub":         "# only a comment\n\n",
		"/k/cert.pub":         certLine(t, 1) + "\n",
		"/k/opts.pub":         `from="10.0.0.1" ` + testkeys.Line(t, 1) + "\n",
		"/k/garbage.pub":      "ssh-ed25519 !!!notbase64\n",
		"/k/putty":            "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n",
		"/k/big.pub":          strings.Repeat("#", maxKeyFile+1),
	}
	read := func(p string) ([]byte, error) {
		if c, ok := files[p]; ok {
			return []byte(c), nil
		}
		return nil, errors.New("open " + p + ": no such file or directory")
	}
	tests := []struct {
		name    string
		role    keyRole
		arg     string
		wantFP  string
		wantKey bool
		wantErr string
	}{
		{"fingerprint", roleKey, fp1, fp1, false, ""},
		{"padded fingerprint", roleOld, fp1 + "=", fp1, false, ""},
		{"malformed fingerprint", roleKey, "SHA256:abc", "", false, "--key SHA256:abc: malformed fingerprint"},
		{"pasted ssh-keygen -lf output", roleKey, "256 " + fp1 + " me@laptop (ED25519)", fp1, false, ""},
		{"pasted output, malformed", roleKey, "256 SHA256:short me (ED25519)", "", false, "malformed fingerprint"},
		{"pasted output, no comment", roleOld, "256 " + fp1 + " no comment (ED25519)", fp1, false, ""},
		{"pasted output, trailing newline", roleKey, "256 " + fp1 + " me@laptop (ED25519)\n", fp1, false, ""},
		// G020: a key line whose comment names another key's fingerprint is
		// that key line, never the fingerprint in its comment.
		{"key line, comment holds a fingerprint", roleKey, testkeys.Line(t, 1) + " alice new laptop, replaces " + fpOf(t, 2), fp1, true, ""},
		{"key line with options, comment holds a fingerprint", roleOld, "restrict " + testkeys.Line(t, 1) + " old " + fpOf(t, 2), fp1, true, ""},
		{"key line, comment holds a malformed fingerprint", roleKey, testkeys.Line(t, 1) + " old SHA256:" + strings.Repeat("A", 43), fp1, true, ""},
		{"--new key line, comment holds a fingerprint", roleNew, testkeys.Line(t, 1) + " dave from " + fpOf(t, 2), fp1, true, ""},
		{"text holding a fingerprint is not a fingerprint", roleKey, "bob " + fpOf(t, 2), "", false, "not a valid public key line"},
		{"MD5 prefix", roleKey, "MD5:aa:bb:cc", "", false, "MD5 fingerprints are not supported — use ssh-keygen -l -E sha256 -f FILE"},
		{"hex colon", roleOld, "aa:bb:cc:dd:ee:ff", "", false, "MD5 fingerprints are not supported"},
		{"key line", roleKey, testkeys.Line(t, 1) + " me@laptop", fp1, true, ""},
		{"key line with options", roleKey, "restrict " + testkeys.Line(t, 1), fp1, true, ""},
		{"broken key line", roleKey, "ssh-ed25519 !!!notbase64", "", false, "not a valid public key line"},
		{"broken key line says quote", roleKey, "ssh-ed25519", "", false, "quote the whole line"},
		{"~/ path", roleKey, "~/.ssh/id.pub", fp1, true, ""},
		{"path starting with ssh-", roleKey, "ssh-keys/alice.pub", fp1, true, ""},
		{"missing path lists the forms", roleKey, "/k/nope.pub", "", false, "pass a SHA256: fingerprint, a public-key line, or a .pub file path"},
		{"missing path for --new", roleNew, "/k/nope.pub", "", false, "pass a public-key line or a .pub file path"},
		{"multi-key .pub", roleKey, "/k/two.pub", "", false, "--key /k/two.pub: holds 2 key lines — want exactly one"},
		{"empty .pub", roleKey, "/k/none.pub", "", false, "holds 0 key lines"},
		{"certificate file", roleOld, "/k/cert.pub", "", false, "--old /k/cert.pub is an SSH certificate, not a public key — pass the plain key (id_ed25519.pub, not id_ed25519-cert.pub)"},
		{"certificate line", roleKey, certLine(t, 1), "", false, "is an SSH certificate, not a public key"},
		{"unparseable file", roleKey, "/k/garbage.pub", "", false, "--key /k/garbage.pub: does not hold a valid public key line"},
		{"PuTTY private key", roleKey, "/k/putty", "", false, "--key /k/putty is a private key — pass the public key (/k/putty.pub)"},
		{"oversized file", roleKey, "/k/big.pub", "", false, "larger than 64 KiB"},
		{"--new fingerprint", roleNew, fp1, "", false, "--new " + fp1 + ": a fingerprint carries no key"},
		{"--new key line with options", roleNew, "restrict " + testkeys.Line(t, 1), "", false, "rotate keeps the old line's options; edit them in the manifest"},
		{"--new file with options", roleNew, "/k/opts.pub", "", false, "rotate keeps the old line's options; edit them in the manifest"},
		{"--new plain file", roleNew, "/home/u/.ssh/id.pub", fp1, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := classifyKeyArg(tt.role, tt.arg, "/home/u", read)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("classifyKeyArg: %v", err)
			}
			if got.Fingerprint != tt.wantFP || (got.Key != nil) != tt.wantKey || got.Arg != tt.arg {
				t.Errorf("got %+v, want fp %s, key %v", got, tt.wantFP, tt.wantKey)
			}
		})
	}
}

// TestClassifyPrivateKeyNeverQuotesContents: neither the BEGIN line nor any
// byte after it reaches the error — for a synthetic file and for a real
// OpenSSH private key on disk.
func TestClassifyPrivateKeyNeverQuotesContents(t *testing.T) {
	material := "c2VjcmV0LWtleS1tYXRlcmlhbA"
	content := "-----BEGIN OPENSSH " + "PRIVATE KEY-----\n" + material + "\n"
	read := func(string) ([]byte, error) { return []byte(content), nil }
	_, err := classifyKeyArg(roleKey, "/k/id_ed25519", "", read)
	if err == nil || !strings.Contains(err.Error(), "/k/id_ed25519 is a private key — pass the public key (/k/id_ed25519.pub)") {
		t.Fatalf("err = %v, want the private-key refusal", err)
	}
	if strings.Contains(err.Error(), material) || strings.Contains(err.Error(), "BEGIN") {
		t.Errorf("error quotes the file: %v", err)
	}

	path := sshtest.WriteKeyFile(t, t.TempDir(), "id_ed25519", sshtest.Key(7), nil)
	body, rerr := os.ReadFile(path)
	if rerr != nil {
		t.Fatal(rerr)
	}
	_, err = parseKeyArg(roleOld, path)
	if err == nil || !strings.Contains(err.Error(), "is a private key") {
		t.Fatalf("err = %v, want the private-key refusal", err)
	}
	for _, line := range strings.Split(string(body), "\n")[1:] {
		if len(line) >= 8 && strings.Contains(err.Error(), line) {
			t.Errorf("error quotes key material %q", line)
		}
	}
	// The .pub next to it is accepted.
	if got, err := parseKeyArg(roleNew, path+".pub"); err != nil || got.Fingerprint != sshtest.Fingerprint(t, sshtest.Key(7)) {
		t.Errorf("parseKeyArg(.pub) = (%+v, %v)", got, err)
	}
}

func TestLooksLikeKey(t *testing.T) {
	for arg, want := range map[string]bool{
		"alice":                  false,
		"deploy-bot":             false,
		"ssh-admin":              false,
		"ssh-keys/alice.pub":     false,
		"ops.team":               false,
		fpOf(t, 1):               true,
		"256 " + fpOf(t, 1):      true,
		"MD5:aa:bb":              true,
		"aa:bb:cc":               true,
		"ssh-ed25519":            true,
		"restrict":               true,
		"from=10.0.0.1":          true,
		"no-pty,restrict":        true,
		"No-PTY":                 true, // option names match case-insensitively (authkeys' table)
		"Verify-Required":        true,
		"X11-forwarding,pty":     true,
		"no-ptty":                false, // not an option: a path
		"fromage":                false,
		testkeys.Line(t, 1):      true,
		"alice bob":              true,
		"ecdsa-sha2-nistp256":    true,
		"sk-ssh-ed25519@openssh": true,
	} {
		if got := looksLikeKey(arg); got != want {
			t.Errorf("looksLikeKey(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestExpiry(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	if got := expiryOption([]string{"no-pty", `Expiry-Time="20270101"`}); got != `Expiry-Time="20270101"` {
		t.Errorf("expiryOption = %q, want the option verbatim", got)
	}
	if got := expiryOption([]string{"no-pty"}); got != "" {
		t.Errorf("expiryOption = %q, want none", got)
	}
	tests := []struct {
		opt     string
		passed  bool
		wantErr bool
	}{
		{`expiry-time="20200101"`, true, false},
		{`expiry-time="20991231"`, false, false},
		{`expiry-time="202610231159Z"`, true, false},
		{`expiry-time="20261023120100Z"`, false, false},
		// OpenSSH's UTC suffixes are case-insensitive: z, UTC, utc.
		{`expiry-time="202610231159z"`, true, false},
		{`expiry-time="20261023120100z"`, false, false},
		{`expiry-time="202610231159UTC"`, true, false},
		{`expiry-time="20261023120100utc"`, false, false},
		{`expiry-time="20261024UTC"`, false, false},
		{`expiry-time="2026"`, false, true},
		{`expiry-time="2026xx01"`, false, true},
	}
	for _, tt := range tests {
		passed, err := expiryPassed(tt.opt, now)
		if passed != tt.passed || (err != nil) != tt.wantErr {
			t.Errorf("expiryPassed(%s) = (%v, %v), want (%v, err=%v)", tt.opt, passed, err, tt.passed, tt.wantErr)
		}
	}
}

// TestExpiryAgreesWithManifestRule: expiryPassed and the manifest loader
// accept exactly the same expiry values — each checked against an explicit
// verdict, not only against each other (they share one parser, so mere
// agreement would hold even if both broke the same way).
func TestExpiryAgreesWithManifestRule(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	for v, valid := range map[string]bool{
		"20270101": true, "202701011200": true, "20270101120000Z": true,
		"202701011200z": true, "20270101UTC": true, "20270101120000utc": true, "202701011200Utc": true,
		"2027": false, "2027xx01": false, "20271301": false, "20270101GMT": false, "UTC": false, "z": false,
	} {
		opt := `expiry-time="` + v + `"`
		if _, err := expiryPassed(opt, now); (err == nil) != valid {
			t.Errorf("%s: expiryPassed err = %v, want valid=%v", opt, err, valid)
		}
		if got := authkeys.CheckOption(opt); (got == "") != valid {
			t.Errorf("%s: CheckOption = %q, want valid=%v", opt, got, valid)
		}
	}
}
