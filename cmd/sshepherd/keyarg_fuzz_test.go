package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fuzzPubPath is the fixed path FuzzKeyArg reads fuzzed contents from.
const fuzzPubPath = "/k/id.pub"

// keyFileErrors are the only error texts a .pub read may produce, digits
// normalized to N: each names the argument and nothing else — no byte of
// the file can reach an error.
var keyFileErrors = map[string]bool{
	"--key /k/id.pub: larger than N KiB — not a public key file":                                                     true,
	"--key /k/id.pub is a private key — pass the public key (/k/id.pub.pub)":                                         true,
	"--key /k/id.pub: holds N key lines — want exactly one":                                                          true,
	"--key /k/id.pub is an SSH certificate, not a public key — pass the plain key (id_edN.pub, not id_edN-cert.pub)": true,
	"--key /k/id.pub: does not hold a valid public key line":                                                         true,
}

var digits = regexp.MustCompile(`[0-9]+`)

// FuzzKeyArg: KEY classification never panics on any argument, for any
// role, a .pub file's error never echoes its contents, and an argument that
// parses as a key line classifies as its own fingerprint (G020).
func FuzzKeyArg(f *testing.F) {
	line := testkeys.Line(f, 1)
	f.Add("SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8", []byte(line+"\n"))
	f.Add("256 SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8 me (ED25519)", []byte("# c\n"+line+" me\n"))
	f.Add("MD5:aa:bb", []byte(line+"\n"+line+"\n"))
	f.Add(line+" me@x", []byte("-----BEGIN OPENSSH "+"PRIVATE KEY-----\nc2VjcmV0\n"))
	f.Add("restrict "+line, []byte("PuTTY-User-Key-File-3: ssh-ed25519\n"))
	f.Add("~/.ssh/id.pub", []byte("ssh-ed25519-cert-v01@openssh.com AAAA x\n"))
	f.Add("aa:bb:cc", []byte("ssh-ed25519 !!!\n"))
	// G020: a key line whose comment holds another key's fingerprint, and
	// one whose comment holds a malformed one.
	f.Add(line+" alice new laptop, replaces SHA256:4A9jyZBOhnKZvcGQ6TRFbf5Gymb41AfYvYaVmWHD+G4", []byte(line+"\n"))
	f.Add(line+" old SHA256:"+strings.Repeat("A", 43), []byte(line+"\n"))
	f.Fuzz(func(t *testing.T, arg string, content []byte) {
		read := func(string) ([]byte, error) { return content, nil }
		own, perr := authkeys.ParseLine(arg)
		for _, role := range []keyRole{roleKey, roleOld, roleNew} {
			got, err := classifyKeyArg(role, arg, "/home/u", read)
			if err == nil && got.Fingerprint == "" {
				t.Fatalf("classifyKeyArg(%s, %q) succeeded without a fingerprint", role, arg)
			}
			if perr == nil && own != nil {
				checkOwnFingerprint(t, role, arg, own, got, err)
			}
			_ = looksLikeKey(arg)
		}
		_, err := classifyKeyArg(roleKey, fuzzPubPath, "/home/u", read)
		if err == nil {
			return
		}
		if msg := digits.ReplaceAllString(err.Error(), "N"); !keyFileErrors[msg] {
			t.Fatalf("unexpected .pub error (may echo file content): %q\ncontent: %q", err.Error(), content)
		}
	})
}

// checkOwnFingerprint is FuzzKeyArg's key-line oracle (G020): an argument
// that parses as a key line never classifies as any other key's
// fingerprint, and it classifies as its own unless a refusal applies (a
// SHA256:/MD5: prefix, which steps 1 and 3 take; a certificate; options on
// --new).
func checkOwnFingerprint(t *testing.T, role keyRole, arg string, own *authkeys.Key, got keyArg, err error) {
	t.Helper()
	if err == nil && got.Fingerprint != own.Fingerprint {
		t.Fatalf("classifyKeyArg(%s, %q) = %s, want the line's own fingerprint %s", role, arg, got.Fingerprint, own.Fingerprint)
	}
	refused := strings.HasPrefix(arg, "SHA256:") || strings.HasPrefix(arg, "MD5:") ||
		isCertLine(arg) || isCertType(own.Type) || (role == roleNew && len(own.Options) > 0)
	if err != nil && !refused {
		t.Fatalf("classifyKeyArg(%s, %q) refused a parseable key line: %v", role, arg, err)
	}
}
