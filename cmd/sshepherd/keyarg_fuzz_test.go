package main

import (
	"regexp"
	"testing"

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
// role, and a .pub file's error never echoes its contents.
func FuzzKeyArg(f *testing.F) {
	line := testkeys.Line(f, 1)
	f.Add("SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8", []byte(line+"\n"))
	f.Add("256 SHA256:fe85JkIjo8VPe+XqXJGH5Mau1EMFdK1OdKvJUFicyA8 me (ED25519)", []byte("# c\n"+line+" me\n"))
	f.Add("MD5:aa:bb", []byte(line+"\n"+line+"\n"))
	f.Add(line+" me@x", []byte("-----BEGIN OPENSSH "+"PRIVATE KEY-----\nc2VjcmV0\n"))
	f.Add("restrict "+line, []byte("PuTTY-User-Key-File-3: ssh-ed25519\n"))
	f.Add("~/.ssh/id.pub", []byte("ssh-ed25519-cert-v01@openssh.com AAAA x\n"))
	f.Add("aa:bb:cc", []byte("ssh-ed25519 !!!\n"))
	f.Fuzz(func(t *testing.T, arg string, content []byte) {
		read := func(string) ([]byte, error) { return content, nil }
		for _, role := range []keyRole{roleKey, roleOld, roleNew} {
			got, err := classifyKeyArg(role, arg, "/home/u", read)
			if err == nil && got.Fingerprint == "" {
				t.Fatalf("classifyKeyArg(%s, %q) succeeded without a fingerprint", role, arg)
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
