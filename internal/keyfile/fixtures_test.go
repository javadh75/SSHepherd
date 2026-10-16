package keyfile

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The committed throwaway keys under testdata/ were produced by the real
// ssh-keygen (see testdata/README): they pin interop with OpenSSH's own
// output, which x/crypto's marshalers only approximate.
const fixturePassphrase = "throwaway-fixture"

func fingerprint(pub ssh.PublicKey) string { return ssh.FingerprintSHA256(pub) }

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return b
}

func TestLoadSSHKeygenFixtures(t *testing.T) {
	tests := []struct {
		key       string
		encrypted bool
	}{
		{"throwaway_ed25519", false},
		{"throwaway_ed25519_enc", true},
		{"throwaway_rsa_pem", false},
		{"throwaway_rsa_pem_enc", true},
	}
	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			f := newFS().key("/k", readFixture(t, tt.key)).key("/k.pub", readFixture(t, tt.key+".pub")).
				key("/pw", []byte(fixturePassphrase+"\n"))
			pp := Passphrases{}
			if tt.encrypted {
				pp.Default = "/pw"
			}
			ids, _, err := load(t, f, pp, nil, "/k")
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			pub := readPublic(f, "/k.pub")
			if pub == nil || len(ids) != 1 || ids[0].Fingerprint != fingerprint(pub) {
				t.Fatalf("ids = %+v, want the fingerprint of %s.pub", ids, tt.key)
			}
		})
	}
	t.Run("throwaway.ppk", func(t *testing.T) {
		_, _, err := load(t, newFS().key("/k", readFixture(t, "throwaway.ppk")), Passphrases{}, nil, "/k")
		if err == nil {
			t.Fatal("PuTTY key accepted")
		}
	})
}
