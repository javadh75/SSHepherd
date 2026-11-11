package authkeys

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys/sshdmodel"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// typeTestKeys returns one public key per plain key type sshd reads.
func typeTestKeys(t *testing.T) map[string]ssh.PublicKey {
	t.Helper()
	keys := map[string]ssh.PublicKey{}
	add := func(pub ssh.PublicKey) { keys[pub.Type()] = pub }
	parse := func(line string) ssh.PublicKey {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		return pub
	}
	add(parse(testkeys.Line(t, 21)))
	add(parse(testkeys.RSALine(t, 21, 3072)))
	add(parse(testkeys.DSALine(t, 21)))
	for _, c := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := ssh.NewPublicKey(&priv.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		add(pub)
	}
	// Security-key types, from their wire format (x/crypto makes no sk keys).
	edPub := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	skEd, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name, Key, App string
	}{ssh.KeyAlgoSKED25519, string(edPub), "ssh:"}))
	if err != nil {
		t.Fatalf("sk-ed25519: %v", err)
	}
	add(skEd)
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point := elliptic.Marshal(elliptic.P256(), ecPriv.X, ecPriv.Y) //nolint:staticcheck // SA1019: the SSH wire format is the uncompressed point
	skEC, err := ssh.ParsePublicKey(ssh.Marshal(struct {
		Name, Curve, Point, App string
	}{ssh.KeyAlgoSKECDSA256, "nistp256", string(point), "ssh:"}))
	if err != nil {
		t.Fatalf("sk-ecdsa: %v", err)
	}
	add(skEC)
	return keys
}

// certFor certifies pub with a throwaway ed25519 CA.
func certFor(t *testing.T, pub ssh.PublicKey) *ssh.Certificate {
	t.Helper()
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{Key: pub, Serial: 1, CertType: ssh.UserCert, KeyId: "k", ValidBefore: ssh.CertTimeInfinity}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("sign a %s certificate: %v", pub.Type(), err)
	}
	return cert
}

// TestEveryKeyTypeToken (review F002): each type token sshd's
// sshkey_type_from_name matches exactly reads a line whose blob is the type
// it names, in ParseLine and in the sshd model alike. The list is spelled
// out, not read from keyTypeNames, so a dropped or remapped row fails.
func TestEveryKeyTypeToken(t *testing.T) {
	keys := typeTestKeys(t)
	tokens := []struct{ token, blobType string }{
		{"ssh-ed25519", "ssh-ed25519"},
		{"sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519@openssh.com"},
		{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256"},
		{"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384"},
		{"ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521"},
		{"sk-ecdsa-sha2-nistp256@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"},
		{"ssh-dss", "ssh-dss"},
		{"ssh-rsa", "ssh-rsa"},
		{"rsa-sha2-256", "ssh-rsa"},
		{"rsa-sha2-512", "ssh-rsa"},
		{"webauthn-sk-ecdsa-sha2-nistp256@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"},
		{"ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519-cert-v01@openssh.com"},
		{"sk-ssh-ed25519-cert-v01@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com"},
		{"ecdsa-sha2-nistp256-cert-v01@openssh.com", "ecdsa-sha2-nistp256-cert-v01@openssh.com"},
		{"ecdsa-sha2-nistp384-cert-v01@openssh.com", "ecdsa-sha2-nistp384-cert-v01@openssh.com"},
		{"ecdsa-sha2-nistp521-cert-v01@openssh.com", "ecdsa-sha2-nistp521-cert-v01@openssh.com"},
		{"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"},
		{"ssh-dss-cert-v01@openssh.com", "ssh-dss-cert-v01@openssh.com"},
		{"ssh-rsa-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com"},
		{"rsa-sha2-256-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com"},
		{"rsa-sha2-512-cert-v01@openssh.com", "ssh-rsa-cert-v01@openssh.com"},
	}
	if len(tokens) != len(keyTypeNames) {
		t.Errorf("%d tokens tested, keyTypeNames has %d: test the new one", len(tokens), len(keyTypeNames))
	}
	for _, tt := range tokens {
		t.Run(tt.token, func(t *testing.T) {
			var blob []byte
			if plain, ok := strings.CutSuffix(tt.blobType, "-cert-v01@openssh.com"); ok {
				pub := keys[plain]
				if pub == nil {
					pub = keys[plain+"@openssh.com"] // sk-…-cert-v01@openssh.com certifies sk-…@openssh.com
				}
				if pub == nil {
					t.Fatalf("no key for %s", plain)
				}
				blob = certFor(t, pub).Marshal()
			} else {
				pub := keys[tt.blobType]
				if pub == nil {
					t.Fatalf("no key for %s", tt.blobType)
				}
				blob = pub.Marshal()
			}
			line := tt.token + " " + base64.StdEncoding.EncodeToString(blob) + " c"
			k, err := ParseLine(line)
			if err != nil || k == nil {
				t.Fatalf("ParseLine(%s line) = (%v, %v), want the key", tt.token, k, err)
			}
			if k.Type != tt.blobType {
				t.Errorf("type = %s, want %s", k.Type, tt.blobType)
			}
			if !sshdmodel.Accepts(line) {
				t.Errorf("the sshd model refuses the %s line: %s", tt.token, sshdmodel.Read(line).Reason)
			}
		})
	}
}
