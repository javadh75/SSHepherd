package sshconn

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"testing"

	"golang.org/x/crypto/ssh"
)

// seededSigner builds a deterministic ed25519 ssh.Signer.
func seededSigner(t *testing.T, seed byte) ssh.Signer {
	t.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(raw))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s
}

func TestRecordingSignersRecordOnSign(t *testing.T) {
	signer := seededSigner(t, 1)
	rec := &sessionKey{}
	wrapped := wrapSigners([]ssh.Signer{signer, seededSigner(t, 2)}, rec)
	if len(wrapped) != 2 {
		t.Fatalf("wrapped %d signers, want 2", len(wrapped))
	}
	if rec.get() != "" {
		t.Fatal("fingerprint recorded before any Sign")
	}
	if _, err := wrapped[0].Sign(rand.Reader, []byte("handshake data")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got, want := rec.get(), ssh.FingerprintSHA256(signer.PublicKey()); got != want {
		t.Errorf("recorded fingerprint = %s, want %s", got, want)
	}
	// The last successful Sign wins: the server accepted that key.
	if _, err := wrapped[1].Sign(rand.Reader, []byte("retry")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if got, want := rec.get(), ssh.FingerprintSHA256(wrapped[1].PublicKey()); got != want {
		t.Errorf("recorded fingerprint after second sign = %s, want %s", got, want)
	}
}

// bareSigner strips every optional interface so wrapSigners' downgrade path
// is exercised.
type bareSigner struct{ s ssh.Signer }

func (b bareSigner) PublicKey() ssh.PublicKey { return b.s.PublicKey() }
func (b bareSigner) Sign(r io.Reader, data []byte) (*ssh.Signature, error) {
	return b.s.Sign(r, data)
}

func TestWrapSignersPreservesAlgorithmSigner(t *testing.T) {
	realSigner := seededSigner(t, 1)
	rec := &sessionKey{}
	// x/crypto type-asserts AlgorithmSigner to negotiate rsa-sha2-*; losing
	// the upgrade in the wrapper would silently downgrade RSA agent keys.
	// The fixture must implement it, or this test stops exercising the
	// upgrade path — assert the precondition instead of skipping silently.
	if _, ok := realSigner.(ssh.AlgorithmSigner); !ok {
		t.Fatal("fixture signer no longer implements AlgorithmSigner — the upgrade path is untested")
	}
	w := wrapSigners([]ssh.Signer{realSigner}, rec)[0]
	alg, ok := w.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("wrapped signer lost the AlgorithmSigner upgrade")
	}
	if _, err := alg.SignWithAlgorithm(rand.Reader, []byte("d"), ""); err != nil {
		t.Fatalf("SignWithAlgorithm: %v", err)
	}
	if rec.get() == "" {
		t.Error("SignWithAlgorithm did not record the fingerprint")
	}
	// A bare signer wraps without gaining an upgrade it never had.
	w = wrapSigners([]ssh.Signer{bareSigner{s: realSigner}}, &sessionKey{})[0]
	if _, ok := w.(ssh.AlgorithmSigner); ok {
		t.Error("bare signer wrapper must not claim AlgorithmSigner")
	}
}

func TestConnSessionKeyFPNilSafe(t *testing.T) {
	c := &Conn{}
	if got := c.SessionKeyFP(); got != "" {
		t.Errorf("bare Conn SessionKeyFP = %q, want empty", got)
	}
}
