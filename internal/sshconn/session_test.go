package sshconn

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
	if _, ok := realSigner.(ssh.AlgorithmSigner); ok {
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
	}
	// A bare signer wraps without gaining an upgrade it never had.
	w := wrapSigners([]ssh.Signer{bareSigner{s: realSigner}}, &sessionKey{})[0]
	if _, ok := w.(ssh.AlgorithmSigner); ok {
		t.Error("bare signer wrapper must not claim AlgorithmSigner")
	}
}

// agentSocket serves a real in-memory agent holding the given private keys.
func agentSocket(t *testing.T, keys ...ed25519.PrivateKey) string {
	t.Helper()
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatalf("keyring add: %v", err)
		}
	}
	dir, err := os.MkdirTemp("", "ag") // short path: unix sun_path is ~104 bytes on macOS
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = agent.ServeAgent(keyring, c) // returns on client close (EOF)
				_ = c.Close()
			}()
		}
	}()
	return sock
}

func TestAgentFingerprints(t *testing.T) {
	raw := make([]byte, ed25519.SeedSize)
	raw[0] = 7
	priv := ed25519.NewKeyFromSeed(raw)
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("public key: %v", err)
	}

	t.Run("lists held keys", func(t *testing.T) {
		got, err := AgentFingerprints(context.Background(), agentSocket(t, priv))
		if err != nil {
			t.Fatalf("AgentFingerprints: %v", err)
		}
		if len(got) != 1 || got[0] != ssh.FingerprintSHA256(pub) {
			t.Errorf("fingerprints = %v, want [%s]", got, ssh.FingerprintSHA256(pub))
		}
	})
	t.Run("empty agent is empty, not an error", func(t *testing.T) {
		// CheckAgent owns the empty-agent verdict; the guard has its own
		// empty-listing fallback and needs the distinction.
		got, err := AgentFingerprints(context.Background(), agentSocket(t))
		if err != nil || len(got) != 0 {
			t.Errorf("got (%v, %v), want ([], nil)", got, err)
		}
	})
	t.Run("dead socket errors", func(t *testing.T) {
		if _, err := AgentFingerprints(context.Background(), filepath.Join(t.TempDir(), "nope.sock")); err == nil {
			t.Error("dead socket produced no error")
		}
	})
}

func TestConnSessionKeyFPNilSafe(t *testing.T) {
	c := &Conn{}
	if got := c.SessionKeyFP(); got != "" {
		t.Errorf("bare Conn SessionKeyFP = %q, want empty", got)
	}
}
