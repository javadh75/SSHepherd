package sshconn

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// sessionKey records which agent key completed the handshake. Mutex-guarded:
// the transport may try several signers; the last successful Sign is the one
// the server accepted.
type sessionKey struct {
	mu sync.Mutex
	fp string
}

func (s *sessionKey) record(pub ssh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fp = ssh.FingerprintSHA256(pub)
}

func (s *sessionKey) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fp
}

// recordingSigner wraps a signer so a completed Sign records the key's
// fingerprint — the "key this session logged in with" that apply's guard
// surfaces when a plan removes it.
type recordingSigner struct {
	ssh.Signer
	rec *sessionKey
}

func (r recordingSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	sig, err := r.Signer.Sign(rand, data)
	if err == nil {
		r.rec.record(r.PublicKey())
	}
	//nolint:wrapcheck // the wrapper's contract is transparency: the transport must see the signer's error verbatim.
	return sig, err
}

// recordingAlgorithmSigner additionally preserves the AlgorithmSigner
// upgrade: x/crypto type-asserts it to negotiate rsa-sha2-*, and a wrapper
// that hides it would silently downgrade RSA agent keys to ssh-rsa.
type recordingAlgorithmSigner struct {
	recordingSigner
	alg ssh.AlgorithmSigner
}

func (r recordingAlgorithmSigner) SignWithAlgorithm(rand io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	sig, err := r.alg.SignWithAlgorithm(rand, data, algorithm)
	if err == nil {
		r.rec.record(r.PublicKey())
	}
	//nolint:wrapcheck // the wrapper's contract is transparency: the transport must see the signer's error verbatim.
	return sig, err
}

// wrapSigners wraps each signer with the recorder, keeping the
// AlgorithmSigner upgrade where the original had it.
func wrapSigners(signers []ssh.Signer, rec *sessionKey) []ssh.Signer {
	out := make([]ssh.Signer, len(signers))
	for i, s := range signers {
		rs := recordingSigner{Signer: s, rec: rec}
		if alg, ok := s.(ssh.AlgorithmSigner); ok {
			out[i] = recordingAlgorithmSigner{recordingSigner: rs, alg: alg}
			continue
		}
		out[i] = rs
	}
	return out
}

// AgentFingerprints lists the SHA256 fingerprints of every key the agent at
// sock holds — captured once at apply's preflight as the self-lockout
// guard's ground truth. An empty agent yields an empty list, not an error:
// CheckAgent owns that verdict, and apply's guard refuses every write when
// the listing is empty.
func AgentFingerprints(ctx context.Context, sock string) ([]string, error) {
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", sock)
	if err != nil {
		return nil, fmt.Errorf("SSH agent unreachable at %s: %w", sock, err)
	}
	defer func() { _ = conn.Close() }()                   // errcheck: close error is uninteresting on a preflight
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second)) // a wedged agent must not hang the preflight
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return nil, fmt.Errorf("list SSH agent keys at %s: %w", sock, err)
	}
	fps := make([]string, 0, len(keys))
	for _, k := range keys {
		fps = append(fps, ssh.FingerprintSHA256(k))
	}
	return fps, nil
}
