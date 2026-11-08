package sshconn

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// hostCert signs a host certificate for plain with ca.
func hostCert(t *testing.T, plain ssh.Signer, ca ssh.Signer, validBefore uint64) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key: plain.PublicKey(), CertType: ssh.HostCert, KeyId: "web-1",
		ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: validBefore,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("sign host cert: %v", err)
	}
	s, err := ssh.NewCertSigner(cert, plain)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	return s
}

func caLine(f fixture, ca ssh.PublicKey) string {
	return "@cert-authority " + knownhosts.Normalize(f.srv.Addr()) + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca)))
}

// TestHostKeyTypeClassification drives every row of spec section 3 through a
// real handshake.
func TestHostKeyTypeClassification(t *testing.T) {
	user := sshtest.Key(1)
	plain := sshtest.Signer(t, sshtest.Key(40))
	ca := sshtest.Signer(t, sshtest.Key(50))
	otherCA := sshtest.Signer(t, sshtest.Key(51))
	past := uint64(time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC).Unix())
	tests := []struct {
		name     string
		hostKeys []ssh.Signer
		khLines  func(f fixture) []string
		kind     fleet.ErrorKind
		want     []string
	}{
		{
			name:     "only ssh-dss recorded: nothing verifiable was lost",
			hostKeys: []ssh.Signer{plain},
			khLines:  func(f fixture) []string { return []string{f.srv.KnownHostsLine(dsaKey(t))} },
			kind:     fleet.ErrorKindHostKeyTypeUnrecorded,
			want:     []string{"not recorded", "recorded: ssh-dss"},
		},
		{
			name:     "a CA-only host presenting a plain key of another type",
			hostKeys: []ssh.Signer{ecdsaSigner(t)},
			khLines:  func(f fixture) []string { return []string{caLine(f, ca.PublicKey())} },
			kind:     fleet.ErrorKindHostKeyTypeChanged,
			want:     []string{"HOST KEY TYPE CHANGED", "recorded: ssh-ed25519 (CA)"},
		},
		{
			name:     "TestHostCertUnvouchedSignerAlerts: a certificate from an unvouched signer on a CA-vouched host",
			hostKeys: []ssh.Signer{hostCert(t, plain, otherCA, ssh.CertTimeInfinity)},
			khLines:  func(f fixture) []string { return []string{caLine(f, ca.PublicKey())} },
			kind:     fleet.ErrorKindHostKeyTypeChanged,
			want:     []string{"HOST KEY TYPE CHANGED", "no @cert-authority line for this host vouches for"},
		},
		{
			name:     "an expired certificate from the vouched CA stays host_key",
			hostKeys: []ssh.Signer{hostCert(t, plain, ca, past)},
			khLines:  func(f fixture) []string { return []string{caLine(f, ca.PublicKey())} },
			kind:     fleet.ErrorKindHostKey,
		},
		{
			name:     "an unknown host presenting a certificate stays host_key",
			hostKeys: []ssh.Signer{hostCert(t, plain, otherCA, ssh.CertTimeInfinity)},
			khLines:  func(fixture) []string { return nil },
			kind:     fleet.ErrorKindHostKey,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, sshtest.ServerConfig{HostKeys: tt.hostKeys, Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()}}, user)
			kh := sshtest.KnownHostsFile(t, tt.khLines(f)...)
			conn, err := f.dialer(kh).Connect(ctxTimeout(t, 10*time.Second), f.cfgSrv)
			if err == nil {
				_ = conn.Close()
				t.Fatal("Connect succeeded, want a host-key refusal")
			}
			if got := kindOf(t, err); got != tt.kind {
				t.Errorf("kind = %q, want %q (err: %v)", got, tt.kind, err)
			}
			hint := fleet.HintOf(err)
			for _, w := range tt.want {
				if !strings.Contains(hint, w) {
					t.Errorf("hint lacks %q:\n%s", w, hint)
				}
			}
			if n := len(f.srv.Attempts()); n != 0 {
				t.Errorf("%d auth attempts reached an untrusted host, want 0", n)
			}
		})
	}
}
