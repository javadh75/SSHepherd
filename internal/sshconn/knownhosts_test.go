package sshconn

import (
	"crypto/rand"
	"crypto/rsa"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

func authorizedLine(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

func rsaPub(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa: %v", err)
	}
	return sshtest.Signer(t, priv).PublicKey()
}

func TestHostKeyAlgorithms(t *testing.T) {
	ed := sshtest.Signer(t, sshtest.Key(40)).PublicKey()
	ec := ecdsaSigner(t).PublicKey()
	rsa := rsaPub(t)
	ca := sshtest.Signer(t, sshtest.Key(50)).PublicKey()
	const addr = "web.example.com:22"
	const other = "db.example.org:22"
	line := func(host string, k ssh.PublicKey) string {
		return knownhosts.Line([]string{host}, k)
	}
	tests := []struct {
		name      string
		lines     []string
		addr      string
		wantFirst []string // exact prefix
		wantNil   bool
		certs     bool
	}{
		{name: "unknown host keeps x/crypto defaults", lines: []string{line(other, ed)}, addr: addr, wantNil: true},
		{name: "ed25519 recorded goes first", lines: []string{line(addr, ed)}, addr: addr,
			wantFirst: []string{ssh.KeyAlgoED25519}},
		{name: "ssh-rsa maps to the SHA-2 signatures too", lines: []string{line(addr, rsa)}, addr: addr,
			wantFirst: []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}},
		{name: "several recorded types in strength order", lines: []string{line(addr, rsa), line(addr, ec)}, addr: addr,
			wantFirst: []string{ssh.KeyAlgoECDSA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}},
		{name: "non-default port entries match", lines: []string{line("web.example.com:2222", ec)}, addr: "web.example.com:2222",
			wantFirst: []string{ssh.KeyAlgoECDSA256}},
		{name: "matching CA puts certificates first", addr: addr, certs: true,
			lines:     []string{"@cert-authority *.example.com " + authorizedLine(ca), line(addr, ed)},
			wantFirst: []string{ssh.CertAlgoED25519v01}},
		{name: "non-matching CA offers no certificates", addr: addr,
			lines:     []string{"@cert-authority *.example.org " + authorizedLine(ca), line(addr, ed)},
			wantFirst: []string{ssh.KeyAlgoED25519}},
		{name: "negated CA pattern offers no certificates", addr: addr,
			lines:     []string{"@cert-authority *.example.com,!web.example.com " + authorizedLine(ca), line(addr, ed)},
			wantFirst: []string{ssh.KeyAlgoED25519}},
		{name: "hashed host entries match", addr: addr,
			lines:     []string{knownhosts.HashHostname(knownhosts.Normalize(addr)) + " " + authorizedLine(ec)},
			wantFirst: []string{ssh.KeyAlgoECDSA256}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kh, err := LoadKnownHosts(sshtest.KnownHostsFile(t, tt.lines...))
			if err != nil {
				t.Fatalf("LoadKnownHosts: %v", err)
			}
			got := kh.HostKeyAlgorithms(tt.addr)
			if tt.wantNil {
				if got != nil {
					t.Errorf("algos = %v, want nil", got)
				}
				return
			}
			if len(got) < len(tt.wantFirst) || !slices.Equal(got[:len(tt.wantFirst)], tt.wantFirst) {
				t.Errorf("algos = %v, want prefix %v", got, tt.wantFirst)
			}
			hasCert := slices.ContainsFunc(got, func(a string) bool { return strings.Contains(a, "-cert-") })
			if hasCert != tt.certs {
				t.Errorf("certificate algorithms offered = %v, want %v (%v)", hasCert, tt.certs, got)
			}
			// Every plain algorithm stays available after the preferred ones.
			for _, a := range plainHostKeyAlgos {
				if !slices.Contains(got, a) {
					t.Errorf("algos %v lack %s", got, a)
				}
			}
		})
	}
}

func TestLoadKnownHostsErrors(t *testing.T) {
	if _, err := LoadKnownHosts("/nonexistent/known_hosts"); err == nil || !strings.Contains(err.Error(), "load known_hosts") {
		t.Errorf("err = %v, want a labeled load error", err)
	}
	bad := sshtest.KnownHostsFile(t, "host ssh-ed25519 not-base64!")
	if _, err := LoadKnownHosts(bad); err == nil {
		t.Error("malformed known_hosts loaded without error")
	}
}
