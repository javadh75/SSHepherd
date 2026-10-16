package sshconn

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// credServer is a hermetic server accepting exactly authorized.
func credServer(t *testing.T, authorized ...ssh.PublicKey) (*sshtest.Server, string, config.Server) {
	t.Helper()
	host := sshtest.Signer(t, sshtest.Key(40))
	s := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{host}, Authorized: authorized})
	kh := sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey()))
	return s, kh, config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
}

func TestFileOnlyAuthWithNoAgent(t *testing.T) {
	key := sshtest.Key(1)
	s, kh, srv := credServer(t, sshtest.Signer(t, key).PublicKey())
	d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/keys/ci", key)}}, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("Connect with a key file and no agent: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got, want := conn.SessionKeyFP(), sshtest.Fingerprint(t, key); got != want {
		t.Errorf("SessionKeyFP = %s, want the file key %s (the recorder sees file keys)", got, want)
	}
	if got := s.Attempts(); len(got) != 1 {
		t.Errorf("attempts = %v, want exactly the file key", got)
	}
}

func TestAgentCertificateStillLogsIn(t *testing.T) {
	c, ca := sshtest.Key(3), sshtest.Key(9)
	cert := sshtest.UserCert(t, c, ca, "deploy")
	_, kh, srv := credServer(t, cert)
	creds := &Credentials{AgentSock: sshtest.AgentKeys(t, agent.AddedKey{PrivateKey: c, Certificate: cert})}
	d := &Dialer{KnownHostsPath: kh, Creds: creds, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("certificate login: %v", err)
	}
	_ = conn.Close()
}

func TestBrokenAgentWithFileKeyConnects(t *testing.T) {
	key := sshtest.Key(1)
	log, buf := warnLog()
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/ci", key)}, AgentSock: deadSock(t), Log: log}
	_, kh, srv := credServer(t, sshtest.Signer(t, key).PublicKey())
	d := &Dialer{KnownHostsPath: kh, Creds: creds, DialTimeout: 5 * time.Second}
	for range 2 {
		conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
		if err != nil {
			t.Fatalf("Connect despite a broken agent: %v", err)
		}
		_ = conn.Close()
	}
	if n := strings.Count(buf.String(), "ssh-agent unusable"); n != 1 {
		t.Errorf("warnings = %d, want exactly one per run:\n%s", n, buf.String())
	}
}

func TestConnectWithoutKeysFailsBeforeDialing(t *testing.T) {
	// A bare TCP listener counts connections: Signers runs before the dial,
	// so an agent failure with no key files never opens a TCP connection
	// (key offers alone could not tell "never dialed" from "dialed, offered
	// nothing").
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = l.Close(); <-done })
	srv := config.Server{Name: "web-1", Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, User: "deploy"}
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: deadSock(t)}, DialTimeout: time.Second}
	if _, err := d.Connect(ctxTimeout(t, 5*time.Second), srv); err == nil || kindOf(t, err) != audit.ErrorKindAgent {
		t.Fatalf("Connect err = %v, want ErrorKindAgent", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("%d TCP connections although nothing could authenticate, want none (signers come before the dial)", n)
	}
}

func TestOnlyAcrossSources(t *testing.T) {
	file, ag := sshtest.Key(1), sshtest.Key(2)
	s, kh, srv := credServer(t, sshtest.Signer(t, file).PublicKey(), sshtest.Signer(t, ag).PublicKey())
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/f", file)}, AgentSock: sshtest.Agent(t, ag)}
	d := &Dialer{KnownHostsPath: kh, Creds: creds, DialTimeout: 5 * time.Second}
	for _, only := range []string{sshtest.Fingerprint(t, ag), sshtest.Fingerprint(t, file)} {
		before := len(s.Attempts())
		conn, err := d.ConnectWith(ctxTimeout(t, 10*time.Second), srv, ConnectOptions{Only: []string{only}})
		if err != nil {
			t.Fatalf("ConnectWith Only %s: %v", only, err)
		}
		if got := conn.SessionKeyFP(); got != only {
			t.Errorf("logged in with %s, want %s", got, only)
		}
		_ = conn.Close()
		if got := s.Attempts()[before:]; !slices.Equal(got, []string{only}) {
			t.Errorf("attempts = %v, want exactly [%s]", got, only)
		}
	}
}

func TestPreferTiesKeepFileFirst(t *testing.T) {
	file, ag := sshtest.Key(1), sshtest.Key(2)
	s, kh, srv := credServer(t, sshtest.Signer(t, ag).PublicKey())
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/f", file)}, AgentSock: sshtest.Agent(t, ag)}
	d := &Dialer{KnownHostsPath: kh, Creds: creds, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_ = conn.Close()
	want := []string{sshtest.Fingerprint(t, file), sshtest.Fingerprint(t, ag)}
	if got := s.Attempts(); !slices.Equal(got, want) {
		t.Errorf("attempts = %v, want the file key before the agent key: %v", got, want)
	}
}
