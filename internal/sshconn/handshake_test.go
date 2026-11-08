package sshconn

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

const (
	refusedText   = "ssh: handshake failed: ssh: unable to authenticate, attempted methods [none publickey], no supported methods remain"
	exhaustedText = "ssh: handshake failed: ssh: disconnect, reason 2: Too many authentication failures"
)

// TestHandshakeKindAuthNeedsVerifiedHostKey: under D9 an auth verdict rolls
// a server back, so text an unverified peer sent can never produce it.
func TestHandshakeKindAuthNeedsVerifiedHostKey(t *testing.T) {
	ctx := context.Background()
	for _, tt := range []struct {
		name     string
		text     string
		verified bool
		want     fleet.ErrorKind
	}{
		{"refused after the host key verified", refusedText, true, fleet.ErrorKindAuth},
		{"the same text before verification", refusedText, false, fleet.ErrorKindHandshake},
		{"a pre-kex disconnect quoting it", "ssh: handshake failed: ssh: disconnect, reason 2: unable to authenticate", false, fleet.ErrorKindHandshake},
		{"other handshake failure", "ssh: handshake failed: EOF", true, fleet.ErrorKindHandshake},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := handshakeKind(ctx, errors.New(tt.text), tt.verified); got != tt.want {
				t.Errorf("handshakeKind = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestAuthExhaustedText pins the MaxAuthTries signal: the text sshd sends,
// and only after the host key verified.
func TestAuthExhaustedText(t *testing.T) {
	for _, tt := range []struct {
		name     string
		text     string
		verified bool
		want     bool
	}{
		{"verified", exhaustedText, true, true},
		{"unverified", exhaustedText, false, false},
		{"another disconnect", "ssh: handshake failed: ssh: disconnect, reason 11: bye", true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := authExhausted(errors.New(tt.text), tt.verified); got != tt.want {
				t.Errorf("authExhausted = %v, want %v", got, tt.want)
			}
		})
	}
}

// disconnectServer speaks just enough SSH to send one msgDisconnect with
// desc before any key exchange, and returns its port.
func disconnectServer(t *testing.T, desc string) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { <-done })
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(c, "SSH-2.0-evil\r\n")
		payload := []byte{1, 0, 0, 0, 2}
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(desc))) // #nosec G115 -- small test constant
		payload = append(payload, desc...)
		payload = binary.BigEndian.AppendUint32(payload, 0)
		pad := 8 - (5+len(payload))%8
		if pad < 4 {
			pad += 8
		}
		pkt := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad)) // #nosec G115 -- small test constant
		pkt = append(pkt, byte(pad))
		pkt = append(pkt, payload...)
		pkt = append(pkt, make([]byte, pad)...)
		_, _ = c.Write(pkt)
		_, _ = io.Copy(io.Discard, c)
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// TestPreKexDisconnectNeverSteersAVerdict: text a server sends before its
// host key is verified sets neither auth nor the exhausted flag.
func TestPreKexDisconnectNeverSteersAVerdict(t *testing.T) {
	for _, desc := range []string{"ssh: unable to authenticate", tooManyAuthText} {
		t.Run(desc, func(t *testing.T) {
			port := disconnectServer(t, desc)
			d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: time.Second}
			_, err := d.Connect(ctxTimeout(t, 5*time.Second), config.Server{Name: "evil", Host: "127.0.0.1", Port: port, User: "u"})
			if err == nil {
				t.Fatal("dial succeeded against a disconnecting server")
			}
			var e *Error
			if !errors.As(err, &e) || e.Kind != fleet.ErrorKindHandshake || e.AuthExhausted {
				t.Fatalf("err = %#v, want kind handshake with AuthExhausted false", e)
			}
		})
	}
}

// TestDialFactsFailure pins the failure site's table with the facts set
// directly: a verified MaxAuthTries disconnect, the keep-the-kind rule, the
// incomplete offer and the signer failure.
func TestDialFactsFailure(t *testing.T) {
	ctx := context.Background()
	verified := func() *hostKeyState { return &hostKeyState{verified: true} }
	failedSign := &sessionKey{}
	failedSign.fail()
	for _, tt := range []struct {
		name          string
		f             dialFacts
		text          string
		kind          fleet.ErrorKind
		authExhausted bool
	}{
		{"exhausted, every key offered", dialFacts{hk: verified(), rec: &sessionKey{}}, exhaustedText, fleet.ErrorKindHandshake, true},
		{"exhausted, a key not offered", dialFacts{hk: verified(), rec: &sessionKey{}, asked: 2, missing: 1}, exhaustedText, fleet.ErrorKindAgent, false},
		{"refused, every key offered", dialFacts{hk: verified(), rec: &sessionKey{}}, refusedText, fleet.ErrorKindAuth, false},
		{"refused, a key not offered", dialFacts{hk: verified(), rec: &sessionKey{}, asked: 2, missing: 1}, refusedText, fleet.ErrorKindAgent, false},
		{"a signer failed", dialFacts{hk: verified(), rec: failedSign}, "ssh: handshake failed: agent refused", fleet.ErrorKindAgent, false},
		{"plain handshake failure", dialFacts{hk: verified(), rec: &sessionKey{}}, "ssh: handshake failed: EOF", fleet.ErrorKindHandshake, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tt.f.user, tt.f.addr = "u", "h:22"
			var e *Error
			if err := tt.f.failure(ctx, errors.New(tt.text)); !errors.As(err, &e) {
				t.Fatalf("err = %v, want *Error", err)
			}
			if e.Kind != tt.kind || e.AuthExhausted != tt.authExhausted {
				t.Errorf("kind = %q, exhausted = %v; want %q, %v", e.Kind, e.AuthExhausted, tt.kind, tt.authExhausted)
			}
		})
	}
	t.Run("a host-key verdict wins", func(t *testing.T) {
		verdict := &Error{Kind: fleet.ErrorKindHostKeyChanged, Err: errors.New("mismatch")}
		f := dialFacts{user: "u", addr: "h:22", hk: &hostKeyState{verdict: verdict}, rec: &sessionKey{}}
		if got := fleet.ErrorKindOf(f.failure(ctx, errors.New(refusedText))); got != fleet.ErrorKindHostKeyChanged {
			t.Errorf("kind = %q, want host_key_changed", got)
		}
	})
}

type failingSigner struct{ ssh.Signer }

func (failingSigner) Sign(io.Reader, []byte) (*ssh.Signature, error) {
	return nil, errors.New("agent refused to sign")
}

// failingAlgoSigner fails the path real agent signers take: x/crypto calls
// SignWithAlgorithm on any signer that has it, never Sign.
type failingAlgoSigner struct{ ssh.AlgorithmSigner }

func (failingAlgoSigner) SignWithAlgorithm(io.Reader, []byte, string) (*ssh.Signature, error) {
	return nil, errors.New("agent refused to sign")
}

// TestSignerErrorDuringAuthIsAgent: a signer that fails between list and
// sign (a locked or killed agent) is an agent failure, not an opaque
// handshake error.
func TestSignerErrorDuringAuthIsAgent(t *testing.T) {
	key := sshtest.Key(1)
	_, kh, srv := credServer(t, sshtest.Signer(t, key).PublicKey())
	for name, wrap := range map[string]func(ssh.Signer) ssh.Signer{
		"Sign":              func(s ssh.Signer) ssh.Signer { return failingSigner{s} },
		"SignWithAlgorithm": func(s ssh.Signer) ssh.Signer { return failingAlgoSigner{s.(ssh.AlgorithmSigner)} },
	} {
		t.Run(name, func(t *testing.T) {
			id := sshtest.Identity(t, "/k/ci", key)
			id.Signer = wrap(id.Signer)
			d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{Files: []keyfile.Identity{id}}, DialTimeout: 5 * time.Second}
			if _, err := d.Connect(ctxTimeout(t, 10*time.Second), srv); err == nil || kindOf(t, err) != fleet.ErrorKindAgent {
				t.Fatalf("Connect err = %v, want ErrorKindAgent", err)
			}
		})
	}
}

// closingListener accepts and closes every connection and counts them.
func closingListener(t *testing.T) (int, *atomic.Int32) {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := new(atomic.Int32)
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
	return l.Addr().(*net.TCPAddr).Port, accepted
}

// TestConnectWithOnlyNoneOfferedIsAgent: a locked agent answers with an
// empty list, so nothing could be offered. That proves nothing about the
// server, costs it no connection, and is an agent failure.
func TestConnectWithOnlyNoneOfferedIsAgent(t *testing.T) {
	port, accepted := closingListener(t)
	srv := config.Server{Name: "web-1", Host: "127.0.0.1", Port: port, User: "deploy"}
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t)}, DialTimeout: time.Second}
	_, err := d.ConnectWith(ctxTimeout(t, 5*time.Second), srv, ConnectOptions{Only: []string{"SHA256:gone"}})
	if err == nil || kindOf(t, err) != fleet.ErrorKindAgent {
		t.Fatalf("err = %v, want ErrorKindAgent", err)
	}
	if !strings.Contains(err.Error(), "none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)") {
		t.Errorf("err = %q", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("%d TCP connections, want none", n)
	}
}

// TestConnectWithOnlyPartialOfferAuthIsAgent: some survivors offered and
// all refused cannot prove the missing key's line is broken; a login that
// succeeds on the offered keys is still a valid proof.
func TestConnectWithOnlyPartialOfferAuthIsAgent(t *testing.T) {
	held, gone := sshtest.Key(1), sshtest.Key(2)
	only := []string{sshtest.Fingerprint(t, held), sshtest.Fingerprint(t, gone)}
	t.Run("refused", func(t *testing.T) {
		_, kh, srv := credServer(t, sshtest.Signer(t, sshtest.Key(3)).PublicKey())
		d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, held)}, DialTimeout: 5 * time.Second}
		_, err := d.ConnectWith(ctxTimeout(t, 10*time.Second), srv, ConnectOptions{Only: only})
		if err == nil || kindOf(t, err) != fleet.ErrorKindAgent {
			t.Fatalf("err = %v, want ErrorKindAgent", err)
		}
		if !strings.Contains(err.Error(), "1 of the 2 surviving keys not offered") {
			t.Errorf("err = %q, want the count", err)
		}
	})
	t.Run("accepted", func(t *testing.T) {
		_, kh, srv := credServer(t, sshtest.Signer(t, held).PublicKey())
		d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, held)}, DialTimeout: 5 * time.Second}
		conn, err := d.ConnectWith(ctxTimeout(t, 10*time.Second), srv, ConnectOptions{Only: only})
		if err != nil {
			t.Fatalf("a login on an offered survivor is a valid proof: %v", err)
		}
		_ = conn.Close()
	})
}

// TestConnectRequireOfferEmptyIsAgent: the reconnect after a dropped write
// must not read an empty offer as "this server refused you". Without the
// option an empty offer still dials, so audit's kinds do not change.
func TestConnectRequireOfferEmptyIsAgent(t *testing.T) {
	port, accepted := closingListener(t)
	srv := config.Server{Name: "web-1", Host: "127.0.0.1", Port: port, User: "deploy"}
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t)}, DialTimeout: time.Second}
	_, err := d.ConnectWith(ctxTimeout(t, 5*time.Second), srv, ConnectOptions{RequireOffer: true})
	if err == nil || kindOf(t, err) != fleet.ErrorKindAgent {
		t.Fatalf("err = %v, want ErrorKindAgent", err)
	}
	if !strings.Contains(err.Error(), "no key to offer (agent locked, or keys removed since the plan)") {
		t.Errorf("err = %q", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Errorf("%d TCP connections, want none", n)
	}
	if _, err := d.ConnectWith(ctxTimeout(t, 5*time.Second), srv, ConnectOptions{}); err == nil || kindOf(t, err) == fleet.ErrorKindAgent {
		t.Fatalf("without RequireOffer: err = %v, want a dial that fails on the server side", err)
	}
	if n := accepted.Load(); n != 1 {
		t.Errorf("%d TCP connections without RequireOffer, want 1", n)
	}
}

// TestConnectSessionTimeoutExtendsSocketDeadline: with SessionTimeout the
// socket deadline restarts at the handshake's end, so a slow but healthy
// login is not cut off by the dial bound; without it the dial deadline
// still bounds the session.
func TestConnectSessionTimeoutExtendsSocketDeadline(t *testing.T) {
	key := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, key).PublicKey()},
		Handle: func(_ context.Context, _ string, _ io.Reader, stdout, _ io.Writer) int {
			time.Sleep(2300 * time.Millisecond) // past the 2 s dial bound below
			_, _ = io.WriteString(stdout, "done\n")
			return 0
		},
	})
	srv := config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
	kh := sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey()))
	d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, key)}, DialTimeout: 2 * time.Second}
	run := func(t *testing.T, opts ConnectOptions) error {
		t.Helper()
		conn, err := d.ConnectWith(ctxTimeout(t, 2*time.Second), srv, opts)
		if err != nil {
			t.Fatalf("ConnectWith: %v", err)
		}
		defer func() { _ = conn.Close() }()
		_, _, _, err = Exec(context.Background(), conn.Client, "x", nil)
		return err
	}
	t.Run("session deadline replaces the dial deadline", func(t *testing.T) {
		if err := run(t, ConnectOptions{SessionTimeout: 10 * time.Second}); err != nil {
			t.Fatalf("exec after a late handshake: %v", err)
		}
	})
	t.Run("without it the dial deadline bounds the exec", func(t *testing.T) {
		if err := run(t, ConnectOptions{}); err == nil {
			t.Fatal("exec past the dial deadline succeeded")
		}
	})
}

// TestExecMarksASessionThatNeverOpened: the marker means no script ran. A
// session that opened and then dropped must not carry it, and the message
// stays what it was.
func TestExecMarksASessionThatNeverOpened(t *testing.T) {
	key := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	started, release := make(chan struct{}), make(chan struct{})
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, key).PublicKey()},
		Handle: func(_ context.Context, _ string, _ io.Reader, _, _ io.Writer) int {
			close(started)
			<-release
			return 0
		},
	})
	srv := config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
	kh := sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey()))
	d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, key)}, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Run("a session that opened and then dropped is not marked", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			select {
			case <-started:
			case <-time.After(5 * time.Second):
			}
			_ = conn.Close()
		}()
		_, _, _, err := Exec(context.Background(), conn.Client, "x", nil)
		<-done
		close(release)
		if err == nil || errors.Is(err, ErrSessionNotOpened) {
			t.Fatalf("err = %v, want a transport error without the marker", err)
		}
	})
	t.Run("a dead connection never opens a session", func(t *testing.T) {
		_, _, _, err := Exec(context.Background(), conn.Client, "x", nil)
		if !errors.Is(err, ErrSessionNotOpened) || !strings.HasPrefix(err.Error(), "open session: ") || kindOf(t, err) != fleet.ErrorKindRemote {
			t.Fatalf("err = %v, want the marker and today's message", err)
		}
	})
}
