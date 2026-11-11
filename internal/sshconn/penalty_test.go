package sshconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// rawServer accepts TCP on 127.0.0.1 and hands every connection to serve,
// which owns it; Cleanup closes the listener and waits for every handler.
func rawServer(t *testing.T, serve func(net.Conn)) int {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); serve(c) }()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// Server behaviors before and after the SSH version banner.
var (
	// dropAtAccept is sshd's PerSourcePenalties (and MaxStartups) drop:
	// the connection closes before the server says anything.
	dropAtAccept = func(c net.Conn) { _ = c.Close() }
	// dropAfterNotice closes after a pre-banner line (RFC 4253 lets a
	// server send other lines before its version), still before the banner.
	dropAfterNotice = func(c net.Conn) {
		_, _ = io.WriteString(c, "please wait\r\n")
		_ = c.Close()
	}
	// resetAtAccept refuses with a TCP RST instead of a FIN.
	resetAtAccept = func(c net.Conn) {
		if tc, ok := c.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}
		_ = c.Close()
	}
	// dropAfterBanner sends the banner, then closes: the server spoke SSH,
	// so its drop is no penalty.
	dropAfterBanner = func(c net.Conn) {
		_, _ = io.WriteString(c, "SSH-2.0-OpenSSH_10.3\r\n")
		buf := make([]byte, 256)
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = c.Read(buf) // the client's version line
		_ = c.Close()
	}
)

// TestPreBannerDropGetsPenaltyHint (G016): a handshake that ends before the
// server's version banner is handshake with PenaltyHint, so an operator
// whose healthy accounts are dropped by sshd's PerSourcePenalties is told
// where to look. A drop after the banner, a timeout and a cancel get no
// such hint, and none of them is ever auth or the MaxAuthTries signal (the
// login check reads those as REJECTED).
func TestPreBannerDropGetsPenaltyHint(t *testing.T) {
	for _, tt := range []struct {
		name  string
		serve func(net.Conn)
		hint  string
	}{
		{"closed before any byte", dropAtAccept, PenaltyHint},
		{"closed after a pre-banner line", dropAfterNotice, PenaltyHint},
		{"reset before any byte", resetAtAccept, PenaltyHint},
		{"closed after the banner", dropAfterBanner, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			port := rawServer(t, tt.serve)
			d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: time.Second}
			_, err := d.Connect(ctxTimeout(t, 5*time.Second), config.Server{Name: "web-1", Host: "127.0.0.1", Port: port, User: "u"})
			assertPenaltyErr(t, err, fleet.ErrorKindHandshake, tt.hint)
		})
	}
	t.Run("a stalled server times out without the hint", func(t *testing.T) {
		f := newFixture(t, sshtest.ServerConfig{Stall: true}, sshtest.Key(1))
		_, err := f.dialer(sshtest.KnownHostsFile(t)).Connect(ctxTimeout(t, 200*time.Millisecond), f.cfgSrv)
		assertPenaltyErr(t, err, fleet.ErrorKindTimeout, "")
	})
	t.Run("a cancel before the banner gets no hint", func(t *testing.T) {
		f := newFixture(t, sshtest.ServerConfig{Stall: true}, sshtest.Key(1))
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		_, err := f.dialer(sshtest.KnownHostsFile(t)).Connect(ctx, f.cfgSrv)
		assertPenaltyErr(t, err, fleet.ErrorKindCanceled, "")
	})
	t.Run("a healthy server behind the same check connects", func(t *testing.T) {
		host := sshtest.Signer(t, sshtest.Key(40))
		f := newFixture(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{host}, Authorized: []ssh.PublicKey{sshtest.Signer(t, sshtest.Key(1)).PublicKey()}}, sshtest.Key(1))
		conn, err := f.dialer(sshtest.KnownHostsFile(t, f.srv.KnownHostsLine(host.PublicKey()))).Connect(ctxTimeout(t, 5*time.Second), f.cfgSrv)
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		_ = conn.Close()
	})
}

// TestPreBannerDropThroughBastionGetsPenaltyHint (G016): behind a bastion
// the target sees the bastion's address, so one failing account there
// penalizes every target reached through it; the drop is the target's own
// (no HopStage) and carries the same hint.
func TestPreBannerDropThroughBastionGetsPenaltyHint(t *testing.T) {
	port := rawServer(t, dropAtAccept)
	f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
	f.targetSrv.Port = port
	f.kh = sshtest.KnownHostsFile(t, f.hop.KnownHostsLine(f.hopKey.PublicKey()),
		f.target.KnownHostsLine(f.targetKey.PublicKey()))
	_, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
	assertPenaltyErr(t, err, fleet.ErrorKindHandshake, PenaltyHint)
	if hop := fleet.FailedHopOf(err); hop != "" {
		t.Errorf("FailedHopOf = %q, want the target's own failure", hop)
	}
}

func assertPenaltyErr(t *testing.T, err error, kind fleet.ErrorKind, hint string) {
	t.Helper()
	if err == nil {
		t.Fatal("Connect succeeded")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v, want *Error", err)
	}
	if e.Kind != kind || e.AuthExhausted {
		t.Errorf("kind = %q, exhausted = %v; want %q, false (err: %v)", e.Kind, e.AuthExhausted, kind, err)
	}
	if got := fleet.HintOf(err); got != hint {
		t.Errorf("hint = %q, want %q (err: %v)", got, hint, err)
	}
}

// TestPreBannerHintNeedsHandshakeKind: a pre-banner EOF that the deadline
// caused (a via target's tunnel ends as the hop's socket deadline fires,
// before ctx's timer) is a timeout and carries no penalty hint.
func TestPreBannerHintNeedsHandshakeKind(t *testing.T) {
	f := dialFacts{user: "u", addr: "h:22", hk: &hostKeyState{}, rec: &sessionKey{}, banner: &bannerWatch{}}
	err := f.failure(pastDeadlineCtx{context.Background()}, io.EOF)
	assertPenaltyErr(t, err, fleet.ErrorKindTimeout, "")
	err = f.failure(context.Background(), io.EOF)
	assertPenaltyErr(t, err, fleet.ErrorKindHandshake, PenaltyHint)
}

// TestDroppedBeforeBanner pins which transport endings count as a drop
// before the banner (a close, a reset, or a write into a reset socket),
// and that a run with no banner facts (nil watch) never gets the hint.
func TestDroppedBeforeBanner(t *testing.T) {
	seen := &bannerWatch{}
	seen.scan([]byte("SSH-2.0-x\n"))
	opErr := func(errno syscall.Errno) error {
		return fmt.Errorf("ssh: handshake failed: %w", &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", errno)})
	}
	for _, tt := range []struct {
		name   string
		err    error
		banner *bannerWatch
		want   bool
	}{
		{"EOF", fmt.Errorf("ssh: handshake failed: %w", io.EOF), &bannerWatch{}, true},
		{"reset", opErr(syscall.ECONNRESET), &bannerWatch{}, true},
		{"broken pipe", opErr(syscall.EPIPE), &bannerWatch{}, true},
		{"refused text", errors.New("ssh: handshake failed: EOF"), &bannerWatch{}, false},
		{"other errno", opErr(syscall.ETIMEDOUT), &bannerWatch{}, false},
		{"EOF after the banner", io.EOF, seen, false},
		{"EOF with no banner facts", io.EOF, nil, false},
	} {
		if got := droppedBeforeBanner(tt.err, tt.banner); got != tt.want {
			t.Errorf("%s: droppedBeforeBanner = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestBannerWatch pins the banner detector over split reads: only a line
// starting "SSH-" and ending in a newline is the banner.
func TestBannerWatch(t *testing.T) {
	for _, tt := range []struct {
		name   string
		chunks []string
		want   bool
	}{
		{"nothing", nil, false},
		{"a banner in one read", []string{"SSH-2.0-OpenSSH_10.3\r\n"}, true},
		{"a banner a byte at a time", []string{"S", "S", "H", "-", "2", "\r", "\n"}, true},
		{"a banner with no newline yet", []string{"SSH-2.0-OpenSSH_10.3"}, false},
		{"pre-banner lines, then the banner", []string{"hello\r\nwait\n", "SSH-2.0-x\n"}, true},
		{"pre-banner lines only", []string{"hello\r\nSSH\n", "xSSH-2.0\n"}, false},
		{"SSH- inside a line", []string{"say SSH-2.0\n"}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var b bannerWatch
			for _, c := range tt.chunks {
				b.scan([]byte(c))
			}
			if got := b.seen.Load(); got != tt.want {
				t.Errorf("seen = %v, want %v", got, tt.want)
			}
		})
	}
}
