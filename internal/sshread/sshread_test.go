package sshread

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// ed25519Key parses a deterministic ssh-ed25519 public key for tests.
func ed25519Key(t *testing.T, seed byte) ssh.PublicKey {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testkeys.Line(t, seed)))
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	return k
}

// ecdsaKey generates an ECDSA host key — a different type than ed25519Key.
func ecdsaKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("wrap ecdsa: %v", err)
	}
	return pub
}

func TestInterpretExit(t *testing.T) {
	tests := []struct {
		name       string
		code       int
		stderr     string
		wantAbsent bool
		wantErr    bool
	}{
		{"success", 0, "", false, false},
		{"file absent", fileAbsentExit, "", true, false},
		{"cat failure", 1, "cat: permission denied", false, true},
		{"other failure", 127, "sh: not found", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			absent, err := interpretExit(tt.code, tt.stderr)
			if absent != tt.wantAbsent {
				t.Errorf("absent = %v, want %v", absent, tt.wantAbsent)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.stderr != "" && !strings.Contains(err.Error(), strings.TrimSpace(tt.stderr)) {
				t.Errorf("err %q should include remote stderr", err)
			}
		})
	}
}

func TestCheckAgent(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		if err := CheckAgent(""); err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
			t.Errorf("CheckAgent(\"\") = %v, want SSH_AUTH_SOCK error", err)
		}
	})
	t.Run("dead socket", func(t *testing.T) {
		if err := CheckAgent(filepath.Join(t.TempDir(), "nope.sock")); err == nil {
			t.Error("CheckAgent(dead) = nil, want error")
		}
	})
	t.Run("live socket", func(t *testing.T) {
		sock := filepath.Join(t.TempDir(), "agent.sock")
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		if err := CheckAgent(sock); err != nil {
			t.Errorf("CheckAgent(live) = %v, want nil", err)
		}
	})
}

func TestHostKeyHint(t *testing.T) {
	srv := config.Server{Name: "web-1", Host: "10.0.0.1", Port: 22, User: "deploy"}

	t.Run("unknown host gets keyscan hint", func(t *testing.T) {
		err := hostKeyHint(&knownhosts.KeyError{}, ed25519Key(t, 1), srv, "/kh")
		if !strings.Contains(err.Error(), "ssh-keyscan -p 22 10.0.0.1") {
			t.Errorf("hint = %q, want exact-host keyscan command", err)
		}
	})
	t.Run("same-type mismatch gets changed-key warning", func(t *testing.T) {
		// known_hosts records one ed25519 key; the host presents a different
		// ed25519 key — that is a genuine changed-key alarm.
		ke := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: ed25519Key(t, 2)}}}
		err := hostKeyHint(ke, ed25519Key(t, 1), srv, "/kh")
		if !strings.Contains(err.Error(), "HOST KEY CHANGED") {
			t.Errorf("hint = %q, want changed-key warning", err)
		}
		if !strings.Contains(err.Error(), "presented ssh-ed25519 key SHA256:") {
			t.Errorf("hint = %q, want the presented key identified", err)
		}
	})
	t.Run("unrecorded key type gets keyscan-refresh hint, not alarm", func(t *testing.T) {
		// known_hosts records only an ed25519 key; the host presents an ECDSA
		// key — no recorded key of that type exists, so this is likely a
		// stale known_hosts entry, not a hostile key swap.
		ke := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: ed25519Key(t, 2)}}}
		err := hostKeyHint(ke, ecdsaKey(t), srv, "/kh")
		if strings.Contains(err.Error(), "HOST KEY CHANGED") {
			t.Errorf("hint = %q, must not raise the changed-key alarm", err)
		}
		if !strings.Contains(err.Error(), "not recorded in known_hosts") {
			t.Errorf("hint = %q, want unrecorded-type wording", err)
		}
		if !strings.Contains(err.Error(), "recorded: ssh-ed25519") {
			t.Errorf("hint = %q, want the recorded types listed", err)
		}
	})
	t.Run("unrelated error passes through", func(t *testing.T) {
		orig := net.ErrClosed
		if got := hostKeyHint(orig, ed25519Key(t, 1), srv, "/kh"); !errors.Is(got, orig) {
			t.Errorf("unrelated error was wrapped: %v", got)
		}
	})
}

func TestClientBadAgentSock(t *testing.T) {
	c := &Client{
		AgentSock:      filepath.Join(t.TempDir(), "nope.sock"),
		KnownHostsPath: filepath.Join(t.TempDir(), "kh"),
		DialTimeout:    time.Second,
	}
	srv := config.Server{Name: "s", Host: "127.0.0.1", Port: 1, User: "u"}
	_, err := c.ReadAuthorizedKeys(context.Background(), srv)
	if err == nil || !strings.Contains(err.Error(), "agent") {
		t.Errorf("err = %v, want agent connection error", err)
	}
}

func TestClientBadKnownHostsPath(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c := &Client{
		AgentSock:      sock,
		KnownHostsPath: filepath.Join(t.TempDir(), "does-not-exist"),
		DialTimeout:    time.Second,
	}
	srv := config.Server{Name: "s", Host: "127.0.0.1", Port: 1, User: "u"}
	_, err = c.ReadAuthorizedKeys(context.Background(), srv)
	if err == nil || !strings.Contains(err.Error(), "known_hosts") {
		t.Errorf("err = %v, want known_hosts load error", err)
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{limit: 8}

	n, err := b.Write([]byte("12345"))
	if n != 5 || err != nil {
		t.Fatalf("Write under cap = (%d, %v), want (5, nil)", n, err)
	}
	if b.truncated {
		t.Error("truncated = true before cap was hit")
	}

	n, err = b.Write([]byte("6789A")) // only 3 bytes of room left
	if n != 5 || err != nil {
		t.Fatalf("Write over cap = (%d, %v), want (5, nil) — must report full length, never fail", n, err)
	}
	if !b.truncated {
		t.Error("truncated = false after overflowing the cap")
	}
	if got := b.String(); got != "12345678" {
		t.Errorf("String() = %q, want first 8 bytes only", got)
	}

	n, err = b.Write([]byte("x")) // already full
	if n != 1 || err != nil {
		t.Errorf("Write past full = (%d, %v), want (1, nil)", n, err)
	}
	if got := len(b.Bytes()); got != 8 {
		t.Errorf("len = %d after writes past cap, want 8", got)
	}

	// Filling exactly to the cap is not truncation, and empty writes at the
	// cap must not flag it either.
	exact := &cappedBuffer{limit: 2}
	_, _ = exact.Write([]byte("ab"))
	_, _ = exact.Write(nil)
	if exact.truncated {
		t.Error("exact-fit buffer flagged as truncated")
	}
}

func TestSanitizeRemote(t *testing.T) {
	in := "a\x1b[31mred\x07\rb\nc\td\x00"
	want := "a[31mredb\nc\td"
	if got := sanitizeRemote(in); got != want {
		t.Errorf("sanitizeRemote(%q) = %q, want %q", in, got, want)
	}
	if got := sanitizeRemote("clean text"); got != "clean text" {
		t.Errorf("clean input altered: %q", got)
	}
}

// startFakeAgent serves a unix socket that accepts and holds connections —
// enough for the client's agent dial to succeed without a real agent.
func startFakeAgent(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen agent: %v", err)
	}
	holder := newConnHolder(l)
	t.Cleanup(holder.close)
	return sock
}

// connHolder accepts connections and keeps them open (a silent peer) until
// closed, so client-side deadlines — not peer EOFs — end the exchange.
type connHolder struct {
	l     net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newConnHolder(l net.Listener) *connHolder {
	h := &connHolder{l: l}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.conns = append(h.conns, c)
			h.mu.Unlock()
		}
	}()
	return h
}

func (h *connHolder) close() {
	_ = h.l.Close()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.conns {
		_ = c.Close()
	}
}

// TestClientDeadline pins the hard time bound on the whole SSH exchange: a
// server that accepts TCP but never speaks SSH must not hang a worker beyond
// the ctx deadline — or, absent one, the derived 3×DialTimeout floor.
func TestClientDeadline(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	holder := newConnHolder(l)
	t.Cleanup(holder.close)

	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	agentSock := startFakeAgent(t)
	srv := config.Server{
		Name: "silent", Host: "127.0.0.1",
		Port: l.Addr().(*net.TCPAddr).Port, User: "u",
	}

	t.Run("ctx deadline bounds the handshake", func(t *testing.T) {
		c := &Client{AgentSock: agentSock, KnownHostsPath: kh, DialTimeout: 5 * time.Second}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := c.ReadAuthorizedKeys(ctx, srv)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("silent server produced no error")
		}
		if elapsed > time.Second {
			t.Errorf("returned after %v, want well under 1s (200ms deadline)", elapsed)
		}
	})

	t.Run("deadline floor kicks in without a ctx deadline", func(t *testing.T) {
		c := &Client{AgentSock: agentSock, KnownHostsPath: kh, DialTimeout: 100 * time.Millisecond}
		start := time.Now()
		_, err := c.ReadAuthorizedKeys(context.Background(), srv) // no deadline: floor = 300ms
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("silent server produced no error")
		}
		if elapsed > time.Second {
			t.Errorf("returned after %v, want well under 1s (300ms derived floor)", elapsed)
		}
	})
}
