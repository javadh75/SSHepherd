package sshread

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

func TestCheckAgent(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		if err := checkAgent(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
			t.Errorf("checkAgent(\"\") = %v, want SSH_AUTH_SOCK error", err)
		}
	})
	t.Run("dead socket", func(t *testing.T) {
		if err := checkAgent(context.Background(), filepath.Join(t.TempDir(), "nope.sock")); err == nil {
			t.Error("checkAgent(dead) = nil, want error")
		}
	})
	t.Run("agent with keys", func(t *testing.T) {
		if err := checkAgent(context.Background(), serveAgent(t, true)); err != nil {
			t.Errorf("checkAgent(agent with keys) = %v, want nil", err)
		}
	})
	t.Run("empty agent", func(t *testing.T) {
		// The socket answers the agent protocol but holds zero keys: every
		// later per-server auth would fail. The preflight must say so once.
		err := checkAgent(context.Background(), serveAgent(t, false))
		if err == nil || !strings.Contains(err.Error(), "no keys") {
			t.Errorf("checkAgent(empty agent) = %v, want a no-keys error", err)
		}
		if err != nil && !strings.Contains(err.Error(), "ssh-add") {
			t.Errorf("err %q should tell the operator to run ssh-add", err)
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		// Ctrl-C during the preflight must abort the dial: the caller's
		// context flows into DialContext instead of being dropped.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := checkAgent(ctx, serveAgent(t, true))
		if !errors.Is(err, context.Canceled) {
			t.Errorf("checkAgent(canceled ctx) = %v, want context.Canceled", err)
		}
	})
	t.Run("unresponsive socket", func(t *testing.T) {
		// Reachable but not speaking the agent protocol (closes on accept).
		sock := filepath.Join(shortTempDir(t), "agent.sock")
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
		if err := checkAgent(context.Background(), sock); err == nil {
			t.Error("checkAgent(unresponsive) = nil, want error")
		}
	})
}

// shortTempDir returns a temp dir with a short absolute path: unix socket
// paths are capped (~104 bytes on macOS) and t.TempDir() embeds the full
// subtest name, which can exceed it.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveAgent runs a real in-memory SSH agent on a unix socket, holding one
// generated key when withKey is set, and returns the socket path.
func serveAgent(t *testing.T, withKey bool) string {
	t.Helper()
	keyring := agent.NewKeyring()
	if withKey {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
			t.Fatalf("keyring add: %v", err)
		}
	}
	sock := filepath.Join(shortTempDir(t), "agent.sock")
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

func TestClientBadAgentSock(t *testing.T) {
	c := &Client{
		Creds:          &sshconn.Credentials{AgentSock: filepath.Join(t.TempDir(), "nope.sock")},
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
	// The signers are fetched before anything else (a working agent), so
	// the first failure is the known_hosts load.
	c := &Client{
		Creds:          &sshconn.Credentials{AgentSock: serveAgent(t, true)},
		KnownHostsPath: filepath.Join(t.TempDir(), "does-not-exist"),
		DialTimeout:    time.Second,
	}
	srv := config.Server{Name: "s", Host: "127.0.0.1", Port: 1, User: "u"}
	_, err := c.ReadAuthorizedKeys(context.Background(), srv)
	if err == nil || !strings.Contains(err.Error(), "known_hosts") {
		t.Errorf("err = %v, want known_hosts load error", err)
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
		c := &Client{Creds: &sshconn.Credentials{AgentSock: agentSock}, KnownHostsPath: kh, DialTimeout: 5 * time.Second}
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
		c := &Client{Creds: &sshconn.Credentials{AgentSock: agentSock}, KnownHostsPath: kh, DialTimeout: 100 * time.Millisecond}
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

// TestClientLogNilSafe: an unset Log field must yield a usable logger.
func TestClientLogNilSafe(_ *testing.T) {
	c := &Client{}
	c.log().Debug("must not panic")
}
