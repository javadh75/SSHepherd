package sshread

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
)

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
		err := hostKeyHint(&knownhosts.KeyError{}, srv, "/kh")
		if !strings.Contains(err.Error(), "ssh-keyscan -p 22 10.0.0.1") {
			t.Errorf("hint = %q, want exact-host keyscan command", err)
		}
	})
	t.Run("changed key gets warning", func(t *testing.T) {
		err := hostKeyHint(&knownhosts.KeyError{Want: make([]knownhosts.KnownKey, 1)}, srv, "/kh")
		if !strings.Contains(err.Error(), "HOST KEY CHANGED") {
			t.Errorf("hint = %q, want changed-key warning", err)
		}
	})
	t.Run("unrelated error passes through", func(t *testing.T) {
		orig := net.ErrClosed
		if got := hostKeyHint(orig, srv, "/kh"); !errors.Is(got, orig) {
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
