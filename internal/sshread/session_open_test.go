package sshread

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestReadSessionThatNeverOpens (F1 Q4, gap 13): a server that accepts the
// login but never answers the session open fails the read at
// SessionOpenTimeout, kind timeout, still marked as never opened, through
// the read's %w wrapping and ReadAuthorizedKeys' SanitizedError. The ctx
// has no deadline, so Connect's 3×DialTimeout floor (30 s) is the socket
// deadline and the bound (10 s) is what ends the wait.
func TestReadSessionThatNeverOpens(t *testing.T) {
	user := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:       []ssh.Signer{host},
		Authorized:     []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		SilentSessions: true,
	})
	c := &Client{
		KnownHostsPath: sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey())),
		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, user)},
		DialTimeout:    10 * time.Second,
	}
	done := make(chan error, 1)
	go func() {
		_, err := c.ReadAuthorizedKeys(context.Background(), config.Server{Name: "web-1", Host: srv.Host, Port: srv.Port, User: "deploy"})
		done <- err
	}()
	var err error
	select {
	case err = <-done:
	case <-time.After(25 * time.Second):
		t.Fatal("the read is still waiting for a session that never opens")
	}
	if !errors.Is(err, sshconn.ErrSessionNotOpened) || fleet.ErrorKindOf(err) != fleet.ErrorKindTimeout {
		t.Fatalf("err = %v (kind %q), want the never-opened marker, kind timeout", err, fleet.ErrorKindOf(err))
	}
	if !strings.HasPrefix(err.Error(), "remote read on ") || !strings.HasSuffix(err.Error(), "open session: no answer from the server within 10s") {
		t.Errorf("err = %q", err)
	}
}
