package sshconn

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// silentConn logs in to a server that never answers a session open.
func silentConn(t *testing.T) *Conn {
	t.Helper()
	key := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:       []ssh.Signer{host},
		Authorized:     []ssh.PublicKey{sshtest.Signer(t, key).PublicKey()},
		SilentSessions: true,
	})
	srv := config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
	kh := sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey()))
	d := &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: sshtest.Agent(t, key)}, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 30*time.Second), srv) // socket deadline 30 s: never the bound here
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// withSessionOpenWait shortens the bound for one test (no sshconn test runs
// in parallel).
func withSessionOpenWait(t *testing.T, wait time.Duration) {
	t.Helper()
	was := sessionOpenWait
	sessionOpenWait = wait
	t.Cleanup(func() { sessionOpenWait = was })
}

// TestExecBoundsASessionThatNeverOpens (F1 Q4): x/crypto's NewSession can
// wait forever on a dying connection. Exec stops waiting when the bound
// elapses (a ctx without a deadline, as context.WithoutCancel gives) or ctx
// ends first, returns the never-opened marker with kind timeout or ctx's
// kind, and closes the client so the waiting open returns: goleak (TestMain)
// fails the package if the opener goroutine is still running when the
// package's tests end.
func TestExecBoundsASessionThatNeverOpens(t *testing.T) {
	for _, tt := range []struct {
		name     string
		wait     time.Duration
		ctx      func(tb testing.TB) context.Context
		wantKind fleet.ErrorKind
		wantText string
	}{
		{"the bound ends a wait ctx cannot", 100 * time.Millisecond,
			func(testing.TB) context.Context { return context.WithoutCancel(context.Background()) },
			fleet.ErrorKindTimeout, "open session: no answer from the server within 100ms"},
		{"a ctx deadline ends it first", time.Hour,
			func(tb testing.TB) context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
				tb.Cleanup(cancel)
				return ctx
			},
			fleet.ErrorKindTimeout, "open session: context deadline exceeded"},
		{"cancellation ends it", time.Hour,
			func(tb testing.TB) context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				tb.Cleanup(cancel)
				time.AfterFunc(100*time.Millisecond, cancel)
				return ctx
			},
			fleet.ErrorKindCanceled, "open session: context canceled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			withSessionOpenWait(t, tt.wait)
			conn := silentConn(t)
			ctx := tt.ctx(t)
			done := make(chan error, 1)
			go func() {
				_, _, _, err := Exec(ctx, conn.Client, "x", nil)
				done <- err
			}()
			var err error
			select {
			case err = <-done:
			case <-time.After(20 * time.Second):
				t.Fatal("Exec still waiting for a session that never opens")
			}
			if !errors.Is(err, ErrSessionNotOpened) || err.Error() != tt.wantText || kindOf(t, err) != tt.wantKind {
				t.Fatalf("err = %v, want %q with the marker and kind %s", err, tt.wantText, tt.wantKind)
			}
			waited := make(chan struct{})
			go func() { _ = conn.Client.Wait(); close(waited) }()
			select {
			case <-waited:
			case <-time.After(10 * time.Second):
				t.Fatal("Exec left the client open after giving up")
			}
		})
	}
}

// TestExecHealthySessionUnchanged (F1 Q4): a server that answers runs the
// script as before, well inside the bound.
func TestExecHealthySessionUnchanged(t *testing.T) {
	withSessionOpenWait(t, 5*time.Second)
	key := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, key).PublicKey()},
		Handle: func(_ context.Context, _ string, _ io.Reader, stdout, _ io.Writer) int {
			_, _ = io.WriteString(stdout, "ok\n")
			return 3
		},
	})
	srv := config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"}
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t, s.KnownHostsLine(host.PublicKey())), Creds: &Credentials{AgentSock: sshtest.Agent(t, key)}, DialTimeout: 5 * time.Second}
	conn, err := d.Connect(ctxTimeout(t, 10*time.Second), srv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	code, stdout, _, err := Exec(context.WithoutCancel(context.Background()), conn.Client, "x", nil)
	if err != nil || code != 3 || stdout.String() != "ok\n" {
		t.Fatalf("Exec = %d, %q, %v; want 3, \"ok\\n\", nil", code, stdout.String(), err)
	}
}
