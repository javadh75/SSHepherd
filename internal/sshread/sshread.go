// Package sshread is the real KeyReader: it connects to a server over SSH
// (agent auth, strict known_hosts) and reads the remote authorized_keys.
// The connection glue lives in internal/sshconn (shared with the write
// path); this package keeps the read decision logic and its public API.
package sshread

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// PreflightKnownHosts verifies the known_hosts file loads before any server
// is dialed, so a bad path fails once with a clear message instead of once
// per server. It keeps the knownhosts dependency inside this package.
func PreflightKnownHosts(path string) error {
	if _, err := knownhosts.New(path); err != nil {
		return fmt.Errorf("load known_hosts %s: %w", path, err)
	}
	return nil
}

// CheckAgent verifies a usable SSH agent — reachable and holding at least
// one key — before any server is dialed, so a missing or empty agent fails
// once with a clear message instead of once per server with a cryptic
// "no supported methods remain" auth error. ctx cancellation aborts the
// dial; the 3s timeout still bounds a wedged agent on its own.
func CheckAgent(ctx context.Context, sock string) error {
	if sock == "" {
		return errors.New("no SSH agent: SSH_AUTH_SOCK is not set (start ssh-agent and ssh-add a key)")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", sock)
	if err != nil {
		return fmt.Errorf("SSH agent unreachable at %s: %w", sock, err)
	}
	defer func() { _ = conn.Close() }()                   // errcheck: close error is uninteresting on a preflight
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second)) // a wedged agent must not hang the preflight
	keys, err := agent.NewClient(conn).List()
	if err != nil {
		return fmt.Errorf("SSH agent at %s is not answering (is it an SSH agent?): %w", sock, err)
	}
	if len(keys) == 0 {
		return fmt.Errorf("SSH agent at %s has no keys loaded (run ssh-add to load your key)", sock)
	}
	return nil
}

// Client reads remote authorized_keys over SSH. It implements audit.KeyReader.
type Client struct {
	KnownHostsPath string
	AgentSock      string
	DialTimeout    time.Duration
	Log            *slog.Logger // optional stage-level telemetry; nil discards
}

var _ audit.KeyReader = (*Client)(nil)

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (c *Client) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.DiscardHandler)
}

// ReadAuthorizedKeys connects to srv and reads its authorized_keys via
// readAuthorizedKeys, wrapping any error so its message is control-stripped:
// handshake errors can embed server-supplied text (disconnect messages,
// algorithm names), which must never reach an operator's terminal raw.
func (c *Client) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (audit.ReadResult, error) {
	res, err := c.readAuthorizedKeys(ctx, srv)
	if err != nil {
		return res, sshconn.SanitizedError{Err: err}
	}
	return res, nil
}

// readAuthorizedKeys connects through sshconn.Dialer and reads the server's
// authorized_keys — srv.AuthorizedKeysFile when set, ~/.ssh/authorized_keys
// otherwise — via a one-shot session. Deadline semantics live in Connect:
// the ctx deadline (or the derived 3×DialTimeout floor) bounds the whole
// exchange, not just the dial.
func (c *Client) readAuthorizedKeys(ctx context.Context, srv config.Server) (audit.ReadResult, error) {
	var zero audit.ReadResult
	d := &sshconn.Dialer{
		KnownHostsPath: c.KnownHostsPath,
		AgentSock:      c.AgentSock,
		DialTimeout:    c.DialTimeout,
		Log:            c.Log,
	}
	conn, err := d.Connect(ctx, srv)
	if err != nil {
		return zero, err
	}
	defer func() { _ = conn.Close() }()

	path := srv.AuthorizedKeysFile
	if path == "" {
		path = sshconn.DefaultAuthorizedKeysPath
	}
	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	code, stdout, stderr, err := sshconn.Exec(conn.Client, sshconn.AuthorizedKeysCmdFor(path), nil)
	if err != nil {
		return zero, fmt.Errorf("remote read on %s: %w", addr, err)
	}
	c.log().Debug("remote read done", "addr", addr, "exit", code)
	return sshconn.FinishRead(code, stdout, stderr, addr, c.log())
}
