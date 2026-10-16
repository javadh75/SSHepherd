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
	"sync"
	"time"

	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// LoadKnownHosts verifies the known_hosts file loads before any server is
// dialed, so a bad path fails once with a clear message instead of once per
// server, and returns the parsed snapshot: set it as Client.KnownHosts (or sshconn.Dialer.KnownHosts) and every
// server in the run is verified against this one parse.
func LoadKnownHosts(path string) (*sshconn.KnownHosts, error) {
	return sshconn.LoadKnownHosts(path) // sshconn labels the error with the path (wrapcheck-exempt package)
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
// Use it by pointer and share one Client across a fan-out: it builds a
// single sshconn.Dialer, so known_hosts is parsed once per run.
type Client struct {
	KnownHostsPath string
	// KnownHosts optionally supplies the preflight's parsed snapshot
	// (LoadKnownHosts); nil parses KnownHostsPath once, on first read.
	KnownHosts  *sshconn.KnownHosts
	AgentSock   string
	DialTimeout time.Duration
	// PreferKeys optionally names the agent keys to offer first per server
	// (see sshconn.Dialer.PreferKeys) — typically audit.GrantedFingerprints.
	PreferKeys func(srv config.Server) []string
	Log        *slog.Logger // optional stage-level telemetry; nil discards

	once   sync.Once
	dialer *sshconn.Dialer
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

// getDialer returns the Client's one Dialer, built on first use.
func (c *Client) getDialer() *sshconn.Dialer {
	c.once.Do(func() {
		c.dialer = &sshconn.Dialer{
			KnownHostsPath: c.KnownHostsPath,
			KnownHosts:     c.KnownHosts,
			AgentSock:      c.AgentSock,
			DialTimeout:    c.DialTimeout,
			PreferKeys:     c.PreferKeys,
			Log:            c.Log,
		}
	})
	return c.dialer
}

// readAuthorizedKeys connects through sshconn.Dialer and reads the server's
// authorized_keys — srv.AuthorizedKeysFile when set, ~/.ssh/authorized_keys
// otherwise — via a one-shot session. For the default path it also probes
// ~/.ssh/authorized_keys2 (a second session on the same connection), which
// sshd's default AuthorizedKeysFile consults too. Deadline semantics live
// in Connect: the ctx deadline (or the derived 3×DialTimeout floor) bounds
// the whole exchange, not just the dial; ctx cancellation ends it at once.
func (c *Client) readAuthorizedKeys(ctx context.Context, srv config.Server) (audit.ReadResult, error) {
	var zero audit.ReadResult
	conn, err := c.getDialer().Connect(ctx, srv)
	if err != nil {
		return zero, err
	}
	defer func() { _ = conn.Close() }()

	path := srv.AuthorizedKeysFile
	if path == "" {
		path = sshconn.DefaultAuthorizedKeysPath
	}
	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	code, stdout, stderr, err := sshconn.Exec(ctx, conn.Client, sshconn.AuthorizedKeysCmdFor(path), nil)
	if err != nil {
		return zero, fmt.Errorf("remote read on %s: %w", addr, err)
	}
	c.log().Debug("remote read done", "addr", addr, "exit", code)
	res, err := sshconn.FinishRead(code, stdout, stderr, addr, c.log())
	if err != nil {
		return zero, err
	}
	res.SessionKeyFP = conn.SessionKeyFP()

	if path == sshconn.DefaultAuthorizedKeysPath {
		code, _, stderr, err := sshconn.Exec(ctx, conn.Client, sshconn.SecondaryKeysCmd(), nil)
		if err != nil {
			return zero, fmt.Errorf("authorized_keys2 probe on %s: %w", addr, err)
		}
		present, err := sshconn.FinishSecondaryProbe(code, stderr)
		if err != nil {
			return zero, fmt.Errorf("on %s: %w", addr, err)
		}
		res.AuthorizedKeys2 = present
	}
	return res, nil
}
