// Package sshread is the real KeyReader: it connects to a server over SSH
// (key files and/or agent, strict known_hosts) and reads the remote
// authorized_keys.
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

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// LoadKnownHosts verifies the known_hosts file loads before any server is
// dialed, so a bad path fails once with a clear message instead of once per
// server, and returns the parsed snapshot: set it as Client.KnownHosts (or sshconn.Dialer.KnownHosts) and every
// server in the run is verified against this one parse.
func LoadKnownHosts(path string) (*sshconn.KnownHosts, error) {
	return sshconn.LoadKnownHosts(path) // sshconn labels the error with the path (wrapcheck-exempt package)
}

// CheckCredentials verifies, before any server is dialed, that the run has
// something to authenticate with, so a missing or empty agent fails once
// with a clear message instead of once per server with a cryptic "no
// supported methods remain". With no key files the agent is required and
// the messages are checkAgent's, verbatim. needHeld (apply) additionally
// requires a non-empty held set — plain keys, since certificates never
// count toward the self-lockout guard — so a certificate-only operator is
// refused with a certificate-specific message; audit/adopt (needHeld
// false) count signers, so a certificate-only agent passes, as before.
func CheckCredentials(ctx context.Context, creds *sshconn.Credentials, needHeld bool) error {
	if len(creds.Files) == 0 {
		if err := checkAgent(ctx, creds.AgentSock); err != nil {
			return err
		}
	}
	if !needHeld {
		signers, release, err := creds.Signers(ctx)
		if err != nil {
			return err
		}
		release()
		if len(signers) == 0 {
			return errors.New("no keys to authenticate with")
		}
		return nil
	}
	held, err := creds.Held(ctx)
	if err != nil {
		return err
	}
	if len(held) == 0 {
		return errors.New("the keys you hold (identity files + agent) are all certificates — certificates never count toward apply's self-lockout guard, so no write could be proven safe (ssh-add a plain key, or pass --identity PATH)")
	}
	return nil
}

// checkAgent verifies a usable SSH agent — reachable and holding at least
// one key — before any server is dialed, so a missing or empty agent fails
// once with a clear message instead of once per server with a cryptic
// "no supported methods remain" auth error. ctx cancellation aborts the
// dial; the 3s timeout still bounds a wedged agent on its own.
func checkAgent(ctx context.Context, sock string) error {
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
	KnownHosts *sshconn.KnownHosts
	// Creds is the run's credential source (key files + agent); one per
	// run, shared with the writer and the probe.
	Creds       *sshconn.Credentials
	DialTimeout time.Duration
	// PreferKeys optionally names the keys to offer first per server (see
	// sshconn.Dialer.PreferKeys) — typically audit.GrantedFingerprints.
	PreferKeys func(srv config.Server) []string
	// Server resolves a via: name (see sshconn.Dialer.Server); without it a
	// server behind a bastion fails closed.
	Server func(name string) (config.Server, bool)
	// OfferAll and QuietFallback: see sshconn.Dialer.
	OfferAll      bool
	QuietFallback bool
	// ReadKeys2 also reads a non-empty ~/.ssh/authorized_keys2 (with the
	// managed read's size cap) into ReadResult.Keys2 — the post-revoke
	// sweep's proof that a revoked key is gone from it too.
	ReadKeys2 bool
	Log       *slog.Logger // optional stage-level telemetry; nil discards

	once   sync.Once
	dialer *sshconn.Dialer
}

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
func (c *Client) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (fleet.ReadResult, error) {
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
			Creds:          c.Creds,
			DialTimeout:    c.DialTimeout,
			PreferKeys:     c.PreferKeys,
			Server:         c.Server,
			OfferAll:       c.OfferAll,
			QuietFallback:  c.QuietFallback,
			Log:            c.Log,
		}
	})
	return c.dialer
}

// readAuthorizedKeys connects through sshconn.Dialer and reads the server's
// authorized_keys — srv.AuthorizedKeysFile when set, ~/.ssh/authorized_keys
// otherwise — via a one-shot session. A second short session on the same
// connection runs the posture probe (sshconn.PostureCmdFor), for every read:
// the StrictModes state of the file and its directories, and whether a
// non-empty ~/.ssh/authorized_keys2 sits beside a managed path that is the
// default one or an equivalent spelling of it. A failed or malformed probe
// fails the read (fail-closed: a server cannot look clean by hiding its
// posture). Deadline semantics live
// in Connect: the ctx deadline (or the derived 3×DialTimeout floor) bounds
// the whole exchange, not just the dial; ctx cancellation ends it at once.
func (c *Client) readAuthorizedKeys(ctx context.Context, srv config.Server) (fleet.ReadResult, error) {
	var zero fleet.ReadResult
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

	code, stdout, stderr, err = sshconn.Exec(ctx, conn.Client, sshconn.PostureCmdFor(path), nil)
	if err != nil {
		return zero, fmt.Errorf("posture probe on %s: %w", addr, err)
	}
	posture, present, err := sshconn.FinishPosture(code, stdout, stderr)
	if err != nil {
		return zero, fmt.Errorf("on %s: %w", addr, err)
	}
	res.Posture = posture
	res.AuthorizedKeys2 = present
	if present && c.ReadKeys2 {
		res.Keys2, res.Keys2Err = c.readKeys2(ctx, conn, addr)
	}
	return res, nil
}

// readKeys2 cats ~/.ssh/authorized_keys2 on the open connection, with the
// managed read's size cap and error mapping. Errors are control-stripped
// (they can embed remote text) and never fail the main read.
func (c *Client) readKeys2(ctx context.Context, conn *sshconn.Conn, addr string) ([]byte, error) {
	code, stdout, stderr, err := sshconn.Exec(ctx, conn.Client, sshconn.AuthorizedKeysCmdFor(sshconn.SecondaryAuthorizedKeysPath), nil)
	if err != nil {
		return nil, sshconn.SanitizedError{Err: fmt.Errorf("authorized_keys2 read on %s: %w", addr, err)}
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, addr, c.log())
	if err != nil {
		return nil, sshconn.SanitizedError{Err: err}
	}
	if res.FileAbsent {
		return nil, nil
	}
	return res.Content, nil
}
