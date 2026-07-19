package sshconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
)

// Dialer holds the per-fleet connection settings shared by every server
// connection, read and write paths alike.
type Dialer struct {
	KnownHostsPath string
	AgentSock      string
	DialTimeout    time.Duration
	Log            *slog.Logger // optional stage-level telemetry; nil discards
}

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (d *Dialer) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Conn is an authenticated SSH connection to one server.
type Conn struct {
	Client  *ssh.Client
	session *sessionKey
}

// SessionKeyFP returns the SHA256 fingerprint of the agent key whose
// signature completed this connection's handshake — the key this session
// logged in with. Empty when unknown (test fakes, or nothing signed).
func (c *Conn) SessionKeyFP() string {
	if c.session == nil {
		return ""
	}
	return c.session.get()
}

// Close is nil-safe so test fakes can hand out a bare Conn.
func (c *Conn) Close() error {
	if c.Client == nil {
		return nil
	}
	if err := c.Client.Close(); err != nil {
		return fmt.Errorf("close ssh connection: %w", err)
	}
	return nil
}

// Connect dials srv and completes an agent-authenticated handshake under
// strict known_hosts verification (moved verbatim from sshread; the security
// posture — agent-only auth, no TOFU — is unchanged). The ctx deadline
// bounds agent I/O, dial, and handshake, and is installed as the socket
// deadline, so it keeps bounding whatever sessions the caller runs on the
// returned connection. Callers without a ctx deadline get a hard floor:
// 3×DialTimeout (30s when DialTimeout is zero). The agent connection lives
// only until Connect returns — signing happens during auth, never after.
func (d *Dialer) Connect(ctx context.Context, srv config.Server) (*Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		fallback := 3 * d.DialTimeout
		if fallback <= 0 {
			fallback = 30 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fallback)
		defer cancel()
	}
	dl, _ := ctx.Deadline() // always present: the floor above guarantees it
	log := d.log()

	agentDialer := net.Dialer{}
	agentConn, err := agentDialer.DialContext(ctx, "unix", d.AgentSock)
	if err != nil {
		return nil, fmt.Errorf("connect ssh-agent: %w", err)
	}
	defer func() { _ = agentConn.Close() }() // errcheck: auth is complete (or failed) by return; close error uninteresting
	_ = agentConn.SetDeadline(dl)            // ag.Signers does I/O mid-handshake; a wedged agent must not hang a worker
	ag := agent.NewClient(agentConn)

	hostKeys, err := knownhosts.New(d.KnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", d.KnownHostsPath, err)
	}
	// Wrap the strict callback so verification failures carry the key the
	// server actually presented — hostKeyHint needs it to tell a changed key
	// apart from an unrecorded key type.
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if khErr := hostKeys(hostname, remote, key); khErr != nil {
			return hostKeyHint(khErr, key, srv, d.KnownHostsPath)
		}
		log.Debug("host key verified", "server", srv.Name)
		return nil
	}

	rec := &sessionKey{}
	auth := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		signers, err := ag.Signers()
		if err != nil {
			return nil, fmt.Errorf("agent signers: %w", err)
		}
		return wrapSigners(signers, rec), nil
	})

	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	dialer := net.Dialer{Timeout: d.DialTimeout}
	log.Debug("dialing", "server", srv.Name, "addr", addr)
	dialStart := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	log.Debug("dial ok", "server", srv.Name, "addr", addr,
		"dur", time.Since(dialStart).Round(time.Millisecond))
	_ = conn.SetDeadline(dl) // bounds handshake + all later session I/O, not just dial

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            srv.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: cb,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("ssh %s@%s: %w", srv.User, addr, err)
	}
	log.Debug("auth ok", "server", srv.Name, "user", srv.User)
	return &Conn{Client: ssh.NewClient(sshConn, chans, reqs), session: rec}, nil
}

// Exec runs cmd in one session over client, optionally feeding stdin, and
// returns the remote exit code with capped stdout/stderr. A nonzero exit is
// data, not an error — sentinel exits (44 file-absent, sshwrite's 45
// symlink) are protocol semantics only the caller can interpret. err is
// non-nil only for transport-level failures (session open, channel I/O).
func Exec(client *ssh.Client, cmd string, stdin io.Reader) (code int, stdout, stderr *CappedBuffer, err error) {
	sess, err := client.NewSession()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("open session: %w", err)
	}
	defer func() { _ = sess.Close() }()

	stdout = NewCappedBuffer(MaxRemoteOutput)
	stderr = NewCappedBuffer(MaxRemoteOutput)
	sess.Stdin = stdin
	sess.Stdout = stdout
	sess.Stderr = stderr

	if runErr := sess.Run(cmd); runErr != nil {
		var exitErr *ssh.ExitError
		if !errors.As(runErr, &exitErr) {
			return 0, nil, nil, fmt.Errorf("run remote command: %w", runErr)
		}
		code = exitErr.ExitStatus()
	}
	return code, stdout, stderr, nil
}
