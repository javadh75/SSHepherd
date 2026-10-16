package sshconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
)

// Dialer holds the per-fleet connection settings shared by every server
// connection, read and write paths alike. Use it by pointer: it caches the
// known_hosts snapshot after the first Connect.
type Dialer struct {
	KnownHostsPath string
	// KnownHosts is an optional pre-parsed snapshot (typically the
	// preflight's). Nil loads KnownHostsPath once, on first Connect, and
	// reuses that snapshot for every later connection through this Dialer.
	KnownHosts  *KnownHosts
	AgentSock   string
	DialTimeout time.Duration
	// PreferKeys optionally returns the agent-key fingerprints to offer
	// first when connecting to srv — the keys the manifest grants there,
	// operators first (audit.GrantedFingerprints). Remaining agent keys
	// follow in agent order. Without it an agent holding many keys offers
	// them in agent order, and sshd's MaxAuthTries (default 6) can
	// disconnect before the granted key is tried.
	PreferKeys func(srv config.Server) []string
	Log        *slog.Logger // optional stage-level telemetry; nil discards

	khOnce sync.Once
	kh     *KnownHosts
	khErr  error
}

// ConnectOptions tunes one connection's agent-key offering.
type ConnectOptions struct {
	// Prefer lists fingerprints to offer first, in order; nil falls back to
	// Dialer.PreferKeys(srv).
	Prefer []string
	// Only, when non-empty, offers exactly the agent keys with these
	// fingerprints (in this order) and nothing else — the IdentitiesOnly
	// posture. A login that succeeds therefore proves the server accepts
	// one of them (apply's post-write login probe); none held by the agent
	// is an auth failure, never a fallback to other keys.
	Only []string
}

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (d *Dialer) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.New(slog.DiscardHandler)
}

// knownHosts returns the run's single known_hosts snapshot.
func (d *Dialer) knownHosts() (*KnownHosts, error) {
	d.khOnce.Do(func() {
		if d.KnownHosts != nil {
			d.kh = d.KnownHosts
			return
		}
		d.kh, d.khErr = LoadKnownHosts(d.KnownHostsPath)
	})
	return d.kh, d.khErr
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

// Connect is ConnectWith with default options (Dialer.PreferKeys ordering).
func (d *Dialer) Connect(ctx context.Context, srv config.Server) (*Conn, error) {
	return d.ConnectWith(ctx, srv, ConnectOptions{})
}

// ConnectWith dials srv and completes an agent-authenticated handshake
// under strict known_hosts verification (agent-only auth, no TOFU), with
// host-key algorithms ordered from what known_hosts records for srv. The
// ctx deadline bounds agent I/O, dial, and handshake, and is installed as
// the socket deadline, so it keeps bounding whatever sessions the caller
// runs on the returned connection; ctx cancellation aborts the handshake.
// Callers without a ctx deadline get a hard floor: 3×DialTimeout (30s when
// DialTimeout is zero). The agent connection lives only until ConnectWith
// returns — signing happens during auth, never after. Every error is an
// *Error carrying its audit.ErrorKind.
func (d *Dialer) ConnectWith(ctx context.Context, srv config.Server, opts ConnectOptions) (*Conn, error) {
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
		return nil, classify(audit.ErrorKindAgent, fmt.Errorf("connect ssh-agent: %w", err))
	}
	defer func() { _ = agentConn.Close() }() // errcheck: auth is complete (or failed) by return; close error uninteresting
	_ = agentConn.SetDeadline(dl)            // ag.Signers does I/O mid-handshake; a wedged agent must not hang a worker
	ag := agent.NewClient(agentConn)

	kh, err := d.knownHosts()
	if err != nil {
		return nil, classify(audit.ErrorKindHostKey, err)
	}
	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))

	// Wrap the strict callback so verification failures carry the key the
	// server actually presented — hostKeyHint needs it to tell a changed key
	// apart from an unrecorded key type. The verdict is also captured here:
	// x/crypto may not keep it in the chain NewClientConn returns.
	var (
		hkMu  sync.Mutex
		hkErr error
	)
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if khErr := kh.callback(hostname, remote, key); khErr != nil {
			err := hostKeyHint(khErr, key, srv, kh.Path)
			hkMu.Lock()
			hkErr = err
			hkMu.Unlock()
			return err
		}
		log.Debug("host key verified", "server", srv.Name)
		return nil
	}

	prefer, only := opts.Prefer, opts.Only
	if prefer == nil && d.PreferKeys != nil {
		prefer = d.PreferKeys(srv)
	}
	rec := &sessionKey{}
	auth := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
		signers, err := ag.Signers()
		if err != nil {
			return nil, fmt.Errorf("agent signers: %w", err)
		}
		return wrapSigners(orderSigners(signers, prefer, only), rec), nil
	})

	dialer := net.Dialer{Timeout: d.DialTimeout}
	log.Debug("dialing", "server", srv.Name, "addr", addr)
	dialStart := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		kind := audit.ErrorKindDial
		if ctx.Err() != nil {
			kind = ctxKind(ctx)
		}
		return nil, classify(kind, fmt.Errorf(
			"dial %s: %w\n  hint: check the host, port, and firewall; hosts reachable only through a bastion (ProxyJump/ProxyCommand) are dialed directly — jump hosts are not supported yet",
			addr, err))
	}
	log.Debug("dial ok", "server", srv.Name, "addr", addr,
		"dur", time.Since(dialStart).Round(time.Millisecond))
	_ = conn.SetDeadline(dl) // bounds handshake + all later session I/O, not just dial
	// Cancellation (Ctrl-C) must abort a handshake in flight, not wait for
	// the deadline: closing the socket unblocks every read.
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              srv.User,
		Auth:              []ssh.AuthMethod{auth},
		HostKeyCallback:   cb,
		HostKeyAlgorithms: kh.HostKeyAlgorithms(addr),
	})
	if err != nil {
		_ = conn.Close()
		hkMu.Lock()
		verdict := hkErr
		hkMu.Unlock()
		if verdict != nil {
			return nil, fmt.Errorf("ssh %s@%s: %w", srv.User, addr, verdict)
		}
		return nil, classify(handshakeKind(ctx, err), fmt.Errorf("ssh %s@%s: %w", srv.User, addr, err))
	}
	if !stopCancel() {
		// ctx ended exactly as the handshake completed: the socket is closed.
		_ = sshConn.Close()
		return nil, classify(ctxKind(ctx), fmt.Errorf("ssh %s@%s: %w", srv.User, addr, ctx.Err()))
	}
	log.Debug("auth ok", "server", srv.Name, "user", srv.User)
	return &Conn{Client: ssh.NewClient(sshConn, chans, reqs), session: rec}, nil
}

// orderSigners applies the per-connection key offering: with only set,
// exactly those keys in that order; otherwise prefer's keys first (in
// prefer order), then every other agent key in agent order. Fingerprints the
// agent does not hold are skipped.
func orderSigners(signers []ssh.Signer, prefer, only []string) []ssh.Signer {
	byFP := make(map[string]ssh.Signer, len(signers))
	for _, s := range signers {
		byFP[ssh.FingerprintSHA256(s.PublicKey())] = s
	}
	pick := func(fps []string) []ssh.Signer {
		var out []ssh.Signer
		var seen []string
		for _, fp := range fps {
			if s, ok := byFP[fp]; ok && !slices.Contains(seen, fp) {
				out = append(out, s)
				seen = append(seen, fp)
			}
		}
		return out
	}
	if len(only) > 0 {
		return pick(only)
	}
	out := pick(prefer)
	for _, s := range signers {
		if !slices.Contains(prefer, ssh.FingerprintSHA256(s.PublicKey())) {
			out = append(out, s)
		}
	}
	return out
}

// remoteCommand wraps a POSIX-sh script so it runs under /bin/sh whatever
// the account's login shell is: sshd hands the command string to
// "$SHELL -c", and fish or csh/tcsh would misparse the scripts' POSIX
// syntax (${HOME:?}, set -C, redirections). The script becomes one quoted
// word that every common login shell (sh, bash, zsh, fish, csh, tcsh)
// parses identically: single quotes everywhere, with ' and \ emitted
// outside them as \' and \\ — fish treats a backslash inside single quotes
// as an escape, so none may appear there. Scripts must be single-line
// (csh rejects newlines inside quotes); Exec enforces it.
func remoteCommand(script string) string {
	var b strings.Builder
	b.WriteString("exec /bin/sh -c '")
	for _, r := range script {
		switch r {
		case '\'':
			b.WriteString(`'\''`)
		case '\\':
			b.WriteString(`'\\'`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString("'")
	return b.String()
}

// Exec runs the single-line POSIX-sh script in one session over client
// (as exec /bin/sh -c, see remoteCommand), optionally feeding stdin, and
// returns the remote exit code with capped stdout/stderr. A nonzero exit is
// data, not an error — sentinel exits (44 file-absent, sshwrite's 45
// symlink) are protocol semantics only the caller can interpret. err is
// non-nil only for transport-level failures (session open, channel I/O) or
// ctx ending the run: cancellation closes the session at once, so a caller
// that must let a started command finish passes context.WithoutCancel.
func Exec(ctx context.Context, client *ssh.Client, script string, stdin io.Reader) (code int, stdout, stderr *CappedBuffer, err error) {
	if strings.ContainsAny(script, "\n\r") {
		return 0, nil, nil, classify(audit.ErrorKindRemote, errors.New("remote script must be a single line"))
	}
	if ctx.Err() != nil {
		return 0, nil, nil, classify(ctxKind(ctx), fmt.Errorf("run remote command: %w", ctx.Err()))
	}
	sess, err := client.NewSession()
	if err != nil {
		return 0, nil, nil, classify(audit.ErrorKindRemote, fmt.Errorf("open session: %w", err))
	}
	defer func() { _ = sess.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = sess.Close() })
	defer stop()

	stdout = NewCappedBuffer(MaxRemoteOutput)
	stderr = NewCappedBuffer(MaxRemoteOutput)
	sess.Stdin = stdin
	sess.Stdout = stdout
	sess.Stderr = stderr

	if runErr := sess.Run(remoteCommand(script)); runErr != nil {
		if ctx.Err() != nil {
			return 0, nil, nil, classify(ctxKind(ctx), fmt.Errorf("run remote command: %w", ctx.Err()))
		}
		var exitErr *ssh.ExitError
		if !errors.As(runErr, &exitErr) {
			return 0, nil, nil, classify(audit.ErrorKindRemote, fmt.Errorf("run remote command: %w", runErr))
		}
		code = exitErr.ExitStatus()
	}
	return code, stdout, stderr, nil
}
