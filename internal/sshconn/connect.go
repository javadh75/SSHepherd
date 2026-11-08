package sshconn

import (
	"cmp"
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

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sanitize"
)

// Dialer holds the per-fleet connection settings shared by every server
// connection, read and write paths alike. Use it by pointer: it caches the
// known_hosts snapshot after the first Connect.
type Dialer struct {
	KnownHostsPath string
	// KnownHosts is an optional pre-parsed snapshot (typically the
	// preflight's). Nil loads KnownHostsPath once, on first Connect, and
	// reuses that snapshot for every later connection through this Dialer.
	KnownHosts *KnownHosts
	// Creds is the run's credential source (key files + agent), shared
	// with every other Dialer and the read client of the run. Nil offers
	// nothing: every connect fails with ErrorKindAgent.
	Creds       *Credentials
	DialTimeout time.Duration
	// PreferKeys optionally returns the keys the manifest grants on srv
	// (audit.GrantedFingerprints), in offer order. Only those of the held
	// keys are offered, so a server never learns a key it was not granted
	// (D17); when the run holds none of them, every held key is offered
	// with a warning. Without it, nothing is granted: the fallback applies.
	PreferKeys func(srv config.Server) []string
	// OfferAll is --offer-all-keys: offer the granted keys first, then every
	// other held key, with no restriction.
	OfferAll bool
	// QuietFallback drops the per-server fallback warning to debug level,
	// after a preflight that already warned once for the whole run.
	QuietFallback bool
	Log           *slog.Logger // optional stage-level telemetry; nil discards

	khOnce sync.Once
	kh     *KnownHosts
	khErr  error
}

// ConnectOptions tunes one connection's key offering.
type ConnectOptions struct {
	// Prefer lists the granted fingerprints, in offer order; nil falls back
	// to Dialer.PreferKeys(srv).
	Prefer []string
	// Only, when non-empty, offers exactly the held keys (key files or
	// agent) with these fingerprints (in this order) and nothing else — the
	// IdentitiesOnly posture. A login that succeeds therefore proves the
	// server accepts one of them (apply's post-write login probe). Holding
	// none of them is an ErrorKindAgent error before any dial, never a
	// fallback to other keys, and a login refused with some of them not
	// offered is ErrorKindAgent too: an incomplete offer proves nothing
	// about the keys it left out.
	Only []string
	// RequireOffer refuses to dial with no key to offer: that is an
	// ErrorKindAgent error before any connection. Only the reconnect after a
	// dropped write sets it, where a handshake with nothing to offer would
	// otherwise fail as auth and read as "this server refused you".
	RequireOffer bool
	// SessionTimeout, when positive, replaces the dial deadline as the
	// socket deadline once the handshake finishes: now + SessionTimeout.
	// Without it a handshake that finished late in the dial bound would
	// leave the caller's sessions almost no time.
	SessionTimeout time.Duration
}

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (d *Dialer) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.New(slog.DiscardHandler)
}

// credentials returns Creds, or an empty source (no key files, no agent)
// when none is set.
func (d *Dialer) credentials() *Credentials {
	if d.Creds != nil {
		return d.Creds
	}
	return &Credentials{Log: d.Log}
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

// SessionKeyFP returns the SHA256 fingerprint of the key (file or agent)
// whose signature completed this connection's handshake — the key this session
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

// ConnectWith dials srv and completes a public-key handshake under strict
// known_hosts verification (no TOFU), offering the Credentials' signers
// (key files, then agent), with host-key algorithms ordered from what
// known_hosts records for srv. The signers are fetched BEFORE the TCP dial,
// so an agent problem fails (or, with key files, degrades) without touching
// the server. The ctx deadline bounds agent I/O, dial, and handshake, and
// is installed as the socket deadline, so it keeps bounding whatever
// sessions the caller runs on the returned connection unless
// ConnectOptions.SessionTimeout replaces it after the handshake; ctx
// cancellation aborts the handshake. Callers without a ctx deadline get a hard floor:
// 3×DialTimeout (30s when DialTimeout is zero). The agent connection lives
// only until ConnectWith returns — signing happens during auth, never
// after. Every error is an *Error carrying its fleet.ErrorKind.
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

	signers, release, err := d.credentials().Signers(ctx)
	if err != nil {
		return nil, err // already classified (ErrorKindAgent)
	}
	defer release() // agent signers sign mid-handshake; release once auth is over

	kh, err := d.knownHosts()
	if err != nil {
		return nil, classify(fleet.ErrorKindHostKey, err)
	}
	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))

	// Wrap the strict callback so verification failures carry the key the
	// server actually presented — hostKeyHint needs it to tell a changed key
	// apart from an unrecorded key type. The verdict is also captured here:
	// x/crypto may not keep it in the chain NewClientConn returns.
	hk := &hostKeyState{}
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		err := kh.callback(hostname, remote, key)
		if err != nil {
			err = hostKeyHint(err, key, srv, kh)
		} else {
			log.Debug("host key verified", "server", srv.Name)
		}
		hk.record(err)
		return err
	}

	offer := d.offerFor(srv, signers, opts)
	if err := emptyOffer(opts, offer.signers); err != nil {
		return nil, err
	}
	missing := notOffered(opts.Only, offer.signers)
	rec := &sessionKey{}
	offered := wrapSigners(offer.signers, rec)
	auth := ssh.PublicKeysCallback(func() ([]ssh.Signer, error) { return offered, nil })

	dialer := net.Dialer{Timeout: d.DialTimeout}
	log.Debug("dialing", "server", srv.Name, "addr", addr)
	dialStart := time.Now()
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, dialFailure(ctx, addr, err)
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
		return nil, dialFacts{user: srv.User, addr: addr, hk: hk, rec: rec, asked: len(opts.Only), missing: missing, offer: offer}.failure(ctx, err)
	}
	if !stopCancel() {
		// ctx ended exactly as the handshake completed: the socket is closed.
		_ = sshConn.Close()
		return nil, classify(ctxKind(ctx), fmt.Errorf("ssh %s@%s: %w", srv.User, addr, ctx.Err()))
	}
	if opts.SessionTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(opts.SessionTimeout))
	}
	log.Debug("auth ok", "server", srv.Name, "user", srv.User)
	return &Conn{Client: ssh.NewClient(sshConn, chans, reqs), session: rec}, nil
}

// hostKeyState is what the host-key callback saw during one dial: its
// failing verdict (kept here because x/crypto may not keep it in the chain
// NewClientConn returns), or that the key verified.
type hostKeyState struct {
	mu       sync.Mutex
	verdict  error
	verified bool
}

func (h *hostKeyState) record(err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.verdict, h.verified = err, err == nil
}

func (h *hostKeyState) get() (verified bool, verdict error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.verified, h.verdict
}

// dialFacts is what one dial knows when its handshake fails.
type dialFacts struct {
	user, addr string
	hk         *hostKeyState
	rec        *sessionKey
	asked      int // len(ConnectOptions.Only)
	missing    int // how many of those fingerprints were not offered
	offer      offering
}

// failure classifies a failed ssh.NewClientConn. An incomplete Only offer
// never reports auth or the MaxAuthTries signal: a rollback needs every held
// survivor actually tried, so it is an agent failure naming what was not
// offered. A signer that failed during auth is an agent failure too.
func (f dialFacts) failure(ctx context.Context, err error) error {
	verified, verdict := f.hk.get()
	if verdict != nil {
		return fmt.Errorf("ssh %s@%s: %w", f.user, f.addr, verdict)
	}
	wrapped := fmt.Errorf("ssh %s@%s: %w", f.user, f.addr, remoteText{err})
	kind := handshakeKind(ctx, err, verified)
	exhausted := kind == fleet.ErrorKindHandshake && authExhausted(err, verified)
	switch {
	case f.missing > 0 && (kind == fleet.ErrorKindAuth || exhausted):
		return classify(fleet.ErrorKindAgent, fmt.Errorf("%w; %d of the %d surviving keys not offered (agent locked, or keys removed since the plan)", wrapped, f.missing, f.asked))
	case kind == fleet.ErrorKindHandshake && f.rec.signFailed():
		return classify(fleet.ErrorKindAgent, wrapped)
	}
	return &Error{Kind: kind, Err: wrapped, Hint: f.offer.authHint(kind), AuthExhausted: exhausted}
}

// remoteText bounds server-controlled transport text (disconnect reasons,
// version and kex failures, sent before the host key is verified, and the
// message of a rejected session channel, sent after it) for error
// lines via sanitize.RemoteSnippet (SEC-8); Unwrap keeps errors.Is/As and
// the kind classification on the original error.
type remoteText struct{ err error }

func (e remoteText) Error() string { return sanitize.RemoteSnippet(e.err.Error()) }
func (e remoteText) Unwrap() error { return e.err }

// DialHint is the operator remediation for a TCP connect that failed. It is
// carried in Error.Hint, never in the message, so reports print it once per
// run and JSON keeps it in a separate `hint` field.
const DialHint = "check the host, port, and firewall; hosts reachable only through a bastion (ProxyJump/ProxyCommand) are dialed directly — jump hosts are not supported yet"

// dialFailure classifies a TCP connect that failed.
func dialFailure(ctx context.Context, addr string, err error) error {
	kind, hint := fleet.ErrorKindDial, DialHint
	if ctx.Err() != nil {
		kind = ctxKind(ctx)
		if kind == fleet.ErrorKindCanceled {
			hint = "" // the operator interrupted; there is nothing to fix
		}
	}
	return classifyHint(kind, hint, dialErr(addr, err))
}

// dialErr names addr only when the net error does not already: a refused or
// timed-out dial reads "dial tcp 10.0.0.1:22: connect: connection refused",
// while a DNS failure names the host but not the port.
func dialErr(addr string, err error) error {
	if strings.Contains(err.Error(), addr) {
		return err
	}
	return fmt.Errorf("dial %s: %w", addr, err)
}

// offering is one connection's key offer.
type offering struct {
	signers  []ssh.Signer
	withheld int  // held keys the restricted offer left out
	fellBack bool // no granted key is held, so every held key is offered
}

// offerFor resolves the keys this connection offers and logs a fallback.
func (d *Dialer) offerFor(srv config.Server, signers []ssh.Signer, opts ConnectOptions) offering {
	prefer := opts.Prefer
	if prefer == nil && d.PreferKeys != nil {
		prefer = d.PreferKeys(srv)
	}
	offer := orderSigners(signers, prefer, opts.Only, d.OfferAll)
	if offer.fellBack {
		msg := fmt.Sprintf("%s: none of the keys granted here are loaded; offering all %s", srv.Name, heldKeys(len(signers)))
		if d.QuietFallback {
			d.log().Debug(msg)
		} else {
			d.log().Warn(msg)
		}
	}
	return offer
}

// authHint is the remediation for a server that refused the granted keys
// while other held keys were withheld. The offer is never widened by
// itself: a retry would hand every held key to any server that refuses the
// granted ones, which is what the restricted offer prevents.
func (o offering) authHint(kind fleet.ErrorKind) string {
	if kind != fleet.ErrorKindAuth || o.withheld == 0 {
		return ""
	}
	keys := fmt.Sprintf("%d other loaded key was", o.withheld)
	if o.withheld > 1 {
		keys = fmt.Sprintf("%d other loaded keys were", o.withheld)
	}
	return "none of the keys the manifest grants here were accepted; " + keys +
		" not offered — if one of them still logs in here, re-run with --offer-all-keys (this server then sees every loaded key)"
}

func heldKeys(n int) string {
	if n == 1 {
		return "1 held key"
	}
	return fmt.Sprintf("%d held keys", n)
}

// GrantIndex is the offering's one matcher: pub's position in granted, or
// -1 when it is not granted. A certificate's fingerprint is not its key's,
// so a certificate matches through its key or through its CA (a manifest
// cert-authority line grants the signer).
func GrantIndex(pub ssh.PublicKey, granted []string) int {
	fps := []string{ssh.FingerprintSHA256(pub)}
	if cert, ok := pub.(*ssh.Certificate); ok {
		fps = append(fps, ssh.FingerprintSHA256(cert.Key), ssh.FingerprintSHA256(cert.SignatureKey))
	}
	best := -1
	for _, fp := range fps {
		if i := slices.Index(granted, fp); i >= 0 && (best < 0 || i < best) {
			best = i
		}
	}
	return best
}

// orderSigners applies the per-connection key offering. With only set:
// exactly those keys, in that order, and never a fallback (the login probe's
// IdentitiesOnly posture). Otherwise the held keys matching prefer, in
// prefer order, and nothing else; when none matches, every held key in
// Signers order (key files before agent keys) with fellBack set. offerAll
// restores the unrestricted offer: granted first, then every other key.
func orderSigners(signers []ssh.Signer, prefer, only []string, offerAll bool) offering {
	if len(only) > 0 {
		return offering{signers: pickExact(signers, only)}
	}
	var granted, rest []ssh.Signer
	for _, s := range signers {
		if GrantIndex(s.PublicKey(), prefer) >= 0 {
			granted = append(granted, s)
		} else {
			rest = append(rest, s)
		}
	}
	slices.SortStableFunc(granted, func(a, b ssh.Signer) int {
		return cmp.Compare(GrantIndex(a.PublicKey(), prefer), GrantIndex(b.PublicKey(), prefer))
	})
	switch {
	case offerAll:
		return offering{signers: append(granted, rest...)}
	case len(granted) == 0:
		return offering{signers: signers, fellBack: len(signers) > 0}
	default:
		return offering{signers: granted, withheld: len(rest)}
	}
}

// pickExact returns the held keys with exactly these fingerprints, in this
// order, each once.
func pickExact(signers []ssh.Signer, fps []string) []ssh.Signer {
	byFP := make(map[string]ssh.Signer, len(signers))
	for _, s := range signers {
		byFP[ssh.FingerprintSHA256(s.PublicKey())] = s
	}
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

// notOffered counts the distinct fingerprints in only that ordered does not
// hold.
func notOffered(only []string, ordered []ssh.Signer) int {
	held := make(map[string]bool, len(ordered))
	for _, s := range ordered {
		held[ssh.FingerprintSHA256(s.PublicKey())] = true
	}
	missing := make(map[string]bool)
	for _, fp := range only {
		if !held[fp] {
			missing[fp] = true
		}
	}
	return len(missing)
}

// emptyOffer reports a dial that has no key to offer although its caller
// needs one. An empty offer proves nothing about the server, so it is an
// agent failure before any connection, not an auth verdict.
func emptyOffer(opts ConnectOptions, ordered []ssh.Signer) error {
	switch {
	case len(ordered) > 0:
		return nil
	case len(opts.Only) > 0:
		return classify(fleet.ErrorKindAgent, fmt.Errorf("none of the %d surviving keys is offered (agent locked, or keys removed since the plan)", len(opts.Only)))
	case opts.RequireOffer:
		return classify(fleet.ErrorKindAgent, errors.New("no key to offer (agent locked, or keys removed since the plan)"))
	}
	return nil
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

// ErrSessionNotOpened marks an Exec whose SSH session never opened, so the
// script cannot have started. Its text is the failure message's prefix.
var ErrSessionNotOpened = errors.New("open session")

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
		return 0, nil, nil, classify(fleet.ErrorKindRemote, errors.New("remote script must be a single line"))
	}
	if ctx.Err() != nil {
		return 0, nil, nil, classify(ctxKind(ctx), fmt.Errorf("run remote command: %w", ctx.Err()))
	}
	sess, err := client.NewSession()
	if err != nil {
		// A rejected channel (*ssh.OpenChannelError) carries the server's
		// free-text message: bounded like stderr (SEC-8).
		return 0, nil, nil, classify(fleet.ErrorKindRemote, fmt.Errorf("%w: %w", ErrSessionNotOpened, remoteText{err}))
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
			return 0, nil, nil, classify(fleet.ErrorKindRemote, fmt.Errorf("run remote command: %w", runErr))
		}
		code = exitErr.ExitStatus()
	}
	return code, stdout, stderr, nil
}
