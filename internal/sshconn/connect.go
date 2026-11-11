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
	// Server resolves a via: name to its server entry (config.Config's
	// ServerNamed). A server with via: on a Dialer without it fails closed:
	// the connect returns an error and never dials the host directly. The
	// CLI always sets it.
	Server func(name string) (config.Server, bool)
	Log    *slog.Logger // optional stage-level telemetry; nil discards

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
	// hop is the bastion connection this one is tunnelled through (via:);
	// nil for a direct connection. Close closes it after the target.
	hop *Conn
	// raw is the transport under Client: the TCP socket, or for a tunnelled
	// connection the direct-tcpip channel, whose SetDeadline does nothing;
	// setDeadline moves the hop's socket along with it.
	raw net.Conn
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

// Close closes the connection and then, always, its hop, even when Client
// is nil. A bare Conn (a test fake) closes to nil.
func (c *Conn) Close() error {
	var err error
	if c.Client != nil {
		if cerr := c.Client.Close(); cerr != nil {
			err = fmt.Errorf("close ssh connection: %w", cerr)
		}
	}
	c.hop.closeQuiet()
	return err
}

// closeQuiet closes c when it is not nil and drops the error: a hop is the
// tunnel's carrier, and its close error is never the caller's concern.
func (c *Conn) closeQuiet() {
	if c != nil {
		_ = c.Close()
	}
}

// setDeadline moves the socket deadline of c and of every hop under it.
func (c *Conn) setDeadline(t time.Time) {
	if c.raw != nil {
		_ = c.raw.SetDeadline(t)
	}
	if c.hop != nil {
		c.hop.setDeadline(t)
	}
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
// after. Every error is an *Error carrying its fleet.ErrorKind. A via
// server is reached through a fresh connection to its bastion (dialTarget):
// the hop gets the same ctx, offers keys as any connection to that bastion
// would, and is closed with the target and on every failure.
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
			err = hostKeyHint(err, key, srv, d.Route(srv), kh)
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

	log.Debug("dialing", "server", srv.Name, "addr", addr, "via", srv.Via)
	dialStart := time.Now()
	conn, hop, err := d.dialTarget(ctx, srv, addr)
	if err != nil {
		return nil, err
	}
	log.Debug("dial ok", "server", srv.Name, "addr", addr,
		"dur", time.Since(dialStart).Round(time.Millisecond))
	_ = conn.SetDeadline(dl) // bounds handshake + all later session I/O; a no-op on a tunnel, whose hop socket carries dl
	// Cancellation (Ctrl-C) must abort a handshake in flight, not wait for
	// the deadline: closing the socket unblocks every read. Closing a tunnel
	// only sends a close and waits for the peer's reply, so the hop is
	// closed too (spec S5, fact 4).
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close(); hop.closeQuiet() })
	defer stopCancel()

	banner := &bannerWatch{Conn: conn} // a drop before the banner gets PenaltyHint (G016)
	sshConn, chans, reqs, err := ssh.NewClientConn(banner, addr, &ssh.ClientConfig{
		User:              srv.User,
		Auth:              []ssh.AuthMethod{auth},
		HostKeyCallback:   cb,
		HostKeyAlgorithms: kh.HostKeyAlgorithms(addr),
	})
	if err != nil {
		_ = conn.Close()
		hop.closeQuiet()
		return nil, dialFacts{user: srv.User, addr: addr, hk: hk, rec: rec, asked: len(opts.Only), missing: missing, offer: offer, banner: banner}.failure(ctx, err)
	}
	if !stopCancel() {
		// ctx ended exactly as the handshake completed: the socket is closed.
		_ = sshConn.Close()
		hop.closeQuiet()
		return nil, classify(ctxKind(ctx), fmt.Errorf("ssh %s@%s: %w", srv.User, addr, ctx.Err()))
	}
	c := &Conn{Client: ssh.NewClient(sshConn, chans, reqs), session: rec, hop: hop, raw: conn}
	if opts.SessionTimeout > 0 {
		c.setDeadline(time.Now().Add(opts.SessionTimeout))
	}
	log.Debug("auth ok", "server", srv.Name, "user", srv.User)
	return c, nil
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
	banner     *bannerWatch // whether the server's banner arrived; nil: unknown
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
	case kind == fleet.ErrorKindHandshake && droppedBeforeBanner(err, f.banner):
		return &Error{Kind: kind, Err: wrapped, Hint: PenaltyHint}
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
const DialHint = "check the host, port, and firewall; a host reachable only through a bastion needs via: in the manifest"

// ForwardHint is the remediation when a bastion refused to open the
// direct-tcpip channel (sshd's AllowTcpForwarding no, or a no-port-forwarding,
// restrict or permitopen= key line).
const ForwardHint = "the bastion refused the forward; allow TCP forwarding for this account"

// HopDialHint is the remediation when the bastion opened the channel but
// could not reach the server behind it: the server's own failure, so it
// carries no HopStage, and DialHint's "needs via:" advice would be wrong for
// a server that already has one.
const HopDialHint = "the bastion could not reach this server; check that it is up and reachable from the bastion"

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

// dialTarget opens srv's transport: a TCP dial, or for a via server a
// direct-tcpip channel through a fresh connection to its bastion (one hop
// connection per target, never pooled: the hop's socket carries this
// target's deadline). hop is nil for a direct dial. A via the Dialer cannot
// resolve fails closed: srv is never dialed directly.
func (d *Dialer) dialTarget(ctx context.Context, srv config.Server, addr string) (net.Conn, *Conn, error) {
	if srv.Via == "" {
		dialer := net.Dialer{Timeout: d.DialTimeout}
		conn, err := dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, nil, dialFailure(ctx, addr, err)
		}
		return conn, nil, nil
	}
	hopSrv, ok := d.lookup(srv.Via)
	if !ok {
		return nil, nil, classify(fleet.ErrorKindDial, fmt.Errorf("%s: via %q is not a server this run knows — refusing to dial %s directly", srv.Name, srv.Via, addr))
	}
	hop, err := d.ConnectWith(ctx, hopSrv, ConnectOptions{}) // never Only or Prefer: the hop offers as any connection to it does
	if err != nil {
		return nil, nil, viaFailure(hopSrv.Name, err)
	}
	conn, err := hop.Client.DialContext(ctx, "tcp", addr)
	if err != nil {
		_ = hop.Close()
		return nil, nil, forwardFailure(ctx, hopSrv.Name, addr, err)
	}
	return conn, hop, nil
}

// lookup resolves a via name through Dialer.Server; false without one.
func (d *Dialer) lookup(name string) (config.Server, bool) {
	if d.Server == nil {
		return config.Server{}, false
	}
	return d.Server(name)
}

// Route lists the bastions srv is reached through, root first, as far as
// the Dialer resolves them; nil for a direct server.
func (d *Dialer) Route(srv config.Server) []config.Server {
	var out []config.Server
	for v := srv.Via; v != "" && len(out) <= config.MaxViaDepth; {
		hop, ok := d.lookup(v)
		if !ok {
			break
		}
		out = append(out, hop)
		v = hop.Via
	}
	slices.Reverse(out)
	return out
}

// viaFailure is a dependent's error when its bastion could not be reached:
// the hop's kind and hint, "via NAME: " before the hop's own text, and the
// failing bastion as HopStage — the innermost one of a longer chain. The
// MaxAuthTries signal is not carried: it is the bastion's, not the
// server's.
func viaFailure(hop string, err error) error {
	stage := hop
	var e *Error
	if errors.As(err, &e) && e.HopStage != "" {
		stage = e.HopStage
	}
	return &Error{Kind: fleet.ErrorKindOf(err), Err: fmt.Errorf("via %s: %w", hop, err), Hint: fleet.HintOf(err), HopStage: stage}
}

// forwardFailure classifies a direct-tcpip channel the bastion did not open.
// Prohibited (AllowTcpForwarding no, no-port-forwarding, restrict,
// permitopen=) is the bastion's doing: kind dial, ForwardHint, HopStage
// set. Any other rejection means the bastion could not reach the server:
// the server's own dial failure, with HopDialHint (DialHint's "needs via:"
// would be wrong advice here). Server text is bounded (remoteText). A
// failure once ctx's deadline has passed is a timeout even before ctx.Err
// is set, as in handshakeKind: the hop's socket carries the same deadline,
// and its read timeout can fail the pending open first (F012).
func forwardFailure(ctx context.Context, hop, addr string, err error) error {
	if ctx.Err() != nil || pastDeadline(ctx) {
		cause := ctx.Err()
		if cause == nil {
			cause = context.DeadlineExceeded
		}
		return classify(ctxKind(ctx), fmt.Errorf("via %s: open %s: %w", hop, addr, cause))
	}
	var oce *ssh.OpenChannelError
	if errors.As(err, &oce) && oce.Reason == ssh.Prohibited {
		return &Error{Kind: fleet.ErrorKindDial, Hint: ForwardHint, HopStage: hop,
			Err: fmt.Errorf("via %s: forward to %s refused: %w", hop, addr, remoteText{err})}
	}
	return classifyHint(fleet.ErrorKindDial, HopDialHint, fmt.Errorf("via %s: %w", hop, dialErr(addr, remoteText{err})))
}

// offering is one connection's key offer.
type offering struct {
	signers  []ssh.Signer
	withheld int  // held keys the restricted offer left out
	fellBack bool // no granted key is held, so every held key is offered
}

// offerFor resolves the keys this connection offers and logs a fallback.
func (d *Dialer) offerFor(srv config.Server, signers []ssh.Signer, opts ConnectOptions) offering {
	if srv.JumpOnly && len(opts.Only) == 0 {
		// A jump_only bastion has no grants to filter by (spec S5): every
		// held key, in Signers order, with no fallback warning.
		return offering{signers: signers}
	}
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

// SessionOpenTimeout bounds how long Exec waits for the server to answer a
// session open when ctx allows longer, or has no deadline at all (a caller
// that passed context.WithoutCancel). Opening a session on an authenticated
// connection is one round trip, cheaper than the TCP connect and key
// exchange the CLI bounds by its 10 s dial timeout, so the same 10 s is a
// generous ceiling for a healthy server (F1 Q4).
const SessionOpenTimeout = 10 * time.Second

// sessionOpenWait is SessionOpenTimeout; tests shorten it.
var sessionOpenWait = SessionOpenTimeout

// openSession opens a session on client, giving up when ctx ends or
// sessionOpenWait elapses. x/crypto's NewSession takes no context and can
// wait forever on a dying connection: the mux drops its channels before the
// transport records its write error, and an open sent in that gap goes
// into the closed socket without error and waits for a reply that never
// comes (TestExecMarksASessionThatNeverOpened). On giving up it closes
// client: on a direct connection that ends a NewSession still waiting; on
// a tunnelled (via:) target the client runs over a direct-tcpip channel,
// so the wait ends when the bastion answers the channel close or when
// Conn.Close closes the hop. In the true race nothing will ever answer the
// open, so its goroutine stays blocked until the process exits: one
// goroutine per stuck open, in a short-lived CLI. A session that opens
// after the wait ended is closed by the goroutine. Either way the exec
// request was never sent, so no script ran: the error wraps
// ErrSessionNotOpened.
func openSession(ctx context.Context, client *ssh.Client) (*ssh.Session, error) {
	type opened struct {
		sess *ssh.Session
		err  error
	}
	result := make(chan opened)
	gaveUp := make(chan struct{})
	go func() {
		sess, err := client.NewSession()
		select {
		case result <- opened{sess, err}:
		case <-gaveUp:
			if sess != nil {
				_ = sess.Close()
			}
		}
	}()
	wait := sessionOpenWait
	timer := time.NewTimer(wait)
	defer timer.Stop()
	var (
		cause error
		kind  = fleet.ErrorKindTimeout
	)
	select {
	case o := <-result:
		if o.err != nil {
			// A rejected channel (*ssh.OpenChannelError) carries the server's
			// free-text message: bounded like stderr (SEC-8).
			return nil, classify(fleet.ErrorKindRemote, fmt.Errorf("%w: %w", ErrSessionNotOpened, remoteText{o.err}))
		}
		return o.sess, nil
	case <-ctx.Done():
		cause, kind = ctx.Err(), ctxKind(ctx)
	case <-timer.C:
		cause = fmt.Errorf("no answer from the server within %s", wait)
	}
	close(gaveUp)
	_ = client.Close() // ends a waiting NewSession (on a tunnel: once the bastion answers, or Conn.Close)
	return nil, classify(kind, fmt.Errorf("%w: %w", ErrSessionNotOpened, cause))
}

// Exec runs the single-line POSIX-sh script in one session over client
// (as exec /bin/sh -c, see remoteCommand), optionally feeding stdin, and
// returns the remote exit code with capped stdout/stderr. A nonzero exit is
// data, not an error — sentinel exits (44 file-absent, sshwrite's 45
// symlink) are protocol semantics only the caller can interpret. err is
// non-nil only for transport-level failures (session open, channel I/O) or
// ctx ending the run: cancellation closes the session at once, so a caller
// that must let a started command finish passes context.WithoutCancel.
// Opening the session is bounded too: by ctx, and by SessionOpenTimeout when
// ctx allows longer (openSession); a session that never opens closes client
// and wraps ErrSessionNotOpened.
func Exec(ctx context.Context, client *ssh.Client, script string, stdin io.Reader) (code int, stdout, stderr *CappedBuffer, err error) {
	if strings.ContainsAny(script, "\n\r") {
		return 0, nil, nil, classify(fleet.ErrorKindRemote, errors.New("remote script must be a single line"))
	}
	if ctx.Err() != nil {
		return 0, nil, nil, classify(ctxKind(ctx), fmt.Errorf("run remote command: %w", ctx.Err()))
	}
	sess, err := openSession(ctx, client)
	if err != nil {
		return 0, nil, nil, err // already classified, marked ErrSessionNotOpened
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
