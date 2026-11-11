package sshconn

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/javadh75/SSHepherd/internal/fleet"
)

// Error is a classified connection or remote-command failure. Kind is the
// wire classification (fleet.ErrorKind), so audit (and apply) tell a changed
// host key from a refused login from a network timeout with errors.As instead
// of matching prose. The message is Err's, unchanged; SanitizedError wrapping
// keeps the chain, so the kind survives sanitization.
type Error struct {
	Kind fleet.ErrorKind
	Err  error
	Hint string // operator remediation, never part of Error()
	// AuthExhausted reports that a server whose host key verified
	// disconnected after too many refused keys (MaxAuthTries). The kind
	// stays ErrorKindHandshake, so audit's error_kind does not change;
	// apply's login check reads this flag.
	AuthExhausted bool
	// HopStage names the bastion where the connection failed: any stage of
	// the connect to it (dial, host key, auth, handshake, timeout), or its
	// refusal to forward. Empty when the failure is the server's own, which
	// includes a target the bastion could not reach. Domain code reads it
	// through fleet.FailedHopOf (it may not import this package, ARC-8).
	HopStage string
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// ErrorKind implements fleet.KindedError.
func (e *Error) ErrorKind() fleet.ErrorKind { return e.Kind }

// ErrorHint implements fleet.Hinted: reports print it on its own line,
// once per distinct hint, and JSON carries it as a separate `hint` field.
func (e *Error) ErrorHint() string { return e.Hint }

// FailedHop implements fleet.HopFailure: the JSON reports' via_failed.
func (e *Error) FailedHop() string { return e.HopStage }

var (
	_ fleet.KindedError = (*Error)(nil)
	_ fleet.Hinted      = (*Error)(nil)
	_ fleet.HopFailure  = (*Error)(nil)
)

// classify wraps err with kind; nil stays nil.
func classify(kind fleet.ErrorKind, err error) error {
	return classifyHint(kind, "", err)
}

// classifyHint is classify with operator remediation kept out of the message.
func classifyHint(kind fleet.ErrorKind, hint string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Kind: kind, Err: err, Hint: hint}
}

// tooManyAuthText is the disconnect text sshd sends once it has refused as
// many keys as MaxAuthTries allows.
const tooManyAuthText = "Too many authentication failures"

// handshakeKind classifies an ssh.NewClientConn failure that was not a
// host-key verdict (those are captured from the callback directly). The
// auth case has no typed error in x/crypto, so its fixed message prefix is
// the only signal, and it counts only after the host key verified: a
// disconnect sent before key exchange can carry any text, and an auth
// verdict rolls a server back. A failure once ctx's deadline has passed is
// a timeout even before ctx.Err is set: a via target's handshake runs over
// the hop, whose socket deadline is the same instant, and the hop's read
// timeout can end the tunnel (an EOF) a moment before ctx's timer fires.
func handshakeKind(ctx context.Context, err error, hostVerified bool) fleet.ErrorKind {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fleet.ErrorKindCanceled
	case ctx.Err() != nil, pastDeadline(ctx):
		return fleet.ErrorKindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fleet.ErrorKindTimeout
	}
	if hostVerified && strings.Contains(err.Error(), "unable to authenticate") {
		return fleet.ErrorKindAuth
	}
	return fleet.ErrorKindHandshake
}

// authExhausted reports sshd's MaxAuthTries disconnect from a server whose
// host key verified. x/crypto turns any msgDisconnect into a transport
// error, so the text is the only signal.
func authExhausted(err error, hostVerified bool) bool {
	return hostVerified && strings.Contains(err.Error(), tooManyAuthText)
}

// pastDeadline reports whether ctx's deadline has passed, whether or not
// its timer has fired yet.
func pastDeadline(ctx context.Context) bool {
	dl, ok := ctx.Deadline()
	return ok && !time.Now().Before(dl)
}

// ctxKind classifies a ctx that ended an exchange.
func ctxKind(ctx context.Context) fleet.ErrorKind {
	if errors.Is(ctx.Err(), context.Canceled) {
		return fleet.ErrorKindCanceled
	}
	return fleet.ErrorKindTimeout
}

// PenaltyHint is the remediation for a handshake the server ended before
// its SSH version banner. OpenSSH 9.8+ sshd drops every new connection from
// an address it is penalizing (PerSourcePenalties, on by default) after
// failed logins from it, so a few accounts that fail turn the healthy ones
// on the same host into this bare EOF; MaxStartups and firewalls look the
// same from here.
const PenaltyHint = `the server closed the connection before its SSH banner: sshd's PerSourcePenalties may be refusing this address after failed logins (or MaxStartups, or a firewall); look for "drop connection ... penalty" in the server log, then fix the account whose login fails or add this address to PerSourcePenaltyExemptList`

// bannerWatch is a net.Conn that notes whether the server's SSH version
// banner arrived: a line starting "SSH-" and ended by a newline (RFC 4253
// lets other lines come first). It only watches until it has seen one.
type bannerWatch struct {
	net.Conn
	seen atomic.Bool
	// line state, touched only by Read (one reader at a time): how many
	// bytes of "SSH-" the current line has matched, -1 when it cannot.
	matched int
}

func (b *bannerWatch) Read(p []byte) (int, error) {
	n, err := b.Conn.Read(p)
	if !b.seen.Load() {
		b.scan(p[:n])
	}
	return n, err //nolint:wrapcheck // a transparent conn: x/crypto must see the transport's error verbatim
}

// scan advances the line state over p.
func (b *bannerWatch) scan(p []byte) {
	const prefix = "SSH-"
	for _, c := range p {
		switch {
		case c == '\n':
			if b.matched == len(prefix) {
				b.seen.Store(true)
				return
			}
			b.matched = 0
		case b.matched >= 0 && b.matched < len(prefix):
			if c == prefix[b.matched] {
				b.matched++
			} else {
				b.matched = -1
			}
		}
	}
}

// bannerSeen reports whether the server's banner arrived; true for a nil
// watch (no facts: no hint).
func (b *bannerWatch) bannerSeen() bool { return b == nil || b.seen.Load() }

// droppedBeforeBanner reports a handshake the server ended before it sent
// its banner: the connection closed (EOF) or was reset, with no banner seen.
func droppedBeforeBanner(err error, b *bannerWatch) bool {
	return !b.bannerSeen() &&
		(errors.Is(err, io.EOF) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE))
}

// AuthExhausted reports whether err's chain carries the MaxAuthTries signal
// from a server whose host key verified.
func AuthExhausted(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.AuthExhausted
}
