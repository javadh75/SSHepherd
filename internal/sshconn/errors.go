package sshconn

import (
	"context"
	"errors"
	"net"
	"strings"

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
// verdict rolls a server back.
func handshakeKind(ctx context.Context, err error, hostVerified bool) fleet.ErrorKind {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fleet.ErrorKindCanceled
	case ctx.Err() != nil:
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

// ctxKind classifies a ctx that ended an exchange.
func ctxKind(ctx context.Context) fleet.ErrorKind {
	if errors.Is(ctx.Err(), context.Canceled) {
		return fleet.ErrorKindCanceled
	}
	return fleet.ErrorKindTimeout
}

// AuthExhausted reports whether err's chain carries the MaxAuthTries signal
// from a server whose host key verified.
func AuthExhausted(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.AuthExhausted
}
