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
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// ErrorKind implements fleet.KindedError.
func (e *Error) ErrorKind() fleet.ErrorKind { return e.Kind }

// ErrorHint implements fleet.Hinted: reports print it on its own line,
// once per distinct hint, and JSON carries it as a separate `hint` field.
func (e *Error) ErrorHint() string { return e.Hint }

var (
	_ fleet.KindedError = (*Error)(nil)
	_ fleet.Hinted      = (*Error)(nil)
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

// handshakeKind classifies an ssh.NewClientConn failure that was not a
// host-key verdict (those are captured from the callback directly). The
// auth case has no typed error in x/crypto, so its fixed message prefix is
// the only signal.
func handshakeKind(ctx context.Context, err error) fleet.ErrorKind {
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
	if strings.Contains(err.Error(), "unable to authenticate") {
		return fleet.ErrorKindAuth
	}
	return fleet.ErrorKindHandshake
}

// ctxKind classifies a ctx that ended an exchange.
func ctxKind(ctx context.Context) fleet.ErrorKind {
	if errors.Is(ctx.Err(), context.Canceled) {
		return fleet.ErrorKindCanceled
	}
	return fleet.ErrorKindTimeout
}
