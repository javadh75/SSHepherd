package sshconn

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
)

// Error is a classified connection or remote-command failure. Kind is the
// audit wire classification, so audit (and apply) tell a changed host key
// from a refused login from a network timeout with errors.As instead of
// matching prose. The message is Err's, unchanged; SanitizedError wrapping
// keeps the chain, so the kind survives sanitization.
type Error struct {
	Kind audit.ErrorKind
	Err  error
	Hint string // operator remediation, never part of Error()
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// ErrorKind implements audit.KindedError.
func (e *Error) ErrorKind() audit.ErrorKind { return e.Kind }

// ErrorHint implements audit.Hinted: reports print it on its own line,
// once per distinct hint, and JSON carries it as a separate `hint` field.
func (e *Error) ErrorHint() string { return e.Hint }

var (
	_ audit.KindedError = (*Error)(nil)
	_ audit.Hinted      = (*Error)(nil)
)

// classify wraps err with kind; nil stays nil.
func classify(kind audit.ErrorKind, err error) error {
	return classifyHint(kind, "", err)
}

// classifyHint is classify with operator remediation kept out of the message.
func classifyHint(kind audit.ErrorKind, hint string, err error) error {
	if err == nil {
		return nil
	}
	return &Error{Kind: kind, Err: err, Hint: hint}
}

// handshakeKind classifies an ssh.NewClientConn failure that was not a
// host-key verdict (those are captured from the callback directly). The
// auth case has no typed error in x/crypto, so its fixed message prefix is
// the only signal.
func handshakeKind(ctx context.Context, err error) audit.ErrorKind {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return audit.ErrorKindCanceled
	case ctx.Err() != nil:
		return audit.ErrorKindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return audit.ErrorKindTimeout
	}
	if strings.Contains(err.Error(), "unable to authenticate") {
		return audit.ErrorKindAuth
	}
	return audit.ErrorKindHandshake
}

// ctxKind classifies a ctx that ended an exchange.
func ctxKind(ctx context.Context) audit.ErrorKind {
	if errors.Is(ctx.Err(), context.Canceled) {
		return audit.ErrorKindCanceled
	}
	return audit.ErrorKindTimeout
}
