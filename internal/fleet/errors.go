package fleet

import (
	"context"
	"errors"
	"net"
)

// ErrorKind classifies why a server could not be reached, read or written.
// The string values are the wire classification (audit and apply JSON): they
// appear verbatim as the JSON reports' error_kind field (additive to schema 1)
// and in the text report's ERROR head.
type ErrorKind string

// The error kinds. Transport-layer readers (sshconn) attach the specific
// kinds; ErrorKindOf derives timeout/canceled/dial from the error chain when
// a reader did not, and falls back to ErrorKindUnknown.
const (
	ErrorKindUnknown ErrorKind = "unknown"
	// ErrorKindHostKeyUnknown: the host has no entry in known_hosts.
	ErrorKindHostKeyUnknown ErrorKind = "host_key_unknown"
	// ErrorKindHostKeyChanged: known_hosts records a key of the presented
	// type for this host and the presented key is a different one — the
	// possible-MITM case. Escalates the audit exit code to 2.
	ErrorKindHostKeyChanged ErrorKind = "host_key_changed"
	// ErrorKindHostKeyTypeUnrecorded: the host is known, but no key of the
	// presented type is recorded — unverified, not proof of a change.
	ErrorKindHostKeyTypeUnrecorded ErrorKind = "host_key_type_unrecorded"
	// ErrorKindHostKeyRevoked: the presented key is marked @revoked in
	// known_hosts. Escalates the audit exit code to 2.
	ErrorKindHostKeyRevoked ErrorKind = "host_key_revoked"
	// ErrorKindHostKey: any other host-key verification failure (e.g. a
	// host certificate no @cert-authority line vouches for).
	ErrorKindHostKey   ErrorKind = "host_key"
	ErrorKindAgent     ErrorKind = "agent"     // the local SSH agent failed
	ErrorKindAuth      ErrorKind = "auth"      // the server refused every offered key
	ErrorKindDial      ErrorKind = "dial"      // TCP connect failed
	ErrorKindTimeout   ErrorKind = "timeout"   // a deadline expired mid-exchange
	ErrorKindCanceled  ErrorKind = "canceled"  // the run was interrupted
	ErrorKindHandshake ErrorKind = "handshake" // SSH protocol negotiation failed
	ErrorKindRemote    ErrorKind = "remote"    // the remote command failed or misbehaved
)

// KindedError is implemented by reader errors that know their own
// classification (sshconn.Error). ErrorKindOf finds it anywhere in the
// error chain, so sanitizing/annotating wrappers keep the kind.
type KindedError interface {
	error
	ErrorKind() ErrorKind
}

// ErrorKindOf classifies err. A KindedError in the chain wins; otherwise
// context and net errors are recognized structurally; anything else is
// ErrorKindUnknown. nil yields "".
func ErrorKindOf(err error) ErrorKind {
	if err == nil {
		return ""
	}
	var ke KindedError
	if errors.As(err, &ke) {
		return ke.ErrorKind()
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return ErrorKindTimeout
	case errors.Is(err, context.Canceled):
		return ErrorKindCanceled
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Timeout() {
			return ErrorKindTimeout
		}
		if opErr.Op == "dial" {
			return ErrorKindDial
		}
	}
	return ErrorKindUnknown
}

// Hinted is implemented by reader errors that carry operator remediation
// separately from the message (sshconn.Error). The hint never appears in
// Error(): reports print it on its own line, once, and JSON carries it as
// `hint`, so `error` stays groupable.
type Hinted interface {
	error
	ErrorHint() string
}

// HintOf returns the hint of the first Hinted in err's chain; "" if none.
func HintOf(err error) string {
	var h Hinted
	if errors.As(err, &h) {
		return h.ErrorHint()
	}
	return ""
}

// HostKeyAlert reports whether kind is a host-key failure that may mean the
// server is being impersonated: exit 2 for audit and for apply's post-write
// login check, not a mere unreachable.
func HostKeyAlert(kind ErrorKind) bool {
	return kind == ErrorKindHostKeyChanged || kind == ErrorKindHostKeyRevoked
}
