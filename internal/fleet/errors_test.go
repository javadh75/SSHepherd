package fleet

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
)

// kindedErr is a reader error that carries its own classification, the
// way sshconn.Error does.
type kindedErr struct {
	kind ErrorKind
	msg  string
}

func (e kindedErr) Error() string        { return e.msg }
func (e kindedErr) ErrorKind() ErrorKind { return e.kind }

// hintedErr is a reader error carrying kind and hint, the way sshconn.Error does.
type hintedErr struct {
	kindedErr
	hint string
}

func (e hintedErr) ErrorHint() string { return e.hint }

func TestErrorKindOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{"nil", nil, ""},
		{"plain", errors.New("boom"), ErrorKindUnknown},
		{"kinded", kindedErr{ErrorKindAuth, "denied"}, ErrorKindAuth},
		{"kinded behind wrappers", fmt.Errorf("read: %w", kindedErr{ErrorKindHostKeyChanged, "x"}), ErrorKindHostKeyChanged},
		{"deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), ErrorKindTimeout},
		{"canceled", fmt.Errorf("x: %w", context.Canceled), ErrorKindCanceled},
		{"net dial", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, ErrorKindDial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ErrorKindOf(tt.err); got != tt.want {
				t.Errorf("ErrorKindOf(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

func TestHintOf(t *testing.T) {
	h := hintedErr{kindedErr{ErrorKindDial, "dial tcp x: refused"}, "check the firewall"}
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"plain", errors.New("boom"), ""},
		{"hinted", h, "check the firewall"},
		{"hinted behind wrappers", fmt.Errorf("read: %w", h), "check the firewall"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := HintOf(tt.err); got != tt.want {
				t.Errorf("HintOf = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestErrorKindWireValues pins the JSON contract: these strings appear
// verbatim as error_kind in audit and apply documents (schema 1).
func TestErrorKindWireValues(t *testing.T) {
	want := map[ErrorKind]string{
		ErrorKindUnknown: "unknown", ErrorKindHostKeyUnknown: "host_key_unknown",
		ErrorKindHostKeyChanged: "host_key_changed", ErrorKindHostKeyTypeUnrecorded: "host_key_type_unrecorded",
		ErrorKindHostKeyRevoked: "host_key_revoked", ErrorKindHostKey: "host_key", ErrorKindAgent: "agent",
		ErrorKindAuth: "auth", ErrorKindDial: "dial", ErrorKindTimeout: "timeout",
		ErrorKindCanceled: "canceled", ErrorKindHandshake: "handshake", ErrorKindRemote: "remote",
	}
	for k, s := range want {
		if string(k) != s {
			t.Errorf("%q != %q", k, s)
		}
	}
}
