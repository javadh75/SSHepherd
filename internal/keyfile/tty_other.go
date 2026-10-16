//go:build !(linux || darwin)

package keyfile

import (
	"context"
	"errors"
)

// TTY is never available on this platform: encrypted keys need a
// passphrase file here.
type TTY struct{}

var _ Prompter = (*TTY)(nil)

// NewTTY returns the (unavailable) terminal prompter.
func NewTTY() *TTY { return &TTY{} }

// Available is always false on this platform.
func (*TTY) Available() bool { return false }

// ReadPassphrase always fails on this platform.
func (*TTY) ReadPassphrase(context.Context, string) ([]byte, error) {
	return nil, errors.New("terminal passphrase prompts are not supported on this platform")
}
