//go:build linux || darwin

package keyfile

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The controlling-terminal paths cannot run under go test (no controlling
// tty); these pin the headless verdicts. tty_pty_test.go drives the real
// prompter on a pseudo-terminal.
func TestTTYHeadless(t *testing.T) {
	notTTY, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = notTTY.Close() }()
	if (&TTY{path: "/dev/tty", stdin: notTTY}).Available() {
		t.Error("Available with a non-terminal stdin, want false")
	}
	if (&TTY{path: "/dev/tty"}).Available() {
		t.Error("Available with no stdin, want false")
	}
	if NewTTY().path != "/dev/tty" {
		t.Error("NewTTY must prompt on /dev/tty")
	}
	missing := &TTY{path: filepath.Join(t.TempDir(), "no-tty"), stdin: notTTY}
	if _, err := missing.ReadPassphrase(context.Background(), "p: "); err == nil {
		t.Error("ReadPassphrase on a missing tty succeeded")
	}
	regular := &TTY{path: notTTY.Name(), stdin: notTTY}
	if _, err := regular.ReadPassphrase(context.Background(), "p: "); err == nil {
		t.Error("ReadPassphrase on a regular file succeeded, want not-a-terminal")
	}
}
