//go:build linux || darwin

package keyfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// TTY prompts on the controlling terminal, never on stdout (audit --json
// stays clean) and regardless of -q. Build it with NewTTY.
type TTY struct {
	path  string   // "/dev/tty"
	stdin *os.File // must be a terminal too (apply's confirmation contract)
}

var _ Prompter = (*TTY)(nil)

// NewTTY returns the /dev/tty prompter.
func NewTTY() *TTY { return &TTY{path: "/dev/tty", stdin: os.Stdin} }

// Available is true only when /dev/tty opens, stdin is a terminal, and this
// process is in the terminal's foreground process group. Anything else is
// headless — docker run -t, a pty-allocating CI executor, or `cmd &` — and
// fails with the no-passphrase-source error instead of hanging or being
// stopped by SIGTTIN.
func (t *TTY) Available() bool {
	if t.stdin == nil || !term.IsTerminal(int(t.stdin.Fd())) {
		return false
	}
	f, err := os.OpenFile(t.path, os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	return foreground(f)
}

// foreground reports tcgetpgrp(tty) == getpgrp().
func foreground(f *os.File) bool {
	rc, err := f.SyscallConn()
	if err != nil {
		return false
	}
	fg := false
	_ = rc.Control(func(fd uintptr) {
		pgrp, err := unix.IoctlGetInt(int(fd), unix.TIOCGPGRP)
		fg = err == nil && pgrp == unix.Getpgrp()
	})
	return fg
}

// ReadPassphrase writes prompt to the terminal, turns echo off, and reads
// one line. On ctx.Done() it restores the terminal state, prints a newline,
// closes the tty and returns ctx.Err() (wrapped) at once — the first Ctrl-C
// always works and never leaves the shell without echo. The tty is driven
// through the *os.File (SyscallConn for the ioctls), never a raw fd, so
// closing it cannot race a read onto a reused descriptor.
func (t *TTY) ReadPassphrase(ctx context.Context, prompt string) ([]byte, error) {
	f, err := os.OpenFile(t.path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", t.path, err)
	}
	restore, err := echoOff(f)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	done := func() {
		restore()
		_, _ = f.WriteString("\n") // the user's Enter was not echoed
		_ = f.Close()
	}
	if _, err := f.WriteString(prompt); err != nil {
		done()
		return nil, fmt.Errorf("write prompt: %w", err)
	}
	type result struct {
		line []byte
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := readLine(f, maxPassphraseFile)
		ch <- result{line, err}
	}()
	select {
	case r := <-ch:
		done()
		return r.line, r.err
	case <-ctx.Done():
		done() // closing the tty ends the read where the platform allows; the result is dropped
		return nil, fmt.Errorf("passphrase prompt: %w", ctx.Err())
	}
}

// echoOff clears ECHO (keeping canonical mode and signals, so Ctrl-C still
// interrupts) and returns the restore func.
func echoOff(f *os.File) (func(), error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("tty: %w", err)
	}
	var old *unix.Termios
	var ctlErr error
	if err := rc.Control(func(fd uintptr) {
		old, ctlErr = unix.IoctlGetTermios(int(fd), ioctlGetTermios)
		if ctlErr != nil {
			return
		}
		noEcho := *old
		noEcho.Lflag &^= unix.ECHO
		noEcho.Lflag |= unix.ICANON | unix.ISIG
		ctlErr = unix.IoctlSetTermios(int(fd), ioctlSetTermios, &noEcho)
	}); err != nil {
		return nil, fmt.Errorf("tty: %w", err)
	}
	if ctlErr != nil {
		if errors.Is(ctlErr, syscall.ENOTTY) {
			return nil, fmt.Errorf("%s is not a terminal: %w", f.Name(), ctlErr)
		}
		return nil, fmt.Errorf("tty: %w", ctlErr)
	}
	return func() {
		_ = rc.Control(func(fd uintptr) { _ = unix.IoctlSetTermios(int(fd), ioctlSetTermios, old) })
	}, nil
}
