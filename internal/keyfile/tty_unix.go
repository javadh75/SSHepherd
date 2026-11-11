//go:build linux || darwin

package keyfile

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// TTY prompts on the controlling terminal, never on stdout (audit --json
// stays clean) and regardless of -q. Build it with NewTTY.
type TTY struct {
	path  string   // "/dev/tty"
	stdin *os.File // must be a terminal too (apply's confirmation contract)
	// Test seam, nil in production: inForeground replaces foreground (a
	// test pty is not the controlling terminal).
	inForeground func(*os.File) bool
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
//
// Job control (G009): the stop signals (SIGTSTP, SIGTTIN, SIGTTOU) are
// never caught. Once os/signal has caught one, Go keeps its own handler
// for good and drops the signal when nobody listens, so Ctrl-Z would stop
// working for the rest of the run (and an inherited SIG_IGN cannot be
// seen through signal.Ignored for them). The process stops as any program
// does, the shell takes the terminal back in its own mode, and on SIGCONT
// the prompt turns echo off again and rewrites itself, so a passphrase
// typed after Ctrl-Z and fg is never shown.
func (t *TTY) ReadPassphrase(ctx context.Context, prompt string) ([]byte, error) {
	f, err := os.OpenFile(t.path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", t.path, err)
	}
	// Registered before echo goes off, so a resume that comes once the
	// prompt is up is always seen.
	cont := make(chan os.Signal, 1)
	signal.Notify(cont, syscall.SIGCONT)
	mode, err := echoOff(f)
	if err != nil {
		signal.Stop(cont)
		_ = f.Close()
		return nil, err
	}
	done := func() {
		signal.Stop(cont)
		mode.restore()
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
	for {
		select {
		case r := <-ch:
			done()
			return r.line, r.err
		case <-ctx.Done():
			done() // closing the tty ends the read where the platform allows; the result is dropped
			return nil, fmt.Errorf("passphrase prompt: %w", ctx.Err())
		case <-cont:
			t.resume(f, mode, prompt)
		}
	}
}

// resume runs on SIGCONT: from the foreground it turns echo off again and
// rewrites the prompt (the shell gave the terminal back in its own,
// echoing mode). From the background it leaves the terminal alone:
// tcsetattr there would raise SIGTTOU.
func (t *TTY) resume(f *os.File, mode *ttyMode, prompt string) {
	if t.foreground(f) {
		mode.silence()
		_, _ = f.WriteString(prompt)
	}
}

func (t *TTY) foreground(f *os.File) bool {
	if t.inForeground != nil {
		return t.inForeground(f)
	}
	return foreground(f)
}

// ttyMode is the terminal state the prompt saved and changes.
type ttyMode struct {
	f   *os.File
	old unix.Termios // the state before the prompt, put back by restore
}

// echoOff clears ECHO (keeping canonical mode and signals, so Ctrl-C still
// interrupts) and returns the saved mode.
func echoOff(f *os.File) (*ttyMode, error) {
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
		ctlErr = unix.IoctlSetTermios(int(fd), ioctlSetTermios, noEcho(*old))
	}); err != nil {
		return nil, fmt.Errorf("tty: %w", err)
	}
	if ctlErr != nil {
		if errors.Is(ctlErr, syscall.ENOTTY) {
			return nil, fmt.Errorf("%s is not a terminal: %w", f.Name(), ctlErr)
		}
		return nil, fmt.Errorf("tty: %w", ctlErr)
	}
	return &ttyMode{f: f, old: *old}, nil
}

func noEcho(tio unix.Termios) *unix.Termios {
	tio.Lflag &^= unix.ECHO
	tio.Lflag |= unix.ICANON | unix.ISIG
	return &tio
}

// silence turns echo off again over the terminal's current state.
func (m *ttyMode) silence() {
	m.control(func(fd int) {
		if cur, err := unix.IoctlGetTermios(fd, ioctlGetTermios); err == nil {
			_ = unix.IoctlSetTermios(fd, ioctlSetTermios, noEcho(*cur))
		}
	})
}

// restore puts back the state saved before the prompt.
func (m *ttyMode) restore() {
	m.control(func(fd int) { _ = unix.IoctlSetTermios(fd, ioctlSetTermios, &m.old) })
}

func (m *ttyMode) control(fn func(fd int)) {
	if rc, err := m.f.SyscallConn(); err == nil {
		_ = rc.Control(func(fd uintptr) { fn(int(fd)) })
	}
}
