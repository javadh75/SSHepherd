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
	// Test seams, nil in production: inForeground replaces foreground (a
	// test pty is not the controlling terminal) and raise replaces stopping
	// this process with a job-control signal.
	inForeground func(*os.File) bool
	raise        func(syscall.Signal)
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

// stopSignals are the job-control stop signals the prompt handles the way
// readpassphrase(3) does.
var stopSignals = []syscall.Signal{syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU}

// ReadPassphrase writes prompt to the terminal, turns echo off, and reads
// one line. On ctx.Done() it restores the terminal state, prints a newline,
// closes the tty and returns ctx.Err() (wrapped) at once — the first Ctrl-C
// always works and never leaves the shell without echo. The tty is driven
// through the *os.File (SyscallConn for the ioctls), never a raw fd, so
// closing it cannot race a read onto a reused descriptor.
//
// Job control follows readpassphrase(3) (G009): on SIGTSTP/SIGTTIN/SIGTTOU
// the prompt restores the terminal, lets the signal take its default action
// and stops; on SIGCONT it turns echo off again and rewrites the prompt, so
// a passphrase typed after Ctrl-Z and fg is never shown. A stop signal the
// process inherited as ignored stays ignored.
func (t *TTY) ReadPassphrase(ctx context.Context, prompt string) ([]byte, error) {
	f, err := os.OpenFile(t.path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", t.path, err)
	}
	// Registered before echo goes off, so a stop that comes once the
	// prompt is up is always caught.
	jc := t.watchJobControl()
	mode, err := echoOff(f)
	if err != nil {
		jc.stop()
		_ = f.Close()
		return nil, err
	}
	done := func() {
		// Back to the default stop actions first: a restore from the
		// background then stops the process (as before) instead of looping
		// on a caught SIGTTOU.
		jc.stop()
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
		case sig := <-jc.stops:
			t.suspend(f, mode, sig)
		case <-jc.cont:
			t.resume(f, mode, jc, prompt)
		}
	}
}

// jobControl is the prompt's job-control signal registration.
type jobControl struct {
	handled []os.Signal // the stop signals not inherited as ignored
	stops   chan os.Signal
	cont    chan os.Signal
}

func (t *TTY) watchJobControl() *jobControl {
	jc := &jobControl{stops: make(chan os.Signal, len(stopSignals)), cont: make(chan os.Signal, 1)}
	for _, s := range stopSignals {
		if !signal.Ignored(s) {
			jc.handled = append(jc.handled, s)
		}
	}
	signal.Notify(jc.cont, syscall.SIGCONT)
	jc.arm()
	return jc
}

// arm (re-)catches the stop signals.
func (jc *jobControl) arm() {
	if len(jc.handled) > 0 {
		signal.Notify(jc.stops, jc.handled...)
	}
}

// stop hands every signal back to its previous disposition.
func (jc *jobControl) stop() {
	signal.Stop(jc.stops)
	signal.Stop(jc.cont)
}

// suspend restores the terminal (only from the foreground: tcsetattr from
// the background raises SIGTTOU), gives sig its default action back and
// re-raises it, stopping the process.
func (t *TTY) suspend(f *os.File, mode *ttyMode, sig os.Signal) {
	s, ok := sig.(syscall.Signal)
	if !ok {
		return
	}
	if t.foreground(f) {
		mode.restore()
	}
	signal.Reset(s)
	t.raiseSignal(s)
}

// resume runs on SIGCONT: from the foreground it turns echo off again and
// rewrites the prompt (the shell gave the terminal back in its own,
// echoing mode); it always re-arms the stop signals.
func (t *TTY) resume(f *os.File, mode *ttyMode, jc *jobControl, prompt string) {
	if t.foreground(f) {
		mode.silence()
		_, _ = f.WriteString(prompt)
	}
	jc.arm()
}

func (t *TTY) foreground(f *os.File) bool {
	if t.inForeground != nil {
		return t.inForeground(f)
	}
	return foreground(f)
}

func (t *TTY) raiseSignal(s syscall.Signal) {
	if t.raise != nil {
		t.raise(s)
		return
	}
	_ = unix.Kill(os.Getpid(), s)
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
