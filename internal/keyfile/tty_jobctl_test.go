//go:build linux || darwin

package keyfile

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// slaveEcho reports the pty slave's ECHO flag without a *testing.T, for
// use inside the prompter's goroutine (the raise seam).
func (r *ptyRig) slaveEcho() (bool, error) {
	rc, err := r.slave.SyscallConn()
	if err != nil {
		return false, err
	}
	var (
		tio    *unix.Termios
		ctlErr error
	)
	if err := rc.Control(func(fd uintptr) { tio, ctlErr = unix.IoctlGetTermios(int(fd), ioctlGetTermios) }); err != nil {
		return false, err
	}
	if ctlErr != nil {
		return false, ctlErr
	}
	return tio.Lflag&unix.ECHO != 0, nil
}

// setEcho turns the slave's ECHO flag on, as a shell does to the terminal
// while the job is stopped.
func (r *ptyRig) setEcho(t *testing.T) {
	t.Helper()
	var err error
	withFD(t, r.slave, func(fd int) {
		var tio *unix.Termios
		if tio, err = unix.IoctlGetTermios(fd, ioctlGetTermios); err != nil {
			return
		}
		tio.Lflag |= unix.ECHO
		err = unix.IoctlSetTermios(fd, ioctlSetTermios, tio)
	})
	if err != nil {
		t.Fatalf("tcsetattr: %v", err)
	}
}

type raised struct {
	sig  syscall.Signal
	echo bool // the terminal's ECHO flag when the prompter stopped itself
	err  error
}

// jobRig is a pty rig whose prompter stops itself through a recording seam
// (the test process must never really stop) and whose foreground verdict
// the test sets (the pty is not this process's controlling terminal).
func jobRig(t *testing.T) (*ptyRig, *atomic.Bool, <-chan raised) {
	t.Helper()
	r := newPTYRig(t)
	fg := &atomic.Bool{}
	fg.Store(true)
	stops := make(chan raised, 4)
	// A safety net: should the prompter not catch a stop signal, this keeps
	// the test binary from stopping (the test then fails on its timeout).
	// The prompter's signal.Reset drops it too, so raise puts it back: a
	// prompter that forgets to re-arm then fails instead of stopping the run.
	guard := make(chan os.Signal, 8)
	armGuard := func() { signal.Notify(guard, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU) }
	armGuard()
	t.Cleanup(func() { signal.Stop(guard) })
	r.tty.inForeground = func(*os.File) bool { return fg.Load() }
	r.tty.raise = func(sig syscall.Signal) {
		armGuard()
		echo, err := r.slaveEcho()
		stops <- raised{sig, echo, err}
	}
	return r, fg, stops
}

func sendSelf(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatalf("kill %v: %v", sig, err)
	}
}

func waitStop(t *testing.T, r *ptyRig, stops <-chan raised, want syscall.Signal) raised {
	t.Helper()
	select {
	case got := <-stops:
		if got.err != nil {
			t.Fatalf("reading termios at the stop: %v", got.err)
		}
		if got.sig != want {
			t.Fatalf("prompter stopped itself with %v, want %v", got.sig, want)
		}
		return got
	case <-time.After(5 * time.Second):
		_, _ = io.WriteString(r.master, "\n") // end the read so the reader exits before goleak looks
		t.Fatalf("the prompter did not stop itself on %v", want)
		return raised{}
	}
}

// waitPrompts waits until the prompt has been written n times.
func (r *ptyRig) waitPrompts(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for strings.Count(r.screenText(), "Enter passphrase for /k: ") < n {
		if time.Now().After(deadline) {
			_, _ = io.WriteString(r.master, "\n")
			t.Fatalf("prompt written %d times, want %d: %q", strings.Count(r.screenText(), "Enter passphrase"), n, r.screenText())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTTYSuspendResumeKeepsEchoOff (G009): Ctrl-Z at the prompt, then fg.
// Like readpassphrase(3), the prompter puts the terminal back before it
// stops (the shell gets an echoing tty), and on SIGCONT turns echo off
// again and rewrites the prompt, so the passphrase typed after fg is not
// shown.
func TestTTYSuspendResumeKeepsEchoOff(t *testing.T) {
	r, _, stops := jobRig(t)
	ch := r.read(context.Background())
	r.waitEchoOff(t)
	r.waitPrompts(t, 1)

	sendSelf(t, syscall.SIGTSTP) // Ctrl-Z
	if got := waitStop(t, r, stops, syscall.SIGTSTP); !got.echo {
		t.Error("the prompter stopped with echo still off; it must restore the terminal first")
	}
	r.setEcho(t) // the shell's own mode while the job is stopped
	sendSelf(t, syscall.SIGCONT)

	r.waitEchoOff(t) // fails here without the SIGCONT handling: echo stays on
	r.waitPrompts(t, 2)
	if _, err := io.WriteString(r.master, "s3cret\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-ch:
		if res.err != nil || string(res.line) != "s3cret" {
			t.Fatalf("ReadPassphrase = (%q, %v), want s3cret", res.line, res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPassphrase did not return")
	}
	if s := r.screenText(); strings.Contains(s, "s3cret") {
		t.Errorf("the passphrase typed after the resume was echoed: %q", s)
	}
	if !r.echo(t) {
		t.Error("echo not restored after the read")
	}
}

// TestTTYStopAgainAfterResume: the stop handler is re-armed on SIGCONT, so
// a second Ctrl-Z (and SIGTTOU/SIGTTIN) is handled the same way.
func TestTTYStopAgainAfterResume(t *testing.T) {
	r, _, stops := jobRig(t)
	ch := r.read(context.Background())
	r.waitEchoOff(t)
	for i, sig := range []syscall.Signal{syscall.SIGTSTP, syscall.SIGTTOU, syscall.SIGTSTP, syscall.SIGTTIN} {
		sendSelf(t, sig)
		if got := waitStop(t, r, stops, sig); !got.echo {
			t.Errorf("stop %d (%v): echo still off when the prompter stopped", i, sig)
		}
		sendSelf(t, syscall.SIGCONT)
		r.waitEchoOff(t)
		r.waitPrompts(t, i+2)
	}
	_, _ = io.WriteString(r.master, "pw\n")
	if res := <-ch; res.err != nil || string(res.line) != "pw" {
		t.Fatalf("ReadPassphrase = (%q, %v), want pw", res.line, res.err)
	}
}

// TestTTYBackgroundLeavesTerminalAlone: a process not in the terminal's
// foreground group must not change termios (tcsetattr from the background
// raises SIGTTOU) nor write the prompt; it stops as is, and resumes the
// prompt only once it is in the foreground again.
func TestTTYBackgroundLeavesTerminalAlone(t *testing.T) {
	r, fg, stops := jobRig(t)
	ch := r.read(context.Background())
	r.waitEchoOff(t)
	fg.Store(false) // `bg`: the read then raises SIGTTIN
	sendSelf(t, syscall.SIGTTIN)
	if got := waitStop(t, r, stops, syscall.SIGTTIN); got.echo {
		t.Error("a background stop changed the terminal (echo turned back on)")
	}
	sendSelf(t, syscall.SIGCONT) // continued, still in the background
	time.Sleep(50 * time.Millisecond)
	if n := strings.Count(r.screenText(), "Enter passphrase for /k: "); n != 1 {
		t.Errorf("a background resume wrote the prompt (%d prompts)", n)
	}
	r.setEcho(t)
	fg.Store(true) // `fg`
	sendSelf(t, syscall.SIGCONT)
	r.waitEchoOff(t)
	r.waitPrompts(t, 2)
	_, _ = io.WriteString(r.master, "pw\n")
	if res := <-ch; res.err != nil || string(res.line) != "pw" {
		t.Fatalf("ReadPassphrase = (%q, %v), want pw", res.line, res.err)
	}
}

// TestTTYCanceledAfterResumeRestoresEcho: a cancel after a resume still
// restores the terminal and returns at once.
func TestTTYCanceledAfterResumeRestoresEcho(t *testing.T) {
	r, _, stops := jobRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch := r.read(ctx)
	r.waitEchoOff(t)
	sendSelf(t, syscall.SIGTSTP)
	waitStop(t, r, stops, syscall.SIGTSTP)
	sendSelf(t, syscall.SIGCONT)
	r.waitEchoOff(t)
	cancel()
	select {
	case res := <-ch:
		if !errors.Is(res.err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", res.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPassphrase did not return on cancel")
	}
	if !r.echo(t) {
		t.Error("a canceled prompt left the terminal without echo")
	}
	_, _ = io.WriteString(r.master, "\n")
}
