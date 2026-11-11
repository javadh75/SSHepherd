//go:build linux || darwin

package keyfile

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// termios reads the slave's termios.
func (r *ptyRig) termios(t *testing.T) unix.Termios {
	t.Helper()
	var (
		tio *unix.Termios
		err error
	)
	withFD(t, r.slave, func(fd int) { tio, err = unix.IoctlGetTermios(fd, ioctlGetTermios) })
	if err != nil {
		t.Fatalf("tcgetattr: %v", err)
	}
	return *tio
}

// setTermios changes the slave's termios through fn, as a shell does to the
// terminal while the job is stopped.
func (r *ptyRig) setTermios(t *testing.T, fn func(*unix.Termios)) {
	t.Helper()
	tio := r.termios(t)
	fn(&tio)
	var err error
	withFD(t, r.slave, func(fd int) { err = unix.IoctlSetTermios(fd, ioctlSetTermios, &tio) })
	if err != nil {
		t.Fatalf("tcsetattr: %v", err)
	}
}

// jobRig is a pty rig whose foreground verdict the test sets (the pty is
// not this process's controlling terminal).
func jobRig(t *testing.T) (*ptyRig, *atomic.Bool) {
	t.Helper()
	r := newPTYRig(t)
	fg := &atomic.Bool{}
	fg.Store(true)
	r.tty.inForeground = func(*os.File) bool { return fg.Load() }
	return r, fg
}

func sendSelf(t *testing.T, sig syscall.Signal) {
	t.Helper()
	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatalf("kill %v: %v", sig, err)
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

func (r *ptyRig) answer(t *testing.T, ch <-chan readResult, line string) {
	t.Helper()
	if _, err := io.WriteString(r.master, line+"\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-ch:
		if res.err != nil || string(res.line) != line {
			t.Fatalf("ReadPassphrase = (%q, %v), want %q", res.line, res.err, line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadPassphrase did not return")
	}
}

// TestTTYResumeTurnsEchoOffAgain (G009): after Ctrl-Z the shell gives the
// terminal back in its own, echoing mode; on SIGCONT (fg) the prompter
// turns echo off again over the terminal's current state and rewrites the
// prompt, so the passphrase typed after fg is not shown. The read's end
// still puts back the state from before the prompt.
func TestTTYResumeTurnsEchoOffAgain(t *testing.T) {
	r, _ := jobRig(t)
	before := r.termios(t)
	ch := r.read(context.Background())
	r.waitEchoOff(t)
	r.waitPrompts(t, 1)

	// The shell's own mode while the job is stopped: echo on, and a flag
	// the prompter does not own changed.
	r.setTermios(t, func(tio *unix.Termios) {
		tio.Lflag |= unix.ECHO
		tio.Iflag ^= unix.IXON
	})
	sendSelf(t, syscall.SIGCONT) // fg

	r.waitEchoOff(t) // fails here without the SIGCONT handling: echo stays on
	r.waitPrompts(t, 2)
	if got := r.termios(t).Iflag & unix.IXON; got != (before.Iflag^unix.IXON)&unix.IXON {
		t.Error("the resume put back the saved termios instead of turning echo off over the current state")
	}
	r.answer(t, ch, "s3cret")
	if s := r.screenText(); strings.Contains(s, "s3cret") {
		t.Errorf("the passphrase typed after the resume was echoed: %q", s)
	}
	after := r.termios(t)
	if after.Lflag != before.Lflag || after.Iflag != before.Iflag {
		t.Errorf("termios after the read = lflag %#x iflag %#x, want the state before the prompt (%#x, %#x)",
			after.Lflag, after.Iflag, before.Lflag, before.Iflag)
	}
}

// TestTTYPromptForcesCanonicalAndSignals: a terminal left in raw mode still
// gets a line-read prompt on which Ctrl-C interrupts; the raw mode comes
// back afterwards.
func TestTTYPromptForcesCanonicalAndSignals(t *testing.T) {
	r, _ := jobRig(t)
	r.setTermios(t, func(tio *unix.Termios) { tio.Lflag &^= unix.ICANON | unix.ISIG })
	ch := r.read(context.Background())
	r.waitEchoOff(t)
	if l := r.termios(t).Lflag; l&unix.ICANON == 0 || l&unix.ISIG == 0 {
		t.Errorf("prompt lflag %#x, want ICANON and ISIG set", l)
	}
	// After a resume too.
	r.setTermios(t, func(tio *unix.Termios) { tio.Lflag = tio.Lflag&^(unix.ICANON|unix.ISIG) | unix.ECHO })
	sendSelf(t, syscall.SIGCONT)
	r.waitEchoOff(t)
	if l := r.termios(t).Lflag; l&unix.ICANON == 0 || l&unix.ISIG == 0 {
		t.Errorf("resumed prompt lflag %#x, want ICANON and ISIG set", l)
	}
	r.answer(t, ch, "pw")
	if l := r.termios(t).Lflag; l&(unix.ICANON|unix.ISIG) != 0 {
		t.Errorf("lflag after the read %#x, want the raw mode back", l)
	}
}

// TestTTYBackgroundResumeLeavesTerminalAlone: a process continued in the
// background must not change termios (tcsetattr from the background raises
// SIGTTOU) nor write the prompt; it resumes the prompt once it is in the
// foreground again.
func TestTTYBackgroundResumeLeavesTerminalAlone(t *testing.T) {
	r, fg := jobRig(t)
	ch := r.read(context.Background())
	r.waitEchoOff(t)
	r.setTermios(t, func(tio *unix.Termios) { tio.Lflag |= unix.ECHO })
	fg.Store(false) // `bg`
	sendSelf(t, syscall.SIGCONT)
	time.Sleep(50 * time.Millisecond)
	if n := strings.Count(r.screenText(), "Enter passphrase for /k: "); n != 1 {
		t.Errorf("a background resume wrote the prompt (%d prompts)", n)
	}
	if !r.echo(t) {
		t.Error("a background resume changed the terminal")
	}
	fg.Store(true) // `fg`
	sendSelf(t, syscall.SIGCONT)
	r.waitEchoOff(t)
	r.waitPrompts(t, 2)
	r.answer(t, ch, "pw")
}

// TestTTYCanceledAfterResumeRestoresEcho: a cancel after a resume still
// restores the terminal and returns at once.
func TestTTYCanceledAfterResumeRestoresEcho(t *testing.T) {
	r, _ := jobRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch := r.read(ctx)
	r.waitEchoOff(t)
	r.setTermios(t, func(tio *unix.Termios) { tio.Lflag |= unix.ECHO })
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

// The real job-control path cannot be seen in-process: a seam would hide
// what the Go runtime does with a stop signal. TestTTYJobControlRealProcess
// re-executes this test binary as a small job-control shell ("jobshell",
// a session leader on a pty) that runs the prompter ("prompter") as its
// foreground job, in a process group that is not orphaned, so the kernel
// really stops it on SIGTSTP.
const helperModeEnv = "SSHEPHERD_KEYFILE_TEST_MODE"

func init() {
	helpers["prompter"] = prompterHelper
	helpers["jobshell"] = jobShellHelper
}

// prompterHelper prompts on /dev/tty, reports "READ ok" (the passphrase
// was s3cret) or "READ bad" on fd 3, then waits to be stopped and killed.
func prompterHelper() int {
	tty := NewTTY()
	if !tty.Available() {
		_, _ = fmt.Fprintln(os.Stderr, "HELPER FAIL: the prompter is not available")
		return 10
	}
	line, err := tty.ReadPassphrase(context.Background(), "Enter passphrase for /k: ")
	status := "bad"
	if err == nil && string(line) == "s3cret" {
		status = "ok"
	}
	report := os.NewFile(3, "report")
	_, _ = fmt.Fprintf(report, "READ %s\n", status)
	_ = report.Close()
	time.Sleep(30 * time.Second)
	return 0
}

// jobShellHelper plays the shell: Ctrl-Z while the prompt is up, the
// shell's own echoing mode while the job is stopped, fg, then (after the
// test types the passphrase) Ctrl-Z again once the prompt is over. In mode
// "ignored" it starts the job with SIGTSTP ignored, which must stay so.
// Progress and failures go to the terminal as "HELPER …" lines.
func jobShellHelper() int {
	ignored := os.Getenv(helperModeEnv) == "ignored"
	tty := os.Stdin
	fd := int(tty.Fd())
	say := func(format string, args ...any) { _, _ = fmt.Fprintf(tty, "\r\nHELPER "+format+"\r\n", args...) }
	fail := func(format string, args ...any) int { say("FAIL: "+format, args...); return 1 }
	if ignored {
		signal.Ignore(syscall.SIGTSTP) // inherited by the job across exec
	}
	pr, pw, err := os.Pipe()
	if err != nil {
		return fail("pipe: %v", err)
	}
	job := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^$")
	job.Env = append(os.Environ(), helperEnv+"=prompter")
	job.Stdin, job.Stdout, job.Stderr = tty, tty, tty
	job.ExtraFiles = []*os.File{pw}
	job.SysProcAttr = &syscall.SysProcAttr{Foreground: true, Ctty: fd}
	if err := job.Start(); err != nil {
		return fail("start the job: %v", err)
	}
	_ = pw.Close()
	pid := job.Process.Pid
	defer func() {
		_ = unix.Kill(pid, unix.SIGKILL)
		var ws unix.WaitStatus
		_, _ = unix.Wait4(pid, &ws, 0, nil)
	}()
	signal.Ignore(syscall.SIGTTOU) // like a shell: take the terminal back from the background

	if !waitEcho(fd, false) {
		return fail("the prompt never turned echo off")
	}
	_ = unix.Kill(-pid, unix.SIGTSTP) // Ctrl-Z
	stopped, why := waitStopped(pid, ignored)
	switch {
	case ignored && stopped:
		return fail("the job stopped although SIGTSTP was inherited as ignored")
	case ignored && why != stillRunning:
		return fail("%s", why)
	case ignored:
		if echoOn(fd) {
			return fail("an ignored Ctrl-Z turned echo back on")
		}
	case !stopped:
		return fail("Ctrl-Z at the prompt did not stop the job: %s", why)
	default:
		// The shell takes the terminal in its own, echoing mode, then fg.
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, unix.Getpgrp()); err != nil {
			return fail("take the terminal: %v", err)
		}
		if err := setEchoOn(fd); err != nil {
			return fail("echo on: %v", err)
		}
		if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, pid); err != nil {
			return fail("give the terminal back: %v", err)
		}
		_ = unix.Kill(-pid, unix.SIGCONT)
		if !waitEcho(fd, false) {
			return fail("echo stayed on after fg")
		}
	}
	say("ready")

	_ = pr.SetReadDeadline(time.Now().Add(20 * time.Second))
	line, err := bufio.NewReader(pr).ReadString('\n')
	if strings.TrimSpace(line) != "READ ok" {
		return fail("the job read %q (%v), want READ ok", line, err)
	}
	_ = unix.Kill(-pid, unix.SIGTSTP) // Ctrl-Z once the prompt is over
	stopped, why = waitStopped(pid, ignored)
	switch {
	case ignored && stopped:
		return fail("after the prompt the job stopped although SIGTSTP was inherited as ignored")
	case ignored && why != stillRunning:
		return fail("%s", why)
	case !ignored && !stopped:
		return fail("after the prompt Ctrl-Z did not stop the job: %s", why)
	}
	say("done")
	return 0
}

// waitStopped polls for the job to stop: up to 5 s, or 500 ms when the stop
// is expected not to happen. why explains a job that ended instead.
func waitStopped(pid int, expectNone bool) (stopped bool, why string) {
	limit := 5 * time.Second
	if expectNone {
		limit = 500 * time.Millisecond
	}
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		var ws unix.WaitStatus
		wpid, err := unix.Wait4(pid, &ws, unix.WNOHANG|unix.WUNTRACED, nil)
		switch {
		case err != nil:
			return false, fmt.Sprintf("wait4: %v", err)
		case wpid == pid && ws.Stopped():
			return true, ""
		case wpid == pid:
			return false, fmt.Sprintf("the job ended (status %#x)", uint32(ws))
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false, stillRunning
}

const stillRunning = "still running"

func echoOn(fd int) bool {
	tio, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	return err == nil && tio.Lflag&unix.ECHO != 0
}

func waitEcho(fd int, on bool) bool {
	deadline := time.Now().Add(10 * time.Second)
	for echoOn(fd) != on {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(5 * time.Millisecond)
	}
	return true
}

func setEchoOn(fd int) error {
	tio, err := unix.IoctlGetTermios(fd, ioctlGetTermios)
	if err != nil {
		return err
	}
	tio.Lflag |= unix.ECHO
	return unix.IoctlSetTermios(fd, ioctlSetTermios, tio)
}

// TestTTYJobControlRealProcess (G009): Ctrl-Z at the prompt really stops
// the process, a passphrase typed after fg is not shown, Ctrl-Z still
// stops the process once the prompt is over, and a SIGTSTP the process
// inherited as ignored stays ignored (echo stays off).
func TestTTYJobControlRealProcess(t *testing.T) {
	for _, mode := range []string{"default", "ignored"} {
		t.Run(mode, func(t *testing.T) {
			r := newPTYRig(t)
			shell := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^$")
			shell.Env = append(os.Environ(), helperEnv+"=jobshell", helperModeEnv+"="+mode)
			shell.Stdin, shell.Stdout, shell.Stderr = r.slave, r.slave, r.slave
			shell.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := shell.Start(); err != nil {
				t.Skipf("start the job-control helper: %v", err)
			}
			exited := make(chan error, 1)
			go func() { exited <- shell.Wait() }()
			waitFor := func(marker string) {
				t.Helper()
				deadline := time.Now().Add(30 * time.Second)
				for !strings.Contains(r.screenText(), marker) {
					if s := r.screenText(); strings.Contains(s, "HELPER FAIL") || time.Now().After(deadline) {
						_ = shell.Process.Kill()
						<-exited
						t.Fatalf("waiting for %q; terminal:\n%s", marker, s)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
			waitFor("HELPER ready")
			wantPrompts := 2
			if mode == "ignored" {
				wantPrompts = 1
			}
			if n := strings.Count(r.screenText(), "Enter passphrase for /k: "); n != wantPrompts {
				t.Errorf("prompt written %d times, want %d", n, wantPrompts)
			}
			if _, err := io.WriteString(r.master, "s3cret\n"); err != nil {
				t.Fatal(err)
			}
			waitFor("HELPER done")
			select {
			case err := <-exited:
				if err != nil {
					t.Errorf("helper: %v; terminal:\n%s", err, r.screenText())
				}
			case <-time.After(30 * time.Second):
				_ = shell.Process.Kill()
				<-exited
				t.Fatal("the helper did not exit")
			}
			if s := r.screenText(); strings.Contains(s, "s3cret") {
				t.Errorf("the passphrase was echoed: %q", s)
			}
		})
	}
}
