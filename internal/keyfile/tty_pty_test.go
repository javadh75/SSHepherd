//go:build linux || darwin

package keyfile

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ptyRig drives the real prompter against a pseudo-terminal: the master is
// the operator's keyboard and screen, the slave stands in for /dev/tty.
type ptyRig struct {
	master *os.File
	slave  *os.File // held open by the test: termios is read through it
	tty    *TTY
	mu     sync.Mutex
	screen bytes.Buffer
	done   chan struct{}
}

func newPTYRig(t *testing.T) *ptyRig {
	t.Helper()
	master, name := openPTY(t)
	slave, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		_ = master.Close()
		t.Skipf("open pty slave: %v", err)
	}
	r := &ptyRig{master: master, slave: slave, tty: &TTY{path: name, stdin: slave}, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		buf := make([]byte, 256)
		for {
			n, err := master.Read(buf)
			r.mu.Lock()
			r.screen.Write(buf[:n])
			r.mu.Unlock()
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = slave.Close()
		_ = master.Close()
		<-r.done
	})
	return r
}

// withFD runs fn on f's descriptor through SyscallConn — never Fd(), which
// would switch f to blocking mode (and a blocked Read would then outlive
// Close, failing goleak).
func withFD(t *testing.T, f *os.File, fn func(fd int)) {
	t.Helper()
	rc, err := f.SyscallConn()
	if err != nil {
		t.Fatalf("syscall conn: %v", err)
	}
	if err := rc.Control(func(fd uintptr) { fn(int(fd)) }); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// echo reports whether the slave's ECHO flag is set.
func (r *ptyRig) echo(t *testing.T) bool {
	t.Helper()
	var (
		tio *unix.Termios
		err error
	)
	withFD(t, r.slave, func(fd int) { tio, err = unix.IoctlGetTermios(fd, ioctlGetTermios) })
	if err != nil {
		t.Fatalf("tcgetattr: %v", err)
	}
	return tio.Lflag&unix.ECHO != 0
}

// waitEchoOff waits until the prompter has turned echo off (its prompt is
// up and the read is about to start).
func (r *ptyRig) waitEchoOff(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for r.echo(t) {
		if time.Now().After(deadline) {
			t.Fatal("echo never turned off")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (r *ptyRig) screenText() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.screen.String()
}

type readResult struct {
	line []byte
	err  error
}

func (r *ptyRig) read(ctx context.Context) <-chan readResult {
	ch := make(chan readResult, 1)
	go func() {
		line, err := r.tty.ReadPassphrase(ctx, "Enter passphrase for /k: ")
		ch <- readResult{line, err}
	}()
	return ch
}

func TestTTYReadPassphraseOnPTY(t *testing.T) {
	r := newPTYRig(t)
	if !r.echo(t) {
		t.Fatal("a fresh pty has echo off")
	}
	if r.tty.Available() {
		t.Error("Available on a terminal that is not this process's controlling tty, want false (headless)")
	}
	ch := r.read(context.Background())
	r.waitEchoOff(t)
	if _, err := io.WriteString(r.master, "s3cret\n"); err != nil {
		t.Fatal(err)
	}
	res := <-ch
	if res.err != nil || string(res.line) != "s3cret" {
		t.Fatalf("ReadPassphrase = (%q, %v), want s3cret", res.line, res.err)
	}
	if !r.echo(t) {
		t.Error("echo not restored after the read")
	}
	if s := r.screenText(); strings.Contains(s, "s3cret") {
		t.Errorf("the passphrase was echoed: %q", s)
	}
}

func TestTTYCanceledPromptRestoresEcho(t *testing.T) {
	r := newPTYRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	ch := r.read(ctx)
	r.waitEchoOff(t)
	cancel() // what the first Ctrl-C does through signal.NotifyContext
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
	// Where closing the tty cannot end a blocked read, this line does, so
	// the abandoned reader exits before goleak looks.
	_, _ = io.WriteString(r.master, "\n")
}
