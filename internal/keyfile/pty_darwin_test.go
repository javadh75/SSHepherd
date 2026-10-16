package keyfile

import (
	"bytes"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal pair: the master (the test's keyboard
// and screen) and the slave's device path (what the prompter opens).
func openPTY(t *testing.T) (master *os.File, slave string) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	name := make([]byte, 128)
	var ctlErr error
	withFD(t, m, func(fd int) {
		if ctlErr = unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); ctlErr != nil {
			return
		}
		if ctlErr = unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); ctlErr != nil {
			return
		}
		//nolint:staticcheck // SA1019: TIOCPTYGNAME fills a 128-byte buffer and x/sys has no wrapper for it
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0]))); errno != 0 {
			ctlErr = errno
		}
	})
	if ctlErr != nil {
		_ = m.Close()
		t.Fatalf("pty setup: %v", ctlErr)
	}
	return m, string(name[:bytes.IndexByte(name, 0)])
}
