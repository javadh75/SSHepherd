package keyfile

import (
	"fmt"
	"os"
	"testing"

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
	var (
		n      int
		ctlErr error
	)
	withFD(t, m, func(fd int) {
		if ctlErr = unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); ctlErr != nil {
			return
		}
		n, ctlErr = unix.IoctlGetInt(fd, unix.TIOCGPTN)
	})
	if ctlErr != nil {
		_ = m.Close()
		t.Fatalf("pty setup: %v", ctlErr)
	}
	return m, fmt.Sprintf("/dev/pts/%d", n)
}
