//go:build unix

package keyfile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestOSFS exercises the real FS against real files: fstat of the open
// descriptor, ownership, the FIFO exemption and EACCES.
func TestOSFS(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "key")
	if err := os.WriteFile(key, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	r, info, err := OSFS{}.Open(key)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	_ = r.Close()
	if !info.Mode.IsRegular() || info.Mode.Perm() != 0o600 || info.UID != os.Getuid() {
		t.Errorf("info = %+v, want a regular 0600 file owned by uid %d", info, os.Getuid())
	}
	if (OSFS{}).UID() != os.Getuid() {
		t.Errorf("UID = %d, want %d", (OSFS{}).UID(), os.Getuid())
	}
	if _, err := (OSFS{}).Stat(filepath.Join(dir, "nope")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Stat(missing) = %v, want ErrNotExist", err)
	}
	if _, _, err := (OSFS{}).Open(filepath.Join(dir, "nope")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("Open(missing) = %v, want ErrNotExist", err)
	}

	t.Run("loose own file refused through the real FS", func(t *testing.T) {
		loose := filepath.Join(dir, "loose")
		if err := os.WriteFile(loose, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(loose, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readChecked(OSFS{}, loose, maxKeyFile, "key file"); err == nil || !strings.Contains(err.Error(), "are too open") {
			t.Fatalf("err = %v, want the permission refusal", err)
		}
	})
	t.Run("FIFO is exempt", func(t *testing.T) {
		fifo := filepath.Join(dir, "fifo")
		if err := syscall.Mkfifo(fifo, 0o644); err != nil {
			t.Skipf("mkfifo: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
			if err != nil {
				done <- err
				return
			}
			_, err = w.WriteString("secret\n")
			_ = w.Close()
			done <- err
		}()
		b, err := readChecked(OSFS{}, fifo, maxPassphraseFile, "passphrase file")
		if werr := <-done; werr != nil {
			t.Fatalf("writer: %v", werr)
		}
		if err != nil || string(b) != "secret\n" {
			t.Fatalf("readChecked(fifo) = (%q, %v), want the pipe content", b, err)
		}
	})
	t.Run("EACCES through the real FS", func(t *testing.T) {
		if os.Getuid() == 0 {
			t.Skip("root reads everything")
		}
		locked := filepath.Join(dir, "locked")
		if err := os.WriteFile(locked, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		_, err := readChecked(OSFS{}, locked, maxKeyFile, "key file")
		if err == nil || !strings.Contains(err.Error(), "mode 0000") || !strings.Contains(err.Error(), "Container usage") {
			t.Fatalf("err = %v, want the targeted EACCES message", err)
		}
	})
}
