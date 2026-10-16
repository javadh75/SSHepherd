//go:build unix

package keyfile

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// OSFS is the real FS: os.Open plus fstat of the opened descriptor.
type OSFS struct{}

var _ FS = OSFS{}

// Open opens path once and returns it with the fstat of that descriptor.
func (OSFS) Open(path string) (io.ReadCloser, FileInfo, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own --identity / passphrase-file path
	if err != nil {
		return nil, FileInfo{}, fmt.Errorf("open: %w", err)
	}
	fi, err := f.Stat() // fstat: the descriptor we will read, not the path
	if err != nil {
		_ = f.Close()
		return nil, FileInfo{}, fmt.Errorf("fstat %s: %w", path, err)
	}
	return f, infoOf(fi), nil
}

// Stat stats path (diagnostics only — never used to decide what to read).
func (OSFS) Stat(path string) (FileInfo, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return FileInfo{}, fmt.Errorf("stat: %w", err)
	}
	return infoOf(fi), nil
}

// UID is the process's real uid.
func (OSFS) UID() int { return os.Getuid() }

func infoOf(fi fs.FileInfo) FileInfo {
	info := FileInfo{Mode: fi.Mode(), UID: -1}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		info.UID = int(st.Uid)
	}
	return info
}
