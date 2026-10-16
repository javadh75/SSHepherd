//go:build !unix

package keyfile

import (
	"errors"
	"io"
)

// OSFS is unavailable off unix: key-file ownership and modes cannot be
// checked there, so --identity is refused rather than read unchecked.
type OSFS struct{}

var _ FS = OSFS{}

var errUnsupportedOS = errors.New("--identity key files are supported on unix only")

// Open always fails off unix.
func (OSFS) Open(string) (io.ReadCloser, FileInfo, error) { return nil, FileInfo{}, errUnsupportedOS }

// Stat always fails off unix.
func (OSFS) Stat(string) (FileInfo, error) { return FileInfo{}, errUnsupportedOS }

// UID is unknown off unix.
func (OSFS) UID() int { return -1 }
