//go:build !linux && !darwin

package manifest

import (
	"errors"
	"io/fs"
	"os"
)

// lock is unavailable off linux/darwin: without flock the save cannot
// exclude a concurrent run, so revoke/rotate refuse to save.
func lock(string) (func(), error) {
	return nil, errors.New("saving the manifest needs flock, available on linux and darwin only")
}

// linkCount is unknown here: SameAs then trusts only the same directory
// entry.
func linkCount(fs.FileInfo) (uint64, bool) { return 0, false }

// keepOwner is a no-op where lock already refuses.
func keepOwner(*os.File, fs.FileInfo) error { return nil }
