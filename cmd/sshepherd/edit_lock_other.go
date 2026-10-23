//go:build !linux && !darwin

package main

import (
	"errors"
	"io/fs"
	"os"
)

// lockManifest is unavailable off linux/darwin: without flock the save
// cannot exclude a concurrent run, so revoke/rotate refuse to save.
func lockManifest(string) (func(), error) {
	return nil, errors.New("saving the manifest needs flock, available on linux and darwin only")
}

// keepOwner is a no-op where lockManifest already refuses.
func keepOwner(*os.File, fs.FileInfo) error { return nil }
