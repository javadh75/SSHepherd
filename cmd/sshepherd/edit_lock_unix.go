//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// lockManifest takes an exclusive, non-blocking flock on the manifest's
// persistent sidecar (mode 0600, never deleted). A held lock is
// errManifestLocked; the returned func releases it.
func lockManifest(resolved string) (func(), error) {
	path := lockPath(resolved)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- sidecar next to the user's own manifest
	if err != nil {
		return nil, fmt.Errorf("lock manifest: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- fd fits an int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, errManifestLocked
		}
		return nil, fmt.Errorf("lock manifest %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // #nosec G115 -- fd fits an int
		_ = f.Close()
	}, nil
}

// keepOwner gives tmp the original manifest's uid/gid when they differ
// from the process's; a failed chown refuses the save before the rename
// rather than silently changing the manifest's owner.
func keepOwner(tmp *os.File, orig fs.FileInfo) error {
	st, ok := orig.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid, gid := int(st.Uid), int(st.Gid)
	if uid == os.Getuid() && gid == os.Getgid() {
		return nil
	}
	if err := tmp.Chown(uid, gid); err != nil {
		return fmt.Errorf("would change the manifest's owner (%d:%d): %w", uid, gid, err)
	}
	return nil
}
