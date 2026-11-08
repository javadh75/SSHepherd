//go:build linux || darwin

package manifest

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// Seams: ownerOf reads uid/gid from a FileInfo; geteuid is os.Geteuid.
var (
	ownerOf = func(fi fs.FileInfo) (uid, gid int, ok bool) {
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, false
		}
		return int(st.Uid), int(st.Gid), true
	}
	geteuid = os.Geteuid
)

// lock takes an exclusive, non-blocking flock on the manifest's persistent
// sidecar (mode 0600, never deleted). The sidecar is opened without
// following a symlink (O_NOFOLLOW) and without blocking on a planted FIFO
// (O_NONBLOCK), and must be a regular file owned by this euid or by the
// manifest's owner (so `sudo` on your own manifest still works); anything
// else is refused, never created through. A held lock is ErrLocked; the
// returned func releases it.
func lock(resolved string) (func(), error) {
	path := LockPath(resolved)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600) // #nosec G304 -- sidecar next to the user's own manifest
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("lock manifest: %s is a symlink; refusing to follow it — remove it and re-run", path)
		}
		return nil, fmt.Errorf("lock manifest: %w", err)
	}
	if err := checkLockFile(f, path, resolved); err != nil {
		_ = f.Close()
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- fd fits an int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock manifest %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // #nosec G115 -- fd fits an int
		_ = f.Close()
	}, nil
}

// checkLockFile refuses a lock sidecar that is not a regular file, or that
// is owned by neither this euid nor the manifest's owner (a lock planted by
// a third uid).
func checkLockFile(f *os.File, path, resolved string) error {
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("lock manifest %s: %w", path, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("lock manifest: %s is not a regular file — remove it and re-run", path)
	}
	uid, _, ok := ownerOf(fi)
	if !ok || uid == geteuid() {
		return nil
	}
	if mi, err := os.Stat(resolved); err == nil {
		if muid, _, ok := ownerOf(mi); ok && muid == uid {
			return nil
		}
	}
	return fmt.Errorf("lock manifest: %s is owned by uid %d, not by you (uid %d) or the manifest's owner — remove it and re-run", path, uid, geteuid())
}

// linkCount is the file's hard-link count.
func linkCount(fi fs.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true // #nosec G115 -- widening: Nlink is uint16 (darwin) or uint64 (linux)
}

// chown is (*os.File).Chown, swappable to force the refusal path in tests.
var chown = (*os.File).Chown

// keepOwner gives tmp the original manifest's uid/gid whenever tmp did not
// get them already (process ids, BSD/setgid directory inheritance); a failed
// chown refuses the save before the rename rather than silently changing the
// manifest's owner.
func keepOwner(tmp *os.File, orig fs.FileInfo) error {
	uid, gid, ok := ownerOf(orig)
	if !ok {
		return nil
	}
	ti, err := tmp.Stat()
	if err != nil {
		return fmt.Errorf("stat temp file: %w", err)
	}
	if tuid, tgid, ok := ownerOf(ti); ok && tuid == uid && tgid == gid {
		return nil
	}
	if err := chown(tmp, uid, gid); err != nil {
		return fmt.Errorf("would change the manifest's owner (%d:%d): %w", uid, gid, err)
	}
	return nil
}
