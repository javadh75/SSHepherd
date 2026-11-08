package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// Store is the manifest as a run read it: the path given, the resolved file
// (symlinks followed — the save writes there and leaves the link intact),
// and the exact bytes read, which the save's compare-and-swap and plain
// apply's pre-write re-check compare against. A manifest that is not a
// regular file (a pipe: --config /dev/stdin or <(...)) is a Stream: it has
// no resolved path, nothing to re-read and nothing to save to.
type Store struct {
	Path     string
	Resolved string
	Loaded   []byte
	Stream   bool
}

// Read reads the manifest once and, for a regular file, resolves its real
// path. The type comes from the opened descriptor, so a /dev/fd path whose
// /proc link target does not resolve (Linux) still loads.
func Read(path string) (Store, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the user's own --config flag
	if err != nil {
		return Store{}, fmt.Errorf("read manifest: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return Store{}, fmt.Errorf("read manifest: %w", err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return Store{}, fmt.Errorf("read manifest: %w", err)
	}
	s := Store{Path: path, Loaded: data, Stream: !fi.Mode().IsRegular()}
	if s.Stream {
		return s, nil
	}
	if s.Resolved, err = filepath.EvalSymlinks(path); err != nil {
		return Store{}, fmt.Errorf("read manifest: %w", err)
	}
	return s, nil
}

// Unchanged re-reads the resolved file: a manifest that changed since it
// was read (a concurrent revoke, a hand edit, a git pull) must not be
// planned against or overwritten. A stream passes: it cannot be re-read,
// and nothing can replace it under this run.
func (s Store) Unchanged() error {
	if s.Stream {
		return nil
	}
	now, err := os.ReadFile(s.Resolved)
	if err != nil {
		return fmt.Errorf("re-read manifest %s: %w", s.Path, err)
	}
	if !bytes.Equal(now, s.Loaded) {
		return fmt.Errorf("manifest %s changed since it was read; re-run", s.Path)
	}
	return nil
}

// SameAs reports whether path names the very file this Store read (symlinks
// followed): adopt/import -o pointing at the manifest is an in-place update
// and must go through Save. A missing path, a stream and a zero Store are
// never the same. A hard link to the manifest under another name is refused:
// Save renames over the read path only, so the other name would keep the
// old bytes.
func (s Store) SameAs(path string) (bool, error) {
	if s.Stream || s.Resolved == "" {
		return false, nil
	}
	fi, err := os.Stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	mi, err := os.Stat(s.Resolved)
	if err != nil {
		return false, fmt.Errorf("re-read manifest %s: %w", s.Path, err)
	}
	if !os.SameFile(fi, mi) {
		return false, nil
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	same, err := sameEntry(resolved, s.Resolved)
	if err != nil {
		return false, err
	}
	// One link means one name: path is the manifest's own name spelled
	// another way (a case or normalization variant on a case-insensitive
	// filesystem). With more links, only the same directory entry counts.
	if n, ok := linkCount(fi); same || (ok && n == 1) {
		return true, nil
	}
	return false, fmt.Errorf("%s is a hard link to the manifest %s; pass the manifest's own path", path, s.Path)
}

// sameEntry reports whether two symlink-free paths name the same directory
// entry: the same final name in the same directory, however each is spelled
// (relative or absolute, the directory through another path).
func sameEntry(a, b string) (bool, error) {
	var dirs [2]fs.FileInfo
	var bases [2]string
	for i, p := range [2]string{a, b} {
		abs, err := filepath.Abs(p)
		if err != nil {
			return false, fmt.Errorf("resolve %s: %w", p, err)
		}
		bases[i] = filepath.Base(abs)
		if dirs[i], err = os.Stat(filepath.Dir(abs)); err != nil {
			return false, fmt.Errorf("resolve %s: %w", p, err)
		}
	}
	return bases[0] == bases[1] && os.SameFile(dirs[0], dirs[1]), nil
}

// beforeSave is a test seam: it runs at the start of Save, before the lock
// and the compare-and-swap.
var beforeSave = func(Store) {}

// Save replaces the manifest with data, once: under an exclusive
// non-blocking flock on a persistent sidecar (.NAME.sshepherd-lock next to
// the resolved file, never deleted, so the lock outlives the rename's inode
// change), after a compare-and-swap against the bytes read, through an
// O_EXCL temp file in the same directory carrying the original's permission
// bits and owner, fsynced, renamed over the resolved path, directory
// fsynced.
func (s Store) Save(data []byte) error {
	if s.Stream {
		return fmt.Errorf("save manifest %s: not a regular file", s.Path)
	}
	beforeSave(s)
	unlock, err := lock(s.Resolved)
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.Unchanged(); err != nil {
		return err
	}
	fi, err := os.Stat(s.Resolved)
	if err != nil {
		return fmt.Errorf("save manifest %s: %w", s.Path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.Resolved), "."+filepath.Base(s.Resolved)+".tmp-*")
	if err != nil {
		return fmt.Errorf("save manifest %s: %w", s.Path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save manifest %s: %w", s.Path, err)
	}
	if err := keepOwner(tmp, fi); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save manifest %s: %w", s.Path, err)
	}
	if err := writeSynced(tmp, s.Path, data); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.Resolved); err != nil {
		return fmt.Errorf("save manifest %s: %w", s.Path, err)
	}
	return syncDir(s.Resolved)
}

// LockPath is the persistent lock sidecar for a resolved manifest path.
func LockPath(resolved string) string {
	return filepath.Join(filepath.Dir(resolved), "."+filepath.Base(resolved)+".sshepherd-lock")
}

// ErrLocked is returned when another run holds the manifest lock.
var ErrLocked = errors.New("manifest is being updated by another sshepherd run; re-run")

// linkFile is os.Link, swappable so tests can simulate filesystems without
// hard links.
var linkFile = os.Link

// WriteFile writes data to path with owner-only permissions, refusing to
// replace an existing file unless force is set. The write goes to a temp
// file in the destination directory first and is fsynced — link
// (no-clobber) or rename (force) publishes it and the directory is fsynced
// after, so a failed write or a crash can never truncate an existing
// manifest and readers never observe a half-written file. Under force a
// symlinked path is refused rather than replaced by a regular file (or
// written through). On filesystems without hard links (exFAT, some SMB/FUSE
// mounts) no-clobber falls back to an O_EXCL create — still never
// clobbering, but no longer atomic for readers.
func WriteFile(path string, data []byte, force bool) error {
	if force {
		if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink; refusing to replace it — pass the link's target path instead", path)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once published; cleans up every failure path
	// CreateTemp modes are umask-subject; pin owner-only explicitly.
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := writeSynced(tmp, path, data); err != nil {
		return err
	}
	if !force {
		// Link fails with EEXIST when path exists — the same atomic
		// no-clobber guarantee O_EXCL gave the previous in-place write.
		if err := linkFile(tmp.Name(), path); err != nil {
			switch {
			case os.IsExist(err):
				return fmt.Errorf("%s already exists; pass --force to overwrite", path)
			case errors.Is(err, errors.ErrUnsupported) || errors.Is(err, fs.ErrPermission):
				// No hard links here (EPERM/ENOTSUP): O_EXCL keeps the
				// no-clobber guarantee.
				if err := createExclusive(path, data); err != nil {
					return err
				}
			default:
				return fmt.Errorf("write %s: %w", path, err)
			}
		}
		return syncDir(path)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return syncDir(path)
}

// writeSynced writes data to f, fsyncs and closes it — the data must be on
// disk before the name is published, or a crash can leave an empty file
// under the manifest's name. Errors name path, the destination.
func writeSynced(f *os.File, path string, data []byte) error {
	_, err := f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// createExclusive is the no-hard-link fallback: create path with O_EXCL
// (refusing an existing file) and write it in place, removing the partial
// file — which this call created — on failure.
func createExclusive(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- path is the user's own --output flag
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; pass --force to overwrite", path)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := writeSynced(f, path, data); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

// syncDir fsyncs path's parent directory so the published name survives a
// crash. Filesystems that cannot sync a directory (EINVAL/ENOTSUP) are
// tolerated: the file itself is already durable.
func syncDir(path string) error {
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("sync %s: %w", filepath.Dir(path), err)
	}
	err = d.Sync()
	_ = d.Close()
	if err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, errors.ErrUnsupported) {
		return fmt.Errorf("sync %s: %w", filepath.Dir(path), err)
	}
	return nil
}
