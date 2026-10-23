package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

// runFlags are the flags apply, revoke and rotate share, registered with
// apply's defaults and help text (apply adds --server on top).
type runFlags struct {
	cfgPath    string
	knownHosts string
	parallel   int
	dryRun     bool
	yes        bool
	idf        identityFlags
}

// register declares the shared flags on cmd.
func (f *runFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.cfgPath, "config", "sshepherd.yaml", "path to the manifest")
	cmd.Flags().StringVar(&f.knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&f.parallel, "parallel", defaultParallel, "max concurrent server connections")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "plan and report only; never write")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "skip the confirmation prompt (automation)")
	cmd.MarkFlagsMutuallyExclusive("dry-run", "yes")
	f.idf.register(cmd)
}

// manifestTarget is the manifest as a run read it: the path given, the
// resolved file (symlinks followed — the save writes there and leaves the
// link intact), and the exact bytes read, which the save's compare-and-swap
// and plain apply's pre-write re-check compare against. A manifest that is
// not a regular file (a pipe: --config /dev/stdin or <(...)) is a Stream:
// it has no resolved path, nothing to re-read and nothing to save to.
type manifestTarget struct {
	Path     string
	Resolved string
	Loaded   []byte
	Stream   bool
}

// readManifest reads the manifest once and, for a regular file, resolves
// its real path. The type comes from the opened descriptor, so a /dev/fd
// path whose /proc link target does not resolve (Linux) still loads.
func readManifest(path string) (manifestTarget, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the user's own --config flag
	if err != nil {
		return manifestTarget{}, fmt.Errorf("read manifest: %w", err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return manifestTarget{}, fmt.Errorf("read manifest: %w", err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return manifestTarget{}, fmt.Errorf("read manifest: %w", err)
	}
	m := manifestTarget{Path: path, Loaded: data, Stream: !fi.Mode().IsRegular()}
	if m.Stream {
		return m, nil
	}
	if m.Resolved, err = filepath.EvalSymlinks(path); err != nil {
		return manifestTarget{}, fmt.Errorf("read manifest: %w", err)
	}
	return m, nil
}

// Unchanged re-reads the resolved file: a manifest that changed since it
// was read (a concurrent revoke, a hand edit, a git pull) must not be
// planned against or overwritten. A stream passes: it cannot be re-read,
// and nothing can replace it under this run.
func (m manifestTarget) Unchanged() error {
	if m.Stream {
		return nil
	}
	now, err := os.ReadFile(m.Resolved)
	if err != nil {
		return fmt.Errorf("re-read manifest %s: %w", m.Path, err)
	}
	if !bytes.Equal(now, m.Loaded) {
		return fmt.Errorf("manifest %s changed since it was read; re-run", m.Path)
	}
	return nil
}

// beforeManifestSave is a test seam: it runs at the start of Save, before
// the lock and the compare-and-swap.
var beforeManifestSave = func(manifestTarget) {}

// Save replaces the manifest with data, once: under an exclusive
// non-blocking flock on a persistent sidecar (.NAME.sshepherd-lock next to
// the resolved file, never deleted, so the lock outlives the rename's inode
// change), after a compare-and-swap against the bytes read, through an
// O_EXCL temp file in the same directory carrying the original's permission
// bits and owner, fsynced, renamed over the resolved path, directory
// fsynced.
func (m manifestTarget) Save(data []byte) error {
	if m.Stream {
		return fmt.Errorf("save manifest %s: not a regular file", m.Path)
	}
	beforeManifestSave(m)
	unlock, err := lockManifest(m.Resolved)
	if err != nil {
		return err
	}
	defer unlock()
	if err := m.Unchanged(); err != nil {
		return err
	}
	fi, err := os.Stat(m.Resolved)
	if err != nil {
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(m.Resolved), "."+filepath.Base(m.Resolved)+".tmp-*")
	if err != nil {
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op once renamed
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	if err := keepOwner(tmp, fi); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	if err := writeSynced(tmp, m.Path, data); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), m.Resolved); err != nil {
		return fmt.Errorf("save manifest %s: %w", m.Path, err)
	}
	return syncDir(m.Resolved)
}

// lockPath is the persistent lock sidecar for a resolved manifest path.
func lockPath(resolved string) string {
	return filepath.Join(filepath.Dir(resolved), "."+filepath.Base(resolved)+".sshepherd-lock")
}

// errManifestLocked is returned when another run holds the manifest lock.
var errManifestLocked = errors.New("manifest is being updated by another sshepherd run; re-run")
