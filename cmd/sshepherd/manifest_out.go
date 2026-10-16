package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"gopkg.in/yaml.v3"
)

// serverOut/userOut/accessOut mirror the config types for output: omitempty
// keeps default ports and never-set fields out of the generated YAML. Shared
// by every command that emits a manifest (import, adopt).
type serverOut struct {
	Name               string `yaml:"name"`
	Description        string `yaml:"description,omitempty"`
	Host               string `yaml:"host"`
	Port               int    `yaml:"port,omitempty"`
	User               string `yaml:"user"`
	AuthorizedKeysFile string `yaml:"authorized_keys_file,omitempty"`
}

type userOut struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	Comment     string   `yaml:"comment,omitempty"`
	Operator    bool     `yaml:"operator,omitempty"`
	Keys        []string `yaml:"keys"`
}

type accessOut struct {
	User    string   `yaml:"user"`
	Servers []string `yaml:"servers"`
	Except  []string `yaml:"except,omitempty"`
}

type manifestOut struct {
	Users   []userOut   `yaml:"users"`
	Servers []serverOut `yaml:"servers"`
	Access  []accessOut `yaml:"access"`
}

// encodeManifest renders a manifest preceded by a raw header comment block
// (the header must supply its own trailing newline).
func encodeManifest(header string, m manifestOut) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(m); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	return buf.Bytes(), nil
}

// linkFile is os.Link, swappable so tests can simulate filesystems without
// hard links.
var linkFile = os.Link

// writeFileNoClobber writes data to path with owner-only permissions,
// refusing to replace an existing file unless force is set. The write goes
// to a temp file in the destination directory first and is fsynced — link
// (no-clobber) or rename (force) publishes it and the directory is fsynced
// after, so a failed write or a crash can never truncate an existing
// manifest and readers never observe a half-written file. Under force a
// symlinked path is refused rather than replaced by a regular file (or
// written through). On filesystems without hard links (exFAT, some SMB/FUSE
// mounts) no-clobber falls back to an O_EXCL create — still never
// clobbering, but no longer atomic for readers.
func writeFileNoClobber(path string, data []byte, force bool) error {
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
