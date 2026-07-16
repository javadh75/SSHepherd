package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

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

// writeFileNoClobber writes data to path with owner-only permissions,
// refusing to replace an existing file unless force is set. The write goes
// to a temp file in the destination directory first — link (no-clobber) or
// rename (force) publishes it, so a failed write can never truncate an
// existing manifest and readers never observe a half-written file.
func writeFileNoClobber(path string, data []byte, force bool) error {
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
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if !force {
		// Link fails with EEXIST when path exists — the same atomic
		// no-clobber guarantee O_EXCL gave the previous in-place write.
		if err := os.Link(tmp.Name(), path); err != nil {
			if os.IsExist(err) {
				return fmt.Errorf("%s already exists; pass --force to overwrite", path)
			}
			return fmt.Errorf("write %s: %w", path, err)
		}
		return nil
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
