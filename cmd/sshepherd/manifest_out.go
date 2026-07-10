package main

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// serverOut/userOut/accessOut mirror the config types for output: omitempty
// keeps default ports and never-set fields out of the generated YAML. Shared
// by every command that emits a manifest (import, adopt).
type serverOut struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Host        string `yaml:"host"`
	Port        int    `yaml:"port,omitempty"`
	User        string `yaml:"user"`
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
// refusing to replace an existing file unless force is set.
func writeFileNoClobber(path string, data []byte, force bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if !force {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0o600) // #nosec G304 -- path is the user's own -o flag
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("%s already exists; pass --force to overwrite", path)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	// The mode above only applies at creation; a --force overwrite via
	// O_TRUNC would keep the existing file's permissions, so pin them.
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}
