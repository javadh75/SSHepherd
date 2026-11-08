package main

import (
	"path/filepath"
	"testing"
)

// TestReadManifestAdapter: readManifest hands back the store's read (the
// Store contract itself is tested in internal/manifest).
func TestReadManifestAdapter(t *testing.T) {
	path := writeConfig(t, "users: []\n")
	m, err := readManifest(path)
	if err != nil || string(m.Loaded) != "users: []\n" || m.Path != path || m.Unchanged() != nil {
		t.Fatalf("readManifest = %+v, %v; want the bytes read, unchanged", m, err)
	}
	if _, err := readManifest(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("readManifest of a missing file succeeded")
	}
}
