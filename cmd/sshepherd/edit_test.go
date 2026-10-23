package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadManifestAndUnchanged(t *testing.T) {
	path := writeConfig(t, "users: []\n")
	m, err := readManifest(path)
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if string(m.Loaded) != "users: []\n" || m.Path != path {
		t.Errorf("target = %+v", m)
	}
	if err := m.Unchanged(); err != nil {
		t.Errorf("Unchanged on an untouched file: %v", err)
	}
	if err := os.WriteFile(path, []byte("users: []\n# edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := m.Unchanged(); err == nil || !strings.Contains(err.Error(), "manifest "+path+" changed since it was read; re-run") {
		t.Errorf("Unchanged = %v, want the changed-manifest error", err)
	}
	if _, err := readManifest(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("readManifest of a missing file succeeded")
	}
}
