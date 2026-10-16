package main

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// Adopt must copy an existing wildcard entry's except: carve-out through to
// the generated manifest; entries without except must not emit the key.
func TestEncodeManifestExceptRoundTrip(t *testing.T) {
	m := manifestOut{
		Users: []userOut{
			{Name: "alice", Keys: []string{testkeys.Line(t, 1)}},
			{Name: "bob", Keys: []string{testkeys.Line(t, 2)}},
		},
		Servers: []serverOut{
			{Name: "db-1", Host: "10.0.0.2", User: "deploy"},
			{Name: "web-1", Host: "10.0.0.1", User: "deploy"},
		},
		Access: []accessOut{
			{User: "alice", Servers: []string{"*"}, Except: []string{"db-1"}},
			{User: "bob", Servers: []string{"web-1"}},
		},
	}
	got, err := encodeManifest("# header\n", m)
	if err != nil {
		t.Fatalf("encodeManifest: %v", err)
	}
	if !strings.HasPrefix(string(got), "# header\n") {
		t.Errorf("output %q lacks the header", got)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("round-trip rejected by config.Parse: %v", err)
	}
	if len(c.Access) != 2 || len(c.Access[0].Except) != 1 || c.Access[0].Except[0] != "db-1" {
		t.Errorf("Access = %+v, want alice's except [db-1] preserved", c.Access)
	}
	if strings.Contains(string(got), "except: []") {
		t.Errorf("output %q emits an explicit empty except for bob", got)
	}
}

// A --force overwrite that cannot complete must leave the destination file
// untouched: the write goes to a temp file first and only a successful write
// is renamed into place. Making the directory unwritable blocks the temp
// file; the old in-place O_TRUNC write would have destroyed the original.
func TestWriteFileNoClobberFailedForceOverwriteKeepsDestination(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.yaml")
	if err := os.WriteFile(dest, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := writeFileNoClobber(dest, []byte("replacement\n"), true); err == nil {
		t.Fatal("writeFileNoClobber(force) = nil in a read-only directory, want error (atomic replace needs a writable directory)")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read destination back: %v", err)
	}
	if string(got) != "original\n" {
		t.Errorf("destination = %q after failed overwrite, want original content intact", got)
	}
}

// Success and refusal paths must not litter the output directory with temp
// files, and the no-clobber contract must survive the temp-file rewrite:
// an existing file without --force refuses with the actionable message, and
// a forced overwrite lands with owner-only permissions.
func TestWriteFileNoClobberTempFileHygiene(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.yaml")

	if err := writeFileNoClobber(dest, []byte("first\n"), false); err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	err := writeFileNoClobber(dest, []byte("second\n"), false)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("no-force overwrite = %v, want refusal mentioning --force", err)
	}
	if err := writeFileNoClobber(dest, []byte("third\n"), true); err != nil {
		t.Fatalf("forced overwrite: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "third\n" {
		t.Errorf("content = %q, want %q", got, "third\n")
	}
	info, err := os.Stat(dest)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "out.yaml" {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("directory contains %v, want only out.yaml (no temp leftovers)", names)
	}
}

// --force must never replace a symlinked manifest with a regular file (nor
// silently write through it): it refuses, leaving link and target intact.
func TestWriteFileNoClobberForceRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, []byte("original\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := writeFileNoClobber(link, []byte("replacement\n"), true)
	if err == nil || !strings.Contains(err.Error(), "is a symlink") {
		t.Fatalf("writeFileNoClobber(symlink, force) = %v, want a symlink refusal", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("link replaced: Lstat = %v, %v", fi, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "original\n" {
		t.Errorf("target = %q, want untouched", got)
	}
	// Without --force a symlink is an existing name: the usual refusal.
	if err := writeFileNoClobber(link, []byte("x\n"), false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("no-force write over symlink = %v, want already-exists refusal", err)
	}
}

// On filesystems without hard links (Link fails EPERM/ENOTSUP) the
// no-clobber write falls back to an O_EXCL create instead of failing — and
// still refuses an existing file.
func TestWriteFileNoClobberLinkUnsupportedFallsBack(t *testing.T) {
	for name, linkErr := range map[string]error{
		"EPERM":   syscall.EPERM,
		"ENOTSUP": syscall.ENOTSUP,
	} {
		t.Run(name, func(t *testing.T) {
			orig := linkFile
			linkFile = func(oldname, newname string) error {
				return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: linkErr}
			}
			t.Cleanup(func() { linkFile = orig })
			dir := t.TempDir()
			dest := filepath.Join(dir, "out.yaml")
			if err := writeFileNoClobber(dest, []byte("first\n"), false); err != nil {
				t.Fatalf("fallback write: %v", err)
			}
			got, err := os.ReadFile(dest)
			if err != nil || string(got) != "first\n" {
				t.Fatalf("content = %q, %v; want first", got, err)
			}
			if info, err := os.Stat(dest); err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("mode = %v, %v; want 600", info, err)
			}
			err = writeFileNoClobber(dest, []byte("second\n"), false)
			if err == nil || !strings.Contains(err.Error(), "--force") {
				t.Errorf("fallback over existing file = %v, want refusal mentioning --force", err)
			}
			if got, _ := os.ReadFile(dest); string(got) != "first\n" {
				t.Errorf("content = %q after refused fallback, want first", got)
			}
			if entries, _ := os.ReadDir(dir); len(entries) != 1 {
				t.Errorf("directory has %d entries, want only out.yaml", len(entries))
			}
		})
	}
}
