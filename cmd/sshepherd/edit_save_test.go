//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// saveTarget writes content to a fresh manifest and reads it back as a
// target.
func saveTarget(t *testing.T, content string) manifestTarget {
	t.Helper()
	m, err := readManifest(writeConfig(t, content))
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	return m
}

func TestManifestSave(t *testing.T) {
	m := saveTarget(t, "users: []\n")
	if err := m.Save([]byte("users: []\n# saved\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := os.ReadFile(m.Path)
	if err != nil || string(got) != "users: []\n# saved\n" {
		t.Fatalf("manifest = (%q, %v), want the saved bytes", got, err)
	}
	fi, err := os.Stat(lockPath(m.Resolved))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("lock sidecar = (%v, %v), want it kept at mode 0600", fi, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(m.Resolved))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestManifestSaveCASConflict: a manifest rewritten between the read and
// the save (the seam stands in for a concurrent editor) is never
// overwritten.
func TestManifestSaveCASConflict(t *testing.T) {
	m := saveTarget(t, "users: []\n")
	saved := beforeManifestSave
	beforeManifestSave = func(mt manifestTarget) {
		if err := os.WriteFile(mt.Resolved, []byte("users: []\n# someone else\n"), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeManifestSave = saved })
	err := m.Save([]byte("users: []\n# mine\n"))
	if err == nil || !strings.Contains(err.Error(), "changed since it was read; re-run") {
		t.Fatalf("Save = %v, want the compare-and-swap refusal", err)
	}
	if got, _ := os.ReadFile(m.Path); string(got) != "users: []\n# someone else\n" {
		t.Errorf("manifest = %q, want the concurrent edit kept", got)
	}
}

// TestManifestSaveRace: two saves from the same read race; exactly one
// lands — the other meets the lock or the compare-and-swap.
func TestManifestSaveRace(t *testing.T) {
	for range 20 {
		m := saveTarget(t, "users: []\n")
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = m.Save([]byte("users: []\n# writer " + string(rune('A'+i)) + "\n"))
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, errManifestLocked), strings.Contains(err.Error(), "changed since it was read"):
			default:
				t.Fatalf("unexpected save error: %v", err)
			}
		}
		if ok != 1 {
			t.Fatalf("%d saves succeeded (errs %v), want exactly one", ok, errs)
		}
	}
}

func TestManifestSaveLockHeld(t *testing.T) {
	m := saveTarget(t, "users: []\n")
	unlock, err := lockManifest(m.Resolved)
	if err != nil {
		t.Fatalf("lockManifest: %v", err)
	}
	defer unlock()
	if err := m.Save([]byte("users: []\n# x\n")); !errors.Is(err, errManifestLocked) {
		t.Fatalf("Save = %v, want errManifestLocked", err)
	}
	if got, _ := os.ReadFile(m.Path); string(got) != "users: []\n" {
		t.Errorf("manifest changed under a held lock: %q", got)
	}
}

// TestManifestSaveFollowsSymlink: a symlinked manifest in another
// directory is saved at its target (lock and temp file there); the link
// itself is left intact.
func TestManifestSaveFollowsSymlink(t *testing.T) {
	realDir, linkDir := t.TempDir(), t.TempDir()
	target := filepath.Join(realDir, "fleet.yaml")
	if err := os.WriteFile(target, []byte("users: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "sshepherd.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	m, err := readManifest(link)
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if err := m.Save([]byte("users: []\n# saved\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("link replaced: %v %v", fi, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "users: []\n# saved\n" {
		t.Errorf("target = %q, want the saved bytes", got)
	}
	resolvedDir, _ := filepath.EvalSymlinks(realDir)
	if _, err := os.Stat(filepath.Join(resolvedDir, ".fleet.yaml.sshepherd-lock")); err != nil {
		t.Errorf("lock sidecar not next to the target: %v", err)
	}
	if entries, _ := os.ReadDir(linkDir); len(entries) != 1 {
		t.Errorf("link directory gained files: %v", entries)
	}
}

// TestManifestSaveKeepsMode: a 0640 manifest stays 0640 under umask 077 —
// the temp file's mode is set explicitly, not left to the umask.
func TestManifestSaveKeepsMode(t *testing.T) {
	m := saveTarget(t, "users: []\n")
	if err := os.Chmod(m.Resolved, 0o640); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	if err := m.Save([]byte("users: []\n# saved\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(m.Resolved)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v (%v), want 0640", fi.Mode().Perm(), err)
	}
}
