//go:build linux || darwin

package manifest

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// readTemp writes content to a fresh manifest and reads it back as a Store.
func readTemp(t *testing.T, content string) Store {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sshepherd.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Read(p)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return s
}

func TestReadAndUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sshepherd.yaml")
	if err := os.WriteFile(path, []byte("users: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(s.Loaded) != "users: []\n" || s.Path != path {
		t.Errorf("store = %+v", s)
	}
	if err := s.Unchanged(); err != nil {
		t.Errorf("Unchanged on an untouched file: %v", err)
	}
	if err := os.WriteFile(path, []byte("users: []\n# edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Unchanged(); err == nil || !strings.Contains(err.Error(), "manifest "+path+" changed since it was read; re-run") {
		t.Errorf("Unchanged = %v, want the changed-manifest error", err)
	}
	if _, err := Read(filepath.Join(t.TempDir(), "missing.yaml")); err == nil || !strings.HasPrefix(err.Error(), "read manifest: ") {
		t.Errorf("Read of a missing file = %v, want a read manifest error", err)
	}
}

func TestStoreSave(t *testing.T) {
	s := readTemp(t, "users: []\n")
	if err := s.Save([]byte("users: []\n# saved\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := os.ReadFile(s.Path)
	if err != nil || string(got) != "users: []\n# saved\n" {
		t.Fatalf("manifest = (%q, %v), want the saved bytes", got, err)
	}
	fi, err := os.Stat(LockPath(s.Resolved))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("lock sidecar = (%v, %v), want it kept at mode 0600", fi, err)
	}
	entries, _ := os.ReadDir(filepath.Dir(s.Resolved))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// TestStoreSaveStreamRefused: a stream has nothing to save to.
func TestStoreSaveStreamRefused(t *testing.T) {
	s := Store{Path: "/dev/stdin", Stream: true}
	if err := s.Save([]byte("users: []\n")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Save(stream) = %v, want the not-a-regular-file refusal", err)
	}
	if err := s.Unchanged(); err != nil {
		t.Errorf("Unchanged(stream) = %v, want nil", err)
	}
}

// TestStoreSaveCASConflict: a manifest rewritten between Read and Save is
// never overwritten.
func TestStoreSaveCASConflict(t *testing.T) {
	s := readTemp(t, "users: []\n")
	saved := beforeSave
	beforeSave = func(st Store) {
		if err := os.WriteFile(st.Resolved, []byte("users: []\n# someone else\n"), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeSave = saved })
	err := s.Save([]byte("users: []\n# mine\n"))
	if err == nil || !strings.Contains(err.Error(), "changed since it was read; re-run") {
		t.Fatalf("Save = %v, want the compare-and-swap refusal", err)
	}
	if got, _ := os.ReadFile(s.Path); string(got) != "users: []\n# someone else\n" {
		t.Errorf("manifest = %q, want the concurrent edit kept", got)
	}
}

// TestStoreSaveRace: two saves from the same read race; exactly one lands —
// the other meets the lock or the compare-and-swap.
func TestStoreSaveRace(t *testing.T) {
	for range 20 {
		s := readTemp(t, "users: []\n")
		var wg sync.WaitGroup
		errs := make([]error, 2)
		for i := range 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = s.Save([]byte("users: []\n# writer " + string(rune('A'+i)) + "\n"))
			}()
		}
		wg.Wait()
		ok := 0
		for _, err := range errs {
			switch {
			case err == nil:
				ok++
			case errors.Is(err, ErrLocked), strings.Contains(err.Error(), "changed since it was read"):
			default:
				t.Fatalf("unexpected save error: %v", err)
			}
		}
		if ok != 1 {
			t.Fatalf("%d saves succeeded (errs %v), want exactly one", ok, errs)
		}
	}
}

func TestStoreSaveLockHeld(t *testing.T) {
	s := readTemp(t, "users: []\n")
	unlock, err := lock(s.Resolved)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	defer unlock()
	if err := s.Save([]byte("users: []\n# x\n")); !errors.Is(err, ErrLocked) {
		t.Fatalf("Save = %v, want ErrLocked", err)
	}
	if got, _ := os.ReadFile(s.Path); string(got) != "users: []\n" {
		t.Errorf("manifest changed under a held lock: %q", got)
	}
}

// TestStoreSaveFollowsSymlink: a symlinked manifest in another directory is
// saved at its target (lock and temp file there); the link itself is left
// intact.
func TestStoreSaveFollowsSymlink(t *testing.T) {
	realDir, linkDir := t.TempDir(), t.TempDir()
	target := filepath.Join(realDir, "fleet.yaml")
	if err := os.WriteFile(target, []byte("users: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "sshepherd.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	s, err := Read(link)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if err := s.Save([]byte("users: []\n# saved\n")); err != nil {
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

// TestStoreSaveKeepsMode: a 0640 manifest stays 0640 under umask 077 — the
// temp file's mode is set explicitly, not left to the umask.
func TestStoreSaveKeepsMode(t *testing.T) {
	s := readTemp(t, "users: []\n")
	if err := os.Chmod(s.Resolved, 0o640); err != nil {
		t.Fatal(err)
	}
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	if err := s.Save([]byte("users: []\n# saved\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fi, err := os.Stat(s.Resolved)
	if err != nil || fi.Mode().Perm() != 0o640 {
		t.Errorf("mode = %v (%v), want 0640", fi.Mode().Perm(), err)
	}
}

// TestStoreSameAs: -o naming the manifest read (directly or through a
// symlink) is the same file; anything else is not; a hard link under
// another name is refused.
func TestStoreSameAs(t *testing.T) {
	s := readTemp(t, "users: []\n")
	dir := t.TempDir()
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(s.Resolved, link); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(dir, "other.yaml")
	if err := os.WriteFile(other, []byte("users: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(filepath.Dir(s.Resolved), "hard.yaml")
	if err := os.Link(s.Resolved, hard); err != nil {
		t.Fatal(err)
	}
	stream := Store{Path: "/dev/stdin", Stream: true}
	for _, tc := range []struct {
		name    string
		store   Store
		path    string
		want    bool
		wantErr string
	}{
		{"same path", s, s.Path, true, ""},
		{"symlink to the manifest", s, link, true, ""},
		{"different existing file", s, other, false, ""},
		{"missing path", s, filepath.Join(dir, "missing.yaml"), false, ""},
		{"zero store", Store{}, s.Path, false, ""},
		{"stream store", stream, s.Path, false, ""},
		{"hard link to the manifest", s, hard, false, "hard link"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.store.SameAs(tc.path)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("SameAs = (%v, %v), want an error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("SameAs = (%v, %v), want (%v, nil)", got, err, tc.want)
			}
		})
	}
}

// A planted symlink at the lock name is never followed or created through.
func TestStoreLockRefusesSymlink(t *testing.T) {
	s := readTemp(t, "users: []\n")
	victim := filepath.Join(t.TempDir(), "nologin")
	if err := os.Symlink(victim, LockPath(s.Resolved)); err != nil {
		t.Fatal(err)
	}
	err := s.Save([]byte("users: []\n# x\n"))
	if err == nil || !strings.Contains(err.Error(), "is a symlink") {
		t.Fatalf("Save = %v, want the symlinked-lock refusal", err)
	}
	if _, err := os.Lstat(victim); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("symlink target was created: %v", err)
	}
	if got, _ := os.ReadFile(s.Path); string(got) != "users: []\n" {
		t.Errorf("manifest changed: %q", got)
	}
}

// A FIFO (or any non-regular file) at the lock name is refused without blocking.
func TestStoreLockRefusesNonRegular(t *testing.T) {
	s := readTemp(t, "users: []\n")
	if err := syscall.Mkfifo(LockPath(s.Resolved), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("users: []\n# x\n")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("Save = %v, want the non-regular lock refusal", err)
	}
}

// A lock owned by someone who is neither this euid nor the manifest's owner
// is refused; the seam stands in for a lock planted by another uid.
func TestStoreLockRefusesForeignOwner(t *testing.T) {
	s := readTemp(t, "users: []\n")
	lockFile := LockPath(s.Resolved)
	if err := os.WriteFile(lockFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	saved := ownerOf
	ownerOf = func(fi fs.FileInfo) (int, int, bool) {
		uid, gid, ok := saved(fi)
		if fi.Name() == filepath.Base(lockFile) {
			uid = 4242
		}
		return uid, gid, ok
	}
	t.Cleanup(func() { ownerOf = saved })
	if err := s.Save([]byte("users: []\n# x\n")); err == nil || !strings.Contains(err.Error(), "owned by uid 4242") {
		t.Fatalf("Save = %v, want the foreign-owner refusal", err)
	}
}

// sudo on your own manifest: euid differs, but the lock's owner is the
// manifest's owner — accepted (no regression for `sudo sshepherd revoke`).
func TestStoreLockAcceptsManifestOwner(t *testing.T) {
	s := readTemp(t, "users: []\n")
	saved := geteuid
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = saved })
	if err := s.Save([]byte("users: []\n# x\n")); err != nil {
		t.Fatalf("Save = %v, want success for a lock owned by the manifest's owner", err)
	}
}

// otherGroup returns a supplementary group of this process other than its
// egid, or skips: chgrp to it needs no root.
func otherGroup(t *testing.T) int {
	t.Helper()
	gs, err := os.Getgroups()
	if err != nil {
		t.Skipf("getgroups: %v", err)
	}
	for _, g := range gs {
		if g != os.Getegid() {
			return g
		}
	}
	t.Skip("runner has no supplementary group; keepOwner chgrp path not testable without root")
	return 0
}

func gidOf(t *testing.T, path string) int {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, gid, _ := ownerOf(fi)
	return gid
}

// (a) A manifest chgrp'd to a supplementary group keeps that gid on Save.
func TestStoreSaveKeepsGroup(t *testing.T) {
	g := otherGroup(t)
	s := readTemp(t, "users: []\n")
	if err := os.Chown(s.Resolved, -1, g); err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("users: []\n# x\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got := gidOf(t, s.Resolved); got != g {
		t.Errorf("gid = %d, want %d kept", got, g)
	}
}

// (b) The directory hands new files a different group (BSD inheritance on
// darwin; a setgid directory on Linux) while the manifest has the process's
// own egid: before the fix keepOwner skipped (orig == process ids) and the
// gid silently changed.
func TestStoreSaveKeepsGroupUnderDirInheritance(t *testing.T) {
	g := otherGroup(t)
	dir := t.TempDir()
	if err := os.Chown(dir, -1, g); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o2700); err != nil { // setgid: Linux inherits like BSD
		t.Fatal(err)
	}
	p := filepath.Join(dir, "sshepherd.yaml")
	if err := os.WriteFile(p, []byte("users: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(p, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	s, err := Read(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save([]byte("users: []\n# x\n")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if got := gidOf(t, p); got != os.Getegid() {
		t.Errorf("gid = %d, want the manifest's %d kept (dir group %d leaked in)", got, os.Getegid(), g)
	}
}

// (c) A failing chown refuses the save before the rename: manifest untouched,
// no temp file left.
func TestStoreSaveChownFailureRefuses(t *testing.T) {
	g := otherGroup(t)
	s := readTemp(t, "users: []\n")
	if err := os.Chown(s.Resolved, -1, g); err != nil {
		t.Fatal(err)
	}
	saved := chown
	chown = func(*os.File, int, int) error { return syscall.EPERM }
	t.Cleanup(func() { chown = saved })
	err := s.Save([]byte("users: []\n# x\n"))
	if err == nil || !strings.Contains(err.Error(), "would change the manifest's owner") {
		t.Fatalf("Save = %v, want the owner refusal", err)
	}
	if got, _ := os.ReadFile(s.Path); string(got) != "users: []\n" {
		t.Errorf("manifest changed: %q", got)
	}
	entries, _ := os.ReadDir(filepath.Dir(s.Resolved))
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Errorf("temp file left behind: %s", e.Name())
		}
	}
}

// A filesystem that reports no uid/gid (ownerOf !ok) skips the ownership
// checks rather than refusing: the save lands and nothing is chowned.
func TestStoreSaveWithoutOwnerInfo(t *testing.T) {
	s := readTemp(t, "users: []\n")
	savedOwner, savedChown := ownerOf, chown
	ownerOf = func(fs.FileInfo) (int, int, bool) { return 0, 0, false }
	chown = func(*os.File, int, int) error { t.Error("chown called without owner info"); return nil }
	t.Cleanup(func() { ownerOf, chown = savedOwner, savedChown })
	if err := s.Save([]byte("users: []\n# x\n")); err != nil {
		t.Fatalf("Save = %v, want success", err)
	}
}

// A --force overwrite that cannot complete must leave the destination file
// untouched: the write goes to a temp file first and only a successful write
// is renamed into place. Making the directory unwritable blocks the temp
// file; the old in-place O_TRUNC write would have destroyed the original.
func TestWriteFileFailedForceOverwriteKeepsDestination(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.yaml")
	if err := os.WriteFile(dest, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	if err := WriteFile(dest, []byte("replacement\n"), true); err == nil {
		t.Fatal("WriteFile(force) = nil in a read-only directory, want error (atomic replace needs a writable directory)")
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
func TestWriteFileTempFileHygiene(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "out.yaml")

	if err := WriteFile(dest, []byte("first\n"), false); err != nil {
		t.Fatalf("fresh write: %v", err)
	}
	err := WriteFile(dest, []byte("second\n"), false)
	if err == nil || err.Error() != dest+" already exists; pass --force to overwrite" {
		t.Errorf("no-force overwrite = %v, want the already-exists refusal", err)
	}
	if err := WriteFile(dest, []byte("third\n"), true); err != nil {
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
func TestWriteFileForceRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	if err := os.WriteFile(target, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := WriteFile(link, []byte("replacement\n"), true)
	if err == nil || err.Error() != link+" is a symlink; refusing to replace it — pass the link's target path instead" {
		t.Fatalf("WriteFile(symlink, force) = %v, want a symlink refusal", err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("link replaced: Lstat = %v, %v", fi, err)
	}
	if got, _ := os.ReadFile(target); string(got) != "original\n" {
		t.Errorf("target = %q, want untouched", got)
	}
	// Without --force a symlink is an existing name: the usual refusal.
	if err := WriteFile(link, []byte("x\n"), false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Errorf("no-force write over symlink = %v, want already-exists refusal", err)
	}
}

// On filesystems without hard links (Link fails EPERM/ENOTSUP) the
// no-clobber write falls back to an O_EXCL create instead of failing — and
// still refuses an existing file.
func TestWriteFileLinkUnsupportedFallsBack(t *testing.T) {
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
			if err := WriteFile(dest, []byte("first\n"), false); err != nil {
				t.Fatalf("fallback write: %v", err)
			}
			got, err := os.ReadFile(dest)
			if err != nil || string(got) != "first\n" {
				t.Fatalf("content = %q, %v; want first", got, err)
			}
			if info, err := os.Stat(dest); err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("mode = %v, %v; want 600", info, err)
			}
			err = WriteFile(dest, []byte("second\n"), false)
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
