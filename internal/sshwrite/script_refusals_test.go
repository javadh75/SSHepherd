package sshwrite

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const (
	staleBak = "ssh-ed25519 AAAA revoked-key-from-last-year\n"
	victimTx = "victim\n"
)

// sandbox is a HOME holding the target's name, not yet the target.
func sandbox(t *testing.T) (home, target string) {
	t.Helper()
	home = t.TempDir()
	return home, filepath.Join(home, "auth")
}

// createRun runs a first-contact write of managed over target.
func createRun(t *testing.T, sh []string, home, target string) int {
	t.Helper()
	return runSh(t, sh, writeCmdFor(target, Snapshot{Absent: true}, len(managed)), home, []byte(managed))
}

// TestCreateClearsAnOlderBackup (F010): .bak always means the bytes this
// write replaced, so a write that creates the file removes an older one. A
// refused create changes nothing.
func TestCreateClearsAnOlderBackup(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("a create removes an older backup", func(t *testing.T) {
			home, target := sandbox(t)
			writeFile(t, target+bakSuffix, staleBak)
			if code := createRun(t, sh, home, target); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, target); got != managed {
				t.Errorf("file = %q, want the render", got)
			}
			assertAbsent(t, target+bakSuffix, "a create has no previous version to keep")
			assertNoResidue(t, target)
		})
		t.Run("a symlink at the backup name is removed, never followed", func(t *testing.T) {
			home, target := sandbox(t)
			victim := filepath.Join(home, "victim")
			writeFile(t, victim, victimTx)
			if err := os.Symlink(victim, target+bakSuffix); err != nil {
				t.Fatal(err)
			}
			if code := createRun(t, sh, home, target); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, victim); got != victimTx {
				t.Errorf("victim = %q", got)
			}
			assertAbsent(t, target+bakSuffix, "the planted link goes with the stale backup")
		})
		t.Run("a directory at the backup name exits 1 and creates nothing", func(t *testing.T) {
			home, target := sandbox(t)
			if err := os.Mkdir(target+bakSuffix, 0o700); err != nil {
				t.Fatal(err)
			}
			if code := createRun(t, sh, home, target); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			assertAbsent(t, target, "the failed create must not install the file")
			assertDir(t, target+bakSuffix, "the planted directory stays")
			assertNoResidue(t, target)
		})
		refusals := []struct {
			name string
			want int
			run  func(t *testing.T, home, target string) int
		}{
			{"a short upload", shortWriteExit, func(t *testing.T, home, target string) int {
				t.Helper()
				return runSh(t, sh, writeCmdFor(target, Snapshot{Absent: true}, len(managed)+1), home, []byte(managed))
			}},
			{"a file that appeared", changedExit, func(t *testing.T, home, target string) int {
				t.Helper()
				writeFile(t, target, "appeared\n")
				return createRun(t, sh, home, target)
			}},
			{"a held lock", lockedExit, func(t *testing.T, home, target string) int {
				t.Helper()
				if err := os.Mkdir(target+lockSuffix, 0o700); err != nil {
					t.Fatal(err)
				}
				return createRun(t, sh, home, target)
			}},
		}
		for _, r := range refusals {
			t.Run("a refused create leaves the backup: "+r.name, func(t *testing.T) {
				home, target := sandbox(t)
				writeFile(t, target+bakSuffix, staleBak)
				if code := r.run(t, home, target); code != r.want {
					t.Fatalf("exit = %d, want %d", code, r.want)
				}
				if got := readFile(t, target+bakSuffix); got != staleBak {
					t.Errorf(".bak = %q, a refused write changes nothing", got)
				}
			})
		}
	})
}

// cksumStub installs a PATH cksum that prints crc and size whatever it reads.
// called reports whether it ran (busybox-static runs cksum as an applet).
func cksumStub(t *testing.T, crc uint32, size int) (env []string, called func() bool) {
	t.Helper()
	stub := t.TempDir()
	marker := filepath.Join(stub, "called")
	writeFile(t, filepath.Join(stub, "cksum"), "#!/bin/sh\n: > '"+marker+"'\ncat > /dev/null\necho "+
		strconv.FormatUint(uint64(crc), 10)+" "+strconv.Itoa(size)+"\n")
	if err := os.Chmod(filepath.Join(stub, "cksum"), 0o700); err != nil { // #nosec G302 -- test stub must be executable
		t.Fatal(err)
	}
	return []string{"PATH=" + stub + ":" + os.Getenv("PATH")}, func() bool {
		_, err := os.Stat(marker)
		return err == nil
	}
}

// TestRefusalsThroughRealSh (F014) pins, by what the scripts do, the refusals
// the script goldens were the only test of.
func TestRefusalsThroughRealSh(t *testing.T) {
	wrote := SnapshotOf(false, []byte(managed))
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("a restore refuses a symlinked backup and follows nothing", func(t *testing.T) {
			home, target := sandbox(t)
			victim := filepath.Join(home, "victim")
			writeFile(t, target, managed)
			writeFile(t, victim, victimTx)
			if err := os.Symlink(victim, target+bakSuffix); err != nil {
				t.Fatal(err)
			}
			if code := runSh(t, sh, restoreCmdFor(target, false, wrote), home, nil); code != symlinkExit {
				t.Fatalf("exit = %d, want %d", code, symlinkExit)
			}
			if got := readFile(t, victim); got != victimTx {
				t.Errorf("victim = %q", got)
			}
			if got := readFile(t, target); got != managed {
				t.Errorf("file = %q, want it untouched", got)
			}
			if fi, err := os.Lstat(target); err != nil || !fi.Mode().IsRegular() {
				t.Errorf("target is no longer a regular file (%v)", err)
			}
			assertNoResidue(t, target)
		})
		t.Run("a directory at the backup name exits 1 and leaves the target", func(t *testing.T) {
			home, target := sandbox(t)
			writeFile(t, target, "hand\n")
			if err := os.Mkdir(target+bakSuffix, 0o700); err != nil {
				t.Fatal(err)
			}
			if code := runSh(t, sh, writeCmdFor(target, SnapshotOf(false, []byte("hand\n")), len(managed)), home, []byte(managed)); code != 1 {
				t.Fatalf("exit = %d, want 1", code)
			}
			if got := readFile(t, target); got != "hand\n" {
				t.Errorf("file = %q, want it untouched", got)
			}
			assertDir(t, target+bakSuffix, "the planted directory stays")
			assertNoResidue(t, target)
		})
		for _, tt := range []struct {
			name   string
			expect Snapshot
			before string
		}{
			{"over a file", SnapshotOf(false, []byte("hand\n")), "hand\n"},
			{"first contact", Snapshot{Absent: true}, ""},
		} {
			t.Run("a symlink at the temp name is not written through: "+tt.name, func(t *testing.T) {
				home, target := sandbox(t)
				victim := filepath.Join(home, "victim")
				writeFile(t, victim, victimTx)
				if tt.before != "" {
					writeFile(t, target, tt.before)
				}
				if err := os.Symlink(victim, target+tmpSuffix); err != nil {
					t.Fatal(err)
				}
				if code := runSh(t, sh, writeCmdFor(target, tt.expect, len(managed)), home, []byte(managed)); code != 0 {
					t.Fatalf("exit = %d, want 0", code)
				}
				if got := readFile(t, victim); got != victimTx {
					t.Errorf("victim = %q, the upload followed a planted symlink", got)
				}
				if fi, err := os.Lstat(target); err != nil || !fi.Mode().IsRegular() || readFile(t, target) != managed {
					t.Errorf("target is not the render as a regular file (%v)", err)
				}
				assertNoResidue(t, target)
			})
		}
		t.Run("a symlink swapped in during the upload is refused at the compare-and-swap", func(t *testing.T) {
			home, target := sandbox(t)
			const hand = "hand\n"
			victim := filepath.Join(home, "victim")
			writeFile(t, victim, hand) // the same bytes: only the symlink check can refuse
			writeFile(t, target, hand)
			content := []byte(managed + strings.Repeat("# pad\n", 64))
			half := len(content) / 2
			code := runShConcurrent(t, sh, writeCmdFor(target, SnapshotOf(false, []byte(hand)), len(content)), home, target,
				content[:half], content[half:], func() {
					if err := os.Remove(target); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(victim, target); err != nil {
						t.Fatal(err)
					}
				})
			if code != symlinkExit {
				t.Fatalf("exit = %d, want %d", code, symlinkExit)
			}
			if fi, err := os.Lstat(target); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("target is no longer the symlink (%v)", err)
			}
			if got := readFile(t, victim); got != hand {
				t.Errorf("victim = %q", got)
			}
			assertNoResidue(t, target)
		})
		t.Run("the compare-and-swap reads the size as well as the checksum", func(t *testing.T) {
			for _, tt := range []struct {
				name string
				size int
				want int
			}{
				{"a size-only mismatch refuses", wrote.Size + 1, changedExit},
				{"the matching size passes (the row isolates the size)", wrote.Size, 0},
			} {
				t.Run("restore: "+tt.name, func(t *testing.T) {
					home, target := sandbox(t)
					writeFile(t, target, managed)
					writeFile(t, target+bakSuffix, "previous\n")
					env, called := cksumStub(t, wrote.Cksum, tt.size)
					code := runShEnv(t, sh, restoreCmdFor(target, false, wrote), home, nil, env...)
					if !called() {
						t.Skipf("%v runs cksum as a built-in applet", sh)
					}
					if code != tt.want {
						t.Fatalf("exit = %d, want %d", code, tt.want)
					}
					if tt.want != 0 && readFile(t, target) != managed {
						t.Error("a refused restore must leave the file alone")
					}
				})
				t.Run("write: "+tt.name, func(t *testing.T) {
					home, target := sandbox(t)
					writeFile(t, target, managed)
					env, called := cksumStub(t, wrote.Cksum, tt.size)
					code := runShEnv(t, sh, writeCmdFor(target, wrote, len("new\n")), home, []byte("new\n"), env...)
					if !called() {
						t.Skipf("%v runs cksum as a built-in applet", sh)
					}
					if code != tt.want {
						t.Fatalf("exit = %d, want %d", code, tt.want)
					}
					if tt.want != 0 {
						if readFile(t, target) != managed {
							t.Error("a refused write must leave the file alone")
						}
						assertAbsent(t, target+bakSuffix, "a refused write takes no backup")
					}
				})
			}
		})
	})
}

// newlineDir creates home/real plus a directory whose name is "real" and a
// newline, and returns that one: "$(...)" alone would turn its name into
// the decoy's.
func newlineDir(t *testing.T, home string, mode os.FileMode) string {
	t.Helper()
	if err := os.Mkdir(filepath.Join(home, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(home, "real") + "\n"
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, mode); err != nil { // #nosec G302 -- the unsafe mode under test
		t.Fatal(err)
	}
	return dir
}

// TestNewlineNamedAncestorRefused (G018): the resolved walk checks the
// directory itself, not the decoy a stripped name points at.
func TestNewlineNamedAncestorRefused(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		for _, mode := range []os.FileMode{0o777, 0o770} {
			t.Run("the link itself leads to it "+mode.String(), func(t *testing.T) {
				home := t.TempDir()
				dir := newlineDir(t, home, mode)
				link := filepath.Join(home, "a")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(link, "b", "ak")
				if code := createRun(t, sh, home, target); code != unsafePathExit {
					t.Fatalf("exit = %d, want %d", code, unsafePathExit)
				}
				assertAbsent(t, filepath.Join(dir, "b"), "a refusal creates nothing")
			})
			t.Run("it is the parent of an existing directory "+mode.String(), func(t *testing.T) {
				home := t.TempDir()
				dir := newlineDir(t, home, mode)
				if err := os.Mkdir(filepath.Join(dir, "b"), 0o700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(home, "a")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(link, "b", "ak")
				if code := createRun(t, sh, home, target); code != unsafePathExit {
					t.Fatalf("exit = %d, want %d", code, unsafePathExit)
				}
				assertAbsent(t, filepath.Join(dir, "b", "ak"), "the write must refuse")
			})
		}
		t.Run("a safe newline-named directory is written", func(t *testing.T) {
			home := t.TempDir()
			dir := newlineDir(t, home, 0o700)
			link := filepath.Join(home, "a")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			if code := createRun(t, sh, home, filepath.Join(link, "b", "ak")); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, filepath.Join(dir, "b", "ak")); got != managed {
				t.Errorf("file = %q", got)
			}
		})
	})
}
