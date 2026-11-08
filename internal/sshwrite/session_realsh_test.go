package sshwrite

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// TestRestoreRetryAfterItLandedThroughRealSh runs the real scripts: a second
// restore is refused (46), and the locked read then shows what
// alreadyRestored needs to call the restore done.
func TestRestoreRetryAfterItLandedThroughRealSh(t *testing.T) {
	wrote := SnapshotOf(false, []byte("new\n"))
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("the backup went back", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "new\n")
			writeFile(t, target+bakSuffix, "old\n")
			script := restoreCmdFor(target, false, wrote)
			if code, _ := runShOut(t, sh, script, home, nil); code != 0 {
				t.Fatalf("first restore exit = %d", code)
			}
			if code, _ := runShOut(t, sh, script, home, nil); code != changedExit {
				t.Fatalf("retry exit = %d, want %d", code, changedExit)
			}
			code, out := runShOut(t, sh, lockedReadCmdFor(target), home, nil)
			if code != 0 || SnapshotOf(false, []byte(out)) != SnapshotOf(false, []byte("old\n")) {
				t.Fatalf("read exit = %d, out = %q", code, out)
			}
			assertNoResidue(t, target)
		})
		t.Run("the first-contact file went away", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "new\n")
			script := restoreCmdFor(target, true, wrote)
			if code, _ := runShOut(t, sh, script, home, nil); code != 0 {
				t.Fatalf("first restore exit = %d", code)
			}
			if code, _ := runShOut(t, sh, script, home, nil); code != changedExit {
				t.Fatalf("retry exit = %d, want %d", code, changedExit)
			}
			if code, _ := runShOut(t, sh, lockedReadCmdFor(target), home, nil); code != sshconn.FileAbsentExit {
				t.Fatalf("read exit = %d, want %d", code, sshconn.FileAbsentExit)
			}
		})
	})
}

func TestUnchangedReadCmdThroughRealSh(t *testing.T) {
	const body = "bytes\n"
	entries := func(t *testing.T, dir string) string {
		t.Helper()
		list, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, 0, len(list))
		for _, e := range list {
			names = append(names, e.Name())
		}
		return strings.Join(names, " ")
	}
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("a safe file is read and nothing is created", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, body)
			code, out := runShOut(t, sh, unchangedReadCmdFor(target), home, nil)
			if code != 0 || out != body {
				t.Fatalf("exit = %d, out = %q", code, out)
			}
			if got := entries(t, home); got != "auth" {
				t.Errorf("home holds %q", got)
			}
		})
		t.Run("an absent file is 44", func(t *testing.T) {
			home := t.TempDir()
			if code, _ := runShOut(t, sh, unchangedReadCmdFor(filepath.Join(home, "auth")), home, nil); code != sshconn.FileAbsentExit {
				t.Fatalf("exit = %d", code)
			}
		})
		t.Run("a symlinked target is 45", func(t *testing.T) {
			home := t.TempDir()
			realFile := filepath.Join(home, "real")
			writeFile(t, realFile, body)
			target := filepath.Join(home, "auth")
			if err := os.Symlink(realFile, target); err != nil {
				t.Fatal(err)
			}
			if code, out := runShOut(t, sh, unchangedReadCmdFor(target), home, nil); code != symlinkExit || out != "" {
				t.Fatalf("exit = %d, out = %q", code, out)
			}
		})
		t.Run("a dangling symlink is 45", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			if err := os.Symlink(filepath.Join(home, "nowhere"), target); err != nil {
				t.Fatal(err)
			}
			if code, _ := runShOut(t, sh, unchangedReadCmdFor(target), home, nil); code != symlinkExit {
				t.Fatalf("exit = %d", code)
			}
		})
		t.Run("a symlinked directory is 48", func(t *testing.T) {
			home := t.TempDir()
			realFile := filepath.Join(home, "real")
			if err := os.Mkdir(realFile, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(realFile, "auth"), body)
			link := filepath.Join(home, "dot-ssh")
			if err := os.Symlink(realFile, link); err != nil {
				t.Fatal(err)
			}
			if code, out := runShOut(t, sh, unchangedReadCmdFor(filepath.Join(link, "auth")), home, nil); code != unsafePathExit || out != "" {
				t.Fatalf("exit = %d, out = %q", code, out)
			}
		})
		t.Run("a group-writable directory is 48", func(t *testing.T) {
			home := t.TempDir()
			d := filepath.Join(home, "dot-ssh")
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(d, 0o770); err != nil { // #nosec G302 -- the unsafe mode under test
				t.Fatal(err)
			}
			target := filepath.Join(d, "auth")
			writeFile(t, target, body)
			if code, out := runShOut(t, sh, unchangedReadCmdFor(target), home, nil); code != unsafePathExit || out != "" {
				t.Fatalf("exit = %d, out = %q", code, out)
			}
		})
	})
}

// TestUnchangedReadOwnerChecks reuses the write script's owner fixtures: each
// must refuse here too, with authorized_keys present (a keys2-only plan
// always read the file in phase 1).
func TestUnchangedReadOwnerChecks(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		for _, c := range ownerCases {
			t.Run(c.name, func(t *testing.T) {
				if c.uid == strconv.Itoa(os.Getuid()) {
					t.Skipf("running as uid %s: the stubbed owner is not foreign", c.uid)
				}
				home := t.TempDir()
				target, foreign, _ := c.setup(t, home)
				if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
					t.Fatal(err)
				}
				writeFile(t, target, "k\n")
				env, called, fired := lsStub(t, foreign, c.uid)
				code := runShEnv(t, sh, unchangedReadCmdFor(target), home, nil, env...)
				if !called() {
					t.Skipf("%v runs ls as a built-in applet; a PATH stub cannot fake an owner", sh)
				}
				if !fired() {
					t.Fatalf("the script never listed %s", foreign)
				}
				if code != unsafePathExit {
					t.Fatalf("exit = %d, want %d", code, unsafePathExit)
				}
			})
		}
	})
}

// TestHeldLockOutputIsBounded: only the owner record's first line reaches
// the client, cut to 200 bytes.
func TestHeldLockOutputIsBounded(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		home := t.TempDir()
		target := filepath.Join(home, "auth")
		writeFile(t, target, "old\n")
		lock := target + lockSuffix
		if err := os.Mkdir(lock, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, lock+"/owner", strings.Repeat("a", 500)+"\nsecond line\n")
		code, out := runShOut(t, sh, lockedReadCmdFor(target), home, nil)
		if code != lockedExit {
			t.Fatalf("exit = %d", code)
		}
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		if len(lines) != 2 || len(lines[1]) != 200 {
			t.Fatalf("got %d lines, owner line of %d bytes", len(lines), len(lines[len(lines)-1]))
		}
	})
}
