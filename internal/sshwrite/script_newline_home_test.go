package sshwrite

import (
	"os"
	"path/filepath"
	"testing"
)

// newlineHome makes <tmp>/h<NL> as HOME with mode, plus, when decoy is
// non-zero, the sibling <tmp>/h a bare $(dirname …) would name instead.
func newlineHome(t *testing.T, mode, decoy os.FileMode) (home, decoyPath string) {
	t.Helper()
	base := t.TempDir()
	home = filepath.Join(base, "h") + "\n"
	decoyPath = filepath.Join(base, "h")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, mode); err != nil { // #nosec G302 -- the mode under test
		t.Fatal(err)
	}
	if decoy != 0 {
		if err := os.Mkdir(decoyPath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(decoyPath, decoy); err != nil { // #nosec G302 -- the mode under test
			t.Fatal(err)
		}
	}
	return home, decoyPath
}

// TestWriteScriptsWalkAHomeEndingInANewline (G018): a ~/NAME override sits
// directly in $HOME, so the scripts' first parent is $HOME itself. Taken
// with a bare $(dirname "$p"), a HOME whose name ends in a newline loses
// it, and the walk grades the sibling without it: an unsafe home was
// written into (and a stray sibling created), a safe one refused for an
// unsafe sibling. Every write-path script takes parents through
// sshconn.DirnameTo.
func TestWriteScriptsWalkAHomeEndingInANewline(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		for _, withDecoy := range []bool{false, true} {
			name := "no sibling"
			var decoy os.FileMode
			if withDecoy {
				name, decoy = "a safe sibling", 0o700
			}
			t.Run("an unsafe home is refused, "+name, func(t *testing.T) {
				home, sibling := newlineHome(t, 0o777, decoy)
				if code := runSh(t, sh, writeCmdFor("~/ak", Snapshot{Absent: true}, len(managed)), home, []byte(managed)); code != unsafePathExit {
					t.Fatalf("write exit = %d, want %d", code, unsafePathExit)
				}
				assertAbsent(t, filepath.Join(home, "ak"), "the write must refuse")
				if !withDecoy {
					assertAbsent(t, sibling, "a refusal creates nothing")
				}
			})
		}
		t.Run("a safe home with an unsafe sibling is written", func(t *testing.T) {
			home, _ := newlineHome(t, 0o700, 0o777)
			if code := runSh(t, sh, writeCmdFor("~/ak", Snapshot{Absent: true}, len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("write exit = %d, want 0", code)
			}
			if got := readFile(t, filepath.Join(home, "ak")); got != managed {
				t.Errorf("file = %q", got)
			}
		})
		t.Run("a missing directory under a safe home with an unsafe sibling is created", func(t *testing.T) {
			home, _ := newlineHome(t, 0o700, 0o777)
			if code := runSh(t, sh, writeCmdFor("~/new/ak", Snapshot{Absent: true}, len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("write exit = %d, want 0", code)
			}
			if got := readFile(t, filepath.Join(home, "new", "ak")); got != managed {
				t.Errorf("file = %q", got)
			}
		})
		t.Run("restore refuses an unsafe home", func(t *testing.T) {
			home, _ := newlineHome(t, 0o777, 0o700)
			target := filepath.Join(home, "ak")
			writeFile(t, target, managed)
			writeFile(t, target+bakSuffix, staleBak)
			if code := runSh(t, sh, restoreCmdFor("~/ak", false, SnapshotOf(false, []byte(managed))), home, nil); code != unsafePathExit {
				t.Fatalf("restore exit = %d, want %d", code, unsafePathExit)
			}
			if got := readFile(t, target); got != managed {
				t.Errorf("file = %q, want it untouched", got)
			}
		})
		t.Run("the keys2-only read refuses an unsafe home", func(t *testing.T) {
			home, _ := newlineHome(t, 0o777, 0o700)
			writeFile(t, filepath.Join(home, "ak"), managed)
			if code := runSh(t, sh, unchangedReadCmdFor("~/ak"), home, nil); code != unsafePathExit {
				t.Fatalf("read exit = %d, want %d", code, unsafePathExit)
			}
		})
		t.Run("the locked re-read finds the home's directory", func(t *testing.T) {
			home, _ := newlineHome(t, 0o700, 0)
			writeFile(t, filepath.Join(home, "ak"), managed)
			code, out := runShOut(t, sh, lockedReadCmdFor("~/ak"), home, nil)
			if code != 0 || out == "" {
				t.Fatalf("locked read = (%d, %q), want the file", code, out)
			}
		})
	})
}
