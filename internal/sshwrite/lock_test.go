package sshwrite

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// runShOut is runSh that also returns stdout.
func runShOut(t *testing.T, shell []string, script, home string, stdin []byte) (int, string) {
	t.Helper()
	argv := append(append([]string{}, shell[1:]...), "-c", script)
	c := exec.CommandContext(t.Context(), shell[0], argv...) // #nosec G204 -- test runs the package's own scripts
	c.Env = append(os.Environ(), "HOME="+home)
	if stdin != nil {
		c.Stdin = bytes.NewReader(stdin)
	}
	var stdout bytes.Buffer
	c.Stdout = &stdout
	err := c.Run()
	if err == nil {
		return 0, stdout.String()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), stdout.String()
	}
	t.Fatalf("%v -c %q: %v", shell, script, err)
	return -1, ""
}

func TestLockOwnerRecordThroughRealSh(t *testing.T) {
	old := SnapshotOf(false, []byte("old\n"))
	setup := func(t *testing.T) (home, target, lock string) {
		home = t.TempDir()
		target = filepath.Join(home, "auth")
		writeFile(t, target, "old\n")
		return home, target, target + lockSuffix
	}
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("a held lock exits 47 and names its owner", func(t *testing.T) {
			home, target, lock := setup(t)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, lock+"/owner", "v1 ci-runner-3 4121 99 1000\n")
			code, out := runShOut(t, sh, writeCmdFor(target, old, len(managed)), home, []byte(managed))
			if code != lockedExit {
				t.Fatalf("exit = %d, want %d", code, lockedExit)
			}
			info := parseLockOwner(out)
			if !info.known || info.owner != "ci-runner-3 pid 4121" || info.age <= 0 {
				t.Errorf("parsed %+v from %q", info, out)
			}
			if got := readFile(t, target); got != "old\n" {
				t.Errorf("file = %q, want it untouched", got)
			}
			assertDir(t, lock, "another apply's lock must stay")
		})
		t.Run("a bare lock reports no owner", func(t *testing.T) {
			home, target, lock := setup(t)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			code, out := runShOut(t, sh, writeCmdFor(target, old, len(managed)), home, []byte(managed))
			if code != lockedExit {
				t.Fatalf("exit = %d, want %d", code, lockedExit)
			}
			if info := parseLockOwner(out); info.known || info.owner != ownerUnknown {
				t.Errorf("parsed %+v from %q", info, out)
			}
		})
		t.Run("a completed write leaves neither lock nor record", func(t *testing.T) {
			home, target, _ := setup(t)
			if code := runSh(t, sh, writeCmdFor(target, old, len(managed)), home, []byte(managed)); code != 0 {
				t.Fatalf("exit = %d", code)
			}
			assertNoResidue(t, target)
		})
		t.Run("a failing write clears them through the trap", func(t *testing.T) {
			home, target, _ := setup(t)
			if code := runSh(t, sh, writeCmdFor(target, old, len(managed)+1), home, []byte(managed)); code != shortWriteExit {
				t.Fatalf("exit = %d, want %d", code, shortWriteExit)
			}
			assertNoResidue(t, target)
		})
		t.Run("a signal clears them through the trap", func(t *testing.T) {
			home, target, lock := setup(t)
			argv := append(append([]string{}, sh[1:]...), "-c", writeCmdFor(target, old, len(managed)))
			c := exec.CommandContext(t.Context(), sh[0], argv...) // #nosec G204 -- test runs the package's own scripts
			c.Env = append(os.Environ(), "HOME="+home)
			in, err := c.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
				if _, err := os.Stat(lock + "/owner"); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the owner record never appeared")
				}
			}
			if err := c.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			_ = in.Close() // cat sees EOF, then the shell runs its deferred trap
			_ = c.Wait()
			assertNoResidue(t, target)
		})
		t.Run("the removal command clears a stale lock and only that", func(t *testing.T) {
			home, target, lock := setup(t)
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, lock+"/owner", "v1 h 1 2 3\n")
			if code := runSh(t, sh, lockRemovalScript(target), home, nil); code != 0 {
				t.Fatalf("exit = %d", code)
			}
			assertAbsent(t, lock, "the removal command must clear the lock")
			if err := os.Mkdir(lock, 0o700); err != nil {
				t.Fatal(err)
			}
			writeFile(t, lock+"/unexpected", "x")
			if code := runSh(t, sh, lockRemovalScript(target), home, nil); code == 0 {
				t.Fatal("rmdir must refuse a lock holding something unexpected")
			}
			assertDir(t, lock, "an unexpected lock directory stays")
		})
	})
}

func TestParseLockOwner(t *testing.T) {
	ten := 10 * time.Second
	for _, tt := range []struct {
		name, out string
		known     bool
		owner     string
		age       time.Duration
	}{
		{"valid", "sshepherd-lock 1010\nv1 ci-runner-3 4121 99 1000\n", true, "ci-runner-3 pid 4121", ten},
		{"no record", "sshepherd-lock 1010\n", false, ownerUnknown, ageUnknown},
		{"no marker at all", "", false, ownerUnknown, ageUnknown},
		{"a record without the marker is ignored", "garbage\nv1 h 1 2 1000\n", false, ownerUnknown, ageUnknown},
		{"hostile bytes", "sshepherd-lock 1010\nv1 \x1b]0;pwned\a 1 2 3\n", false, ownerUnrecognized, ageUnknown},
		{"host too long", "sshepherd-lock 1010\nv1 " + strings.Repeat("h", 65) + " 1 2 3\n", false, ownerUnrecognized, ageUnknown},
		{"future epoch is an unknown age", "sshepherd-lock 10\nv1 h 1 2 1000\n", true, "h pid 1", ageUnknown},
		{"bad clock is an unknown age", "sshepherd-lock soon\nv1 h 1 2 1000\n", true, "h pid 1", ageUnknown},
		{"absurd gap is an unknown age", "sshepherd-lock 9000000000000000000\nv1 h 1 2 1000\n", true, "h pid 1", ageUnknown},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLockOwner(tt.out)
			if got.known != tt.known || got.owner != tt.owner || got.age != tt.age {
				t.Errorf("parseLockOwner = %+v", got)
			}
		})
	}
}

func TestClientIdent(t *testing.T) {
	for _, tt := range []struct {
		host string
		want string
	}{
		{"ci-runner-3.example", "ci-runner-3.example 77"},
		{"bad host!;$(id)", "badhostid 77"},
		{"", "unknown 77"},
		{strings.Repeat("h", 70), strings.Repeat("h", 64) + " 77"},
	} {
		if got := clientIdent(tt.host, 77); got != tt.want {
			t.Errorf("clientIdent(%q) = %q, want %q", tt.host, got, tt.want)
		}
	}
}

func TestLockedErrorMessage(t *testing.T) {
	const tail = " (a killed write can also leave ~/.ssh/authorized_keys.sshepherd.tmp and ~/.ssh/authorized_keys.sshepherd.cas; the next write reclaims both)"
	known := &LockedError{Path: "~/.ssh/authorized_keys", Owner: "ci-runner-3 pid 4121", Age: 192 * time.Second, Known: true, RemoveCmd: "ssh -p 22 deploy@10.0.0.1 'x'"}
	if want := "another apply is in progress on ~/.ssh/authorized_keys (lock held by ci-runner-3 pid 4121 for 3m12s); remove it only if no apply is running on ci-runner-3 (pid 4121): ssh -p 22 deploy@10.0.0.1 'x'" + tail; known.Error() != want {
		t.Errorf("known:\n got %s\nwant %s", known, want)
	}
	unknown := &LockedError{Path: "~/.ssh/authorized_keys", Owner: ownerUnknown, Age: ageUnknown, RemoveCmd: "ssh x"}
	if want := "another apply is in progress on ~/.ssh/authorized_keys (lock held by an unknown owner (older sshepherd or killed shell)); remove it only if no apply is running: ssh x" + tail; unknown.Error() != want {
		t.Errorf("unknown:\n got %s\nwant %s", unknown, want)
	}
}

func TestLockRemoveCmd(t *testing.T) {
	srv := config.Server{User: "deploy", Host: "10.0.0.1", Port: 22}
	want := `ssh -p 22 deploy@10.0.0.1 ` + sshconn.ShQuote(`p="${HOME:?}"/'.ssh/authorized_keys'; rm -f -- "$p.sshepherd.lock/owner"; rmdir -- "$p.sshepherd.lock"`)
	if got := lockRemoveCmd(srv, "~/.ssh/authorized_keys"); got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
	for _, tt := range []struct {
		user, want string
	}{
		{"a;b", "ssh -p 22 'a;b@h' "},
		{"-oProxyCommand=x", "ssh -p 22 -- -oProxyCommand=x@h "},
	} {
		if got := lockRemoveCmd(config.Server{User: tt.user, Host: "h", Port: 22}, "/p"); !strings.HasPrefix(got, tt.want) {
			t.Errorf("user %q: got %s", tt.user, got)
		}
	}
}
