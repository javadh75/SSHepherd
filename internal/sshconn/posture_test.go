package sshconn

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
)

func capped(s string) *CappedBuffer {
	b := NewCappedBuffer(MaxRemoteOutput)
	_, _ = b.Write([]byte(s))
	return b
}

func TestFinishPosture(t *testing.T) {
	rec := func(mode, uid, issue, path string) string {
		return "SSHEPHERD-POSTURE " + mode + " " + uid + " " + issue + " " + path + "\n"
	}
	worldHome := fleet.PostureIssue{Path: "/home/d/.ssh", Issue: fleet.PostureWorldWritable, Mode: "drwxrwxrwx", UID: "1001"}
	tests := []struct {
		name    string
		code    int
		stdout  string
		want    []fleet.PostureIssue
		keys2   bool
		wantErr string
	}{
		{name: "clean", stdout: ""},
		{name: "one finding", stdout: rec("drwxrwxrwx", "1001", "world_writable", "/home/d/.ssh"), want: []fleet.PostureIssue{worldHome}},
		{name: "keys2", stdout: "SSHEPHERD-KEYS2 1\n", keys2: true},
		{name: "mode with an xattr marker", stdout: rec("-rw-rw-r--@", "5", "group_writable", "/k"),
			want: []fleet.PostureIssue{{Path: "/k", Issue: "group_writable", Mode: "-rw-rw-r--@", UID: "5"}}},
		{name: "path with spaces", stdout: rec("lrwxrwxrwx", "5", "symlink", "/a b/k"),
			want: []fleet.PostureIssue{{Path: "/a b/k", Issue: "symlink", Mode: "lrwxrwxrwx", UID: "5"}}},
		{name: "as-written and resolved duplicates collapse",
			stdout: rec("drwxrwxrwx", "1001", "world_writable", "/home/d/.ssh") + rec("drwxrwxrwx", "1001", "world_writable", "/home/d/.ssh"),
			want:   []fleet.PostureIssue{worldHome}},
		{name: "both write bits are two records",
			stdout: rec("drwxrwxrwx", "1", "group_writable", "/x") + rec("drwxrwxrwx", "1", "world_writable", "/x"),
			want: []fleet.PostureIssue{{Path: "/x", Issue: "group_writable", Mode: "drwxrwxrwx", UID: "1"},
				{Path: "/x", Issue: "world_writable", Mode: "drwxrwxrwx", UID: "1"}}},
		{name: "path is sanitized", stdout: rec("drwxrwxrwx", "1", "world_writable", "/x\x1b[31m"),
			want: []fleet.PostureIssue{{Path: "/x[31m", Issue: "world_writable", Mode: "drwxrwxrwx", UID: "1"}}},
		{name: "garbage line", stdout: "hello\n", wantErr: "malformed"},
		{name: "blank line", stdout: "\n", wantErr: "malformed"},
		{name: "unknown issue", stdout: rec("drwxrwxrwx", "1", "cursed", "/x"), wantErr: "malformed"},
		{name: "bad mode", stdout: rec("drwx", "1", "world_writable", "/x"), wantErr: "malformed"},
		{name: "bad uid", stdout: rec("drwxrwxrwx", "root", "world_writable", "/x"), wantErr: "malformed"},
		{name: "newline in path", stdout: rec("drwxrwxrwx", "1", "world_writable", "/x\n/y"), wantErr: "malformed"},
		{name: "no final newline", stdout: strings.TrimSuffix(rec("drwxrwxrwx", "1", "world_writable", "/x"), "\n"), wantErr: "malformed"},
		{name: "keys2 with another value", stdout: "SSHEPHERD-KEYS2 2\n", wantErr: "malformed"},
		{name: "65 records", stdout: strings.Repeat(rec("drwxrwxrwx", "1", "world_writable", "/x"), 65), wantErr: "malformed"},
		{name: "64 records", stdout: strings.Repeat(rec("drwxrwxrwx", "1", "world_writable", "/x"), 64),
			want: []fleet.PostureIssue{{Path: "/x", Issue: "world_writable", Mode: "drwxrwxrwx", UID: "1"}}},
		{name: "non-zero exit", code: 2, stdout: rec("drwxrwxrwx", "1", "world_writable", "/x"), wantErr: "posture probe failed (exit 2): boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, keys2, err := FinishPosture(tt.code, capped(tt.stdout), capped("boom\n"))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || fleet.ErrorKindOf(err) != fleet.ErrorKindRemote {
					t.Fatalf("err = %v, want a remote error containing %q", err, tt.wantErr)
				}
				if got != nil || keys2 {
					t.Fatalf("a failed probe must return nothing: %v, %v", got, keys2)
				}
				return
			}
			if err != nil {
				t.Fatalf("FinishPosture: %v", err)
			}
			if !slices.Equal(got, tt.want) || keys2 != tt.keys2 {
				t.Errorf("got %+v keys2=%v, want %+v keys2=%v", got, keys2, tt.want, tt.keys2)
			}
		})
	}
	t.Run("output at the capture limit", func(t *testing.T) {
		b := NewCappedBuffer(MaxRemoteOutput)
		_, _ = b.Write([]byte(strings.Repeat("x", MaxRemoteOutput+1)))
		if _, _, err := FinishPosture(0, b, capped("")); fleet.ErrorKindOf(err) != fleet.ErrorKindRemote {
			t.Errorf("err = %v, want remote", err)
		}
	})
}

// postureHome builds a HOME the walk accepts: home 0700, ~/.ssh 0700, a
// 0600 authorized_keys.
func postureHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	must(t, os.Chmod(home, 0o700)) // t.TempDir's mode follows the umask
	must(t, os.Mkdir(filepath.Join(home, ".ssh"), 0o700))
	must(t, os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("k\n"), 0o600))
	return home
}

// runPosture runs the probe through a real sh, parses it, and fails on any
// probe error.
func runPosture(t *testing.T, home, path string) ([]fleet.PostureIssue, bool) {
	t.Helper()
	c := exec.CommandContext(t.Context(), "sh", "-c", PostureCmdFor(path)) // #nosec G204 -- the probe under test
	c.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	c.Stdout, c.Stderr = &stdout, &stderr
	code := 0
	var exitErr *exec.ExitError
	if err := c.Run(); errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	issues, keys2, err := FinishPosture(code, capped(stdout.String()), capped(stderr.String()))
	if err != nil {
		t.Fatalf("FinishPosture: %v\nstdout: %s", err, stdout.String())
	}
	return issues, keys2
}

// issueSet renders findings as sorted, distinct "base-of-path issue": a
// macOS TempDir is /var/… as written and /private/var/… resolved, so full
// paths do not compare and one directory yields two records.
func issueSet(issues []fleet.PostureIssue) []string {
	out := make([]string, 0, len(issues))
	for _, i := range issues {
		out = append(out, filepath.Base(i.Path)+" "+i.Issue)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func TestPostureCmdFindings(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T, home string)
		want  []string
	}{
		{"0700 is clean", func(*testing.T, string) {}, nil},
		{"world-writable ~/.ssh",
			func(t *testing.T, h string) { must(t, os.Chmod(filepath.Join(h, ".ssh"), 0o777)) },
			[]string{".ssh group_writable", ".ssh world_writable"}},
		{"group-writable ~/.ssh",
			func(t *testing.T, h string) { must(t, os.Chmod(filepath.Join(h, ".ssh"), 0o770)) },
			[]string{".ssh group_writable"}},
		{"group-writable file",
			func(t *testing.T, h string) { must(t, os.Chmod(filepath.Join(h, ".ssh", "authorized_keys"), 0o660)) },
			[]string{"authorized_keys group_writable"}},
		{"world-writable file",
			func(t *testing.T, h string) { must(t, os.Chmod(filepath.Join(h, ".ssh", "authorized_keys"), 0o602)) },
			[]string{"authorized_keys world_writable"}},
		{"group-writable home",
			func(t *testing.T, h string) { must(t, os.Chmod(h, 0o770)) },
			[]string{"HOME group_writable"}},
		{"symlinked file is reported, its target's mode is not",
			func(t *testing.T, h string) {
				f := filepath.Join(h, ".ssh", "authorized_keys")
				must(t, os.Remove(f))
				must(t, os.WriteFile(filepath.Join(h, ".ssh", "real"), []byte("k\n"), 0o666))
				must(t, os.Symlink("real", f))
			},
			[]string{"authorized_keys symlink"}},
		{"absent file is clean", func(t *testing.T, h string) { must(t, os.Remove(filepath.Join(h, ".ssh", "authorized_keys"))) }, nil},
		{"absent ~/.ssh is clean", func(t *testing.T, h string) { must(t, os.RemoveAll(filepath.Join(h, ".ssh"))) }, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := postureHome(t)
			tt.setup(t, home)
			issues, _ := runPosture(t, home, DefaultAuthorizedKeysPath)
			got := issueSet(issues)
			want := slices.Clone(tt.want)
			for i := range want {
				want[i] = strings.Replace(want[i], "HOME", filepath.Base(home), 1)
			}
			slices.Sort(want)
			if len(got) == 0 && len(want) == 0 {
				return
			}
			if !slices.Equal(got, want) {
				t.Errorf("findings = %v, want %v", got, want)
			}
		})
	}
}

// TestPostureOutsideHomeWalksToRoot (D14c): an override outside $HOME is
// walked up to /, so a writable directory far above it is reported.
func TestPostureOutsideHomeWalksToRoot(t *testing.T) {
	home := postureHome(t)
	outer := t.TempDir()
	must(t, os.Chmod(outer, 0o700))
	loose := filepath.Join(outer, "loose")
	must(t, os.Mkdir(loose, 0o777))
	must(t, os.Chmod(loose, 0o777)) // defeat the umask
	inner := filepath.Join(loose, "inner")
	must(t, os.Mkdir(inner, 0o700))
	must(t, os.WriteFile(filepath.Join(inner, "keys"), []byte("k\n"), 0o600))
	issues, _ := runPosture(t, home, filepath.Join(inner, "keys"))
	if got := issueSet(issues); !slices.Contains(got, "loose world_writable") || !slices.Contains(got, "loose group_writable") {
		t.Errorf("findings = %v, want the loose ancestor reported", got)
	}
}

// TestPostureRootIsAnAcceptedOwner (D14a): the outside-home walk passes
// through root-owned directories up to / and must not report any of them.
func TestPostureRootIsAnAcceptedOwner(t *testing.T) {
	home := postureHome(t)
	outer := t.TempDir()
	must(t, os.Chmod(outer, 0o700))
	must(t, os.WriteFile(filepath.Join(outer, "keys"), []byte("k\n"), 0o600))
	issues, _ := runPosture(t, home, filepath.Join(outer, "keys"))
	for _, i := range issues {
		if i.Issue == fleet.PostureForeignOwner && i.UID == "0" {
			t.Errorf("root reported as a foreign owner: %+v", i)
		}
	}
}

func TestPostureForeignOwnerUsesProbeUID(t *testing.T) {
	home := postureHome(t)
	bin := t.TempDir()
	// A stubbed id: the probe thinks it runs as uid 4242, so every owner is
	// foreign — without needing root to chown anything.
	must(t, os.WriteFile(filepath.Join(bin, "id"), []byte("#!/bin/sh\necho 4242\n"), 0o755))    // #nosec G306 -- test stub on PATH
	c := exec.CommandContext(t.Context(), "sh", "-c", PostureCmdFor(DefaultAuthorizedKeysPath)) // #nosec G204 -- the probe under test
	c.Env = []string{"HOME=" + home, "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
	out, err := c.Output()
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if os.Getuid() == 0 {
		t.Skip("running as root: root is an accepted owner, so nothing is foreign")
	}
	issues, _, err := FinishPosture(0, capped(string(out)), capped(""))
	if err != nil {
		t.Fatalf("FinishPosture: %v", err)
	}
	got := issueSet(issues)
	want := []string{filepath.Base(home) + " foreign_owner", ".ssh foreign_owner", "authorized_keys foreign_owner"}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("findings = %v, want %v", got, want)
	}
}

// runStubbed runs the probe with a stub of tool first on PATH and returns
// FinishPosture's verdict.
func runStubbed(t *testing.T, home, path, tool, body string) ([]fleet.PostureIssue, error) {
	t.Helper()
	bin := t.TempDir()
	must(t, os.WriteFile(filepath.Join(bin, tool), []byte(body), 0o755))   // #nosec G306 -- test stub on PATH
	c := exec.CommandContext(t.Context(), "sh", "-c", PostureCmdFor(path)) // #nosec G204 -- the probe under test
	c.Env = []string{"HOME=" + home, "PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH")}
	var stdout, stderr strings.Builder
	c.Stdout, c.Stderr = &stdout, &stderr
	code := 0
	var exitErr *exec.ExitError
	if err := c.Run(); errors.As(err, &exitErr) {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	issues, _, err := FinishPosture(code, capped(stdout.String()), capped(stderr.String()))
	return issues, err
}

// TestPostureDanglingSymlinkAncestor: a symlink along the path that points
// nowhere is not a directory, so the walk starts above it, but its owner is
// still judged. Only components that do not exist are skipped.
func TestPostureDanglingSymlinkAncestor(t *testing.T) {
	home := postureHome(t)
	must(t, os.Symlink(filepath.Join(home, "nowhere"), filepath.Join(home, "dangle")))
	path := filepath.Join(home, "dangle", "keys")
	if issues, _ := runPosture(t, home, path); len(issues) != 0 {
		t.Errorf("a dangling link owned by the login user is clean, got %+v", issues)
	}
	if os.Getuid() == 0 {
		t.Skip("running as root: root is an accepted owner, so nothing is foreign")
	}
	issues, err := runStubbed(t, home, path, "id", "#!/bin/sh\necho 4242\n")
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if got := issueSet(issues); !slices.Contains(got, "dangle foreign_owner") {
		t.Errorf("findings = %v, want the dangling link's owner reported", got)
	}
}

// TestPostureFailedLsFailsClosed: a failed ls leaves $1 and $3 empty, so the
// probe prints a record the grammar refuses and the server is unreachable,
// never clean. The message is "malformed", not "failed (exit N)": the
// shared walk's bytes are pinned and it cannot exit on a failed ls (plan
// decision 15).
func TestPostureFailedLsFailsClosed(t *testing.T) {
	_, err := runStubbed(t, postureHome(t), DefaultAuthorizedKeysPath, "ls", "#!/bin/sh\nexit 1\n")
	if fleet.ErrorKindOf(err) != fleet.ErrorKindRemote || err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Errorf("err = %v, want a remote malformed-output error", err)
	}
}

// TestPostureFailedIdFailsClosed: with no login uid the owner checks mean
// nothing (a root-owned path would print no record and look clean), so a
// failed id fails the probe before the walk.
func TestPostureFailedIdFailsClosed(t *testing.T) {
	issues, err := runStubbed(t, postureHome(t), DefaultAuthorizedKeysPath, "id", "#!/bin/sh\nexit 1\n")
	if fleet.ErrorKindOf(err) != fleet.ErrorKindRemote || err == nil || !strings.Contains(err.Error(), "posture probe failed (exit 1)") {
		t.Errorf("err = %v, want a remote probe failure", err)
	}
	if issues != nil {
		t.Errorf("a failed probe must return nothing, got %+v", issues)
	}
}

// TestPostureKeys2 keeps the removed SecondaryKeysCmdFor rule: any spelling
// that resolves on the server to ~/.ssh/authorized_keys sees keys2; nothing
// else does.
func TestPostureKeys2(t *testing.T) {
	linkFile := func(rel string) func(t *testing.T, home string) {
		return func(t *testing.T, home string) {
			t.Helper()
			must(t, os.WriteFile(filepath.Join(home, rel), []byte("k\n"), 0o600))
			must(t, os.MkdirAll(filepath.Join(home, "keys"), 0o700))
			must(t, os.Symlink(filepath.Join(home, rel), filepath.Join(home, "keys", "ak")))
		}
	}
	tests := []struct {
		name  string
		path  func(home string) string
		setup func(t *testing.T, home string)
		ak2   bool
		empty bool
		want  bool
	}{
		{name: "default spelling", path: func(string) string { return DefaultAuthorizedKeysPath }, ak2: true, want: true},
		{name: "default spelling, absent", path: func(string) string { return DefaultAuthorizedKeysPath }},
		{name: "default spelling, empty", path: func(string) string { return DefaultAuthorizedKeysPath }, ak2: true, empty: true},
		{name: "absolute default", path: func(h string) string { return filepath.Join(h, ".ssh", "authorized_keys") }, ak2: true, want: true},
		{name: "absolute default, no keys2", path: func(h string) string { return filepath.Join(h, ".ssh", "authorized_keys") }},
		{name: "through a symlinked dir", path: func(h string) string { return filepath.Join(h, "link", "authorized_keys") },
			setup: func(t *testing.T, h string) { must(t, os.Symlink(filepath.Join(h, ".ssh"), filepath.Join(h, "link"))) }, ak2: true, want: true},
		{name: "other file in ~/.ssh", path: func(h string) string { return filepath.Join(h, ".ssh", "other") }, ak2: true},
		{name: "tilde override elsewhere", path: func(string) string { return "~/keys/deploy" }, ak2: true},
		{name: "missing dir never matches", path: func(h string) string { return filepath.Join(h, "nodir", "authorized_keys") }, ak2: true},
		{name: "symlinked file to the default", path: func(h string) string { return filepath.Join(h, "keys", "ak") },
			setup: linkFile(".ssh/authorized_keys"), ak2: true, want: true},
		{name: "tilde symlinked file to the default", path: func(string) string { return "~/keys/ak" },
			setup: linkFile(".ssh/authorized_keys"), ak2: true, want: true},
		{name: "symlinked file to the default, no keys2", path: func(h string) string { return filepath.Join(h, "keys", "ak") },
			setup: linkFile(".ssh/authorized_keys")},
		{name: "symlinked file to another file", path: func(h string) string { return filepath.Join(h, "keys", "ak") },
			setup: linkFile(".ssh/other"), ak2: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := postureHome(t)
			if tt.ak2 {
				content := "ssh-ed25519 AAAA planted\n"
				if tt.empty {
					content = ""
				}
				must(t, os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys2"), []byte(content), 0o600))
			}
			if tt.setup != nil {
				tt.setup(t, home)
			}
			if _, got := runPosture(t, home, tt.path(home)); got != tt.want {
				t.Errorf("keys2 = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPostureCmdIsSingleLineAndQuotesPath(t *testing.T) {
	script := PostureCmdFor(`/srv/it's; touch /tmp/pwn`)
	if strings.ContainsAny(script, "\r\n") {
		t.Fatal("remote scripts must be single-line")
	}
	if want := `p='/srv/it'\''s; touch /tmp/pwn'`; !strings.HasPrefix(script, want+";") {
		t.Errorf("script %q does not start with the quoted assignment", script[:60])
	}
	if n := strings.Count(script, "touch"); n != 1 {
		t.Errorf("the path entered the script %d times, want 1", n)
	}
}

// TestReadCmdUnchanged: sshwrite's verify reads back through this exact
// command, so the posture work must not touch it.
func TestReadCmdUnchanged(t *testing.T) {
	want := `p="${HOME:?}"/'.ssh/authorized_keys'; if [ -e "$p" ]; then cat "$p"; else exit 44; fi`
	if got := AuthorizedKeysCmdFor(DefaultAuthorizedKeysPath); got != want {
		t.Errorf("read command changed:\n got %s\nwant %s", got, want)
	}
}
