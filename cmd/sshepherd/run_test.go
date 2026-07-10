package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestRunVersion(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run([]string{"--version"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "sshepherd") {
		t.Errorf("stdout = %q, want it to contain %q", out.String(), "sshepherd")
	}
}

func TestRunNoCommand(t *testing.T) {
	var out, errBuf bytes.Buffer
	code := run(nil, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "no command") {
		t.Errorf("stderr = %q, want it to mention %q", errBuf.String(), "no command")
	}
}

func TestRunNilArgsIgnoresOSArgs(t *testing.T) {
	// run(nil) must mean "no CLI arguments". Cobra treats SetArgs(nil) as
	// "fall back to os.Args[1:]", which leaks the test binary's own flags
	// (e.g. -update) into the command. Simulate such a leak deterministically:
	// if run(nil) read os.Args it would print the version and exit 0.
	orig := os.Args
	os.Args = []string{"sshepherd.test", "--version"}
	defer func() { os.Args = orig }()

	var out, errBuf bytes.Buffer
	code := run(nil, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (run(nil) must not read os.Args; stdout: %q)", code, out.String())
	}
	if !strings.Contains(errBuf.String(), "no command") {
		t.Errorf("stderr = %q, want the no-command error", errBuf.String())
	}
}

func TestRunUnknownFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--nope"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
}
