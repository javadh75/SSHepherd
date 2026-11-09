package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"
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
	if code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
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
	if code != 3 {
		t.Fatalf("exit code = %d, want 3 (run(nil) must not read os.Args; stdout: %q)", code, out.String())
	}
	if !strings.Contains(errBuf.String(), "no command") {
		t.Errorf("stderr = %q, want the no-command error", errBuf.String())
	}
}

func TestRunUnknownFlag(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--nope"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
}

func TestRunFatalErrorPrefix(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run(nil, &out, &errBuf); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !strings.HasPrefix(errBuf.String(), "error: ") {
		t.Errorf("stderr = %q, want an %q prefix", errBuf.String(), "error: ")
	}
}

func TestRunVerboseQuietConflict(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"-v", "-q"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	got := errBuf.String()
	if !strings.Contains(got, "verbose") || !strings.Contains(got, "quiet") {
		t.Errorf("stderr = %q, want the mutual-exclusion message naming both flags", got)
	}
}

// TestUsageErrorsArePlain: our own wording, the plain "error:" format (no
// timestamp, even with -v), one line.
func TestUsageErrorsArePlain(t *testing.T) {
	path := writeConfig(t, "")
	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"audit", "-v", "-q", "--config", path}, "error: -v/--verbose and -q/--quiet cannot be combined; pick one\n"},
		{[]string{"apply", "--dry-run", "--yes", "--config", path}, "error: --dry-run and --yes cannot be combined: --dry-run previews without writing, --yes writes without asking\n"},
		{[]string{"revoke", "bob", "--dry-run", "--yes", "--config", path}, "error: --dry-run and --yes cannot be combined: --dry-run previews without writing, --yes writes without asking\n"},
		{[]string{"audti"}, "error: unknown command \"audti\" (did you mean audit?); see 'sshepherd --help'\n"},
		{[]string{"zzz"}, "error: unknown command \"zzz\"; see 'sshepherd --help'\n"},
		// -v builds the timestamped logger before these checks run (root's
		// RunE, the run modes); usage errors still print plain.
		{[]string{"-v", "audti"}, "error: unknown command \"audti\" (did you mean audit?); see 'sshepherd --help'\n"},
		{[]string{"--verbose", "zzz"}, "error: unknown command \"zzz\"; see 'sshepherd --help'\n"},
		{[]string{"-v"}, "error: no command given (try --help)\n"},
		{[]string{"apply", "-v", "--dry-run", "--yes", "--config", path}, "error: --dry-run and --yes cannot be combined: --dry-run previews without writing, --yes writes without asking\n"},
		{[]string{"revoke", "bob", "-v", "--json", "--config", path}, "error: --json needs --dry-run or --yes (a script cannot answer the confirmation prompt)\n"},
	} {
		var out, errBuf bytes.Buffer
		if code := run(tt.args, &out, &errBuf); code != 3 {
			t.Errorf("%v: exit = %d, want 3", tt.args, code)
		}
		if errBuf.String() != tt.want {
			t.Errorf("%v: stderr = %q, want %q", tt.args, errBuf.String(), tt.want)
		}
	}
}

// TestHelpExamplesAndExitCodes: every subcommand shows examples and its
// exit-code footer, every example line parses against the real flag set,
// and README's Exit codes section carries every footer verbatim.
func TestHelpExamplesAndExitCodes(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{exitCodesAudit, exitCodesWrite, exitCodesAdopt, exitCodesImport, exitCodesValidate} {
		if !strings.Contains(string(raw), f) {
			t.Errorf("README lacks the --help footer:\n%s", f)
		}
	}
	// revoke/rotate --no-apply exit 0 with servers still to push; the footer
	// must not let a script read 0 as "converged" there.
	if !strings.Contains(exitCodesWrite, "--no-apply") {
		t.Errorf("exitCodesWrite does not say what exit 0 means under --no-apply:\n%s", exitCodesWrite)
	}
	for name, footer := range map[string]string{
		"audit": exitCodesAudit, "apply": exitCodesWrite, "revoke": exitCodesWrite, "rotate": exitCodesWrite,
		"adopt": exitCodesAdopt, "import": exitCodesImport, "validate": exitCodesValidate,
	} {
		var out, errBuf bytes.Buffer
		if code := run([]string{name, "--help"}, &out, &errBuf); code != 0 {
			t.Fatalf("%s --help exit = %d", name, code)
		}
		help := out.String()
		if !strings.Contains(help, "Examples:\n") || !strings.Contains(help, footer) {
			t.Errorf("%s --help lacks examples or footer:\n%s", name, help)
		}
		_, ex, _ := strings.Cut(help, "Examples:\n")
		for _, line := range strings.Split(ex, "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "sshepherd ") {
				continue
			}
			root := newRootCmd(&app{}, io.Discard, io.Discard)
			cmd, rest, err := root.Find(strings.Fields(line)[1:])
			if err == nil {
				err = cmd.ParseFlags(rest)
			}
			if err != nil {
				t.Errorf("%s example %q does not parse: %v", name, line, err)
			}
		}
	}
}

func TestRunInvalidColor(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--color", "sometimes"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "invalid color mode") {
		t.Errorf("stderr = %q, want the invalid-color message", errBuf.String())
	}
}

// TestRunQuietFatalStillPrints pins the spec promise: errors are never
// swallowed, quiet mode included.
func TestRunQuietFatalStillPrints(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"-q"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "no command") {
		t.Errorf("stderr = %q, want the fatal error even under -q", errBuf.String())
	}
	if !strings.HasPrefix(errBuf.String(), "error: ") {
		t.Errorf("stderr = %q, want the error: prefix", errBuf.String())
	}
}

// TestRunColorAlwaysFatal proves the --color flag reaches the logger: with
// always, the fatal line carries ANSI even though stderr is a buffer.
func TestRunColorAlwaysFatal(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--color", "always"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "\x1b[31merror:\x1b[0m") {
		t.Errorf("stderr = %q, want a red error: prefix", errBuf.String())
	}
	// A usage error under -v keeps the plain format and still honors --color.
	errBuf.Reset()
	if code := run([]string{"--color", "always", "-v", "audti"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit code = %d, want 3", code)
	}
	if !strings.HasPrefix(errBuf.String(), "\x1b[31merror:\x1b[0m unknown command") {
		t.Errorf("stderr = %q, want a red error: prefix and no timestamp", errBuf.String())
	}
}

func TestFmtDur(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{in: 34 * time.Millisecond, want: "34ms"},
		{in: 999 * time.Millisecond, want: "999ms"},
		{in: 2340 * time.Millisecond, want: "2.3s"},
		{in: 61 * time.Second, want: "1m1s"},
	}
	for _, tt := range tests {
		if got := fmtDur(tt.in); got != tt.want {
			t.Errorf("fmtDur(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestExitCodeFor pins the tool-wide exit contract from the 2026-07-16 spec:
// 0 ok, 1 drift/unreachable, 2 critical drift, 3 everything else.
func TestExitCodeFor(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"non-compliant", errNonCompliant, 1},
		{"fleet unreadable", errFleetUnreadable, 1},
		{"critical drift", errCriticalDrift, 2},
		{"wrapped critical", fmt.Errorf("audit: %w", errCriticalDrift), 2},
		{"generic error", errors.New("boom"), 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeFor(tt.err); got != tt.want {
				t.Errorf("exitCodeFor(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
