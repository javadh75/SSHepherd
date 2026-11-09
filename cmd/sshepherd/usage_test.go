package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

// TestFlagUsagesMatchesPflag109Layout pins pflag v1.0.9's layout: bool
// flags carry no [=true|false] suffix, varnames and non-zero defaults are
// kept, hidden flags are skipped, and the usage column is aligned.
func TestFlagUsagesMatchesPflag109Layout(t *testing.T) {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	fs.BoolP("yes", "y", false, "skip the prompt")
	fs.Bool("dry-run", false, "plan only")
	fs.String("config", "sshepherd.yaml", "path to the manifest")
	fs.Int("parallel", 32, "max connections")
	fs.StringArray("identity", nil, "private key `PATH` to use")
	fs.Bool("secret", false, "never shown")
	if err := fs.MarkHidden("secret"); err != nil {
		t.Fatal(err)
	}
	want := "" +
		"      --config string   path to the manifest (default \"sshepherd.yaml\")\n" +
		"      --dry-run         plan only\n" +
		"      --identity PATH   private key PATH to use\n" +
		"      --parallel int    max connections (default 32)\n" +
		"  -y, --yes             skip the prompt\n"
	if got := flagUsages(fs); got != want {
		t.Errorf("flagUsages =\n%s\nwant\n%s", got, want)
	}
}

// TestFlagUsagesLeavesSourceFlagsUntouched: rendering wraps a copy only;
// the real bool flag still parses without a value.
func TestFlagUsagesLeavesSourceFlagsUntouched(t *testing.T) {
	fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
	yes := fs.Bool("yes", false, "skip the prompt")
	_ = flagUsages(fs)
	if err := fs.Parse([]string{"--yes"}); err != nil {
		t.Fatalf("--yes without a value no longer parses: %v", err)
	}
	if !*yes {
		t.Fatal("--yes did not set the flag")
	}
	if f := fs.Lookup("yes"); f.NoOptDefVal != "true" {
		t.Errorf("NoOptDefVal = %q, want \"true\"", f.NoOptDefVal)
	}
}

// TestUsageTemplateRoutesBothFlagSections guards against a cobra upgrade
// changing its default template so the rewrite silently misses.
func TestUsageTemplateRoutesBothFlagSections(t *testing.T) {
	for _, want := range []string{"{{flagUsages .LocalFlags", "{{flagUsages .InheritedFlags"} {
		if !strings.Contains(usageTemplate, want) {
			t.Errorf("usageTemplate lacks %q:\n%s", want, usageTemplate)
		}
	}
	if strings.Contains(usageTemplate, ".FlagUsages") {
		t.Errorf("usageTemplate still calls pflag's FlagUsages directly:\n%s", usageTemplate)
	}
}

// helpCommands is the root ("") plus every user-facing command; the
// golden and no-suffix tests iterate it.
var helpCommands = []string{"", "audit", "import", "adopt", "apply", "revoke", "rotate", "validate"}

// helpOutput runs `sshepherd [name] --help` and returns stdout.
func helpOutput(t *testing.T, name string) string {
	t.Helper()
	args := []string{"--help"}
	if name != "" {
		args = []string{name, "--help"}
	}
	var out, errBuf bytes.Buffer
	if code := run(args, &out, &errBuf); code != 0 {
		t.Fatalf("%v exit = %d, stderr: %s", args, code, errBuf.String())
	}
	return out.String()
}

// TestHelpHasNoBoolValueSuffix: no command's --help shows pflag v1.1.0's
// [=true|false] suffix, in Flags or Global Flags (UX-13/UX-2).
func TestHelpHasNoBoolValueSuffix(t *testing.T) {
	for _, name := range helpCommands {
		got := helpOutput(t, name)
		if strings.Contains(got, "[=true|false]") {
			t.Errorf("%q --help renders a bool value suffix:\n%s", name, got)
		}
		if !strings.Contains(got, "  -h, --help ") {
			t.Errorf("%q --help lacks a plain `-h, --help` line:\n%s", name, got)
		}
	}
}
