package main

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// readmeFlagCells returns the first-column cells of the flag table under
// README's "### `sshepherd <name>`" heading, e.g. "`--identity PATH`".
func readmeFlagCells(t *testing.T, readme, name string) []string {
	t.Helper()
	_, section, ok := strings.Cut(readme, "### `sshepherd "+name+"`")
	if !ok {
		t.Fatalf("README has no `sshepherd %s` section", name)
	}
	if i := strings.Index(section, "\n#"); i >= 0 {
		section = section[:i]
	}
	var cells []string
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `-") {
			continue
		}
		cells = append(cells, strings.TrimSpace(strings.Split(line, "|")[1]))
	}
	return cells
}

// helpFlagCell renders a flag as the README's first column spells it: the
// shorthand, the long name, and the --help varname when the usage names
// one with backticks (cobra's UnquoteUsage).
func helpFlagCell(f *pflag.Flag) string {
	cell := "--" + f.Name
	if f.Shorthand != "" {
		cell = "-" + f.Shorthand + ", " + cell
	}
	if strings.Contains(f.Usage, "`") {
		varname, _ := pflag.UnquoteUsage(f)
		cell += " " + varname
	}
	return "`" + cell + "`"
}

// TestHelpMatchesREADMETables: every local flag of audit/adopt/apply/revoke/rotate
// appears in its README table spelled as --help renders it (varnames
// included), and the tables list nothing --help does not.
func TestHelpMatchesREADMETables(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	var out, errBuf bytes.Buffer
	root := newRootCmd(&app{}, &out, &errBuf)
	for _, name := range []string{"audit", "adopt", "apply", "revoke", "rotate"} {
		t.Run(name, func(t *testing.T) {
			var cmd *cobra.Command
			for _, c := range root.Commands() {
				if c.Name() == name {
					cmd = c
				}
			}
			if cmd == nil {
				t.Fatalf("no %s command", name)
			}
			var want []string
			cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
				if f.Name != "help" && !f.Hidden {
					want = append(want, helpFlagCell(f))
				}
			})
			got := readmeFlagCells(t, string(raw), name)
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("README table for %s = %v\n--help flags        = %v", name, got, want)
			}
		})
	}
}

// TestHelpShowsIdentityVarnames pins the rendered --help lines.
func TestHelpShowsIdentityVarnames(t *testing.T) {
	for _, name := range []string{"audit", "adopt", "apply", "revoke", "rotate"} {
		var out, errBuf bytes.Buffer
		if code := run([]string{name, "--help"}, &out, &errBuf); code != 0 {
			t.Fatalf("%s --help exit = %d", name, code)
		}
		for _, want := range []string{"--identity PATH", "--identity-passphrase-file FILE", "--identity-passphrase KEY=FILE"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s --help lacks %q:\n%s", name, want, out.String())
			}
		}
	}
}
