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

// readmeFlagRow is one row of a README flag table: its flag cell and its
// default cell, e.g. {"`--parallel`", "`32`"}.
type readmeFlagRow struct{ flag, def string }

// readmeFlagRows returns the flag-table rows under the README heading line
// that equals heading exactly, up to the next heading.
func readmeFlagRows(t *testing.T, readme, heading string) []readmeFlagRow {
	t.Helper()
	_, section, ok := strings.Cut(readme, "\n"+heading+"\n")
	if !ok {
		t.Fatalf("README has no %q heading", heading)
	}
	if i := strings.Index(section, "\n#"); i >= 0 {
		section = section[:i]
	}
	var rows []readmeFlagRow
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "| `-") {
			continue
		}
		cells := strings.Split(line, "|")
		rows = append(rows, readmeFlagRow{strings.TrimSpace(cells[1]), strings.TrimSpace(cells[2])})
	}
	return rows
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

// zeroDefaultWords are the README's words for "no default value".
var zeroDefaultWords = []string{"none", "—", "all", "stdout"}

// defaultMatches reports whether a README default cell spells f's --help
// default: off/on for a bool, one of zeroDefaultWords for an unset value,
// otherwise the default itself in backticks.
func defaultMatches(f *pflag.Flag, cell string) bool {
	switch {
	case f.Value.Type() == "bool":
		return cell == map[string]string{"false": "off", "true": "on"}[f.DefValue]
	case f.DefValue == "" || f.DefValue == "[]":
		return slices.Contains(zeroDefaultWords, cell)
	default:
		return cell == "`"+f.DefValue+"`"
	}
}

// flagSet picks which of a command's flags a README table documents.
type flagSet int

const (
	localFlags      flagSet = iota // every flag the command's --help lists under Flags
	persistentFlags                // the root's flags that every command inherits
	rootOnlyFlags                  // the root's flags no subcommand accepts (--version)
)

func (s flagSet) of(cmd *cobra.Command) *pflag.FlagSet {
	switch s {
	case persistentFlags:
		return cmd.PersistentFlags()
	case rootOnlyFlags:
		return cmd.LocalNonPersistentFlags()
	default:
		return cmd.LocalFlags()
	}
}

// TestHelpMatchesREADMETables: for the root and every command, the README
// table lists exactly the flags --help shows (varnames included), and each
// row's default matches the flag's --help default (TST-4). The root's flags
// split in two: "Global flags" (persistent, accepted by every command) and
// "Top-level flags" (root-only, e.g. --version), so the README never calls
// a root-only flag global.
func TestHelpMatchesREADMETables(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	readme := string(raw)
	var out, errBuf bytes.Buffer
	root := newRootCmd(&app{}, &out, &errBuf)
	root.InitDefaultVersionFlag() // cobra adds --version lazily at Execute
	tables := []struct {
		name, heading string
		set           flagSet
	}{
		{"", "### Global flags", persistentFlags},
		{"", "### Top-level flags", rootOnlyFlags},
		{"audit", "### `sshepherd audit`", localFlags},
		{"import", "### `sshepherd import [ssh-config-path]`", localFlags},
		{"adopt", "### `sshepherd adopt`", localFlags},
		{"apply", "### `sshepherd apply`", localFlags},
		{"revoke", "### `sshepherd revoke`", localFlags},
		{"rotate", "### `sshepherd rotate`", localFlags},
		{"validate", "### `sshepherd validate`", localFlags},
	}
	for _, tc := range tables {
		t.Run(tc.heading, func(t *testing.T) {
			cmd := root
			if tc.name != "" {
				cmd = nil
				for _, c := range root.Commands() {
					if c.Name() == tc.name {
						cmd = c
					}
				}
				if cmd == nil {
					t.Fatalf("no %s command", tc.name)
				}
			}
			rows := readmeFlagRows(t, readme, tc.heading)
			defaults := map[string]string{}
			var got []string
			for _, r := range rows {
				got = append(got, r.flag)
				defaults[r.flag] = r.def
			}
			var want []string
			tc.set.of(cmd).VisitAll(func(f *pflag.Flag) {
				if f.Name == "help" || f.Hidden {
					return
				}
				cell := helpFlagCell(f)
				want = append(want, cell)
				if def, ok := defaults[cell]; ok && !defaultMatches(f, def) {
					t.Errorf("README default for %s = %s; --help default is %q", cell, def, f.DefValue)
				}
			})
			slices.Sort(want)
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("README table %s = %v\n--help flags = %v", tc.heading, got, want)
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
