package main

import (
	"bytes"
	"cmp"
	"os"
	"slices"
	"strings"
	"testing"

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

// TestHelpMatchesREADMETables: for the root and every command, the README
// table lists exactly the flags --help shows (varnames included), and each
// row's default matches the flag's --help default (TST-4).
func TestHelpMatchesREADMETables(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatalf("README: %v", err)
	}
	readme := string(raw)
	var out, errBuf bytes.Buffer
	root := newRootCmd(&app{}, &out, &errBuf)
	root.InitDefaultVersionFlag() // cobra adds --version lazily at Execute
	tables := []struct{ name, heading string }{
		{"", "### Global flags"},
		{"audit", "### `sshepherd audit`"},
		{"import", "### `sshepherd import [ssh-config-path]`"},
		{"adopt", "### `sshepherd adopt`"},
		{"apply", "### `sshepherd apply`"},
		{"revoke", "### `sshepherd revoke`"},
		{"rotate", "### `sshepherd rotate`"},
	}
	for _, tc := range tables {
		t.Run(cmp.Or(tc.name, "root"), func(t *testing.T) {
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
			cmd.LocalFlags().VisitAll(func(f *pflag.Flag) {
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
				t.Errorf("README table for %s = %v\n--help flags        = %v", cmp.Or(tc.name, "root"), got, want)
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
