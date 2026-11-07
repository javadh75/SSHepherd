package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// usageTemplate is cobra's own default usage template with the Flags and
// Global Flags sections sent through flagUsages. It is derived from the
// cobra in go.mod, so a cobra upgrade keeps its layout;
// TestUsageTemplateRoutesBothFlagSections fails if the rewrite misses.
var usageTemplate = strings.NewReplacer(
	".LocalFlags.FlagUsages", "flagUsages .LocalFlags",
	".InheritedFlags.FlagUsages", "flagUsages .InheritedFlags",
).Replace((&cobra.Command{}).UsageTemplate())

// init registers flagUsages before any template is parsed: cobra parses
// usage templates lazily against its global function map.
func init() {
	cobra.AddTemplateFunc("flagUsages", flagUsages)
}

// plainBool hides IsBoolFlag from pflag's usage renderer. pflag v1.1.0
// appends "[=true|false]" to every value whose IsBoolFlag is true
// (flag.go:794), with no option to turn it off. It wraps a render-only
// copy; the parsed flag keeps its real value.
type plainBool struct{ pflag.Value }

// flagUsages renders fs exactly as pflag's FlagUsages does, minus the
// v1.1.0 bool suffix: `--yes`, not `--yes[=true|false]`. Order, hidden
// flags, varnames, defaults and alignment all stay pflag's own.
func flagUsages(fs *pflag.FlagSet) string {
	view := pflag.NewFlagSet("usage", pflag.ContinueOnError)
	view.SortFlags = fs.SortFlags
	fs.VisitAll(func(f *pflag.Flag) {
		c := *f
		if c.Value.Type() == "bool" {
			c.Value = plainBool{c.Value}
		}
		view.AddFlag(&c)
	})
	return view.FlagUsages()
}
