package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// version is the binary version, overridden at build time via
// -ldflags "-X main.version=<v>". Defaults to "dev" for local builds.
var version = "dev"

// errNonCompliant signals exit code 1: the audit ran but the fleet is not
// (provably) compliant. Everything else non-nil maps to usage/config exit 2.
var errNonCompliant = errors.New("fleet not compliant")

// errFleetUnreadable signals exit code 1 for adopt's strict gate: some
// servers could not be read and --partial was not given. Per-server details
// are already on stderr.
var errFleetUnreadable = errors.New("fleet not fully readable")

// run is the testable entrypoint: it builds the Cobra tree, executes it
// against the provided streams, and maps errors to process exit codes.
func run(args []string, stdout, stderr io.Writer) int {
	root := newRootCmd(stdout, stderr)
	if args == nil {
		args = []string{} // SetArgs(nil) would fall back to os.Args[1:]
	}
	root.SetArgs(args)
	err := root.Execute()
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errNonCompliant), errors.Is(err, errFleetUnreadable):
		return 1 // report already rendered; nothing more to say
	default:
		fmt.Fprintln(stderr, "sshepherd:", err)
		return 2
	}
}

func newRootCmd(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "sshepherd",
		Short:         "Manage SSH authorized_keys across a fleet of servers",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true, // run() prints errors with consistent formatting
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("no command given (try --help)")
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("sshepherd {{.Version}}\n")
	root.AddCommand(newAuditCmd(stdout))
	root.AddCommand(newImportCmd(stdout))
	root.AddCommand(newAdoptCmd(stdout))
	return root
}
