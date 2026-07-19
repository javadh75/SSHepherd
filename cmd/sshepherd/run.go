package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/clog"
	"github.com/javadh75/SSHepherd/internal/config"
)

// version is the binary version, overridden at build time via
// -ldflags "-X main.version=<v>". Defaults to "dev" for local builds.
var version = "dev"

// errNonCompliant signals exit code 1: the audit ran but the fleet is not
// (provably) compliant. Everything else non-nil maps to usage/config exit 3.
var errNonCompliant = errors.New("fleet not compliant")

// errFleetUnreadable signals exit code 1 for adopt's strict gate: some
// servers could not be read and --partial was not given. Per-server details
// are already on stderr.
var errFleetUnreadable = errors.New("fleet not fully readable")

// errCriticalDrift signals exit code 2: the audit ran and at least one
// server is missing an operator key — the drift class that threatens fleet
// access itself.
var errCriticalDrift = errors.New("fleet has critical drift")

// app carries the per-invocation logging state from flag parsing
// (PersistentPreRunE) to the subcommands and to run()'s fatal-error path.
type app struct {
	logger      *slog.Logger // stderr logger; nil until flags are parsed
	reportColor bool         // whether stdout renderers may color
}

// log returns the flag-configured logger, or a plain never-colored fallback
// for failures before or during flag parsing (unknown flags, --color
// validation), where no explicit color choice can be known yet.
// The fallback constructs a second handler (own mutex) on the same stderr;
// that is safe only because it is used strictly after Execute returns, when
// the flag-built logger (if any) is no longer being written to.
func (a *app) log(stderr io.Writer) *slog.Logger {
	if a.logger != nil {
		return a.logger
	}
	return slog.New(clog.NewHandler(stderr, clog.Options{
		Level: slog.LevelInfo,
		Color: clog.Enabled(stderr, clog.ColorNever),
	}))
}

// fmtDur renders durations at operator resolution: whole milliseconds under
// a second, tenths of a second above.
func fmtDur(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

// logFleetReadDone logs the shared fleet-read summary line once a
// fan-out read returns, tallying how many servers came back with an
// error. A fleet with no servers never started a read phase, so it
// logs nothing.
func logFleetReadDone(log *slog.Logger, cfg *config.Config, results []audit.ServerResult, start time.Time) {
	if len(cfg.Servers) == 0 {
		return
	}
	var unreachable int
	for _, r := range results {
		if r.Err != nil {
			unreachable++
		}
	}
	log.Info(fmt.Sprintf("done in %s — %d read, %d unreachable",
		fmtDur(time.Since(start)), len(results)-unreachable, unreachable))
}

// run is the testable entrypoint: it builds the Cobra tree, executes it
// against the provided streams, and maps errors to process exit codes.
func run(args []string, stdout, stderr io.Writer) int {
	a := &app{}
	root := newRootCmd(a, stdout, stderr)
	if args == nil {
		args = []string{} // SetArgs(nil) would fall back to os.Args[1:]
	}
	root.SetArgs(args)
	err := root.Execute()
	code := exitCodeFor(err)
	if code == 3 {
		a.log(stderr).Error(err.Error())
	}
	return code
}

// exitCodeFor maps Execute's error to the monitoring-style process exit code
// (see docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md).
// Sentinel-mapped outcomes have already rendered their report; only the
// tool-error case (3) still needs the error logged.
func exitCodeFor(err error) int {
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errNonCompliant), errors.Is(err, errFleetUnreadable):
		return 1
	case errors.Is(err, errCriticalDrift):
		return 2
	default:
		return 3
	}
}

func newRootCmd(a *app, stdout, stderr io.Writer) *cobra.Command {
	var (
		verbose   bool
		quiet     bool
		colorFlag string
	)
	root := &cobra.Command{
		Use:           "sshepherd",
		Short:         "Manage SSH authorized_keys across a fleet of servers",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true, // run() prints errors with consistent formatting
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			mode, err := clog.ParseColorMode(colorFlag)
			if err != nil {
				return fmt.Errorf("--color: %w", err)
			}
			level := slog.LevelInfo
			switch {
			case quiet:
				level = slog.LevelError
			case verbose:
				level = slog.LevelDebug
			}
			a.logger = slog.New(clog.NewHandler(stderr, clog.Options{
				Level:   level,
				Color:   clog.Enabled(stderr, mode),
				Verbose: verbose,
			}))
			a.reportColor = clog.Enabled(stdout, mode)
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("no command given (try --help)")
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("sshepherd {{.Version}}\n")
	pf := root.PersistentFlags()
	pf.BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")
	pf.BoolVarP(&quiet, "quiet", "q", false, "log errors only")
	pf.StringVar(&colorFlag, "color", "auto", "colorize output: auto, always, or never")
	root.MarkFlagsMutuallyExclusive("verbose", "quiet")
	root.AddCommand(newAuditCmd(a, stdout))
	root.AddCommand(newImportCmd(a, stdout))
	root.AddCommand(newAdoptCmd(a, stdout))
	root.AddCommand(newApplyCmd(a, stdout))
	return root
}
