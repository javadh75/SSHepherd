package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/clog"
	"github.com/javadh75/SSHepherd/internal/config"
)

// version is the binary version, overridden at build time via
// -ldflags "-X main.version=<v>" (make build, make dist, the Dockerfile).
// resolveVersion falls back to the module version when it is left at "dev".
var version = "dev"

// resolveVersion picks the version --version prints: the -X main.version
// value (make build, Dockerfile, release binaries) when set; otherwise the
// module version the go command stamped (go install …@vX.Y.Z, or a VCS
// pseudo-version for a build inside a git checkout); otherwise "dev".
func resolveVersion(ldflag string, read func() (*debug.BuildInfo, bool)) string {
	if ldflag != "dev" && ldflag != "" {
		return ldflag
	}
	if bi, ok := read(); ok && bi != nil && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

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
	errColor    bool         // whether stderr may color; false until flags are parsed
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
	return a.plainLog(stderr)
}

// plainLog is the "error: …" format with no timestamp, whatever -v says:
// the pre-parse fallback, and how runContext prints a usageError. It
// colors as --color resolved for stderr (never, before flags are parsed).
// Like the fallback, it is a second handler on stderr, used only after
// Execute returns.
func (a *app) plainLog(stderr io.Writer) *slog.Logger {
	return slog.New(clog.NewHandler(stderr, clog.Options{Level: slog.LevelInfo, Color: a.errColor}))
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

// run is the process entrypoint: SIGINT/SIGTERM cancel the command's
// context instead of killing the process, so in-flight work unwinds through
// ctx (sessions close, apply reports what it finished) and run still maps
// the outcome to an exit code. A second signal exits at once (see
// watchSignals).
func run(args []string, stdout, stderr io.Writer) int {
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	ctx, stop := watchSignals(context.Background(), sigs, os.Exit)
	defer func() {
		signal.Stop(sigs)
		stop()
	}()
	return runContext(ctx, args, stdout, stderr)
}

// watchSignals cancels the returned context on the first signal from sigs
// and calls exit(128+signo) on a second one. The forced exit is explicit
// rather than "re-raise and let the default action kill us": in a container
// sshepherd may run as PID 1 (the distroless image has no init), and the
// kernel ignores default signal actions for PID 1. stop ends the watcher
// and cancels the context.
func watchSignals(parent context.Context, sigs <-chan os.Signal, exit func(int)) (ctx context.Context, stop func()) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		canceled := false
		for {
			select {
			case s := <-sigs:
				if !canceled {
					canceled = true
					cancel()
					continue
				}
				code := 130 // 128 + SIGINT
				if sn, ok := s.(syscall.Signal); ok {
					code = 128 + int(sn)
				}
				exit(code)
				return
			case <-done:
				return
			}
		}
	}()
	return ctx, func() {
		close(done)
		cancel()
	}
}

// runContext is the testable entrypoint: it builds the Cobra tree, executes
// it under ctx against the provided streams, and maps errors to process
// exit codes.
func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	a := &app{}
	root := newRootCmd(a, stdout, stderr) //nolint:contextcheck // the tree receives ctx through ExecuteContext below
	if args == nil {
		args = []string{} // SetArgs(nil) would fall back to os.Args[1:]
	}
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	code := exitCodeFor(err)
	if code == 3 {
		log := a.log(stderr)
		if errors.As(err, new(usageError)) {
			log = a.plainLog(stderr)
		}
		log.Error(err.Error())
	}
	return code
}

// usageError is a bad invocation found after flag parsing (an unknown
// command, contradictory run modes). runContext prints it through plainLog,
// the format cobra's own flag errors get, so -v never timestamps it.
type usageError struct{ error }

func (e usageError) Unwrap() error { return e.error }

// The exitCodes* footers end each subcommand's --help description (audit;
// apply/revoke/rotate; adopt; import); README's Exit codes section carries
// every one verbatim.
const exitCodesAudit = `Exit codes:
  0  compliant (a header serial below the manifest's is not drift)
  1  drift or unreachable servers (compliance not proven), including a server
     written by a newer manifest serial and a key installed where its access
     was revoked
  2  critical: a missing operator key or one that cannot log in, a changed or
     @revoked host key or a changed host key type, a world-writable managed
     path, a revoked key still installed, a forged header serial, or a policy
     conflict in the manifest
  3  tool error: bad flags, unloadable manifest, failed preflight, interrupted`

const exitCodesWrite = `Exit codes:
  0  converged: nothing left to do (a header-only update applied, or a server
     a newer manifest wrote whose keys already match); a revoke whose targets
     were already revoked; or, with revoke/rotate --no-apply, the edit is
     saved but not pushed (run the apply hint it prints)
  1  pending changes, unreachable, refused or failed servers (a newer
     manifest's serial, a policy conflict), a write whose login check could
     not prove access (unproven), or a declined prompt; with --sweep, a server
     the sweep could not read
  2  a human must act now: a lockout not restored (the restore of
     authorized_keys or authorized_keys2 after a rejected login check failed,
     or the reconnect after the upload started was refused), a rollback that
     put back a key on the revoked: list, a changed or @revoked host key or a
     changed host key type at the post-write login check, or revoke/rotate
     --sweep found a revoked key still installed
  3  tool error: bad flags, unloadable manifest, failed preflight, a manifest
     that would keep a policy conflict or add a weak key, a failed serial
     save, or refused before anything was saved or written`

const exitCodesAdopt = `Exit codes:
  0  manifest emitted
  1  a server could not be fully read and --partial was not given (nothing
     emitted), or --partial could not read some servers (the partial manifest
     is emitted)
  3  tool error: bad flags, unloadable manifest, failed preflight, an existing
     --output without --force, an in-place save refused, a manifest that
     would keep a policy conflict or add a weak key, --partial with no server
     read, interrupted`

const exitCodesImport = `Exit codes:
  0  manifest emitted
  3  tool error: bad flags, unreadable ssh config or --merge manifest, an
     existing --output without --force, an in-place save refused, a --merge
     manifest that would keep a policy conflict or add a weak key`

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
		Version:       resolveVersion(version, debug.ReadBuildInfo),
		SilenceUsage:  true,
		SilenceErrors: true, // run() prints errors with consistent formatting
		// Args: any, so cobra's legacyArgs never builds its multi-line
		// "Did you mean this?" error; RunE words an unknown command on one line.
		Args: cobra.ArbitraryArgs,
		// cobra's own default, which it applies only inside its finder;
		// SuggestionsFor reads the field as is.
		SuggestionsMinimumDistance: 2,
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			// Checked before a.logger is built, so the error prints through
			// the plain fallback handler (no timestamp, even with -v).
			if verbose && quiet {
				return errors.New("-v/--verbose and -q/--quiet cannot be combined; pick one")
			}
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
			a.errColor = clog.Enabled(stderr, mode)
			a.logger = slog.New(clog.NewHandler(stderr, clog.Options{
				Level:   level,
				Color:   a.errColor,
				Verbose: verbose,
			}))
			a.reportColor = clog.Enabled(stdout, mode)
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return usageError{errors.New("no command given (try --help)")}
			}
			if s := cmd.SuggestionsFor(args[0]); len(s) > 0 {
				return usageError{fmt.Errorf("unknown command %q (did you mean %s?); see 'sshepherd --help'", args[0], strings.Join(s, ", "))}
			}
			return usageError{fmt.Errorf("unknown command %q; see 'sshepherd --help'", args[0])}
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("sshepherd {{.Version}}\n")
	root.SetUsageTemplate(usageTemplate) // bool flags without pflag v1.1.0's [=true|false]; see usage.go
	pf := root.PersistentFlags()
	pf.BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")
	pf.BoolVarP(&quiet, "quiet", "q", false, "log errors only")
	pf.StringVar(&colorFlag, "color", "auto", "colorize output: auto, always, or never")
	root.AddCommand(newAuditCmd(a, stdout))
	root.AddCommand(newImportCmd(a, stdout))
	root.AddCommand(newAdoptCmd(a, stdout))
	root.AddCommand(newApplyCmd(a, stdout))
	root.AddCommand(newRevokeCmd(a, stdout))
	root.AddCommand(newRotateCmd(a, stdout))
	return root
}
