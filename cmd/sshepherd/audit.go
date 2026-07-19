package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshread"
)

const (
	// defaultParallel is sized from the fan-out benchmarks (make bench),
	// not core count: workers are network-blocked, scheduler overhead per
	// server is negligible through p=128, and straggler wall time is
	// timeout × ⌈hung/parallel⌉ — at 32 a burst of 25 unreachable hosts
	// costs one 30s wave instead of three. 32 keeps the socket/agent burst
	// modest on an operator machine; see the tuning note in
	// docs/superpowers/specs/2026-07-06-audit-slice-design.md.
	defaultParallel   = 32
	dialTimeout       = 10 * time.Second
	perServerTimeout  = 30 * time.Second
	defaultKnownHosts = "~/.ssh/known_hosts"
)

func newAuditCmd(a *app, stdout io.Writer) *cobra.Command {
	var (
		cfgPath    string
		knownHosts string
		parallel   int
		jsonOut    bool
		comments   bool
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Report drift between the manifest and each server's authorized_keys (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if parallel < 1 {
				return fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
			}
			log := a.logger
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err) // wrapcheck: wrap at package boundary
			}
			log.Info(fmt.Sprintf("loaded manifest: %d users, %d servers", len(cfg.Users), len(cfg.Servers)))
			for _, w := range cfg.Warnings {
				log.Warn(w)
			}
			// One render path for the empty-fleet early return and the main
			// flow, so the two cannot drift apart.
			render := func(results []audit.ServerResult) error {
				if jsonOut {
					return audit.RenderJSON(stdout, cfg, results, audit.JSONOptions{Comments: comments})
				}
				audit.Render(stdout, cfg, results, audit.RenderOptions{Color: a.reportColor, Comments: comments})
				return nil
			}
			if len(cfg.Servers) == 0 {
				return render(nil)
			}
			if err := sshread.CheckAgent(cmd.Context(), os.Getenv("SSH_AUTH_SOCK")); err != nil {
				return fmt.Errorf("agent preflight: %w", err)
			}
			khPath, err := expandHome(knownHosts)
			if err != nil {
				return err
			}
			// Preflight known_hosts once: a bad path fails with a single
			// clear error instead of N identical per-server errors.
			if err := sshread.PreflightKnownHosts(khPath); err != nil {
				return fmt.Errorf("known_hosts preflight: %w", err)
			}
			reader := &sshread.Client{
				KnownHostsPath: khPath,
				AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
				DialTimeout:    dialTimeout,
				Log:            log,
			}
			log.Info(fmt.Sprintf("auditing %d servers (parallelism %d)…", len(cfg.Servers), parallel))
			start := time.Now()
			results := audit.Run(cmd.Context(), cfg, reader, audit.Options{
				Parallel:         parallel,
				PerServerTimeout: perServerTimeout,
				Logger:           log,
			})
			logFleetReadDone(log, cfg, results, start)
			if err := render(results); err != nil {
				return err
			}
			return auditVerdict(cfg, results)
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "sshepherd.yaml", "path to the manifest")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&parallel, "parallel", defaultParallel, "max concurrent server audits")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "emit the report as machine-readable JSON on stdout")
	cmd.Flags().BoolVar(&comments, "comments", false,
		"also report comment drift on present keys (informational; never affects the exit code)")
	return cmd
}

// auditVerdict converts the fleet's ExitCode into run()'s sentinel errors so
// the process exits 0 (compliant), 1 (drift/unreachable), or 2 (critical).
func auditVerdict(cfg *config.Config, results []audit.ServerResult) error {
	switch audit.ExitCode(cfg, results) {
	case 2:
		return errCriticalDrift
	case 1:
		return errNonCompliant
	default:
		return nil
	}
}
