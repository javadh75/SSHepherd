package main

import (
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
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
		cf       connFlags
		jsonOut  bool
		comments bool
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Report drift between the manifest and each server's authorized_keys (read-only)",
		Long: "Reports drift between the manifest and each server's authorized_keys.\n" +
			"Read-only: nothing is written to any server.\n\n" + exitCodesAudit,
		Example: "  # Check the whole fleet\n" +
			"  sshepherd audit --config fleet.yaml\n\n" +
			"  # Monitoring: JSON report on stdout, alert on the exit code\n" +
			"  sshepherd audit --json --config fleet.yaml",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ids, err := cf.validate()
			if err != nil {
				return err
			}
			log := a.logger
			cfg, err := config.Load(cf.cfgPath)
			if err != nil {
				return manifestError("--config", cf.cfgPath, err)
			}
			logManifest(log, cfg)
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
				if err := render(nil); err != nil {
					return err
				}
				return auditVerdict(cfg, nil) // a policy conflict is critical with no server read
			}
			results, err := readFleet(cmd.Context(), log, cfg, &cf, ids, "auditing")
			if err != nil {
				return err
			}
			if err := render(results); err != nil {
				return err
			}
			return auditVerdict(cfg, results)
		},
	}
	cf.register(cmd, "max concurrent server audits")
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
