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
	defaultParallel   = 10
	dialTimeout       = 10 * time.Second
	perServerTimeout  = 30 * time.Second
	defaultKnownHosts = "~/.ssh/known_hosts"
)

func newAuditCmd(stdout io.Writer) *cobra.Command {
	var (
		cfgPath    string
		knownHosts string
		parallel   int
	)
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Report drift between the manifest and each server's authorized_keys (read-only)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if parallel < 1 {
				return fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
			}
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err) // wrapcheck: wrap at package boundary
			}
			if len(cfg.Servers) == 0 {
				audit.Render(stdout, cfg, nil)
				return nil
			}
			if err := sshread.CheckAgent(os.Getenv("SSH_AUTH_SOCK")); err != nil {
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
			}
			results := audit.Run(cmd.Context(), cfg, reader, audit.Options{
				Parallel:         parallel,
				PerServerTimeout: perServerTimeout,
			})
			audit.Render(stdout, cfg, results)
			if audit.ExitCode(results) != 0 {
				return errNonCompliant
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "sshepherd.yaml", "path to the manifest")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&parallel, "parallel", defaultParallel, "max concurrent server audits")
	return cmd
}
