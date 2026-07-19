package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshread"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
)

func newApplyCmd(a *app, stdout io.Writer) *cobra.Command {
	var (
		cfgPath    string
		knownHosts string
		parallel   int
		serverSel  []string
		dryRun     bool
		yes        bool
	)
	cmd := &cobra.Command{
		Use:   "apply",
		Short: "Make each server's authorized_keys match the manifest (writes to the fleet)",
		Long: "Makes each targeted server's authorized_keys equal the manifest's rendered\n" +
			"desired state — a FULL-FILE rewrite (managed header, operator keys first,\n" +
			"decided comment policy). Non-key lines (hand-written comments, blank lines)\n" +
			"are DELETED by the rewrite; the plan shows a normalize row with the count\n" +
			"before anything is written. Flow: read the whole fleet, show one plan,\n" +
			"confirm once (interactive prompt, or --yes), then write only drifted\n" +
			"servers — atomically (temp file + rename), with a .sshepherd.bak backup\n" +
			"and a read-back verify. A self-lockout guard refuses any write that would\n" +
			"remove every agent-held key from a server. --dry-run previews the plan\n" +
			"and never writes.",
		Args: cobra.NoArgs,
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
			targets, err := selectServers(cfg, serverSel)
			if err != nil {
				return err
			}
			skipped := len(cfg.Servers) - len(targets)
			ropts := apply.RenderOptions{Color: a.reportColor}
			if len(targets) == 0 {
				apply.Render(stdout, cfg, nil, ropts)
				return nil
			}

			khPath, agentFPs, err := applyPreflight(cmd.Context(), knownHosts)
			if err != nil {
				return err
			}

			// Phase 1: read + plan (audit's pipeline over the targeted subset).
			reader := &sshread.Client{
				KnownHostsPath: khPath,
				AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
				DialTimeout:    dialTimeout,
				Log:            log,
			}
			log.Info(fmt.Sprintf("planning %d servers (parallelism %d)…", len(targets), parallel))
			start := time.Now()
			results := audit.Run(cmd.Context(), cfg, reader, audit.Options{
				Parallel:         parallel,
				PerServerTimeout: perServerTimeout,
				Servers:          targets,
				Logger:           log,
			})
			logFleetReadDone(log, cfg, results, start)
			plans, err := apply.Build(cfg, results, agentFPs)
			if err != nil {
				return fmt.Errorf("plan: %w", err) // wrapcheck: wrap at package boundary
			}
			apply.Render(stdout, cfg, plans, ropts)

			finish := func() error {
				apply.RenderSummary(stdout, plans, ropts)
				if skipped > 0 {
					fmt.Fprintf(stdout, "(%d servers skipped by --server)\n", skipped)
				}
				if apply.ExitCode(plans) != 0 {
					return errNonCompliant
				}
				return nil
			}

			toApply := countChanges(plans)
			if toApply == 0 || dryRun {
				// Nothing to confirm (or a preview): report + summary only.
				return finish()
			}

			// Confirmation gate: prompt on stderr, answer from stdin, so
			// `apply > plan.txt` captures exactly the report.
			in := cmd.InOrStdin()
			errW := cmd.ErrOrStderr()
			ok, err := confirm(in, errW, stdioIsTTY(in, errW), yes, toApply, len(plans))
			if err != nil {
				return err
			}
			if !ok {
				log.Error("aborted; no changes made")
				return finish() // pending changes → exit 1
			}

			// Phase 2: write drifted servers only.
			writer := &sshwrite.FleetWriter{
				Dialer: &sshconn.Dialer{
					KnownHostsPath: khPath,
					AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
					DialTimeout:    dialTimeout,
					Log:            log,
				},
				Log: log,
			}
			log.Info(fmt.Sprintf("applying %d servers (parallelism %d)…", toApply, parallel))
			apply.Execute(cmd.Context(), plans, writer, apply.ExecOptions{
				Parallel:         parallel,
				PerServerTimeout: perServerTimeout,
				AgentFPs:         agentFPs,
				Logger:           log,
			})
			return finish()
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "sshepherd.yaml", "path to the manifest")
	cmd.Flags().StringVar(&knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&parallel, "parallel", defaultParallel, "max concurrent server connections")
	cmd.Flags().StringArrayVar(&serverSel, "server", nil, "restrict the run to this server (repeatable; canary rollout)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "plan and report only; never write")
	cmd.Flags().BoolVar(&yes, "yes", false, "skip the confirmation prompt (automation)")
	cmd.MarkFlagsMutuallyExclusive("dry-run", "yes")
	return cmd
}

// applyPreflight runs apply's pre-dial checks: audit's agent and
// known_hosts preflights, plus the agent-fingerprint capture that is the
// self-lockout guard's ground truth.
func applyPreflight(ctx context.Context, knownHosts string) (khPath string, agentFPs []string, err error) {
	if err := sshread.CheckAgent(ctx, os.Getenv("SSH_AUTH_SOCK")); err != nil {
		return "", nil, fmt.Errorf("agent preflight: %w", err)
	}
	agentFPs, err = sshconn.AgentFingerprints(ctx, os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return "", nil, fmt.Errorf("agent preflight: %w", err)
	}
	khPath, err = expandHome(knownHosts)
	if err != nil {
		return "", nil, err
	}
	if err := sshread.PreflightKnownHosts(khPath); err != nil {
		return "", nil, fmt.Errorf("known_hosts preflight: %w", err)
	}
	return khPath, agentFPs, nil
}

// countChanges tallies the servers phase 2 would write.
func countChanges(plans []apply.ServerPlan) int {
	n := 0
	for _, p := range plans {
		if p.Class == apply.ClassChange {
			n++
		}
	}
	return n
}

// selectServers resolves --server names to manifest servers, preserving
// manifest order and deduplicating; no names selects the whole fleet. An
// unknown name is a usage error — a canary typo must not silently apply
// nothing.
func selectServers(cfg *config.Config, names []string) ([]config.Server, error) {
	if len(names) == 0 {
		return cfg.Servers, nil
	}
	known := make(map[string]bool, len(cfg.Servers))
	for _, s := range cfg.Servers {
		known[s.Name] = true
	}
	wanted := make(map[string]bool, len(names))
	for _, n := range names {
		if !known[n] {
			return nil, fmt.Errorf("--server: unknown server %q", n)
		}
		wanted[n] = true
	}
	var targets []config.Server
	for _, s := range cfg.Servers {
		if wanted[s.Name] {
			targets = append(targets, s)
		}
	}
	return targets, nil
}

// confirm gates phase 2. --yes short-circuits; otherwise a TTY prompts once
// on stderr, defaulting to no; non-TTY without --yes is a usage error —
// automation must opt in explicitly, never by accident of a pipe.
func confirm(in io.Reader, errW io.Writer, tty, yes bool, n, total int) (bool, error) {
	if yes {
		return true, nil
	}
	if !tty {
		return false, errors.New("confirmation required: re-run with --yes (or --dry-run to preview) — stdin/stderr is not a terminal")
	}
	fmt.Fprintf(errW, "apply %d of %d servers? [y/N] ", n, total)
	sc := bufio.NewScanner(in)
	if !sc.Scan() {
		return false, nil // EOF (Ctrl-D) declines
	}
	switch strings.ToLower(strings.TrimSpace(sc.Text())) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}

// stdioIsTTY reports whether both in and errW are terminals — the prompt
// contract needs both: stdin to read the answer, stderr to show the
// question even when stdout is redirected.
func stdioIsTTY(in io.Reader, errW io.Writer) bool {
	fi, ok := in.(*os.File)
	if !ok || !term.IsTerminal(int(fi.Fd())) {
		return false
	}
	fe, ok := errW.(*os.File)
	return ok && term.IsTerminal(int(fe.Fd()))
}
