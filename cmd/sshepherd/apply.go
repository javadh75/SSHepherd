package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
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
		idf        identityFlags
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
			"servers — atomically (length-checked temp file + rename, under a\n" +
			"per-file lock), with a .sshepherd.bak backup of the previous version, a\n" +
			"one-time .sshepherd.orig of the pre-SSHepherd file, and a read-back\n" +
			"verify. A server whose file changed after the plan was read is refused\n" +
			"(re-run apply). A self-lockout guard refuses any write that would leave\n" +
			"no key you hold (identity files + agent) on a server; after each write a\n" +
			"fresh login offering only the surviving keys must succeed, or the\n" +
			"previous file is restored. --yes skips only the confirmation: an\n" +
			"encrypted --identity key may still prompt for its passphrase.\n" +
			"Ctrl-C stops new writes; started ones finish. --dry-run previews the\n" +
			"plan and never writes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ids, err := validateFlags(parallel, &idf)
			if err != nil {
				return err
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

			pre, err := applyPreflight(cmd.Context(), log, knownHosts, ids)
			if err != nil {
				return err
			}
			// Offer each server's granted keys first (operators first), so
			// many held keys cannot exhaust sshd's MaxAuthTries before the
			// key that matters is tried.
			preferKeys := func(s config.Server) []string { return audit.GrantedFingerprints(cfg, s.Name) }

			// Phase 1: read + plan (audit's pipeline over the targeted subset).
			reader := &sshread.Client{
				KnownHostsPath: pre.khPath,
				KnownHosts:     pre.kh,
				Creds:          pre.creds,
				DialTimeout:    dialTimeout,
				PreferKeys:     preferKeys,
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
			if err := interrupted(cmd.Context()); err != nil {
				return err // nothing written: phase 2 never started
			}
			plans, err := apply.Build(cfg, results, pre.held)
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

			ok, err := confirmGate(cmd, yes, toApply, len(plans))
			if err != nil {
				return err
			}
			if !ok {
				log.Error("aborted; no changes made")
				return finish() // pending changes → exit 1
			}

			log.Info(fmt.Sprintf("applying %d servers (parallelism %d)…", toApply, parallel))
			writePhase(cmd.Context(), log, pre, preferKeys, plans, parallel)
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
	idf.register(cmd)
	return cmd
}

// writePhase runs phase 2 over the drifted servers. The prompt can wait
// indefinitely: agent keys may expire (ssh-add -t) or be removed, or the
// agent vanish, meanwhile — so the held keys are re-listed first and the
// per-server guard re-check and the post-write login probe use what is
// held now. A degraded listing (agent gone, key files left) is used as is,
// never replaced; only a failed listing (no key files, agent gone) leaves
// it empty, which fails every write through the guard rather than
// guessing.
func writePhase(ctx context.Context, log *slog.Logger, pre preflight, preferKeys func(config.Server) []string, plans []apply.ServerPlan, parallel int) {
	fresh, err := pre.creds.Held(ctx)
	if err != nil {
		log.Error(fmt.Sprintf("%s: %v — no server will be written", relistPrefix(pre.creds), err))
		fresh = nil
	}
	writer := &sshwrite.FleetWriter{
		Dialer: &sshconn.Dialer{
			KnownHostsPath: pre.khPath,
			KnownHosts:     pre.kh,
			Creds:          pre.creds,
			DialTimeout:    dialTimeout,
			PreferKeys:     preferKeys,
			Log:            log,
		},
		Log: log,
	}
	apply.Execute(ctx, plans, writer, apply.ExecOptions{
		Parallel:         parallel,
		PerServerTimeout: perServerTimeout,
		Held:             fresh,
		Logger:           log,
	})
	if n := apply.Interrupted(plans); n > 0 {
		log.Error(fmt.Sprintf("interrupted: %d servers not started (nothing written there); started writes finished", n))
	}
}

// preflight is what apply's pre-dial checks hand to both phases.
type preflight struct {
	khPath string
	kh     *sshconn.KnownHosts  // parsed once, shared by the reader and the writer
	creds  *sshconn.Credentials // the run's one credential source: reader, writer, probe
	held   []sshconn.HeldKey    // the plan-time guard's ground truth
}

// applyPreflight runs apply's pre-dial checks in the order of operations:
// known_hosts (parsed exactly once per run; both phases share the
// snapshot), then the key files (may prompt), then the credentials check —
// apply needs plain held keys — and the held-key capture that is the
// self-lockout guard's ground truth.
func applyPreflight(ctx context.Context, log *slog.Logger, knownHosts string, ids identities) (preflight, error) {
	var pre preflight
	var err error
	if pre.khPath, err = expandHome(knownHosts); err != nil {
		return pre, err
	}
	if pre.kh, err = sshread.LoadKnownHosts(pre.khPath); err != nil {
		return pre, fmt.Errorf("known_hosts preflight: %w", err)
	}
	if pre.creds, err = ids.credentials(ctx, log); err != nil {
		return pre, err
	}
	if err := checkCredentials(ctx, pre.creds, true); err != nil {
		return pre, err
	}
	if pre.held, err = pre.creds.Held(ctx); err != nil {
		return pre, fmt.Errorf("agent preflight: %w", err)
	}
	return pre, nil
}

// relistPrefix words a failed post-confirmation re-list: the
// pre---identity wording for an agent-only run, a key-neutral one when
// --identity keys are in the union.
func relistPrefix(creds *sshconn.Credentials) string {
	if len(creds.Files) == 0 {
		return "re-listing agent keys after confirmation"
	}
	return "re-listing the keys you hold after confirmation"
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

// confirmGate runs confirm on the command's streams: the prompt goes to
// stderr and the answer comes from stdin, so `apply > plan.txt` captures
// exactly the report. Ctrl-C at the prompt is an interrupted run (exit 3,
// nothing written).
func confirmGate(cmd *cobra.Command, yes bool, n, total int) (bool, error) {
	in := cmd.InOrStdin()
	errW := cmd.ErrOrStderr()
	ok, err := confirm(cmd.Context(), in, errW, stdioIsTTY(in, errW), yes, n, total)
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(errW)
		return false, interrupted(cmd.Context())
	}
	return ok, err
}

// confirm gates phase 2. --yes short-circuits; otherwise a TTY prompts once
// on stderr, defaulting to no; non-TTY without --yes is a usage error —
// automation must opt in explicitly, never by accident of a pipe. Ctrl-C at
// the prompt cancels ctx and returns ctx's error at once: the stdin read
// runs in a goroutine, so the signal is not swallowed while it blocks (the
// abandoned read ends when the process exits).
func confirm(ctx context.Context, in io.Reader, errW io.Writer, tty, yes bool, n, total int) (bool, error) {
	if yes {
		return true, nil
	}
	if !tty {
		return false, errors.New("confirmation required: re-run with --yes (or --dry-run to preview) — stdin/stderr is not a terminal")
	}
	fmt.Fprintf(errW, "apply %d of %d servers? [y/N] ", n, total)
	answer := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(in)
		if !sc.Scan() {
			close(answer) // EOF (Ctrl-D) declines
			return
		}
		answer <- sc.Text()
	}()
	var text string
	select {
	case <-ctx.Done():
		return false, fmt.Errorf("confirmation: %w", ctx.Err())
	case text = <-answer:
	}
	switch strings.ToLower(strings.TrimSpace(text)) {
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
