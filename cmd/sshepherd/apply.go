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
		rf        runFlags
		serverSel []string
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
			"(re-run apply), and so is the whole run when the manifest itself changed\n" +
			"since it was read. A self-lockout guard refuses any write that would leave\n" +
			"no key you hold (identity files + agent) on a server; after each write a\n" +
			"fresh login offering only the surviving keys must succeed, or the\n" +
			"previous file is restored. --yes skips only the confirmation: an\n" +
			"encrypted --identity key may still prompt for its passphrase.\n" +
			"Ctrl-C stops new writes; started ones finish. --dry-run previews the\n" +
			"plan and never writes.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ids, err := validateFlags(rf.parallel, &rf.idf)
			if err != nil {
				return err
			}
			log := a.logger
			m, err := readManifest(rf.cfgPath)
			if err != nil {
				return fmt.Errorf("load manifest: %w", err)
			}
			cfg, err := config.Parse(m.Loaded)
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
			return runApply(cmd, a, stdout, &rf, ids, applyRun{
				cfg:     cfg,
				servers: targets,
				// Offer each server's granted keys first (operators first),
				// so many held keys cannot exhaust sshd's MaxAuthTries
				// before the key that matters is tried.
				preferKeys: func(s config.Server) []string { return audit.GrantedFingerprints(cfg, s.Name) },
				prompt: func(_ []apply.ServerPlan, toWrite int) (string, error) {
					return fmt.Sprintf("apply %d of %d servers?", toWrite, len(targets)), nil
				},
				// A concurrent revoke may have replaced the manifest while
				// this run planned against the old one: writing that plan
				// would reinstall the revoked key.
				beforeWrite: func(context.Context, []apply.ServerPlan, []sshconn.HeldKey) error {
					return m.Unchanged()
				},
				finish: func(plans []apply.ServerPlan, stage applyStage) error {
					if stage == stageDeclined {
						log.Error("aborted; no changes made")
					}
					apply.RenderSummary(stdout, plans, ropts)
					if skipped > 0 {
						fmt.Fprintf(stdout, "(%s skipped by --server)\n", apply.Plural(skipped, "server", "servers"))
					}
					if apply.ExitCode(plans) != 0 {
						return errNonCompliant
					}
					return nil
				},
			})
		},
	}
	rf.register(cmd)
	cmd.Flags().StringArrayVar(&serverSel, "server", nil, "restrict the run to this server (repeatable; canary rollout)")
	return cmd
}

// applyStage tells an applyRun's finish how far the run got.
type applyStage int

const (
	stagePlanned   applyStage = iota // plan shown, nothing confirmed: --dry-run, or nothing to confirm
	stageDeclined                    // the confirmation prompt was declined
	stageConfirmed                   // confirmed: beforeWrite passed and the writes (if any) ran
)

// applyRun parameterizes runApply: plain apply passes the loaded config
// and its whole selection; revoke/rotate pass the edited config, the
// affected servers and the edit's hooks.
type applyRun struct {
	cfg        *config.Config               // the config the plan renders (the edited one for revoke/rotate)
	former     *config.Config               // the as-loaded config before an edit; nil for plain apply
	formerNote string                       // label note for keys only former owns: "" (revoked) or "rotated out"
	servers    []config.Server              // the servers to plan, manifest order; never empty
	preferKeys func(config.Server) []string // fingerprints offered first on every dial (read and write)
	header     func(io.Writer)              // printed to stdout before anything connects; nil prints nothing
	// alwaysConfirm asks even when no server needs a write (the manifest
	// edit is itself a change).
	alwaysConfirm bool
	// prompt returns the confirmation question (confirm appends " [y/N] "),
	// or an error that ends the run before any prompt.
	prompt func(plans []apply.ServerPlan, toWrite int) (string, error)
	// beforeWrite runs once after confirmation and before any write: inside
	// writePhase after the post-prompt held-key re-list when a server will
	// be written (fresh is that listing), else straight after the prompt
	// (fresh nil). An error ends the run with nothing written.
	beforeWrite func(ctx context.Context, plans []apply.ServerPlan, fresh []sshconn.HeldKey) error
	// finish renders the tail of the report and maps the run to its exit.
	finish func(plans []apply.ServerPlan, stage applyStage) error
}

// runApply is apply's run body over run.servers: preflight (known_hosts,
// key files, credentials, held keys), phase-1 read and plan, the report,
// the confirmation gate, beforeWrite, the writes, finish.
func runApply(cmd *cobra.Command, a *app, stdout io.Writer, rf *runFlags, ids identities, run applyRun) error {
	ctx, log := cmd.Context(), a.logger
	if run.header != nil {
		run.header(stdout)
	}
	pre, err := applyPreflight(ctx, log, rf.knownHosts, ids)
	if err != nil {
		return err
	}
	plans, err := planFleet(ctx, log, pre, run, rf.parallel)
	if err != nil {
		return err
	}
	apply.Render(stdout, run.cfg, plans, apply.RenderOptions{Color: a.reportColor, Former: run.former, FormerNote: run.formerNote})

	toWrite := countChanges(plans)
	if rf.dryRun || (toWrite == 0 && !run.alwaysConfirm) {
		return run.finish(plans, stagePlanned) // a preview, or nothing to confirm
	}
	question, err := run.prompt(plans, toWrite)
	if err != nil {
		return err
	}
	ok, err := confirmGate(cmd, rf.yes, question)
	if err != nil {
		return err
	}
	if !ok {
		return run.finish(plans, stageDeclined)
	}
	if toWrite == 0 {
		if err := run.beforeWrite(ctx, plans, nil); err != nil {
			return err
		}
		return run.finish(plans, stageConfirmed)
	}
	log.Info(fmt.Sprintf("applying %d servers (parallelism %d)…", toWrite, rf.parallel))
	if err := writePhase(ctx, log, pre, run.preferKeys, plans, rf.parallel, run.beforeWrite); err != nil {
		return err
	}
	return run.finish(plans, stageConfirmed)
}

// planFleet is phase 1: audit's pipeline over run.servers, then the plan
// from run.cfg.
func planFleet(ctx context.Context, log *slog.Logger, pre preflight, run applyRun, parallel int) ([]apply.ServerPlan, error) {
	reader := &sshread.Client{
		KnownHostsPath: pre.khPath,
		KnownHosts:     pre.kh,
		Creds:          pre.creds,
		DialTimeout:    dialTimeout,
		PreferKeys:     run.preferKeys,
		Log:            log,
	}
	log.Info(fmt.Sprintf("planning %d servers (parallelism %d)…", len(run.servers), parallel))
	start := time.Now()
	results := audit.Run(ctx, run.cfg, reader, audit.Options{
		Parallel:         parallel,
		PerServerTimeout: perServerTimeout,
		Servers:          run.servers,
		Logger:           log,
	})
	logFleetReadDone(log, run.cfg, results, start)
	if err := interrupted(ctx); err != nil {
		return nil, err // nothing written: phase 2 never started
	}
	plans, err := apply.Build(run.cfg, results, pre.held)
	if err != nil {
		return nil, fmt.Errorf("plan: %w", err) // wrapcheck: wrap at package boundary
	}
	return plans, nil
}

// writePhase runs phase 2 over the drifted servers. The prompt can wait
// indefinitely: agent keys may expire (ssh-add -t) or be removed, or the
// agent vanish, meanwhile — so the held keys are re-listed first and the
// per-server guard re-check and the post-write login probe use what is
// held now. A degraded listing (agent gone, key files left) is used as is,
// never replaced; only a failed listing (no key files, agent gone) leaves
// it empty, which fails every write through the guard rather than
// guessing. beforeWrite (the manifest re-check or save) runs after the
// re-list and before any worker starts; its error writes nothing.
func writePhase(ctx context.Context, log *slog.Logger, pre preflight, preferKeys func(config.Server) []string,
	plans []apply.ServerPlan, parallel int,
	beforeWrite func(context.Context, []apply.ServerPlan, []sshconn.HeldKey) error,
) error {
	fresh, err := pre.creds.Held(ctx)
	if err != nil {
		log.Error(fmt.Sprintf("%s: %v — no server will be written", relistPrefix(pre.creds), err))
		fresh = nil
	}
	if beforeWrite != nil {
		if err := beforeWrite(ctx, plans, fresh); err != nil {
			return err
		}
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
	return nil
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

// promptStreams returns the confirmation prompt's input, output and TTY
// verdict: stdin, stderr, and whether both are terminals. A test seam —
// run() never wires a terminal.
var promptStreams = func(cmd *cobra.Command) (io.Reader, io.Writer, bool) {
	in, errW := cmd.InOrStdin(), cmd.ErrOrStderr()
	return in, errW, stdioIsTTY(in, errW)
}

// confirmGate runs confirm on the command's streams: the prompt goes to
// stderr and the answer comes from stdin, so `apply > plan.txt` captures
// exactly the report. Ctrl-C at the prompt is an interrupted run (exit 3,
// nothing written).
func confirmGate(cmd *cobra.Command, yes bool, question string) (bool, error) {
	in, errW, tty := promptStreams(cmd)
	ok, err := confirm(cmd.Context(), in, errW, tty, yes, question)
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
func confirm(ctx context.Context, in io.Reader, errW io.Writer, tty, yes bool, question string) (bool, error) {
	if yes {
		return true, nil
	}
	if !tty {
		return false, errors.New("confirmation required: re-run with --yes (or --dry-run to preview) — stdin/stderr is not a terminal")
	}
	fmt.Fprintf(errW, "%s [y/N] ", question)
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
