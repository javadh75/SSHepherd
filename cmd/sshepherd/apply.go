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
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshread"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
	"github.com/javadh75/SSHepherd/internal/workflow"
)

// The transport implementations of the domain seams, checked at compile time.
var (
	_ audit.KeyReader = (*sshread.Client)(nil)
	_ apply.Writer    = (*sshwrite.FleetWriter)(nil)
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
			"fresh login offering only the surviving keys must succeed: a refused\n" +
			"login restores the previous file, and a login that never got past\n" +
			"authentication (network, agent, host key) keeps the new file and reports\n" +
			"UNPROVEN. --yes skips only the confirmation: an\n" +
			"encrypted --identity key may still prompt for its passphrase.\n" +
			"Ctrl-C stops new writes; started ones finish. --dry-run previews the\n" +
			"plan and never writes.\n\n" + exitCodesWrite,
		Example: "  # Preview, then write after one confirmation\n" +
			"  sshepherd apply --dry-run\n" +
			"  sshepherd apply\n\n" +
			"  # Canary: one server first, then the rest\n" +
			"  sshepherd apply --server web-1\n" +
			"  sshepherd apply\n\n" +
			"  # CI with a deploy key instead of ssh-agent\n" +
			"  sshepherd apply --yes --identity ~/.ssh/ci --identity-passphrase-file /run/secrets/ci.pass",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ids, err := validateFlags(rf.parallel, &rf.idf)
			if err != nil {
				return err
			}
			if err := rf.checkModes(); err != nil {
				return err
			}
			log := a.logger
			m, err := readManifest(rf.cfgPath)
			if err != nil {
				return manifestError("--config", rf.cfgPath, err)
			}
			cfg, err := config.Parse(m.Loaded)
			if err != nil {
				return manifestError("--config", rf.cfgPath, err)
			}
			logManifest(log, cfg)
			targets, err := selectServers(cfg, serverSel)
			if err != nil {
				return err
			}
			skipped := len(cfg.Servers) - len(targets)
			ropts := apply.RenderOptions{Color: a.reportColor}
			if len(targets) == 0 {
				if rf.json {
					return apply.RenderJSON(stdout, cfg, nil, apply.JSONOptions{Command: "apply", DryRun: rf.dryRun, Skipped: skipped})
				}
				apply.Render(stdout, cfg, nil, ropts)
				return nil
			}
			pa := &plainApply{m: m, cfg: cfg, log: log, stdout: stdout, rf: &rf, skipped: skipped, targets: len(targets), ropts: ropts}
			return runWorkflow(cmd, a, stdout, &rf, ids, applySpec{
				cfg:     cfg,
				servers: targets,
				// Offer each server's granted keys first (operators first),
				// so many held keys cannot exhaust sshd's MaxAuthTries
				// before the key that matters is tried.
				preferKeys: func(s config.Server) []string { return audit.GrantedFingerprints(cfg, s.Name) },
				question:   pa.question,
				commit:     pa.commit,
				finish:     pa.finish,
			})
		},
	}
	rf.register(cmd)
	cmd.Flags().StringArrayVar(&serverSel, "server", nil, "restrict the run to this server (repeatable; canary rollout)")
	return cmd
}

// plainApply is plain apply's commit and finish seams, as methods so the
// command's own function stays small (gocyclo).
type plainApply struct {
	m       manifestTarget
	cfg     *config.Config
	log     *slog.Logger
	stdout  io.Writer
	rf      *runFlags
	skipped int
	targets int
	ropts   apply.RenderOptions
	bump    *apply.SerialBump // D4b: what this run bumped (or would), for the text and JSON reports
}

// question is plain apply's confirmation question. A bump that would push
// a render over the limit withholds the run here, before the prompt and the
// save (spec §7): a plan's class may not change after it is shown.
func (pa *plainApply) question(plans []apply.ServerPlan, toWrite int) (string, error) {
	if msgs := pa.oversizedBump(plans); len(msgs) > 0 {
		for _, m := range msgs {
			pa.log.Error(m)
		}
		pa.bump = &apply.SerialBump{From: pa.cfg.Serial(), Warning: strings.Join(msgs, "; ")}
		return "", fmt.Errorf("%w: a serial bump would exceed the render limit", workflow.ErrWithheld)
	}
	return fmt.Sprintf("apply %d of %s?", toWrite, apply.Plural(pa.targets, "server", "servers")), nil
}

// oversizedBump is ReserialOversize for a run that will bump and can save:
// a pipe or an anchored manifest gets no bump, so no growth and no check.
func (pa *plainApply) oversizedBump(plans []apply.ServerPlan) []string {
	from := pa.cfg.Serial()
	if !apply.NeedsSerialBump(plans, from) {
		return nil
	}
	if _, err := serialEditable(pa.m); err != nil {
		return nil // the commit reports a manifest it cannot edit
	}
	return apply.ReserialOversize(plans, from+1)
}

// commit runs after the prompt, before the first write. A concurrent
// revoke may have replaced the manifest while this run planned against the
// old one: writing that plan would reinstall the revoked key. Then D4b: a
// removal on a server whose header serial is not above the manifest's
// bumps serial: once, saved here, and every write carries it (Reserial).
func (pa *plainApply) commit(_ context.Context, plans []apply.ServerPlan, _ []fleet.HeldKey) (bool, error) {
	if err := pa.m.Unchanged(); err != nil {
		return false, err //nolint:wrapcheck // "changed since it was read" is the user-facing text
	}
	from := pa.cfg.Serial()
	if !apply.NeedsSerialBump(plans, from) {
		return false, nil
	}
	to, err := saveSerialBump(pa.m)
	if errors.Is(err, errNoSerialSave) {
		pa.log.Warn(noBumpWarning)
		pa.bump = &apply.SerialBump{From: from, Warning: noBumpWarning}
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := apply.Reserial(plans, to); err != nil {
		return false, err //nolint:wrapcheck // a bug: … message
	}
	pa.bump = &apply.SerialBump{From: from, To: &to, Saved: true}
	if !pa.rf.json {
		fmt.Fprintf(pa.stdout, "manifest serial: %d → %d (saved; this apply removes keys)\n", from, to)
	}
	return true, nil
}

// finish renders the run's outcome: the JSON document, or the summary and
// the dry-run's would-bump line.
func (pa *plainApply) finish(out workflow.Outcome, _ *fleetSession) error {
	if out.Stage == workflow.StageDeclined {
		pa.log.Error("aborted; no changes made")
	}
	if pa.rf.dryRun {
		pa.bump = dryRunBump(pa.m, pa.cfg, out.Plans)
	}
	if pa.rf.json {
		return finishDoc(func(plans []apply.ServerPlan, _ bool, _ *apply.SweepReport) error {
			return apply.RenderJSON(pa.stdout, pa.cfg, plans, apply.JSONOptions{Command: "apply", DryRun: pa.rf.dryRun, Skipped: pa.skipped, SerialBump: pa.bump})
		}, out, nil)
	}
	apply.RenderSummary(pa.stdout, pa.cfg, out.Plans, pa.ropts)
	if pa.skipped > 0 {
		fmt.Fprintf(pa.stdout, "(%s skipped by --server)\n", apply.Plural(pa.skipped, "server", "servers"))
	}
	printDryRunBump(pa.stdout, pa.log, pa.rf.dryRun, pa.bump)
	return exitFor(out.ExitCode())
}

// noBumpWarning: apply removes keys but cannot save the bumped serial.
const noBumpWarning = "removing keys without a serial bump: an older copy could re-grant them"

// errNoSerialSave: the manifest cannot be saved in place — a pipe, or a
// shape the comment-preserving editor refuses (anchors); apply then warns
// and writes without the bump.
var errNoSerialSave = errors.New("manifest cannot be saved in place")

// serialEditable loads the manifest for the D4b edit — the one
// classification saveSerialBump and dryRunBump share, so a dry run never
// promises a bump the real run would only warn about: a pipe, or a shape
// the comment-preserving editor refuses (anchors, aliases), cannot be
// saved in place (errNoSerialSave: warn and write without the bump).
func serialEditable(m manifestTarget) (*manifest.File, error) {
	if m.Stream {
		return nil, errNoSerialSave
	}
	mf, err := manifest.Load(m.Loaded)
	var ue *manifest.UnsupportedError
	if errors.As(err, &ue) {
		return nil, errNoSerialSave
	}
	if err != nil {
		return nil, fmt.Errorf("serial bump: %w", err)
	}
	return mf, nil
}

// saveSerialBump raises the manifest's serial: by one through the locked
// store (its compare-and-swap included) and returns the new value. A failed
// save is a tool error: nothing is written (spec §6).
func saveSerialBump(m manifestTarget) (uint64, error) {
	mf, err := serialEditable(m)
	if err != nil {
		return 0, err
	}
	to, err := mf.BumpSerial()
	if err != nil {
		return 0, fmt.Errorf("serial bump: %w", err)
	}
	out, err := mf.Encode()
	if err != nil {
		return 0, fmt.Errorf("serial bump: %w", err)
	}
	if err := m.Save(out); err != nil {
		return 0, err //nolint:wrapcheck // "save manifest …" / "changed since it was read" are the user-facing text
	}
	return to, nil
}

// dryRunBump is what a confirmed run of these plans would bump (nil:
// none), classified exactly as saveSerialBump would (serialEditable).
func dryRunBump(m manifestTarget, cfg *config.Config, plans []apply.ServerPlan) *apply.SerialBump {
	from := cfg.Serial()
	if !apply.NeedsSerialBump(plans, from) {
		return nil
	}
	if _, err := serialEditable(m); err != nil {
		return &apply.SerialBump{From: from, Warning: noBumpWarning}
	}
	if msgs := apply.ReserialOversize(plans, from+1); len(msgs) > 0 {
		return &apply.SerialBump{From: from, Warning: strings.Join(msgs, "; ")}
	}
	to := from + 1
	return &apply.SerialBump{From: from, To: &to}
}

// printDryRunBump prints the dry-run's would-bump line (or the warning a
// piped --config gets).
func printDryRunBump(stdout io.Writer, log *slog.Logger, dryRun bool, b *apply.SerialBump) {
	switch {
	case !dryRun || b == nil:
	case b.To == nil:
		log.Warn(b.Warning)
	default:
		fmt.Fprintf(stdout, "would bump serial: %d → %d (this apply removes keys)\n", b.From, *b.To)
	}
}

// applySpec is what apply, revoke and rotate vary: plain apply passes the
// loaded config and its whole selection; revoke/rotate pass the edited
// config, the affected servers and the edit's seams. runWorkflow maps it to
// a workflow.Request and the Outcome to finish.
type applySpec struct {
	cfg        *config.Config               // the config the plan renders (the edited one for revoke/rotate)
	former     *config.Config               // the as-loaded config before an edit; nil for plain apply
	formerNote string                       // label note for keys only former owns: "" (revoked) or "rotated out"
	servers    []config.Server              // the servers to plan, manifest order; never empty
	preferKeys func(config.Server) []string // fingerprints offered first on every dial (read and write)
	header     func(io.Writer)              // printed to stdout before anything connects (not under --json); nil prints nothing
	// alwaysConfirm asks even when no server needs a write (the manifest
	// edit is itself a change).
	alwaysConfirm bool
	// bumped: the run saves a higher serial: and servers is its bump scope
	// (revoke/rotate's affected set): equal-body servers get header-only
	// writes (workflow.Request.Bumped).
	bumped bool
	// question returns the confirmation question (confirm appends
	// " [y/N] "), workflow.ErrWithheld to withhold the run before any
	// prompt, or a tool error.
	question func(plans []apply.ServerPlan, toWrite int) (string, error)
	// commit runs once after confirmation and before any write (see
	// workflow.ManifestCommitter); workflow.ErrWithheld withholds the run,
	// any other error is a tool error. Either way nothing is written.
	commit workflow.CommitFunc
	// finish renders the tail of the report (or, under --json, the whole
	// document) and maps the outcome to its exit; StageWithheld always maps
	// to exit 1. sess is the run's fleet session, for revoke/rotate's sweep.
	finish func(out workflow.Outcome, sess *fleetSession) error
}

// newWriter builds a run's write transport; a test seam.
var newWriter = func(d *sshconn.Dialer, log *slog.Logger) apply.Writer {
	return &sshwrite.FleetWriter{Dialer: d, Log: log}
}

// runWorkflow is apply's run body over s.servers: the header, preflight
// (known_hosts, key files, credentials, held keys), then the write
// workflow over the transport seams built here, then finish. Under --json
// no text reaches stdout: finish renders the one document.
func runWorkflow(cmd *cobra.Command, a *app, stdout io.Writer, rf *runFlags, ids identities, s applySpec) error {
	ctx, log := cmd.Context(), a.logger
	if s.header != nil && !rf.json {
		s.header(stdout) // before the preflight, which may prompt for a passphrase
	}
	pre, err := applyPreflight(ctx, log, &rf.connFlags, ids)
	if err != nil {
		return err
	}
	out, err := workflow.Apply(ctx, workflow.Request{
		Cfg:              s.cfg,
		Servers:          s.servers,
		Held:             pre.held,
		Reader:           pre.reader(s.preferKeys),
		Writer:           newWriter(pre.dialer(s.preferKeys), log),
		Relister:         pre.creds,
		RelistLabel:      relistPrefix(pre.creds),
		Parallel:         pre.parallel,
		PerServerTimeout: perServerTimeout,
		DryRun:           rf.dryRun,
		AlwaysConfirm:    s.alwaysConfirm,
		Bumped:           s.bumped,
		Question:         s.question,
		Confirmer: workflow.ConfirmFunc(func(ctx context.Context, q string) (bool, error) {
			return confirmGate(ctx, cmd, rf.yes, q)
		}),
		Committer: s.commit,
		Reporter: textReporter{json: rf.json, stdout: stdout, log: log, cfg: s.cfg,
			ropts: apply.RenderOptions{Color: a.reportColor, Former: s.former, FormerNote: s.formerNote}},
		Log: log,
	})
	if errors.Is(err, workflow.ErrInterrupted) {
		if ierr := interrupted(ctx); ierr != nil {
			return ierr // nothing rendered, saved or written: phase 2 never started
		}
	}
	if err != nil {
		return err //nolint:wrapcheck // our own seams' errors (confirm gate, manifest commit), returned verbatim: their exit-3 text is user-facing
	}
	return s.finish(out, pre.fleetSession)
}

// textReporter is the workflow's report seam: the phase-1 done line in
// every mode, the plan report outside --json. runWorkflow prints the
// header itself, before the preflight, so Header is a no-op here.
type textReporter struct {
	json   bool
	stdout io.Writer
	log    *slog.Logger
	cfg    *config.Config
	ropts  apply.RenderOptions
}

func (textReporter) Header() {}

func (r textReporter) ReadDone(results []audit.ServerResult, start time.Time) {
	logFleetReadDone(r.log, r.cfg, results, start)
}

func (r textReporter) Planned(plans []apply.ServerPlan) {
	if !r.json {
		apply.Render(r.stdout, r.cfg, plans, r.ropts)
	}
}

// preflight is what apply's pre-dial checks hand to both phases: the
// run's fleet session (known_hosts parsed once and the one credential
// source, shared by the reader, the writer and the probe) and the held keys.
type preflight struct {
	*fleetSession
	held []fleet.HeldKey // the plan-time guard's ground truth
}

// applyPreflight runs apply's pre-dial checks in the order of operations:
// openFleet (known_hosts, the key files, the credentials check — apply
// needs plain held keys), then the held-key capture that is the
// self-lockout guard's ground truth.
func applyPreflight(ctx context.Context, log *slog.Logger, f *connFlags, ids identities) (preflight, error) {
	s, err := openFleet(ctx, log, f, ids, true)
	if err != nil {
		return preflight{}, err
	}
	held, err := s.creds.Held(ctx)
	if err != nil {
		return preflight{}, fmt.Errorf("agent preflight: %w", err)
	}
	return preflight{fleetSession: s, held: held}, nil
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
func confirmGate(ctx context.Context, cmd *cobra.Command, yes bool, question string) (bool, error) {
	in, errW, tty := promptStreams(cmd)
	ok, err := confirm(ctx, in, errW, tty, yes, question)
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(errW)
		return false, interrupted(ctx)
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
