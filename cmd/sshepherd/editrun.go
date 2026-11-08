package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// editFlags are revoke's and rotate's flags: apply's shared set plus the
// operator acknowledgement and --no-apply.
type editFlags struct {
	run      runFlags
	operator bool
	noApply  bool
}

func (f *editFlags) register(cmd *cobra.Command) {
	f.run.register(cmd)
	cmd.Flags().BoolVar(&f.operator, "operator", false,
		"confirm that a target is, or belongs to, an operator user (fleet-wide, protected)")
	cmd.Flags().BoolVar(&f.noApply, "no-apply", false,
		"edit and save the manifest after confirmation; contact no server")
}

// connectionFlags are the flags --no-apply would leave silently unused.
var connectionFlags = []string{"identity", "identity-passphrase-file", "identity-passphrase", "known-hosts", "parallel"}

// validate is step 1's flag half (exit 3 before the manifest is read):
// --dry-run and --yes exclude each other, and --json needs one of them
// (--no-apply still confirms); --no-apply
// refuses the connection flags; otherwise --parallel and the identity flags
// are checked exactly as apply checks them.
func (f *editFlags) validate(cmd *cobra.Command) (identities, error) {
	if err := f.run.checkModes(); err != nil {
		return identities{}, err
	}
	if f.noApply {
		for _, name := range connectionFlags {
			if cmd.Flags().Changed(name) {
				return identities{}, fmt.Errorf("--no-apply contacts no server, so --%s would be unused; drop one of them", name)
			}
		}
		return identities{}, nil
	}
	return validateFlags(f.run.parallel, &f.run.idf)
}

// loadForEdit is step 2: read the manifest once (exact bytes + resolved
// path) and load its node tree. A valid manifest the comment-preserving
// edits cannot handle is its own refusal.
func loadForEdit(log *slog.Logger, path string) (manifestTarget, *manifest.File, error) {
	m, err := readManifest(path)
	if err != nil {
		return manifestTarget{}, nil, manifestError("--config", path, err)
	}
	if m.Stream {
		return manifestTarget{}, nil, fmt.Errorf("cannot edit %s: not a regular file — revoke and rotate save the manifest in place; pass the manifest file's path", path)
	}
	mf, err := manifest.Load(m.Loaded)
	var ue *manifest.UnsupportedError
	if errors.As(err, &ue) {
		apply := (&connFlags{cfgPath: path, knownHosts: defaultKnownHosts}).followUp().command("apply", nil)
		return manifestTarget{}, nil, fmt.Errorf("cannot edit %s: %s — edit the manifest by hand and run '%s'", path, ue.Reason, apply)
	}
	if err != nil {
		return manifestTarget{}, nil, manifestError("--config", path, err)
	}
	logManifest(log, mf.Config())
	return m, mf, nil
}

// operatorGate enforces the operator protection contract over every
// resolved target user before any edit: an operator target needs
// --operator, and --operator needs an operator target (a habitually
// passed flag would empty the gate). Returns the operator targets.
func operatorGate(cfg *config.Config, users []string, acknowledged bool) ([]string, error) {
	var ops []string
	for _, name := range users {
		for _, u := range cfg.Users {
			if u.Name == name && u.Operator && !slices.Contains(ops, name) {
				ops = append(ops, name)
			}
		}
	}
	switch {
	case len(ops) == 1 && !acknowledged:
		return nil, fmt.Errorf("%s is an operator (fleet-wide, protected); pass --operator to confirm", ops[0])
	case len(ops) > 1 && !acknowledged:
		return nil, fmt.Errorf("%s are operators (fleet-wide, protected); pass --operator to confirm", strings.Join(ops, ", "))
	case len(ops) == 0 && acknowledged:
		return nil, errors.New("--operator given but no target is an operator; drop the flag")
	}
	return ops, nil
}

// editPlan is a resolved, encoded manifest edit (steps 1–3), ready for
// runEdit (steps 4–8).
type editPlan struct {
	target     manifestTarget
	former     *config.Config // the as-loaded config
	encoded    []byte         // the one Encode: the plan, Affected and the save all use these bytes
	edited     *config.Config // config.Parse(encoded)
	summary    apply.EditSummary
	formerNote string         // "" (revoked) or "rotated out"
	removesKey bool           // print the scope line after the writes
	stillHas   string         // "alice still has" — for the nothing-can-land refusal
	saveNote   string         // the save reminder's tail; "" = defaultSaveNote
	overlap    *overlapFinish // rotate --keep-old: the finish hint to print; nil otherwise
}

// overlapFinish is rotate --keep-old's pending finish: the revoke --key
// that ends the overlap once every client uses the new key.
type overlapFinish struct {
	user     string // the rotated user
	oldFP    string // the old key, which the finish revokes
	operator bool   // the user is an operator: the finish needs --operator
}

// overlapHint is rotate --keep-old's finish hint for one text-mode path
// (never under --json or --dry-run, whose callers return first): affected
// is the affected-server count, noApply is --no-apply, and notConverged
// counts a confirmed run's affected servers that do not hold the new key
// yet. CMD carries the run's flags (h) and quotes like applyHint; an
// operator's hint gets a second line.
func overlapHint(o overlapFinish, h followUp, affected int, noApply bool, notConverged int) string {
	var opTail []string
	if o.operator {
		opTail = append(opTail, "--operator")
	}
	cmd := h.command("revoke", []string{"--key", hintArg(o.oldFP)}, opTail...)
	var lead string
	switch {
	case affected == 0:
		lead = "new key recorded — " + o.user + " has no grants yet, so no server was contacted; finish the overlap with: "
	case noApply:
		lead = "overlap recorded, not pushed — run the apply hint above, then, once every client uses the new key, finish with: "
	case notConverged == 0:
		lead = "overlap started — every affected server accepts both keys; once every client uses the new key, finish with: "
	default:
		lead = fmt.Sprintf("overlap incomplete — %s %s not have the new key yet; push it first (see the apply hint above), then finish with: ",
			apply.Plural(notConverged, "server", "servers"), pluralWord(notConverged, "does", "do"))
	}
	out := lead + cmd + "\n"
	if o.operator {
		out += "if the old key is how this machine logs in, run the finish with --identity pointing at the new key's private key, or the lockout guard will refuse it\n"
	}
	return out
}

// defaultSaveNote is the save reminder's tail for edits that remove a key
// (revoke USER, revoke --key, plain rotate).
const defaultSaveNote = "an apply from a copy without this edit re-grants the removed key"

// encodeEdit is step 3's one Encode; its built-in config.Parse self-check
// is the only validation (a failure is an internal error, nothing saved).
func encodeEdit(mf *manifest.File) ([]byte, *config.Config, error) {
	out, err := mf.Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("edit manifest: %w", err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		return nil, nil, fmt.Errorf("edit manifest: %w", err)
	}
	return out, cfg, nil
}

// runEdit is steps 4–8: the affected set and header, then either the
// save-only path (zero affected, or --no-apply) or apply's pipeline over
// the affected servers with the save in beforeWrite.
func runEdit(cmd *cobra.Command, a *app, stdout io.Writer, f *editFlags, ids identities, ep editPlan) error {
	log := a.logger
	for _, w := range ep.edited.Warnings {
		if !slices.Contains(ep.former.Warnings, w) {
			log.Warn(w)
		}
	}
	aff := apply.Affected(ep.former, ep.edited)
	ep.summary.Affected = len(aff.Servers)
	ep.summary.Emptied = emptiedServers(ep.former, aff.Emptied)
	// Every hint repeats the run's own flags (a --no-apply run sets no
	// connection flags, so its hints carry --config only).
	h := f.run.followUp()
	ep.summary.FollowUp = h.suffix()
	ropts := apply.RenderOptions{Color: a.reportColor, Former: ep.former, FormerNote: ep.formerNote}
	header := func(w io.Writer) { apply.RenderEditHeader(w, ep.summary, ropts) }
	// doc renders the --json document; nil in text mode. Every exit-0/1
	// path calls it exactly once, and nothing else reaches stdout.
	var doc editDoc
	if f.run.json {
		doc = func(plans []apply.ServerPlan, saved bool) error {
			return apply.RenderJSON(stdout, ep.edited, plans, apply.JSONOptions{
				Command: cmd.Name(), DryRun: f.run.dryRun, Former: ep.former, Edit: &ep.summary, Saved: saved,
			})
		}
	}
	if f.noApply || len(aff.Servers) == 0 {
		if doc == nil {
			header(stdout)
		}
		return saveOnly(cmd, log, stdout, f, ep, aff, doc, h)
	}
	// saved is set by beforeWrite after a successful save and read by
	// finish, which runs after it: false under --dry-run and on the
	// withheld paths.
	saved := false
	return runApply(cmd, a, stdout, &f.run, ids, applyRun{
		cfg:        ep.edited,
		former:     ep.former,
		formerNote: ep.formerNote,
		servers:    serversNamed(ep.edited, aff.Servers),
		// Sessions authenticate with what is installed now: the old
		// config's grants first, then the new one's.
		preferKeys: func(s config.Server) []string {
			return unionFPs(audit.GrantedFingerprints(ep.former, s.Name), audit.GrantedFingerprints(ep.edited, s.Name))
		},
		header:        header,
		alwaysConfirm: true,
		prompt: func(plans []apply.ServerPlan, toWrite int) (string, error) {
			if nothingCanLand(plans) {
				log.Error(fmt.Sprintf("nothing saved — %s access on %s; fix the refusals and re-run, or record the change without touching servers with --no-apply",
					ep.stillHas, apply.Plural(len(plans), "server", "servers")))
				return "", errNonCompliant
			}
			return apply.EditPrompt(ep.summary.Operators, toWrite, len(plans), false), nil
		},
		beforeWrite: func(ctx context.Context, plans []apply.ServerPlan, fresh []sshconn.HeldKey) error {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("interrupted: %w — manifest not saved, nothing written", err)
			}
			if countChanges(plans) > 0 && !anySurvivor(plans, fresh) && !anyConverged(plans) {
				log.Error("nothing saved — none of the keys you hold would survive on any server (did a key expire after the plan?)")
				return errNonCompliant
			}
			if err := saveEdit(stdout, ep, doc != nil); err != nil {
				return err
			}
			saved = true
			return nil
		},
		finish: func(plans []apply.ServerPlan, stage applyStage) error {
			return finishEdit(stdout, log, ep, aff, h, plans, stage, ropts, doc, saved)
		},
	})
}

// editDoc renders the --json document from the plans (nil on revoke's and
// rotate's edit-only path) and whether the manifest was saved (always
// false for plain apply, which has no edit section).
type editDoc func(plans []apply.ServerPlan, saved bool) error

// saveOnly confirms and saves without contacting any server: zero
// affected servers, or --no-apply. --dry-run stops before the prompt.
// Under --json (doc non-nil) the document replaces every text line.
func saveOnly(cmd *cobra.Command, log *slog.Logger, stdout io.Writer, f *editFlags, ep editPlan, aff apply.AffectedSet, doc editDoc, h followUp) error {
	if f.run.dryRun {
		log.Info("dry run — manifest not changed")
		if doc != nil {
			return doc(nil, false)
		}
		return nil
	}
	ok, err := confirmGate(cmd, f.run.yes, apply.EditPrompt(ep.summary.Operators, 0, len(aff.Servers), f.noApply))
	if err != nil {
		return err
	}
	if !ok {
		log.Error("aborted; manifest not changed, nothing written")
		return errNonCompliant
	}
	if err := saveEdit(stdout, ep, doc != nil); err != nil {
		return err
	}
	if doc != nil {
		return doc(nil, true)
	}
	noApplyNote(stdout, f, ep, aff, h)
	if ep.overlap != nil {
		fmt.Fprint(stdout, overlapHint(*ep.overlap, h, len(aff.Servers), f.noApply, 0))
	}
	return nil
}

// noApplyNote is saveOnly's text tail after the save: under --no-apply what
// is left to push — only the servers apply would not refuse, as finishEdit
// does, since an emptied server is never written — else the scope line of a
// key removal that affected no server.
func noApplyNote(stdout io.Writer, f *editFlags, ep editPlan, aff apply.AffectedSet, h followUp) {
	pushable := slices.DeleteFunc(slices.Clone(aff.Servers), func(s string) bool { return slices.Contains(aff.Emptied, s) })
	switch {
	case f.noApply && len(aff.Servers) == 0:
		fmt.Fprintln(stdout, "no servers contacted — no server's desired keys changed")
	case f.noApply && len(pushable) == 0:
		fmt.Fprintln(stdout, "no servers contacted — nothing to push: every affected server would be left with no granted keys (see the warnings above)")
	case f.noApply:
		fmt.Fprintf(stdout, "no servers contacted — %s still %s the old keys; run '%s' to push\n",
			apply.Plural(len(pushable), "affected server", "affected servers"), pluralWord(len(pushable), "carries", "carry"), applyHint(h, pushable))
	case ep.removesKey:
		printScope(stdout, h, 0, len(ep.edited.Servers))
	}
}

// saveEdit is step 7's save, then the reminder that the manifest is the
// source of truth only once it is committed (skipped when quiet: --json,
// whose edit.saved carries the fact).
func saveEdit(stdout io.Writer, ep editPlan, quiet bool) error {
	if err := ep.target.Save(ep.encoded); err != nil {
		return err
	}
	if quiet {
		return nil
	}
	note := ep.saveNote
	if note == "" {
		note = defaultSaveNote
	}
	fmt.Fprintf(stdout, "manifest %s updated — commit and push it: %s\n", ep.target.Path, note)
	return nil
}

// finishDoc is finish under --json, shared by apply, revoke and rotate:
// render the one document, then map the run to its exit — stageWithheld
// (nothing saved or written) and any server not converged are exit 1. A
// declined prompt cannot occur: --json needs --dry-run or --yes.
func finishDoc(doc editDoc, plans []apply.ServerPlan, stage applyStage, saved bool) error {
	if err := doc(plans, saved); err != nil {
		return err
	}
	if stage == stageWithheld || apply.ExitCode(plans) != 0 {
		return errNonCompliant
	}
	return nil
}

// finishEdit renders step 8's tail (or, under --json, the whole document)
// and maps the exit code. stageWithheld (nothing can land, or no held key
// survives) is exit 1 with nothing saved; in text mode the hook already
// logged why and the plan is shown, so nothing more is printed.
func finishEdit(stdout io.Writer, log *slog.Logger, ep editPlan, aff apply.AffectedSet, h followUp,
	plans []apply.ServerPlan, stage applyStage, ropts apply.RenderOptions, doc editDoc, saved bool,
) error {
	if doc != nil {
		return finishDoc(doc, plans, stage, saved)
	}
	switch stage {
	case stageDeclined:
		log.Error("aborted; manifest not changed, nothing written")
		return errNonCompliant
	case stageWithheld:
		return errNonCompliant
	}
	apply.RenderSummary(stdout, plans, ropts)
	if stage == stageConfirmed {
		var pending []string
		for _, p := range plans {
			converged := p.Class == apply.ClassConverged || (p.Class == apply.ClassChange && p.Outcome == apply.OutcomeApplied)
			if !converged && !slices.Contains(aff.Emptied, p.Server.Name) {
				pending = append(pending, p.Server.Name)
			}
		}
		if len(pending) > 0 {
			fmt.Fprintf(stdout, "manifest updated; %s not converged — finish with: %s\n",
				apply.Plural(len(pending), "server", "servers"), applyHint(h, pending))
		}
		if ep.removesKey {
			printScope(stdout, h, len(plans), len(ep.edited.Servers))
		}
		if ep.overlap != nil {
			fmt.Fprint(stdout, overlapHint(*ep.overlap, h, len(aff.Servers), false, len(pending)))
		}
	}
	if apply.ExitCode(plans) != 0 {
		return errNonCompliant
	}
	return nil
}

// printScope is the scope line after a key removal: only affected servers
// were contacted, with the audit and apply commands (carrying the run's
// flags) that confirm and sweep the rest of the fleet.
func printScope(w io.Writer, h followUp, contacted, fleet int) {
	fmt.Fprintf(w, "scope: only servers whose grants changed were contacted (%d of %d); the removed key may still be installed elsewhere as drift — run '%s' to confirm, '%s' to sweep\n",
		contacted, fleet, h.command("audit", nil), h.command("apply", nil))
}

// shellSafe matches arguments that need no quoting in a hint.
var shellSafe = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

func hintArg(s string) string {
	if shellSafe.MatchString(s) {
		return s
	}
	return sshconn.ShQuote(s)
}

// applyHint is the apply command that finishes the job: the run's flags
// (h), one --server per server.
func applyHint(h followUp, servers []string) string {
	tail := make([]string, 0, len(servers))
	for _, s := range servers {
		tail = append(tail, "--server "+hintArg(s))
	}
	return h.command("apply", nil, tail...)
}

// nothingCanLand: no affected server is change-planned or converged, and
// at least one is refused (unreachable servers can converge later).
func nothingCanLand(plans []apply.ServerPlan) bool {
	refused := false
	for _, p := range plans {
		switch p.Class {
		case apply.ClassChange, apply.ClassConverged:
			return false
		case apply.ClassRefused:
			refused = true
		}
	}
	return refused
}

// anySurvivor: some change-planned server keeps a key held under the
// post-prompt listing.
func anySurvivor(plans []apply.ServerPlan, fresh []sshconn.HeldKey) bool {
	held := make(map[string]bool, len(fresh))
	for _, k := range fresh {
		held[k.Fingerprint] = true
	}
	for _, p := range plans {
		if p.Class == apply.ClassChange && len(apply.Survivors(p.Desired, held)) > 0 {
			return true
		}
	}
	return false
}

func anyConverged(plans []apply.ServerPlan) bool {
	return slices.ContainsFunc(plans, func(p apply.ServerPlan) bool { return p.Class == apply.ClassConverged })
}

// emptiedServers details each emptied server for the header: the former
// owners of the keys that stay installed there.
func emptiedServers(former *config.Config, names []string) []apply.EmptiedServer {
	out := make([]apply.EmptiedServer, 0, len(names))
	for _, name := range names {
		keys := former.DesiredFor(name)
		e := apply.EmptiedServer{Server: name, Keys: len(keys)}
		for _, k := range keys {
			if u, ok := former.OwnerOf(k.Fingerprint); ok && !slices.Contains(e.Users, u.Name) {
				e.Users = append(e.Users, u.Name)
			}
		}
		out = append(out, e)
	}
	return out
}

// serversNamed returns cfg's servers named in names, manifest order.
func serversNamed(cfg *config.Config, names []string) []config.Server {
	var out []config.Server
	for _, s := range cfg.Servers {
		if slices.Contains(names, s.Name) {
			out = append(out, s)
		}
	}
	return out
}

// unionFPs concatenates fingerprint lists, first occurrence wins.
func unionFPs(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		for _, fp := range l {
			if !slices.Contains(out, fp) {
				out = append(out, fp)
			}
		}
	}
	return out
}

// keyName names a key argument in messages: the argument as given, or its
// fingerprint when the argument was a whole key line.
func keyName(k keyArg) string {
	if k.Key != nil && looksLikeKeyLine(k.Arg) {
		return k.Fingerprint
	}
	return k.Arg
}
