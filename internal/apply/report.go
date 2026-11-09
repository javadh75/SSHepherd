package apply

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
)

// RenderOptions tunes report presentation.
type RenderOptions struct {
	Color bool // ANSI-color glyphs and key words; off = byte-identical to plain
	// Former is the as-loaded config before a revoke/rotate edit; nil for
	// plain apply. A key the rendered config no longer owns is labeled with
	// its former owner ("alice (revoked)") instead of "(unknown)".
	Former *config.Config
	// FormerNote is the parenthesized note on such a label: "revoked" when
	// empty, "rotated out" for rotate.
	FormerNote string
}

// Plural renders a count with its noun: "1 key", "2 keys", "0 keys".
func Plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

// SGR codes, four characters each — the same tabwriter-safe discipline as
// audit's report (columns stay aligned whether or not color is on).
const (
	codeGreen   = "0;32"
	codeRed     = "0;31"
	codeBoldRed = "1;31"
	codeYellow  = "0;33"
)

// palette paints report fragments when color is on.
type palette struct{ on bool }

func (p palette) paint(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// collapse folds whitespace runs to single spaces so hostile error text
// cannot forge report rows or a Summary line (terminal escapes are already
// stripped upstream).
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// oneLine is collapse for an error's text.
func oneLine(err error) string { return collapse(err.Error()) }

// label mirrors audit's row label: the owning user (with their comment:
// when set); for a key only opts.Former owns, its former owner and the
// edit's note ("alice (revoked)", "deploy (rotated out)"); else
// audit.UnknownLabel — "(unknown)" plus the key's on-server comment — for a
// key the manifest does not know.
func label(cfg *config.Config, opts RenderOptions, k authkeys.Key) string {
	u, ok := cfg.OwnerOf(k.Fingerprint)
	if !ok {
		if opts.Former != nil {
			if fu, fok := opts.Former.OwnerOf(k.Fingerprint); fok {
				note := opts.FormerNote
				if note == "" {
					note = "revoked"
				}
				return fmt.Sprintf("%s (%s)", fu.Name, note)
			}
		}
		return audit.UnknownLabel(k)
	}
	if u.Comment != "" {
		return fmt.Sprintf("%s (%s)", u.Name, u.Comment)
	}
	return u.Name
}

// formerOwns reports whether only the pre-edit config (opts.Former) owns k:
// such a key is labeled by its former owner, not as an unknown key.
func formerOwns(opts RenderOptions, k authkeys.Key) bool {
	if opts.Former == nil {
		return false
	}
	_, ok := opts.Former.OwnerOf(k.Fingerprint)
	return ok
}

// removeDetail is a remove row's status cell. A key neither config owns
// also shows its on-server options; the cell is the row's last, which
// tabwriter never pads, so alignment holds.
func removeDetail(cfg *config.Config, opts RenderOptions, k authkeys.Key) string {
	detail := "remove (unauthorized)"
	if _, ok := cfg.OwnerOf(k.Fingerprint); !ok && !formerOwns(opts, k) {
		detail += audit.UnknownOptions(k)
	}
	return detail
}

// Render writes the plan report — the operator's review surface before the
// confirmation gate. Outcome lines and the final Summary are
// RenderSummary's: they exist only once phase 2 has run or been skipped.
func Render(w io.Writer, cfg *config.Config, plans []ServerPlan, opts RenderOptions) {
	if len(plans) == 0 {
		fmt.Fprintln(w, "Summary: 0 servers targeted — nothing to apply")
		return
	}
	pal := palette{on: opts.Color}
	var hints audit.Hints
	for _, p := range plans {
		head := fmt.Sprintf("%s (%s@%s:%d)", p.Server.Name, p.Server.User, p.Server.Host, p.Server.Port)
		switch p.Class {
		case ClassUnreachable:
			tag, alert := audit.ErrorTag(p.Err)
			code := codeRed
			if alert {
				code = codeBoldRed
			}
			fmt.Fprintf(w, "%s  %s %s\n", head, pal.paint(code, tag), oneLine(p.Err))
			hints.Write(w, p.Err)
			fmt.Fprintln(w)
		case ClassConverged:
			fmt.Fprintf(w, "%s  converged (no changes)\n", head)
			if p.SerialNote != "" {
				fmt.Fprintf(w, "  note: %s\n", p.SerialNote)
			}
			renderKeys2Warning(w, p, pal)
			fmt.Fprintln(w)
		case ClassRefused:
			fmt.Fprintf(w, "%s  %s %s\n", head, pal.paint(codeBoldRed, "REFUSED:"), p.Refusal)
			renderKeys2Warning(w, p, pal)
			fmt.Fprintln(w)
		default:
			fmt.Fprintln(w, head)
			renderChange(w, cfg, p, pal, opts)
			fmt.Fprintln(w)
		}
	}
}

func renderChange(w io.Writer, cfg *config.Config, p ServerPlan, pal palette, opts RenderOptions) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range p.Add {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tadd (authorized, missing)\n",
			pal.paint(codeGreen, "+"), label(cfg, opts, k), k.Fingerprint, k.Type)
	}
	for _, k := range p.Remove {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			pal.paint(codeRed, "-"), label(cfg, opts, k), k.Fingerprint, k.Type, removeDetail(cfg, opts, k))
	}
	for _, rw := range p.Rewrites {
		// The detail is the row's last cell, which tabwriter never pads, so
		// painting it keeps the columns aligned.
		detail := rewriteDetail(rw)
		if len(rw.Loosens) > 0 || len(rw.Widens) > 0 {
			detail = pal.paint(codeBoldRed, detail)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			pal.paint(codeYellow, "~"), label(cfg, opts, rw.Key), rw.Key.Fingerprint, rw.Key.Type, detail)
	}
	if p.Normalize.Any() {
		fmt.Fprintf(tw, "  %s\t(formatting)\t\t\tnormalize: %s\n",
			pal.paint(codeYellow, "~"), normalizeDetail(p.Normalize))
	}
	if p.DisableKeys2() {
		fmt.Fprintf(tw, "  %s\t(authorized_keys2)\t\t\tdisable ~/.ssh/authorized_keys2 → ~/.ssh/authorized_keys2%s (unmanaged; sshd would keep accepting its keys)\n",
			pal.paint(codeRed, "-"), Keys2DisabledSuffix)
	}
	headerOnlyRow(tw, p, pal)
	_ = tw.Flush()

	if p.FileAbsent {
		// The audit diagnostic, carried into the plan: creating the audited
		// file is purely additive and never blocks apply.
		fmt.Fprintln(w, "  note: the audited file is absent yet login succeeded — sshd may consult")
		fmt.Fprintln(w, "        another key source; creating the file is purely additive")
	}
	serialWarning(w, p, pal)
	if p.Note != "" {
		fmt.Fprintf(w, "  note: %s\n", p.Note)
	}
	if p.Warning != "" {
		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), p.Warning)
	}
	if p.AgentOnly != "" {
		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), p.AgentOnly)
	}
	protectedRemovalWarnings(w, p, pal)
	for _, rw := range p.Rewrites {
		renderRewriteWarning(w, cfg, opts, pal, rw.Key, "drops restrictive", rw.Loosens)
	}
	for _, rw := range p.Rewrites {
		renderRewriteWarning(w, cfg, opts, pal, rw.Key, "adds relaxing", rw.Widens)
	}
	summaryLine(w, p)
}

// headerOnlyRow is a header-only write's one row in place of key rows (§3
// "Report").
func headerOnlyRow(tw io.Writer, p ServerPlan, pal palette) {
	if p.HeaderOnly {
		fmt.Fprintf(tw, "  %s\t(header)\t\t\tupdate header: %s → %d (keys unchanged)\n",
			pal.paint(codeYellow, "~"), headerFrom(p.Serial), p.Serial.Writes)
	}
}

// serialWarning prints rows 1 and 3's note (forged, removal-only) on a
// change.
func serialWarning(w io.Writer, p ServerPlan, pal palette) {
	if p.SerialNote != "" {
		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), p.SerialNote)
	}
}

// protectedRemovalWarnings prints one warning per protected key an except:
// takes off this server.
func protectedRemovalWarnings(w io.Writer, p ServerPlan, pal palette) {
	for _, msg := range p.ProtectedRemovals {
		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), msg)
	}
}

// summaryLine is a change's last line: the key counts, or "header only".
func summaryLine(w io.Writer, p ServerPlan) {
	if p.HeaderOnly {
		fmt.Fprintf(w, "  → %s desired · header only\n", Plural(len(p.Desired), "key", "keys"))
		return
	}
	fmt.Fprintf(w, "  → %s desired · %d add · %d remove · %d rewrite\n",
		Plural(len(p.Desired), "key", "keys"), len(p.Add), len(p.Remove), len(p.Rewrites))
}

// headerFrom names the header a header-only write replaces: "no serial"
// (legacy), "serial S", or "forged serial S".
func headerFrom(sp SerialPlan) string {
	switch {
	case sp.Case == SerialForged:
		return fmt.Sprintf("forged serial %d", sp.Header)
	case sp.Header == 0:
		return "no serial"
	default:
		return fmt.Sprintf("serial %d", sp.Header)
	}
}

// renderRewriteWarning prints one bold-red warning naming the options a
// rewrite drops (loosening) or adds (widening): either way the manifest line
// grants more than the server does today. Nothing for an empty list; %q
// keeps hostile option text inert.
func renderRewriteWarning(w io.Writer, cfg *config.Config, opts RenderOptions, pal palette, k authkeys.Key, verb string, options []string) {
	if len(options) == 0 {
		return
	}
	quoted := make([]string, 0, len(options))
	for _, o := range options {
		quoted = append(quoted, fmt.Sprintf("%q", o))
	}
	fmt.Fprintf(w, "  %s the rewrite of %s's key %s option(s) %s — the manifest line grants more than the server does today\n",
		pal.paint(codeBoldRed, "warning:"), label(cfg, opts, k), verb, strings.Join(quoted, ", "))
}

// renderKeys2Warning prints the phase-1 authorized_keys2 finding on a
// server apply will not write (a change plan disables the file instead):
// apply cannot converge what sshd may also read.
func renderKeys2Warning(w io.Writer, p ServerPlan, pal palette) {
	if p.AuthorizedKeys2 && !p.DisableKeys2() {
		fmt.Fprintf(w, "  %s ~/.ssh/authorized_keys2 exists and is non-empty — sshd may accept keys from it; apply disables it only on a server it writes (review and remove it by hand)\n",
			pal.paint(codeYellow, "warning:"))
	}
}

// Keys2DisabledSuffix names where a write moves authorized_keys2 aside.
const Keys2DisabledSuffix = fleet.Keys2DisabledSuffix // gitleaks:allow (a Go constant name, not a secret)

// rewriteDetail renders a rewrite row's change. %q escapes any control
// bytes a hostile on-server comment or option carries.
func rewriteDetail(rw RewriteRow) string {
	opts := fmt.Sprintf("rewrite options: %s → %s", fmtOptions(rw.ActualOptions), fmtOptions(rw.Key.Options))
	switch {
	case rw.CommentDiffers && rw.OptionsDiffer:
		return fmt.Sprintf("%s · comment: %q → %q", opts, rw.ActualComment, rw.DesiredComment)
	case rw.OptionsDiffer:
		return opts
	default:
		return fmt.Sprintf("rewrite comment: %q → %q", rw.ActualComment, rw.DesiredComment)
	}
}

// fmtOptions renders an options list as authorized_keys writes it, quoted,
// or "(none)".
func fmtOptions(opts []string) string {
	if len(opts) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%q", strings.Join(opts, ","))
}

func normalizeDetail(n Normalize) string {
	var parts []string
	if n.Reorder {
		parts = append(parts, "reordering")
	}
	if n.NonKeyLines > 0 {
		parts = append(parts, fmt.Sprintf("removing %s (comments/blank)", Plural(n.NonKeyLines, "non-key line", "non-key lines")))
	}
	if n.Duplicates > 0 {
		d := "removing " + Plural(n.Duplicates, "duplicate key line", "duplicate key lines")
		if n.DuplicateOptionsDiffer {
			d += " (some carry options different from the first copy)"
		}
		parts = append(parts, d)
	}
	if n.Whitespace {
		parts = append(parts, "whitespace/format")
	}
	return strings.Join(parts, "; ")
}

// summaryCounts is the outcome tally behind the text Summary line and the
// JSON summary object — one helper so the two can never disagree.
// converged includes servers applied this run; refused counts plan
// refusals and write refusals alike.
type summaryCounts struct {
	converged, applied, pending, refused, failed, unreachable, unproven, lockout int
}

func countSummary(plans []ServerPlan) summaryCounts {
	var c summaryCounts
	for _, p := range plans {
		switch p.Class {
		case ClassConverged:
			c.converged++
		case ClassRefused:
			c.refused++
		case ClassUnreachable:
			c.unreachable++
		case ClassChange:
			switch p.Outcome {
			case OutcomeApplied:
				c.converged++
				c.applied++
			case OutcomeRefused:
				c.refused++
			case OutcomeFailed:
				c.failed++
			case OutcomeUnproven:
				c.unproven++
			case OutcomeLockoutUnrestored:
				c.lockout++
			default:
				c.pending++
			}
		}
	}
	return c
}

// RenderSummary writes the phase-2 outcome lines (one per written, refused,
// failed, unproven, or interrupted-before-writing server) and the final
// Summary. "Converged" counts servers that needed nothing and servers
// applied-and-verified this run. cfg names the keys a rollback put back.
func RenderSummary(w io.Writer, cfg *config.Config, plans []ServerPlan, opts RenderOptions) {
	if len(plans) == 0 {
		return // Render already printed the 0-servers summary
	}
	pal := palette{on: opts.Color}
	// The summary keeps its own dedupe set: a hint seen in the plan report
	// prints again at most once here.
	var hints audit.Hints
	for _, p := range plans {
		if p.Class == ClassChange {
			renderOutcome(w, cfg, p, pal, opts, &hints)
		}
	}
	c := countSummary(plans)
	line := fmt.Sprintf("Summary: %d/%d servers converged", c.converged, len(plans))
	if c.applied > 0 {
		line += fmt.Sprintf(" (%d applied)", c.applied)
	}
	for _, seg := range []struct {
		n     int
		label string
	}{{c.pending, "pending"}, {c.failed, "failed"}, {c.refused, "refused"}, {c.unreachable, "unreachable"}, {c.unproven, "unproven"}, {c.lockout, "lockout not restored"}} {
		if seg.n > 0 {
			line += fmt.Sprintf(" · %d %s", seg.n, seg.label)
		}
	}
	fmt.Fprintf(w, "%s  → exit %d\n", line, ExitCode(plans))
}

// renderOutcome is one change server's outcome line.
func renderOutcome(w io.Writer, cfg *config.Config, p ServerPlan, pal palette, opts RenderOptions, hints *audit.Hints) {
	label, code := outcomeLabel(p)
	switch {
	case p.Outcome == OutcomeApplied:
		fmt.Fprintf(w, "%s: %s\n", p.Server.Name, pal.paint(codeGreen, "applied · verified"))
	case label != "":
		fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(code, label), collapse(outcomeText(cfg, opts.Former, p)))
		hints.Write(w, p.OutcomeErr)
	case p.OutcomeErr != nil:
		fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeYellow, "NOT STARTED:"), oneLine(p.OutcomeErr))
	}
}

// outcomeLabel is an outcome line's word and color; bold red marks every
// line that exits 2.
func outcomeLabel(p ServerPlan) (label, code string) {
	switch p.Outcome {
	case OutcomeRefused:
		return "REFUSED:", codeBoldRed
	case OutcomeLockoutUnrestored:
		return "LOCKOUT — NOT RESTORED:", codeBoldRed
	case OutcomeFailed:
		if needsHuman(p) {
			return "FAILED:", codeBoldRed
		}
		return "FAILED:", codeRed
	case OutcomeUnproven:
		if needsHuman(p) {
			return "UNPROVEN:", codeBoldRed
		}
		return "UNPROVEN:", codeYellow
	}
	return "", ""
}

// outcomeText is a failed server's message: the error, plus the keys a
// rollback put back. The JSON report's error is the same text.
func outcomeText(cfg, former *config.Config, p ServerPlan) string {
	return p.OutcomeErr.Error() + rollbackDetail(cfg, former, p)
}

// rollbackDetail names each key a rollback reinstated, marking the ones on
// the manifest's revoked: list; "" when there is no rollback or nothing was
// removed.
func rollbackDetail(cfg, former *config.Config, p ServerPlan) string {
	if !p.RolledBack || len(p.Remove) == 0 {
		return ""
	}
	parts := make([]string, 0, len(p.Remove))
	for _, k := range p.Remove {
		mark := ""
		if slices.Contains(p.RevokedRemovals, k.Fingerprint) {
			mark = ", on the revoked: list"
		}
		parts = append(parts, fmt.Sprintf("%s (%s%s)", rollbackLabel(cfg, former, k), k.Fingerprint, mark))
	}
	list := parts[len(parts)-1]
	if n := len(parts); n > 1 {
		list = strings.Join(parts[:n-1], ", ") + " and " + parts[n-1]
	}
	return fmt.Sprintf("; it still grants %s, which the manifest removed — fix the surviving key and re-run", list)
}

// rollbackLabel names a removed key: its owner in the rendered config, its
// former owner, or the unknown-key label (a key nobody owned).
func rollbackLabel(cfg, former *config.Config, k authkeys.Key) string {
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		return u.Name
	}
	if former != nil {
		if u, ok := former.OwnerOf(k.Fingerprint); ok {
			return u.Name
		}
	}
	return audit.UnknownLabel(k)
}
