package apply

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
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

// oneLine collapses newlines so hostile error text cannot forge report rows
// or a Summary line (terminal escapes are already stripped upstream).
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// label mirrors audit's row label: the owning user (with their comment:
// when set); for a key only opts.Former owns, its former owner and the
// edit's note ("alice (revoked)", "deploy (rotated out)"); else
// "(unknown)" for a key the manifest does not know.
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
		return "(unknown)"
	}
	if u.Comment != "" {
		return fmt.Sprintf("%s (%s)", u.Name, u.Comment)
	}
	return u.Name
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
	for _, p := range plans {
		head := fmt.Sprintf("%s (%s@%s:%d)", p.Server.Name, p.Server.User, p.Server.Host, p.Server.Port)
		switch p.Class {
		case ClassUnreachable:
			fmt.Fprintf(w, "%s  %s %s\n\n", head, pal.paint(codeRed, "ERROR:"), oneLine(p.Err))
		case ClassConverged:
			fmt.Fprintf(w, "%s  converged (no changes)\n", head)
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
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tremove (unauthorized)\n",
			pal.paint(codeRed, "-"), label(cfg, opts, k), k.Fingerprint, k.Type)
	}
	for _, rw := range p.Rewrites {
		// The detail is the row's last cell, which tabwriter never pads, so
		// painting it keeps the columns aligned.
		detail := rewriteDetail(rw)
		if len(rw.Loosens) > 0 {
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
	_ = tw.Flush()

	if p.FileAbsent {
		// The audit diagnostic, carried into the plan: creating the audited
		// file is purely additive and never blocks apply.
		fmt.Fprintln(w, "  note: the audited file is absent yet login succeeded — sshd may consult")
		fmt.Fprintln(w, "        another key source; creating the file is purely additive")
	}
	if p.Note != "" {
		fmt.Fprintf(w, "  note: %s\n", p.Note)
	}
	if p.Warning != "" {
		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), p.Warning)
	}
	if p.AgentOnly != "" {
		fmt.Fprintf(w, "  %s %s\n", pal.paint(codeYellow, "warning:"), p.AgentOnly)
	}
	for _, rw := range p.Rewrites {
		if len(rw.Loosens) == 0 {
			continue
		}
		quoted := make([]string, 0, len(rw.Loosens))
		for _, o := range rw.Loosens {
			quoted = append(quoted, fmt.Sprintf("%q", o))
		}
		fmt.Fprintf(w, "  %s the rewrite of %s's key drops restrictive option(s) %s — the manifest line grants more than the server does today\n",
			pal.paint(codeBoldRed, "warning:"), label(cfg, opts, rw.Key), strings.Join(quoted, ", "))
	}
	fmt.Fprintf(w, "  → %s desired · %d add · %d remove · %d rewrite\n",
		Plural(len(p.Desired), "key", "keys"), len(p.Add), len(p.Remove), len(p.Rewrites))
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
const Keys2DisabledSuffix = sshwrite.Keys2DisabledSuffix

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

// RenderSummary writes the phase-2 outcome lines (one per written, refused,
// failed, or interrupted-before-writing server) and the final Summary. "Converged" counts servers that
// needed nothing and servers applied-and-verified this run.
func RenderSummary(w io.Writer, plans []ServerPlan, opts RenderOptions) {
	if len(plans) == 0 {
		return // Render already printed the 0-servers summary
	}
	pal := palette{on: opts.Color}
	var converged, applied, pending, refused, failed, unreachable int
	for _, p := range plans {
		switch p.Class {
		case ClassConverged:
			converged++
		case ClassRefused:
			refused++
		case ClassUnreachable:
			unreachable++
		case ClassChange:
			switch p.Outcome {
			case OutcomeApplied:
				converged++
				applied++
				fmt.Fprintf(w, "%s: %s\n", p.Server.Name, pal.paint(codeGreen, "applied · verified"))
			case OutcomeRefused:
				refused++
				fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeBoldRed, "REFUSED:"), oneLine(p.OutcomeErr))
			case OutcomeFailed:
				failed++
				fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeRed, "FAILED:"), oneLine(p.OutcomeErr))
			default:
				pending++
				if p.OutcomeErr != nil {
					fmt.Fprintf(w, "%s: %s %s\n", p.Server.Name, pal.paint(codeYellow, "NOT STARTED:"), oneLine(p.OutcomeErr))
				}
			}
		}
	}
	line := fmt.Sprintf("Summary: %d/%d servers converged", converged, len(plans))
	if applied > 0 {
		line += fmt.Sprintf(" (%d applied)", applied)
	}
	for _, seg := range []struct {
		n     int
		label string
	}{{pending, "pending"}, {failed, "failed"}, {refused, "refused"}, {unreachable, "unreachable"}} {
		if seg.n > 0 {
			line += fmt.Sprintf(" · %d %s", seg.n, seg.label)
		}
	}
	fmt.Fprintf(w, "%s  → exit %d\n", line, ExitCode(plans))
}
