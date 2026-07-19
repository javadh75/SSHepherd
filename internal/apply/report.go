package apply

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// RenderOptions tunes report presentation.
type RenderOptions struct {
	Color bool // ANSI-color glyphs and key words; off = byte-identical to plain
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
// when set), or "(unknown)" for a key the manifest does not know.
func label(cfg *config.Config, k authkeys.Key) string {
	u, ok := cfg.OwnerOf(k.Fingerprint)
	if !ok {
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
			fmt.Fprintf(w, "%s  converged (no changes)\n\n", head)
		case ClassRefused:
			fmt.Fprintf(w, "%s  %s %s\n\n", head, pal.paint(codeBoldRed, "REFUSED:"), p.Refusal)
		default:
			fmt.Fprintln(w, head)
			renderChange(w, cfg, p, pal)
			fmt.Fprintln(w)
		}
	}
}

func renderChange(w io.Writer, cfg *config.Config, p ServerPlan, pal palette) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range p.Add {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tadd (authorized, missing)\n",
			pal.paint(codeGreen, "+"), label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, k := range p.Remove {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tremove (unauthorized)\n",
			pal.paint(codeRed, "-"), label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, rw := range p.Rewrites {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			pal.paint(codeYellow, "~"), label(cfg, rw.Key), rw.Key.Fingerprint, rw.Key.Type, rewriteDetail(rw))
	}
	if p.Normalize.Any() {
		fmt.Fprintf(tw, "  %s\t(formatting)\t\t\tnormalize: %s\n",
			pal.paint(codeYellow, "~"), normalizeDetail(p.Normalize))
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
	fmt.Fprintf(w, "  → %d keys desired · %d add · %d remove · %d rewrite\n",
		len(p.Desired), len(p.Add), len(p.Remove), len(p.Rewrites))
}

func rewriteDetail(rw RewriteRow) string {
	switch {
	case rw.CommentDiffers && rw.OptionsDiffer:
		// %q escapes any control bytes a hostile on-server comment carries.
		return fmt.Sprintf("rewrite options · comment: %q → %q", rw.ActualComment, rw.DesiredComment)
	case rw.OptionsDiffer:
		return "rewrite options"
	default:
		return fmt.Sprintf("rewrite comment: %q → %q", rw.ActualComment, rw.DesiredComment)
	}
}

func normalizeDetail(n Normalize) string {
	var parts []string
	if n.Reorder {
		parts = append(parts, "reordering")
	}
	if n.NonKeyLines > 0 {
		parts = append(parts, fmt.Sprintf("removing %d non-key lines (comments/blank)", n.NonKeyLines))
	}
	if n.Whitespace {
		parts = append(parts, "whitespace/format")
	}
	return strings.Join(parts, "; ")
}

// RenderSummary writes the phase-2 outcome lines (one per written, refused,
// or failed server) and the final Summary. "Converged" counts servers that
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
