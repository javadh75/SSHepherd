package audit

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// ExitCode maps audit results to the process exit code (monitoring-style,
// see docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md):
// 0 every server compliant (an empty fleet is trivially compliant);
// 1 drift and/or unreachable servers — compliance not proven;
// 2 critical drift — at least one server is missing an operator key.
// Tool errors (exit 3) are the caller's domain; this function never sees them.
func ExitCode(cfg *config.Config, results []ServerResult) int {
	code := 0
	for _, r := range results {
		switch statusOf(cfg, r) {
		case statusCritical:
			return 2
		case statusDrift, statusUnreachable:
			code = 1
		}
	}
	return code
}

// RenderOptions tunes report presentation.
type RenderOptions struct {
	Color bool // ANSI-color drift glyphs and key words; off = byte-identical to plain
}

// SGR codes used by the report. Every code is exactly four characters
// ("0;32"): text/tabwriter sizes columns by rune count and knows nothing of
// ANSI, and because SGR codes are pure ASCII (bytes == runes) every painted
// glyph cell inflates by the same amount — so columns stay aligned whether
// or not color is on.
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

// oneLine renders err for the report head. Newlines are collapsed so a
// hostile server's error text cannot forge report rows or a Summary line;
// terminal escapes are already stripped upstream (sshread), this closes the
// line-forgery half of the boundary.
func oneLine(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// Render writes the human-readable audit report. The report is the command's
// stdout product; diagnostics beyond the report belong on stderr (caller's
// concern).
func Render(w io.Writer, cfg *config.Config, results []ServerResult, opts RenderOptions) {
	if len(results) == 0 {
		fmt.Fprintln(w, "Summary: 0 servers configured — nothing to audit")
		return
	}
	pal := palette{on: opts.Color}
	for _, r := range results {
		renderServer(w, cfg, r, pal)
		fmt.Fprintln(w)
	}
	renderSummary(w, cfg, results)
}

func renderServer(w io.Writer, cfg *config.Config, r ServerResult, pal palette) {
	head := fmt.Sprintf("%s (%s@%s:%d)", r.Server.Name, r.Server.User, r.Server.Host, r.Server.Port)
	if r.Err != nil {
		fmt.Fprintf(w, "%s  %s %s\n", head, pal.paint(codeRed, "ERROR:"), oneLine(r.Err))
		return
	}
	fmt.Fprintln(w, head)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range r.Diff.OK {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tpresent & authorized\n",
			pal.paint(codeGreen, "✓"), label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, k := range r.Diff.Missing {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tauthorized but %s (%s: operator key)\n",
				pal.paint(codeBoldRed, "‼"), label(cfg, k), k.Fingerprint, k.Type,
				pal.paint(codeRed, "MISSING"), pal.paint(codeBoldRed, "CRITICAL"))
			continue
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tauthorized but %s\n",
			pal.paint(codeRed, "✗"), label(cfg, k), k.Fingerprint, k.Type,
			pal.paint(codeRed, "MISSING"))
	}
	for _, k := range r.Diff.Unauthorized {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tinstalled but %s\n",
			pal.paint(codeYellow, "⚠"), label(cfg, k), k.Fingerprint, k.Type,
			pal.paint(codeYellow, "UNAUTHORIZED"))
	}
	_ = tw.Flush()

	for _, pe := range r.ParseErrs {
		fmt.Fprintf(w, "  ⚠ line %d: unparseable entry\n", pe.Line)
	}
	if r.FileAbsent {
		fmt.Fprintln(w, "  note: authorized_keys is absent yet login succeeded — either sshd consults")
		fmt.Fprintln(w, "        another key source (custom AuthorizedKeysFile, AuthorizedKeysCommand,")
		fmt.Fprintln(w, "        or CA certificates) or all keys have been removed from this file;")
		fmt.Fprintln(w, "        verify before dismissing")
	} else if emptyFile(r) {
		fmt.Fprintln(w, "  note: authorized_keys is empty yet login succeeded — either sshd consults")
		fmt.Fprintln(w, "        another key source or all keys have been removed from this file;")
		fmt.Fprintln(w, "        verify before dismissing")
	}
	if r.NoUsersGranted {
		fmt.Fprintln(w, "  note: no users granted access in the manifest")
	}

	fmt.Fprintf(w, "  → %d authorized · %d present · %d missing · %d unauthorized\n",
		len(r.Diff.OK)+len(r.Diff.Missing), len(r.Diff.OK),
		len(r.Diff.Missing), len(r.Diff.Unauthorized))
}

// emptyFile reports the paradox case: connection fine, file present, zero
// entries parsed and nothing unparseable — yet our login key got us in.
func emptyFile(r ServerResult) bool {
	return len(r.Diff.OK) == 0 && len(r.Diff.Unauthorized) == 0 &&
		len(r.ParseErrs) == 0 && !r.NoUsersGranted
}

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

// criticalDrift reports whether this server's drift includes a missing
// operator key — the drift class that threatens fleet access itself.
func criticalDrift(cfg *config.Config, r ServerResult) bool {
	if r.Err != nil {
		return false // unreachable: nothing knowable about its keys
	}
	for _, k := range r.Diff.Missing {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			return true
		}
	}
	return false
}

// serverStatus classifies one server's audit outcome. The string values are
// wire contract: they appear verbatim as the JSON report's status field.
type serverStatus string

const (
	statusUnreachable serverStatus = "unreachable"
	statusCompliant   serverStatus = "compliant"
	statusCritical    serverStatus = "critical"
	statusDrift       serverStatus = "drift"
)

// statusOf is the single classifier behind the JSON status field, the
// summary counts, and (via ExitCode's criticalDrift use) the exit code.
// Precedence: unreachable (nothing knowable) > compliant > critical > drift.
func statusOf(cfg *config.Config, r ServerResult) serverStatus {
	switch {
	case r.Err != nil:
		return statusUnreachable
	case r.Compliant():
		return statusCompliant
	case criticalDrift(cfg, r):
		return statusCritical
	default:
		return statusDrift
	}
}

// tallyCounts aggregates fleet outcomes for the summary line and the JSON
// report. A critical server counts in both drift and critical.
type tallyCounts struct {
	compliant, drift, critical, unreachable int
}

func tallyResults(cfg *config.Config, results []ServerResult) tallyCounts {
	var c tallyCounts
	for _, r := range results {
		switch statusOf(cfg, r) {
		case statusUnreachable:
			c.unreachable++
		case statusCompliant:
			c.compliant++
		case statusCritical:
			c.drift++
			c.critical++
		default:
			c.drift++
		}
	}
	return c
}

func renderSummary(w io.Writer, cfg *config.Config, results []ServerResult) {
	c := tallyResults(cfg, results)
	fmt.Fprintf(w, "Summary: %d/%d servers compliant · %d with drift (%d critical) · %d unreachable  → exit %d\n",
		c.compliant, len(results), c.drift, c.critical, c.unreachable, ExitCode(cfg, results))
}
