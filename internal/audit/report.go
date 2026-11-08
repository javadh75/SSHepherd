package audit

import (
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sanitize"
)

// ExitCode maps audit results to the process exit code (monitoring-style,
// see docs/superpowers/specs/2026-07-16-audit-json-exit-codes-design.md and
// the 2026-11-08 revocation-memory spec §8): 0 every server compliant (an
// empty fleet is trivially compliant; a header serial below the manifest's
// is not drift); 1 drift and/or unreachable servers — including a server
// written by a newer manifest (D4a) and a key installed where its access
// was revoked (D1d); 2 critical — a missing operator key, a revoked key
// still installed (D2), a forged header serial, a policy conflict in the
// manifest (D29, even with no server read), or a host key that changed (or
// is @revoked). Tool errors (exit 3) are the caller's domain.
func ExitCode(cfg *config.Config, results []ServerResult) int {
	if len(cfg.Conflicts()) > 0 {
		return 2
	}
	code := 0
	for _, r := range results {
		switch statusOf(cfg, r) {
		case statusCritical:
			return 2
		case statusUnreachable:
			if hostKeyAlert(fleet.ErrorKindOf(r.Err)) {
				return 2
			}
			code = 1
		case statusDrift:
			code = 1
		}
	}
	return code
}

// RenderOptions tunes report presentation.
type RenderOptions struct {
	Color bool // ANSI-color drift glyphs and key words; off = byte-identical to plain
	// Comments annotates OK rows whose on-server comment differs from the
	// write-policy's desired comment (config.DesiredComment). Informational
	// only — never affects classification or the exit code; off (the
	// default) keeps output byte-identical to earlier releases.
	Comments bool
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
	pal := palette{on: opts.Color}
	renderConflicts(w, cfg, pal)
	if len(results) == 0 {
		fmt.Fprintln(w, "Summary: 0 servers configured — nothing to audit")
		return
	}
	var hints Hints
	for _, r := range results {
		renderServer(w, cfg, r, pal, opts.Comments, &hints)
		fmt.Fprintln(w)
	}
	renderSummary(w, cfg, results)
}

// renderConflicts prints the manifest's policy conflicts (D29) before any
// server: each one is critical on its own.
func renderConflicts(w io.Writer, cfg *config.Config, pal palette) {
	cs := cfg.Conflicts()
	for _, c := range cs {
		fmt.Fprintf(w, "%s manifest: %s (%s: policy conflict)\n", pal.paint(codeBoldRed, "‼"), c.Message, pal.paint(codeBoldRed, "CRITICAL"))
	}
	if len(cs) > 0 {
		fmt.Fprintln(w)
	}
}

// ErrorTag is the head of an unreachable server's row: "ERROR [kind]:" for
// a classified failure, plain "ERROR:" otherwise. alert marks a host-key
// alert (changed or @revoked), painted bold red by both reports. The kind
// leads so a changed host key is told apart from a timeout at a glance.
func ErrorTag(err error) (tag string, alert bool) {
	kind := fleet.ErrorKindOf(err)
	if kind == "" || kind == fleet.ErrorKindUnknown {
		return "ERROR:", false
	}
	return "ERROR [" + string(kind) + "]:", hostKeyAlert(kind)
}

// CleanHint is err's hint on one sanitized line, the form both reports print
// and JSON carries. Hints are built locally, but they quote the configured
// host and the known_hosts path, so they get the same boundary as error text.
func CleanHint(err error) string {
	return sanitize.Remote(strings.Join(strings.Fields(fleet.HintOf(err)), " "))
}

// Hints prints each distinct remediation hint once per report, on its own
// indented line under the first server that needs it. A fleet-wide outage
// gets one bastion hint, not N. Per-host hints such as host-key changes are
// distinct by text and still print per server. The zero value is ready.
type Hints struct{ seen map[string]bool }

// Write prints err's hint as "  hint: …" unless it is empty or was already
// printed through h.
func (h *Hints) Write(w io.Writer, err error) {
	hint := CleanHint(err)
	if hint == "" || h.seen[hint] {
		return
	}
	if h.seen == nil {
		h.seen = make(map[string]bool)
	}
	h.seen[hint] = true
	fmt.Fprintf(w, "  hint: %s\n", hint)
}

func renderServer(w io.Writer, cfg *config.Config, r ServerResult, pal palette, comments bool, hints *Hints) {
	head := fmt.Sprintf("%s (%s@%s:%d)", r.Server.Name, r.Server.User, r.Server.Host, r.Server.Port)
	if r.Err != nil {
		tag, alert := ErrorTag(r.Err)
		code := codeRed
		if alert {
			code = codeBoldRed
		}
		fmt.Fprintf(w, "%s  %s %s\n", head, pal.paint(code, tag), oneLine(r.Err))
		hints.Write(w, r.Err) // plain text: no new SGR, color-stripped == plain holds
		return
	}
	fmt.Fprintln(w, head)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range r.Diff.OK {
		glyph, status := okStatus(cfg, r, k, pal, comments)
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n",
			glyph, label(cfg, k), k.Fingerprint, k.Type, status)
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
		if t, revoked := cfg.Revoked(k.Fingerprint); revoked {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tinstalled but %s (%s: revoked key)\n",
				pal.paint(codeBoldRed, "‼"), revokedLabel(t), k.Fingerprint, k.Type,
				pal.paint(codeRed, "REVOKED"), pal.paint(codeBoldRed, "CRITICAL"))
			continue
		}
		// A key the manifest does not own also shows its on-server options:
		// with the comment, the only clue to what it is and what it can do.
		// A known owner's key keeps today's cell.
		suffix := ""
		if _, ok := cfg.OwnerOf(k.Fingerprint); !ok {
			suffix = UnknownOptions(k)
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tinstalled but %s%s\n",
			pal.paint(codeYellow, "⚠"), unauthorizedLabel(cfg, r.Server.Name, k), k.Fingerprint, k.Type,
			pal.paint(codeYellow, "UNAUTHORIZED"), suffix)
	}
	_ = tw.Flush()

	for _, pe := range r.ParseErrs {
		fmt.Fprintf(w, "  ⚠ line %d: unparseable entry\n", pe.Line)
	}
	for _, d := range r.Duplicates {
		fmt.Fprintf(w, "  ⚠ duplicate entry: %s %s appears on %d lines — sshd tries each line, so the least restricted copy wins\n",
			label(cfg, d.Key), d.Key.Fingerprint, d.Count)
	}
	if r.AuthorizedKeys2 {
		fmt.Fprintln(w, "  ⚠ unmanaged authorized_keys2 present: ~/.ssh/authorized_keys2 is non-empty and")
		fmt.Fprintln(w, "    sshd's default AuthorizedKeysFile accepts its keys too — this audit does not")
		fmt.Fprintln(w, "    list them; apply moves the file aside when it writes this server")
	}
	renderMemoryNotes(w, cfg, r, pal)
	renderFileNotes(w, r)
	if r.NoUsersGranted {
		fmt.Fprintln(w, "  note: no users granted access in the manifest")
	}

	fmt.Fprintf(w, "  → %d authorized · %d present · %d missing · %d unauthorized\n",
		len(r.Diff.OK)+len(r.Diff.Missing), len(r.Diff.OK),
		len(r.Diff.Missing), len(r.Diff.Unauthorized))
}

// renderMemoryNotes prints the server's serial and conflict findings: a
// forged header (critical), a newer manifest's header (drift, D4a), and
// membership in a policy conflict (critical, D29).
func renderMemoryNotes(w io.Writer, cfg *config.Config, r ServerResult, pal palette) {
	m := cfg.Serial()
	switch {
	case r.forged(m):
		fmt.Fprintf(w, "  %s header claims serial %d, far above this manifest's %d — someone edited this file (%s: forged header)\n",
			pal.paint(codeBoldRed, "‼"), r.HeaderSerial, m, pal.paint(codeBoldRed, "CRITICAL"))
	case r.serialAhead(m):
		fmt.Fprintf(w, "  ⚠ written by newer manifest serial %d (yours is %d): pull the latest manifest\n", r.HeaderSerial, m)
	}
	if inConflict(cfg, r.Server.Name) {
		fmt.Fprintf(w, "  %s named by a manifest policy conflict above (%s: policy conflict)\n",
			pal.paint(codeBoldRed, "‼"), pal.paint(codeBoldRed, "CRITICAL"))
	}
}

// revokedLabel labels a tombstoned key: "alice (REVOKED 2026-11-08)", or
// "(REVOKED 2026-11-08)" for an unlabelled tombstone.
func revokedLabel(t config.Tombstone) string {
	if t.User == "" {
		return "(REVOKED " + t.Date + ")"
	}
	return t.User + " (REVOKED " + t.Date + ")"
}

// unauthorizedLabel is label, widened for a known owner whose access to
// server an access tombstone removed (D1d): "bob (access revoked DATE)".
func unauthorizedLabel(cfg *config.Config, server string, k authkeys.Key) string {
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		if t, gone := cfg.AccessRevoked(u.Name, server); gone {
			return u.Name + " (access revoked " + t.Date + ")"
		}
	}
	return label(cfg, k)
}

// okStatus renders a matched key's glyph and status cell.
func okStatus(cfg *config.Config, r ServerResult, k authkeys.Key, pal palette, comments bool) (glyph, status string) {
	glyph = pal.paint(codeGreen, "✓")
	status = "present & authorized"
	// Options drift is security drift (a stripped from=/command=/restrict
	// widens the key's power), so it changes the glyph and the verdict; %q
	// keeps hostile option text on one inert line.
	if actual, desired, drifted := r.optionsDrift(k); drifted {
		glyph = pal.paint(codeYellow, "⚠")
		status = fmt.Sprintf("present but %s (server: %s · manifest: %s)",
			pal.paint(codeYellow, "OPTIONS DIFFER"), quoteOptions(actual), quoteOptions(desired))
	}
	// Plain text on purpose: no new SGR codes, so the color-stripped-
	// equals-plain invariant keeps holding.
	if actual, desired, drifted := commentDrift(cfg, r, k); comments && drifted {
		status += fmt.Sprintf(" · comment differs: %q → %q", actual, desired)
	}
	return glyph, status
}

// renderFileNotes writes the absent/empty-file paradox notes.
func renderFileNotes(w io.Writer, r ServerResult) {
	// The absent/empty notes are path-aware only when an override is set:
	// the no-override wording below is pinned byte-identical by the existing
	// goldens. With an override, the most likely cause flips from "sshd has
	// a custom AuthorizedKeysFile" (moot — the operator declared a path) to
	// "the declared path is wrong", so that hypothesis leads.
	if r.FileAbsent {
		if p := r.Server.AuthorizedKeysFile; p != "" {
			fmt.Fprintf(w, "  note: %s is absent yet login succeeded — the\n", p)
			fmt.Fprintln(w, "        authorized_keys_file override may not match sshd's AuthorizedKeysFile,")
			fmt.Fprintln(w, "        or sshd consults another key source (AuthorizedKeysCommand, CA")
			fmt.Fprintln(w, "        certificates); verify the override before dismissing")
		} else {
			fmt.Fprintln(w, "  note: authorized_keys is absent yet login succeeded — either sshd consults")
			fmt.Fprintln(w, "        another key source (custom AuthorizedKeysFile, AuthorizedKeysCommand,")
			fmt.Fprintln(w, "        or CA certificates) or all keys have been removed from this file;")
			fmt.Fprintln(w, "        verify before dismissing")
		}
	} else if emptyFile(r) {
		if p := r.Server.AuthorizedKeysFile; p != "" {
			fmt.Fprintf(w, "  note: %s is empty yet login succeeded — the\n", p)
			fmt.Fprintln(w, "        authorized_keys_file override may not match sshd's AuthorizedKeysFile,")
			fmt.Fprintln(w, "        or sshd consults another key source, or all keys have been removed")
			fmt.Fprintln(w, "        from this file; verify the override before dismissing")
		} else {
			fmt.Fprintln(w, "  note: authorized_keys is empty yet login succeeded — either sshd consults")
			fmt.Fprintln(w, "        another key source or all keys have been removed from this file;")
			fmt.Fprintln(w, "        verify before dismissing")
		}
	}
}

// emptyFile reports the paradox case: connection fine, file present, zero
// entries parsed and nothing unparseable — yet our login key got us in.
func emptyFile(r ServerResult) bool {
	return len(r.Diff.OK) == 0 && len(r.Diff.Unauthorized) == 0 &&
		len(r.ParseErrs) == 0 && !r.NoUsersGranted
}

// quoteOptions renders an options list as it appears on a key line, Go-
// quoted so hostile on-server text stays one inert token; "(none)" for an
// unrestricted key.
func quoteOptions(opts []string) string {
	if len(opts) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%q", strings.Join(opts, ","))
}

// maxLabelComment caps the on-server comment shown beside "(unknown)" so a
// long or hostile comment cannot blow out the label column.
const maxLabelComment = 40

// UnknownLabel labels a key the manifest does not own: "(unknown)" plus its
// sanitized on-server comment, Go-quoted (tabs/quotes stay inert inside the
// tabwriter cell) and capped — the one clue to whose key it is.
func UnknownLabel(k authkeys.Key) string {
	c := sanitize.Remote(strings.Join(strings.Fields(k.Comment), " "))
	if c == "" {
		return "(unknown)"
	}
	if r := []rune(c); len(r) > maxLabelComment {
		c = string(r[:maxLabelComment-1]) + "…"
	}
	return fmt.Sprintf("(unknown) %q", c)
}

// UnknownOptions is the status-cell suffix naming an unowned key's
// on-server options; "" when it has none. The cell is the row's last, which
// tabwriter never pads, so length cannot misalign columns.
func UnknownOptions(k authkeys.Key) string {
	if len(k.Options) == 0 {
		return ""
	}
	return " · options: " + quoteOptions(sanitizeAll(k.Options))
}

func label(cfg *config.Config, k authkeys.Key) string {
	u, ok := cfg.OwnerOf(k.Fingerprint)
	if !ok {
		return UnknownLabel(k)
	}
	if u.Comment != "" {
		return fmt.Sprintf("%s (%s)", u.Name, u.Comment)
	}
	return u.Name
}

// commentDrift compares a present key's on-server comment (Diff.Actual)
// against the decided write-time comment (config.DesiredComment). Keys with
// unknown owners have no desired comment and never drift. Cosmetic by
// definition: consumed only by the opt-in --comments annotations, never by
// classification or exit codes.
func commentDrift(cfg *config.Config, r ServerResult, k authkeys.Key) (actual, desired string, drifted bool) {
	u, ok := cfg.OwnerOf(k.Fingerprint)
	if !ok {
		return "", "", false
	}
	desired = config.DesiredComment(u, k)
	actual = r.Diff.Actual[k.Fingerprint].Comment
	return actual, desired, actual != desired
}

// criticalDrift reports drift that threatens the fleet: a missing operator
// key, a revoked key still installed (D2), a forged header serial, or a
// policy conflict naming this server (D29).
func criticalDrift(cfg *config.Config, r ServerResult) bool {
	if r.Err != nil {
		return false // unreachable: nothing knowable about its keys
	}
	for _, k := range r.Diff.Missing {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			return true
		}
	}
	for _, k := range r.Diff.Unauthorized {
		if _, revoked := cfg.Revoked(k.Fingerprint); revoked {
			return true
		}
	}
	return r.forged(cfg.Serial()) || inConflict(cfg, r.Server.Name)
}

// forged: the header claims a serial more than authkeys.ForgedMargin above
// the manifest's — someone edited the file.
func (r ServerResult) forged(m uint64) bool {
	return r.HeaderManaged && r.HeaderSerial > m+authkeys.ForgedMargin
}

// serialAhead: a newer manifest wrote this server (D4a) — drift, not critical.
func (r ServerResult) serialAhead(m uint64) bool {
	return r.HeaderManaged && r.HeaderSerial > m && !r.forged(m)
}

// inConflict reports whether a policy conflict names server.
func inConflict(cfg *config.Config, server string) bool {
	for _, c := range cfg.Conflicts() {
		if slices.Contains(c.Servers, server) {
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
// summary counts, and the exit code. Precedence: unreachable (nothing
// knowable) > critical > drift > compliant — critical and drift are checked
// first, so a key-compliant server with a forged or newer header, or one a
// policy conflict names, is never reported compliant.
func statusOf(cfg *config.Config, r ServerResult) serverStatus {
	switch {
	case r.Err != nil:
		return statusUnreachable
	case criticalDrift(cfg, r):
		return statusCritical
	case !r.Compliant() || r.serialAhead(cfg.Serial()):
		return statusDrift
	default:
		return statusCompliant
	}
}

// tallyCounts aggregates fleet outcomes for the summary line and the JSON
// report. A critical server counts in both drift and critical.
type tallyCounts struct {
	compliant, drift, critical, unreachable int
	hostKeyAlerts                           int // unreachable servers whose host key changed or is revoked
	revokedKeys                             int // tombstoned keys installed, across reachable servers
}

func tallyResults(cfg *config.Config, results []ServerResult) tallyCounts {
	var c tallyCounts
	for _, r := range results {
		for _, k := range r.Diff.Unauthorized {
			if _, revoked := cfg.Revoked(k.Fingerprint); revoked && r.Err == nil {
				c.revokedKeys++
			}
		}
		switch statusOf(cfg, r) {
		case statusUnreachable:
			c.unreachable++
			if hostKeyAlert(fleet.ErrorKindOf(r.Err)) {
				c.hostKeyAlerts++
			}
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
	// The alert count appears only when nonzero, keeping the common summary
	// line byte-identical to earlier releases.
	alerts := ""
	if c.hostKeyAlerts > 0 {
		alerts = fmt.Sprintf(" (%d HOST KEY ALERT)", c.hostKeyAlerts)
	}
	fmt.Fprintf(w, "Summary: %d/%d servers compliant · %d with drift (%d critical) · %d unreachable%s  → exit %d\n",
		c.compliant, len(results), c.drift, c.critical, c.unreachable, alerts, ExitCode(cfg, results))
}
