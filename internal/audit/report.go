package audit

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// ExitCode maps audit results to the process exit code: 0 only when every
// server is compliant. An empty fleet is trivially compliant.
func ExitCode(results []ServerResult) int {
	for _, r := range results {
		if !r.Compliant() {
			return 1
		}
	}
	return 0
}

// Render writes the human-readable audit report. The report is the command's
// stdout product; diagnostics beyond the report belong on stderr (caller's
// concern).
func Render(w io.Writer, cfg *config.Config, results []ServerResult) {
	if len(results) == 0 {
		fmt.Fprintln(w, "Summary: 0 servers configured — nothing to audit")
		return
	}
	for _, r := range results {
		renderServer(w, cfg, r)
		fmt.Fprintln(w)
	}
	renderSummary(w, results)
}

func renderServer(w io.Writer, cfg *config.Config, r ServerResult) {
	head := fmt.Sprintf("%s (%s@%s:%d)", r.Server.Name, r.Server.User, r.Server.Host, r.Server.Port)
	if r.Err != nil {
		fmt.Fprintf(w, "%s  ERROR: %v\n", head, r.Err)
		return
	}
	fmt.Fprintln(w, head)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range r.Diff.OK {
		fmt.Fprintf(tw, "  ✓\t%s\t%s\t%s\tpresent & authorized\n", label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, k := range r.Diff.Missing {
		fmt.Fprintf(tw, "  ✗\t%s\t%s\t%s\tauthorized but MISSING\n", label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, k := range r.Diff.Unauthorized {
		fmt.Fprintf(tw, "  ⚠\t(unknown)\t%s\t%s\tinstalled but UNAUTHORIZED\n", k.Fingerprint, k.Type)
	}
	_ = tw.Flush()

	for _, pe := range r.ParseErrs {
		fmt.Fprintf(w, "  ⚠ line %d: unparseable entry\n", pe.Line)
	}
	if r.FileAbsent {
		fmt.Fprintln(w, "  note: login succeeded but the audited authorized_keys file is absent —")
		fmt.Fprintln(w, "        sshd likely consults another key source (custom AuthorizedKeysFile,")
		fmt.Fprintln(w, "        AuthorizedKeysCommand, or CA certificates); this server may not be")
		fmt.Fprintln(w, "        auditable via this file")
	} else if emptyFile(r) {
		fmt.Fprintln(w, "  note: login succeeded but the audited authorized_keys file is empty —")
		fmt.Fprintln(w, "        sshd likely consults another key source; see file-absent guidance")
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

func renderSummary(w io.Writer, results []ServerResult) {
	var compliant, drift, unreachable int
	for _, r := range results {
		switch {
		case r.Err != nil:
			unreachable++
		case r.Compliant():
			compliant++
		default:
			drift++
		}
	}
	fmt.Fprintf(w, "Summary: %d/%d servers compliant · %d with drift · %d unreachable  → exit %d\n",
		compliant, len(results), drift, unreachable, ExitCode(results))
}
