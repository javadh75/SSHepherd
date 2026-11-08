package apply

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// SerialCase names the row of the spec 2026-11-08 §3 table that planned a
// server; it is the JSON serial.case value.
type SerialCase string

// The §3 rows (rows 5 and 8 on an equal serial are "equal"; rows 7 and 8
// on an older one are "older").
const (
	SerialForged           SerialCase = "forged"             // row 1
	SerialNewerConverged   SerialCase = "newer_converged"    // row 2 (D4c)
	SerialNewerRemovalOnly SerialCase = "newer_removal_only" // row 3
	SerialNewerRefused     SerialCase = "newer_refused"      // row 4
	SerialEqual            SerialCase = "equal"              // rows 5 and 8
	SerialHeaderOnly       SerialCase = "header_only"        // row 6, the PRD-2 fix
	SerialOlder            SerialCase = "older"              // rows 7 and 8
)

// newer reports rows 2-4: a real (not forged) header serial above the
// manifest's.
func (c SerialCase) newer() bool {
	return c == SerialNewerConverged || c == SerialNewerRemovalOnly || c == SerialNewerRefused
}

// SerialPlan is one server's header serial against the manifest's.
type SerialPlan struct {
	Header   uint64     // S as the server's header claims it; 0 = no serial (legacy header, hand-written or absent file)
	Manifest uint64     // M, the rendered manifest's serial
	Writes   uint64     // the serial a planned write's header carries (meaningful for ClassChange only)
	Case     SerialCase // "" when no row applied (unreachable, refused before rendering, granted nothing)
}

// BuildOptions tunes BuildWith.
type BuildOptions struct {
	// Bumped: this run saves a higher serial: (revoke, rotate) and every
	// planned server is in its bump scope (the affected set), so a server
	// whose keys already match and whose header is older gets a
	// header-only write carrying the new serial (§3 row 6). A plain apply
	// leaves it false.
	Bumped bool
}

// serialDecision is planSerial's verdict for one server.
type serialDecision struct {
	sp         SerialPlan
	converged  bool   // rows 2, 5, 7: no write
	refusal    string // row 4
	headerOnly bool   // rows 1 and 6 with equal bodies and no authorized_keys2
	equalBody  bool   // the server's body equals the render's: no key rows
	note       string // rows 1-3
}

// bodyOf is a file's body: everything after its first line.
func bodyOf(content []byte) []byte {
	_, body, _ := bytes.Cut(content, []byte("\n"))
	return body
}

// planSerial applies the §3 table. Bodies are equal only when the server's
// first line is a managed header and the rest is byte-identical to the
// render's; a non-empty authorized_keys2 to move aside makes an equal body
// a write (rows 2→3, 5/7→8).
func planSerial(m uint64, r audit.ServerResult, entries []authkeys.RenderEntry, renderedBody []byte, bumped bool) serialDecision {
	var s uint64
	managed := false
	if !r.FileAbsent {
		s, managed = authkeys.ParseHeaderOf(r.Content)
	}
	equal := managed && bytes.Equal(bodyOf(r.Content), renderedBody)
	quiet := equal && !r.AuthorizedKeys2
	d := serialDecision{sp: SerialPlan{Header: s, Manifest: m, Writes: m}, equalBody: equal}
	switch {
	case s > m+authkeys.ForgedMargin:
		d.sp.Case, d.headerOnly = SerialForged, quiet
		d.note = fmt.Sprintf("header claims serial %d, far above this manifest's %d — treated as no serial", s, m)
	case s > m:
		return newerSerial(d, r, entries, quiet)
	case s == m:
		d.sp.Case, d.converged = SerialEqual, quiet
	case quiet && bumped:
		d.sp.Case, d.headerOnly = SerialHeaderOnly, true
	default:
		d.sp.Case, d.converged = SerialOlder, quiet
	}
	return d
}

// newerSerial is rows 2-4: a server a newer manifest wrote. Only a write
// that removes access proceeds, and it keeps the server's serial, so a
// serial on a server never goes down.
func newerSerial(d serialDecision, r audit.ServerResult, entries []authkeys.RenderEntry, quiet bool) serialDecision {
	s, m := d.sp.Header, d.sp.Manifest
	switch {
	case quiet:
		d.sp.Case, d.converged = SerialNewerConverged, true
		d.note = fmt.Sprintf("written by newer manifest serial %d (yours is %d): pull the latest manifest", s, m)
	case removalOnly(r, entries):
		d.sp.Case, d.sp.Writes = SerialNewerRemovalOnly, s
		d.note = fmt.Sprintf("written by newer manifest serial %d; this write only removes keys, so it proceeds", s)
	default:
		d.sp.Case = SerialNewerRefused
		d.refusal = fmt.Sprintf("written by manifest serial %d, this manifest is %d — a newer manifest revoked or rotated keys here; pull the latest manifest, or if you are sure, set serial: %d in your manifest (this is the only override)", s, m, s)
	}
	return d
}

// removalOnly reports a write that grants nothing: every rendered key is
// already installed (its first line, as Diff keeps it) with the same option
// list, and no key is added. Comments, order, non-key lines and duplicate
// lines may differ. Any change to a kept key's options — loosening above
// all (authkeys.Loosening's cases) — is a grant, never removal-only.
func removalOnly(r audit.ServerResult, entries []authkeys.RenderEntry) bool {
	if len(r.Diff.Missing) > 0 {
		return false
	}
	for _, e := range entries {
		actual, ok := r.Diff.Actual[e.Key.Fingerprint]
		if !ok || !slices.Equal(actual.Options, e.Key.Options) {
			return false
		}
	}
	return true
}

// conflictRefusal is the refusal text for a server a revoked-kind policy
// conflict names (D29): each conflict's message, joined; "" when none names
// it. Weak-key conflicts have their own rule, weakRefusal.
func conflictRefusal(cfg *config.Config, server string) string {
	return conflictMessages(cfg, server, func(kind string) bool { return kind != config.ConflictWeakKey })
}

// weakRefusal is the refusal text for a server a weak-key conflict names, ""
// when none does. Unlike the revoked kinds it has one exception: a write
// that grants nothing and removes at least one key cannot install or widen
// the weak key, and without it an unrelated revoke would save but leave the
// revoked key installed on every server granting a weak key (OP4).
func weakRefusal(cfg *config.Config, r audit.ServerResult, entries []authkeys.RenderEntry) string {
	msgs := conflictMessages(cfg, r.Server.Name, func(kind string) bool { return kind == config.ConflictWeakKey })
	if msgs == "" || (removalOnly(r, entries) && len(r.Diff.Unauthorized) > 0) {
		return ""
	}
	return msgs
}

func conflictMessages(cfg *config.Config, server string, match func(kind string) bool) string {
	var msgs []string
	for _, c := range cfg.Conflicts() {
		if match(c.Kind) && slices.Contains(c.Servers, server) {
			msgs = append(msgs, c.Message)
		}
	}
	return strings.Join(msgs, "; ")
}
