// Package apply computes the write plan for `sshepherd apply`: pure
// classification of each server against the manifest's rendered desired
// state, the self-lockout guard, phase-2 orchestration behind a writer
// seam, and the plan/outcome report. Nothing here imports the SSH
// transport.
package apply

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
)

// Class classifies one server's plan.
type Class string

const (
	// ClassConverged — current bytes equal the render, or the desired set is
	// empty and nothing is installed, authorized_keys2 included ("nothing
	// should be there and nothing is").
	ClassConverged Class = "converged"
	// ClassChange — a write is needed and allowed.
	ClassChange Class = "change"
	// ClassRefused — a write would occur but must not (wipe, unparseable
	// content, predicted lockout, a render too large to verify).
	ClassRefused Class = "refused"
	// ClassUnreachable — the phase-1 read failed; nothing knowable.
	ClassUnreachable Class = "unreachable"
	// ClassJumpOnly — a jump_only bastion (spec S5, OP8): listed, never read
	// or written; never guarded or probed; never changes the exit code.
	ClassJumpOnly Class = "jump_only"
)

// Outcome is the phase-2 result for a ClassChange server.
type Outcome string

// The phase-2 outcomes for a ClassChange server.
const (
	OutcomePending Outcome = "pending" // not written: dry-run, declined, phase 2 not run, or interrupted before the write (OutcomeErr set)
	OutcomeApplied Outcome = "applied" // written, byte-verified, and the surviving keys proved they can log in
	OutcomeRefused Outcome = "refused" // refused at the server before any change (symlink, unsafe path, changed since plan, locked)
	OutcomeFailed  Outcome = "failed"  // write or verify failed, or a rejected login check restored everything it had changed
	// OutcomeUnproven: written and verified, but the login check never got
	// past authentication; the file is kept.
	OutcomeUnproven Outcome = "unproven"
	// OutcomeLockoutUnrestored: a rejected login check whose restore of
	// authorized_keys or move-back of authorized_keys2 failed, or a refused
	// reconnect after the upload started — the operator may be locked out.
	OutcomeLockoutUnrestored Outcome = "lockout_unrestored"
)

// RewriteRow is a matched key whose on-server form differs from the render.
type RewriteRow struct {
	Key            authkeys.Key // desired (manifest) form; Key.Options are the options written
	ActualComment  string
	DesiredComment string
	ActualOptions  []string // on-server options, replaced by Key.Options
	CommentDiffers bool
	OptionsDiffer  bool
	// Loosens lists restrictive on-server options the rewrite drops (from=,
	// command=, restrict, the no-* restrictions, verify-required,
	// expiry-time=, the last permitopen=/permitlisten=, cert-authority,
	// principals=), plus any on-server option that makes sshd ignore the
	// line today (unknown, bad value, repeated once-only clause). See
	// authkeys.Loosening.
	Loosens []string
	// Widens lists relaxing options the rewrite adds (no-touch-required;
	// pty/port-/agent-/X11-forwarding/user-rc when both lines carry restrict;
	// a further permitopen=/permitlisten= clause beside the server's).
	// Together with Loosens: the key gains access it does not have today.
	Widens []string
}

// Normalize captures byte drift the per-key rows don't explain.
type Normalize struct {
	Reorder     bool // matched keys ordered differently than desired
	NonKeyLines int  // current comment/blank lines (managed header excluded) the rewrite removes
	// Duplicates counts repeated key lines (same fingerprint as an earlier
	// line) the rewrite removes; DuplicateOptionsDiffer reports that at
	// least one of them carried options other than its first copy's.
	Duplicates             int
	DuplicateOptionsDiffer bool
	Whitespace             bool // residual byte drift with nothing else to blame
	// EmptyExternalSection: the file holds the preserve: marker but no line
	// is kept any more (the tool removed its lines, or the rule was dropped),
	// so the rewrite drops it (spec S6). Not part of Any: the plan prints it
	// as its own row.
	EmptyExternalSection bool
	// ExternalSection: the write adds the preserve: marker the file lacks
	// (kept lines sit in the file with no marker above them yet, most often
	// the first apply after preserve: is added). Not part of Any: the plan
	// prints it as its own row (F1 Q3).
	ExternalSection bool
}

// Any reports whether a normalize row should render.
func (n Normalize) Any() bool {
	return n.Reorder || n.NonKeyLines > 0 || n.Duplicates > 0 || n.Whitespace
}

// ServerPlan is the computed plan for one server.
type ServerPlan struct {
	Server  config.Server
	Class   Class
	Err     error  // unreachable detail
	Refusal string // refused detail
	// WeakRefused marks a refusal by a weak-key conflict alone. It never
	// withholds an edit's save (OP4): an unrelated edit and the weak key's
	// own remediation save, and the push is refused at this server.
	WeakRefused bool

	Desired  []authkeys.Key // rendered key set, DesiredFor order
	Rendered []byte         // the exact bytes a write installs

	Add       []authkeys.Key // desired but missing
	Remove    []authkeys.Key // installed but not desired (on-server form)
	Rewrites  []RewriteRow
	Normalize Normalize

	Note    string // guard note: session key removed, another survives
	Warning string // restrictive-options warning
	// AgentOnly warns that --identity keys were given but only agent keys
	// survive here: a later run without this agent (the next headless CI
	// job) would be locked out. Not a refusal — union semantics.
	AgentOnly string
	// ProtectedRemovals warns, one line per user, that an except: takes a
	// protected user's key off this server. The lockout guard judges only
	// this run's keys, so a human run would otherwise remove CI's key with
	// no sign (spec S4). Set only on a server that will be written.
	ProtectedRemovals []string
	// ProbeForward is the host:port the post-write login check forwards to
	// when this server is another server's via (fleet.WriteRequest
	// .ProbeForward); "" when nothing goes through it.
	ProbeForward string
	// Kept counts the lines a preserve: rule keeps here (audit's External,
	// spec S6); the render writes them after the desired keys. Meaningful
	// for a converged or change plan.
	Kept       int
	FileAbsent bool // phase-1 diagnostic, carried into the report
	// AuthorizedKeys2 carries the phase-1 finding that an unmanaged,
	// non-empty ~/.ssh/authorized_keys2 exists: sshd may accept keys from it
	// whatever apply writes, so a change plan also disables it (see
	// DisableKeys2).
	AuthorizedKeys2 bool
	// Expect is the phase-1 snapshot the write is conditional on: phase 2
	// refuses a file that changed after this plan was shown.
	Expect fleet.Snapshot
	// HeaderOnly marks a change that rewrites only line 1 — the managed
	// header — to carry the manifest's serial (§3 rows 1 and 6): every byte
	// after it is the server's own, so it cannot widen access.
	HeaderOnly bool
	// Serial is the header-serial verdict; SerialNote the human note of
	// rows 1-3 (forged, newer converged, newer removal-only), "" otherwise.
	Serial     SerialPlan
	SerialNote string

	Outcome    Outcome
	OutcomeErr error
	// RevokedRemovals are the fingerprints in Remove on the manifest's
	// revoked: list (D10a), in Remove order.
	RevokedRemovals []string
	// RolledBack: a rejected login check restored the previous file, so the
	// keys in Remove are installed again.
	RolledBack bool
	// Warnings are the server's D9c warnings, in the order they arose.
	Warnings []string
}

// DisableKeys2 reports whether the write moves a non-empty
// ~/.ssh/authorized_keys2 aside: every change plan does when phase 1 found
// one (probed when the managed path is the default file under any spelling
// that resolves to it), because sshd keeps accepting its keys — a revoked
// key there would survive the revoke.
// A server the manifest grants nothing never gets here: with a non-empty
// authorized_keys2 it is refused, since apply never wipes a server.
func (p ServerPlan) DisableKeys2() bool {
	return p.Class == ClassChange && p.AuthorizedKeys2
}

// KeysUnchanged reports a plan whose only work is moving
// authorized_keys2 aside: the render equals the phase-1 snapshot, so the
// file is not rewritten and .bak is not rotated. It is evaluated after the
// commit, because Reserial may have re-rendered the header.
func (p ServerPlan) KeysUnchanged() bool {
	return p.DisableKeys2() && authkeys.ManagedSnapshot(false, p.Rendered) == p.Expect
}

// BuildWith computes the plan for every phase-1 result. held is what the
// run could authenticate with at preflight (the run's held-key listing: key
// files and plain agent keys, with their sources) — the self-lockout
// guard's ground truth. Pure; the only possible error is a render failure,
// impossible for a validated manifest (a tool bug, exit 3).
func BuildWith(cfg *config.Config, results []audit.ServerResult, held []fleet.HeldKey, opts BuildOptions) ([]ServerPlan, error) {
	plans := make([]ServerPlan, 0, len(results))
	for _, r := range results {
		p, err := planOne(cfg, r, held, opts)
		if err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, nil
}

// maxRender caps the rendered file at what the read path accepts back: a
// larger file could be written but never verified or audited. A variable
// only so tests can lower it.
var maxRender = fleet.MaxRemoteOutput

// theLines words the unparseable-line refusal's fix ("the line" / "the
// lines"); a helper so planOne stays under the gocyclo cap.
func theLines(n int) string {
	if n == 1 {
		return "the line"
	}
	return "the lines"
}

// planNoGrants classifies a server whose desired set is empty. Apply never
// wipes a server, so nothing is ever written here — converged when nothing
// (parseable or not) is installed, authorized_keys2 included; refused
// otherwise.
func planNoGrants(p ServerPlan, r audit.ServerResult) ServerPlan {
	switch {
	case len(r.Diff.Unauthorized) > 0 || len(r.ParseErrs) > 0:
		p.Class = ClassRefused
		p.Refusal = fmt.Sprintf("%s installed but manifest grants none — refusing to wipe",
			Plural(len(r.Diff.Unauthorized), "key", "keys"))
		if n := len(r.ParseErrs); n > 0 {
			p.Refusal = fmt.Sprintf(
				"%s and %s installed but manifest grants none — refusing to wipe",
				Plural(len(r.Diff.Unauthorized), "key", "keys"), Plural(n, "unparseable line", "unparseable lines"))
		}
	case r.AuthorizedKeys2:
		// sshd still accepts keys from authorized_keys2, so this is not
		// converged (audit calls it drift). Apply never wipes a server —
		// the on-hold empty-server mode — so refuse and leave the file to
		// the operator (COR-2).
		p.Class = ClassRefused
		p.Refusal = "authorized_keys2 holds keys but the manifest grants none — refusing to wipe; remove it by hand"
	default:
		p.Class = ClassConverged
	}
	return p
}

func planOne(cfg *config.Config, r audit.ServerResult, held []fleet.HeldKey, opts BuildOptions) (ServerPlan, error) {
	p := ServerPlan{
		Server: r.Server, Outcome: OutcomePending, FileAbsent: r.FileAbsent,
		AuthorizedKeys2: r.AuthorizedKeys2,
		Expect:          authkeys.ManagedSnapshot(r.FileAbsent, r.Content),
	}
	if r.Server.JumpOnly {
		p.Class = ClassJumpOnly
		return p, nil
	}
	if r.Err != nil {
		p.Class = ClassUnreachable
		p.Err = r.Err
		return p, nil //nolint:nilerr // an unreachable server is a plan class, not a Build failure
	}
	// A revoked-kind policy conflict names this server (D29): nothing is
	// written here — a revoked key is never installed, a revoked grant never
	// restored. The weak-key kind is checked below, once entries exist.
	if refusal := conflictRefusal(cfg, r.Server.Name); refusal != "" {
		p.Class, p.Refusal = ClassRefused, refusal
		return p, nil
	}
	p.Kept = len(r.External)

	entries := desiredEntries(cfg, r.Server.Name)
	for _, e := range entries {
		p.Desired = append(p.Desired, e.Key)
	}
	if len(entries) == 0 {
		return planNoGrants(p, r), nil
	}
	if refusal := weakRefusal(cfg, r, entries); refusal != "" {
		p.Class, p.Refusal, p.WeakRefused = ClassRefused, refusal, true
		return p, nil
	}

	// Unparseable lines: a full-file render would destroy content we could
	// not account for. Remediation: fix the line remotely or correct
	// authorized_keys_file.
	if n := len(r.ParseErrs); n > 0 {
		p.Class = ClassRefused
		p.Refusal = fmt.Sprintf(
			"%s — refusing to rewrite a file that could not be fully read (fix %s or correct authorized_keys_file)",
			Plural(n, "unparseable line", "unparseable lines"), theLines(n))
		return p, nil
	}
	return planWrite(cfg, p, r, entries, held, opts)
}

// refuseOversize refuses p because its render is over maxRender.
func refuseOversize(p ServerPlan) ServerPlan {
	p.Class = ClassRefused
	p.Refusal = fmt.Sprintf(
		"rendered file is %d bytes, over the %d-byte limit the read path accepts — refusing to write a file that could never be verified or audited (split the grant across accounts)",
		len(p.Rendered), maxRender)
	return p
}

// planWrite renders the server's file and classifies it by the §3 serial
// table: converged, refused (a newer manifest's serial, a render too large
// to verify), a header-only write, or a change with its key rows — then the
// self-lockout guard, which judges every write alike.
func planWrite(cfg *config.Config, p ServerPlan, r audit.ServerResult, entries []authkeys.RenderEntry, held []fleet.HeldKey, opts BuildOptions) (ServerPlan, error) {
	m := cfg.Serial()
	kept := keptLines(r)
	rendered, err := authkeys.RenderKept(entries, m, kept)
	if err != nil {
		return p, fmt.Errorf("render %s: %w", r.Server.Name, err)
	}
	p.Rendered = rendered
	if len(rendered) > maxRender {
		return refuseOversize(p), nil
	}
	d := planSerial(m, r, entries, bodyOf(rendered), opts.Bumped)
	p.Serial, p.SerialNote = d.sp, d.note
	switch {
	case d.refusal != "":
		p.Class, p.Refusal = ClassRefused, d.refusal
		return p, nil
	case d.converged:
		p.Class = ClassConverged
		return p, nil
	}
	if d.sp.Writes != m { // row 3 keeps the server's (higher) serial
		if p.Rendered, err = authkeys.RenderKept(entries, d.sp.Writes, kept); err != nil {
			return p, fmt.Errorf("render %s: %w", r.Server.Name, err)
		}
		if len(p.Rendered) > maxRender { // S is longer than M, and these are the bytes written
			p.SerialNote = ""
			return refuseOversize(p), nil
		}
	}
	p.HeaderOnly = d.headerOnly
	if !d.equalBody {
		p.Add = r.Diff.Missing
		p.Remove = r.Diff.Unauthorized
		p.RevokedRemovals = revokedRemovals(cfg, p.Remove)
		p.Rewrites = rewriteRows(r, entries)
		explained := len(p.Add)+len(p.Remove)+len(p.Rewrites) > 0
		p.Normalize = normalize(r, entries, explained)
	}
	v := guardCheck(cfg, r, entries, held)
	if v.Refusal != "" {
		p.Class = ClassRefused
		p.Refusal = v.Refusal
		return p, nil
	}
	p.Note, p.Warning, p.AgentOnly = v.Note, v.Warning, v.AgentOnly
	p.ProtectedRemovals = protectedRemovals(cfg, r.Server.Name, p.Remove)
	p.ProbeForward = probeForwardFor(cfg, r.Server.Name)
	p.Class = ClassChange
	return p, nil
}

// keptLines are the lines a preserve: rule keeps on this server, in file
// order (audit.ServerResult.External): the render appends them, with their
// comment lines, under authkeys.PreserveMarker (spec S6).
func keptLines(r audit.ServerResult) []authkeys.ScannedLine {
	out := make([]authkeys.ScannedLine, 0, len(r.External))
	for _, e := range r.External {
		out = append(out, e.Line)
	}
	return out
}

// revokedRemovals returns the fingerprints of remove on the manifest's
// revoked: list. cfg is the rendered config, so revoke and rotate see the
// tombstones their own edit appended. Key tombstones only: Revoked ignores
// access tombstones.
func revokedRemovals(cfg *config.Config, remove []authkeys.Key) []string {
	var out []string
	for _, k := range remove {
		if _, ok := cfg.Revoked(k.Fingerprint); ok {
			out = append(out, k.Fingerprint)
		}
	}
	return out
}

// protectedRemovals words one warning per protected user whose key an except:
// takes off server. A key in remove is not desired here, so the grant union
// does not cover the pair, as ExceptCarveOut requires; a group's except:
// counts too.
func protectedRemovals(cfg *config.Config, server string, remove []authkeys.Key) []string {
	var out []string
	for _, k := range remove {
		u, ok := cfg.OwnerOf(k.Fingerprint)
		if !ok || !u.IsProtected() || !cfg.ExceptCarveOut(u.Name, server) {
			continue
		}
		msg := fmt.Sprintf("removes protected key of %q (its except: excludes this server)", u.Name)
		if !slices.Contains(out, msg) {
			out = append(out, msg)
		}
	}
	return out
}

// desiredEntries builds the render input for one server: DesiredFor order
// (protected keys first), comments resolved through config.DesiredComment — the
// single write-time comment policy, shared with audit --comments so the
// preview and the write can never disagree.
func desiredEntries(cfg *config.Config, serverName string) []authkeys.RenderEntry {
	keys := cfg.DesiredFor(serverName)
	entries := make([]authkeys.RenderEntry, 0, len(keys))
	for _, k := range keys {
		u, _ := cfg.OwnerOf(k.Fingerprint) // always found: DesiredFor emits only owned keys
		entries = append(entries, authkeys.RenderEntry{Key: k, Comment: config.DesiredComment(u, k)})
	}
	return entries
}

// rewriteRows finds matched keys whose on-server form differs from what the
// render writes: comment (per the decided policy) or options.
func rewriteRows(r audit.ServerResult, entries []authkeys.RenderEntry) []RewriteRow {
	var rows []RewriteRow
	for _, e := range entries {
		actual, ok := r.Diff.Actual[e.Key.Fingerprint]
		if !ok {
			continue
		}
		row := RewriteRow{
			Key:            e.Key,
			ActualComment:  actual.Comment,
			DesiredComment: e.Comment,
			ActualOptions:  actual.Options,
			CommentDiffers: actual.Comment != e.Comment,
			OptionsDiffer:  !slices.Equal(actual.Options, e.Key.Options),
		}
		if row.OptionsDiffer {
			row.Loosens, row.Widens = authkeys.Loosening(actual.Options, e.Key.Options)
		}
		if row.CommentDiffers || row.OptionsDiffer {
			rows = append(rows, row)
		}
	}
	return rows
}

// normalize explains byte drift beyond the per-key rows: non-key lines the
// full-file render removes, repeated key lines it collapses, reordering of
// matched keys, or (when nothing else accounts for the byte difference)
// residual whitespace/format drift. A marker with nothing under it is
// EmptyExternalSection, and a marker the render adds is ExternalSection
// (spec S6, F1 Q3).
// Only called for servers whose bytes differ from the render.
func normalize(r audit.ServerResult, entries []authkeys.RenderEntry, explained bool) Normalize {
	var n Normalize
	n.NonKeyLines, n.EmptyExternalSection, n.ExternalSection = nonKeyLines(r)
	n.Reorder = matchedOrderDiffers(r, entries)
	// Duplicates: Diff collapses them first-wins, but each is a whole key
	// line (possibly with its own options) the rewrite deletes — a semantic
	// change the plan must name, never "whitespace".
	n.Duplicates, n.DuplicateOptionsDiffer = duplicateLines(r)
	if !explained && !n.Reorder && n.NonKeyLines == 0 && n.Duplicates == 0 && !n.EmptyExternalSection && !n.ExternalSection {
		n.Whitespace = true
	}
	return n
}

// nonKeyLines counts the comment and blank lines the rewrite removes: not
// the managed header (re-emitted), not the comment lines kept above a
// preserved line, and not the one PreserveMarker the render writes back
// while lines are kept. A marker with nothing left under it is
// emptySection instead; every further marker is a removed non-key line.
// newSection: lines are kept and the file has no marker, so the render
// adds one (authkeys.RenderKept writes it exactly when something is kept).
func nonKeyLines(r audit.ServerResult) (n int, emptySection, newSection bool) {
	lines := strings.Split(string(r.Content), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // a well-formed file's trailing newline, not a blank line
	}
	markers := 0
	for _, line := range lines {
		t := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		_, managed := authkeys.ParseHeader(t)
		switch {
		case managed:
		case t == authkeys.PreserveMarker:
			markers++
		case t == "" || strings.HasPrefix(t, "#"):
			n++
		}
	}
	for _, e := range r.External {
		n -= len(e.Line.Above)
	}
	if markers > 0 {
		n += markers - 1
		emptySection = len(r.External) == 0
	}
	newSection = markers == 0 && len(r.External) > 0
	return n, emptySection, newSection
}

// duplicateLines counts the repeated key lines the rewrite removes (same
// fingerprint as an earlier line) and whether any carried options other
// than its first copy's. A kept fingerprint is not counted: every one of
// its lines stays. Content re-parses cleanly here (parse errors were
// refused earlier).
func duplicateLines(r audit.ServerResult) (n int, optionsDiffer bool) {
	keys, _ := authkeys.ParseFile(r.Content)
	first := make(map[string]authkeys.Key, len(keys))
	for _, k := range keys {
		if r.IsExternal(k.Fingerprint) {
			continue
		}
		f, seen := first[k.Fingerprint]
		if !seen {
			first[k.Fingerprint] = k
			continue
		}
		n++
		if !slices.Equal(f.Options, k.Options) {
			optionsDiffer = true
		}
	}
	return n, optionsDiffer
}

// matchedOrderDiffers reports whether the matched keys' relative order on
// the server differs from the desired order. Content re-parses cleanly here
// (parse errors were refused earlier); duplicate fingerprints collapse
// first-wins, exactly like Diff.
func matchedOrderDiffers(r audit.ServerResult, entries []authkeys.RenderEntry) bool {
	desiredSet := make(map[string]bool, len(entries))
	var want []string
	for _, e := range entries {
		desiredSet[e.Key.Fingerprint] = true
	}
	for _, e := range entries {
		if _, ok := r.Diff.Actual[e.Key.Fingerprint]; ok {
			want = append(want, e.Key.Fingerprint)
		}
	}
	actualKeys, _ := authkeys.ParseFile(r.Content)
	seen := make(map[string]bool, len(actualKeys))
	var got []string
	for _, k := range actualKeys {
		if seen[k.Fingerprint] {
			continue
		}
		seen[k.Fingerprint] = true
		if desiredSet[k.Fingerprint] {
			got = append(got, k.Fingerprint)
		}
	}
	return !slices.Equal(want, got)
}

// guardVerdict is the self-lockout guard's decision for one server.
type guardVerdict struct {
	Refusal   string
	Note      string
	Warning   string
	AgentOnly string
}

// guardCheck enforces the invariant "after the write, this operator can
// still log in": the rendered desired set must intersect the keys the run
// holds (key files + plain agent keys; certificates never count).
// Deliberately not the operator spec's literal "never remove the session
// key" — which key signs a handshake is an accident of key order and server
// choice, and the literal rule would randomly block rotate (see the
// 2026-07-19 spec's guard section; owner-approved refinement). Removing the
// very key that authenticated is allowed when another held key survives —
// that is what rotate is — with a loud per-server note.
func guardCheck(cfg *config.Config, r audit.ServerResult, entries []authkeys.RenderEntry, held []fleet.HeldKey) guardVerdict {
	set := heldSet(held)
	// Nothing held means nothing could ever prove this session keeps
	// access (and the post-write login probe would have nothing to offer):
	// refuse. Unreachable from the CLI, whose preflight requires a
	// non-empty held set, but phase 2 re-lists after the prompt.
	if len(set) == 0 {
		return guardVerdict{Refusal: "you hold no plain keys (identity files + agent; certificates do not count) — refusing to write (nothing could prove this session keeps access)"}
	}

	keys := make([]authkeys.Key, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, e.Key)
	}
	surviving := Survivors(keys, set)
	if len(surviving) == 0 {
		return guardVerdict{Refusal: lockoutRefusal(r.Server.Name, keys, held, set)}
	}
	if refusal := forwardRefusal(cfg, r.Server.Name, surviving); refusal != "" {
		return guardVerdict{Refusal: refusal}
	}

	var v guardVerdict
	if fp := r.SessionKeyFP; fp != "" && !fpInEntries(entries, fp) {
		if _, installed := r.Diff.Actual[fp]; installed && !r.IsExternal(fp) { // a kept line stays (spec S6)
			v.Note = fmt.Sprintf("removes the key this session logged in with; %s remains",
				survivorLabel(cfg, surviving[0]))
		}
	}
	restrictive := 0
	for _, k := range surviving {
		if hasRestrictiveOption(k.Options) {
			restrictive++
		}
	}
	if restrictive == len(surviving) {
		v.Warning = "every remaining key you hold carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked"
	}
	v.AgentOnly = agentOnlyWarning(surviving, held)
	return v
}

// lockoutRefusal explains a predicted lockout, listing every held key with
// its source so a mismatch (the wrong --identity, a stray agent) is
// visible at a glance.
func lockoutRefusal(server string, keys []authkeys.Key, held []fleet.HeldKey, set map[string]bool) string {
	// len(set), not len(held): one key can be held twice (an --identity
	// file the agent also holds), and the message counts distinct keys.
	held1 := fmt.Sprintf("none of the %d keys you hold (identity files + agent) would remain", len(set))
	if len(set) == 1 {
		held1 = "the 1 key you hold (identity files + agent) would not remain"
	}
	refusal := fmt.Sprintf(
		"%s in %s's authorized_keys — applying would lock this session out (held: %s). Add one of your keys to the manifest (or grant its user this server)",
		held1, server, heldList(held))
	for _, k := range keys {
		if set[k.Fingerprint] {
			refusal += " (a key you hold stays only as a cert-authority/principals= line, which accepts certificates, not the bare key)"
			break
		}
	}
	if slices.ContainsFunc(held, isFileKey) {
		refusal += "; rotating an --identity key? pass the new key with another --identity, so the guard and the post-write login probe can use it"
	}
	return refusal
}

// forwardRefusal is the bastion guard (spec S5): a managed server another
// server's via names must keep forwarding for a key this run holds, so some
// surviving key's line must allow a direct-tcpip channel to every
// dependent. "" when one does, or when nothing goes through the server. The
// post-write forward probe then checks the key that actually logs in (gap
// item 3).
func forwardRefusal(cfg *config.Config, server string, surviving []authkeys.Key) string {
	deps := cfg.Dependents(server)
	if len(deps) == 0 {
		return ""
	}
	for _, k := range surviving {
		if forwardsAll(k.Options, deps) {
			return ""
		}
	}
	more := ""
	if n := len(deps) - 1; n > 0 {
		more = fmt.Sprintf(" and %d more", n)
	}
	return fmt.Sprintf("none of the surviving keys you hold may forward through %s (no-port-forwarding, restrict or permitopen=); this write would cut off %s%s",
		server, deps[0].Name, more)
}

// forwardsAll reports whether a key line may forward to every dependent.
func forwardsAll(opts []string, deps []config.Server) bool {
	for _, d := range deps {
		if !authkeys.Forwards(opts, d.Host, d.Port) {
			return false
		}
	}
	return true
}

// probeForwardFor is where the bastion's post-write probe forwards: its
// first dependent, as the bastion will be asked for it; "" when nothing
// goes through the server.
func probeForwardFor(cfg *config.Config, server string) string {
	deps := cfg.Dependents(server)
	if len(deps) == 0 {
		return ""
	}
	return net.JoinHostPort(deps[0].Host, strconv.Itoa(deps[0].Port))
}

// agentOnlyWarning is set when --identity keys were given (some held key
// is a file) but every survivor here is an agent key: the guard passes on
// a credential the next run without this agent will not have.
func agentOnlyWarning(surviving []authkeys.Key, held []fleet.HeldKey) string {
	if !slices.ContainsFunc(held, isFileKey) {
		return ""
	}
	src := sourceMap(held)
	labels := make([]string, 0, len(surviving))
	for _, k := range surviving {
		if src[k.Fingerprint] != fleet.SourceAgent {
			return ""
		}
		labels = append(labels, k.Fingerprint+" ("+fleet.SourceAgent+")")
	}
	verb := "keeps"
	if len(labels) > 1 {
		verb = "keep"
	}
	return fmt.Sprintf("only %s %s access; none of your --identity keys survives — a run without this agent will be locked out",
		strings.Join(labels, ", "), verb)
}

// isFileKey reports whether k came from an --identity file.
func isFileKey(k fleet.HeldKey) bool { return k.Source != fleet.SourceAgent }

// heldSet indexes the held keys' fingerprints.
func heldSet(held []fleet.HeldKey) map[string]bool {
	set := make(map[string]bool, len(held))
	for _, k := range held {
		set[k.Fingerprint] = true
	}
	return set
}

// sourceMap maps each held fingerprint to its first source.
func sourceMap(held []fleet.HeldKey) map[string]string {
	src := make(map[string]string, len(held))
	for _, k := range held {
		if _, ok := src[k.Fingerprint]; !ok {
			src[k.Fingerprint] = k.Source
		}
	}
	return src
}

// heldList renders the held keys, distinct, in listing order:
// "SHA256:… (/path), SHA256:… (agent)".
func heldList(held []fleet.HeldKey) string {
	seen := make(map[string]bool, len(held))
	parts := make([]string, 0, len(held))
	for _, k := range held {
		if !seen[k.Fingerprint] {
			seen[k.Fingerprint] = true
			parts = append(parts, k.Label())
		}
	}
	return strings.Join(parts, ", ")
}

// Survivors returns the desired keys that keep a login this run can make:
// held (key file or agent), and on a line that accepts the bare key — cert-authority
// lines accept only certificates the key signed, and principals= belongs to
// them. These are the keys the guard counts and the post-write login probe
// offers.
func Survivors(desired []authkeys.Key, held map[string]bool) []authkeys.Key {
	var out []authkeys.Key
	for _, k := range desired {
		if held[k.Fingerprint] && !certOnly(k.Options) {
			out = append(out, k)
		}
	}
	return out
}

// certOnly reports whether options make the line a certificate-authority
// entry that does not log in with the bare key (see authkeys.CertOnly).
func certOnly(options []string) bool { return authkeys.CertOnly(options) }

func fpInEntries(entries []authkeys.RenderEntry, fp string) bool {
	for _, e := range entries {
		if e.Key.Fingerprint == fp {
			return true
		}
	}
	return false
}

// survivorLabel names the held key that keeps this session's access:
// the owning user, or the fingerprint for a key the manifest cannot name
// (unreachable in practice — surviving keys are desired, hence owned).
func survivorLabel(cfg *config.Config, k authkeys.Key) string {
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		return u.Name
	}
	return k.Fingerprint
}

// hasRestrictiveOption: options that can stop a future non-interactive
// SSHepherd login outright (see authkeys.BlocksLogin). Name kept: exec.go
// orders probe survivors with it.
func hasRestrictiveOption(options []string) bool { return authkeys.BlocksLogin(options) }

// ExitCode maps plans to the process exit code (monitoring-style, mirroring
// audit): 2 when any server needs a human now (needsHuman); 0 when every
// targeted server is converged — already, or applied and verified this run;
// 1 otherwise (pending under --dry-run or a declined prompt, refused,
// failed, unproven, unreachable). A jump_only server never changes the
// code. Tool errors (3) are the caller's domain.
func ExitCode(plans []ServerPlan) int {
	code := 0
	for _, p := range plans {
		switch {
		case needsHuman(p):
			return 2
		case p.Class == ClassConverged || p.Class == ClassJumpOnly || (p.Class == ClassChange && p.Outcome == OutcomeApplied):
		default:
			code = 1
		}
	}
	return code
}

// needsHuman is the D28 exit-2 rule for a written server: an unrestored
// lockout, authorized_keys or authorized_keys2 (D10), a rollback that put
// back a key on the revoked: list
// (D10a), or a login check stopped at a host-key alarm audit would page on
// (D10b).
func needsHuman(p ServerPlan) bool {
	if p.Class != ClassChange {
		return false
	}
	switch p.Outcome {
	case OutcomeLockoutUnrestored:
		return true
	case OutcomeFailed:
		return p.RolledBack && len(p.RevokedRemovals) > 0
	case OutcomeUnproven:
		// The server's own host-key alarm pages (D10b); a bastion's is exit
		// 1: it says nothing about this server (spec S5).
		return fleet.HostKeyAlert(fleet.ErrorKindOf(p.OutcomeErr)) && fleet.FailedHopOf(p.OutcomeErr) == ""
	}
	return false
}
