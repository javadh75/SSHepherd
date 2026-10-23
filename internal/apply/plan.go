// Package apply computes the write plan for `sshepherd apply`: pure
// classification of each server against the manifest's rendered desired
// state, the self-lockout guard, phase-2 orchestration behind a writer
// seam, and the plan/outcome report. Nothing here touches the network.
package apply

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
)

// Class classifies one server's plan.
type Class string

const (
	// ClassConverged — current bytes equal the render, or the desired set is
	// empty with nothing installed ("nothing should be there and nothing is").
	ClassConverged Class = "converged"
	// ClassChange — a write is needed and allowed.
	ClassChange Class = "change"
	// ClassRefused — a write would occur but must not (wipe, unparseable
	// content, predicted lockout, a render too large to verify).
	ClassRefused Class = "refused"
	// ClassUnreachable — the phase-1 read failed; nothing knowable.
	ClassUnreachable Class = "unreachable"
)

// Outcome is the phase-2 result for a ClassChange server.
type Outcome string

// The four phase-2 outcomes for a ClassChange server.
const (
	OutcomePending Outcome = "pending" // not written: dry-run, declined, phase 2 not run, or interrupted before the write (OutcomeErr set)
	OutcomeApplied Outcome = "applied" // written, byte-verified, and the surviving keys proved they can log in
	OutcomeRefused Outcome = "refused" // refused at the server before any change (symlink, unsafe path, changed since plan, locked)
	OutcomeFailed  Outcome = "failed"  // write, verify or login probe failed (a failed probe restores the previous file)
)

// RewriteRow is a matched key whose on-server form differs from the render.
type RewriteRow struct {
	Key            authkeys.Key // desired (manifest) form; Key.Options are the options written
	ActualComment  string
	DesiredComment string
	ActualOptions  []string // on-server options, replaced by Key.Options
	CommentDiffers bool
	OptionsDiffer  bool
	// Loosens lists restrictive on-server options (from=, command=,
	// restrict, no-*, expiry-time=, permitopen=, permitlisten=,
	// cert-authority, principals=) the rewrite drops — the key gains access
	// it does not have today.
	Loosens []string
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
	AgentOnly  string
	FileAbsent bool // phase-1 diagnostic, carried into the report
	// AuthorizedKeys2 carries the phase-1 finding that an unmanaged,
	// non-empty ~/.ssh/authorized_keys2 exists: sshd may accept keys from it
	// whatever apply writes, so a change plan also disables it (see
	// DisableKeys2).
	AuthorizedKeys2 bool
	// Expect is the phase-1 snapshot the write is conditional on: phase 2
	// refuses a file that changed after this plan was shown.
	Expect sshwrite.Snapshot

	Outcome    Outcome
	OutcomeErr error
}

// DisableKeys2 reports whether the write moves a non-empty
// ~/.ssh/authorized_keys2 aside: every change plan does when phase 1 found
// one (only probed while the managed path is the default), because sshd
// keeps accepting its keys — a revoked key there would survive the revoke.
func (p ServerPlan) DisableKeys2() bool {
	return p.Class == ClassChange && p.AuthorizedKeys2
}

// Build computes the plan for every phase-1 result. held is what the run
// could authenticate with at preflight (sshconn.Credentials.Held: key files
// and plain agent keys, with their sources) — the self-lockout guard's
// ground truth. Pure; the only possible error is a render failure,
// impossible for a validated manifest (a tool bug, exit 3).
func Build(cfg *config.Config, results []audit.ServerResult, held []sshconn.HeldKey) ([]ServerPlan, error) {
	plans := make([]ServerPlan, 0, len(results))
	for _, r := range results {
		p, err := planOne(cfg, r, held)
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
var maxRender = sshconn.MaxRemoteOutput

// theLines words the unparseable-line refusal's fix ("the line" / "the
// lines"); a helper so planOne stays under the gocyclo cap.
func theLines(n int) string {
	if n == 1 {
		return "the line"
	}
	return "the lines"
}

func planOne(cfg *config.Config, r audit.ServerResult, held []sshconn.HeldKey) (ServerPlan, error) {
	p := ServerPlan{
		Server: r.Server, Outcome: OutcomePending, FileAbsent: r.FileAbsent,
		AuthorizedKeys2: r.AuthorizedKeys2,
		Expect:          sshwrite.SnapshotOf(r.FileAbsent, r.Content),
	}
	if r.Err != nil {
		p.Class = ClassUnreachable
		p.Err = r.Err
		return p, nil //nolint:nilerr // an unreachable server is a plan class, not a Build failure
	}

	entries := desiredEntries(cfg, r.Server.Name)
	for _, e := range entries {
		p.Desired = append(p.Desired, e.Key)
	}

	// Empty desired set: apply never wipes a server, so nothing is ever
	// written here — converged when nothing (parseable or not) is
	// installed, refused otherwise.
	if len(entries) == 0 {
		if len(r.Diff.Unauthorized) == 0 && len(r.ParseErrs) == 0 {
			p.Class = ClassConverged
			return p, nil
		}
		p.Class = ClassRefused
		p.Refusal = fmt.Sprintf("%s installed but manifest grants none — refusing to wipe",
			Plural(len(r.Diff.Unauthorized), "key", "keys"))
		if n := len(r.ParseErrs); n > 0 {
			p.Refusal = fmt.Sprintf(
				"%s and %s installed but manifest grants none — refusing to wipe",
				Plural(len(r.Diff.Unauthorized), "key", "keys"), Plural(n, "unparseable line", "unparseable lines"))
		}
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

	rendered, err := authkeys.Render(entries)
	if err != nil {
		return p, fmt.Errorf("render %s: %w", r.Server.Name, err)
	}
	p.Rendered = rendered
	if len(rendered) > maxRender {
		p.Class = ClassRefused
		p.Refusal = fmt.Sprintf(
			"rendered file is %d bytes, over the %d-byte limit the read path accepts — refusing to write a file that could never be verified or audited (split the grant across accounts)",
			len(rendered), maxRender)
		return p, nil
	}

	// Byte-exact convergence: a server needs a write iff its current bytes
	// differ from the render, or a non-empty authorized_keys2 must be
	// disabled. (A file-absent server with desired keys is never converged
	// — the file itself is missing.)
	same := !r.FileAbsent && bytes.Equal(r.Content, rendered)
	if same && !r.AuthorizedKeys2 {
		p.Class = ClassConverged
		return p, nil
	}

	if !same {
		p.Add = r.Diff.Missing
		p.Remove = r.Diff.Unauthorized
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
	p.Class = ClassChange
	return p, nil
}

// desiredEntries builds the render input for one server: DesiredFor order
// (operators first), comments resolved through config.DesiredComment — the
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
			row.Loosens = droppedRestrictions(actual.Options, e.Key.Options)
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
// residual whitespace/format drift.
// Only called for servers whose bytes differ from the render.
func normalize(r audit.ServerResult, entries []authkeys.RenderEntry, explained bool) Normalize {
	var n Normalize
	lines := strings.Split(string(r.Content), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1] // a well-formed file's trailing newline, not a blank line
	}
	for _, line := range lines {
		t := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if t == authkeys.ManagedHeader {
			continue // re-emitted by the render, not removed
		}
		if t == "" || strings.HasPrefix(t, "#") {
			n.NonKeyLines++
		}
	}

	n.Reorder = matchedOrderDiffers(r, entries)

	// Duplicates: Diff collapses them first-wins, but each is a whole key
	// line (possibly with its own options) the rewrite deletes — a semantic
	// change the plan must name, never "whitespace". Content re-parses
	// cleanly here (parse errors were refused earlier).
	keys, _ := authkeys.ParseFile(r.Content)
	first := make(map[string]authkeys.Key, len(keys))
	for _, k := range keys {
		f, seen := first[k.Fingerprint]
		if !seen {
			first[k.Fingerprint] = k
			continue
		}
		n.Duplicates++
		if !slices.Equal(f.Options, k.Options) {
			n.DuplicateOptionsDiffer = true
		}
	}

	if !explained && !n.Reorder && n.NonKeyLines == 0 && n.Duplicates == 0 {
		n.Whitespace = true
	}
	return n
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
func guardCheck(cfg *config.Config, r audit.ServerResult, entries []authkeys.RenderEntry, held []sshconn.HeldKey) guardVerdict {
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

	var v guardVerdict
	if fp := r.SessionKeyFP; fp != "" && !fpInEntries(entries, fp) {
		if _, installed := r.Diff.Actual[fp]; installed {
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
func lockoutRefusal(server string, keys []authkeys.Key, held []sshconn.HeldKey, set map[string]bool) string {
	// len(set), not len(held): one key can be held twice (an --identity
	// file the agent also holds), and the message counts distinct keys.
	held1 := fmt.Sprintf("none of the %d keys you hold (identity files + agent) would remain", len(set))
	if len(set) == 1 {
		held1 = "the 1 key you hold (identity files + agent) would not remain"
	}
	refusal := fmt.Sprintf(
		"%s in %s's authorized_keys — applying would lock this session out (held: %s). Add one of your keys to the manifest (or mark its user operator: true)",
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

// agentOnlyWarning is set when --identity keys were given (some held key
// is a file) but every survivor here is an agent key: the guard passes on
// a credential the next run without this agent will not have.
func agentOnlyWarning(surviving []authkeys.Key, held []sshconn.HeldKey) string {
	if !slices.ContainsFunc(held, isFileKey) {
		return ""
	}
	src := sourceMap(held)
	labels := make([]string, 0, len(surviving))
	for _, k := range surviving {
		if src[k.Fingerprint] != sshconn.SourceAgent {
			return ""
		}
		labels = append(labels, k.Fingerprint+" ("+sshconn.SourceAgent+")")
	}
	verb := "keeps"
	if len(labels) > 1 {
		verb = "keep"
	}
	return fmt.Sprintf("only %s %s access; none of your --identity keys survives — a run without this agent will be locked out",
		strings.Join(labels, ", "), verb)
}

// isFileKey reports whether k came from an --identity file.
func isFileKey(k sshconn.HeldKey) bool { return k.Source != sshconn.SourceAgent }

// heldSet indexes the held keys' fingerprints.
func heldSet(held []sshconn.HeldKey) map[string]bool {
	set := make(map[string]bool, len(held))
	for _, k := range held {
		set[k.Fingerprint] = true
	}
	return set
}

// sourceMap maps each held fingerprint to its first source.
func sourceMap(held []sshconn.HeldKey) map[string]string {
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
func heldList(held []sshconn.HeldKey) string {
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
// entry that does not log in with the bare key.
func certOnly(options []string) bool {
	for _, o := range options {
		lo := strings.ToLower(o)
		if lo == "cert-authority" || strings.HasPrefix(lo, "principals=") {
			return true
		}
	}
	return false
}

// droppedRestrictions lists the restrictive options in actual that desired
// does not carry verbatim (a changed from= value counts as dropped: the old
// restriction no longer applies).
func droppedRestrictions(actual, desired []string) []string {
	var out []string
	for _, o := range actual {
		if isRestriction(o) && !slices.Contains(desired, o) {
			out = append(out, o)
		}
	}
	return out
}

// isRestriction reports whether an authorized_keys option narrows what the
// key may do: removing it widens access.
func isRestriction(o string) bool {
	lo := strings.ToLower(o)
	if lo == "restrict" || lo == "cert-authority" || strings.HasPrefix(lo, "no-") {
		return true
	}
	for _, prefix := range []string{"from=", "command=", "expiry-time=", "permitopen=", "permitlisten=", "principals="} {
		if strings.HasPrefix(lo, prefix) {
			return true
		}
	}
	return false
}

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

// restrictive authorized_keys options can limit whether a future
// non-interactive SSHepherd login works at all: from= (source filter),
// command= (no shell), restrict (everything off), expiry-time=.
func hasRestrictiveOption(options []string) bool {
	for _, o := range options {
		lo := strings.ToLower(o)
		if lo == "restrict" || strings.HasPrefix(lo, "from=") ||
			strings.HasPrefix(lo, "command=") || strings.HasPrefix(lo, "expiry-time=") {
			return true
		}
	}
	return false
}

// ExitCode maps plans to the process exit code (monitoring-style, mirroring
// audit): 0 when every targeted server is converged — already, or applied
// and verified this run; 1 otherwise (pending under --dry-run or a declined
// prompt, refused, failed, unreachable). Tool errors (3) are the caller's
// domain; 2 stays reserved (audit's critical drift; apply has no
// equivalent class yet).
func ExitCode(plans []ServerPlan) int {
	for _, p := range plans {
		if p.Class == ClassConverged || (p.Class == ClassChange && p.Outcome == OutcomeApplied) {
			continue
		}
		return 1
	}
	return 0
}
