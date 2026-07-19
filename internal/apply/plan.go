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
	// content, predicted lockout).
	ClassRefused Class = "refused"
	// ClassUnreachable — the phase-1 read failed; nothing knowable.
	ClassUnreachable Class = "unreachable"
)

// Outcome is the phase-2 result for a ClassChange server.
type Outcome string

// The four phase-2 outcomes for a ClassChange server.
const (
	OutcomePending Outcome = "pending" // not written: dry-run, declined, or phase 2 not run
	OutcomeApplied Outcome = "applied" // written and byte-verified
	OutcomeRefused Outcome = "refused" // refused at the server (symlinked target)
	OutcomeFailed  Outcome = "failed"  // write or verify failed
)

// RewriteRow is a matched key whose on-server form differs from the render.
type RewriteRow struct {
	Key            authkeys.Key // desired (manifest) form
	ActualComment  string
	DesiredComment string
	CommentDiffers bool
	OptionsDiffer  bool
}

// Normalize captures byte drift the per-key rows don't explain.
type Normalize struct {
	Reorder     bool // matched keys ordered differently than desired
	NonKeyLines int  // current comment/blank lines (managed header excluded) the rewrite removes
	Whitespace  bool // residual byte drift with nothing else to blame
}

// Any reports whether a normalize row should render.
func (n Normalize) Any() bool { return n.Reorder || n.NonKeyLines > 0 || n.Whitespace }

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

	Note       string // guard note: session key removed, another survives
	Warning    string // restrictive-options warning
	FileAbsent bool   // phase-1 diagnostic, carried into the report

	Outcome    Outcome
	OutcomeErr error
}

// Build computes the plan for every phase-1 result. agentFPs is the set of
// SHA256 fingerprints the operator's agent held at preflight — the
// self-lockout guard's ground truth. Pure; the only possible error is a
// render failure, impossible for a validated manifest (a tool bug, exit 3).
func Build(cfg *config.Config, results []audit.ServerResult, agentFPs []string) ([]ServerPlan, error) {
	plans := make([]ServerPlan, 0, len(results))
	for _, r := range results {
		p, err := planOne(cfg, r, agentFPs)
		if err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, nil
}

func planOne(cfg *config.Config, r audit.ServerResult, agentFPs []string) (ServerPlan, error) {
	p := ServerPlan{Server: r.Server, Outcome: OutcomePending, FileAbsent: r.FileAbsent}
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
		p.Refusal = fmt.Sprintf("%d keys installed but manifest grants none — refusing to wipe",
			len(r.Diff.Unauthorized))
		if n := len(r.ParseErrs); n > 0 {
			p.Refusal = fmt.Sprintf(
				"%d keys and %d unparseable lines installed but manifest grants none — refusing to wipe",
				len(r.Diff.Unauthorized), n)
		}
		return p, nil
	}

	// Unparseable lines: a full-file render would destroy content we could
	// not account for. Remediation: fix the line remotely or correct
	// authorized_keys_file.
	if n := len(r.ParseErrs); n > 0 {
		p.Class = ClassRefused
		p.Refusal = fmt.Sprintf(
			"%d unparseable line(s) — refusing to rewrite a file that could not be fully read (fix the line(s) or correct authorized_keys_file)", n)
		return p, nil
	}

	rendered, err := authkeys.Render(entries)
	if err != nil {
		return p, fmt.Errorf("render %s: %w", r.Server.Name, err)
	}
	p.Rendered = rendered

	// Byte-exact convergence: a server needs a write iff its current bytes
	// differ from the render. (A file-absent server with desired keys is
	// never converged — the file itself is missing.)
	if !r.FileAbsent && bytes.Equal(r.Content, rendered) {
		p.Class = ClassConverged
		return p, nil
	}

	p.Add = r.Diff.Missing
	p.Remove = r.Diff.Unauthorized
	p.Rewrites = rewriteRows(r, entries)
	explained := len(p.Add)+len(p.Remove)+len(p.Rewrites) > 0
	p.Normalize = normalize(r, entries, explained)

	v := guardCheck(cfg, r, entries, agentFPs)
	if v.Refusal != "" {
		p.Class = ClassRefused
		p.Refusal = v.Refusal
		return p, nil
	}
	p.Note, p.Warning = v.Note, v.Warning
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
			CommentDiffers: actual.Comment != e.Comment,
			OptionsDiffer:  !slices.Equal(actual.Options, e.Key.Options),
		}
		if row.CommentDiffers || row.OptionsDiffer {
			rows = append(rows, row)
		}
	}
	return rows
}

// normalize explains byte drift beyond the per-key rows: non-key lines the
// full-file render removes, reordering of matched keys, or (when nothing
// else accounts for the byte difference) residual whitespace/format drift.
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

	if !explained && !n.Reorder && n.NonKeyLines == 0 {
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
	Refusal string
	Note    string
	Warning string
}

// guardCheck enforces the invariant "after the write, this operator can
// still log in": the rendered desired set must intersect the agent-held
// keys. Deliberately not the operator spec's literal "never remove the
// session key" — which key signs a handshake is an accident of agent order
// and server choice, and the literal rule would randomly block rotate (see
// the 2026-07-19 spec's guard section; owner-approved refinement). Removing
// the very key that authenticated is allowed when another agent-held key
// survives — that is what rotate is — with a loud per-server note.
func guardCheck(cfg *config.Config, r audit.ServerResult, entries []authkeys.RenderEntry, agentFPs []string) guardVerdict {
	held := make(map[string]bool, len(agentFPs))
	for _, fp := range agentFPs {
		held[fp] = true
	}
	// Defensive fallback: no usable agent listing (agent died mid-run) —
	// purely additive writes may proceed, anything that removes a key is
	// refused.
	if len(held) == 0 {
		if len(r.Diff.Unauthorized) > 0 {
			return guardVerdict{Refusal: "agent key listing is unavailable — refusing a write that removes keys"}
		}
		return guardVerdict{}
	}

	var surviving []authkeys.Key
	restrictive := 0
	for _, e := range entries {
		if !held[e.Key.Fingerprint] {
			continue
		}
		surviving = append(surviving, e.Key)
		if hasRestrictiveOption(e.Key.Options) {
			restrictive++
		}
	}
	if len(surviving) == 0 {
		return guardVerdict{Refusal: fmt.Sprintf(
			"none of the %d keys in this agent would remain in %s's authorized_keys — applying would lock this session out. Add one of your keys to the manifest (or mark its user operator: true)",
			len(agentFPs), r.Server.Name)}
	}

	var v guardVerdict
	if fp := r.SessionKeyFP; fp != "" && !fpInEntries(entries, fp) {
		if _, installed := r.Diff.Actual[fp]; installed {
			v.Note = fmt.Sprintf("removes the key this session logged in with; %s remains",
				survivorLabel(cfg, surviving[0]))
		}
	}
	if restrictive == len(surviving) {
		v.Warning = "every remaining agent-held key carries a restrictive option (from=/command=/restrict/expiry-time=) — future sshepherd logins may be functionally blocked"
	}
	return v
}

func fpInEntries(entries []authkeys.RenderEntry, fp string) bool {
	for _, e := range entries {
		if e.Key.Fingerprint == fp {
			return true
		}
	}
	return false
}

// survivorLabel names the agent-held key that keeps this session's access:
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
