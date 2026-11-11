// Package adopt turns audit results into manifest additions: unknown keys
// found on the fleet become new users with access to exactly the servers
// where they were found (never a wildcard); keys of known users found beyond their grants become access
// extensions. Pure logic — no I/O; the cmd layer owns SSH and rendering.
package adopt

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/naming"
)

// NewUser is one unknown key adopted into a generated user.
type NewUser struct {
	Name        string
	Line        string   // authorized_keys line as found (minus an unsafe comment); first line sshd honors wins
	Fingerprint string   // the key's SHA256 fingerprint
	Type        string   // the key's algorithm, e.g. "ssh-ed25519"
	FoundOn     []string // sorted names of servers where the key was found
}

// Extension grants an existing user the servers their key was found on
// beyond the manifest's current grants.
type Extension struct {
	User    string
	Servers []string // sorted
}

// Issue is a server whose keys could not be (fully) read, or that holds a
// key whose every line sshd ignores, or an unknown key whose line the
// manifest cannot hold; the cmd layer enforces the strict/--partial gate
// on these. Detail can embed
// remote-influenced text, but the sshread and authkeys layers control-strip
// it at the source, so it is safe to print. Hint is the failure's operator
// remediation (audit.CleanHint: one sanitized line, empty when there is
// none); it is never part of Detail, so the cmd layer can print each
// distinct hint once instead of once per server.
type Issue struct {
	Server string
	Detail string
	Hint   string
	// Kind classifies a transport failure; "" for a line-level issue on a
	// server that was read.
	Kind fleet.ErrorKind
}

// The Warning kinds adopt assigns. Consumers ignore kinds they do not know.
const (
	WarnRevokedKeySkipped    = "revoked_key_skipped"
	WarnRevokedAccessSkipped = "revoked_access_skipped"
	WarnExceptSkipped        = "except_skipped"
	WarnKeyDiffers           = "key_differs"
	WarnCommentDropped       = "comment_dropped"
	WarnWeakKeySkipped       = "weak_key_skipped"
)

// Warning is one finding for the operator. Message is the stderr text; the
// other fields are the structured form --json carries, omitted when they do
// not apply. User is the tombstone's label on a revoked key and the owner
// otherwise.
type Warning struct {
	Kind        string `json:"kind"`
	Server      string `json:"server,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	User        string `json:"user,omitempty"`
	Date        string `json:"date,omitempty"`
	Message     string `json:"message"`
}

// Plan is everything adopt would add to the manifest, plus warnings for the
// operator and issues for the strict gate.
type Plan struct {
	NewUsers   []NewUser
	Extensions []Extension
	Warnings   []Warning
	Issues     []Issue
}

// pending accumulates one unknown key during the sweep.
type pending struct {
	line    string
	comment string
	keyType string
	foundOn []string
}

// Build attributes every unauthorized key in results: keys owned by a
// manifest user extend that user's access; unknown keys become new users.
// results must be sorted by server name (audit.Run guarantees this) and keys
// are processed in file order, so the output is deterministic.
func Build(cfg *config.Config, results []audit.ServerResult) Plan {
	var p Plan
	byFP := make(map[string]*pending)
	var order []string // fingerprints in discovery order
	extByUser := make(map[string]map[string]bool)
	for _, r := range results {
		if r.Err != nil {
			p.Issues = append(p.Issues, Issue{Server: r.Server.Name, Detail: r.Err.Error(), Hint: audit.CleanHint(r.Err), Kind: fleet.ErrorKindOf(r.Err)})
			continue
		}
		for _, pe := range r.ParseErrs {
			p.Issues = append(p.Issues, Issue{Server: r.Server.Name, Detail: pe.Error()})
		}
		lines := linesByFingerprint(r.Content)
		for _, first := range r.Diff.Unauthorized {
			// Revocation memory first (D2a): a tombstoned key is never
			// adopted — not even as an Issue that would move adopt's exit
			// code — whatever its lines look like. A weak key likewise: a
			// warning, and it is neither adopted nor granted to more servers.
			if w, skip := skipKey(cfg, r.Server.Name, first); skip {
				p.Warnings = append(p.Warnings, w)
				continue
			}
			// sshd skips a line with an unknown option, a bad value or a
			// repeated once-only clause and keeps scanning, so the key logs
			// in through its first line sshd honors. When there is none the
			// key never logged in here: report it like an unparseable line so
			// the strict gate / --partial decide. err quotes the option with
			// %q, so remote control bytes are escaped.
			k, err := honoredLine(first, lines[first.Fingerprint])
			if err != nil {
				p.Issues = append(p.Issues, Issue{Server: r.Server.Name,
					Detail: fmt.Sprintf("key %s: %v", first.Fingerprint, err)})
				continue
			}
			if owner, known := cfg.OwnerOf(k.Fingerprint); known {
				if w, skip := ownerSkip(cfg, owner.Name, r.Server.Name, k.Fingerprint); skip {
					p.Warnings = append(p.Warnings, w)
					continue
				}
				if extByUser[owner.Name] == nil {
					extByUser[owner.Name] = make(map[string]bool)
				}
				extByUser[owner.Name][r.Server.Name] = true
				continue
			}
			if pd, seen := byFP[k.Fingerprint]; seen {
				if pd.line != k.Raw && pd.line != stripComment(k) {
					p.Warnings = append(p.Warnings, Warning{Kind: WarnKeyDiffers, Server: r.Server.Name, Fingerprint: k.Fingerprint,
						Message: fmt.Sprintf("key %s on %s differs from the copy first seen on %s (options/comment); keeping the first",
							k.Fingerprint, r.Server.Name, pd.foundOn[0])})
				}
				pd.foundOn = append(pd.foundOn, r.Server.Name)
				continue
			}
			line, dropped, err := manifestLine(k)
			if err != nil {
				p.Issues = append(p.Issues, Issue{Server: r.Server.Name,
					Detail: fmt.Sprintf("key %s: this line logs in, but the manifest cannot hold it: %v — not adopted", k.Fingerprint, err)})
				continue
			}
			byFP[k.Fingerprint] = &pending{line: line, comment: k.Comment, keyType: k.Type, foundOn: []string{r.Server.Name}}
			order = append(order, k.Fingerprint)
			if dropped != "" {
				p.Warnings = append(p.Warnings, Warning{Kind: WarnCommentDropped, Server: r.Server.Name, Fingerprint: k.Fingerprint,
					Message: fmt.Sprintf("key %s on %s: comment %s — adopted without its comment",
						k.Fingerprint, r.Server.Name, dropped)})
			}
		}
	}
	p.Extensions = extensions(cfg, extByUser)
	p.NewUsers = nameUsers(cfg, byFP, order)
	return p
}

// skipKey reports a key adopt never takes: one the manifest's revoked: list
// remembers (first, so a key that is both warns only as REVOKED), or a weak
// one (emitting it would produce a manifest with a policy conflict).
func skipKey(cfg *config.Config, server string, k authkeys.Key) (Warning, bool) {
	if w, revoked := revokedWarning(cfg, server, k.Fingerprint); revoked {
		return w, true
	}
	if k.Weak != "" {
		return Warning{Kind: WarnWeakKeySkipped, Server: server, Fingerprint: k.Fingerprint,
			Message: fmt.Sprintf("key %s on %s: %s key not adopted", k.Fingerprint, server, k.Weak)}, true
	}
	return Warning{}, false
}

// revokedWarning reports a key the manifest's revoked: list remembers.
func revokedWarning(cfg *config.Config, server, fp string) (Warning, bool) {
	t, ok := cfg.Revoked(fp)
	if !ok {
		return Warning{}, false
	}
	return Warning{Kind: WarnRevokedKeySkipped, Server: server, Fingerprint: fp, User: t.User, Date: t.Date,
		Message: fmt.Sprintf("key %s on %s is REVOKED (%s) — not adopted; run 'sshepherd apply --server %s' to remove it",
			fp, server, t.Label(), server)}, true
}

// ownerSkip reports why a known owner's key found on server is not an
// access extension: their except: list excludes the server, or an access
// tombstone removed it (D1a). Either way audit flags the key as drift.
func ownerSkip(cfg *config.Config, owner, server, fp string) (Warning, bool) {
	if cfg.ExceptCarveOut(owner, server) {
		return Warning{Kind: WarnExceptSkipped, Server: server, Fingerprint: fp, User: owner,
			Message: fmt.Sprintf("key %s of %q found on %q, which their except: list deliberately excludes — not re-granted; audit flags this drift",
				fp, owner, server)}, true
	}
	if t, ok := cfg.AccessRevoked(owner, server); ok {
		return Warning{Kind: WarnRevokedAccessSkipped, Server: server, Fingerprint: fp, User: owner, Date: t.Date,
			Message: fmt.Sprintf("key %s of %q found on %q, whose access was revoked (%s) — not re-granted; audit flags this drift",
				fp, owner, server, t.Date)}, true
	}
	return Warning{}, false
}

// linesByFingerprint indexes every parsed line of a server's file by
// fingerprint, in file order. audit's Diff keeps only the first line per
// fingerprint; sshd reads them all.
func linesByFingerprint(content []byte) map[string][]authkeys.Key {
	keys, _ := authkeys.ParseFile(content) // parse errors are already Issues (r.ParseErrs)
	return authkeys.LinesByFingerprint(keys)
}

// honoredLine returns the first of a key's lines that sshd honors (sshd
// skips a line whose options it cannot read and keeps scanning, so a bad
// copy before a good one does not cost the key its access). first is the
// key's first line (audit's Diff entry); lines are all of them. The error
// describes the ignored lines when sshd honors none.
func honoredLine(first authkeys.Key, lines []authkeys.Key) (authkeys.Key, error) {
	if len(lines) == 0 {
		lines = []authkeys.Key{first}
	}
	for _, l := range lines {
		if authkeys.IgnoredBySSHD(l.Options) == nil {
			return l, nil
		}
	}
	err := authkeys.IgnoredBySSHD(lines[0].Options)
	if len(lines) == 1 {
		return first, fmt.Errorf("sshd ignores this line: %w", err)
	}
	return first, fmt.Errorf("sshd ignores each of its %d lines; the first: %w", len(lines), err)
}

// extensions turns the per-user found-on sets into Extensions, in manifest
// user order (deterministic output) with each server list sorted.
func extensions(cfg *config.Config, extByUser map[string]map[string]bool) []Extension {
	var out []Extension
	for _, u := range cfg.Users {
		srvSet := extByUser[u.Name]
		if len(srvSet) == 0 {
			continue
		}
		srvs := make([]string, 0, len(srvSet))
		for s := range srvSet {
			srvs = append(srvs, s)
		}
		sort.Strings(srvs)
		out = append(out, Extension{User: u.Name, Servers: srvs})
	}
	return out
}

// manifestLine is the manifest line adopt writes for a line that logs in:
// the line as found, or without its comment when the manifest refuses the
// comment (dropped says why). The key is what grants access. err is set
// when the manifest cannot hold the line at all: option bytes it would
// render verbatim (control or format runes, invalid UTF-8, which sshd
// accepts inside quotes), or bytes a reviewer of the generated manifest
// cannot see (a tail after a NUL, whitespace inside the key field: review
// F002, F008). Adopting either would fail adopt's self-check or hide what it
// grants.
func manifestLine(k authkeys.Key) (line, dropped string, err error) {
	if err := authkeys.OptionIssue(k.Options); err != nil {
		return "", "", fmt.Errorf("%w", err)
	}
	line = k.Raw
	if dropped = authkeys.RenderTextIssue(k.Comment); dropped != "" {
		line = stripComment(k)
	}
	if issue := authkeys.LineTextIssue(line); issue != "" {
		return "", "", fmt.Errorf("the line %s", issue)
	}
	return line, dropped, nil
}

// stripComment returns k's line without its trailing comment: options (as
// written) plus key type and material. Raw is whitespace-trimmed and the
// parser takes the comment as the trimmed remainder after the key field, so
// the comment is Raw's suffix, unless Raw holds a tail sshd does not read
// (after a NUL); then Raw comes back whole and manifestLine refuses it.
func stripComment(k authkeys.Key) string {
	if k.Comment == "" {
		return k.Raw
	}
	return strings.TrimRightFunc(strings.TrimSuffix(k.Raw, k.Comment), unicode.IsSpace)
}

// UnreadableServers lists the distinct servers with issues, in result order.
func (p Plan) UnreadableServers() []string {
	var names []string
	seen := make(map[string]bool)
	for _, is := range p.Issues {
		if !seen[is.Server] {
			seen[is.Server] = true
			names = append(names, is.Server)
		}
	}
	return names
}

// nameUsers turns accumulated unknown keys into named users, resolving
// collisions against manifest names and each other with numeric suffixes
// (the allocator import uses too, see internal/naming). Each user is
// granted exactly the servers its key was found on, by name: never "*",
// which would also grant servers added later (D5).
func nameUsers(cfg *config.Config, byFP map[string]*pending, order []string) []NewUser {
	taken := make(map[string]bool, len(cfg.Users))
	for _, u := range cfg.Users {
		taken[u.Name] = true
	}
	// A name kept only by an access tombstone is not free either: the new
	// grant would be a policy conflict, refused at save with a hint the
	// operator cannot follow.
	for _, t := range cfg.Tombstones {
		if !t.IsKey() {
			taken[t.User] = true
		}
	}
	users := make([]NewUser, 0, len(order))
	for _, fp := range order {
		pd := byFP[fp]
		var name string
		if base := sanitizeName(pd.comment); base != "" {
			name, _ = naming.Claim(taken, base)
		} else {
			// Continue numbering past earlier runs' adopted-key-<n>
			// (adopt --merge) instead of restarting at 1 and stacking a
			// suffix onto it.
			name = naming.ClaimNumbered(taken, "adopted-key-")
		}
		sort.Strings(pd.foundOn)
		users = append(users, NewUser{Name: name, Line: pd.line, Fingerprint: fp, Type: pd.keyType, FoundOn: pd.foundOn})
	}
	return users
}

// maxNameLen caps generated user names: a key comment is attacker-supplied
// remote content and must not balloon into an unbounded manifest name.
const maxNameLen = 64

// sanitizeName derives a manifest user name from a key comment: lowercase,
// every run of characters outside [a-z0-9] collapses to a single '-',
// leading and trailing '-' trimmed, capped at maxNameLen characters.
// Returns "" when nothing usable remains — the caller falls back to a
// numbered name.
func sanitizeName(comment string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(comment) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			if pendingDash && b.Len() > 0 {
				b.WriteByte('-')
			}
			pendingDash = false
			b.WriteRune(r)
		default:
			pendingDash = true
		}
	}
	name := b.String()
	if len(name) > maxNameLen {
		// Output is pure ASCII, so byte slicing is rune-safe; a dash at
		// the cut would leave an invalid trailing '-'.
		name = strings.TrimRight(name[:maxNameLen], "-")
	}
	return name
}
