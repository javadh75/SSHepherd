// Package adopt turns audit results into manifest additions: unknown keys
// found on the fleet become new users with access to the servers where they
// were found; keys of known users found beyond their grants become access
// extensions. Pure logic — no I/O; the cmd layer owns SSH and rendering.
package adopt

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
)

// NewUser is one unknown key adopted into a generated user.
type NewUser struct {
	Name     string
	Line     string   // raw authorized_keys line; first occurrence wins
	FoundOn  []string // sorted names of servers where the key was found
	Wildcard bool     // grant renders as ["*"]: the key covers the whole fleet
}

// Extension grants an existing user the servers their key was found on
// beyond the manifest's current grants.
type Extension struct {
	User    string
	Servers []string // sorted
}

// Issue is a server whose keys could not be (fully) read; the cmd layer
// enforces the strict/--partial gate on these. Detail can embed
// remote-influenced text, but the sshread and authkeys layers control-strip
// it at the source, so it is safe to print.
type Issue struct {
	Server string
	Detail string
}

// Plan is everything adopt would add to the manifest, plus warnings for the
// operator and issues for the strict gate.
type Plan struct {
	NewUsers   []NewUser
	Extensions []Extension
	Warnings   []string
	Issues     []Issue
}

// pending accumulates one unknown key during the sweep.
type pending struct {
	line    string
	comment string
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
			p.Issues = append(p.Issues, Issue{Server: r.Server.Name, Detail: r.Err.Error()})
			continue
		}
		for _, pe := range r.ParseErrs {
			p.Issues = append(p.Issues, Issue{Server: r.Server.Name, Detail: pe.Error()})
		}
		for _, k := range r.Diff.Unauthorized {
			if owner, known := cfg.OwnerOf(k.Fingerprint); known {
				if hasExceptCarveOut(cfg, owner.Name, r.Server.Name) {
					p.Warnings = append(p.Warnings, fmt.Sprintf(
						"key %s of %q found on %q, which their except: list deliberately excludes — not re-granted; audit flags this drift",
						k.Fingerprint, owner.Name, r.Server.Name))
					continue
				}
				if extByUser[owner.Name] == nil {
					extByUser[owner.Name] = make(map[string]bool)
				}
				extByUser[owner.Name][r.Server.Name] = true
				continue
			}
			if pd, seen := byFP[k.Fingerprint]; seen {
				if pd.line != k.Raw {
					p.Warnings = append(p.Warnings, fmt.Sprintf(
						"key %s on %s differs from the copy first seen on %s (options/comment); keeping the first",
						k.Fingerprint, r.Server.Name, pd.foundOn[0]))
				}
				pd.foundOn = append(pd.foundOn, r.Server.Name)
				continue
			}
			byFP[k.Fingerprint] = &pending{line: k.Raw, comment: k.Comment, foundOn: []string{r.Server.Name}}
			order = append(order, k.Fingerprint)
		}
	}
	for _, u := range cfg.Users { // manifest order keeps output deterministic
		srvSet := extByUser[u.Name]
		if len(srvSet) == 0 {
			continue
		}
		srvs := make([]string, 0, len(srvSet))
		for s := range srvSet {
			srvs = append(srvs, s)
		}
		sort.Strings(srvs)
		p.Extensions = append(p.Extensions, Extension{User: u.Name, Servers: srvs})
	}
	var nameWarnings []string
	p.NewUsers, nameWarnings = nameUsers(cfg, byFP, order)
	p.Warnings = append(p.Warnings, nameWarnings...)
	return p
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

// hasExceptCarveOut reports whether user's access deliberately excludes
// server via a wildcard except: list. Such a server is never re-granted by
// adopt — the carve-out is a statement of intent; the installed key is drift.
//
// Callers must only ask about (user, server) pairs the grant union does not
// cover — Build's Unauthorized loop guarantees this; outside that context a
// wildcard user with an explicit grant of an excepted server would be
// misclassified.
func hasExceptCarveOut(cfg *config.Config, user, server string) bool {
	for _, a := range cfg.Access {
		if a.User != user || !slices.Contains(a.Servers, "*") {
			continue
		}
		if slices.Contains(a.Except, server) {
			return true
		}
	}
	return false
}

// nameUsers turns accumulated unknown keys into named users, resolving
// collisions against manifest names and each other with numeric suffixes.
// A key found on every server of a 2+-server fleet compacts to a wildcard
// grant, mirroring import's rule, with the same review warning.
func nameUsers(cfg *config.Config, byFP map[string]*pending, order []string) ([]NewUser, []string) {
	taken := make(map[string]bool, len(cfg.Users))
	for _, u := range cfg.Users {
		taken[u.Name] = true
	}
	var users []NewUser
	var warnings []string
	anon := 0
	for _, fp := range order {
		pd := byFP[fp]
		base := sanitizeName(pd.comment)
		if base == "" {
			anon++
			base = fmt.Sprintf("adopted-key-%d", anon)
		}
		name := base
		for n := 2; taken[name]; n++ {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		taken[name] = true
		sort.Strings(pd.foundOn)
		nu := NewUser{Name: name, Line: pd.line, FoundOn: pd.foundOn}
		if len(cfg.Servers) >= 2 && len(pd.foundOn) == len(cfg.Servers) {
			nu.Wildcard = true
			warnings = append(warnings, fmt.Sprintf(
				"access for %q covers every server; emitted as wildcard %q (includes servers added later)", name, "*"))
		}
		users = append(users, nu)
	}
	return users, warnings
}

// sanitizeName derives a manifest user name from a key comment: lowercase,
// every run of characters outside [a-z0-9] collapses to a single '-',
// leading and trailing '-' trimmed. Returns "" when nothing usable remains —
// the caller falls back to a numbered name.
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
	return b.String()
}
