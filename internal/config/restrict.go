package config

import (
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// grantOptionErrors checks access entry i's options: (spec 2026-11-08 S7
// Validation): each one is an option sshd accepts and a restriction, the
// grant repeats no once-only clause, and no name is already on a key line the
// entry reaches (each member's keys for a group entry), which would repeat a
// once-only clause or widen a permitopen=/permitlisten= union.
func (c *Config) grantOptionErrors(i int, a Access) []error {
	var errs []error
	for _, opt := range a.Options {
		if err := grantOptionIssue(i, opt); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs
	}
	if err := authkeys.OptionIssue(a.Options); err != nil {
		return []error{fmt.Errorf("access[%d]: %w", i, err)}
	}
	for _, user := range c.entryUsers(a) {
		for ki, k := range c.keysByUser[user] {
			if err := keyLineClash(i, a.Options, user, ki+1, k); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errs
}

// grantOptionIssue reports why one grant option is refused; nil when it is
// a restriction sshd accepts.
func grantOptionIssue(i int, opt string) error {
	if issue := authkeys.CheckOption(opt); issue != "" {
		return fmt.Errorf("access[%d]: option %q %s", i, opt, issue)
	}
	if authkeys.CertOnly([]string{opt}) {
		return fmt.Errorf("access[%d]: option %q makes the key accept certificates only; a grant cannot turn a key into a certificate authority", i, opt)
	}
	if !authkeys.IsRestriction(opt) {
		return fmt.Errorf("access[%d]: option %q does not restrict access; a grant can only add restrictions", i, opt)
	}
	return nil
}

// keyLineClash refuses a grant option whose name the key line already
// carries (authkeys.FindOption ignores case), then runs OptionIssue over the
// combined line as a last check; that check cannot fire once the name rule
// passed (plan gap 8) and stays as defense in depth.
func keyLineClash(i int, grant []string, user string, index int, k authkeys.Key) error {
	for _, opt := range grant {
		name, _, _ := strings.Cut(opt, "=")
		if have, ok := authkeys.FindOption(k.Options, name); ok {
			return fmt.Errorf("access[%d]: option %q: user %q key %d already carries %q; restrict a key on its key line or on its grants, not both",
				i, opt, user, index, have)
		}
	}
	if err := authkeys.OptionIssue(slices.Concat(k.Options, grant)); err != nil {
		return fmt.Errorf("access[%d]: user %q key %d: %w", i, user, index, err)
	}
	return nil
}

// implicitGrant is the entry of a fleet-wide operator's implicit grant of
// every server, which adds no options. It comes before access[0] (plan gap 3).
const implicitGrant = -1

// grantSource is one way a user reaches a server: access entry entry (or
// implicitGrant) and the options it adds there.
type grantSource struct {
	entry   int
	options []string
}

// grantSources lists every way user reaches s, the implicit operator grant
// first, then access entries in order. A jump_only server has none. On a
// pair an access tombstone blocked no entry counts: it renders nothing and
// takes no part in the clash check (spec S7 Tombstones); a fleet-wide
// operator's implicit grant still does, as it still installs the key ("How
// selectors meet tombstones"). A user with a source renders on s exactly when
// DesiredFor emits its keys there (FuzzLoad's checkGrantOptions).
func (c *Config) grantSources(user string, s Server) []grantSource {
	if s.JumpOnly {
		return nil
	}
	var out []grantSource
	if c.fleetWide[user] {
		out = append(out, grantSource{entry: implicitGrant})
	}
	if c.blocked[grantPair{user, s.Name}] {
		return out
	}
	for n, a := range c.Access {
		if c.entryApplies(a, user) && entryCovers(a, s) {
			out = append(out, grantSource{entry: n, options: a.Options})
		}
	}
	return out
}

// keysOn is user's keys as rendered on s (spec S7 Render): each key line's
// options, then the options of the first grant source reaching it. Every
// source agrees unless a restriction conflict names the pair; then the first
// source still decides, so DesiredFor stays deterministic, and apply refuses
// the server. Copies: the manifest's parsed keys never change.
func (c *Config) keysOn(user string, s Server) []authkeys.Key {
	keys := c.keysByUser[user]
	if !c.optioned {
		return keys
	}
	src := c.grantSources(user, s)
	if len(src) == 0 || len(src[0].options) == 0 {
		return keys
	}
	out := make([]authkeys.Key, len(keys))
	for i, k := range keys {
		k.Options = slices.Concat(k.Options, src[0].options)
		out[i] = k
	}
	return out
}

// restrictionConflicts finds every user whose grants give their keys
// different restrictions on a server (spec S7, OP6): one conflict per user
// and pair of grant sources, users in users order. Only a user an entry with
// options: reaches can clash, and only one with keys (plan gap 5).
func (c *Config) restrictionConflicts() []Conflict {
	if !c.optioned {
		return nil
	}
	var out []Conflict
	for _, u := range c.Users {
		if len(c.keysByUser[u.Name]) > 0 && c.reachedByOptions(u.Name) {
			out = append(out, c.userClashes(u.Name)...)
		}
	}
	return out
}

// reachedByOptions reports whether an access: entry with options: grants to user.
func (c *Config) reachedByOptions(user string) bool {
	return slices.ContainsFunc(c.Access, func(a Access) bool { return len(a.Options) > 0 && c.entryApplies(a, user) })
}

// clashKey names the pair of grant sources a restriction conflict is about.
type clashKey struct{ first, second int }

// clash is one restriction conflict being collected: its two sources and
// every server where they are the first disagreement, servers: order.
type clash struct {
	first, second grantSource
	servers       []string
}

// userClashes collects user's restriction conflicts, one per pair of
// sources, in the order their first server appears.
func (c *Config) userClashes(user string) []Conflict {
	var order []clashKey
	found := make(map[clashKey]*clash)
	for _, s := range c.Servers {
		a, b, ok := firstClash(c.grantSources(user, s))
		if !ok {
			continue
		}
		k := clashKey{a.entry, b.entry}
		if found[k] == nil {
			found[k] = &clash{first: a, second: b}
			order = append(order, k)
		}
		found[k].servers = append(found[k].servers, s.Name)
	}
	out := make([]Conflict, 0, len(order))
	for _, k := range order {
		cl := found[k]
		out = append(out, Conflict{Kind: ConflictRestriction, User: user, Servers: cl.servers, Message: clashMessage(user, cl)})
	}
	return out
}

// firstClash returns the first source and the first later one whose options
// differ from it (spec S7: with three different sets, the first two in order
// are named); ok is false when every source agrees.
func firstClash(src []grantSource) (a, b grantSource, ok bool) {
	for i := 1; i < len(src); i++ {
		if !authkeys.SameOptions(src[0].options, src[i].options) {
			return src[0], src[i], true
		}
	}
	return grantSource{}, grantSource{}, false
}

// clashMessage is the design's text: what is wrong, then the way out.
func clashMessage(user string, cl *clash) string {
	where := fmt.Sprintf("server %q is", cl.servers[0])
	if more := len(cl.servers) - 1; more > 0 {
		where = fmt.Sprintf("servers %q and %d more are", cl.servers[0], more)
	}
	return fmt.Sprintf("user %q: %s granted by %s and by %s; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user",
		user, where, sourceLabel(cl.first), sourceLabel(cl.second))
}

// sourceLabel names a grant source in a conflict: `access[2] with
// [from="10.0.0.0/8" no-pty]`, `access[5] with no options` or `its operator
// grant with no options`. Options print verbatim: each passed CheckOption.
func sourceLabel(s grantSource) string {
	with := "no options"
	if len(s.options) > 0 {
		with = "[" + strings.Join(s.options, " ") + "]"
	}
	if s.entry == implicitGrant {
		return "its operator grant with " + with
	}
	return fmt.Sprintf("access[%d] with %s", s.entry, with)
}
