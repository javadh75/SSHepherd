package config

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// MaxSerial is the largest manifest serial, 2^53-1, so every JSON consumer
// reads it exactly. authkeys.MaxHeaderSerial is the same bound for the
// managed header (a test in internal/apply pins the two equal).
const MaxSerial = 1<<53 - 1

// Serial is the manifest's serial: (absent = 0). Only a plain, unquoted
// decimal YAML integer in [0, MaxSerial] decodes: a quoted, signed, hex,
// octal-looking or underscored value is a load error, so the number in the
// file is the number every tool compares.
type Serial uint64

var plainDecimal = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *Serial) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!int" && n.Style == 0 && plainDecimal.MatchString(n.Value) {
		if v, err := strconv.ParseUint(n.Value, 10, 64); err == nil && v <= MaxSerial {
			*s = Serial(v)
			return nil
		}
	}
	return fmt.Errorf("serial: want an integer from 0 to %d, got %q", MaxSerial, n.Value)
}

// Tombstone is one revoked: entry. A key tombstone has Fingerprint (User is
// an optional label naming the former owner, who need not exist); an access
// tombstone has no Fingerprint and records that User lost Servers. Deleting
// an entry by hand is a deliberate un-revoke.
type Tombstone struct {
	Fingerprint string   `yaml:"fingerprint"`
	User        string   `yaml:"user"`
	Servers     []string `yaml:"servers"`
	Date        string   `yaml:"date"`
	Reason      string   `yaml:"reason"`
}

// IsKey reports a key tombstone (as opposed to an access tombstone).
func (t Tombstone) IsKey() bool { return t.Fingerprint != "" }

// Label is the parenthesis every message prints: "2026-11-08, alice", or
// "2026-11-08" for an unlabelled entry.
func (t Tombstone) Label() string {
	if t.User == "" {
		return t.Date
	}
	return t.Date + ", " + t.User
}

// Serial returns the manifest's serial (0 when absent).
func (c *Config) Serial() uint64 { return uint64(c.ManifestSerial) }

// rejectNullSerial catches serial: with a YAML null value (`serial:`,
// `serial: ~`, `serial: null`). yaml.v3 never calls an Unmarshaler for a
// !!null node (decoder.prepare), so Serial.UnmarshalYAML alone would load
// it as 0 — and BumpSerial would later fail on a value that "passed
// validation". A yaml.Node field is filled before that check, so a second
// decode sees the raw node. Parse calls it only after the strict decode
// succeeded, so this decode cannot fail on syntax.
func rejectNullSerial(data []byte) error {
	var probe struct {
		Serial yaml.Node `yaml:"serial"`
	}
	if err := yaml.Unmarshal(data, &probe); err != nil {
		return nil //nolint:nilerr // the strict decode in Parse already reported every syntax error
	}
	n := &probe.Serial
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	if n.Kind == yaml.ScalarNode && n.ShortTag() == "!!null" {
		return fmt.Errorf("serial: want an integer from 0 to %d, got %q", MaxSerial, n.Value)
	}
	return nil
}

// The policy-conflict kinds (D29).
const (
	ConflictRevokedKey    = "revoked_key"
	ConflictRevokedAccess = "revoked_access"
	ConflictWeakKey       = "weak_key"
)

// Conflict is a manifest that breaks its own policy: a tombstoned key still
// listed, a grant over an access tombstone, or a weak key granted on a
// server. It is not a load error (D29): audit reports it critical, apply
// refuses Servers, and a saving command refuses per conflictRefusal in
// cmd/sshepherd. The json tags are the wire shape of policy_conflicts.
type Conflict struct {
	Kind        string   `json:"kind"`
	Message     string   `json:"message"`
	User        string   `json:"user"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Servers     []string `json:"servers"` // every server the key or grant would render on; never nil
}

// fingerprintShape is OpenSSH's SHA256 fingerprint: "SHA256:" and 43
// unpadded base64 characters (32 bytes).
var fingerprintShape = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)

// maxTombstoneText caps a tombstone's printed user and reason labels.
const maxTombstoneText = 256

// validateRevoked checks each revoked: entry's shape (load errors, spec §2)
// and records the D1e warnings: a server an access tombstone names that is
// not in servers: is ignored for that entry, never an error.
func (c *Config) validateRevoked() []error {
	var errs []error
	c.ignored = make(map[int]map[string]bool)
	known := make(map[string]bool, len(c.Servers))
	for _, s := range c.Servers {
		known[s.Name] = true
	}
	firstFP := make(map[string]int)
	for i, t := range c.Tombstones {
		p := fmt.Sprintf("revoked[%d]: ", i)
		if t.IsKey() {
			errs = append(errs, keyShape(p, t)...)
			if j, dup := firstFP[t.Fingerprint]; dup {
				errs = append(errs, fmt.Errorf("%s%s is already revoked by revoked[%d]", p, t.Fingerprint, j))
			} else {
				firstFP[t.Fingerprint] = i
			}
		} else {
			errs = append(errs, accessShape(p, t)...)
			c.warnUnknownServers(i, t, known)
		}
		errs = append(errs, dateErrors(p, t.Date)...)
		errs = append(errs, textErrors(p, "user", t.User)...)
		errs = append(errs, textErrors(p, "reason", t.Reason)...)
	}
	return errs
}

func keyShape(p string, t Tombstone) []error {
	var errs []error
	if !fingerprintShape.MatchString(t.Fingerprint) {
		errs = append(errs, fmt.Errorf("%sfingerprint %q is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)", p, t.Fingerprint))
	}
	if len(t.Servers) > 0 {
		errs = append(errs, fmt.Errorf("%sservers is not allowed on a key entry (%s); record access with a separate entry that has user and servers", p, t.Fingerprint))
	}
	return errs
}

func accessShape(p string, t Tombstone) []error {
	var errs []error
	switch {
	case t.User == "":
		errs = append(errs, fmt.Errorf("%san entry without fingerprint needs user and servers", p))
	case len(t.Servers) == 0:
		errs = append(errs, fmt.Errorf("%sservers must not be empty", p))
	}
	// Only the spec §2 rules are load errors. Any other name — even one
	// with control runes, which can never be in servers: — is an unknown
	// server: a D1e warning (warnUnknownServers), never a load error.
	if slices.Contains(t.Servers, "*") {
		errs = append(errs, fmt.Errorf(`%sservers cannot be "*"; list the servers by name`, p))
	}
	if slices.ContainsFunc(t.Servers, isTagSelector) {
		errs = append(errs, fmt.Errorf("%sservers cannot hold a selector; list the servers by name", p))
	}
	return errs
}

func dateErrors(p, d string) []error {
	if d == "" {
		return []error{fmt.Errorf("%sdate is required", p)}
	}
	if _, err := time.Parse(time.DateOnly, d); err != nil || len(d) != len(time.DateOnly) {
		return []error{fmt.Errorf("%sdate %q is not a YYYY-MM-DD date", p, d)}
	}
	return nil
}

// textErrors: user and reason are printed by every tool, so they pass the
// render-text predicate and a length cap.
func textErrors(p, field, s string) []error {
	if issue := authkeys.RenderTextIssue(s); issue != "" {
		return []error{fmt.Errorf("%s%s %s", p, field, issue)}
	}
	if len(s) > maxTombstoneText {
		return []error{fmt.Errorf("%s%s is %d bytes, over the %d-byte limit", p, field, len(s), maxTombstoneText)}
	}
	return nil
}

// warnUnknownServers records, for access tombstone i, every server it names
// that servers: does not hold (D1e): a warning, and the entry is ignored for
// that server (AccessRevoked and the conflict check skip it).
func (c *Config) warnUnknownServers(i int, t Tombstone, known map[string]bool) {
	for _, s := range t.Servers {
		if s == "*" || known[s] {
			continue
		}
		if c.ignored[i] == nil {
			c.ignored[i] = make(map[string]bool)
		}
		c.ignored[i][s] = true
		// The name is printed: quoted first (the spec's quotes); the second
		// time raw for any name a server could have (the spec's text,
		// verbatim) and quoted otherwise, so no control rune reaches a
		// terminal.
		bare := s
		if ServerFieldIssue(s) != "" {
			bare = strconv.Quote(s)
		}
		msg := fmt.Sprintf("revoked[%d]: unknown server %q — this entry is ignored for it; remove %s from the entry once the server is gone for good", i, s, bare)
		c.warn(ManifestWarning{Kind: WarnTombstoneUnknownServer, RevokedIndex: &i, User: t.User, Server: s, Message: msg})
	}
}

// Revoked returns the key tombstone for fingerprint fp.
func (c *Config) Revoked(fp string) (Tombstone, bool) {
	for _, t := range c.Tombstones {
		if t.IsKey() && t.Fingerprint == fp {
			return t, true
		}
	}
	return Tombstone{}, false
}

// AccessRevoked returns the latest access tombstone recording that user
// lost server. A server the entry names but servers: does not hold is
// ignored for that entry (D1e), so it never matches.
func (c *Config) AccessRevoked(user, server string) (Tombstone, bool) {
	var found Tombstone
	ok := false
	for i, t := range c.Tombstones {
		if t.IsKey() || t.User != user || !slices.Contains(t.Servers, server) || c.ignored[i][server] {
			continue
		}
		found, ok = t, true
	}
	return found, ok
}

// Conflicts returns the manifest's policy conflicts (D29), key conflicts
// first, each in revoked: order.
func (c *Config) Conflicts() []Conflict { return slices.Clone(c.conflicts) }

// computeConflicts runs after validation succeeded: owners and grants are
// built, every tombstone is well-formed.
func (c *Config) computeConflicts() []Conflict {
	var out []Conflict
	for _, t := range c.Tombstones {
		u, owned := c.owners[t.Fingerprint]
		if !t.IsKey() || !owned {
			continue
		}
		out = append(out, Conflict{
			Kind: ConflictRevokedKey, User: u.Name, Fingerprint: t.Fingerprint, Servers: c.serversRendering(u),
			Message: fmt.Sprintf("key %s of user %q is revoked (%s): remove it from users, or delete the revoked: entry to un-revoke it deliberately",
				t.Fingerprint, u.Name, t.Label()),
		})
	}
	for m, t := range c.Tombstones {
		if t.IsKey() {
			continue
		}
		out = append(out, c.accessConflicts(m, t)...)
	}
	return append(out, c.weakConflicts()...)
}

// accessConflicts: an access: entry for t's user that renders on one of
// t's (known) servers and reaches it directly — named explicitly, or a
// wildcard that does not except it. An @tag reaching it is blocked instead,
// and blockTombstoned leaves such a pair only when another entry is direct, so
// an @tag entry is never the one named here. One conflict per (entry,
// tombstoned server); Servers is every server that entry renders on (spec
// §2), so apply refuses, and audit marks critical, all of them.
func (c *Config) accessConflicts(m int, t Tombstone) []Conflict {
	var out []Conflict
	for n, a := range c.Access {
		if a.User != t.User { // a group entry is blocked, never a conflict
			continue
		}
		covered := c.entryServers(a)
		for _, s := range t.Servers {
			if c.ignored[m][s] || !slices.Contains(covered, s) || !entryDirect(a, s) {
				continue
			}
			out = append(out, Conflict{
				Kind: ConflictRevokedAccess, User: t.User, Servers: slices.Clone(covered),
				Message: fmt.Sprintf("user %q is granted %q by access[%d], but revoked[%d] removed that access (%s): remove the grant, or delete the revoked: entry to restore it deliberately",
					t.User, s, n, m, t.Date),
			})
		}
	}
	return out
}

// entryServers lists, in servers: order, every server access entry a
// renders its user's keys on: what it names or selects, minus its except:
// list and any pair an access tombstone blocked. Never nil.
func (c *Config) entryServers(a Access) []string {
	out := []string{}
	for _, s := range c.Servers {
		if entryCovers(a, s) && !c.blocked[grantPair{a.User, s.Name}] {
			out = append(out, s.Name)
		}
	}
	return out
}

// blockTombstoned drops every (user, server) grant an access tombstone
// covers and no user: entry reaches directly, so the tombstone acts as an
// implicit except: for that user alone: other members of a group keep the
// grant (spec "How selectors meet tombstones"). The grant leaves c.grants, so
// DesiredFor, apply.Affected and every report see no access; c.blocked keeps
// it out of Covers and entryServers. AccessRevoked still answers, which keeps
// adopt, reconcile, revoke's D1c note and audit's D1d label working. Each
// (entry, user, server) warns, unless the implicit operator grant still
// installs the key.
func (c *Config) blockTombstoned() {
	c.blocked = make(map[grantPair]bool)
	revoked := c.latestAccessTombstones()
	for n, a := range c.Access {
		for _, user := range c.entryUsers(a) {
			if len(revoked[user]) > 0 {
				c.blockEntry(n, a, user, revoked[user])
			}
		}
	}
}

// blockEntry applies blockTombstoned to entry n for one of its users. gone
// maps each server the user lost to its latest tombstone's index.
func (c *Config) blockEntry(n int, a Access, user string, gone map[string]int) {
	for _, s := range c.Servers {
		m, lost := gone[s.Name]
		if !lost || !entryCovers(a, s) || c.directlyGranted(user, s.Name) {
			continue
		}
		c.blocked[grantPair{user, s.Name}] = true
		c.grants[s.Name] = slices.DeleteFunc(c.grants[s.Name], func(u string) bool { return u == user })
		if !c.FleetWide(user) {
			c.warnBlocked(n, m, a, user, s)
		}
	}
}

// latestAccessTombstones is AccessRevoked for every pair at once, for
// blockTombstoned: user -> server -> index of the latest access tombstone
// naming it, ignored (D1e) servers skipped. The one-pair walk would make the
// load quadratic in a long revoked: list.
func (c *Config) latestAccessTombstones() map[string]map[string]int {
	out := make(map[string]map[string]int)
	for i, t := range c.Tombstones {
		if t.IsKey() {
			continue
		}
		for _, s := range t.Servers {
			if c.ignored[i][s] {
				continue
			}
			if out[t.User] == nil {
				out[t.User] = make(map[string]int)
			}
			out[t.User][s] = i
		}
	}
	return out
}

// directlyGranted reports a user: entry of user reaching server by name or
// "*". A group entry never counts: it is always blocked (the table in the
// spec's "How selectors meet tombstones").
func (c *Config) directlyGranted(user, server string) bool {
	return slices.ContainsFunc(c.Access, func(a Access) bool { return a.User == user && entryDirect(a, server) })
}

func (c *Config) warnBlocked(n, m int, a Access, user string, s Server) {
	msg := fmt.Sprintf(`access[%d]: %q is not granted %q through %s: revoked[%d] removed that access (%s); delete the revoked: entry to restore it deliberately`,
		n, user, s.Name, grantVia(a, s), m, c.Tombstones[m].Date)
	c.warn(ManifestWarning{Kind: WarnTombstoneBlocksGrant, RevokedIndex: &m, User: user, Server: s.Name, Message: msg})
}

// grantVia names how entry a reaches s in a blocked-grant warning: its group,
// or the first selector that reaches s.
func grantVia(a Access, s Server) string {
	if a.Group != "" {
		return "group " + a.Group
	}
	for _, item := range a.Servers {
		if SelectorMatches(item, s) {
			return item
		}
	}
	return ""
}

// serversRendering lists, in servers: order, every server whose rendered
// file holds u's keys: all of them for a fleet-wide operator, else u's grants.
// Never nil (the JSON servers list is always present).
func (c *Config) serversRendering(u User) []string {
	out := []string{}
	for _, s := range c.Servers {
		if c.FleetWide(u.Name) || slices.Contains(c.grants[s.Name], u.Name) {
			out = append(out, s.Name)
		}
	}
	return out
}
