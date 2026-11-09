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
// t's (known) servers — named explicitly, or a wildcard that does not
// except it. One conflict per (entry, tombstoned server); Servers is every
// server that entry renders on (spec §2), so apply refuses, and audit
// marks critical, all of them.
func (c *Config) accessConflicts(m int, t Tombstone) []Conflict {
	var out []Conflict
	for n, a := range c.Access {
		if a.User != t.User {
			continue
		}
		covered := c.entryServers(a)
		for _, s := range t.Servers {
			if c.ignored[m][s] || !slices.Contains(covered, s) {
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
// renders its user's keys on: its explicit names, or — for a wildcard —
// every server its except: does not name. Never nil.
func (c *Config) entryServers(a Access) []string {
	wildcard := slices.Contains(a.Servers, "*")
	out := []string{}
	for _, s := range c.Servers {
		if (wildcard && !slices.Contains(a.Except, s.Name)) || (!wildcard && slices.Contains(a.Servers, s.Name)) {
			out = append(out, s.Name)
		}
	}
	return out
}

// serversRendering lists, in servers: order, every server whose rendered
// file holds u's keys: all of them for an operator, else u's grants. Never
// nil (the JSON servers list is always present).
func (c *Config) serversRendering(u User) []string {
	out := []string{}
	for _, s := range c.Servers {
		if u.Operator || slices.Contains(c.grants[s.Name], u.Name) {
			out = append(out, s.Name)
		}
	}
	return out
}
