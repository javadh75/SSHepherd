// Package config loads and validates the SSHepherd source-of-truth manifest:
// users (with their public keys), servers, and which users may access which
// servers. Validation is strict — a manifest that parses is safe to act on.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// User is a person (or role) and the public keys that identify them.
type User struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"` // docs only, never sent to a server
	Comment     string   `yaml:"comment"`     // written as the key comment by the apply slice
	Operator    bool     `yaml:"operator"`    // protected, plus an implicit grant of every server (FleetWide)
	Protected   bool     `yaml:"protected"`   // critical when missing, --operator to touch, written first, where granted
	Keys        []string `yaml:"keys"`
}

// IsProtected reports whether u's keys are protected: operator: true or
// protected: true. It decides the audit critical tier, the --operator
// acknowledgement and written-first order. It says nothing about reach; that
// is Config.FleetWide.
func (u User) IsProtected() bool { return u.Operator || u.Protected }

// Server is one machine in the fleet and the account we manage on it.
type Server struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"` // docs only
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"` // defaults to 22
	User        string `yaml:"user"`
	// AuthorizedKeysFile overrides the file read on this server (the
	// resolved value of sshd_config's AuthorizedKeysFile directive — sshd
	// %-tokens are not expanded, so spell the real path). Unset means
	// ~/.ssh/authorized_keys. Must be absolute ("/...") or home-relative
	// with an explicit "~/" prefix, and name a file (no trailing "/");
	// validated strictly because this value reaches a remote shell (quoted
	// by sshread's shQuote).
	AuthorizedKeysFile string `yaml:"authorized_keys_file"`
	// Tags name this server in @tag selectors of access: entries (spec
	// 2026-11-08 S3a). Each matches tagShape; a tag repeats on no server.
	Tags []string `yaml:"tags"`
	// Via names the server this one is reached through: SSHepherd connects
	// to Via first and opens a direct-tcpip channel to this server's host and
	// port from there (spec 2026-11-08 S5, D23). Every hop's host key is
	// checked strictly. Empty dials the host directly.
	Via string `yaml:"via"`
	// JumpOnly makes the server a tunnel and nothing else (OP8): no grant
	// reaches it ("*", @tag and the operator's implicit grant skip it,
	// access: cannot name it), and audit and apply list it as "jump only"
	// without reading or writing its authorized_keys.
	JumpOnly bool `yaml:"jump_only"`
}

// Group names a set of users for access: entries (spec 2026-11-08 S3b). An
// access entry with group: grants every member. Membership is checked at
// load: each member is a known user, listed once.
type Group struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"` // docs only, never sent to a server
	Members     []string `yaml:"members"`
}

// Access grants one user, or every member of one group, access to a list of
// servers. Exactly one of User and Group is set. An item is a server name or
// a selector: "*" (every server, including ones added later; it must be the
// only item) or "@tag" (every server carrying the tag now). Names and tags
// mix as a union; except: removes names from what the selectors reach.
type Access struct {
	User    string   `yaml:"user"`
	Group   string   `yaml:"group"`
	Servers []string `yaml:"servers"`
	Except  []string `yaml:"except"` // only valid with a selector in Servers
}

// Config is the parsed, validated manifest.
type Config struct {
	// ManifestSerial is serial: (absent = 0). Revoke and rotate bump it; the
	// managed header carries it, so apply can refuse a write from an older
	// copy (spec 2026-11-08 §3). The accessor is Serial().
	ManifestSerial Serial   `yaml:"serial"`
	Users          []User   `yaml:"users"`
	Groups         []Group  `yaml:"groups"`
	Servers        []Server `yaml:"servers"`
	Access         []Access `yaml:"access"`
	// Tombstones is revoked: — the revocation memory every tool honours.
	// The accessors are Revoked and AccessRevoked.
	Tombstones []Tombstone `yaml:"revoked"`

	// Warnings collects non-fatal validation findings (e.g. a comment: set
	// on a multi-key user). The manifest is still valid and safe to act on;
	// callers surface these on stderr. Never part of the YAML itself.
	Warnings []string `yaml:"-"`
	// ManifestWarnings are Warnings in structured form (the JSON
	// manifest_warnings objects), one per entry, in the same order.
	ManifestWarnings []ManifestWarning `yaml:"-"`

	// Built during validation.
	keysByUser map[string][]authkeys.Key // user name -> parsed keys, manifest order
	owners     map[string]User           // fingerprint -> owning user
	grants     map[string][]string       // server name -> user names, access order
	operators  []string                  // operator user names, users order
	protected  []string                  // operator: or protected: user names, users order
	fleetWide  map[string]bool           // operators whose implicit grant applies (FleetWide)
	ignored    map[int]map[string]bool   // revoked index -> unknown servers it names (D1e)
	blocked    map[grantPair]bool        // @tag grants an access tombstone dropped (spec "How selectors meet tombstones")
	members    map[string][]string       // group name -> members, as listed
	conflicts  []Conflict                // policy conflicts (D29), computed after validation
	weak       []WeakKey                 // every key failing the strength policy, granted or not
}

// Load reads and parses the manifest at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the user's own --config flag
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	return Parse(data)
}

// Parse parses and validates a manifest. Unknown YAML fields are rejected so
// typos (e.g. "commment") fail loudly instead of being silently ignored.
func Parse(data []byte) (*Config, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var c Config
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	// A second document (a stray "---", two files concatenated) would be
	// silently dropped — and every user it declares revoked by apply. The
	// manifest is exactly one document.
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse manifest: manifest contains multiple YAML documents")
	}
	if err := rejectNullSerial(data); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	c.conflicts = c.computeConflicts()
	c.warnExpired()
	return &c, nil
}

func (c *Config) validate() error {
	var errs []error
	errs = append(errs, c.validateUsers()...)
	errs = append(errs, c.validateServers()...)
	errs = append(errs, c.validateVia()...)
	errs = append(errs, c.validateGroups()...)
	errs = append(errs, c.validateAccess()...)
	errs = append(errs, c.validateRevoked()...)
	c.blockTombstoned() // needs both validateAccess's grants and validateRevoked's ignored set
	return errors.Join(errs...)
}

func (c *Config) validateUsers() []error {
	var errs []error
	c.keysByUser = make(map[string][]authkeys.Key)
	c.owners = make(map[string]User)
	c.operators = nil
	c.protected = nil
	c.Warnings = nil
	c.ManifestWarnings = nil
	seen := make(map[string]bool)
	for ui, u := range c.Users {
		if u.Name == "" {
			errs = append(errs, fmt.Errorf("users[%d]: empty name", ui))
			continue
		}
		if seen[u.Name] {
			errs = append(errs, fmt.Errorf("duplicate user %q", u.Name))
			continue
		}
		seen[u.Name] = true
		if issue := authkeys.RenderTextIssue(u.Name); issue != "" {
			// name is both an identifier and the comment of last resort
			// (DesiredComment's floor): a hostile name would inject content
			// into every rendered authorized_keys file.
			errs = append(errs, fmt.Errorf("user %q: name %s", u.Name, issue))
		}
		if issue := authkeys.RenderTextIssue(u.Comment); issue != "" {
			errs = append(errs, fmt.Errorf("user %q: comment %s", u.Name, issue))
		}
		if u.Comment != "" && len(u.Keys) >= 2 {
			// Not an error: collapsing every key to one comment is a valid,
			// deliberate normalization (2026-07-16 memo) — but make it a
			// conscious choice.
			c.warn(ManifestWarning{Kind: WarnCommentOnMultiKey, Message: fmt.Sprintf(
				"user %q: comment is set on a user with %d keys; apply will write the same comment on every key",
				u.Name, len(u.Keys))})
		}
		for i, line := range u.Keys {
			k, err := parseUserKey(u, i, line)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if owner, dup := c.owners[k.Fingerprint]; dup {
				errs = append(errs, fmt.Errorf("duplicate key %s: already owned by %q, repeated under %q",
					k.Fingerprint, owner.Name, u.Name))
				continue
			}
			c.owners[k.Fingerprint] = u
			c.keysByUser[u.Name] = append(c.keysByUser[u.Name], *k)
		}
		if u.Operator {
			if len(c.keysByUser[u.Name]) == 0 {
				errs = append(errs, fmt.Errorf("user %q: operator requires at least one valid key", u.Name))
				continue
			}
			c.operators = append(c.operators, u.Name)
		}
		if u.IsProtected() {
			c.protected = append(c.protected, u.Name)
		}
	}
	return errs
}

// parseUserKey validates one manifest key line and returns its parsed form.
// The inline comment is a DesiredComment fallback, so it reaches the render
// path like name/comment do — the same RenderTextIssue predicate applies
// (only the control/format arm can fire: the key parser already trims edge
// whitespace off comments). Options are rendered verbatim too, so each one
// is checked by optionIssue.
func parseUserKey(u User, i int, line string) (*authkeys.Key, error) {
	if strings.ContainsAny(line, "\r\n") {
		return nil, fmt.Errorf("user %q key %d: contains a line break", u.Name, i+1)
	}
	k, err := authkeys.ParseLine(line)
	if err != nil {
		return nil, fmt.Errorf("user %q key %d (%q): %w", u.Name, i+1, line, err)
	}
	if k == nil {
		return nil, fmt.Errorf("user %q key %d: blank entry is not a key", u.Name, i+1)
	}
	if issue := authkeys.RenderTextIssue(k.Comment); issue != "" {
		return nil, fmt.Errorf("user %q key %d: inline comment %s", u.Name, i+1, issue)
	}
	for _, opt := range k.Options {
		if issue := optionIssue(opt); issue != "" {
			return nil, fmt.Errorf("user %q key %d: option %q %s", u.Name, i+1, opt, issue)
		}
	}
	// Each option passed; what is left is line-level: a repeated once-only
	// clause (command=, from=, principals=), on which sshd rejects the line.
	if err := authkeys.OptionIssue(k.Options); err != nil {
		return nil, fmt.Errorf("user %q key %d: %w", u.Name, i+1, err)
	}
	return k, nil
}

// optionIssue reports why one key option is unsafe or unknown to sshd; empty
// means acceptable. The meaning table lives in authkeys (one model for
// manifest validation, apply's loosening highlight and rotate's expiry check).
func optionIssue(opt string) string { return authkeys.CheckOption(opt) }

// defaultAuthorizedKeysFile is the file read when a server sets no
// authorized_keys_file override.
const defaultAuthorizedKeysFile = "~/.ssh/authorized_keys"

// target is the remote file a server entry resolves to. Two entries with
// the same target would race on one file under parallel apply (and, once
// their grants diverge, overwrite each other forever).
type target struct {
	host string // lower-cased: hostnames are case-insensitive
	port int
	user string
	path string // effective authorized_keys path
}

func (c *Config) validateServers() []error {
	var errs []error
	seen := make(map[string]bool)
	targets := make(map[target]int) // target -> index of the first server
	routes := make(map[string]int)  // lower-cased host:port -> index of the first server there
	for i := range c.Servers {
		s := &c.Servers[i]
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("servers[%d]: empty name", i))
			continue
		}
		if issue := ServerNameIssue(s.Name); issue != "" {
			// %q escapes the hostile runes so the error itself is inert.
			errs = append(errs, fmt.Errorf("servers[%d]: name %q %s", i, s.Name, issue))
			continue
		}
		if seen[s.Name] {
			errs = append(errs, fmt.Errorf("duplicate server %q", s.Name))
			continue
		}
		seen[s.Name] = true
		if fieldErrs := validateServerFields(s); len(fieldErrs) > 0 {
			errs = append(errs, fieldErrs...)
			continue // an invalid entry has no meaningful target
		}
		if err := c.claimAddress(i, targets, routes); err != nil {
			errs = append(errs, err)
		}
	}
	return errs
}

// claimAddress records server i's target and route (OP7): a second entry for
// one target is refused, worded by whether the two take the same route, and
// so is a second route to one host:port, whatever the user or file:
// known_hosts is keyed by address, so it could not tell two machines apart.
func (c *Config) claimAddress(i int, targets map[target]int, routes map[string]int) error {
	s := c.Servers[i]
	t := target{host: strings.ToLower(s.Host), port: s.Port, user: s.User, path: s.AuthorizedKeysFile}
	if t.path == "" {
		t.path = defaultAuthorizedKeysFile
	}
	if first, dup := targets[t]; dup {
		f := c.Servers[first]
		if f.Via != s.Via {
			return fmt.Errorf("servers %q and %q both target %s@%s:%d %s through different hops; a manifest holds one entry per address, so remove one",
				f.Name, s.Name, s.User, s.Host, s.Port, t.path)
		}
		return fmt.Errorf("servers %q and %q both target %s@%s:%d %s; merge them into one entry",
			f.Name, s.Name, s.User, s.Host, s.Port, t.path)
	}
	targets[t] = i
	addr := net.JoinHostPort(t.host, strconv.Itoa(s.Port))
	first, seen := routes[addr]
	switch {
	case !seen:
		routes[addr] = i
	case c.Servers[first].Via != s.Via:
		return fmt.Errorf("servers %q and %q reach %s through different hops; every entry at one address must use the same route; if these are different machines, give each a hostname its own hop can resolve",
			c.Servers[first].Name, s.Name, net.JoinHostPort(s.Host, strconv.Itoa(s.Port)))
	}
	return nil
}

// validateServerFields checks one named server's host, user, port (applying
// the default of 22) and authorized_keys_file override.
func validateServerFields(s *Server) []error {
	var errs []error
	if s.Host == "" {
		errs = append(errs, fmt.Errorf("server %q: host is required", s.Name))
	} else if issue := ServerFieldIssue(s.Host); issue != "" {
		errs = append(errs, fmt.Errorf("server %q: host %q %s", s.Name, s.Host, issue))
	}
	if s.User == "" {
		errs = append(errs, fmt.Errorf("server %q: user is required", s.Name))
	} else if issue := ServerFieldIssue(s.User); issue != "" {
		errs = append(errs, fmt.Errorf("server %q: user %q %s", s.Name, s.User, issue))
	}
	if s.Port == 0 {
		s.Port = 22
	}
	if s.Port < 1 || s.Port > 65535 {
		errs = append(errs, fmt.Errorf("server %q: port %d out of range", s.Name, s.Port))
	}
	if s.JumpOnly && s.AuthorizedKeysFile != "" {
		errs = append(errs, fmt.Errorf("server %q: jump_only has no managed file; remove authorized_keys_file", s.Name))
	}
	errs = append(errs, validateTags(s)...)
	return append(errs, validateAuthorizedKeysFile(s.Name, s.AuthorizedKeysFile)...)
}

// ServerFieldIssue reports why a server name, host or user is unsafe;
// empty means safe. Exported so generators (import) can skip such values
// with a warning instead of emitting a manifest that fails to load. These fields are printed raw in plan and audit report
// headers (the review surface apply's confirmation hangs on), so unsafe
// runes (authkeys.IsUnsafeRune) are rejected; whitespace never belongs in an
// identifier, hostname or login name either.
func ServerFieldIssue(s string) string {
	if strings.ContainsFunc(s, authkeys.IsUnsafeRune) {
		return "contains control or format characters"
	}
	if strings.ContainsFunc(s, unicode.IsSpace) {
		return "contains whitespace"
	}
	return ""
}

// maxAuthorizedKeysFileLen caps the override path length; PATH_MAX is 4096
// on Linux and anything longer is hostile or broken.
const maxAuthorizedKeysFileLen = 4096

// validateAuthorizedKeysFile checks a server's authorized_keys_file
// override. The value reaches a remote shell (single-quoted by sshread), so
// unsafe runes (authkeys.IsUnsafeRune: control, format, line/paragraph
// separators) are rejected outright: newline/CSI smuggling must die here
// even if the quoting layer ever regressed. Shape: absolute or an explicit
// "~/" prefix with a non-empty remainder — bare-relative paths are
// ambiguous (home-relative per sshd vs cwd-relative per shell intuition) and
// "~user/" expansion is unsupported. '%' is rejected: sshd's %u/%h/%% tokens
// are not expanded, so a copied directive would make apply maintain a file
// sshd never reads. A trailing '/' names a directory, never a keys file.
// Unset means the default ~/.ssh/authorized_keys.
func validateAuthorizedKeysFile(server, path string) []error {
	if path == "" {
		return nil
	}
	var errs []error
	if len(path) > maxAuthorizedKeysFileLen {
		errs = append(errs, fmt.Errorf("server %q: authorized_keys_file is too long (%d bytes, max %d)",
			server, len(path), maxAuthorizedKeysFileLen))
	}
	if strings.ContainsFunc(path, authkeys.IsUnsafeRune) {
		errs = append(errs, fmt.Errorf("server %q: authorized_keys_file contains control characters", server))
	}
	if strings.Contains(path, "%") {
		errs = append(errs, fmt.Errorf(
			"server %q: authorized_keys_file %q contains '%%': sshd tokens (%%u, %%h, %%%%) are not expanded; spell the resolved path (e.g. %%u -> the server's user)",
			server, path))
	}
	if strings.HasSuffix(path, "/") {
		errs = append(errs, fmt.Errorf(
			"server %q: authorized_keys_file %q ends with '/': it must name a file, not a directory", server, path))
	}
	validPrefix := strings.HasPrefix(path, "/") ||
		(strings.HasPrefix(path, "~/") && len(path) > 2)
	if !validPrefix {
		errs = append(errs, fmt.Errorf(
			"server %q: authorized_keys_file must be an absolute path or start with ~/ (got %q)", server, path))
	}
	return errs
}

func (c *Config) validateAccess() []error {
	var errs []error
	users := make(map[string]bool, len(c.Users))
	for _, u := range c.Users {
		users[u.Name] = true
	}
	servers := make(map[string]bool, len(c.Servers))
	for _, s := range c.Servers {
		servers[s.Name] = true
	}
	c.grants = make(map[string][]string)
	c.fleetWide = c.fleetWideOperators()
	granted := make(map[string]map[string]bool) // server -> user -> already granted
	for i, a := range c.Access {
		if err := c.entrySubjectError(i, a, users); err != nil {
			errs = append(errs, err)
			continue
		}
		targets, tErrs := c.expandServers(a, servers)
		if len(tErrs) > 0 {
			errs = append(errs, tErrs...)
			continue
		}
		c.warnWildcardRoot(a, targets)
		c.warnRedundantGrant(a)
		who := c.entryUsers(a)
		for _, srv := range targets {
			if !servers[srv] {
				errs = append(errs, fmt.Errorf("access for %s: unknown server %q", entryLabel(a), srv))
				continue
			}
			if granted[srv] == nil {
				granted[srv] = make(map[string]bool)
			}
			for _, user := range who {
				if granted[srv][user] { // multiple entries union silently
					continue
				}
				granted[srv][user] = true
				c.grants[srv] = append(c.grants[srv], user)
			}
		}
	}
	return errs
}

// expandServers resolves an access entry's server list: each name as
// written, each selector ("*", "@tag") as the servers it reaches in manifest
// order minus the except names. A server reached twice is left for
// validateAccess's union. Errors cover misused selector and except syntax; an
// entry that grants nothing is certainly a mistake.
func (c *Config) expandServers(a Access, servers map[string]bool) ([]string, []error) {
	if errs := c.entryShape(a, servers); len(errs) > 0 {
		return nil, errs
	}
	var targets []string
	for _, item := range a.Servers {
		if !IsSelector(item) {
			targets = append(targets, item)
			continue
		}
		for i := range c.Servers {
			if s := c.Servers[i]; SelectorMatches(item, s) && !slices.Contains(a.Except, s.Name) {
				targets = append(targets, s.Name)
			}
		}
	}
	switch {
	case len(targets) > 0:
		return targets, nil
	case slices.Contains(a.Servers, "*"):
		return nil, []error{fmt.Errorf("access for %s: wildcard grants no servers", entryLabel(a))}
	}
	return nil, []error{fmt.Errorf("access for %s: selectors grant no servers after except", entryLabel(a))}
}

// entryShape is the access-entry rules that hold before any expansion: "*"
// stands alone, except: needs a selector and lists known server names none of
// which the entry also names, every @tag is carried by a server a grant can
// reach, and no name is a jump_only server.
func (c *Config) entryShape(a Access, servers map[string]bool) []error {
	if slices.Contains(a.Servers, "*") && len(a.Servers) != 1 {
		return []error{fmt.Errorf("access for %s: %q must be the only servers entry", entryLabel(a), "*")}
	}
	if len(a.Except) > 0 && !slices.ContainsFunc(a.Servers, IsSelector) {
		return []error{fmt.Errorf(`access for %s: except requires servers ["*"] or an @tag`, entryLabel(a))}
	}
	if len(a.Servers) == 0 {
		return []error{fmt.Errorf("access for %s: servers is empty (grants no servers)", entryLabel(a))}
	}
	errs := c.itemErrors(a)
	for _, e := range a.Except { // duplicates are tolerated, like grants unioning
		switch {
		case isTagSelector(e):
			errs = append(errs, fmt.Errorf("access for %s: except takes server names, not the selector %q", entryLabel(a), e))
		case !servers[e]:
			errs = append(errs, fmt.Errorf("access for %s: unknown except server %q", entryLabel(a), e))
		case slices.Contains(a.Servers, e):
			errs = append(errs, fmt.Errorf("access for %s: %q is in both servers and except", entryLabel(a), e))
		case c.jumpOnly(e):
			errs = append(errs, jumpOnlyNamed(a, e))
		}
	}
	return errs
}

// itemErrors checks an entry's servers: items: a @tag must be carried by a
// server, and by one that is not jump_only; a name must not be a jump_only
// server (spec S5, OP8).
func (c *Config) itemErrors(a Access) []error {
	var errs []error
	for _, item := range a.Servers {
		switch {
		case isTagSelector(item) && !c.tagCarried(item, true):
			errs = append(errs, fmt.Errorf("access for %s: unknown tag %q", entryLabel(a), item))
		case isTagSelector(item) && !c.tagCarried(item, false):
			errs = append(errs, fmt.Errorf("access for %s: %q matches only jump_only servers", entryLabel(a), item))
		case !IsSelector(item) && c.jumpOnly(item):
			errs = append(errs, jumpOnlyNamed(a, item))
		}
	}
	return errs
}

// jumpOnlyNamed is the refusal of an access entry naming a jump_only server.
func jumpOnlyNamed(a Access, server string) error {
	return fmt.Errorf("access for %s: server %q is jump_only; access cannot name it", entryLabel(a), server)
}

// tagCarried reports whether any server carries selector's tag; with
// withJumpOnly false, only a server a grant can reach counts.
func (c *Config) tagCarried(selector string, withJumpOnly bool) bool {
	tag := strings.TrimPrefix(selector, tagSelectorPrefix)
	return slices.ContainsFunc(c.Servers, func(s Server) bool {
		return slices.Contains(s.Tags, tag) && (withJumpOnly || !s.JumpOnly)
	})
}

// warnWildcardRoot records D20a: a non-operator servers: ["*"] entry that
// reaches a root account, once per entry. An operator's own "*" never warns:
// it replaces an implicit grant that reached every server. An @tag is a
// deliberate list, so it does not warn either.
// A group entry always warns: its members are not operators by default and
// its grant stands for whoever joins later.
func (c *Config) warnWildcardRoot(a Access, targets []string) {
	if !slices.Contains(a.Servers, "*") || slices.Contains(c.operators, a.User) {
		return
	}
	var roots []string
	for _, s := range c.Servers {
		if s.User == "root" && slices.Contains(targets, s.Name) {
			roots = append(roots, s.Name)
		}
	}
	if len(roots) == 0 {
		return
	}
	where := roots[0]
	if more := len(roots) - 1; more > 0 {
		where = fmt.Sprintf("%s and %d more", where, more)
	}
	c.warn(ManifestWarning{Kind: WarnWildcardRoot, Message: fmt.Sprintf(
		`access for %s: servers ["*"] includes the root account on %s; list the servers or use an @tag that excludes root accounts`,
		entryLabel(a), where)})
}

// DesiredFor returns the desired key set for a server: protected keys first
// (users order; a fleet-wide operator everywhere, any other protected user
// only where granted), then the keys of every other granted user (access
// order). Deterministic; a user is never emitted twice. An operator's own
// servers: ["*"] entry replaces the implicit grant, so its except: applies.
// A jump_only server renders nothing: no access entry reaches it, and the
// implicit operator grant skips it.
func (c *Config) DesiredFor(serverName string) []authkeys.Key {
	var keys []authkeys.Key
	jumpOnly := c.jumpOnly(serverName)
	first := make(map[string]bool, len(c.protected))
	for _, name := range c.protected {
		if (c.fleetWide[name] && !jumpOnly) || slices.Contains(c.grants[serverName], name) {
			first[name] = true
			keys = append(keys, c.keysByUser[name]...)
		}
	}
	for _, userName := range c.grants[serverName] {
		if !first[userName] { // redundant grant for a protected user: already emitted
			keys = append(keys, c.keysByUser[userName]...)
		}
	}
	return keys
}

// DesiredComment returns the comment the apply slice will write for key k
// owned by u, encoding the decided write-time order (2026-07-16
// comment-policy memo, Option A): the user's comment: field if non-empty,
// else the key line's own inline comment, else the user's name. Apply and
// audit's --comments drift reporting both consume this, so the write path
// and the drift preview can never disagree.
func DesiredComment(u User, k authkeys.Key) string {
	if u.Comment != "" {
		return u.Comment
	}
	if k.Comment != "" {
		return k.Comment
	}
	return u.Name
}

// OwnerOf resolves a key fingerprint to the user that owns it in the manifest.
func (c *Config) OwnerOf(fingerprint string) (User, bool) {
	u, ok := c.owners[fingerprint]
	return u, ok
}

// Covers reports whether user's access — explicit grants, a selector minus
// its except: list, not a grant an access tombstone blocked — covers server.
// server need not exist in the manifest yet: a wildcard grant covers future
// servers by design, so beyond the expanded grants (which only know the
// current fleet) the user's raw access entries are scanned, with server as a
// tagless entry: a future server carries no tag, so an @tag never covers it.
//
// The c.blocked check comes first because a group entry's "*" or literal
// name matches the raw scan below for a member a tombstone blocked.
//
// A fleet-wide operator's implicit grant is deliberately excluded: check
// FleetWide first. Reading Covers(op, srv) == false as "no access" would
// contradict DesiredFor, which grants such an operator every server. An
// operator with its own "*" entry is an ordinary grantee here.
//
// A jump_only server is covered by nothing (spec S5).
func (c *Config) Covers(user, server string) bool {
	if c.blocked[grantPair{user, server}] || c.jumpOnly(server) {
		return false
	}
	if slices.Contains(c.grants[server], user) {
		return true
	}
	for _, a := range c.Access {
		if c.entryApplies(a, user) && entryCovers(a, Server{Name: server}) {
			return true
		}
	}
	return false
}

// ExceptCarveOut reports whether user's access deliberately excludes
// server via an except: list, on a "*" or an @tag entry. Such a server is
// never re-granted by merge tooling — the carve-out is a statement of intent;
// an installed key there is drift.
//
// A group entry's except: carves out for every member.
//
// Callers must only ask about (user, server) pairs the grant union does
// not cover (i.e. after Covers returned false) — outside that context a
// user with an explicit grant of an excepted server would be misclassified.
func (c *Config) ExceptCarveOut(user, server string) bool {
	for _, a := range c.Access {
		if c.entryApplies(a, user) && slices.Contains(a.Except, server) { // except: requires a selector
			return true
		}
	}
	return false
}
