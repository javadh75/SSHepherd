// Package config loads and validates the SSHepherd source-of-truth manifest:
// users (with their public keys), servers, and which users may access which
// servers. Validation is strict — a manifest that parses is safe to act on.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
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
	Operator    bool     `yaml:"operator"`    // fleet-wide grant; protected from removal by apply/revoke
	Keys        []string `yaml:"keys"`
}

// Server is one machine in the fleet and the account we manage on it.
type Server struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"` // docs only
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"` // defaults to 22
	User        string `yaml:"user"`
	// AuthorizedKeysFile overrides the file read on this server (mirrors
	// sshd_config's AuthorizedKeysFile directive). Unset means
	// ~/.ssh/authorized_keys. Must be absolute ("/...") or home-relative
	// with an explicit "~/" prefix; validated strictly because this value
	// reaches a remote shell (quoted by sshread's shQuote).
	AuthorizedKeysFile string `yaml:"authorized_keys_file"`
}

// Access grants one user access to a list of servers. servers: ["*"] grants
// every server (including ones added later), minus the except names.
type Access struct {
	User    string   `yaml:"user"`
	Servers []string `yaml:"servers"`
	Except  []string `yaml:"except"` // only valid with servers: ["*"]
}

// Config is the parsed, validated manifest.
type Config struct {
	Users   []User   `yaml:"users"`
	Servers []Server `yaml:"servers"`
	Access  []Access `yaml:"access"`

	// Warnings collects non-fatal validation findings (e.g. a comment: set
	// on a multi-key user). The manifest is still valid and safe to act on;
	// callers surface these on stderr. Never part of the YAML itself.
	Warnings []string `yaml:"-"`

	// Built during validation.
	keysByUser map[string][]authkeys.Key // user name -> parsed keys, manifest order
	owners     map[string]User           // fingerprint -> owning user
	grants     map[string][]string       // server name -> user names, access order
	operators  []string                  // operator user names, users order
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
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) validate() error {
	var errs []error
	errs = append(errs, c.validateUsers()...)
	errs = append(errs, c.validateServers()...)
	errs = append(errs, c.validateAccess()...)
	return errors.Join(errs...)
}

func (c *Config) validateUsers() []error {
	var errs []error
	c.keysByUser = make(map[string][]authkeys.Key)
	c.owners = make(map[string]User)
	c.operators = nil
	c.Warnings = nil
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
			c.Warnings = append(c.Warnings, fmt.Sprintf(
				"user %q: comment is set on a user with %d keys; apply will write the same comment on every key",
				u.Name, len(u.Keys)))
		}
		for i, line := range u.Keys {
			if strings.ContainsAny(line, "\r\n") {
				errs = append(errs, fmt.Errorf("user %q key %d: contains a line break", u.Name, i+1))
				continue
			}
			k, err := authkeys.ParseLine(line)
			if err != nil {
				errs = append(errs, fmt.Errorf("user %q key %d (%q): %w", u.Name, i+1, line, err))
				continue
			}
			if k == nil {
				errs = append(errs, fmt.Errorf("user %q key %d: blank entry is not a key", u.Name, i+1))
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
	}
	return errs
}

func (c *Config) validateServers() []error {
	var errs []error
	seen := make(map[string]bool)
	for i := range c.Servers {
		s := &c.Servers[i]
		if s.Name == "" {
			errs = append(errs, fmt.Errorf("servers[%d]: empty name", i))
			continue
		}
		if s.Name == "*" {
			errs = append(errs, fmt.Errorf("servers[%d]: name %q is reserved for wildcard grants", i, "*"))
			continue
		}
		if seen[s.Name] {
			errs = append(errs, fmt.Errorf("duplicate server %q", s.Name))
			continue
		}
		seen[s.Name] = true
		if s.Host == "" {
			errs = append(errs, fmt.Errorf("server %q: host is required", s.Name))
		}
		if s.User == "" {
			errs = append(errs, fmt.Errorf("server %q: user is required", s.Name))
		}
		if s.Port == 0 {
			s.Port = 22
		}
		if s.Port < 1 || s.Port > 65535 {
			errs = append(errs, fmt.Errorf("server %q: port %d out of range", s.Name, s.Port))
		}
		errs = append(errs, validateAuthorizedKeysFile(s.Name, s.AuthorizedKeysFile)...)
	}
	return errs
}

// maxAuthorizedKeysFileLen caps the override path length; PATH_MAX is 4096
// on Linux and anything longer is hostile or broken.
const maxAuthorizedKeysFileLen = 4096

// validateAuthorizedKeysFile checks a server's authorized_keys_file
// override. The value reaches a remote shell (single-quoted by sshread), so
// control and format runes are rejected outright: newline/CSI smuggling must
// die here even if the quoting layer ever regressed. Shape: absolute or an
// explicit "~/" prefix with a non-empty remainder — bare-relative paths are
// ambiguous (home-relative per sshd vs cwd-relative per shell intuition) and
// "~user/" expansion is unsupported. Unset means the default
// ~/.ssh/authorized_keys.
func validateAuthorizedKeysFile(server, path string) []error {
	if path == "" {
		return nil
	}
	var errs []error
	if len(path) > maxAuthorizedKeysFileLen {
		errs = append(errs, fmt.Errorf("server %q: authorized_keys_file is too long (%d bytes, max %d)",
			server, len(path), maxAuthorizedKeysFileLen))
	}
	for _, r := range path {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			errs = append(errs, fmt.Errorf("server %q: authorized_keys_file contains control characters", server))
			break
		}
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
	granted := make(map[string]map[string]bool) // server -> user -> already granted
	for _, a := range c.Access {
		if !users[a.User] {
			errs = append(errs, fmt.Errorf("access: unknown user %q", a.User))
			continue
		}
		targets, tErrs := c.expandServers(a, servers)
		if len(tErrs) > 0 {
			errs = append(errs, tErrs...)
			continue
		}
		for _, srv := range targets {
			if !servers[srv] {
				errs = append(errs, fmt.Errorf("access for %q: unknown server %q", a.User, srv))
				continue
			}
			if granted[srv] == nil {
				granted[srv] = make(map[string]bool)
			}
			if granted[srv][a.User] { // multiple entries union silently
				continue
			}
			granted[srv][a.User] = true
			c.grants[srv] = append(c.grants[srv], a.User)
		}
	}
	return errs
}

// expandServers resolves an access entry's server list: ["*"] expands to
// every server (manifest order) minus the except names; explicit lists pass
// through untouched. Errors cover misused wildcard/except syntax; an entry
// that grants nothing is certainly a mistake.
func (c *Config) expandServers(a Access, servers map[string]bool) ([]string, []error) {
	if !slices.Contains(a.Servers, "*") {
		if len(a.Except) > 0 {
			return nil, []error{fmt.Errorf(`access for %q: except requires servers ["*"]`, a.User)}
		}
		return a.Servers, nil
	}
	if len(a.Servers) != 1 {
		return nil, []error{fmt.Errorf("access for %q: %q must be the only servers entry", a.User, "*")}
	}
	var errs []error
	excluded := make(map[string]bool, len(a.Except))
	for _, e := range a.Except {
		if !servers[e] {
			errs = append(errs, fmt.Errorf("access for %q: unknown except server %q", a.User, e))
			continue
		}
		excluded[e] = true // duplicates are tolerated, like grants unioning
	}
	if len(errs) > 0 {
		return nil, errs
	}
	var targets []string
	for i := range c.Servers {
		if !excluded[c.Servers[i].Name] {
			targets = append(targets, c.Servers[i].Name)
		}
	}
	if len(targets) == 0 {
		return nil, []error{fmt.Errorf("access for %q: wildcard grants no servers", a.User)}
	}
	return targets, nil
}

// DesiredFor returns the desired key set for a server: operator users' keys
// first (users order — operators are implicitly granted every server), then
// the keys of every user granted access to it (access order). Deterministic;
// a user is never emitted twice.
// An operator's implicit grant also wins over any except carve-out in that
// user's own access entries — operator means every server, unconditionally.
func (c *Config) DesiredFor(serverName string) []authkeys.Key {
	var keys []authkeys.Key
	asOperator := make(map[string]bool, len(c.operators))
	for _, name := range c.operators {
		asOperator[name] = true
		keys = append(keys, c.keysByUser[name]...)
	}
	for _, userName := range c.grants[serverName] {
		if asOperator[userName] { // redundant grant for an operator: already emitted
			continue
		}
		keys = append(keys, c.keysByUser[userName]...)
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

// Covers reports whether user's access — explicit grants, or a wildcard
// grant minus its except: list — covers server. server need not exist in
// the manifest yet: a wildcard grant covers future servers by design, so
// beyond the expanded grants (which only know the current fleet) the
// user's raw access entries are scanned for a wildcard not excepting
// server.
//
// Operators' implicit fleet-wide grant is deliberately excluded — check
// Operator first. Reading Covers(op, srv) == false as "no access" would
// contradict DesiredFor, which grants operators every server
// unconditionally.
func (c *Config) Covers(user, server string) bool {
	if slices.Contains(c.grants[server], user) {
		return true
	}
	for _, a := range c.Access {
		if a.User != user || !slices.Contains(a.Servers, "*") {
			continue
		}
		if !slices.Contains(a.Except, server) {
			return true
		}
	}
	return false
}

// ExceptCarveOut reports whether user's access deliberately excludes
// server via a wildcard except: list. Such a server is never re-granted by
// merge tooling — the carve-out is a statement of intent; an installed key
// there is drift.
//
// Callers must only ask about (user, server) pairs the grant union does
// not cover (i.e. after Covers returned false) — outside that context a
// wildcard user with an explicit grant of an excepted server would be
// misclassified.
func (c *Config) ExceptCarveOut(user, server string) bool {
	for _, a := range c.Access {
		if a.User != user || !slices.Contains(a.Servers, "*") {
			continue
		}
		if slices.Contains(a.Except, server) {
			return true
		}
	}
	return false
}
