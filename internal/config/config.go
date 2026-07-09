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

	"gopkg.in/yaml.v3"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// User is a person (or role) and the public keys that identify them.
type User struct {
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"` // docs only, never sent to a server
	Comment     string   `yaml:"comment"`     // written as the key comment by the apply slice
	Keys        []string `yaml:"keys"`
}

// Server is one machine in the fleet and the account we manage on it.
type Server struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"` // docs only
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"` // defaults to 22
	User        string `yaml:"user"`
}

// Access grants one user access to a list of servers.
type Access struct {
	User    string   `yaml:"user"`
	Servers []string `yaml:"servers"`
}

// Config is the parsed, validated manifest.
type Config struct {
	Users   []User   `yaml:"users"`
	Servers []Server `yaml:"servers"`
	Access  []Access `yaml:"access"`

	// Built during validation.
	keysByUser map[string][]authkeys.Key // user name -> parsed keys, manifest order
	owners     map[string]User           // fingerprint -> owning user
	grants     map[string][]string       // server name -> user names, access order
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
	seen := make(map[string]bool)
	for _, u := range c.Users {
		if u.Name == "" {
			errs = append(errs, errors.New("user with empty name"))
			continue
		}
		if seen[u.Name] {
			errs = append(errs, fmt.Errorf("duplicate user %q", u.Name))
			continue
		}
		seen[u.Name] = true
		for i, line := range u.Keys {
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
	}
	return errs
}

func (c *Config) validateServers() []error {
	var errs []error
	seen := make(map[string]bool)
	for i := range c.Servers {
		s := &c.Servers[i]
		if s.Name == "" {
			errs = append(errs, errors.New("server with empty name"))
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
		for _, srv := range a.Servers {
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
