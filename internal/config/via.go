package config

import (
	"fmt"
	"slices"
	"strings"
)

// MaxViaDepth is the most bastions a server may sit behind (spec S5): a
// three-hop chain already uses most of the 30-second per-server budget.
const MaxViaDepth = 3

// ServerNamed returns the server called name.
func (c *Config) ServerNamed(name string) (Server, bool) {
	i := slices.IndexFunc(c.Servers, func(s Server) bool { return s.Name == name })
	if i < 0 {
		return Server{}, false
	}
	return c.Servers[i], true
}

// Chain lists the bastions s is reached through, root first: the one dialed
// directly leads and s's own via comes last. Nil for a direct server. It
// walks the whole fleet, so it answers for any server a run selects, and it
// stops after MaxViaDepth+1 names, so even an unvalidated manifest cannot
// make it loop.
func (c *Config) Chain(s Server) []string {
	var out []string
	for v := s.Via; v != "" && len(out) <= MaxViaDepth; {
		out = append(out, v)
		hop, ok := c.ServerNamed(v)
		if !ok {
			break
		}
		v = hop.Via
	}
	slices.Reverse(out)
	return out
}

// Dependents lists, in servers: order, every server whose via is name: the
// servers that bastion forwards to directly.
func (c *Config) Dependents(name string) []Server {
	var out []Server
	for _, s := range c.Servers {
		if s.Via == name {
			out = append(out, s)
		}
	}
	return out
}

// jumpOnly reports whether server is a jump_only bastion, which no grant
// reaches.
func (c *Config) jumpOnly(server string) bool {
	s, ok := c.ServerNamed(server)
	return ok && s.JumpOnly
}

// validateVia checks every via: (spec S5): it names another server of the
// manifest, its chain does not loop, and the chain is at most MaxViaDepth
// bastions long. A clean fleet then warns for each jump_only server that no
// via names.
func (c *Config) validateVia() []error {
	var errs []error
	for _, s := range c.Servers {
		_, known := c.ServerNamed(s.Via)
		switch {
		case s.Via == "":
		case s.Via == s.Name:
			errs = append(errs, fmt.Errorf("server %q: via names the server itself", s.Name))
		case !known:
			errs = append(errs, fmt.Errorf("server %q: unknown via %q", s.Name, s.Via))
		}
	}
	if len(errs) > 0 {
		return errs // a chain through an unknown name cannot be walked
	}
	for _, s := range c.Servers {
		if loop := c.viaLoop(s); loop != nil {
			errs = append(errs, fmt.Errorf("server %q: via chain loops (%s)", s.Name, strings.Join(loop, " → ")))
			continue
		}
		if chain := c.Chain(s); len(chain) > MaxViaDepth {
			errs = append(errs, fmt.Errorf("server %q: via chain is %d hops deep (%s); at most %d",
				s.Name, len(chain), strings.Join(chain, " → "), MaxViaDepth))
		}
	}
	if len(errs) == 0 {
		c.warnUnusedJumpOnly()
	}
	return errs
}

// viaLoop follows s's via chain and returns the walk up to the first name it
// repeats; nil when the chain ends.
func (c *Config) viaLoop(s Server) []string {
	path := []string{s.Name}
	seen := map[string]bool{s.Name: true}
	for v := s.Via; v != ""; {
		path = append(path, v)
		if seen[v] {
			return path
		}
		seen[v] = true
		hop, _ := c.ServerNamed(v) // known: validateVia checked every via first
		v = hop.Via
	}
	return nil
}

// warnUnusedJumpOnly records jump_only_unused for each jump_only server no
// via names: nothing connects through it, so nothing checks it either.
func (c *Config) warnUnusedJumpOnly() {
	for _, s := range c.Servers {
		if s.JumpOnly && len(c.Dependents(s.Name)) == 0 {
			c.warn(ManifestWarning{Kind: WarnJumpOnlyUnused, Server: s.Name, Message: fmt.Sprintf(
				"server %q: jump_only but no server has via: %s; nothing connects through it and nothing checks it", s.Name, s.Name)})
		}
	}
}
