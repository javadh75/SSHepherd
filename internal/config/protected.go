package config

import (
	"fmt"
	"slices"
)

// FleetWide reports whether user holds the operator's implicit grant of every
// server: operator: true with no servers: ["*"] entry of their own. Such an
// entry replaces the implicit grant, which is what makes except: work for an
// operator; the user is then an ordinary grantee and still protected (spec
// S4, D21). A group's "*" entry does not count.
func (c *Config) FleetWide(user string) bool { return c.fleetWide[user] }

// fleetWideOperators is c.operators minus each operator with a "*" user:
// entry. A group entry's empty a.User deletes nothing.
func (c *Config) fleetWideOperators() map[string]bool {
	out := make(map[string]bool, len(c.operators))
	for _, name := range c.operators {
		out[name] = true
	}
	for _, a := range c.Access {
		if slices.Contains(a.Servers, "*") {
			delete(out, a.User)
		}
	}
	return out
}

// warnRedundantGrant records that a user: entry cannot narrow a fleet-wide
// operator: an @tag or literal entry adds nothing (spec S4). A group entry
// never warns: it still grants its other members.
func (c *Config) warnRedundantGrant(a Access) {
	if !c.fleetWide[a.User] {
		return
	}
	c.warn(ManifestWarning{Kind: WarnOperatorGrantRedundant, User: a.User, Message: fmt.Sprintf(
		"operator %q: this access entry adds nothing; operator: true still grants every server", a.User)})
}
