package config

import "slices"

// GroupGrantsReaching names, in access order and once each, every group whose
// access: entry reaches server for user. A pair an access tombstone blocked
// reaches nothing (its member gets revoke's D1c note), and a server not in the
// manifest is reached by no group here: it has nothing to refuse.
func (c *Config) GroupGrantsReaching(user, server string) []string {
	if c.blocked[grantPair{user, server}] {
		return nil
	}
	i := slices.IndexFunc(c.Servers, func(s Server) bool { return s.Name == server })
	if i < 0 {
		return nil
	}
	var out []string
	for _, a := range c.Access {
		if a.Group == "" || !c.entryApplies(a, user) || !entryCovers(a, c.Servers[i]) || slices.Contains(out, a.Group) {
			continue
		}
		out = append(out, a.Group)
	}
	return out
}

// OwnExceptCarveOut is ExceptCarveOut limited to the user's own access:
// entries. A group's except: stops applying when the member leaves the group,
// so it is no memory for a personal trim (D1a). revoke asks this one before
// it skips a tombstone. adopt and reconcile keep ExceptCarveOut, because a
// member's key on a server the group excepts is drift today.
func (c *Config) OwnExceptCarveOut(user, server string) bool {
	return slices.ContainsFunc(c.Access, func(a Access) bool {
		return a.User == user && slices.Contains(a.Except, server)
	})
}
