package config

// GrantCount is the number of (user, server) pairs the render would write:
// every fleet-wide operator on every server, plus each other granted user
// with at least one key. A fleet-wide operator also named in access: is
// counted once. A jump_only server renders nothing and counts nothing.
func (c *Config) GrantCount() int {
	n := 0
	for _, s := range c.Servers {
		if s.JumpOnly {
			continue // no grant reaches it, the implicit one included
		}
		n += len(c.fleetWide)
		for _, user := range c.grants[s.Name] {
			if !c.fleetWide[user] && len(c.keysByUser[user]) > 0 {
				n++
			}
		}
	}
	return n
}
