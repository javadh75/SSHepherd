package config

import "slices"

// GrantCount is the number of (user, server) pairs the render would write:
// every operator on every server, plus each granted user with at least one
// key. An operator also named in access: is counted once.
func (c *Config) GrantCount() int {
	n := 0
	for _, s := range c.Servers {
		n += len(c.operators)
		for _, user := range c.grants[s.Name] {
			if !slices.Contains(c.operators, user) && len(c.keysByUser[user]) > 0 {
				n++
			}
		}
	}
	return n
}
