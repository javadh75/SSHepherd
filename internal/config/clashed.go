package config

import "slices"

// ClashedKeys lists the fingerprints a restriction conflict names on server
// (spec 2026-11-08 S7 Mechanics): every key of each user whose grants there
// disagree. Audit skips their options comparison, because there is no one
// desired set; presence is still compared. Nil when no restriction conflict
// names server.
func (c *Config) ClashedKeys(server string) map[string]bool {
	var out map[string]bool
	for _, cf := range c.conflicts {
		if cf.Kind != ConflictRestriction || !slices.Contains(cf.Servers, server) {
			continue
		}
		if out == nil {
			out = make(map[string]bool)
		}
		for _, k := range c.keysByUser[cf.User] {
			out[k.Fingerprint] = true
		}
	}
	return out
}
