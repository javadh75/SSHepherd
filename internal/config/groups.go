package config

import "fmt"

// validateGroups checks groups: each name has tagShape and is unique, and
// every member is a known user, listed once. An empty group is valid with a
// warning, so revoking its last member never breaks the manifest. It records
// c.members for access: entries, every named group included so one bad name
// is reported once.
func (c *Config) validateGroups() []error {
	var errs []error
	users := make(map[string]bool, len(c.Users))
	for _, u := range c.Users {
		users[u.Name] = true
	}
	c.members = make(map[string][]string, len(c.Groups))
	for _, g := range c.Groups {
		if !tagShape.MatchString(g.Name) {
			errs = append(errs, fmt.Errorf("group %q: name is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters", g.Name))
		}
		if _, dup := c.members[g.Name]; dup {
			errs = append(errs, fmt.Errorf("duplicate group %q", g.Name))
			continue
		}
		c.members[g.Name] = g.Members
		errs = append(errs, memberErrors(g, users)...)
		if len(g.Members) == 0 {
			c.warn(ManifestWarning{Kind: WarnEmptyGroup, Message: fmt.Sprintf("group %q has no members; its grants add nothing", g.Name)})
		}
	}
	return errs
}

// memberErrors checks one group's members: each is a known user, listed once.
func memberErrors(g Group, users map[string]bool) []error {
	var errs []error
	seen := make(map[string]bool, len(g.Members))
	for _, m := range g.Members {
		switch {
		case !users[m]:
			errs = append(errs, fmt.Errorf("group %q: unknown member %q", g.Name, m))
		case seen[m]:
			errs = append(errs, fmt.Errorf("group %q: member %q is repeated", g.Name, m))
		}
		seen[m] = true
	}
	return errs
}

// entrySubjectError checks who access entry i grants to: exactly one of
// user: and group:, naming something that exists.
func (c *Config) entrySubjectError(i int, a Access, users map[string]bool) error {
	switch {
	case (a.User == "") == (a.Group == ""):
		return fmt.Errorf("access[%d]: set exactly one of user or group", i)
	case a.Group != "":
		if _, ok := c.members[a.Group]; !ok {
			return fmt.Errorf("access: unknown group %q", a.Group)
		}
	case !users[a.User]:
		return fmt.Errorf("access: unknown user %q", a.User)
	}
	return nil
}

// entryUsers lists whom access entry a grants to: its user, or its group's
// members in member order.
func (c *Config) entryUsers(a Access) []string {
	if a.Group != "" {
		return c.members[a.Group]
	}
	return []string{a.User}
}

// entryLabel names an access entry in messages: `"x"` for a user entry and
// `group "x"` for a group entry.
func entryLabel(a Access) string {
	if a.Group != "" {
		return fmt.Sprintf("group %q", a.Group)
	}
	return fmt.Sprintf("%q", a.User)
}
