package config

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// tagSelectorPrefix starts an @tag selector in an access: servers list.
const tagSelectorPrefix = "@"

// tagShape is a valid tag: lowercase, digits, '.', '_' and '-', starting with
// a letter or digit, at most 63 characters.
var tagShape = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// IsSelector reports whether an access: servers item selects servers ("*" or
// "@tag") instead of naming one.
func IsSelector(item string) bool { return item == "*" || isTagSelector(item) }

func isTagSelector(item string) bool { return strings.HasPrefix(item, tagSelectorPrefix) }

// SelectorMatches reports whether selector item reaches server s: "*" reaches
// every server, "@tag" those carrying the tag. A server name is not a
// selector and matches nothing here.
func SelectorMatches(item string, s Server) bool {
	if item == "*" {
		return true
	}
	tag, ok := strings.CutPrefix(item, tagSelectorPrefix)
	return ok && slices.Contains(s.Tags, tag)
}

// ServerNameIssue reports why name cannot be a server name; empty means it
// can. It is ServerFieldIssue plus the names selector syntax reserves.
// Exported so import skips such an alias with a warning instead of generating
// a manifest that fails to load.
func ServerNameIssue(name string) string {
	if issue := ServerFieldIssue(name); issue != "" {
		return issue
	}
	switch {
	case name == "*":
		return "is reserved for wildcard grants"
	case isTagSelector(name):
		return "is reserved for tag selectors"
	}
	return ""
}

// validateTags checks one server's tags: each has tagShape, none repeats.
func validateTags(s *Server) []error {
	var errs []error
	seen := make(map[string]bool, len(s.Tags))
	for _, tag := range s.Tags {
		if !tagShape.MatchString(tag) {
			errs = append(errs, fmt.Errorf("server %q: tag %q is not valid: want lowercase letters, digits, '.', '_' or '-', starting with a letter or digit, at most 63 characters", s.Name, tag))
			continue
		}
		if seen[tag] {
			errs = append(errs, fmt.Errorf("server %q: tag %q is repeated", s.Name, tag))
		}
		seen[tag] = true
	}
	return errs
}

// grantPair is one (user, server) grant.
type grantPair struct{ user, server string }

// entryApplies reports whether access entry a grants to user.
func entryApplies(a Access, user string) bool { return a.User == user }

// entryCovers reports whether entry a reaches server s: named, or selected
// and not excepted. A server not in the manifest is passed as Server{Name: n}:
// it carries no tags, so only "*" can reach it.
func entryCovers(a Access, s Server) bool {
	if slices.Contains(a.Except, s.Name) {
		return false
	}
	return slices.ContainsFunc(a.Servers, func(item string) bool { return item == s.Name || SelectorMatches(item, s) })
}

// entryDirect reports whether entry a reaches server by name or through "*",
// the two forms a tombstone contradicts outright (a D29 policy conflict).
func entryDirect(a Access, server string) bool {
	if slices.Contains(a.Except, server) {
		return false
	}
	return slices.Contains(a.Servers, server) || slices.Contains(a.Servers, "*")
}
