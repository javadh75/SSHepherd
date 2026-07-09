package sshcfg

import "strings"

// matchGlob implements OpenSSH host-pattern matching: '*' matches any run of
// characters (including none), '?' matches exactly one. Case-sensitive,
// byte-wise (host aliases are ASCII in practice). Iterative with single-star
// backtracking, so it cannot blow the stack on hostile patterns.
func matchGlob(pattern, s string) bool {
	pi, si := 0, 0
	star, starSi := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]):
			pi++
			si++
		case pi < len(pattern) && pattern[pi] == '*':
			star, starSi = pi, si
			pi++
		case star >= 0:
			starSi++
			si = starSi
			pi = star + 1
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// matchPatterns applies a Host line's pattern list to an alias: any matching
// negated ("!") pattern excludes the alias outright; otherwise at least one
// positive pattern must match. This is OpenSSH's rule.
func matchPatterns(patterns []string, alias string) bool {
	matched := false
	for _, p := range patterns {
		if neg, ok := strings.CutPrefix(p, "!"); ok {
			if matchGlob(neg, alias) {
				return false
			}
			continue
		}
		if matchGlob(p, alias) {
			matched = true
		}
	}
	return matched
}
