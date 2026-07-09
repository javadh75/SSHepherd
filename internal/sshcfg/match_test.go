package sshcfg

import "testing"

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"", "", true},
		{"", "x", false},
		{"web-1", "web-1", true},
		{"web-1", "web-10", false},
		{"web-*", "web-1", true},
		{"web-*", "db-1", false},
		{"web-?", "web-1", true},
		{"web-?", "web-10", false},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "abc", true},
		{"a*b*c", "ac", false},
		{"*a*", "bab", true},
	}
	for _, tt := range tests {
		if got := matchGlob(tt.pattern, tt.s); got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.s, got, tt.want)
		}
	}
}

func TestMatchPatterns(t *testing.T) {
	tests := []struct {
		patterns []string
		alias    string
		want     bool
	}{
		{[]string{"web-*"}, "web-1", true},
		{[]string{"web-*", "!web-3"}, "web-1", true},
		{[]string{"web-*", "!web-3"}, "web-3", false}, // negation excludes
		{[]string{"!web-3", "web-*"}, "web-3", false}, // order irrelevant
		{[]string{"!web-3"}, "web-1", false},          // nothing positive matched
		{[]string{"a", "b"}, "b", true},
		{[]string{"*"}, "whatever", true},
	}
	for _, tt := range tests {
		if got := matchPatterns(tt.patterns, tt.alias); got != tt.want {
			t.Errorf("matchPatterns(%v, %q) = %v, want %v", tt.patterns, tt.alias, got, tt.want)
		}
	}
}
