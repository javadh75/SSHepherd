package authkeys

import (
	"slices"
	"testing"
)

// TestIsRestrictionIsTheSpecList (spec S7 Validation): exactly these options
// may be added by a grant. The table decides, so a restricting option joins
// the list only by being added to the table.
func TestIsRestrictionIsTheSpecList(t *testing.T) {
	want := []string{"command", "expiry-time", "from", "no-agent-forwarding", "no-port-forwarding", "no-pty",
		"no-user-rc", "no-x11-forwarding", "permitlisten", "permitopen", "restrict", "touch-required", "verify-required"}
	var got []string
	for name, s := range options {
		opt := name
		if s.takesValue {
			opt += `="x"`
		}
		if IsRestriction(opt) {
			got = append(got, name)
		}
	}
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Errorf("restrictions = %v\n          want %v", got, want)
	}
}

func TestIsRestriction(t *testing.T) {
	for opt, want := range map[string]bool{
		`FROM="10.0.0.0/8"`:  true, // names are case-insensitive
		"No-Pty":             true,
		"cert-authority":     false, // a grant must not make a key a certificate authority
		`principals="ops"`:   false,
		"pty":                false, // a re-enabler widens
		"no-touch-required":  false,
		"touch-required":     true,  // review F025: requires the user-presence touch
		"no-verify-required": false, // neutral: the default
		`environment="A=b"`:  false, // neutral
		`tunnel="0"`:         false,
		"bogus":              false,
	} {
		if got := IsRestriction(opt); got != want {
			t.Errorf("IsRestriction(%q) = %v, want %v", opt, got, want)
		}
	}
}

func TestSameOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b []string
		want bool
	}{
		{"both empty", nil, []string{}, true},
		{"order", []string{"no-pty", `from="10.0.0.0/8"`}, []string{`from="10.0.0.0/8"`, "no-pty"}, true},
		{"name case", []string{`FROM="a"`, "No-Pty"}, []string{`from="a"`, "no-pty"}, true},
		{"a repeat", []string{"no-pty", "no-pty"}, []string{"no-pty"}, true},
		{"value case matters", []string{`from="A"`}, []string{`from="a"`}, false},
		{"one more", []string{"no-pty"}, []string{"no-pty", "restrict"}, false},
		{"none and some", nil, []string{"no-pty"}, false},
	} {
		if got := SameOptions(tc.a, tc.b); got != tc.want {
			t.Errorf("%s: SameOptions(%q, %q) = %v, want %v", tc.name, tc.a, tc.b, got, tc.want)
		}
	}
}
