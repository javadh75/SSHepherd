package apply

import (
	"strings"
	"testing"
)

// TestEditHeaderCountsGroups: a member of two groups reads "2 groups"; with
// none the line is the one every existing golden pins.
func TestEditHeaderCountsGroups(t *testing.T) {
	for _, tc := range []struct {
		name   string
		groups []string
		want   string
	}{
		{"none", nil, "manifest edit: remove user alice (1 key, 0 access grants) — 1 server affected\n"},
		{"one", []string{"web-team"}, "manifest edit: remove user alice (1 key, 0 access grants, 1 group) — 1 server affected\n"},
		{"two", []string{"web-team", "dba"}, "manifest edit: remove user alice (1 key, 0 access grants, 2 groups) — 1 server affected\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			RenderEditHeader(&b, EditSummary{Edits: []Edit{{Kind: EditRemoveUser, User: "alice", Keys: 1, Groups: tc.groups}}, Affected: 1}, RenderOptions{})
			if b.String() != tc.want {
				t.Errorf("got %q\nwant %q", b.String(), tc.want)
			}
		})
	}
}
