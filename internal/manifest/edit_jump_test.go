package manifest

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRemoveAccessDropsWildcardLeftOnJumpOnly: a "*" entry whose only other
// reach is jump_only servers is deleted once its last real server goes:
// selectorReach asks config.SelectorMatches, which skips jump_only (spec S5).
func TestRemoveAccessDropsWildcardLeftOnJumpOnly(t *testing.T) {
	y := "users:\n  - {name: bob, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: edge, host: e, user: jump, jump_only: true}\n  - {name: web-1, host: w, user: deploy, via: edge}\n" +
		"access:\n  - {user: bob, servers: [\"*\"]}\n"
	mf, err := Load([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	r, err := mf.RemoveAccess("bob", []string{"web-1"})
	if err != nil {
		t.Fatal(err)
	}
	if r.EntriesRemoved != 1 || r.WildcardsRemoved != 1 || r.ServersExcepted != 0 {
		t.Errorf("RemoveAccess = %+v, want the * entry deleted", r)
	}
	out, err := mf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"*"`) || strings.Contains(string(out), "except") {
		t.Errorf("the * entry survived:\n%s", out)
	}
}
