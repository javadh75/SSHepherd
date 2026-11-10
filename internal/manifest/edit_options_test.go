package manifest

import (
	"slices"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRemoveAccessKeepsGrantOptions (spec S7): trimming a server from an
// entry with options: keeps them on what is left, after the except:
// RemoveAccess inserts right after servers:.
func TestRemoveAccessKeepsGrantOptions(t *testing.T) {
	f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\n"+
		"access:\n  - {user: bob, servers: [\"@web\", web-1], options: [no-pty]}\n")
	if _, err := f.RemoveAccess("bob", []string{"web-1"}); err != nil {
		t.Fatal(err)
	}
	out, cfg := encodeParsed(t, f)
	inOrder(t, out, `{user: bob, servers: ["@web"], except: [web-1], options: [no-pty]}`)
	if d := cfg.DesiredFor("web-2"); len(d) != 1 || !slices.Equal(d[0].Options, []string{"no-pty"}) {
		t.Errorf("web-2 desired = %+v, want bob with no-pty", d)
	}
}
