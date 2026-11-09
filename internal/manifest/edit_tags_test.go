package manifest

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagEditFixture: bob holds @web and db-1 mixed, alice a block-style @db,
// carol a wildcard. web-1 and web-2 are tagged web; db-1 and db-2 db.
func tagEditFixture(tb testing.TB) string {
	tb.Helper()
	return `# fleet manifest
users:
  - {name: alice, keys: ["` + testkeys.Line(tb, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(tb, 4) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(tb, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]} # front
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
  - {name: db-1, host: 10.0.0.9, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.8, user: deploy, tags: [db]}
access:
  # bob: the web tier and a db
  - user: bob
    servers: ["@web", db-1] # reviewed 2026-10
  # alice: every db
  - user: alice
    servers:
      - "@db"
  # carol: everywhere
  - user: carol
    servers: ["*"]
# end of manifest
`
}

func TestRemoveAccessSelectors(t *testing.T) {
	for _, tc := range []struct {
		name, user string
		servers    []string
		want       AccessRemoval
		yaml       string
		grants     []string
	}{
		{"tag member: except created after servers, flow", "bob", []string{"web-2"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 1},
			"    servers: [\"@web\", db-1] # reviewed 2026-10\n    except: [web-2]\n", []string{"web-1", "db-1"}},
		{"literal item only", "bob", []string{"db-1"}, AccessRemoval{EntriesChanged: 1},
			"    servers: [\"@web\"] # reviewed 2026-10\n", []string{"web-1", "web-2"}},
		{"tag member and literal together", "bob", []string{"web-1", "db-1"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 1},
			"    servers: [\"@web\"] # reviewed 2026-10\n    except: [web-1]\n", []string{"web-2"}},
		{"block style: except stays block", "alice", []string{"db-1"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 1},
			"    servers:\n      - \"@db\"\n    except:\n      - db-1\n", []string{"db-2"}},
		{"wildcard behaves as before", "carol", []string{"db-1"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 1},
			"    servers: [\"*\"]\n    except: [db-1]\n", []string{"web-1", "web-2", "db-2"}},
		{"name kept: tag fully excepted, entry stays", "bob", []string{"web-1", "web-2"},
			AccessRemoval{EntriesChanged: 1, ServersExcepted: 2},
			"    servers: [\"@web\", db-1] # reviewed 2026-10\n    except: [web-1, web-2]\n", []string{"db-1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := loadFixture(t, tagEditFixture(t))
			r, err := f.RemoveAccess(tc.user, tc.servers)
			if err != nil {
				t.Fatalf("RemoveAccess: %v", err)
			}
			if r != tc.want {
				t.Errorf("AccessRemoval = %+v, want %+v", r, tc.want)
			}
			out, cfg := encodeParsed(t, f)
			inOrder(t, out, tc.yaml)
			if got := grantsOf(cfg, tc.user); !slices.Equal(got, tc.grants) {
				t.Errorf("grants = %v, want %v", got, tc.grants)
			}
			inOrder(t, out, "tags: [web]} # front\n", "# bob: the web tier", "# alice: every db", "# carol: everywhere", "# end of manifest")
		})
	}
}

// TestRemoveAccessTagMemberAlsoNamed: a server both named and reached by a
// tag loses the name and gains except:, or the entry would still reach it.
func TestRemoveAccessTagMemberAlsoNamed(t *testing.T) {
	f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\n"+
		"access:\n  - {user: bob, servers: [\"@web\", web-1]}\n")
	r, err := f.RemoveAccess("bob", []string{"web-1"})
	if err != nil || r != (AccessRemoval{EntriesChanged: 1, ServersExcepted: 1}) {
		t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
	}
	out, cfg := encodeParsed(t, f)
	inOrder(t, out, "{user: bob, servers: [\"@web\"], except: [web-1]}")
	if got := grantsOf(cfg, "bob"); !slices.Equal(got, []string{"web-2"}) {
		t.Errorf("grants = %v, want [web-2]", got)
	}
}

// TestRemoveAccessTagEntryDeleted: nothing named and every tag member
// excepted: the entry goes, its head comment rescued, no wildcard counted.
func TestRemoveAccessTagEntryDeleted(t *testing.T) {
	f := loadFixture(t, tagEditFixture(t))
	r, err := f.RemoveAccess("alice", []string{"db-1", "db-2"})
	if err != nil || r != (AccessRemoval{EntriesRemoved: 1}) {
		t.Fatalf("RemoveAccess = (%+v, %v), want one entry removed, no wildcard", r, err)
	}
	out, cfg := encodeParsed(t, f)
	if strings.Contains(out, "- user: alice") || len(grantsOf(cfg, "alice")) != 0 {
		t.Errorf("alice's entry survived:\n%s", out)
	}
	inOrder(t, out, "# alice: every db\n  # carol: everywhere\n  - user: carol\n")
	checkGolden(t, "edit_remove_access_tags_deleted.golden", []byte(out))
}

// TestRemoveAccessMixedFullyTrimmed: the name goes and every tag member is
// excepted, so nothing is left: the entry is deleted.
func TestRemoveAccessMixedFullyTrimmed(t *testing.T) {
	f := loadFixture(t, tagEditFixture(t))
	r, err := f.RemoveAccess("bob", []string{"web-1", "web-2", "db-1"})
	if err != nil || r != (AccessRemoval{EntriesRemoved: 1}) {
		t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
	}
	out, _ := encodeParsed(t, f)
	if strings.Contains(out, "- user: bob") || strings.Contains(out, "reviewed 2026-10") {
		t.Errorf("bob's entry survived:\n%s", out)
	}
}

// TestRemoveAccessTagNotCovered: a server the entry neither names nor
// selects is left alone, byte for byte.
func TestRemoveAccessTagNotCovered(t *testing.T) {
	want, err := loadFixture(t, tagEditFixture(t)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	f := loadFixture(t, tagEditFixture(t))
	r, err := f.RemoveAccess("alice", []string{"web-1"})
	if err != nil || r != (AccessRemoval{}) {
		t.Fatalf("RemoveAccess = (%+v, %v), want nothing changed", r, err)
	}
	if out, _ := encodeParsed(t, f); out != string(want) {
		t.Errorf("an uncovered entry was edited:\n%s", out)
	}
}

// TestRemoveAccessSecondTrimDeletesEntry: except: from the first trim stays
// until the last one removes the entry; each run re-parses, as revoke does.
func TestRemoveAccessSecondTrimDeletesEntry(t *testing.T) {
	f := loadFixture(t, tagEditFixture(t))
	if _, err := f.RemoveAccess("alice", []string{"db-1"}); err != nil {
		t.Fatal(err)
	}
	out, _ := encodeParsed(t, f)
	second := loadFixture(t, out)
	r, err := second.RemoveAccess("alice", []string{"db-2"})
	if err != nil || r != (AccessRemoval{EntriesRemoved: 1}) {
		t.Fatalf("second trim = (%+v, %v)", r, err)
	}
	if last, _ := encodeParsed(t, second); strings.Contains(last, "- user: alice") {
		t.Errorf("the entry survived:\n%s", last)
	}
}

// TestRemoveAccessTagGolden: one File, the three shapes trimmed, one Encode.
func TestRemoveAccessTagGolden(t *testing.T) {
	f := loadFixture(t, tagEditFixture(t))
	for _, c := range []struct {
		user    string
		servers []string
	}{{"bob", []string{"web-2", "db-1"}}, {"alice", []string{"db-2"}}, {"carol", []string{"web-1"}}} {
		if _, err := f.RemoveAccess(c.user, c.servers); err != nil {
			t.Fatalf("RemoveAccess(%s): %v", c.user, err)
		}
	}
	out, _ := encodeParsed(t, f)
	checkGolden(t, "edit_remove_access_tags.golden", []byte(out))
}
