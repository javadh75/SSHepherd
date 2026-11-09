package manifest

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// editFixture is a hand-maintained manifest exercising every comment
// position the edit rules name: a file header on the users: key, a section
// heading above the first users: item, head comments on keys: items, line
// comments, a flow-style keys: list, head comments on access: items (first
// and last), and a document footer.
func editFixture(tb testing.TB) string {
	tb.Helper()
	return `# fleet manifest — hand-maintained
# owner: platform team
users:
  # --- contractors ---
  - name: alice # contractor until 2026-12
    keys:
      # alice laptop
      - ` + testkeys.Line(tb, 2) + ` alice@laptop
      # alice desktop
      - ` + testkeys.Line(tb, 3) + ` alice@desk
  # --- staff ---
  - name: bob
    keys: ["` + testkeys.Line(tb, 4) + `"]
  - name: ops
    # break-glass account
    operator: true # vault-held
    keys:
      - ` + testkeys.Line(tb, 1) + ` ops@vault
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  # alice: web only
  - user: alice
    servers: [web-1]
  - user: bob
    servers: [web-1, db-1]
  # alice db access (temporary)
  - user: alice
    servers: [db-1]
# reviewed 2026-10-01
`
}

// keyFP is a test key's fingerprint.
func keyFP(tb testing.TB, seed byte) string {
	tb.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(tb, seed))
	if err != nil || k == nil {
		tb.Fatalf("keyFP(%d): %v", seed, err)
	}
	return k.Fingerprint
}

func loadFixture(t *testing.T, in string) *File {
	t.Helper()
	f, err := Load([]byte(in))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return f
}

// encodeParsed encodes f and re-parses the output: every edited manifest
// must satisfy config.Parse.
func encodeParsed(t *testing.T, f *File) (string, *config.Config) {
	t.Helper()
	out, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("edited manifest rejected by config.Parse: %v\n%s", err, out)
	}
	return string(out), cfg
}

// inOrder asserts each want occurs in s, in the given order.
func inOrder(t *testing.T, s string, wants ...string) {
	t.Helper()
	at := 0
	for _, w := range wants {
		i := strings.Index(s[at:], w)
		if i < 0 {
			t.Fatalf("output lacks %q after offset %d:\n%s", w, at, s)
		}
		at += i + len(w)
	}
}

func TestRemoveUserGolden(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	r, err := f.RemoveUser("alice")
	if err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if r.Keys != 2 || r.Grants != 2 {
		t.Errorf("UserRemoval = %+v, want 2 keys and 2 grants", r)
	}
	out, cfg := encodeParsed(t, f)
	if _, ok := cfg.OwnerOf(keyFP(t, 2)); ok {
		t.Error("alice's key survived RemoveUser")
	}
	for _, u := range cfg.Users {
		if u.Name == "alice" {
			t.Error("alice's users: entry survived")
		}
	}
	for _, a := range cfg.Access {
		if a.User == "alice" {
			t.Error("an access: entry for alice survived")
		}
	}
	// The file header stays first; the first item's section heading moves
	// to bob (prepended to bob's own); the first access item's head comment
	// moves to bob's grant; the last access item's comment lands in the
	// section footer, before the document footer.
	inOrder(t, out,
		"# fleet manifest — hand-maintained\n# owner: platform team\nusers:\n",
		"  # --- contractors ---\n  # --- staff ---\n  - name: bob\n",
		"access:\n  # alice: web only\n  - user: bob\n",
		"# alice db access (temporary)\n# reviewed 2026-10-01\n")
	for _, gone := range []string{"alice laptop", "alice desktop", "contractor until 2026-12"} {
		if strings.Contains(out, gone) {
			t.Errorf("a comment inside alice's entry survived (%q):\n%s", gone, out)
		}
	}
	checkGolden(t, "edit_remove_user.golden", []byte(out))
}

// TestRemoveUserLastRescuesToFooter: the last users: item has no next
// sibling, so its head comment rides the users: key's foot comment —
// emitted right after the remaining users, never above the file header.
func TestRemoveUserLastRescuesToFooter(t *testing.T) {
	f2 := loadFixture(t, strings.Replace(editFixture(t), "  - name: ops\n", "  # ops: shared account\n  - name: ops\n", 1))
	if _, err := f2.RemoveUser("ops"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	out, _ := encodeParsed(t, f2)
	inOrder(t, out, "# fleet manifest — hand-maintained\n", "  - name: bob\n", "# ops: shared account\n", "servers:\n")
	if strings.Index(out, "# ops: shared account") < strings.Index(out, "users:") {
		t.Errorf("rescued comment landed above the file header:\n%s", out)
	}
}

// TestRemoveOnlyItemsLeaveFlowEmpty: removing the only item of a section
// (or of a keys: list) leaves an empty flow sequence, block or flow source.
func TestRemoveOnlyItemsLeaveFlowEmpty(t *testing.T) {
	block := `users:
  - name: bob
    keys:
      - ` + testkeys.Line(t, 4) + `
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - user: bob
    servers: [web-1]
`
	flow := `users: [{name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}]
servers: [{name: web-1, host: 10.0.0.1, user: deploy}]
access: [{user: bob, servers: [web-1]}]
`
	for name, in := range map[string]string{"block": block, "flow": flow} {
		t.Run(name+" user", func(t *testing.T) {
			f := loadFixture(t, in)
			if _, err := f.RemoveUser("bob"); err != nil {
				t.Fatalf("RemoveUser: %v", err)
			}
			out, cfg := encodeParsed(t, f)
			if !strings.Contains(out, "users: []") || !strings.Contains(out, "access: []") {
				t.Errorf("want empty flow users/access:\n%s", out)
			}
			if len(cfg.Users) != 0 || len(cfg.Access) != 0 || len(cfg.Servers) != 1 {
				t.Errorf("config = %+v, want only the server left", cfg)
			}
		})
		t.Run(name+" key", func(t *testing.T) {
			f := loadFixture(t, in)
			owner, last, err := f.RemoveKey(keyFP(t, 4))
			if err != nil || owner != "bob" || !last {
				t.Fatalf("RemoveKey = (%q, %v, %v), want (bob, true, nil)", owner, last, err)
			}
			out, cfg := encodeParsed(t, f)
			if !strings.Contains(out, "keys: []") {
				t.Errorf("want keys: []:\n%s", out)
			}
			if len(cfg.Users) != 1 || len(cfg.Users[0].Keys) != 0 {
				t.Errorf("users = %+v, want bob with no keys", cfg.Users)
			}
		})
	}
}

// TestRemoveKeyPositions: first / last key of a block list; the removed
// line's head comment goes with it (never re-labels the survivor), and
// options/comments/spacing never matter for the match.
func TestRemoveKeyPositions(t *testing.T) {
	t.Run("first", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		owner, last, err := f.RemoveKey(keyFP(t, 2))
		if err != nil || owner != "alice" || last {
			t.Fatalf("RemoveKey = (%q, %v, %v), want (alice, false, nil)", owner, last, err)
		}
		out, cfg := encodeParsed(t, f)
		if strings.Contains(out, "alice laptop") {
			t.Errorf("the removed key's head comment survived:\n%s", out)
		}
		inOrder(t, out, "    keys:\n      # alice desktop\n      - "+testkeys.Line(t, 3))
		if _, ok := cfg.OwnerOf(keyFP(t, 2)); ok {
			t.Error("removed key still owned")
		}
	})
	t.Run("last", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if _, last, err := f.RemoveKey(keyFP(t, 3)); err != nil || last {
			t.Fatalf("RemoveKey: last=%v err=%v", last, err)
		}
		out, _ := encodeParsed(t, f)
		if strings.Contains(out, "alice desktop") {
			t.Errorf("the removed key's head comment survived:\n%s", out)
		}
		inOrder(t, out, "      # alice laptop\n      - "+testkeys.Line(t, 2)+" alice@laptop\n  # --- staff ---\n")
	})
	t.Run("options and odd spacing still match", func(t *testing.T) {
		in := `users:
  - name: bob
    keys:
      - 'from="10.0.0.1"   ` + testkeys.Line(t, 4) + `   bob@x'
      - ` + testkeys.Line(t, 5) + `
`
		f := loadFixture(t, in)
		if owner, _, err := f.RemoveKey(keyFP(t, 4)); err != nil || owner != "bob" {
			t.Fatalf("RemoveKey = (%q, %v)", owner, err)
		}
		_, cfg := encodeParsed(t, f)
		if len(cfg.Users[0].Keys) != 1 {
			t.Errorf("keys = %v, want only key 5", cfg.Users[0].Keys)
		}
	})
}

// TestRemoveOperatorLastKeyClearsFlag: operator: true with no keys fails
// validation, so the caller clears the flag first; skipping that makes
// Encode's self-check fail (an internal error, nothing written).
func TestRemoveOperatorLastKeyClearsFlag(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	if err := f.SetOperator("ops", false); err != nil {
		t.Fatalf("SetOperator: %v", err)
	}
	owner, last, err := f.RemoveKey(keyFP(t, 1))
	if err != nil || owner != "ops" || !last {
		t.Fatalf("RemoveKey = (%q, %v, %v), want (ops, true, nil)", owner, last, err)
	}
	out, cfg := encodeParsed(t, f)
	for _, u := range cfg.Users {
		if u.Name == "ops" && (u.Operator || len(u.Keys) != 0) {
			t.Errorf("ops = %+v, want a plain user with no keys", u)
		}
	}
	if strings.Contains(out, "vault-held") {
		t.Errorf("the operator: line comment must go with the flag:\n%s", out)
	}
	inOrder(t, out, "  - name: ops\n    # break-glass account\n    keys: []\n")

	g := loadFixture(t, editFixture(t))
	if _, _, err := g.RemoveKey(keyFP(t, 1)); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if _, err := g.Encode(); err == nil || !strings.Contains(err.Error(), "operator requires at least one valid key") {
		t.Errorf("Encode err = %v, want the operator validation failure", err)
	}
}

// TestReplaceKey: the new line lands at the same index with the slot's
// comments kept; the caller-composed line (old options, new key, chosen
// comment) is stored verbatim — quoted as needed, even inside a flow list.
func TestReplaceKey(t *testing.T) {
	t.Run("block, same index, comments kept", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		newLine := `from="10.0.0.0/8",no-pty ` + testkeys.Line(t, 5) + " alice@laptop"
		if err := f.ReplaceKey("alice", keyFP(t, 2), newLine); err != nil {
			t.Fatalf("ReplaceKey: %v", err)
		}
		out, cfg := encodeParsed(t, f)
		if got := cfg.Users[0].Keys; len(got) != 2 || got[0] != newLine {
			t.Fatalf("alice keys = %q, want the new line first", got)
		}
		inOrder(t, out, "      # alice laptop\n", "      # alice desktop\n")
		if u, ok := cfg.OwnerOf(keyFP(t, 5)); !ok || u.Name != "alice" {
			t.Error("new key not owned by alice")
		}
	})
	t.Run("flow list", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		newLine := `from="10.0.0.1,10.0.0.2" ` + testkeys.Line(t, 5) + " bob, it's new"
		if err := f.ReplaceKey("bob", keyFP(t, 4), newLine); err != nil {
			t.Fatalf("ReplaceKey: %v", err)
		}
		_, cfg := encodeParsed(t, f)
		if got := cfg.Users[1].Keys; len(got) != 1 || got[0] != newLine {
			t.Errorf("bob keys = %q, want [%q]", got, newLine)
		}
	})
	t.Run("wrong owner", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		err := f.ReplaceKey("bob", keyFP(t, 2), testkeys.Line(t, 5))
		if err == nil || !strings.Contains(err.Error(), `belongs to "alice", not "bob"`) {
			t.Errorf("err = %v, want the ownership error", err)
		}
	})
}

func TestSetOperator(t *testing.T) {
	t.Run("on inserts before keys", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.SetOperator("bob", true); err != nil {
			t.Fatalf("SetOperator: %v", err)
		}
		out, cfg := encodeParsed(t, f)
		if !cfg.Users[1].Operator {
			t.Errorf("bob not an operator:\n%s", out)
		}
		inOrder(t, out, "  - name: bob\n    operator: true\n    keys:")
	})
	t.Run("on keeps an existing flag", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.SetOperator("ops", true); err != nil {
			t.Fatalf("SetOperator: %v", err)
		}
		out, _ := encodeParsed(t, f)
		if strings.Count(out, "operator:") != 1 || !strings.Contains(out, "operator: true # vault-held") {
			t.Errorf("want the one existing flag kept:\n%s", out)
		}
	})
	t.Run("off without a flag is a no-op", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.SetOperator("bob", false); err != nil {
			t.Fatalf("SetOperator: %v", err)
		}
		if out, _ := encodeParsed(t, f); strings.Count(out, "operator:") != 1 {
			t.Errorf("unexpected operator change:\n%s", out)
		}
	})
	t.Run("off in a flow mapping", func(t *testing.T) {
		f := loadFixture(t, `users: [{name: ops, operator: true, keys: ["`+testkeys.Line(t, 1)+`", "`+testkeys.Line(t, 2)+`"]}]`)
		if err := f.SetOperator("ops", false); err != nil {
			t.Fatalf("SetOperator: %v", err)
		}
		out, cfg := encodeParsed(t, f)
		if cfg.Users[0].Operator || strings.Contains(out, "operator") {
			t.Errorf("flag survived:\n%s", out)
		}
	})
}

// TestEditsThenOneEncode: several edits on one File, one Encode — the
// shape revoke uses (resolve all targets, edit, encode once).
func TestEditsThenOneEncode(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	if _, err := f.RemoveUser("bob"); err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if _, _, err := f.RemoveKey(keyFP(t, 3)); err != nil {
		t.Fatalf("RemoveKey: %v", err)
	}
	if err := f.ReplaceKey("alice", keyFP(t, 2), testkeys.Line(t, 5)+" alice@new"); err != nil {
		t.Fatalf("ReplaceKey: %v", err)
	}
	out, cfg := encodeParsed(t, f)
	if len(cfg.Users) != 2 || len(cfg.Users[0].Keys) != 1 || len(cfg.Access) != 2 {
		t.Errorf("config = %+v", cfg)
	}
	for _, want := range []string{
		"# fleet manifest — hand-maintained", "# --- contractors ---", "# --- staff ---",
		"# alice laptop", "# break-glass account", "# alice: web only",
		"# alice db access (temporary)", "# reviewed 2026-10-01",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	checkGolden(t, "edit_multi.golden", []byte(out))
}

func TestEditErrors(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	if _, err := f.RemoveUser("carol"); err == nil || !strings.Contains(err.Error(), `user "carol" is not in the manifest`) {
		t.Errorf("RemoveUser(carol) err = %v", err)
	}
	if _, _, err := f.RemoveKey(keyFP(t, 9)); err == nil || !strings.Contains(err.Error(), "is not in the manifest") {
		t.Errorf("RemoveKey(unknown) err = %v", err)
	}
	if err := f.SetOperator("carol", false); err == nil {
		t.Error("SetOperator(carol) succeeded")
	}
	if err := f.ReplaceKey("alice", keyFP(t, 9), testkeys.Line(t, 5)); err == nil {
		t.Error("ReplaceKey of an unknown key succeeded")
	}
	empty := loadFixture(t, "")
	if _, err := empty.RemoveUser("bob"); err == nil {
		t.Error("RemoveUser on an empty manifest succeeded")
	}
}

// accessFixture exercises every access: shape RemoveAccess handles: a
// flow explicit list with a line comment, a flow wildcard with except:, a
// block wildcard without except:, and a second explicit entry for the same
// user — with head comments on entries (first, middle, last) and a
// document footer.
func accessFixture(tb testing.TB) string {
	tb.Helper()
	return `# fleet manifest
users:
  - {name: alice, keys: ["` + testkeys.Line(tb, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(tb, 4) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(tb, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  # alice: the web tier
  - user: alice
    servers: [web-1, web-2, db-1] # reviewed 2026-10
  # bob: everywhere but the database
  - user: bob
    servers: ["*"]
    except: [db-1]
  # carol: everywhere
  - user: carol
    servers:
      - "*"
  # alice db access (temporary)
  - user: alice
    servers: [db-1]
# end of manifest
`
}

// grantsOf returns user's effective servers in the re-parsed config.
func grantsOf(cfg *config.Config, user string) []string {
	var out []string
	for _, s := range cfg.Servers {
		if cfg.Covers(user, s.Name) {
			out = append(out, s.Name)
		}
	}
	return out
}

// TestRemoveAccessExplicitPositions: the first, middle and last item of an
// explicit list; removing db-1 also empties alice's second entry, which is
// deleted with its head comment rescued to the section footer (before the
// document footer). The surviving item keeps the entry's line comment.
func TestRemoveAccessExplicitPositions(t *testing.T) {
	for _, tt := range []struct {
		server string
		list   string
		want   AccessRemoval
		grants []string
	}{
		{"web-1", "servers: [web-2, db-1] # reviewed 2026-10", AccessRemoval{EntriesChanged: 1}, []string{"web-2", "db-1"}},
		{"web-2", "servers: [web-1, db-1] # reviewed 2026-10", AccessRemoval{EntriesChanged: 1}, []string{"web-1", "db-1"}},
		{"db-1", "servers: [web-1, web-2] # reviewed 2026-10", AccessRemoval{EntriesChanged: 1, EntriesRemoved: 1}, []string{"web-1", "web-2"}},
	} {
		t.Run(tt.server, func(t *testing.T) {
			f := loadFixture(t, accessFixture(t))
			r, err := f.RemoveAccess("alice", []string{tt.server})
			if err != nil {
				t.Fatalf("RemoveAccess: %v", err)
			}
			if r != tt.want {
				t.Errorf("AccessRemoval = %+v, want %+v", r, tt.want)
			}
			out, cfg := encodeParsed(t, f)
			if got := grantsOf(cfg, "alice"); !slices.Equal(got, tt.grants) {
				t.Errorf("alice's grants = %v, want %v", got, tt.grants)
			}
			inOrder(t, out, "  # alice: the web tier\n  - user: alice\n    "+tt.list+"\n", "  # bob: everywhere but the database\n")
			if tt.server == "db-1" {
				inOrder(t, out, "      - \"*\"\n# alice db access (temporary)\n# end of manifest\n")
				if strings.Count(out, "- user: alice") != 1 {
					t.Errorf("the emptied entry survived:\n%s", out)
				}
			}
		})
	}
}

// TestRemoveAccessDuplicateItems: every item equal to the server goes.
func TestRemoveAccessDuplicateItems(t *testing.T) {
	f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n"+
		"access:\n  - {user: bob, servers: [web-1, db-1, web-1]}\n")
	r, err := f.RemoveAccess("bob", []string{"web-1"})
	if err != nil || r != (AccessRemoval{EntriesChanged: 1}) {
		t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
	}
	out, _ := encodeParsed(t, f)
	if !strings.Contains(out, "{user: bob, servers: [db-1]}") {
		t.Errorf("want only db-1 left:\n%s", out)
	}
}

// TestRemoveAccessBlockListComments: in a block list, a removed item's
// line comment goes with it; a surviving item keeps its own.
func TestRemoveAccessBlockListComments(t *testing.T) {
	f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n"+
		"access:\n  - user: bob\n    servers:\n      - web-1 # primary\n      - db-1 # replica\n")
	if _, err := f.RemoveAccess("bob", []string{"db-1"}); err != nil {
		t.Fatalf("RemoveAccess: %v", err)
	}
	out, _ := encodeParsed(t, f)
	inOrder(t, out, "    servers:\n      - web-1 # primary\n")
	if strings.Contains(out, "replica") {
		t.Errorf("the removed item's line comment survived:\n%s", out)
	}
}

// TestRemoveAccessEmptiedRescuesToNextEntry: a deleted entry that is not
// the last passes its head comment to the next entry.
func TestRemoveAccessEmptiedRescuesToNextEntry(t *testing.T) {
	f := loadFixture(t, accessFixture(t))
	r, err := f.RemoveAccess("alice", []string{"web-1", "web-2", "db-1"})
	if err != nil || r != (AccessRemoval{EntriesRemoved: 2}) {
		t.Fatalf("RemoveAccess = (%+v, %v), want 2 entries removed", r, err)
	}
	out, cfg := encodeParsed(t, f)
	if len(grantsOf(cfg, "alice")) != 0 || len(cfg.Users) != 3 {
		t.Errorf("alice must keep her user entry and lose every grant:\n%s", out)
	}
	inOrder(t, out, "access:\n  # alice: the web tier\n  # bob: everywhere but the database\n  - user: bob\n",
		"# alice db access (temporary)\n# end of manifest\n")
	if strings.Contains(out, "reviewed 2026-10") {
		t.Errorf("a deleted entry's line comment survived:\n%s", out)
	}
}

func TestRemoveAccessErrors(t *testing.T) {
	f := loadFixture(t, accessFixture(t))
	if _, err := f.RemoveAccess("dave", []string{"web-1"}); err == nil || !strings.Contains(err.Error(), `user "dave" is not in the manifest`) {
		t.Errorf("unknown user err = %v", err)
	}
	if _, err := f.RemoveAccess("alice", []string{"db-9"}); err == nil || !strings.Contains(err.Error(), `server "db-9" is not in the manifest`) {
		t.Errorf("unknown server err = %v", err)
	}
}

// TestRemoveAccessWildcard: except: extended (flow), created (block and
// flow styles, right after servers:), and a wildcard left covering no
// current server deleted (decision 1b).
func TestRemoveAccessWildcard(t *testing.T) {
	t.Run("except appended", func(t *testing.T) {
		f := loadFixture(t, accessFixture(t))
		r, err := f.RemoveAccess("bob", []string{"web-2"})
		if err != nil || r != (AccessRemoval{EntriesChanged: 1, ServersExcepted: 1}) {
			t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
		}
		out, cfg := encodeParsed(t, f)
		inOrder(t, out, "  - user: bob\n    servers: [\"*\"]\n    except: [db-1, web-2]\n")
		if got := grantsOf(cfg, "bob"); !slices.Equal(got, []string{"web-1"}) {
			t.Errorf("bob's grants = %v, want [web-1]", got)
		}
		if !cfg.Covers("bob", "web-9") {
			t.Error("the wildcard must keep covering future servers")
		}
	})
	t.Run("except created, block style", func(t *testing.T) {
		f := loadFixture(t, accessFixture(t))
		r, err := f.RemoveAccess("carol", []string{"db-1", "web-1"})
		if err != nil || r != (AccessRemoval{EntriesChanged: 1, ServersExcepted: 2}) {
			t.Fatalf("RemoveAccess = (%+v, %v)", r, err)
		}
		out, cfg := encodeParsed(t, f)
		inOrder(t, out, "  # carol: everywhere\n  - user: carol\n    servers:\n      - \"*\"\n    except:\n      - db-1\n      - web-1\n  # alice db access")
		if got := grantsOf(cfg, "carol"); !slices.Equal(got, []string{"web-2"}) {
			t.Errorf("carol's grants = %v, want [web-2]", got)
		}
	})
	t.Run("except created, flow style", func(t *testing.T) {
		f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
			"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n"+
			"access:\n  - user: bob\n    servers: [\"*\"] # all of them\n")
		if _, err := f.RemoveAccess("bob", []string{"web-1"}); err != nil {
			t.Fatalf("RemoveAccess: %v", err)
		}
		out, _ := encodeParsed(t, f)
		inOrder(t, out, "    servers: [\"*\"] # all of them\n    except: [web-1]\n")
	})
	t.Run("null except is rebuilt in place", func(t *testing.T) {
		f := loadFixture(t, "users:\n  - {name: bob, keys: [\""+testkeys.Line(t, 4)+"\"]}\n"+
			"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n"+
			"access:\n  - user: bob\n    servers: [\"*\"]\n    except:\n")
		if _, err := f.RemoveAccess("bob", []string{"db-1"}); err != nil {
			t.Fatalf("RemoveAccess: %v", err)
		}
		out, _ := encodeParsed(t, f)
		inOrder(t, out, "    servers: [\"*\"]\n    except: [db-1]\n")
	})
	t.Run("wildcard left covering nothing is deleted", func(t *testing.T) {
		f := loadFixture(t, accessFixture(t))
		r, err := f.RemoveAccess("bob", []string{"web-1", "web-2"})
		if err != nil || r != (AccessRemoval{EntriesRemoved: 1, WildcardsRemoved: 1}) {
			t.Fatalf("RemoveAccess = (%+v, %v), want 1 wildcard entry removed", r, err)
		}
		out, cfg := encodeParsed(t, f)
		if len(grantsOf(cfg, "bob")) != 0 || strings.Contains(out, "- user: bob") {
			t.Errorf("bob's wildcard survived:\n%s", out)
		}
		inOrder(t, out, "  # bob: everywhere but the database\n  # carol: everywhere\n  - user: carol\n")
	})
}

// TestRemoveAccessUntouched: an entry covering none of the servers (the
// server is already excepted) is not edited, and other users' entries
// never are: the encode is byte-identical to the unedited one.
func TestRemoveAccessUntouched(t *testing.T) {
	want, err := loadFixture(t, accessFixture(t)).Encode()
	if err != nil {
		t.Fatal(err)
	}
	f := loadFixture(t, accessFixture(t))
	r, err := f.RemoveAccess("bob", []string{"db-1"})
	if err != nil || r != (AccessRemoval{}) {
		t.Fatalf("RemoveAccess = (%+v, %v), want nothing changed", r, err)
	}
	if out, _ := encodeParsed(t, f); out != string(want) {
		t.Errorf("an uncovered entry was edited:\n%s", out)
	}
}

// TestRemoveAccessGolden: one File, three users trimmed, one Encode — the
// shape revoke USER... --from-server uses.
func TestRemoveAccessGolden(t *testing.T) {
	f := loadFixture(t, accessFixture(t))
	for _, c := range []struct {
		user    string
		servers []string
	}{{"alice", []string{"db-1"}}, {"bob", []string{"web-2"}}, {"carol", []string{"db-1"}}} {
		if _, err := f.RemoveAccess(c.user, c.servers); err != nil {
			t.Fatalf("RemoveAccess(%s): %v", c.user, err)
		}
	}
	out, _ := encodeParsed(t, f)
	for _, want := range []string{"# fleet manifest", "# alice: the web tier", "# reviewed 2026-10",
		"# bob: everywhere but the database", "# carol: everywhere", "# alice db access (temporary)", "# end of manifest"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q", want)
		}
	}
	checkGolden(t, "edit_remove_access.golden", []byte(out))
}

// TestAddKeyAfter: the new line lands right after the old key (first,
// middle, last); every existing line, comment and operator: flag stays.
func TestAddKeyAfter(t *testing.T) {
	three := `users:
  - name: ops
    # break-glass account
    operator: true # vault-held
    keys:
      # ops laptop
      - ` + testkeys.Line(t, 1) + ` ops@laptop
      # ops desktop
      - ` + testkeys.Line(t, 2) + ` ops@desk
      - ` + testkeys.Line(t, 3) + ` ops@ci # ci runner
`
	newLine := `from="10.0.0.0/8" ` + testkeys.Line(t, 5) + " ops@new"
	for _, tt := range []struct {
		name string
		old  byte
		want []byte // seeds in order; 5 is the new key
	}{
		{"first", 1, []byte{1, 5, 2, 3}},
		{"middle", 2, []byte{1, 2, 5, 3}},
		{"last", 3, []byte{1, 2, 3, 5}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := loadFixture(t, three)
			if err := f.AddKeyAfter("ops", keyFP(t, tt.old), newLine); err != nil {
				t.Fatalf("AddKeyAfter: %v", err)
			}
			out, cfg := encodeParsed(t, f)
			u := cfg.Users[0]
			if !u.Operator || len(u.Keys) != 4 {
				t.Fatalf("ops = %+v, want an operator with 4 keys", u)
			}
			for i, seed := range tt.want {
				if k, err := authkeys.ParseLine(u.Keys[i]); err != nil || k.Fingerprint != keyFP(t, seed) {
					t.Errorf("keys[%d] = %q, want seed %d", i, u.Keys[i], seed)
				}
			}
			if !slices.Contains(u.Keys, newLine) {
				t.Errorf("new line not stored verbatim: %q", u.Keys)
			}
			for _, c := range []string{"# break-glass account", "operator: true # vault-held", "# ops laptop", "# ops desktop", "# ci runner"} {
				if !strings.Contains(out, c) {
					t.Errorf("output lacks %q:\n%s", c, out)
				}
			}
		})
	}
	t.Run("flow list", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.AddKeyAfter("bob", keyFP(t, 4), newLine); err != nil {
			t.Fatalf("AddKeyAfter: %v", err)
		}
		_, cfg := encodeParsed(t, f)
		if got := cfg.Users[1].Keys; len(got) != 2 || got[1] != newLine {
			t.Errorf("bob keys = %q", got)
		}
	})
	t.Run("errors", func(t *testing.T) {
		f := loadFixture(t, editFixture(t))
		if err := f.AddKeyAfter("alice", keyFP(t, 9), newLine); err == nil || !strings.Contains(err.Error(), "is not in the manifest") {
			t.Errorf("unknown key err = %v", err)
		}
		if err := f.AddKeyAfter("bob", keyFP(t, 2), newLine); err == nil || !strings.Contains(err.Error(), `belongs to "alice", not "bob"`) {
			t.Errorf("wrong owner err = %v", err)
		}
	})
}

func TestBumpSerialCreatesFirstKey(t *testing.T) {
	mf, err := Load([]byte(editFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := mf.BumpSerial(); err != nil || n != 1 {
		t.Fatalf("BumpSerial = %d, %v; want 1", n, err)
	}
	out, err := mf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(out), "# fleet manifest — hand-maintained\n# owner: platform team\nserial: 1\nusers:\n") {
		t.Errorf("serial must be the first key, under the file header:\n%s", out)
	}
	checkGolden(t, "bump_serial_first.golden", out) // spec Testing: "(golden)" — every other byte of the fixture kept
	again, err := Load([]byte("serial: 41\nusers: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n, err := again.BumpSerial(); err != nil || n != 42 {
		t.Errorf("BumpSerial from 41 = %d, %v", n, err)
	}
	top, err := Load([]byte("serial: 9007199254740991\nusers: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := top.BumpSerial(); err == nil || !strings.Contains(err.Error(), "9007199254740991") {
		t.Errorf("BumpSerial at the bound = %v, want an error", err)
	}
}

func TestAddTombstonesPreservesComments(t *testing.T) {
	mf, err := Load([]byte(editFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mf.RemoveUser("bob"); err != nil {
		t.Fatal(err)
	}
	// The access tombstone below records a real trim: a tombstone over a
	// grant that stays is a policy conflict.
	if _, err := mf.RemoveAccess("alice", []string{"db-1"}); err != nil {
		t.Fatal(err)
	}
	added, err := mf.AddTombstones([]config.Tombstone{
		{Fingerprint: keyFP(t, 4), User: "bob", Date: "2026-11-08", Reason: "offboarded"},
		{User: "alice", Servers: []string{"db-1"}, Date: "2026-11-08"},
	})
	if err != nil || len(added) != 2 {
		t.Fatalf("AddTombstones = %v, %v", added, err)
	}
	if _, err := mf.BumpSerial(); err != nil {
		t.Fatal(err)
	}
	out, err := mf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "edit_memory.golden", out)
	for _, c := range []string{"# fleet manifest — hand-maintained", "# alice laptop", "# break-glass account", "# reviewed 2026-10-01"} {
		if !strings.Contains(string(out), c) {
			t.Errorf("lost comment %q:\n%s", c, out)
		}
	}
	cfg, err := config.Parse(out)
	if err != nil || len(cfg.Tombstones) != 2 || cfg.Serial() != 1 || len(cfg.Conflicts()) != 0 {
		t.Fatalf("reparse: %+v, %v", cfg, err)
	}
}

func TestAddTombstonesSkipsKnownFingerprint(t *testing.T) {
	mf, err := Load([]byte("users: []\nrevoked:\n  - {fingerprint: " + keyFP(t, 9) + ", date: 2026-11-01}\n"))
	if err != nil {
		t.Fatal(err)
	}
	added, err := mf.AddTombstones([]config.Tombstone{
		{Fingerprint: keyFP(t, 9), Date: "2026-11-08"},
		{Fingerprint: keyFP(t, 8), Date: "2026-11-08"},
		{Fingerprint: keyFP(t, 8), Date: "2026-11-08"},
	})
	if err != nil || len(added) != 1 || added[0].Fingerprint != keyFP(t, 8) {
		t.Fatalf("added = %+v, %v; want only key 8, once", added, err)
	}
	out, err := mf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if cfg, err := config.Parse(out); err != nil || len(cfg.Tombstones) != 2 || cfg.Tombstones[0].Date != "2026-11-01" {
		t.Fatalf("reparse: %+v, %v (the earliest entry wins)", cfg, err)
	}
}
