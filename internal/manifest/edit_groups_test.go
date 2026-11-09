package manifest

import (
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// groupEditFixture: alice is in web-team, bob in web-team and solo, each
// group holding one entry; comments ride the group and its members.
func groupEditFixture(tb testing.TB) string {
	tb.Helper()
	return `# fleet manifest
users:
  - {name: alice, keys: ["` + testkeys.Line(tb, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(tb, 4) + `"]}
# who works on what
groups:
  - name: web-team
    description: docs only # kept
    members:
      # lead
      - alice
      - bob
  - name: solo
    members: [bob]
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
access:
  # the team
  - group: web-team
    servers: ["@web"]
  - group: solo
    servers: [web-1]
# end of manifest
`
}

// TestLoadKeepsGroups: the editor accepts groups: and a no-op re-encode keeps
// the section and its comments.
func TestLoadKeepsGroups(t *testing.T) {
	f := loadFixture(t, groupEditFixture(t))
	out, cfg := encodeParsed(t, f)
	if len(cfg.Groups) != 2 || cfg.Groups[1].Name != "solo" {
		t.Errorf("Groups = %+v", cfg.Groups)
	}
	for _, want := range []string{"# who works on what", "# lead", "description: docs only # kept", "- group: web-team"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestGenerateWithGroups(t *testing.T) {
	out, err := GenerateWith("", Draft{
		Users:   []config.User{{Name: "alice", Keys: []string{testkeys.Line(t, 2)}}},
		Groups:  []config.Group{{Name: "web-team", Description: "d", Members: []string{"alice"}}, {Name: "none"}},
		Servers: []config.Server{{Name: "web-1", Host: "10.0.0.1", User: "deploy"}},
		Access:  []config.Access{{Group: "web-team", Servers: []string{"web-1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)
	u, g, s := strings.Index(got, "users:"), strings.Index(got, "groups:"), strings.Index(got, "servers:")
	if u < 0 || g < u || s < g {
		t.Errorf("want users:, groups:, servers: in order:\n%s", got)
	}
	if strings.Contains(got, `user: ""`) {
		t.Errorf("a group entry was written with a junk user key:\n%s", got)
	}
	if !strings.Contains(got, "members: []") {
		t.Errorf("an empty group must write members: []:\n%s", got)
	}
	cfg, err := config.Parse(out)
	if err != nil {
		t.Fatalf("generated manifest does not load: %v\n%s", err, got)
	}
	if !reflect.DeepEqual(cfg.Access[0], config.Access{Group: "web-team", Servers: []string{"web-1"}}) {
		t.Errorf("access[0] = %+v", cfg.Access[0])
	}
}

// TestGenerateOmitsEmptyGroups: no groups, no key, so every existing golden
// stays byte-identical.
func TestGenerateOmitsEmptyGroups(t *testing.T) {
	out, err := GenerateWith("", Draft{Users: []config.User{{Name: "alice", Keys: []string{testkeys.Line(t, 2)}}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "groups") {
		t.Errorf("empty Groups wrote a section:\n%s", out)
	}
}

// TestRemoveUserDropsMembership: alice is gone from web-team and bob stays;
// the group and every comment stay.
func TestRemoveUserDropsMembership(t *testing.T) {
	f := loadFixture(t, groupEditFixture(t))
	r, err := f.RemoveUser("alice")
	if err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if r.Keys != 1 || r.Grants != 0 || !reflect.DeepEqual(r.Groups, []string{"web-team"}) {
		t.Errorf("UserRemoval = %+v", r)
	}
	out, cfg := encodeParsed(t, f)
	if !reflect.DeepEqual(cfg.Groups[0].Members, []string{"bob"}) {
		t.Errorf("web-team members = %v", cfg.Groups[0].Members)
	}
	checkGolden(t, "edit_remove_member.golden", []byte(out))
}

// TestRemoveUserLeavesLastGroupEmpty: bob is solo's last member. The group
// keeps its entry and its access: entry, with the empty_group warning, so
// revoking the last member never breaks the manifest (spec S3b).
func TestRemoveUserLeavesLastGroupEmpty(t *testing.T) {
	f := loadFixture(t, groupEditFixture(t))
	r, err := f.RemoveUser("bob")
	if err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if !reflect.DeepEqual(r.Groups, []string{"web-team", "solo"}) {
		t.Errorf("Groups = %v", r.Groups)
	}
	out, cfg := encodeParsed(t, f)
	if len(cfg.Groups) != 2 || len(cfg.Groups[1].Members) != 0 || len(cfg.Access) != 2 {
		t.Errorf("Groups = %+v, access = %+v", cfg.Groups, cfg.Access)
	}
	if !strings.Contains(out, "members: []") {
		t.Errorf("solo must write members: []:\n%s", out)
	}
	if len(cfg.ManifestWarnings) != 1 || cfg.ManifestWarnings[0].Kind != config.WarnEmptyGroup {
		t.Errorf("ManifestWarnings = %+v", cfg.ManifestWarnings)
	}
	checkGolden(t, "edit_remove_last_member.golden", []byte(out))
}

func TestRemoveUserNotInAnyGroupReportsNone(t *testing.T) {
	f := loadFixture(t, editFixture(t))
	r, err := f.RemoveUser("alice")
	if err != nil {
		t.Fatalf("RemoveUser: %v", err)
	}
	if r.Groups != nil {
		t.Errorf("Groups = %v, want nil", r.Groups)
	}
}
