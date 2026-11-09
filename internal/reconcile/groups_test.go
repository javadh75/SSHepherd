package reconcile

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// groupCfg: bob (k4) is in dba, which holds "*" minus db-2, and a tombstone
// blocks bob on db-1.
func groupCfg(t *testing.T) string {
	t.Helper()
	return `
users:
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
groups:
  - {name: dba, members: [bob]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
  - {name: db-3, host: 10.0.0.5, user: deploy, tags: [db]}
access:
  - {group: dba, servers: ["*"], except: [db-2]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`
}

func bobOn(t *testing.T, servers ...string) []identity.User {
	t.Helper()
	return []identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: servers}}
}

// TestReconcileHonoursBlockedGroupGrant also kills Covers without its
// c.blocked check: the raw "*" scan would answer true and skip the
// tombstone's warning.
func TestReconcileHonoursBlockedGroupGrant(t *testing.T) {
	p := mustBuild(t, parseCfg(t, groupCfg(t)), nil, bobOn(t, "db-1"))
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", messages(p.Warnings),
		"key "+mustFP(t, testkeys.Line(t, 4))+` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`)
}

func TestReconcileExceptOnGroupEntryNotExtended(t *testing.T) {
	p := mustBuild(t, parseCfg(t, groupCfg(t)), nil, bobOn(t, "db-2"))
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", messages(p.Warnings), "which their except: list deliberately excludes")
}

func TestReconcileGroupGrantCoversMember(t *testing.T) {
	p := mustBuild(t, parseCfg(t, groupCfg(t)), nil, bobOn(t, "db-3"))
	if len(p.Extensions) != 0 || len(p.Warnings) != 0 {
		t.Errorf("plan = %+v, want the group grant to cover bob", p)
	}
	// dee is the second member, on an @tag: Covers' raw scan cannot answer for
	// a tagless server, so this needs the expansion to reach every member.
	tagged := `
users:
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
  - {name: dee, keys: ["` + testkeys.Line(t, 5) + `"]}
groups:
  - {name: dba, members: [bob, dee]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
access:
  - {group: dba, servers: ["@db"]}
`
	dee := []identity.User{{Name: "dee", Source: "~/.ssh/id_dee", Key: testkeys.Line(t, 5), Servers: []string{"db-1"}}}
	p = mustBuild(t, parseCfg(t, tagged), nil, dee)
	if len(p.Extensions) != 0 || len(p.Warnings) != 0 {
		t.Errorf("plan = %+v, want the group grant to cover dee", p)
	}
}

// TestReconcileGroupWildcardAbsorbsNewServer: "*" covers a server the
// manifest does not have yet, for a member too; an @tag does not.
func TestReconcileGroupWildcardAbsorbsNewServer(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "db-9", HostName: "10.0.0.9", User: "deploy"}}
	p := mustBuild(t, parseCfg(t, groupCfg(t)), hosts, bobOn(t, "db-9"))
	if len(p.Extensions) != 0 {
		t.Errorf("Extensions = %+v, want the wildcard to absorb db-9", p.Extensions)
	}
	tagged := `
users:
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
groups:
  - {name: dba, members: [bob]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
access:
  - {group: dba, servers: ["@db"]}
`
	p = mustBuild(t, parseCfg(t, tagged), hosts, bobOn(t, "db-9"))
	if len(p.Extensions) != 1 || p.Extensions[0].User != "bob" || p.Extensions[0].Servers[0] != "db-9" {
		t.Errorf("Extensions = %+v, want bob extended to db-9 by name", p.Extensions)
	}
}
