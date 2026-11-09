package reconcile

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagCfg: bob (k4) holds @db minus db-2, and a tombstone blocks db-1.
func tagCfg(t *testing.T) string {
	t.Helper()
	return `
users:
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
  - {name: db-3, host: 10.0.0.5, user: deploy, tags: [db]}
access:
  - {user: bob, servers: ["@db"], except: [db-2]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`
}

func TestReconcileHonoursBlockedTagGrant(t *testing.T) {
	p := mustBuild(t, parseCfg(t, tagCfg(t)), nil, []identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: []string{"db-1"}}})
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", messages(p.Warnings),
		"key "+mustFP(t, testkeys.Line(t, 4))+` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`)
}

func TestReconcileExceptOnTagEntryNotExtended(t *testing.T) {
	p := mustBuild(t, parseCfg(t, tagCfg(t)), nil, []identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: []string{"db-2"}}})
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", messages(p.Warnings), "which their except: list deliberately excludes")
}

// TestReconcileTagNeverCoversNewServer: only "*" covers a server the manifest
// does not have yet; an @tag grant is extended by name like any other.
func TestReconcileTagNeverCoversNewServer(t *testing.T) {
	p := mustBuild(t, parseCfg(t, tagCfg(t)),
		[]sshcfg.Host{{Alias: "db-9", HostName: "10.0.0.9", User: "deploy"}},
		[]identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: []string{"db-9"}}})
	if len(p.Extensions) != 1 || p.Extensions[0].User != "bob" || p.Extensions[0].Servers[0] != "db-9" {
		t.Errorf("Extensions = %+v, want bob extended to db-9 by name", p.Extensions)
	}
}

// TestReconcileTaggedServerIdentical: tags are manifest-only, so a tagged
// server matching the ssh config is an identical re-run, not a conflict.
func TestReconcileTaggedServerIdentical(t *testing.T) {
	p := mustBuild(t, parseCfg(t, tagCfg(t)),
		[]sshcfg.Host{{Alias: "db-1", HostName: "10.0.0.3", User: "deploy"}}, nil)
	if len(p.Warnings) != 0 || len(p.NewServers) != 0 {
		t.Errorf("plan = %+v, want a silent identical skip", p)
	}
}
