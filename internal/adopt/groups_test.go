package adopt

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func groupAdoptCfg(t *testing.T, access, extra string) *config.Config {
	t.Helper()
	return parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
  - {name: dee, keys: ["`+testkeys.Line(t, 3)+`"]}
groups:
  - {name: dba, members: [bob, dee]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
access:
  - `+access+"\n"+extra)
}

// TestBuildHonoursBlockedGroupGrant: a tombstone blocks bob's group grant on
// db-1 and his key is still installed there. Adopt must not re-extend him
// (AccessRevoked still answers for a blocked pair).
func TestBuildHonoursBlockedGroupGrant(t *testing.T) {
	cfg := groupAdoptCfg(t, `{group: dba, servers: ["*"]}`, "revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n")
	both := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": both, "db-2": both}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 || len(p.NewUsers) != 0 {
		t.Fatalf("plan = %+v, want db-1 not re-granted", p)
	}
	want := "key " + fpOf(t, 2) + ` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`
	if len(p.Warnings) != 1 || p.Warnings[0].Message != want || p.Warnings[0].Kind != WarnRevokedAccessSkipped {
		t.Errorf("Warnings = %+v\nwant [%q]", p.Warnings, want)
	}
}

// TestBuildExceptOnGroupEntryNotExtended: a group entry's except: excludes
// every member.
func TestBuildExceptOnGroupEntryNotExtended(t *testing.T) {
	cfg := groupAdoptCfg(t, `{group: dba, servers: ["@db"], except: [db-1]}`, "")
	both := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": both, "db-2": both}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0].Message, "their except: list deliberately excludes") {
		t.Errorf("Warnings = %+v", p.Warnings)
	}
}

// TestBuildGroupGrantIsNotDrift: every member's key on a server the group
// reaches is granted, so nothing is extended and nothing warns. dee is the
// second member, so a grant that expanded only the first would extend her.
func TestBuildGroupGrantIsNotDrift(t *testing.T) {
	cfg := groupAdoptCfg(t, `{group: dba, servers: [db-1, db-2]}`, "")
	every := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n" + testkeys.Line(t, 3) + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": every, "db-2": every}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 || len(p.NewUsers) != 0 || len(p.Warnings) != 0 {
		t.Errorf("plan = %+v, want nothing", p)
	}
}
