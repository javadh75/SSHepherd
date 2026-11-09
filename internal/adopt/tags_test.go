package adopt

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestBuildHonoursBlockedTagGrant: a tombstone blocks bob's @db grant on
// db-1, and bob's key is still installed there. Adopt must not re-extend him
// (AccessRevoked still answers for a blocked pair).
func TestBuildHonoursBlockedTagGrant(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
access:
  - {user: bob, servers: ["@db"]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`)
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

// TestBuildExceptOnTagEntryNotExtended: a key found on a server an @tag
// entry's except: excludes is the carve-out warning, not an extension.
func TestBuildExceptOnTagEntryNotExtended(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy, tags: [db]}
  - {name: db-2, host: 10.0.0.4, user: deploy, tags: [db]}
access:
  - {user: bob, servers: ["@db"], except: [db-1]}
`)
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
