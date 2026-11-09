package adopt

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestBuildScopedOperatorExceptNotExtended: this passes once round 1 has
// landed. It pins that adopt needs no operator case: the key on the excepted
// server is ordinary drift through ownerSkip.
func TestBuildScopedOperatorExceptNotExtended(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: db-2, host: 10.0.0.4, user: deploy}
access:
  - {user: op, servers: ["*"], except: [db-2]}
`)
	onBoth := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": onBoth, "db-2": onBoth}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 || len(p.NewUsers) != 0 {
		t.Fatalf("plan = %+v, want nothing extended", p)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0].Message, "their except: list deliberately excludes") {
		t.Errorf("Warnings = %+v", p.Warnings)
	}
}
