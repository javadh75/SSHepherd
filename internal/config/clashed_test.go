package config

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestClashedKeys (spec S7 Mechanics): every key of a user a restriction
// conflict names on a server, and nothing for other servers or other kinds.
func TestClashedKeys(t *testing.T) {
	cfg := mustParse(t, `users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`", "`+testkeys.Line(t, 5)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [web]}
access:
  - {user: alice, servers: ["@web"], options: [no-pty]}
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: [web-1, web-2]}
revoked:
  - {user: bob, servers: [web-2], date: 2026-11-10}
`)
	got := cfg.ClashedKeys("web-1")
	a1, a2 := fpOfLine(t, testkeys.Line(t, 1)), fpOfLine(t, testkeys.Line(t, 5))
	if len(got) != 2 || !got[a1] || !got[a2] {
		t.Errorf("web-1 = %v, want both of alice's keys", got)
	}
	// web-2: bob's revoked_access conflict names it, alice's clash does not.
	if got := cfg.ClashedKeys("web-2"); got != nil {
		t.Errorf("web-2 = %v, want nil", got)
	}
}
