package audit

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestBlockedTagGrantIsDrift (D1d): bob's @web grant over web-2 is blocked
// by a tombstone. His key still on web-2 is the "access revoked" drift, with
// the same label and exit 1 as a removed literal grant. With the key absent,
// the warning alone exits 0 (cmd's TestBlockedGrantNeverChangesTheExit).
func TestBlockedTagGrantIsDrift(t *testing.T) {
	cfg, err := config.Parse([]byte(`serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}
  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: ["@web"]}
revoked:
  - {user: bob, servers: [web-2], date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3}, []byte{1, 2, 3}))
	if s := statusOf(cfg, res[1]); s != statusDrift {
		t.Errorf("web-2 status = %s, want drift", s)
	}
	if code := ExitCode(cfg, res); code != 1 {
		t.Errorf("ExitCode = %d, want 1", code)
	}
	if label := unauthorizedLabel(cfg, "web-2", res[1].Diff.Unauthorized[0]); label != "bob (access revoked 2026-11-08)" {
		t.Errorf("label = %q", label)
	}
}
