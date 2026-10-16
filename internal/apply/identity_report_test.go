package apply

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// identityPlans: the identity-era plan surface — web-1 refused with every
// held key and its source listed; web-2 written, but only an agent key
// survives there while an --identity key was given.
func identityPlans(t *testing.T) (*config.Config, []ServerPlan) {
	t.Helper()
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: ci, keys: ["` + testkeys.Line(t, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: ci, servers: [web-1]}
  - {user: alice, servers: [web-2]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("identityPlans: %v", err)
	}
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 4) + " ci_old\n")},
		"web-2": {FileAbsent: true},
	}}
	held := []sshconn.HeldKey{fileHeld(fp(t, 4), "/home/ci/.ssh/ci_old"), agentHeld(fp(t, 2))[0]}
	return cfg, buildPlansHeld(t, cfg, r, held)
}

func TestRenderPlanIdentityGolden(t *testing.T) {
	cfg, plans := identityPlans(t)
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	out := buf.String()
	for _, want := range []string{
		fmt.Sprintf("(held: %s (/home/ci/.ssh/ci_old), %s (agent))", fp(t, 4), fp(t, 2)),
		"warning: only " + fp(t, 2) + " (agent) keeps access; none of your --identity keys survives",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	checkGolden(t, "plan_identity.golden", buf.Bytes())
}
