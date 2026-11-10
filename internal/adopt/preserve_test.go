package adopt

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestBuildSkipsPreservedLines (spec S6 "Audit"): a line a preserve: rule
// keeps is not unauthorized, so adopt neither adopts its key nor reports
// it; a stray key beside it is still adopted.
func TestBuildSkipsPreservedLines(t *testing.T) {
	cfg := parseConfig(t, `users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: gitea, host: 10.0.4.1, user: git, preserve: [{command: '/usr/local/bin/gitea serv key-[0-9]+'}]}
`)
	gitea := `command="/usr/local/bin/gitea serv key-1",no-pty ` + testkeys.Line(t, 7) + " git@laptop"
	stray, err := authkeys.ParseLine(testkeys.Line(t, 8) + " stray@box")
	if err != nil {
		t.Fatal(err)
	}
	content := testkeys.Line(t, 1) + "\n# gitea public key\n" + gitea + "\n" + stray.Raw + "\n"
	r := &fakeReader{byName: map[string]fleet.ReadResult{"gitea": {Content: []byte(content)}}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || p.NewUsers[0].Fingerprint != stray.Fingerprint || len(p.Issues) != 0 || len(p.Warnings) != 0 {
		t.Errorf("plan = %+v, want only the stray adopted", p)
	}
}
