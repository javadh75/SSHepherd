package adopt

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestBuildRefusesUnreadableRemoteText (review F008, F002): adopt's manifest
// line is the remote line itself, which a human reviews before use. A line
// with invalid UTF-8 in its options (a raw 0x9B is an 8-bit CSI; YAML could
// hold it only as an unreadable !!binary blob), or with bytes sshd skips but
// a reviewer cannot see (a NUL tail, whitespace inside the blob), logs in yet
// is reported as an issue and never adopted. An invalid-UTF-8 comment is
// dropped like any unsafe comment.
func TestBuildRefusesUnreadableRemoteText(t *testing.T) {
	op := testkeys.Line(t, 1)
	carol := testkeys.Line(t, 7)
	typ, blob := strings.Fields(carol)[0], strings.Fields(carol)[1]
	for _, tc := range []struct{ name, line, want string }{
		{"invalid UTF-8 option", "command=\"/bin/true \x9b31m\xff\",cert-authority " + carol + " ev\x9bil",
			"this line logs in, but the manifest cannot hold it: option "},
		{"NUL tail", carol + " carol\x00junk",
			"this line logs in, but the manifest cannot hold it: the line contains control or format characters"},
		{"VT inside the blob", typ + " " + blob[:30] + "\v" + blob[30:] + " carol",
			"this line logs in, but the manifest cannot hold it: the line contains control or format characters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testCfg(t)
			r := &fakeReader{byName: map[string]fleet.ReadResult{
				"db-1":  {Content: []byte(op + "\n" + tc.line + "\n")},
				"web-1": {Content: []byte(op + "\n")},
				"web-2": {Content: []byte(op + "\n")},
			}}
			p := Build(cfg, runAudit(t, cfg, r))
			if len(p.Issues) != 1 || !strings.Contains(p.Issues[0].Detail, tc.want) {
				t.Errorf("Issues = %+v, want one %q issue", p.Issues, tc.want)
			}
			if len(p.NewUsers) != 0 {
				t.Errorf("NewUsers = %+v, want none", p.NewUsers)
			}
		})
	}
	t.Run("invalid UTF-8 comment is dropped", func(t *testing.T) {
		cfg := testCfg(t)
		r := &fakeReader{byName: map[string]fleet.ReadResult{
			"db-1":  {Content: []byte(op + "\n" + carol + " ev\x9bil\n")},
			"web-1": {Content: []byte(op + "\n")},
			"web-2": {Content: []byte(op + "\n")},
		}}
		p := Build(cfg, runAudit(t, cfg, r))
		if len(p.Issues) != 0 || len(p.NewUsers) != 1 || p.NewUsers[0].Line != carol {
			t.Errorf("Issues = %+v, NewUsers = %+v; want carol's key adopted without its comment", p.Issues, p.NewUsers)
		}
	})
}
