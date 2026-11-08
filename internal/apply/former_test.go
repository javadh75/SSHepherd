package apply

import (
	"bytes"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRenderFormerLabels: a key the edited config no longer owns is
// labeled from the former config — "(revoked)" by default, the given note
// for rotate — and a key neither config knows stays "(unknown)".
func TestRenderFormerLabels(t *testing.T) {
	former := planCfg(t) // op k1 operator, alice k2, bob k3 on web-1
	edited, err := config.Parse([]byte(`
users:
  - {name: op, operator: true, comment: "op@sshepherd", keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
`))
	if err != nil {
		t.Fatal(err)
	}
	content := testkeys.Line(t, 1) + " op@sshepherd\n" + testkeys.Line(t, 2) + " alice@work\n" +
		testkeys.Line(t, 3) + " bob\n" + testkeys.Line(t, 9) + " stray\n"
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(content)}}}
	plans := buildPlans(t, edited, r, []string{fp(t, 1)})

	for _, tt := range []struct {
		note string
		want []string
	}{
		{"", []string{"alice (revoked)", "bob (revoked)", "(unknown)"}},
		{"rotated out", []string{"alice (rotated out)", "bob (rotated out)"}},
	} {
		var buf bytes.Buffer
		Render(&buf, edited, plans, RenderOptions{Former: former, FormerNote: tt.note})
		for _, want := range tt.want {
			if !strings.Contains(buf.String(), want) {
				t.Errorf("note %q: report lacks %q:\n%s", tt.note, want, buf.String())
			}
		}
	}
	var plain bytes.Buffer
	Render(&plain, edited, plans, RenderOptions{})
	if strings.Contains(plain.String(), "(revoked)") || strings.Count(plain.String(), "(unknown)") != 3 {
		t.Errorf("plain apply (no Former) must label every unowned key (unknown):\n%s", plain.String())
	}
}
