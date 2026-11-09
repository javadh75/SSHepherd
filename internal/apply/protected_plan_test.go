package apply

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

const protectedRemovalText = `removes protected key of "ci" (its except: excludes this server)`

// exceptFleet: alice (k1, held) holds web-1 and web-2; ci (k2) is granted by
// ciAccess; extra is any further top-level section. The on-server state is
// the caller's.
func exceptFleet(t *testing.T, ciUser, ciAccess, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
` + ciUser + `servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
` + ciAccess + extra))
	if err != nil {
		t.Fatalf("exceptFleet: %v", err)
	}
	return cfg
}

// ciOnWeb2: web-2 still holds ci's key; web-1 is already what the manifest
// renders.
func ciOnWeb2(t *testing.T, cfg *config.Config) *fakeReader {
	t.Helper()
	return &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: renderedFor(t, cfg, "web-1")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")},
	}}
}

func TestPlanWarnsWhenExceptRemovesProtectedKey(t *testing.T) {
	protectedCI := `  - {name: ci, protected: true, keys: ["` + testkeys.Line(t, 2) + `"]}` + "\n"
	plainCI := `  - {name: ci, keys: ["` + testkeys.Line(t, 2) + `"]}` + "\n"
	operatorCI := `  - {name: ci, operator: true, keys: ["` + testkeys.Line(t, 2) + `"]}` + "\n"
	const wild = `  - {user: ci, servers: ["*"], except: [web-2]}` + "\n"
	for _, tc := range []struct {
		name, user, access, extra string
		want                      []string
	}{
		{"a protected key an except removes", protectedCI, wild, "", []string{protectedRemovalText}},
		{"a scoped operator's key an except removes", operatorCI, wild, "", []string{protectedRemovalText}},
		{"a group's except counts", protectedCI, `  - {group: team, servers: ["*"], except: [web-2]}` + "\n",
			"groups:\n  - {name: team, members: [ci]}\n", []string{protectedRemovalText}},
		{"a plain user is not warned about", plainCI, wild, "", nil},
		{"a protected key removed with no except", protectedCI, "  - {user: ci, servers: [web-1]}\n", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := exceptFleet(t, tc.user, tc.access, tc.extra)
			p := planFor(t, buildPlansHeld(t, cfg, ciOnWeb2(t, cfg), agentHeld(fp(t, 1))), "web-2")
			if p.Class != ClassChange {
				t.Fatalf("Class = %s (%s), want change: the warning never refuses", p.Class, p.Refusal)
			}
			if !reflect.DeepEqual(p.ProtectedRemovals, tc.want) {
				t.Errorf("ProtectedRemovals = %q, want %q", p.ProtectedRemovals, tc.want)
			}
		})
	}
}

func TestRenderPlanProtectedExceptGolden(t *testing.T) {
	cfg := exceptFleet(t, `  - {name: ci, protected: true, keys: ["`+testkeys.Line(t, 2)+`"]}`+"\n",
		`  - {user: ci, servers: ["*"], except: [web-2]}`+"\n", "")
	plans := buildPlansHeld(t, cfg, ciOnWeb2(t, cfg), agentHeld(fp(t, 1)))
	var buf bytes.Buffer
	Render(&buf, cfg, plans, RenderOptions{})
	if !strings.Contains(buf.String(), "  warning: "+protectedRemovalText+"\n") {
		t.Errorf("report:\n%s", buf.String())
	}
	checkGolden(t, "plan_protected_except.golden", buf.Bytes())
	got := string(renderJSONCfg(t, cfg, plans, JSONOptions{Command: "apply", DryRun: true}))
	if strings.Count(got, `"protected_removals"`) != 1 || !strings.Contains(got, `removes protected key of \"ci\" (its except: excludes this server)`) {
		t.Errorf("JSON:\n%s", got)
	}
}

// TestLockoutHintNamesTheGrant: a run holding only an excepted key is refused,
// and the flag no longer helps, so the hint says to grant the server.
func TestLockoutHintNamesTheGrant(t *testing.T) {
	cfg := exceptFleet(t, `  - {name: ci, operator: true, keys: ["`+testkeys.Line(t, 2)+`"]}`+"\n",
		`  - {user: ci, servers: ["*"], except: [web-2]}`+"\n", "")
	p := planFor(t, buildPlansHeld(t, cfg, ciOnWeb2(t, cfg), agentHeld(fp(t, 2))), "web-2")
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "Add one of your keys to the manifest (or grant its user this server)") || strings.Contains(p.Refusal, "operator: true") {
		t.Fatalf("Class = %s, Refusal = %q", p.Class, p.Refusal)
	}
	if len(p.ProtectedRemovals) != 0 {
		t.Errorf("ProtectedRemovals = %q on a refused server: nothing will be removed", p.ProtectedRemovals)
	}
}

// TestRenderJSONMarksProtectedKeys: add and rewrite rows carry protected: true
// for a protected non-operator, and never operator: true.
func TestRenderJSONMarksProtectedKeys(t *testing.T) {
	cfg := exceptFleet(t, `  - {name: ci, protected: true, comment: "ci@new", keys: ["`+testkeys.Line(t, 2)+`"]}`+"\n",
		"  - {user: ci, servers: [web-1, web-2]}\n", "")
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {FileAbsent: true},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + " ci@old\n")},
	}}
	got := string(renderJSONCfg(t, cfg, buildPlansHeld(t, cfg, r, agentHeld(fp(t, 1))), JSONOptions{Command: "apply", DryRun: true}))
	if strings.Count(got, `"protected": true`) != 2 || strings.Contains(got, `"operator": true`) {
		t.Errorf("JSON:\n%s", got)
	}
}
