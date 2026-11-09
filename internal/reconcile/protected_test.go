package reconcile

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func scopedOperatorCfg(t *testing.T) string {
	t.Helper()
	return `
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: db-2, host: 10.0.0.4, user: deploy}
access:
  - {user: op, servers: ["*"], except: [db-2]}
`
}

// TestReconcileScopedOperatorExceptNotAbsorbed: a scoped operator's except: is
// the same statement of intent as anyone's, so an excepted server is warned
// about and never silently absorbed by an implicit grant it no longer has,
// with or without --operator-key on the key.
func TestReconcileScopedOperatorExceptNotAbsorbed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		operatorKey bool
	}{
		{"an ssh config key", false},
		{"the same key through --operator-key", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			users := []identity.User{{Name: "op", Source: "~/.ssh/id_op", Operator: tc.operatorKey, Key: testkeys.Line(t, 4), Servers: []string{"db-2"}}}
			p := mustBuild(t, parseCfg(t, scopedOperatorCfg(t)), nil, users)
			if len(p.Extensions) != 0 {
				t.Fatalf("Extensions = %+v, want none", p.Extensions)
			}
			wantContains(t, "Warnings", messages(p.Warnings),
				`key of "op" used for "db-2" in the ssh config, which their except: list deliberately excludes — not re-granted; audit flags this drift`)
		})
	}
}

// TestReconcileProtectedUserExtendsNormally: merge is additive, so a protected
// non-operator is extended like anyone; nothing is taken away.
func TestReconcileProtectedUserExtendsNormally(t *testing.T) {
	y := `
users:
  - {name: ci, protected: true, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: db-2, host: 10.0.0.4, user: deploy}
access:
  - {user: ci, servers: [db-1]}
`
	users := []identity.User{{Name: "ci", Source: "~/.ssh/id_ci", Key: testkeys.Line(t, 4), Servers: []string{"db-2"}}}
	p := mustBuild(t, parseCfg(t, y), nil, users)
	if len(p.Extensions) != 1 || p.Extensions[0].User != "ci" || len(p.Extensions[0].Servers) != 1 || p.Extensions[0].Servers[0] != "db-2" {
		t.Fatalf("Extensions = %+v, want ci -> db-2", p.Extensions)
	}
}
