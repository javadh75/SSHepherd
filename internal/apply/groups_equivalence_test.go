package apply

import (
	"reflect"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func groupEquivFleet(t *testing.T, groups, access, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
groups:
` + groups + `servers:
  - {name: web-1, host: 10.0.1.1, user: deploy, tags: [prod, web]}
  - {name: web-2, host: 10.0.1.2, user: deploy, tags: [prod, web]}
  - {name: db-1, host: 10.0.2.1, user: deploy, tags: [prod, db]}
  - {name: ci, host: 10.0.3.1, user: git}
access:
` + access + extra))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

// TestGroupManifestMatchesFlatTwin: a group entry expands to one grant per
// member inside validateAccess, so a grouped manifest and its hand-flattened
// twin must give every consumer the same answer: DesiredFor per server and
// Affected from a common starting point (spec S3b, equivalence property).
func TestGroupManifestMatchesFlatTwin(t *testing.T) {
	const team = "  - {name: team, members: [alice, bob]}\n"
	const blocked = "revoked:\n  - {user: alice, servers: [web-1], date: 2026-11-08}\n"
	for _, tc := range []struct {
		name, groups, grouped, flat, extra string
	}{
		{"one group", team, "  - {group: team, servers: [web-1, ci]}\n",
			"  - {user: alice, servers: [web-1, ci]}\n  - {user: bob, servers: [web-1, ci]}\n", ""},
		{"tag and except", team, "  - {group: team, servers: [\"@prod\"], except: [web-2]}\n",
			"  - {user: alice, servers: [web-1, db-1]}\n  - {user: bob, servers: [web-1, db-1]}\n", ""},
		{"wildcard", team, "  - {group: team, servers: [\"*\"], except: [ci]}\n",
			"  - {user: alice, servers: [web-1, web-2, db-1]}\n  - {user: bob, servers: [web-1, web-2, db-1]}\n", ""},
		{"member order", "  - {name: team, members: [bob, alice]}\n", "  - {group: team, servers: [web-1]}\n",
			"  - {user: bob, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", ""},
		{"beside a direct grant", team, "  - {user: alice, servers: [ci]}\n  - {group: team, servers: [web-1]}\n",
			"  - {user: alice, servers: [ci]}\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n", ""},
		{"blocked for one member", team, "  - {group: team, servers: [\"@web\"]}\n",
			"  - {user: alice, servers: [web-2]}\n  - {user: bob, servers: [web-1, web-2]}\n", blocked},
		{"operator member", "  - {name: team, members: [op, alice]}\n", "  - {group: team, servers: [web-1]}\n",
			"  - {user: op, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", ""},
		{"empty group", "  - {name: none, members: []}\n", "  - {group: none, servers: [web-1]}\n", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			grouped, flat := groupEquivFleet(t, tc.groups, tc.grouped, tc.extra), groupEquivFleet(t, "", tc.flat, tc.extra)
			before := groupEquivFleet(t, "", "", tc.extra)
			for _, s := range grouped.Servers {
				if got, want := fingerprints(grouped.DesiredFor(s.Name)), fingerprints(flat.DesiredFor(s.Name)); !reflect.DeepEqual(got, want) {
					t.Errorf("DesiredFor(%s) = %v\nflat twin      = %v", s.Name, got, want)
				}
			}
			if got, want := Affected(before, grouped), Affected(before, flat); !reflect.DeepEqual(got, want) {
				t.Errorf("Affected = %+v\nflat twin = %+v", got, want)
			}
			if got := Affected(flat, grouped); len(got.Servers) != 0 {
				t.Errorf("Affected(flat, grouped) = %+v, want none", got)
			}
		})
	}
}
