package apply

import (
	"reflect"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// tagEquivFleet parses a tagged fleet. access is the access: block and extra
// is appended verbatim.
func tagEquivFleet(t *testing.T, access, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
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

func fingerprints(keys []authkeys.Key) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k.Fingerprint)
	}
	return out
}

// TestTaggedManifestMatchesFlatTwin: expansion stays inside expandServers, so
// a tagged manifest and its hand-flattened twin must give every consumer the
// same answer: DesiredFor per server, and Affected from a common starting
// point (spec S3a, equivalence property).
func TestTaggedManifestMatchesFlatTwin(t *testing.T) {
	const blocked = "revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n"
	for _, tc := range []struct {
		name, tagged, flat, extra string
	}{
		{"one tag", "  - {user: alice, servers: [\"@web\"]}\n", "  - {user: alice, servers: [web-1, web-2]}\n", ""},
		{"tag and name", "  - {user: alice, servers: [\"@db\", ci]}\n", "  - {user: alice, servers: [db-1, ci]}\n", ""},
		{"two tags", "  - {user: alice, servers: [\"@web\", \"@db\"]}\n", "  - {user: alice, servers: [web-1, web-2, db-1]}\n", ""},
		{"except", "  - {user: alice, servers: [\"@prod\"], except: [web-2]}\n", "  - {user: alice, servers: [web-1, db-1]}\n", ""},
		{"wildcard beside a tag entry", "  - {user: alice, servers: [\"*\"], except: [ci]}\n  - {user: bob, servers: [\"@db\"]}\n",
			"  - {user: alice, servers: [web-1, web-2, db-1]}\n  - {user: bob, servers: [db-1]}\n", ""},
		{"blocked tag grant", "  - {user: bob, servers: [\"@prod\"]}\n", "  - {user: bob, servers: [web-1, web-2]}\n", blocked},
		{"access order kept", "  - {user: bob, servers: [\"@web\"]}\n  - {user: alice, servers: [\"@web\"]}\n",
			"  - {user: bob, servers: [web-1, web-2]}\n  - {user: alice, servers: [web-1, web-2]}\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tagged, flat := tagEquivFleet(t, tc.tagged, tc.extra), tagEquivFleet(t, tc.flat, tc.extra)
			before := tagEquivFleet(t, "", tc.extra)
			for _, s := range tagged.Servers {
				if got, want := fingerprints(tagged.DesiredFor(s.Name)), fingerprints(flat.DesiredFor(s.Name)); !reflect.DeepEqual(got, want) {
					t.Errorf("DesiredFor(%s) = %v\nflat twin      = %v", s.Name, got, want)
				}
			}
			if got, want := Affected(before, tagged), Affected(before, flat); !reflect.DeepEqual(got, want) {
				t.Errorf("Affected = %+v\nflat twin = %+v", got, want)
			}
			if got := Affected(flat, tagged); len(got.Servers) != 0 {
				t.Errorf("Affected(flat, tagged) = %+v, want none", got)
			}
		})
	}
}
