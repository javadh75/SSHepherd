package manifest

import (
	"errors"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// mergeExceptFixture is the G001 repro: carol's except: rides an inline
// YAML merge key. config.Parse honours the merge (carol is kept off db-1),
// but the editor's valueOf sees only literal keys, so a revoke
// --from-server wrote a second except: that overrode the merged one.
func mergeExceptFixture(tb testing.TB) string {
	tb.Helper()
	return `users:
  - {name: alice, keys: ["` + testkeys.Line(tb, 1) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(tb, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  - user: alice
    servers: [web-1]
  - user: carol
    servers: ["*"]
    <<: {except: [db-1]}
`
}

// mergeKeyManifests are valid manifests (config.Parse accepts each) whose
// tree holds a YAML merge key: Load must refuse them all, as it refuses
// anchors and aliases.
func mergeKeyManifests(tb testing.TB) map[string]string {
	tb.Helper()
	k1, k2 := testkeys.Line(tb, 1), testkeys.Line(tb, 2)
	return map[string]string{
		"merge key on an access entry": mergeExceptFixture(tb),
		"merge key on a user": `users:
  - <<: {name: carol}
    keys: ["` + k1 + `"]
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: carol, servers: [web-1]}
`,
		"merge key carrying a user's keys": `users:
  - name: carol
    <<: {keys: ["` + k2 + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: carol, servers: [web-1]}
`,
		"merge key on a server": `users:
  - {name: carol, keys: ["` + k1 + `"]}
servers:
  - name: web-1
    <<: {host: 10.0.0.1, user: deploy}
access:
  - {user: carol, servers: [web-1]}
`,
		"explicitly tagged merge key": `users:
  - {name: carol, keys: ["` + k1 + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
  - user: carol
    servers: ["*"]
    !!merge <<: {except: [db-1]}
`,
	}
}

func TestLoadRefusesMergeKeys(t *testing.T) {
	for name, in := range mergeKeyManifests(t) {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Parse([]byte(in)); err != nil {
				t.Fatalf("fixture must be a manifest config.Parse accepts: %v", err)
			}
			_, err := Load([]byte(in))
			var ue *UnsupportedError
			if !errors.As(err, &ue) {
				t.Fatalf("Load err = %v, want *UnsupportedError", err)
			}
			if !strings.Contains(ue.Error(), `YAML merge key "<<"`) ||
				!strings.Contains(ue.Error(), "comment-preserving edits do not support them") {
				t.Errorf("reason = %q, want the merge-key refusal", ue.Error())
			}
		})
	}
}

// TestLoadRefusesQuotedMergeSpelling: a key spelled "<<" is refused even
// quoted (a plain string key config.Parse would reject anyway), so no
// spelling of the merge key reaches the editor.
func TestLoadRefusesQuotedMergeSpelling(t *testing.T) {
	in := "users: []\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy, \"<<\": x}\n"
	if _, err := Load([]byte(in)); err == nil {
		t.Fatal("Load accepted a quoted \"<<\" key")
	}
}

// TestMergeKeyRevokeFromServerRepro pins G001's repro at the editor: the
// manifest config.Parse reads as "carol everywhere but db-1" never reaches
// RemoveAccess, so revoke --from-server cannot write an except: that
// overrides the merged one (cmd turns the UnsupportedError into exit 3,
// nothing saved).
func TestMergeKeyRevokeFromServerRepro(t *testing.T) {
	in := mergeExceptFixture(t)
	cfg, err := config.Parse([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Covers("carol", "web-1") || cfg.Covers("carol", "db-1") {
		t.Fatalf("fixture: carol must cover web-1 and not db-1")
	}
	mf, err := Load([]byte(in))
	var ue *UnsupportedError
	if !errors.As(err, &ue) || mf != nil {
		t.Fatalf("Load = (%v, %v), want (nil, *UnsupportedError)", mf, err)
	}
	if !strings.Contains(ue.Error(), "(line 13)") {
		t.Errorf("reason = %q, want the merge key's line (13)", ue.Error())
	}
}
