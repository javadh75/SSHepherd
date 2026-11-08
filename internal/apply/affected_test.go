package apply

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// affectedFleet parses a three-server fleet (web-1, web-2, db-1) with the
// given users: and access: entries. TestAffected's pieces: ops (operator,
// k1) everywhere; alice (k2) on web-1 and web-2; bob (k3) everywhere but
// db-1 via a wildcard; carol (k4) alone on db-1; dave (k5) granted nowhere.
func affectedFleet(t *testing.T, users string, access string) *config.Config {
	t.Helper()
	y := "users:\n" + users + `
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: db-1, host: 10.0.0.9, user: deploy}
access:
` + access
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("affectedFleet: %v\n%s", err, y)
	}
	return cfg
}

func TestAffected(t *testing.T) {
	k := func(seed byte) string { return `"` + testkeys.Line(t, seed) + `"` }
	alice := "  - {name: alice, keys: [" + k(2) + "]}\n"
	bob := "  - {name: bob, keys: [" + k(3) + "]}\n"
	carol := "  - {name: carol, keys: [" + k(4) + "]}\n"
	dave := "  - {name: dave, keys: [" + k(5) + "]}\n"
	ops := "  - {name: ops, operator: true, keys: [" + k(1) + "]}\n"
	aliceGrant := "  - {user: alice, servers: [web-1, web-2]}\n"
	bobGrant := "  - {user: bob, servers: [\"*\"], except: [db-1]}\n"
	carolGrant := "  - {user: carol, servers: [db-1]}\n"
	full := affectedFleet(t, alice+bob+carol+dave, aliceGrant+bobGrant+carolGrant)

	tests := []struct {
		name        string
		old, edited *config.Config
		servers     []string
		emptied     []string
	}{
		{"wildcard with except: only the covered servers",
			full, affectedFleet(t, alice+carol+dave, aliceGrant+carolGrant),
			[]string{"web-1", "web-2"}, nil},
		{"operator fleet-wide grant touches every server",
			affectedFleet(t, ops+alice, aliceGrant), affectedFleet(t, alice, aliceGrant),
			[]string{"web-1", "web-2", "db-1"}, []string{"db-1"}},
		{"user with no grants: zero servers",
			full, affectedFleet(t, alice+bob+carol, aliceGrant+bobGrant+carolGrant),
			nil, nil},
		{"rotation touches only that user's servers",
			full, affectedFleet(t, strings.Replace(alice, k(2), k(6), 1)+bob+carol+dave, aliceGrant+bobGrant+carolGrant),
			[]string{"web-1", "web-2"}, nil},
		{"sole grantee server is emptied",
			full, affectedFleet(t, alice+bob+dave, aliceGrant+bobGrant),
			[]string{"db-1"}, []string{"db-1"}},
		{"identical configs: nothing",
			full, full, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Affected(tt.old, tt.edited)
			if !slices.Equal(got.Servers, tt.servers) || !slices.Equal(got.Emptied, tt.emptied) {
				t.Errorf("Affected = %+v, want servers %v emptied %v", got, tt.servers, tt.emptied)
			}
		})
	}
}

// TestAffectedCommentOnlyChange: a rotation that changes only the rendered
// comment still changes the bytes, so the server is affected.
func TestAffectedCommentOnlyChange(t *testing.T) {
	line := testkeys.Line(t, 2)
	mk := func(comment string) *config.Config {
		return affectedFleet(t, `  - {name: alice, keys: ["`+line+comment+`"]}`+"\n", "  - {user: alice, servers: [web-2]}\n")
	}
	if got := Affected(mk(" old@x"), mk(" new@x")); !slices.Equal(got.Servers, []string{"web-2"}) {
		t.Errorf("Affected = %+v, want web-2", got)
	}
}

// TestAffectedIgnoresSerialBump: a revoke's serial bump alone never widens
// the affected set (renderFor renders serial 0 on both sides).
func TestAffectedIgnoresSerialBump(t *testing.T) {
	base := `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	old, err := config.Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	bumped, err := config.Parse([]byte("serial: 8\n" + base))
	if err != nil {
		t.Fatal(err)
	}
	if got := Affected(old, bumped); len(got.Servers) != 0 {
		t.Fatalf("Affected = %+v, want none", got)
	}
}
