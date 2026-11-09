package config

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestGrantCount: a grant is one (user, server) pair the render would write,
// operators included.
func TestGrantCount(t *testing.T) {
	k1, k2 := testkeys.Line(t, 1), testkeys.Line(t, 2)
	servers := "servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: web-2, host: 10.0.0.2, user: deploy}\n"
	for _, tc := range []struct {
		name, manifest string
		want           int
	}{
		{"operator on every server", "users:\n  - {name: op, operator: true, keys: [\"" + k1 + "\"]}\n" + servers, 2},
		{"operator named in access is not counted twice", "users:\n  - {name: op, operator: true, keys: [\"" + k1 + "\"]}\n" + servers + "access:\n  - {user: op, servers: [web-1]}\n", 2},
		{"operator plus one grant", "users:\n  - {name: op, operator: true, keys: [\"" + k1 + "\"]}\n  - {name: alice, keys: [\"" + k2 + "\"]}\n" + servers + "access:\n  - {user: alice, servers: [web-1]}\n", 3},
		{"wildcard with except", "users:\n  - {name: alice, keys: [\"" + k2 + "\"]}\n" + servers + "access:\n  - {user: alice, servers: [\"*\"], except: [web-2]}\n", 1},
		{"repeated entries union", "users:\n  - {name: alice, keys: [\"" + k2 + "\"]}\n" + servers + "access:\n  - {user: alice, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n", 1},
		{"a user with no keys renders nothing", "users:\n  - {name: alice, keys: []}\n" + servers + "access:\n  - {user: alice, servers: [web-1]}\n", 0},
		{"no servers", "users:\n  - {name: op, operator: true, keys: [\"" + k1 + "\"]}\n", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse([]byte(tc.manifest))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := cfg.GrantCount(); got != tc.want {
				t.Errorf("GrantCount = %d, want %d", got, tc.want)
			}
		})
	}
}
