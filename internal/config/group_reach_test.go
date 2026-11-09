package config

import (
	"reflect"
	"testing"
)

func TestGroupGrantsReaching(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam+"  - {name: dba, members: [alice]}\n",
		"  - {group: web-team, servers: [\"@web\"], except: [web-3]}\n  - {group: dba, servers: [web-1, db-1]}\n  - {group: dba, servers: [web-1]}\n  - {user: bob, servers: [db-1]}\n",
		"revoked:\n  - {user: alice, servers: [web-2], date: 2026-11-08}\n"))
	for _, tc := range []struct {
		user, server string
		want         []string
	}{
		{"alice", "web-1", []string{"web-team", "dba"}}, // access order, a group once
		{"bob", "web-1", []string{"web-team"}},
		{"alice", "db-1", []string{"dba"}},
		{"alice", "web-2", nil}, // blocked: the member gets the D1c note instead
		{"bob", "web-3", nil},   // excepted
		{"bob", "db-1", nil},    // a direct grant is not a group grant
		{"carol", "web-1", nil}, // not a member
		{"alice", "no-such", nil},
	} {
		if got := cfg.GroupGrantsReaching(tc.user, tc.server); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("GroupGrantsReaching(%s, %s) = %v, want %v", tc.user, tc.server, got, tc.want)
		}
	}
}

// TestOwnExceptCarveOut: only the user's own access: entries count. A group's
// except: does not, and ExceptCarveOut still answers for it.
func TestOwnExceptCarveOut(t *testing.T) {
	cfg := mustParse(t, groupFleet(t, webTeam,
		"  - {group: web-team, servers: [\"*\"], except: [web-2]}\n  - {user: carol, servers: [\"*\"], except: [web-3]}\n", ""))
	for _, tc := range []struct {
		user, server string
		want         bool
	}{
		{"carol", "web-3", true},
		{"carol", "web-2", false},
		{"alice", "web-2", false},
		{"bob", "web-3", false},
	} {
		if got := cfg.OwnExceptCarveOut(tc.user, tc.server); got != tc.want {
			t.Errorf("OwnExceptCarveOut(%s, %s) = %v, want %v", tc.user, tc.server, got, tc.want)
		}
	}
	if !cfg.ExceptCarveOut("alice", "web-2") {
		t.Error("ExceptCarveOut must stay group-aware for adopt and reconcile")
	}
}
