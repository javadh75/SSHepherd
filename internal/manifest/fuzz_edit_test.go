package manifest

import (
	"slices"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// FuzzManifestEdit asserts the removal edits' safety property: on any
// manifest Load accepts, RemoveKey (clearing an operator's flag first when
// it removes the operator's last key, exactly as revoke does) and
// RemoveUser always yield a manifest config.Parse accepts, and the removed
// fingerprint is never owned by anyone in the output. pick selects the
// edit and its target: even → RemoveKey, odd → RemoveUser.
func FuzzManifestEdit(f *testing.F) {
	f.Add(editFixture(f), uint8(0))
	f.Add(editFixture(f), uint8(1))
	f.Add(editFixture(f), uint8(4))
	f.Add(editFixture(f), uint8(5))
	f.Add(commentedFixture(f), uint8(2))
	f.Add(`users: [{name: ops, operator: true, keys: ["`+testkeys.Line(f, 1)+`"]}]`, uint8(0))
	f.Add(`users: [{name: ci, protected: true, keys: ["`+testkeys.Line(f, 1)+`"]}]`, uint8(0))
	f.Add("users: []\nservers: []\naccess: []\n", uint8(0))
	f.Add("serial: 3\n"+editFixture(f)+"revoked:\n  - {user: bob, servers: [db-1], date: 2026-11-08}\n", uint8(1))
	f.Add(tagEditFixture(f), uint8(1))
	f.Add(tagEditFixture(f)+"revoked:\n  - {user: bob, servers: [web-1], date: 2026-11-08}\n", uint8(3))
	f.Add(groupEditFixture(f), uint8(1))
	f.Add(groupEditFixture(f), uint8(3))
	f.Fuzz(func(t *testing.T, in string, pick uint8) {
		mf, err := Load([]byte(in))
		if err != nil {
			t.Skip()
		}
		cfg := mf.Config()
		type ownedKey struct {
			fp, owner string
		}
		var keys []ownedKey
		for _, u := range cfg.Users {
			for _, line := range u.Keys {
				k, err := authkeys.ParseLine(line)
				if err != nil || k == nil {
					t.Fatalf("validated key line %q does not parse: %v", line, err)
				}
				keys = append(keys, ownedKey{k.Fingerprint, u.Name})
			}
		}
		var gone []string // fingerprints that must not be owned afterwards
		if pick%2 == 0 {
			if len(keys) == 0 {
				t.Skip()
			}
			k := keys[int(pick/2)%len(keys)]
			owner, _ := cfg.OwnerOf(k.fp)
			if owner.Operator && len(owner.Keys) == 1 {
				if err := mf.SetOperator(owner.Name, false); err != nil {
					t.Fatalf("SetOperator(%q): %v", owner.Name, err)
				}
			}
			got, _, err := mf.RemoveKey(k.fp)
			if err != nil || got != k.owner {
				t.Fatalf("RemoveKey(%s) = (%q, %v), want owner %q", k.fp, got, err, k.owner)
			}
			gone = append(gone, k.fp)
		} else {
			if len(cfg.Users) == 0 {
				t.Skip()
			}
			u := cfg.Users[int(pick/2)%len(cfg.Users)]
			if _, err := mf.RemoveUser(u.Name); err != nil {
				t.Fatalf("RemoveUser(%q): %v", u.Name, err)
			}
			for _, k := range keys {
				if k.owner == u.Name {
					gone = append(gone, k.fp)
				}
			}
		}
		before := mf.Config().Serial()
		tombs := make([]config.Tombstone, 0, len(gone))
		for _, fp := range gone {
			tombs = append(tombs, config.Tombstone{Fingerprint: fp, Date: "2026-11-08"})
		}
		if _, err := mf.AddTombstones(tombs); err != nil {
			t.Fatalf("AddTombstones: %v", err)
		}
		bumped := before < config.MaxSerial
		if bumped {
			if n, err := mf.BumpSerial(); err != nil || n != before+1 {
				t.Fatalf("BumpSerial from %d = %d, %v", before, n, err)
			}
		}
		out, err := mf.Encode()
		if err != nil {
			t.Fatalf("Encode after edit on input %q: %v", in, err)
		}
		after, err := config.Parse(out)
		if err != nil {
			t.Fatalf("edited manifest rejected for input %q:\n%s\nerr: %v", in, out, err)
		}
		for _, fp := range gone {
			if u, ok := after.OwnerOf(fp); ok {
				t.Errorf("removed key %s still owned by %q (input %q):\n%s", fp, u.Name, in, out)
			}
		}
		for _, fp := range gone {
			if _, ok := after.Revoked(fp); !ok {
				t.Errorf("removed key %s not remembered (input %q)", fp, in)
			}
		}
		for _, c := range after.Conflicts() {
			if c.Kind == config.ConflictRevokedKey && slices.Contains(gone, c.Fingerprint) {
				t.Errorf("removing then tombstoning %s left a conflict: %+v", c.Fingerprint, c)
			}
		}
		if bumped && after.Serial() != before+1 {
			t.Errorf("serial %d → %d, want +1", before, after.Serial())
		}
	})
}

// FuzzRemoveAccess asserts RemoveAccess's safety property on selector and
// plain entries alike: on any manifest Load accepts, taking one server from a
// non-operator user (a pair no group grant reaches: revoke refuses those)
// leaves a manifest Encode writes and config.Parse accepts
// (the deletion rule must never leave an entry granting nothing), and the
// user no longer covers that server. pick selects the user and the server.
func FuzzRemoveAccess(f *testing.F) {
	f.Add(tagEditFixture(f), uint8(0))
	f.Add(tagEditFixture(f), uint8(7))
	f.Add(editFixture(f), uint8(1))
	f.Add(groupEditFixture(f), uint8(0))
	f.Fuzz(func(t *testing.T, in string, pick uint8) {
		mf, err := Load([]byte(in))
		if err != nil {
			t.Skip()
		}
		cfg := mf.Config()
		var users []string
		for _, u := range cfg.Users {
			if !u.Operator {
				users = append(users, u.Name)
			}
		}
		if len(users) == 0 || len(cfg.Servers) == 0 {
			t.Skip()
		}
		user := users[int(pick)%len(users)]
		server := cfg.Servers[int(pick/16)%len(cfg.Servers)].Name
		if len(cfg.GroupGrantsReaching(user, server)) > 0 {
			t.Skip() // revoke refuses this pair; RemoveAccess is never called on it
		}
		if _, err := mf.RemoveAccess(user, []string{server}); err != nil {
			t.Fatalf("RemoveAccess(%q, %q) on input %q: %v", user, server, in, err)
		}
		out, err := mf.Encode()
		if err != nil {
			t.Fatalf("Encode after RemoveAccess on input %q: %v", in, err)
		}
		after, err := config.Parse(out)
		if err != nil {
			t.Fatalf("edited manifest rejected for input %q:\n%s\nerr: %v", in, out, err)
		}
		if after.Covers(user, server) {
			t.Errorf("%q still covers %q after RemoveAccess (input %q):\n%s", user, server, in, out)
		}
	})
}
