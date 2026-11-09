package config

import (
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// memoryManifest: alice (k1) -> web-1, web-2; bob (k2) -> db-1; extra is
// appended verbatim (a revoked: section, usually).
func memoryManifest(t *testing.T, extra string) string {
	t.Helper()
	return `users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: db-1, host: 10.0.0.3, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: [db-1]}
` + extra
}

// fpOf is a test key's SHA256 fingerprint.
func fpOf(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("fpOf(%d): %v", seed, err)
	}
	return k.Fingerprint
}

func TestLoadAllowsSerialAndRevoked(t *testing.T) {
	y := "serial: 7\n" + memoryManifest(t, "revoked:\n"+
		"  - {fingerprint: "+fpOf(t, 9)+", user: carol, date: 2026-11-08, reason: offboarded}\n"+
		"  - {user: bob, servers: [web-1], date: 2026-11-08}\n")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Serial() != 7 {
		t.Errorf("Serial() = %d, want 7", cfg.Serial())
	}
	if len(cfg.Tombstones) != 2 || cfg.Tombstones[0].Reason != "offboarded" ||
		cfg.Tombstones[0].Date != "2026-11-08" || cfg.Tombstones[1].Servers[0] != "web-1" {
		t.Errorf("Tombstones = %+v", cfg.Tombstones)
	}
	if !cfg.Tombstones[0].IsKey() || cfg.Tombstones[1].IsKey() {
		t.Errorf("IsKey wrong: %+v", cfg.Tombstones)
	}
	if len(cfg.Conflicts()) != 0 || len(cfg.Warnings) != 0 {
		t.Errorf("Conflicts = %v, Warnings = %v, want none", cfg.Conflicts(), cfg.Warnings)
	}
	if absent, _ := Parse([]byte(memoryManifest(t, ""))); absent.Serial() != 0 {
		t.Errorf("absent serial = %d, want 0", absent.Serial())
	}
}

func TestSerialNegativeRejected(t *testing.T) {
	const want = `parse manifest: serial: want an integer from 0 to 9007199254740991, got `
	// "", "~" and "null" are YAML null: yaml.v3 skips Unmarshalers for
	// !!null, so Parse checks for them itself (plan decision 15).
	for _, v := range []string{"-1", "'7'", "7.5", "0x10", "1_000", "07", "9007199254740992", "null", "~", "", "[1]"} {
		_, err := Parse([]byte("serial: " + v + "\nusers: []\n"))
		if err == nil || !strings.HasPrefix(err.Error(), want) {
			t.Errorf("serial: %s → err %v, want prefix %q", v, err, want)
		}
	}
	for v, n := range map[string]uint64{"0": 0, "1": 1, "9007199254740991": 9007199254740991} {
		cfg, err := Parse([]byte("serial: " + v + "\nusers: []\n"))
		if err != nil || cfg.Serial() != n {
			t.Errorf("serial: %s → %v, %v; want %d", v, cfg, err, n)
		}
	}
}

func TestRevokedFingerprintShape(t *testing.T) {
	fp := fpOf(t, 9)
	long := strings.Repeat("x", 257)
	tests := []struct{ name, entry, want string }{
		{"bad fingerprint", "{fingerprint: SHA256:short, date: 2026-11-08}",
			`revoked[0]: fingerprint "SHA256:short" is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)`},
		{"md5 fingerprint", "{fingerprint: 'MD5:aa:bb', date: 2026-11-08}",
			`revoked[0]: fingerprint "MD5:aa:bb" is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)`},
		{"padded fingerprint", "{fingerprint: '" + fp + "=', date: 2026-11-08}",
			`revoked[0]: fingerprint "` + fp + `=" is not a SHA256 fingerprint (want SHA256: followed by 43 base64 characters)`},
		{"servers on a key entry", "{fingerprint: " + fp + ", servers: [web-1], date: 2026-11-08}",
			"revoked[0]: servers is not allowed on a key entry (" + fp + "); record access with a separate entry that has user and servers"},
		{"access entry without user", "{servers: [web-1], date: 2026-11-08}",
			"revoked[0]: an entry without fingerprint needs user and servers"},
		{"access entry with empty servers", "{user: bob, servers: [], date: 2026-11-08}",
			"revoked[0]: servers must not be empty"},
		{"wildcard", `{user: bob, servers: ["*"], date: 2026-11-08}`,
			`revoked[0]: servers cannot be "*"; list the servers by name`},
		{"missing date", "{fingerprint: " + fp + "}", "revoked[0]: date is required"},
		{"bad date", "{fingerprint: " + fp + ", date: 2026-13-01}", `revoked[0]: date "2026-13-01" is not a YYYY-MM-DD date`},
		{"unpadded date", "{fingerprint: " + fp + ", date: '2026-1-8'}", `revoked[0]: date "2026-1-8" is not a YYYY-MM-DD date`},
		{"user with control runes", `{fingerprint: ` + fp + `, user: "a\e[31m", date: 2026-11-08}`,
			"revoked[0]: user contains control or format characters"},
		{"reason with edge space", `{fingerprint: ` + fp + `, reason: " x", date: 2026-11-08}`,
			"revoked[0]: reason has leading or trailing whitespace"},
		{"reason too long", "{fingerprint: " + fp + ", reason: " + long + ", date: 2026-11-08}",
			"revoked[0]: reason is 257 bytes, over the 256-byte limit"},
		{"user too long", "{fingerprint: " + fp + ", user: " + long + ", date: 2026-11-08}",
			"revoked[0]: user is 257 bytes, over the 256-byte limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(memoryManifest(t, "revoked:\n  - "+tt.entry+"\n")))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v\nwant it to contain %q", err, tt.want)
			}
		})
	}
}

func TestRevokedDuplicateFingerprint(t *testing.T) {
	fp := fpOf(t, 9)
	y := memoryManifest(t, "revoked:\n  - {fingerprint: "+fp+", date: 2026-11-07}\n  - {fingerprint: "+fp+", date: 2026-11-08}\n")
	_, err := Parse([]byte(y))
	if want := "revoked[1]: " + fp + " is already revoked by revoked[0]"; err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("err = %v, want %q", err, want)
	}
}

// TestAccessTombstoneUnknownServerWarns (D1e, owner override): a
// decommissioned server named in an access tombstone is a warning, the
// entry is ignored for that server, and re-adding the server re-applies it.
func TestAccessTombstoneUnknownServerWarns(t *testing.T) {
	y := memoryManifest(t, "revoked:\n  - {user: bob, servers: [db-9, db-1], date: 2026-11-08}\n")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v (an unknown server must not be a load error)", err)
	}
	want := `revoked[0]: unknown server "db-9" — this entry is ignored for it; remove db-9 from the entry once the server is gone for good`
	if len(cfg.Warnings) != 1 || cfg.Warnings[0] != want {
		t.Errorf("Warnings = %q, want [%q]", cfg.Warnings, want)
	}
	if len(cfg.ManifestWarnings) != 1 {
		t.Fatalf("ManifestWarnings = %+v, want one", cfg.ManifestWarnings)
	}
	if w := cfg.ManifestWarnings[0]; w.Kind != WarnTombstoneUnknownServer || w.RevokedIndex == nil || *w.RevokedIndex != 0 ||
		w.User != "bob" || w.Server != "db-9" || w.Message != want {
		t.Errorf("ManifestWarnings[0] = %+v", w)
	}
	if _, ok := cfg.AccessRevoked("bob", "db-9"); ok {
		t.Error("AccessRevoked matched an ignored (unknown) server")
	}
	if got, ok := cfg.AccessRevoked("bob", "db-1"); !ok || got.Date != "2026-11-08" {
		t.Errorf("AccessRevoked(bob, db-1) = %+v, %v; want the entry", got, ok)
	}
	readded := strings.Replace(y, "servers:\n", "servers:\n  - {name: db-9, host: 10.0.0.9, user: deploy}\n", 1)
	again, err := Parse([]byte(readded))
	if err != nil {
		t.Fatalf("Parse re-added: %v", err)
	}
	if len(again.Warnings) != 0 {
		t.Errorf("re-added server still warns: %q", again.Warnings)
	}
	if _, ok := again.AccessRevoked("bob", "db-9"); !ok {
		t.Error("re-adding the server must re-apply the entry")
	}
	// A name no server can have (control runes) is still only a warning
	// (D1e, plan decision 3), printed quoted in both places.
	odd, err := Parse([]byte(memoryManifest(t, "revoked:\n  - {user: bob, servers: [\"db\\e[1A\"], date: 2026-11-08}\n")))
	if err != nil {
		t.Fatalf("Parse: %v (an unknown server must not be a load error)", err)
	}
	wantOdd := `revoked[0]: unknown server "db\x1b[1A" — this entry is ignored for it; remove "db\x1b[1A" from the entry once the server is gone for good`
	if len(odd.Warnings) != 1 || odd.Warnings[0] != wantOdd || strings.ContainsRune(odd.Warnings[0], 0x1b) {
		t.Errorf("Warnings = %q, want [%q]", odd.Warnings, wantOdd)
	}
}

func TestRevokedLookup(t *testing.T) {
	fp := fpOf(t, 9)
	cfg, err := Parse([]byte(memoryManifest(t, "revoked:\n  - {fingerprint: "+fp+", user: carol, date: 2026-11-08}\n")))
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := cfg.Revoked(fp); !ok || got.User != "carol" || got.Label() != "2026-11-08, carol" {
		t.Errorf("Revoked = %+v, %v", got, ok)
	}
	if _, ok := cfg.Revoked(fpOf(t, 1)); ok {
		t.Error("an untombstoned key reported revoked")
	}
	if (Tombstone{Date: "2026-11-08"}).Label() != "2026-11-08" {
		t.Error("an unlabelled tombstone's label must be the date alone")
	}
}

// TestConflictsAreReportedNotFatal (replaces the spec draft's
// TestRevokedRejectsOwnedKey): a listed tombstoned key loads, and
// Conflicts() names it with the verbatim message and the servers it renders on.
func TestConflictsAreReportedNotFatal(t *testing.T) {
	fp := fpOf(t, 1)
	cfg, err := Parse([]byte(memoryManifest(t, "revoked:\n  - {fingerprint: "+fp+", user: alice, date: 2026-11-08}\n")))
	if err != nil {
		t.Fatalf("Parse: %v (a conflict must not be a load error)", err)
	}
	want := Conflict{
		Kind: ConflictRevokedKey, User: "alice", Fingerprint: fp, Servers: []string{"web-1", "web-2"},
		Message: "key " + fp + ` of user "alice" is revoked (2026-11-08, alice): remove it from users, or delete the revoked: entry to un-revoke it deliberately`,
	}
	if got := cfg.Conflicts(); len(got) != 1 || !reflect.DeepEqual(got[0], want) {
		t.Fatalf("Conflicts = %+v\nwant [%+v]", got, want)
	}
	unlabelled, _ := Parse([]byte(memoryManifest(t, "revoked:\n  - {fingerprint: "+fp+", date: 2026-11-08}\n")))
	if m := unlabelled.Conflicts()[0].Message; !strings.Contains(m, "is revoked (2026-11-08): remove") {
		t.Errorf("unlabelled message = %q", m)
	}
}

func TestConflictOperatorAndGrantless(t *testing.T) {
	y := `users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: idle, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
revoked:
  - {fingerprint: ` + fpOf(t, 1) + `, date: 2026-11-08}
  - {fingerprint: ` + fpOf(t, 2) + `, date: 2026-11-08}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	cs := cfg.Conflicts()
	if len(cs) != 2 || !reflect.DeepEqual(cs[0].Servers, []string{"web-1", "web-2"}) || cs[1].Servers == nil || len(cs[1].Servers) != 0 {
		t.Errorf("Conflicts = %+v; want the operator on every server and a grantless user with servers []", cs)
	}
}

// TestAccessTombstoneConflictsExplicitGrant: one conflict per tombstoned
// server, and Servers is every server the conflicting access entry renders
// on (spec §2) — apply refuses, and audit marks critical, all of them.
func TestAccessTombstoneConflictsExplicitGrant(t *testing.T) {
	const msg = `user "bob" is granted "db-1" by access[0], but revoked[0] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately`
	tests := []struct {
		name, access string
		want         []string // conflict messages
		servers      []string // each conflict's Servers, in servers: order
	}{
		{"explicit grant", "  - {user: bob, servers: [db-1, web-1]}\n", []string{msg}, []string{"web-1", "db-1"}},
		{"wildcard without except", "  - {user: bob, servers: [\"*\"]}\n", []string{msg}, []string{"web-1", "db-1", "app-1"}},
		{"wildcard excepting another", "  - {user: bob, servers: [\"*\"], except: [app-1]}\n", []string{msg}, []string{"web-1", "db-1"}},
		{"wildcard excepting it", "  - {user: bob, servers: [\"*\"], except: [db-1]}\n", nil, nil},
		{"other server only", "  - {user: bob, servers: [web-1]}\n", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := `users:
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: app-1, host: 10.0.0.4, user: deploy}
access:
` + tt.access + `revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`
			cfg, err := Parse([]byte(y))
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, c := range cfg.Conflicts() {
				if c.Kind != ConflictRevokedAccess || c.Fingerprint != "" || !reflect.DeepEqual(c.Servers, tt.servers) {
					t.Errorf("conflict shape = %+v", c)
				}
				got = append(got, c.Message)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("messages = %q\nwant %q", got, tt.want)
			}
		})
	}
}

// An access tombstone naming only an unknown server computes no conflict.
func TestConflictIgnoresUnknownTombstoneServer(t *testing.T) {
	y := memoryManifest(t, "revoked:\n  - {user: bob, servers: [db-9], date: 2026-11-08}\n")
	cfg, err := Parse([]byte(y))
	if err != nil || len(cfg.Conflicts()) != 0 {
		t.Fatalf("err %v, conflicts %+v; want none", err, cfg.Conflicts())
	}
}
