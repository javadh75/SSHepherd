package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// samples holds a valid, non-zero value for every exported yaml field of the
// manifest types. A field without a sample fails the test: adding a schema
// field forces proving that adopt (regenerate) and Append (adopt/import
// --merge) carry it.
func samples(t *testing.T) map[string]map[string]any {
	t.Helper()
	k := testkeys.Line(t, 1)
	return map[string]map[string]any{
		"User":   {"Name": "op", "Description": "d", "Comment": "c", "Operator": true, "Keys": []string{k}},
		"Server": {"Name": "web-1", "Description": "d", "Host": "10.0.0.1", "Port": 2222, "User": "deploy", "AuthorizedKeysFile": "/etc/ssh/keys/deploy", "Tags": []string{"prod", "web"}},
		// Group is "": fill sets every field, and a user plus a group would
		// fail exactly-one-of. TestAdoptRegenerateKeepsGroups proves a group
		// entry round-trips; Append has no groups parameter.
		"Access": {"User": "bob", "Group": "", "Servers": []string{"*"}, "Except": []string{"web-1"}},
	}
}

// fill builds a T with every exported yaml field set from its sample.
func fill[T any](t *testing.T, s map[string]map[string]any) T {
	t.Helper()
	var v T
	rv := reflect.ValueOf(&v).Elem()
	name := rv.Type().Name()
	for i := range rv.NumField() {
		f := rv.Type().Field(i)
		if !f.IsExported() || f.Tag.Get("yaml") == "-" {
			continue
		}
		val, ok := s[name][f.Name]
		if !ok {
			t.Fatalf("config.%s.%s has no sample in schema_roundtrip_test.go — add one so adopt/import/Append are proven to carry it", name, f.Name)
		}
		rv.Field(i).Set(reflect.ValueOf(val))
	}
	return v
}

// roundTripConfig is a valid config whose first user, server and access
// entry carry every schema field.
func roundTripConfig(t *testing.T) (*config.Config, config.User, config.Server, config.Access) {
	t.Helper()
	s := samples(t)
	u, srv, a := fill[config.User](t, s), fill[config.Server](t, s), fill[config.Access](t, s)
	cfg := &config.Config{
		Users:   []config.User{u, {Name: "bob", Keys: []string{testkeys.Line(t, 2)}}},
		Servers: []config.Server{srv, {Name: "web-2", Host: "10.0.0.2", User: "deploy"}},
		Access:  []config.Access{a},
	}
	return cfg, u, srv, a
}

// checkRoundTrip parses out and requires the sampled entries back intact.
// (reflect.DeepEqual on config.User/Server/Access compares exported fields
// only: those types have no unexported fields.)
func checkRoundTrip(t *testing.T, how string, out []byte, u config.User, srv config.Server, a config.Access) {
	t.Helper()
	got, err := config.Parse(out)
	if err != nil {
		t.Fatalf("%s output does not load: %v\n%s", how, err, out)
	}
	if len(got.Users) == 0 || len(got.Servers) == 0 || len(got.Access) == 0 {
		t.Fatalf("%s output lost a section:\n%s", how, out)
	}
	if !reflect.DeepEqual(got.Users[0], u) || !reflect.DeepEqual(got.Servers[0], srv) || !reflect.DeepEqual(got.Access[0], a) {
		t.Errorf("config → %s → config lost a field:\nusers[0]   = %+v\nservers[0] = %+v\naccess[0]  = %+v\n%s",
			how, got.Users[0], got.Servers[0], got.Access[0], out)
	}
}

func TestSchemaRoundTripAdopt(t *testing.T) {
	cfg, u, srv, a := roundTripConfig(t)
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	checkRoundTrip(t, "adopt", out, u, srv, a)
}

func TestSchemaRoundTripAppend(t *testing.T) {
	cfg, u, srv, a := roundTripConfig(t)
	mf, err := manifest.Load([]byte("users: []\nservers: []\naccess: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := mf.Append([]string{"rt"}, cfg.Users, cfg.Servers, cfg.Access); err != nil {
		t.Fatal(err)
	}
	out, err := mf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	checkRoundTrip(t, "Append", out, u, srv, a)
}

// TestAdoptRegenerateKeepsTagSelectors: adopt carries access: entries from
// the loaded config, so an @tag selector and its except: come back unchanged.
func TestAdoptRegenerateKeepsTagSelectors(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	cfg.Access = []config.Access{{User: "bob", Servers: []string{"@web", "web-2"}, Except: []string{"web-1"}}}
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err == nil && reflect.DeepEqual(got.Access, cfg.Access) {
		return
	}
	t.Errorf("adopt changed the selector entry (err %v):\n%s", err, out)
}

// TestAdoptRegenerateKeepsRevokedAndSerial: a plain adopt rebuilds the
// manifest from structs; it must carry serial: and every revoked: field, or
// one adopt would erase all revocation memory (PRD-1). Every Tombstone
// field needs a sample (fill fails otherwise).
func TestAdoptRegenerateKeepsRevokedAndSerial(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	key := fill[config.Tombstone](t, map[string]map[string]any{"Tombstone": {
		"Fingerprint": fpOf(t, 9), "User": "carol", "Servers": []string(nil),
		"Date": "2026-11-08", "Reason": "offboarded",
	}})
	access := config.Tombstone{User: "bob", Servers: []string{"web-2"}, Date: "2026-11-08", Reason: "moved teams"}
	cfg.ManifestSerial = 7
	cfg.Tombstones = []config.Tombstone{key, access}
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err != nil {
		t.Fatalf("adopt output does not load: %v\n%s", err, out)
	}
	if got.Serial() != 7 || !reflect.DeepEqual(got.Tombstones, cfg.Tombstones) {
		t.Errorf("adopt lost memory: serial %d, revoked %+v\n%s", got.Serial(), got.Tombstones, out)
	}
}

// TestAdoptRegenerateKeepsGroups: a plain adopt rebuilds the manifest from
// structs; it must carry groups: and a group entry, or one adopt would erase
// every group. Every Group field needs a sample (fill fails otherwise).
// Append cannot carry a group: it has no groups parameter, and adopt and
// import never create one.
func TestAdoptRegenerateKeepsGroups(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	group := fill[config.Group](t, map[string]map[string]any{"Group": {
		"Name": "web-team", "Description": "d", "Members": []string{"op", "bob"},
	}})
	entry := config.Access{Group: "web-team", Servers: []string{"web-2"}}
	cfg.Groups = []config.Group{group}
	cfg.Access = append(cfg.Access, entry)
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err != nil {
		t.Fatalf("adopt output does not load: %v\n%s", err, out)
	}
	if !reflect.DeepEqual(got.Groups, cfg.Groups) || !reflect.DeepEqual(got.Access[len(got.Access)-1], entry) {
		t.Errorf("adopt lost the group: groups %+v, access %+v\n%s", got.Groups, got.Access, out)
	}
	if strings.Contains(string(out), `user: ""`) {
		t.Errorf("a group entry was written with a junk user key:\n%s", out)
	}
}
