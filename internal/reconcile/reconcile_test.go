package reconcile

import (
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func parseCfg(t *testing.T, y string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("test config: %v", err)
	}
	return cfg
}

// baseCfg exercises every ownership shape at once: an operator (key 1),
// a multi-key user to extend (alice, keys 2+3), a wildcard-except user
// (bob, key 4), and a plain granted user (carol, key 5).
func baseCfg(t *testing.T) *config.Config {
	t.Helper()
	return parseCfg(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: alice, keys: ["`+testkeys.Line(t, 2)+`", "`+testkeys.Line(t, 3)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 4)+`"]}
  - {name: carol, keys: ["`+testkeys.Line(t, 5)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, port: 2222, user: deploy, description: primary db}
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: ["*"], except: [db-1]}
  - {user: carol, servers: [db-1]}
`)
}

func mustBuild(t *testing.T, cfg *config.Config, hosts []sshcfg.Host, users []identity.User) Plan {
	t.Helper()
	p, err := Build(cfg, hosts, users)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return p
}

func wantContains(t *testing.T, kind string, got []string, subs ...string) {
	t.Helper()
	if len(got) != len(subs) {
		t.Fatalf("%s = %v, want %d entries matching %v", kind, got, len(subs), subs)
	}
	for i, sub := range subs {
		if !strings.Contains(got[i], sub) {
			t.Errorf("%s[%d] = %q, want it to contain %q", kind, i, got[i], sub)
		}
	}
}

func mustFP(t *testing.T, line string) string {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("mustFP: %v", err)
	}
	return k.Fingerprint
}

// TestReconcileSkipsRevokedPub (D2a for import --merge): a tombstoned
// incoming .pub is neither a new user nor an extension.
func TestReconcileSkipsRevokedPub(t *testing.T) {
	k9 := testkeys.Line(t, 9)
	fp9 := mustFP(t, k9)
	cfg := parseCfg(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
revoked:
  - {fingerprint: `+fp9+`, user: alice, date: 2026-11-08}
`)
	p := mustBuild(t, cfg, nil, []identity.User{{Name: "me-id_old", Source: "~/.ssh/id_old", Key: k9, Servers: []string{"web-1"}}})
	if !p.Empty() {
		t.Fatalf("plan = %+v, want nothing imported", p)
	}
	// IDENTITY is the .pub the import read (plan decision 13, spec §9).
	wantContains(t, "Warnings", p.Warnings, "key "+fp9+" from ~/.ssh/id_old.pub is REVOKED (2026-11-08, alice) — not imported")
	if p.ConflictsSkipped() != 1 {
		t.Errorf("ConflictsSkipped = %d, want 1", p.ConflictsSkipped())
	}
	// An IdentityFile that already names the .pub is printed as is.
	q := mustBuild(t, cfg, nil, []identity.User{{Name: "me-id_old", Source: "~/.ssh/id_old.pub", Key: k9, Servers: []string{"web-1"}}})
	wantContains(t, "Warnings", q.Warnings, "key "+fp9+" from ~/.ssh/id_old.pub is REVOKED (2026-11-08, alice) — not imported")
}

// TestReconcileHonoursAccessTombstone (D1a): a known key used for a server
// whose access was revoked is never extended there.
func TestReconcileHonoursAccessTombstone(t *testing.T) {
	cfg := parseCfg(t, `
users:
  - {name: bob, keys: ["`+testkeys.Line(t, 4)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`)
	p := mustBuild(t, cfg, nil, []identity.User{{Name: "bob", Source: "~/.ssh/id_bob", Key: testkeys.Line(t, 4), Servers: []string{"db-1"}}})
	if len(p.Extensions) != 0 {
		t.Fatalf("Extensions = %+v, want none", p.Extensions)
	}
	wantContains(t, "Warnings", p.Warnings,
		"key "+mustFP(t, testkeys.Line(t, 4))+` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`)
}

// --- Servers ---

func TestBuildNewServers(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "app-1", HostName: "10.0.1.1", Port: 2200, User: "deploy"},
		{Alias: "app-2", HostName: "10.0.1.2", Port: 22, User: "deploy"}, // effective default: port omitted
		{Alias: "app-3", HostName: "10.0.1.3", User: "root"},             // port 0: omitted
	}
	p := mustBuild(t, baseCfg(t), hosts, nil)
	want := []ServerAdd{
		{Name: "app-1", Host: "10.0.1.1", Port: 2200, User: "deploy"},
		{Name: "app-2", Host: "10.0.1.2", User: "deploy"},
		{Name: "app-3", Host: "10.0.1.3", User: "root"},
	}
	if !reflect.DeepEqual(p.NewServers, want) {
		t.Errorf("NewServers = %+v, want %+v", p.NewServers, want)
	}
	if len(p.Warnings) != 0 || len(p.Notes) != 0 {
		t.Errorf("Warnings/Notes = %v / %v, want none", p.Warnings, p.Notes)
	}
	if p.Empty() {
		t.Errorf("Empty() = true with appended servers")
	}
}

// Identical entries skip with a note, never a warning or an append: the
// idempotent-re-run common case. Effective port 22 (host 0 or 22 vs the
// manifest's validation-defaulted 22) compares equal, and manifest-only
// fields (description) never participate.
func TestBuildIdenticalServerSkipped(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "db-1", HostName: "10.0.0.3", Port: 2222, User: "deploy"}, // description ignored
		{Alias: "web-1", HostName: "10.0.0.1", Port: 22, User: "deploy"},  // 22 vs defaulted 22
	}
	p := mustBuild(t, baseCfg(t), hosts, nil)
	if len(p.NewServers) != 0 || !p.Empty() {
		t.Errorf("plan = %+v, want empty (identical servers skip)", p)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none (identical is not a conflict)", p.Warnings)
	}
	wantContains(t, "Notes", p.Notes, `server "db-1" already in the manifest`, `server "web-1" already in the manifest`)
	if p.ConflictsSkipped() != 0 {
		t.Errorf("ConflictsSkipped() = %d, want 0", p.ConflictsSkipped())
	}
}

func TestBuildServerConflict(t *testing.T) {
	cases := []struct {
		name string
		host sshcfg.Host
	}{
		{"host differs", sshcfg.Host{Alias: "web-1", HostName: "10.9.9.9", User: "deploy"}},
		{"port differs", sshcfg.Host{Alias: "web-1", HostName: "10.0.0.1", Port: 2022, User: "deploy"}},
		{"user differs", sshcfg.Host{Alias: "web-1", HostName: "10.0.0.1", User: "root"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := mustBuild(t, baseCfg(t), []sshcfg.Host{tc.host}, nil)
			if len(p.NewServers) != 0 || !p.Empty() {
				t.Errorf("plan = %+v, want the conflicting entry dropped", p)
			}
			wantContains(t, "Warnings", p.Warnings, `server "web-1" in the ssh config differs from the manifest (host/port/user) — manifest kept`)
			if p.ConflictsSkipped() != 1 {
				t.Errorf("ConflictsSkipped() = %d, want 1", p.ConflictsSkipped())
			}
		})
	}
}

// A conflict-only run must yield an empty plan: nothing is appended, so the
// cmd layer emits the original bytes unchanged and warnings live on stderr
// only (adjudicated 2026-07-19).
func TestBuildConflictOnlyRunEmptyPlan(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "web-1", HostName: "10.9.9.9", User: "deploy"}}
	users := []identity.User{
		{Name: "doomed", Source: "~/.ssh/doomed", Key: testkeys.Line(t, 20), Servers: []string{"web-1"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	if !p.Empty() {
		t.Errorf("plan = %+v, want empty (everything dropped by manifest-wins rules)", p)
	}
	if len(p.Warnings) == 0 {
		t.Errorf("Warnings empty; the dropped conflicts must still be reported")
	}
}

// The derived grant-drop rule: an access pair referencing a conflicted alias
// is dropped with its own warning — the alias names a different machine in
// the manifest.
func TestBuildConflictedServerGrantDropped(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "db-1", HostName: "10.9.9.9", Port: 2222, User: "deploy"}}
	users := []identity.User{
		{Name: "alice", Source: "~/.ssh/alice", Key: testkeys.Line(t, 2), Servers: []string{"db-1"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	if len(p.Extensions) != 0 || !p.Empty() {
		t.Errorf("plan = %+v, want the grant dropped alongside the server", p)
	}
	wantContains(t, "Warnings", p.Warnings,
		"manifest kept",
		`access for "alice" to "db-1" dropped: the server conflicts with the manifest`)
	if p.ConflictsSkipped() != 2 {
		t.Errorf("ConflictsSkipped() = %d, want 2 (server + grant)", p.ConflictsSkipped())
	}
}

// An alias absent from the manifest by name but pointing at a manifest
// server's target (host, port, user, default authorized_keys file) is the
// same remote file: config rejects the pair, so it is skipped loudly and
// its grants land on the manifest server. Host comparison folds case.
func TestBuildSameTargetAsManifestServer(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web1.example.com", HostName: "10.0.0.1", User: "deploy"},      // = web-1
		{Alias: "DB", HostName: "10.0.0.3", Port: 2222, User: "deploy"},        // = db-1
		{Alias: "web-1-root", HostName: "10.0.0.1", User: "root"},              // other user: distinct file
		{Alias: "web-1-alt", HostName: "10.0.0.1", Port: 2200, User: "deploy"}, // other port
	}
	users := []identity.User{
		{Name: "dave", Source: "~/.ssh/dave", Key: testkeys.Line(t, 9), Servers: []string{"web1.example.com", "DB"}},
		{Name: "carol-alias", Source: "~/.ssh/carol", Key: testkeys.Line(t, 5), Servers: []string{"web1.example.com"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	var names []string
	for _, s := range p.NewServers {
		names = append(names, s.Name)
	}
	if want := []string{"web-1-root", "web-1-alt"}; !reflect.DeepEqual(names, want) {
		t.Errorf("NewServers = %v, want %v", names, want)
	}
	wantGrants := []Grant{{User: "dave", Servers: []string{"web-1", "db-1"}}}
	if !reflect.DeepEqual(p.NewGrants, wantGrants) {
		t.Errorf("NewGrants = %+v, want %+v (redirected onto the manifest servers)", p.NewGrants, wantGrants)
	}
	wantExt := []Extension{{User: "carol", Servers: []string{"web-1"}}}
	if !reflect.DeepEqual(p.Extensions, wantExt) {
		t.Errorf("Extensions = %+v, want %+v", p.Extensions, wantExt)
	}
	wantContains(t, "Warnings", p.Warnings,
		`server "web1.example.com" in the ssh config targets the same host, port, user and authorized_keys file as manifest server "web-1"`,
		`server "DB" in the ssh config targets the same host, port, user and authorized_keys file as manifest server "db-1"`,
		`belongs to manifest user "carol" — extending their access`)
	if p.ConflictsSkipped() != 2 {
		t.Errorf("ConflictsSkipped() = %d, want 2 (the two skipped aliases)", p.ConflictsSkipped())
	}
}

// A manifest server with an authorized_keys_file override is a different
// remote file than the default an incoming alias targets.
func TestBuildSameHostDifferentAuthorizedKeysFile(t *testing.T) {
	cfg := parseCfg(t, `
users: []
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, authorized_keys_file: /etc/ssh/keys/deploy}
access: []
`)
	p := mustBuild(t, cfg, []sshcfg.Host{{Alias: "web", HostName: "10.0.0.1", User: "deploy"}}, nil)
	if len(p.NewServers) != 1 || len(p.Warnings) != 0 {
		t.Errorf("plan = %+v, want web appended without warnings", p)
	}
}

func TestCollapseTargets(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web1", HostName: "box.example.com", User: "u"},
		{Alias: "web1.example.com", HostName: "box.example.com", Port: 22, User: "u"}, // port 22 = unset
		{Alias: "nouser", HostName: "box.example.com"},                                // never a server: passes through
		{Alias: "WEB1-upper", HostName: "BOX.example.com", User: "u"},                 // hostnames fold case
		{Alias: "other", HostName: "10.0.0.6", User: "u"},
	}
	users := []identity.User{
		{Name: "a", Servers: []string{"web1.example.com", "other"}},
		{Name: "b", Servers: []string{"web1", "web1.example.com", "WEB1-upper"}},
		{Name: "op", Operator: true},
	}
	origB := append([]string(nil), users[1].Servers...)
	kept, gotUsers, warnings := CollapseTargets(hosts, users)
	var names []string
	for _, h := range kept {
		names = append(names, h.Alias)
	}
	if want := []string{"web1", "nouser", "other"}; !reflect.DeepEqual(names, want) {
		t.Errorf("kept = %v, want %v", names, want)
	}
	wantServers := [][]string{{"web1", "other"}, {"web1"}, nil}
	for i, u := range gotUsers {
		if !reflect.DeepEqual(u.Servers, wantServers[i]) {
			t.Errorf("user %s servers = %v, want %v", u.Name, u.Servers, wantServers[i])
		}
	}
	if !reflect.DeepEqual(users[1].Servers, origB) {
		t.Errorf("input users mutated: %v", users[1].Servers)
	}
	wantContains(t, "warnings", warnings,
		`server "web1.example.com" in the ssh config targets the same host, port, user and authorized_keys file as host "web1" — skipped`,
		`server "WEB1-upper" in the ssh config targets the same host, port, user and authorized_keys file as host "web1"`)
}

func TestCollapseTargetsNoDuplicates(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "a", HostName: "h", User: "u"}, {Alias: "b", HostName: "h", User: "v"}}
	users := []identity.User{{Name: "x", Servers: []string{"a", "b"}}}
	kept, gotUsers, warnings := CollapseTargets(hosts, users)
	if !reflect.DeepEqual(kept, hosts) || !reflect.DeepEqual(gotUsers, users) || len(warnings) != 0 {
		t.Errorf("CollapseTargets = %v, %v, %v; want inputs unchanged, no warnings", kept, gotUsers, warnings)
	}
}

// --- Users ---

// Same fingerprint, same name, covered grant: the clean idempotent no-op.
func TestBuildSameKeySameNameNoop(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"}}
	users := []identity.User{
		{Name: "alice", Source: "~/.ssh/alice", Key: testkeys.Line(t, 2), Servers: []string{"web-1"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	if !p.Empty() {
		t.Errorf("plan = %+v, want empty", p)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", p.Warnings)
	}
	wantContains(t, "Notes", p.Notes, `server "web-1" already in the manifest`)
}

// Known fingerprint under a different name: manifest owner wins, access
// proceeds against the owner. Classification is adjudicated: warning only
// when the key produces a plan change (an appended extension); the covered
// steady state is a note, or a re-run would warn forever.
func TestBuildKnownKeyDifferentNameClassification(t *testing.T) {
	t.Run("extension appended: warning", func(t *testing.T) {
		hosts := []sshcfg.Host{{Alias: "app-1", HostName: "10.0.1.1", User: "deploy"}}
		users := []identity.User{
			{Name: "javad-alice", Source: "~/.ssh/alice", Key: testkeys.Line(t, 2), Servers: []string{"app-1"}},
		}
		p := mustBuild(t, baseCfg(t), hosts, users)
		wantExt := []Extension{{User: "alice", Servers: []string{"app-1"}}}
		if !reflect.DeepEqual(p.Extensions, wantExt) {
			t.Errorf("Extensions = %+v, want %+v", p.Extensions, wantExt)
		}
		if len(p.NewUsers) != 0 {
			t.Errorf("NewUsers = %+v, want none (manifest owner wins)", p.NewUsers)
		}
		wantContains(t, "Warnings", p.Warnings, `belongs to manifest user "alice" — extending their access`)
	})
	t.Run("already covered: note", func(t *testing.T) {
		hosts := []sshcfg.Host{{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"}}
		users := []identity.User{
			{Name: "javad-alice", Source: "~/.ssh/alice", Key: testkeys.Line(t, 2), Servers: []string{"web-1"}},
		}
		p := mustBuild(t, baseCfg(t), hosts, users)
		if !p.Empty() {
			t.Errorf("plan = %+v, want empty", p)
		}
		if len(p.Warnings) != 0 {
			t.Errorf("Warnings = %v, want none (steady state must not warn forever)", p.Warnings)
		}
		found := false
		for _, n := range p.Notes {
			if strings.Contains(n, `belongs to manifest user "alice" — already covered`) {
				found = true
			}
		}
		if !found {
			t.Errorf("Notes = %v, want an already-covered note", p.Notes)
		}
	})
}

// The pinned rename bookkeeping: the taken set is seeded with every manifest
// name up front, incoming users claim sequentially in input order, and
// grants travel on the struct — manifest x plus incoming x, x-2 resolves to
// x-2, x-3 with correct grant attribution.
func TestBuildRenameSeededSet(t *testing.T) {
	cfg := parseCfg(t, `
users:
  - {name: x, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`)
	hosts := []sshcfg.Host{{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"}}
	users := []identity.User{
		{Name: "x", Source: "~/.ssh/a", Key: testkeys.Line(t, 21), Servers: []string{"web-1"}},
		{Name: "x-2", Source: "~/.ssh/b", Key: testkeys.Line(t, 22), Servers: []string{"web-1"}},
	}
	p := mustBuild(t, cfg, hosts, users)
	if len(p.NewUsers) != 2 || p.NewUsers[0].Name != "x-2" || p.NewUsers[1].Name != "x-3" {
		t.Fatalf("NewUsers = %+v, want names x-2, x-3", p.NewUsers)
	}
	wantGrants := []Grant{
		{User: "x-2", Servers: []string{"web-1"}},
		{User: "x-3", Servers: []string{"web-1"}},
	}
	if !reflect.DeepEqual(p.NewGrants, wantGrants) {
		t.Errorf("NewGrants = %+v, want %+v (renames must cascade to the grants)", p.NewGrants, wantGrants)
	}
	wantContains(t, "Warnings", p.Warnings,
		`user name "x" already taken`,
		`user name "x-2" already taken`)
}

// A net-new user whose entire server list was dropped by the server-conflict
// rule is not appended at all: a key no server will ever receive is a
// half-truth the self-check cannot catch. A partially surviving list is
// appended with the surviving grants. A skipped user claims no name.
func TestBuildGrantlessUserSkipVsPartialSurvival(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "db-1", HostName: "10.9.9.9", Port: 2222, User: "deploy"}, // conflict
		{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},            // identical
	}
	users := []identity.User{
		{Name: "doomed", Source: "~/.ssh/doomed", Key: testkeys.Line(t, 20), Servers: []string{"db-1"}},
		{Name: "partial", Source: "~/.ssh/partial", Key: testkeys.Line(t, 21), Servers: []string{"db-1", "web-1"}},
		{Name: "doomed", Source: "~/.ssh/later", Key: testkeys.Line(t, 22), Servers: []string{"web-1"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	if len(p.NewUsers) != 2 || p.NewUsers[0].Name != "partial" || p.NewUsers[1].Name != "doomed" {
		t.Fatalf("NewUsers = %+v, want partial then doomed (the skipped user must not claim its name)", p.NewUsers)
	}
	wantGrants := []Grant{
		{User: "partial", Servers: []string{"web-1"}},
		{User: "doomed", Servers: []string{"web-1"}},
	}
	if !reflect.DeepEqual(p.NewGrants, wantGrants) {
		t.Errorf("NewGrants = %+v, want %+v", p.NewGrants, wantGrants)
	}
	wantContains(t, "Warnings", p.Warnings,
		"manifest kept",
		`user "doomed" not added: its only server "db-1" conflicts with the manifest`,
		`access for "partial" to "db-1" dropped`)
}

// Extensions aggregate per owning manifest user: several incoming keys of
// one owner contribute to a single deduplicated server set, emitted as one
// entry per owner in cfg.Users order, servers in first-touch order.
func TestBuildMultiKeyOwnerAggregation(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "app-1", HostName: "10.0.1.1", User: "deploy"},
		{Alias: "app-2", HostName: "10.0.1.2", User: "deploy"},
		{Alias: "app-3", HostName: "10.0.1.3", User: "deploy"},
	}
	users := []identity.User{
		// carol touched first; the output must still order alice first (cfg.Users order).
		{Name: "carol", Source: "~/.ssh/carol", Key: testkeys.Line(t, 5), Servers: []string{"app-1"}},
		{Name: "alice", Source: "~/.ssh/a1", Key: testkeys.Line(t, 2), Servers: []string{"app-2", "app-1"}},
		{Name: "alice", Source: "~/.ssh/a2", Key: testkeys.Line(t, 3), Servers: []string{"app-1", "app-3"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	want := []Extension{
		{User: "alice", Servers: []string{"app-2", "app-1", "app-3"}},
		{User: "carol", Servers: []string{"app-1"}},
	}
	if !reflect.DeepEqual(p.Extensions, want) {
		t.Errorf("Extensions = %+v, want %+v (one merged entry per owner, cfg.Users order, first-touch servers)", p.Extensions, want)
	}
	if len(p.NewUsers) != 0 {
		t.Errorf("NewUsers = %+v, want none", p.NewUsers)
	}
}

// Wildcard absorption: a "*" user automatically gains every appended server,
// so extending them explicitly would be redundant clutter.
func TestBuildWildcardAbsorption(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "app-1", HostName: "10.0.1.1", User: "deploy"}}
	users := []identity.User{
		{Name: "bob", Source: "~/.ssh/bob", Key: testkeys.Line(t, 4), Servers: []string{"app-1"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	if len(p.Extensions) != 0 {
		t.Errorf("Extensions = %+v, want none (wildcard covers the appended server)", p.Extensions)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", p.Warnings)
	}
}

// A server in a wildcard user's except: list is never re-granted.
func TestBuildExceptCarveOutNeverRegranted(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "db-1", HostName: "10.0.0.3", Port: 2222, User: "deploy"}}
	users := []identity.User{
		{Name: "bob", Source: "~/.ssh/bob", Key: testkeys.Line(t, 4), Servers: []string{"db-1"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	if !p.Empty() {
		t.Errorf("plan = %+v, want empty (carve-out never re-granted)", p)
	}
	wantContains(t, "Warnings", p.Warnings,
		`key of "bob" used for "db-1" in the ssh config, which their except: list deliberately excludes — not re-granted; audit flags this drift`)
	if p.ConflictsSkipped() != 1 {
		t.Errorf("ConflictsSkipped() = %d, want 1", p.ConflictsSkipped())
	}
}

// Operators' implicit fleet-wide grant means no extension is ever emitted
// for a key an operator owns.
func TestBuildOperatorOwnerNoExtension(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "app-1", HostName: "10.0.1.1", User: "deploy"}}
	users := []identity.User{
		{Name: "javad-op", Source: "~/.ssh/op", Key: testkeys.Line(t, 1), Servers: []string{"app-1"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	if len(p.Extensions) != 0 || len(p.NewUsers) != 0 {
		t.Errorf("plan = %+v, want no extension for an operator owner", p)
	}
	if len(p.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", p.Warnings)
	}
}

// --operator on a key owned by an existing non-operator user is the locked
// hard error: operator status protects keys from future revocation, so
// promotion must be an explicit manifest edit.
func TestBuildOperatorPromotionError(t *testing.T) {
	users := []identity.User{
		{Name: "javad-alice", Source: "~/.ssh/alice", Operator: true, Key: testkeys.Line(t, 2)},
	}
	_, err := Build(baseCfg(t), nil, users)
	if err == nil {
		t.Fatalf("Build = nil error, want the promotion conflict")
	}
	for _, want := range []string{`"alice"`, "explicit manifest edit"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to contain %q", err, want)
		}
	}
}

// --operator on a key an existing operator already owns is a silent no-op:
// the idempotent re-run of the same flag.
func TestBuildOperatorExistingNoop(t *testing.T) {
	users := []identity.User{
		{Name: "javad-op", Source: "~/.ssh/op", Operator: true, Key: testkeys.Line(t, 1)},
	}
	p := mustBuild(t, baseCfg(t), nil, users)
	if !p.Empty() || len(p.Warnings) != 0 || len(p.Notes) != 0 {
		t.Errorf("plan = %+v, want a completely silent no-op", p)
	}
}

// An unknown --operator key is appended as a new grantless operator user
// (the fleet-wide grant is implied; no access entry).
func TestBuildOperatorUnknownAppended(t *testing.T) {
	users := []identity.User{
		{Name: "javad-spare", Source: "~/.ssh/spare", Operator: true, Key: testkeys.Line(t, 23)},
	}
	p := mustBuild(t, baseCfg(t), nil, users)
	want := []UserAdd{{
		Name:        "javad-spare",
		Description: "imported from ~/.ssh/spare (--operator)",
		Operator:    true,
		Keys:        []string{testkeys.Line(t, 23)},
	}}
	if !reflect.DeepEqual(p.NewUsers, want) {
		t.Errorf("NewUsers = %+v, want %+v", p.NewUsers, want)
	}
	if len(p.NewGrants) != 0 {
		t.Errorf("NewGrants = %+v, want none (fleet-wide grant is implied)", p.NewGrants)
	}
}

// Merged-fleet wildcard compaction: only for net-new users, only when their
// surviving grant covers the entire manifest ∪ appended fleet of ≥2 servers.
func TestBuildWildcardCompaction(t *testing.T) {
	oneServer := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
	t.Run("full merged-fleet coverage compacts", func(t *testing.T) {
		hosts := []sshcfg.Host{
			{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
			{Alias: "app-1", HostName: "10.0.1.1", User: "deploy"},
		}
		users := []identity.User{
			{Name: "newbie", Source: "~/.ssh/n", Key: testkeys.Line(t, 24), Servers: []string{"web-1", "app-1"}},
		}
		p := mustBuild(t, parseCfg(t, oneServer), hosts, users)
		wantGrants := []Grant{{User: "newbie", Servers: []string{"*"}}}
		if !reflect.DeepEqual(p.NewGrants, wantGrants) {
			t.Errorf("NewGrants = %+v, want %+v", p.NewGrants, wantGrants)
		}
		wantContains(t, "Warnings", p.Warnings, "covers every server; emitted as wildcard")
	})
	t.Run("partial coverage stays explicit", func(t *testing.T) {
		hosts := []sshcfg.Host{{Alias: "app-1", HostName: "10.0.1.1", User: "deploy"}}
		users := []identity.User{
			{Name: "newbie", Source: "~/.ssh/n", Key: testkeys.Line(t, 24), Servers: []string{"app-1"}},
		}
		p := mustBuild(t, parseCfg(t, oneServer), hosts, users)
		wantGrants := []Grant{{User: "newbie", Servers: []string{"app-1"}}}
		if !reflect.DeepEqual(p.NewGrants, wantGrants) {
			t.Errorf("NewGrants = %+v, want %+v (the manifest's web-1 is uncovered)", p.NewGrants, wantGrants)
		}
	})
	t.Run("single-server fleet never compacts", func(t *testing.T) {
		hosts := []sshcfg.Host{{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"}}
		users := []identity.User{
			{Name: "newbie", Source: "~/.ssh/n", Key: testkeys.Line(t, 24), Servers: []string{"web-1"}},
		}
		p := mustBuild(t, parseCfg(t, oneServer), hosts, users)
		wantGrants := []Grant{{User: "newbie", Servers: []string{"web-1"}}}
		if !reflect.DeepEqual(p.NewGrants, wantGrants) {
			t.Errorf("NewGrants = %+v, want %+v (one server says nothing about everywhere)", p.NewGrants, wantGrants)
		}
	})
	t.Run("extensions never compact", func(t *testing.T) {
		noGrants := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`
		hosts := []sshcfg.Host{
			{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
			{Alias: "app-1", HostName: "10.0.1.1", User: "deploy"},
		}
		users := []identity.User{
			{Name: "alice", Source: "~/.ssh/alice", Key: testkeys.Line(t, 2), Servers: []string{"web-1", "app-1"}},
		}
		p := mustBuild(t, parseCfg(t, noGrants), hosts, users)
		want := []Extension{{User: "alice", Servers: []string{"web-1", "app-1"}}}
		if !reflect.DeepEqual(p.Extensions, want) {
			t.Errorf("Extensions = %+v, want %+v (explicit even at full fleet coverage)", p.Extensions, want)
		}
	})
}

// New users render the description exactly as non-merge import does.
func TestBuildNewUserDescription(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "app-1", HostName: "10.0.1.1", User: "deploy"}}
	users := []identity.User{
		{Name: "javad-id_ed25519", Source: "~/.ssh/id_ed25519", Default: true,
			Comment: "javad@laptop", Key: testkeys.Line(t, 24) + " javad@laptop", Servers: []string{"app-1"}},
	}
	p := mustBuild(t, baseCfg(t), hosts, users)
	want := []UserAdd{{
		Name:        "javad-id_ed25519",
		Description: "imported from ~/.ssh/id_ed25519 (default identity)",
		Comment:     "javad@laptop",
		Keys:        []string{testkeys.Line(t, 24) + " javad@laptop"},
	}}
	if !reflect.DeepEqual(p.NewUsers, want) {
		t.Errorf("NewUsers = %+v, want %+v", p.NewUsers, want)
	}
}

// Build is deterministic: same inputs, same plan, field for field.
func TestBuildDeterminism(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "db-1", HostName: "10.9.9.9", Port: 2222, User: "deploy"},
		{Alias: "app-1", HostName: "10.0.1.1", User: "deploy"},
		{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
	}
	users := []identity.User{
		{Name: "carol", Source: "~/.ssh/carol", Key: testkeys.Line(t, 5), Servers: []string{"app-1"}},
		{Name: "alice", Source: "~/.ssh/alice", Key: testkeys.Line(t, 2), Servers: []string{"app-1", "db-1"}},
		{Name: "newbie", Source: "~/.ssh/n", Key: testkeys.Line(t, 24), Servers: []string{"app-1", "web-1"}},
		{Name: "alice", Source: "~/.ssh/stray", Key: testkeys.Line(t, 25), Servers: []string{"app-1"}},
	}
	a := mustBuild(t, baseCfg(t), hosts, users)
	b := mustBuild(t, baseCfg(t), hosts, users)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("Build is not deterministic:\n%+v\n%+v", a, b)
	}
}
