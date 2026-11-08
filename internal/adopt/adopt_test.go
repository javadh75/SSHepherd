package adopt

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestBuildSkipsWeakKey: an unknown 1024-bit RSA key is skipped with a
// warning, not adopted and not an Issue (the strict gate does not move).
func TestBuildSkipsWeakKey(t *testing.T) {
	line := testkeys.RSALine(t, 7, 1024)
	k, err := authkeys.ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	cfg := testCfg(t)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(line + "\n")}}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 0 || len(p.Issues) != 0 {
		t.Fatalf("plan = %+v, want no new user and no issue", p)
	}
	want := "key " + k.Fingerprint + " on web-1: rsa_under_2048 key not adopted"
	if !slices.Contains(p.Warnings, want) {
		t.Errorf("warnings = %q, want %q", p.Warnings, want)
	}
}

// TestBuildDoesNotExtendWeakOwnerKey: a known owner's weak key found on one
// more server is not granted there.
func TestBuildDoesNotExtendWeakOwnerKey(t *testing.T) {
	line := testkeys.DSALine(t, 7)
	cfg := parseConfig(t, `users:
  - {name: old, keys: ["`+line+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: old, servers: [web-1]}
`)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(line + "\n")}, "web-2": {Content: []byte(line + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 {
		t.Errorf("extensions = %+v, want none", p.Extensions)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "dsa key not adopted") {
		t.Errorf("warnings = %q", p.Warnings)
	}
}

// TestBuildRevokedWeakKeyWarnsOnce: tombstones run first, so a key that is
// both revoked and weak gets only the REVOKED warning.
func TestBuildRevokedWeakKeyWarnsOnce(t *testing.T) {
	line := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	cfg := parseConfig(t, `servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
revoked:
  - {fingerprint: `+k.Fingerprint+`, user: old, date: 2026-11-08}
`)
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(line + "\n")}}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "REVOKED") {
		t.Errorf("warnings = %q, want only the REVOKED one", p.Warnings)
	}
}

func TestSanitizeName(t *testing.T) {
	tests := []struct{ in, want string }{
		{"alice@laptop.local", "alice-laptop-local"},
		{"Alice@Laptop", "alice-laptop"},
		{"deploy", "deploy"},
		{"alice smith@host", "alice-smith-host"},
		{"a__b..c", "a-b-c"},
		{"@@@", ""},
		{"", ""},
		{"-alice-", "alice"},
		{"Röot@höst", "r-ot-h-st"},
		{"UPPER-09", "upper-09"},
	}
	for _, tt := range tests {
		if got := sanitizeName(tt.in); got != tt.want {
			t.Errorf("sanitizeName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// A huge key comment must not become a huge manifest user name: names are
// capped at 64 characters, and the cut never leaves a trailing dash.
func TestSanitizeNameCapsLength(t *testing.T) {
	if got, want := sanitizeName(strings.Repeat("a", 200)), strings.Repeat("a", 64); got != want {
		t.Errorf("sanitizeName(200 chars) = %q (len %d), want capped at 64", got, len(got))
	}
	// The 64th character lands on a dash: it must be trimmed, not kept.
	in := strings.Repeat("a", 63) + "@" + strings.Repeat("b", 50)
	if got, want := sanitizeName(in), strings.Repeat("a", 63); got != want {
		t.Errorf("sanitizeName(dash at cut) = %q, want %q", got, want)
	}
}

// fakeReader returns canned authorized_keys content per server name.
type fakeReader struct {
	byName map[string]fleet.ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (fleet.ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return fleet.ReadResult{}, err
	}
	return f.byName[srv.Name], nil
}

// runAudit produces ServerResults through the real audit pipeline so adopt
// tests consume exactly what the adopt command consumes.
func runAudit(t *testing.T, cfg *config.Config, r audit.KeyReader) []audit.ServerResult {
	t.Helper()
	return audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 4})
}

func parseConfig(t *testing.T, y string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("test config: %v", err)
	}
	return cfg
}

// testCfg: one operator, three servers, no other users.
// Server name order (= audit result order) is db-1, web-1, web-2.
func testCfg(t *testing.T) *config.Config {
	t.Helper()
	return parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
`)
}

func fpOf(t *testing.T, seed byte) string {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("fpOf(%d): %v", seed, err)
	}
	return k.Fingerprint
}

// TestBuildSkipsRevokedKey (D2a): a tombstoned key found on a server is
// neither a new user nor an extension, with a loud warning naming the
// server and the apply that removes it; an Issue-free plan keeps adopt's
// exit code untouched.
func TestBuildSkipsRevokedKey(t *testing.T) {
	stale := testkeys.Line(t, 7)
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
revoked:
  - {fingerprint: `+fpOf(t, 7)+`, user: alice, date: 2026-11-08}
`)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"web-2": {Content: []byte(testkeys.Line(t, 1) + "\n" + stale + " alice@laptop\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 0 || len(p.Extensions) != 0 || len(p.Issues) != 0 {
		t.Fatalf("plan = %+v, want nothing adopted and no issue", p)
	}
	want := "key " + fpOf(t, 7) + " on web-2 is REVOKED (2026-11-08, alice) — not adopted; run 'sshepherd apply --server web-2' to remove it"
	if len(p.Warnings) != 1 || p.Warnings[0] != want {
		t.Errorf("Warnings = %q\nwant [%q]", p.Warnings, want)
	}
}

// TestBuildHonoursAccessTombstone (D1a): bob's key found on db-1, whose
// access a revoke --server removed, is not re-granted.
func TestBuildHonoursAccessTombstone(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [web-1]}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`)
	both := fleet.ReadResult{Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": both, "web-1": both}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 || len(p.NewUsers) != 0 {
		t.Fatalf("plan = %+v, want db-1 not re-granted", p)
	}
	want := "key " + fpOf(t, 2) + ` of "bob" found on "db-1", whose access was revoked (2026-11-08) — not re-granted; audit flags this drift`
	if len(p.Warnings) != 1 || p.Warnings[0] != want {
		t.Errorf("Warnings = %q\nwant [%q]", p.Warnings, want)
	}
}

// TestBuildNameAvoidsAccessTombstone: a name surviving only in an access
// tombstone is not free to claim: the new grant would be the policy
// conflict the save then refuses, with a hint the operator cannot follow.
func TestBuildNameAvoidsAccessTombstone(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
revoked:
  - {user: bob, servers: [db-1], date: 2026-11-08}
`)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 9) + " bob\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || p.NewUsers[0].Name != "bob-2" {
		t.Fatalf("NewUsers = %+v, want one user named bob-2", p.NewUsers)
	}
}

func TestBuildUnknownKeyBecomesOneUser(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " alice@laptop.local"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n")},
		"web-1": {Content: []byte(op + "\n" + stranger + "\n")},
		"web-2": {Content: []byte(op + "\n" + stranger + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 {
		t.Fatalf("NewUsers = %+v, want exactly one", p.NewUsers)
	}
	u := p.NewUsers[0]
	if u.Name != "alice-laptop-local" {
		t.Errorf("Name = %q, want alice-laptop-local", u.Name)
	}
	if u.Line != stranger {
		t.Errorf("Line = %q, want the raw line as found", u.Line)
	}
	if !reflect.DeepEqual(u.FoundOn, []string{"web-1", "web-2"}) {
		t.Errorf("FoundOn = %v, want [web-1 web-2]", u.FoundOn)
	}
	if len(p.Extensions) != 0 || len(p.Issues) != 0 || len(p.Warnings) != 0 {
		t.Errorf("Extensions/Issues/Warnings = %+v/%+v/%+v, want none",
			p.Extensions, p.Issues, p.Warnings)
	}
}

// The operator's key is desired everywhere, so it never surfaces as
// unauthorized — a fully compliant fleet yields an empty plan.
func TestBuildCompliantFleetEmptyPlan(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	content := fleet.ReadResult{Content: []byte(op + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1": content, "web-1": content, "web-2": content,
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers)+len(p.Extensions)+len(p.Warnings)+len(p.Issues) != 0 {
		t.Errorf("plan = %+v, want empty", p)
	}
}

// A file-absent server contributes nothing and is not an error.
func TestBuildFileAbsentServer(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {FileAbsent: true},
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 0 || len(p.Issues) != 0 {
		t.Errorf("plan = %+v, want empty (absent file is fine)", p)
	}
}

func TestBuildAnonymousKeysNumberedInDiscoveryOrder(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	anonA, anonB := testkeys.Line(t, 8), testkeys.Line(t, 9)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + anonA + "\n")},
		"web-1": {Content: []byte(op + "\n" + anonB + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 2 {
		t.Fatalf("NewUsers = %+v, want two", p.NewUsers)
	}
	// db-1 sorts before web-1, so anonA is discovered first.
	if p.NewUsers[0].Name != "adopted-key-1" || p.NewUsers[0].Line != anonA {
		t.Errorf("first = %+v, want adopted-key-1 = anonA", p.NewUsers[0])
	}
	if p.NewUsers[1].Name != "adopted-key-2" || p.NewUsers[1].Line != anonB {
		t.Errorf("second = %+v, want adopted-key-2 = anonB", p.NewUsers[1])
	}
}

func TestBuildNameCollisions(t *testing.T) {
	// Existing manifest user "carol" + two distinct stranger keys whose
	// comments both sanitize to "carol" -> carol-2, carol-3.
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: carol, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: carol, servers: [web-1]}
`)
	op, carol := testkeys.Line(t, 1), testkeys.Line(t, 2)
	k1 := testkeys.Line(t, 7) + " carol@a"
	k2 := testkeys.Line(t, 8) + " Carol"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(op + "\n" + carol + "\n" + k1 + "\n" + k2 + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 2 {
		t.Fatalf("NewUsers = %+v, want two", p.NewUsers)
	}
	if p.NewUsers[0].Name != "carol-a" {
		t.Errorf("first = %q, want carol-a", p.NewUsers[0].Name)
	}
	if p.NewUsers[1].Name != "carol-2" {
		t.Errorf("second = %q, want carol-2 (collides with manifest user carol)", p.NewUsers[1].Name)
	}
}

// TestBuildNeverWildcards (D5): a key found on every server of the fleet is
// granted those servers by name — never "*", which would also grant every
// server added later — and adopt says nothing about wildcards.
func TestBuildNeverWildcards(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	everywhere := testkeys.Line(t, 7) + " carol@laptop"
	content := fleet.ReadResult{Content: []byte(op + "\n" + everywhere + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1": content, "web-1": content, "web-2": content,
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || !reflect.DeepEqual(p.NewUsers[0].FoundOn, []string{"db-1", "web-1", "web-2"}) {
		t.Fatalf("NewUsers = %+v, want one user found on all three servers", p.NewUsers)
	}
	for _, w := range p.Warnings {
		if strings.Contains(w, "wildcard") {
			t.Errorf("unexpected wildcard warning %q", w)
		}
	}
}

// Same fingerprint, different comment on the second server: first copy wins,
// a warning names the divergence.
func TestBuildDivergentCopiesFirstWins(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	first := testkeys.Line(t, 7) + " carol@a"
	second := testkeys.Line(t, 7) + " carol@b"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + first + "\n")},
		"web-1": {Content: []byte(op + "\n" + second + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || p.NewUsers[0].Line != first {
		t.Fatalf("NewUsers = %+v, want one user keeping the db-1 copy", p.NewUsers)
	}
	if p.NewUsers[0].Name != "carol-a" {
		t.Errorf("Name = %q, want carol-a (first-seen comment names the user)", p.NewUsers[0].Name)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "web-1") {
		t.Errorf("Warnings = %v, want one divergence note naming web-1", p.Warnings)
	}
}

// extCfg: alice (two keys) granted web-1 only; bob wildcard except db-1.
func extCfg(t *testing.T) *config.Config {
	t.Helper()
	return parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: alice, keys: ["`+testkeys.Line(t, 2)+`", "`+testkeys.Line(t, 3)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 4)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: ["*"], except: [db-1]}
`)
}

func TestBuildExtendsKnownUser(t *testing.T) {
	cfg := extCfg(t)
	op, al := testkeys.Line(t, 1), testkeys.Line(t, 2)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + al + "\n")},
		"web-1": {Content: []byte(op + "\n" + al + "\n")}, // granted: not an extension
		"web-2": {Content: []byte(op + "\n" + al + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	want := []Extension{{User: "alice", Servers: []string{"db-1", "web-2"}}}
	if !reflect.DeepEqual(p.Extensions, want) {
		t.Errorf("Extensions = %+v, want %+v", p.Extensions, want)
	}
	if len(p.NewUsers) != 0 {
		t.Errorf("NewUsers = %+v, want none (the key is alice's)", p.NewUsers)
	}
}

// Two different keys of the same user on one ungranted server extend it once.
func TestBuildExtensionDedupesServers(t *testing.T) {
	cfg := extCfg(t)
	op, al1, al2 := testkeys.Line(t, 1), testkeys.Line(t, 2), testkeys.Line(t, 3)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n")},
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n" + al1 + "\n" + al2 + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	want := []Extension{{User: "alice", Servers: []string{"web-2"}}}
	if !reflect.DeepEqual(p.Extensions, want) {
		t.Errorf("Extensions = %+v, want %+v (web-2 once, not twice)", p.Extensions, want)
	}
}

// An except: carve-out is a deliberate "must not be here": never re-granted,
// warned instead.
func TestBuildRespectsExceptCarveOut(t *testing.T) {
	cfg := extCfg(t)
	op, bo := testkeys.Line(t, 1), testkeys.Line(t, 4)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + bo + "\n")}, // bob is excepted from db-1
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 {
		t.Errorf("Extensions = %+v, want none (db-1 is bob's except carve-out)", p.Extensions)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "bob") ||
		!strings.Contains(p.Warnings[0], "db-1") {
		t.Errorf("Warnings = %v, want one naming bob and db-1", p.Warnings)
	}
}

// Extensions come out in manifest user order regardless of discovery order.
func TestBuildExtensionsManifestOrder(t *testing.T) {
	op, al, bo := testkeys.Line(t, 1), testkeys.Line(t, 2), testkeys.Line(t, 4)
	// bob's key on web-1 is discovered before alice's on web-2, but alice
	// precedes bob in the manifest. Explicit grants only (no wildcard), so
	// both users have exactly one ungranted server to be found on.
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: alice, keys: ["`+testkeys.Line(t, 2)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 4)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: [web-2]}
`)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(op + "\n" + al + "\n" + bo + "\n")},
		"web-2": {Content: []byte(op + "\n" + al + "\n" + bo + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	want := []Extension{
		{User: "alice", Servers: []string{"web-2"}},
		{User: "bob", Servers: []string{"web-1"}},
	}
	if !reflect.DeepEqual(p.Extensions, want) {
		t.Errorf("Extensions = %+v, want %+v (manifest user order)", p.Extensions, want)
	}
}

func TestBuildUnreachableServerIsAnIssue(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@x"
	r := &fakeReader{
		byName: map[string]fleet.ReadResult{
			"web-1": {Content: []byte(op + "\n" + stranger + "\n")},
			"web-2": {Content: []byte(op + "\n")},
		},
		errs: map[string]error{"db-1": errors.New("dial tcp: connection refused")},
	}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Issues) != 1 || p.Issues[0].Server != "db-1" ||
		!strings.Contains(p.Issues[0].Detail, "connection refused") {
		t.Fatalf("Issues = %+v, want db-1 with the dial error", p.Issues)
	}
	// Readable servers are still attributed.
	if len(p.NewUsers) != 1 || p.NewUsers[0].Name != "carol-x" {
		t.Errorf("NewUsers = %+v, want carol-x from web-1", p.NewUsers)
	}
	if got := p.UnreadableServers(); !reflect.DeepEqual(got, []string{"db-1"}) {
		t.Errorf("UnreadableServers = %v, want [db-1]", got)
	}
}

// hintedErr is a classified transport error with its remediation kept out
// of the message (the fleet.KindedError and fleet.Hinted pair that
// sshconn.Error implements), built here so adopt's tests need no transport
// import (ARC-8).
type hintedErr struct {
	kind fleet.ErrorKind
	hint string
	err  error
}

func (e *hintedErr) Error() string              { return e.err.Error() }
func (e *hintedErr) Unwrap() error              { return e.err }
func (e *hintedErr) ErrorKind() fleet.ErrorKind { return e.kind }
func (e *hintedErr) ErrorHint() string          { return e.hint }

// testDialHint stands in for the transport's dial hint.
const testDialHint = "check the host, port, and firewall"

// The dial hint is not part of the error text (sshconn keeps it out of
// Error()), so an Issue carries it in its own field for the cmd layer to
// print once; Detail stays the clean error.
func TestBuildKeepsHint(t *testing.T) {
	cfg := testCfg(t)
	err := &hintedErr{
		kind: fleet.ErrorKindDial,
		err:  errors.New("dial tcp 127.0.0.1:1: connect: connection refused"),
		hint: testDialHint,
	}
	p := Build(cfg, []audit.ServerResult{{Server: config.Server{Name: "db-1"}, Err: err}})
	if len(p.Issues) != 1 {
		t.Fatalf("Issues = %+v, want one", p.Issues)
	}
	if got, want := p.Issues[0].Hint, audit.CleanHint(err); got != want || got == "" {
		t.Errorf("Issues[0].Hint = %q, want %q", got, want)
	}
	if strings.Contains(p.Issues[0].Detail, testDialHint) {
		t.Errorf("Issues[0].Detail = %q, must not embed the dial hint", p.Issues[0].Detail)
	}
}

// Unparseable lines are issues too (they might be real access we would
// silently drop), but the lines that did parse are still attributed.
func TestBuildParseErrorsAreIssues(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@x"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\ngarbage-line\nmore garbage\n" + stranger + "\n")},
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Issues) != 2 {
		t.Fatalf("Issues = %+v, want two (one per bad line)", p.Issues)
	}
	if p.Issues[0].Server != "db-1" || p.Issues[1].Server != "db-1" {
		t.Errorf("Issues = %+v, want both on db-1", p.Issues)
	}
	if got := p.UnreadableServers(); !reflect.DeepEqual(got, []string{"db-1"}) {
		t.Errorf("UnreadableServers = %v, want [db-1] (deduped)", got)
	}
	if len(p.NewUsers) != 1 || p.NewUsers[0].Name != "carol-x" {
		t.Errorf("NewUsers = %+v, want carol-x (parsed lines still adopted)", p.NewUsers)
	}
}

// A wildcard user whose except server is ALSO explicitly granted is simply
// granted there (entries union): their key on that server is authorized, so
// adopt neither extends nor warns. Pins the config-layer union invariant
// config.ExceptCarveOut relies on.
func TestBuildExceptOverriddenByExplicitGrant(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 4)+`"]}
servers:
  - {name: db-1, host: 10.0.0.3, user: deploy}
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: ["*"], except: [db-1]}
  - {user: bob, servers: [db-1]}
`)
	op, bo := testkeys.Line(t, 1), testkeys.Line(t, 4)
	content := fleet.ReadResult{Content: []byte(op + "\n" + bo + "\n")}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"db-1": content, "web-1": content}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 || len(p.Warnings) != 0 || len(p.NewUsers) != 0 {
		t.Errorf("plan = %+v, want empty (explicit grant overrides except)", p)
	}
}

// A key on every server, one copy with a different comment: one user keeps
// the first copy, and one divergence note is the only warning (no wildcard
// compaction, D5).
func TestBuildDivergenceKeepsFirstCopy(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	first := testkeys.Line(t, 7) + " carol@a"
	variant := testkeys.Line(t, 7) + " carol@b"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + first + "\n")},
		"web-1": {Content: []byte(op + "\n" + variant + "\n")},
		"web-2": {Content: []byte(op + "\n" + first + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || p.NewUsers[0].Line != first {
		t.Fatalf("NewUsers = %+v, want one user keeping the first copy", p.NewUsers)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "differs") {
		t.Errorf("Warnings = %v, want one divergence note", p.Warnings)
	}
}

// Issues on two servers: UnreadableServers dedupes per server and preserves
// result order.
func TestUnreadableServersOrderAndDedup(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	r := &fakeReader{
		byName: map[string]fleet.ReadResult{
			"web-1": {Content: []byte(op + "\ngarbage-one\ngarbage-two\n")},
			"web-2": {Content: []byte(op + "\n")},
		},
		errs: map[string]error{"db-1": errors.New("connection refused")},
	}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Issues) != 3 {
		t.Fatalf("Issues = %+v, want three (one dial + two parse)", p.Issues)
	}
	if got := p.UnreadableServers(); !reflect.DeepEqual(got, []string{"db-1", "web-1"}) {
		t.Errorf("UnreadableServers = %v, want [db-1, web-1] (deduped, result order)", got)
	}
}

// An unreadable server is an issue; the key is granted exactly the servers
// it was read on.
func TestBuildUnreadableServerListed(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@x"
	content := fleet.ReadResult{Content: []byte(op + "\n" + stranger + "\n")}
	r := &fakeReader{
		byName: map[string]fleet.ReadResult{"web-1": content, "web-2": content},
		errs:   map[string]error{"db-1": errors.New("connection refused")},
	}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || !reflect.DeepEqual(p.NewUsers[0].FoundOn, []string{"web-1", "web-2"}) {
		t.Fatalf("NewUsers = %+v, want one user found on web-1 and web-2 (db-1 was unreadable)", p.NewUsers)
	}
	if got := p.UnreadableServers(); !reflect.DeepEqual(got, []string{"db-1"}) {
		t.Errorf("UnreadableServers = %v, want [db-1]", got)
	}
}

// A remote key whose comment the manifest would reject (tab, ESC, bidi
// override) is still adopted — the key is what grants access — but without
// its comment, and loudly; the generated line must pass manifest validation
// instead of failing adopt's self-check as a "bug:".
func TestBuildUnsafeCommentAdoptedWithoutComment(t *testing.T) {
	for name, comment := range map[string]string{
		"tab":  "alice\tlaptop",
		"esc":  "alice\x1b[31m",
		"bidi": "alice\u202e",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := testCfg(t)
			op := testkeys.Line(t, 1)
			bare := `no-pty,command="/bin/true" ` + testkeys.Line(t, 7)
			line := bare + " " + comment
			r := &fakeReader{byName: map[string]fleet.ReadResult{
				"db-1":  {Content: []byte(op + "\n" + line + "\n")},
				"web-1": {Content: []byte(op + "\n" + line + "\n")},
				"web-2": {Content: []byte(op + "\n")},
			}}
			p := Build(cfg, runAudit(t, cfg, r))
			if len(p.NewUsers) != 1 {
				t.Fatalf("NewUsers = %+v, want one", p.NewUsers)
			}
			if got := p.NewUsers[0].Line; got != bare {
				t.Errorf("Line = %q, want options + key without the comment %q", got, bare)
			}
			if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "adopted without its comment") ||
				!strings.Contains(p.Warnings[0], "db-1") {
				t.Errorf("Warnings = %v, want one adopted-without-comment warning naming db-1", p.Warnings)
			}
			if _, err := config.Parse([]byte(`
users:
  - {name: x, keys: ['` + p.NewUsers[0].Line + `']}
`)); err != nil {
				t.Errorf("adopted line fails manifest validation: %v", err)
			}
		})
	}
}

// adopt --merge re-runs see the previous run's adopted-key-<n> users in the
// manifest; numbering continues past them instead of stacking suffixes
// (adopted-key-1-2).
func TestBuildAnonymousNumberingContinuesAcrossRuns(t *testing.T) {
	prev := testkeys.Line(t, 5)
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: adopted-key-1, keys: ["`+prev+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: adopted-key-1, servers: [web-1]}
`)
	op := testkeys.Line(t, 1)
	anonA, anonB := testkeys.Line(t, 8), testkeys.Line(t, 9)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(op + "\n" + prev + "\n" + anonA + "\n" + anonB + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	var names []string
	for _, u := range p.NewUsers {
		names = append(names, u.Name)
	}
	if want := []string{"adopted-key-2", "adopted-key-3"}; !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

// A found key whose options sshd rejects never logs in: it is an Issue (strict
// gate / --partial), never an adopted user or an access extension.
func TestBuildBadOptionLineIsAnIssue(t *testing.T) {
	for _, prefix := range []string{"zzz ", "no-ptty ", "from=1.2.3.4 "} {
		t.Run(prefix, func(t *testing.T) {
			cfg := testCfg(t)
			op := testkeys.Line(t, 1)
			bad := prefix + testkeys.Line(t, 7) + " carol@laptop"
			good := testkeys.Line(t, 8) + " dave@x"
			r := &fakeReader{byName: map[string]fleet.ReadResult{
				"db-1":  {Content: []byte(op + "\n" + bad + "\n" + good + "\n")},
				"web-1": {Content: []byte(op + "\n")},
				"web-2": {Content: []byte(op + "\n")},
			}}
			p := Build(cfg, runAudit(t, cfg, r))
			if len(p.Issues) != 1 || p.Issues[0].Server != "db-1" ||
				!strings.Contains(p.Issues[0].Detail, "sshd ignores this line: option ") {
				t.Fatalf("Issues = %+v, want one 'sshd ignores this line' issue on db-1", p.Issues)
			}
			if len(p.NewUsers) != 1 || p.NewUsers[0].Name != "dave-x" {
				t.Errorf("NewUsers = %+v, want only dave-x (the bad line is not adopted)", p.NewUsers)
			}
		})
	}
}

// A known user's key on a line sshd ignores is not access: no extension.
func TestBuildBadOptionKnownKeyNotExtended(t *testing.T) {
	cfg := extCfg(t) // existing helper (adopt_test.go:264): alice granted web-1 only
	op, al := testkeys.Line(t, 1), testkeys.Line(t, 2)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + "zzz " + al + "\n")}, // outside alice's grants, line sshd ignores
		"web-1": {Content: []byte(op + "\n" + al + "\n")},          // granted: not an extension
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 {
		t.Errorf("Extensions = %+v, want none (sshd ignores the db-1 line, so it grants nothing)", p.Extensions)
	}
	if len(p.Issues) != 1 || p.Issues[0].Server != "db-1" ||
		!strings.Contains(p.Issues[0].Detail, "sshd ignores this line: option ") {
		t.Errorf("Issues = %+v, want one 'sshd ignores this line' issue on db-1", p.Issues)
	}
	if len(p.NewUsers) != 0 {
		t.Errorf("NewUsers = %+v, want none (the key is alice's)", p.NewUsers)
	}
}

// sshd skips a line it cannot read and keeps scanning, so a later valid line
// of the same key still logs in (OpenSSH_10.3p1: 'zzz KEY' then 'KEY' lets
// the key in). The key is access, adopted from the line sshd honors, in
// either line order.
func TestBuildBadThenGoodLineIsAccess(t *testing.T) {
	op := testkeys.Line(t, 1)
	t.Run("unknown key", func(t *testing.T) {
		for _, content := range []string{
			"zzz " + testkeys.Line(t, 7) + " carol@laptop\n" + testkeys.Line(t, 7) + " carol@laptop\n",
			testkeys.Line(t, 7) + " carol@laptop\n" + "zzz " + testkeys.Line(t, 7) + " carol@laptop\n",
			`command="a",command="b" ` + testkeys.Line(t, 7) + " carol@laptop\n" + testkeys.Line(t, 7) + " carol@laptop\n",
		} {
			cfg := testCfg(t)
			r := &fakeReader{byName: map[string]fleet.ReadResult{
				"db-1":  {Content: []byte(op + "\n" + content)},
				"web-1": {Content: []byte(op + "\n")},
				"web-2": {Content: []byte(op + "\n")},
			}}
			p := Build(cfg, runAudit(t, cfg, r))
			if len(p.Issues) != 0 {
				t.Errorf("%q: Issues = %+v, want none (a later line logs in)", content, p.Issues)
			}
			want := testkeys.Line(t, 7) + " carol@laptop"
			if len(p.NewUsers) != 1 || p.NewUsers[0].Line != want {
				t.Errorf("%q: NewUsers = %+v, want carol adopted from the line sshd honors", content, p.NewUsers)
			}
		}
	})
	t.Run("known key", func(t *testing.T) {
		cfg := extCfg(t)
		al := testkeys.Line(t, 2)
		r := &fakeReader{byName: map[string]fleet.ReadResult{
			"db-1":  {Content: []byte(op + "\n" + "zzz " + al + "\n" + al + "\n")},
			"web-1": {Content: []byte(op + "\n" + al + "\n")},
			"web-2": {Content: []byte(op + "\n")},
		}}
		p := Build(cfg, runAudit(t, cfg, r))
		if len(p.Issues) != 0 {
			t.Errorf("Issues = %+v, want none", p.Issues)
		}
		if len(p.Extensions) != 1 || p.Extensions[0].User != "alice" || !reflect.DeepEqual(p.Extensions[0].Servers, []string{"db-1"}) {
			t.Errorf("Extensions = %+v, want alice extended to db-1", p.Extensions)
		}
	})
}

// Every line of the key is one sshd ignores: one Issue, nothing adopted.
func TestBuildEveryLineIgnoredIsAnIssue(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	k := testkeys.Line(t, 7) + " carol@laptop"
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + "zzz " + k + "\n" + "no-ptty " + k + "\n")},
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Issues) != 1 || !strings.Contains(p.Issues[0].Detail, `sshd ignores each of its 2 lines; the first: option "zzz" is not a recognized authorized_keys option`) {
		t.Errorf("Issues = %+v, want one issue naming both ignored lines", p.Issues)
	}
	if len(p.NewUsers) != 0 {
		t.Errorf("NewUsers = %+v, want none", p.NewUsers)
	}
}

// A repeated command=/from= clause makes sshd reject the line (auth-options.c).
func TestBuildRepeatedClauseLineIsAnIssue(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + `command="echo A",command="echo B" ` + testkeys.Line(t, 7) + " carol@laptop\n")},
		"web-1": {Content: []byte(op + "\n")},
		"web-2": {Content: []byte(op + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Issues) != 1 || !strings.Contains(p.Issues[0].Detail, "sshd ignores this line: option ") ||
		!strings.Contains(p.Issues[0].Detail, "which sshd allows once per line") {
		t.Errorf("Issues = %+v, want one 'sshd ignores this line' repeated-clause issue", p.Issues)
	}
	if len(p.NewUsers) != 0 {
		t.Errorf("NewUsers = %+v, want none", p.NewUsers)
	}
}

// sshd accepts control bytes inside a quoted value (opt_dequote copies them),
// so such a line is access. For a known key the server's options never reach
// the manifest: the extension stands. An unknown key's line cannot be stored
// (the manifest refuses control runes): an Issue that says so, not "sshd
// ignores".
func TestBuildControlRuneOptionLine(t *testing.T) {
	op := testkeys.Line(t, 1)
	t.Run("known key extends", func(t *testing.T) {
		cfg := extCfg(t)
		al := testkeys.Line(t, 2)
		r := &fakeReader{byName: map[string]fleet.ReadResult{
			"db-1":  {Content: []byte(op + "\n" + "command=\"echo\ta\" " + al + "\n")},
			"web-1": {Content: []byte(op + "\n" + al + "\n")},
			"web-2": {Content: []byte(op + "\n")},
		}}
		p := Build(cfg, runAudit(t, cfg, r))
		if len(p.Issues) != 0 {
			t.Errorf("Issues = %+v, want none", p.Issues)
		}
		if len(p.Extensions) != 1 || !reflect.DeepEqual(p.Extensions[0].Servers, []string{"db-1"}) {
			t.Errorf("Extensions = %+v, want alice extended to db-1", p.Extensions)
		}
	})
	t.Run("unknown key is an issue", func(t *testing.T) {
		cfg := testCfg(t)
		r := &fakeReader{byName: map[string]fleet.ReadResult{
			"db-1":  {Content: []byte(op + "\n" + "command=\"echo\ta\" " + testkeys.Line(t, 7) + " carol@laptop\n")},
			"web-1": {Content: []byte(op + "\n")},
			"web-2": {Content: []byte(op + "\n")},
		}}
		p := Build(cfg, runAudit(t, cfg, r))
		if len(p.Issues) != 1 || strings.Contains(p.Issues[0].Detail, "sshd ignores") ||
			!strings.Contains(p.Issues[0].Detail, "this line logs in, but the manifest cannot hold it: option ") ||
			!strings.Contains(p.Issues[0].Detail, "contains control or format characters") {
			t.Errorf("Issues = %+v, want one 'manifest cannot hold it' issue", p.Issues)
		}
		if len(p.NewUsers) != 0 {
			t.Errorf("NewUsers = %+v, want none", p.NewUsers)
		}
	})
}
