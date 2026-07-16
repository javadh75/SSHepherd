package adopt

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

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
	byName map[string]audit.ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (audit.ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return audit.ReadResult{}, err
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

func TestBuildUnknownKeyBecomesOneUser(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " alice@laptop.local"
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
	content := audit.ReadResult{Content: []byte(op + "\n")}
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
	r := &fakeReader{byName: map[string]audit.ReadResult{
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

func TestBuildWildcardCompaction(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	everywhere := testkeys.Line(t, 7) + " carol@laptop"
	content := audit.ReadResult{Content: []byte(op + "\n" + everywhere + "\n")}
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1": content, "web-1": content, "web-2": content,
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || !p.NewUsers[0].Wildcard {
		t.Fatalf("NewUsers = %+v, want one wildcard user", p.NewUsers)
	}
	if !reflect.DeepEqual(p.NewUsers[0].FoundOn, []string{"db-1", "web-1", "web-2"}) {
		t.Errorf("FoundOn = %v, want all three servers (for the description)", p.NewUsers[0].FoundOn)
	}
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "wildcard") {
		t.Errorf("Warnings = %v, want one wildcard-compaction note", p.Warnings)
	}
}

// A single-server fleet says nothing about "everywhere" — no compaction.
func TestBuildNoCompactionSingleServer(t *testing.T) {
	cfg := parseConfig(t, `
users:
  - {name: op, operator: true, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 7) + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || p.NewUsers[0].Wildcard {
		t.Fatalf("NewUsers = %+v, want one non-wildcard user", p.NewUsers)
	}
}

// Same fingerprint, different comment on the second server: first copy wins,
// a warning names the divergence.
func TestBuildDivergentCopiesFirstWins(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	first := testkeys.Line(t, 7) + " carol@a"
	second := testkeys.Line(t, 7) + " carol@b"
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
		byName: map[string]audit.ReadResult{
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

// Unparseable lines are issues too (they might be real access we would
// silently drop), but the lines that did parse are still attributed.
func TestBuildParseErrorsAreIssues(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@x"
	r := &fakeReader{byName: map[string]audit.ReadResult{
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
// hasExceptCarveOut relies on.
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
	content := audit.ReadResult{Content: []byte(op + "\n" + bo + "\n")}
	r := &fakeReader{byName: map[string]audit.ReadResult{"db-1": content, "web-1": content}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.Extensions) != 0 || len(p.Warnings) != 0 || len(p.NewUsers) != 0 {
		t.Errorf("plan = %+v, want empty (explicit grant overrides except)", p)
	}
}

// Divergence and compaction compose: a key on every server, one copy with a
// different comment, still compacts to a wildcard and warns once about each.
func TestBuildDivergenceAndCompactionCompose(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	first := testkeys.Line(t, 7) + " carol@a"
	variant := testkeys.Line(t, 7) + " carol@b"
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + first + "\n")},
		"web-1": {Content: []byte(op + "\n" + variant + "\n")},
		"web-2": {Content: []byte(op + "\n" + first + "\n")},
	}}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || !p.NewUsers[0].Wildcard || p.NewUsers[0].Line != first {
		t.Fatalf("NewUsers = %+v, want one wildcard user keeping the first copy", p.NewUsers)
	}
	var divergence, wildcard int
	for _, w := range p.Warnings {
		if strings.Contains(w, "differs") {
			divergence++
		}
		if strings.Contains(w, "wildcard") {
			wildcard++
		}
	}
	if divergence != 1 || wildcard != 1 || len(p.Warnings) != 2 {
		t.Errorf("Warnings = %v, want one divergence + one wildcard note", p.Warnings)
	}
}

// Issues on two servers: UnreadableServers dedupes per server and preserves
// result order.
func TestUnreadableServersOrderAndDedup(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	r := &fakeReader{
		byName: map[string]audit.ReadResult{
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

// An unreadable server prevents wildcard compaction: found-on can't cover a
// fleet we couldn't fully see.
func TestBuildUnreadableServerSuppressesCompaction(t *testing.T) {
	cfg := testCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@x"
	content := audit.ReadResult{Content: []byte(op + "\n" + stranger + "\n")}
	r := &fakeReader{
		byName: map[string]audit.ReadResult{"web-1": content, "web-2": content},
		errs:   map[string]error{"db-1": errors.New("connection refused")},
	}
	p := Build(cfg, runAudit(t, cfg, r))
	if len(p.NewUsers) != 1 || p.NewUsers[0].Wildcard {
		t.Fatalf("NewUsers = %+v, want one non-wildcard user (db-1 was unreadable)", p.NewUsers)
	}
	if got := p.UnreadableServers(); !reflect.DeepEqual(got, []string{"db-1"}) {
		t.Errorf("UnreadableServers = %v, want [db-1]", got)
	}
}
