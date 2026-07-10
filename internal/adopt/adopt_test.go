package adopt

import (
	"context"
	"reflect"
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
