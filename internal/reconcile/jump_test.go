package reconcile

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestCollapseTargetsByRoute: one target reached two ways may be two
// machines, so the later host is dropped and its grants do not move; the
// same route collapses as before; one address over two routes is dropped
// too, even for another user (OP7).
func TestCollapseTargetsByRoute(t *testing.T) {
	bastion := jh("bastion", "bastion.example.com", "jump", "")
	for _, tt := range []struct {
		name      string
		hosts     []sshcfg.Host
		wantKept  []string
		wantGrant []string // web-b's user's servers afterwards
		warning   string
	}{
		{name: "same target, same route: grants move",
			hosts:     []sshcfg.Host{jh("web-a", "10.0.0.5", "deploy", ""), jh("web-b", "10.0.0.5", "deploy", "")},
			wantKept:  []string{"web-a"},
			wantGrant: []string{"web-a"},
			warning:   `server "web-b" in the ssh config targets the same host, port, user and authorized_keys file as host "web-a"`},
		{name: "same target, direct and through a bastion",
			hosts:     []sshcfg.Host{bastion, jh("web-a", "10.0.0.5", "deploy", ""), jh("web-b", "10.0.0.5", "deploy", "ProxyJump bastion")},
			wantKept:  []string{"bastion", "web-a"},
			wantGrant: []string{},
			warning:   `server "web-b" in the ssh config has the same host, port and user as "web-a" but a different route — skipped, and its access is not moved to "web-a"; a manifest holds one entry per address`},
		{name: "same target, two bastions",
			hosts: []sshcfg.Host{jh("b1", "b1.example.com", "jump", ""), jh("b2", "b2.example.com", "jump", ""),
				jh("web-a", "10.0.0.5", "deploy", "ProxyJump b1"), jh("web-b", "10.0.0.5", "deploy", "ProxyJump b2")},
			wantKept:  []string{"b1", "b2", "web-a"},
			wantGrant: []string{},
			warning:   `server "web-b" in the ssh config has the same host, port and user as "web-a" but a different route — skipped, and its access is not moved to "web-a"; a manifest holds one entry per address`},
		{name: "one address, another user, another route",
			hosts:     []sshcfg.Host{bastion, jh("web-a", "10.0.0.5", "deploy", ""), jh("web-b", "10.0.0.5", "ops", "ProxyJump bastion")},
			wantKept:  []string{"bastion", "web-a"},
			wantGrant: []string{},
			warning:   `server "web-b" in the ssh config is at the same address as "web-a" but takes a different route — skipped, and its access is not moved; every entry at one address must use the same route`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			users := []identity.User{{Name: "bob", Key: testkeys.Line(t, 2), Servers: []string{"web-b"}}}
			kept, out, warnings := CollapseTargets(tt.hosts, users)
			var names []string
			for _, h := range kept {
				names = append(names, h.Alias)
			}
			if !slices.Equal(names, tt.wantKept) {
				t.Errorf("kept = %v, want %v", names, tt.wantKept)
			}
			if got := out[0].Servers; !slices.Equal(got, tt.wantGrant) && (len(got) != 0 || len(tt.wantGrant) != 0) {
				t.Errorf("bob's servers = %v, want %v", got, tt.wantGrant)
			}
			if len(warnings) != 1 || !strings.Contains(warnings[0], tt.warning) {
				t.Errorf("warnings = %q, want one containing %q", warnings, tt.warning)
			}
			if !slices.Equal(users[0].Servers, []string{"web-b"}) {
				t.Error("CollapseTargets modified its input")
			}
		})
	}
}

// TestBuildRouteAgainstManifest: under --merge, an incoming host at a
// manifest server's target by another route is a conflict whose grants are
// dropped; a new server gets its mapped via; a via onto a host that was not
// appended is cleared and warned.
func TestBuildRouteAgainstManifest(t *testing.T) {
	cfg := parseCfg(t, "users: []\nservers:\n  - {name: web-a, host: 10.0.0.5, user: deploy}\n  - {name: bastion-eu, host: bastion.eu, user: jump, jump_only: true}\n")
	hosts := []sshcfg.Host{
		jh("web-b", "10.0.0.5", "deploy", "ProxyJump bastion-eu"),
		jh("app", "10.0.1.7", "deploy", "ProxyJump bastion-eu"),
	}
	plan := mustBuild(t, cfg, hosts, nil)
	if len(plan.NewServers) != 1 || plan.NewServers[0].Name != "app" || plan.NewServers[0].Via != "bastion-eu" {
		t.Fatalf("NewServers = %+v, want app via bastion-eu only", plan.NewServers)
	}
	var msgs []string
	for _, w := range plan.Warnings {
		msgs = append(msgs, w.Message)
	}
	wantContains(t, "merge", msgs, `server "web-b" in the ssh config has the same host, port and user as manifest server "web-a" but a different route`)
}

// TestMergeAddsNoGrantOnJumpOnly: an ssh config key used on a manifest
// jump_only server adds no access there and notes it once; the fleet set
// leaves it out, so a grant on every other server still becomes "*".
func TestMergeAddsNoGrantOnJumpOnly(t *testing.T) {
	alice := testkeys.Line(t, 1)
	cfg := parseCfg(t, "users:\n  - {name: alice, keys: [\""+alice+"\"]}\n"+
		"servers:\n  - {name: bastion-eu, host: bastion.eu, user: jump, jump_only: true}\n"+
		"  - {name: web-1, host: 10.0.1.5, user: deploy, via: bastion-eu}\n  - {name: web-2, host: 10.0.1.6, user: deploy, via: bastion-eu}\n")
	hosts := []sshcfg.Host{
		jh("bastion-eu", "bastion.eu", "jump", ""),
		jh("web-1", "10.0.1.5", "deploy", "ProxyJump bastion-eu"),
		jh("web-2", "10.0.1.6", "deploy", "ProxyJump bastion-eu"),
	}
	users := []identity.User{
		{Name: "alice", Key: alice, Source: "~/.ssh/id_a", Servers: []string{"bastion-eu", "web-1"}},
		{Name: "bob", Key: testkeys.Line(t, 2), Source: "~/.ssh/id_b", Servers: []string{"bastion-eu", "web-1", "web-2"}},
	}
	plan := mustBuild(t, cfg, hosts, users)
	note := `server "bastion-eu" is jump_only in the manifest; no access added`
	if n := strings.Count(strings.Join(plan.Notes, "\n"), note); n != 1 {
		t.Errorf("notes = %q, want the jump_only note exactly once", plan.Notes)
	}
	for _, e := range plan.Extensions {
		if slices.Contains(e.Servers, "bastion-eu") {
			t.Errorf("extension %+v names the jump_only server", e)
		}
	}
	if len(plan.NewGrants) != 1 || !slices.Equal(plan.NewGrants[0].Servers, []string{"*"}) {
		t.Errorf("NewGrants = %+v, want bob compacted to *", plan.NewGrants)
	}
}
