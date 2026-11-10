package reconcile

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
)

func jh(alias, hostname, user, proxy string) sshcfg.Host {
	return sshcfg.Host{Alias: alias, HostName: hostname, User: user, Proxy: proxy}
}

// TestMapRoutes is the import mapping table (spec S5 Import, gap item 11).
func TestMapRoutes(t *testing.T) {
	bastion := jh("bastion", "bastion.example.com", "jump", "")
	inner := jh("inner", "10.0.0.9", "ops", "ProxyJump bastion")
	manifest := []config.Server{
		{Name: "bastion-eu", Host: "bastion.eu", Port: 22, User: "jump", JumpOnly: true},
		{Name: "mid", Host: "10.9.0.1", Port: 22, User: "ops", Via: "bastion-eu"},
	}
	for _, tt := range []struct {
		name     string
		hosts    []sshcfg.Host
		manifest []config.Server
		via      map[string]string // alias -> want Via ("" = direct)
		why      map[string]string // alias -> a substring of the NotMapped reason
	}{
		{name: "one hop by alias",
			hosts: []sshcfg.Host{bastion, jh("web", "10.0.1.5", "deploy", "ProxyJump bastion")},
			via:   map[string]string{"web": "bastion", "bastion": ""}},
		{name: "two hops, the inner one agrees",
			hosts: []sshcfg.Host{bastion, inner, jh("web", "10.0.1.5", "deploy", "ProxyJump bastion,inner")},
			via:   map[string]string{"web": "inner", "inner": "bastion"}},
		{name: "the first hop keeps its own route",
			hosts: []sshcfg.Host{bastion, inner, jh("web", "10.0.1.5", "deploy", "ProxyJump inner")},
			via:   map[string]string{"web": "inner", "inner": "bastion"}},
		{name: "a hop by host, port and user",
			hosts: []sshcfg.Host{bastion, jh("web", "10.0.1.5", "deploy", "ProxyJump jump@bastion.example.com:22")},
			via:   map[string]string{"web": "bastion"}},
		{name: "an explicit user that does not match",
			hosts: []sshcfg.Host{bastion, jh("web", "10.0.1.5", "deploy", "ProxyJump ops@bastion")},
			why:   map[string]string{"web": `hop "ops@bastion" names server "bastion" with another user or port`}},
		{name: "an explicit port that does not match",
			hosts: []sshcfg.Host{bastion, jh("web", "10.0.1.5", "deploy", "ProxyJump bastion:2222")},
			why:   map[string]string{"web": `hop "bastion:2222" names server "bastion" with another user or port`}},
		{name: "a hop that resolves to nothing",
			hosts: []sshcfg.Host{jh("web", "10.0.1.5", "deploy", "ProxyJump gw")},
			why:   map[string]string{"web": `hop "gw" is not a server in the ssh config or the manifest`}},
		{name: "ProxyCommand",
			hosts: []sshcfg.Host{jh("web", "10.0.1.5", "deploy", "ProxyCommand nc %h %p")},
			why:   map[string]string{"web": "only ProxyJump [user@]host[:port] hops are mapped"}},
		{name: "four hops",
			hosts: []sshcfg.Host{jh("a", "a", "u", ""), jh("b", "b", "u", "ProxyJump a"), jh("c", "c", "u", "ProxyJump b"), jh("d", "d", "u", "ProxyJump c"),
				jh("web", "10.0.1.5", "deploy", "ProxyJump a,b,c,d")},
			why: map[string]string{"web": "4 hops; at most 3"}},
		// Direct hops: the depth check, not a parent clash, must refuse it.
		{name: "four hops, each direct",
			hosts: []sshcfg.Host{jh("a", "a", "u", ""), jh("b", "b", "u", ""), jh("c", "c", "u", ""), jh("d", "d", "u", ""),
				jh("web", "10.0.1.5", "deploy", "ProxyJump a,b,c,d")},
			why: map[string]string{"web": "4 hops; at most 3"}},
		{name: "a route deeper than 3 through the first hop",
			hosts: []sshcfg.Host{jh("a", "a", "u", ""), jh("b", "b", "u", "ProxyJump a"), jh("c", "c", "u", "ProxyJump b"), jh("d", "d", "u", "ProxyJump c"),
				jh("web", "10.0.1.5", "deploy", "ProxyJump d")},
			via: map[string]string{"d": "c"},
			why: map[string]string{"web": "the route is 4 hops; at most 3"}},
		// Another chain asks direct "inner" for a parent; web's chain only
		// starts at inner, which keeps its own route, so web still maps.
		{name: "a first hop another chain asks a parent of",
			hosts: []sshcfg.Host{jh("gw", "gw", "u", ""), jh("inner", "10.0.0.9", "ops", ""),
				jh("web", "10.0.1.5", "deploy", "ProxyJump inner"), jh("app", "10.0.1.6", "deploy", "ProxyJump gw,inner")},
			via: map[string]string{"web": "inner", "inner": ""},
			why: map[string]string{"app": `hop "inner" would need two different parents`}},
		{name: "a hop that would need two parents",
			hosts: []sshcfg.Host{bastion, jh("inner", "10.0.0.9", "ops", ""), jh("web", "10.0.1.5", "deploy", "ProxyJump bastion,inner")},
			why:   map[string]string{"web": `hop "inner" would need two different parents`}},
		{name: "a manifest jump_only bastion",
			hosts: []sshcfg.Host{jh("web", "10.0.1.5", "deploy", "ProxyJump bastion-eu")}, manifest: manifest,
			via: map[string]string{"web": "bastion-eu"}},
		{name: "a manifest server the ssh config spells the same",
			hosts: []sshcfg.Host{jh("bastion-eu", "bastion.eu", "jump", ""), jh("web", "10.0.1.5", "deploy", "ProxyJump bastion-eu")}, manifest: manifest,
			via: map[string]string{"web": "bastion-eu"}},
		{name: "an alias the manifest and the ssh config name for different machines",
			hosts: []sshcfg.Host{jh("bastion-eu", "bastion.other", "jump", ""), jh("web", "10.0.1.5", "deploy", "ProxyJump bastion-eu")}, manifest: manifest,
			why: map[string]string{"web": `hop "bastion-eu" names manifest server "bastion-eu", but the ssh config's host of that name is another machine`}},
		{name: "a manifest hop asked for another parent",
			hosts: []sshcfg.Host{bastion, jh("web", "10.0.1.5", "deploy", "ProxyJump bastion,mid")}, manifest: manifest,
			why: map[string]string{"web": `hop "mid" would need two different parents`}},
		{name: "a loop",
			hosts: []sshcfg.Host{jh("a", "a", "u", "ProxyJump b"), jh("b", "b", "u", "ProxyJump a")},
			why:   map[string]string{"a": "loops back", "b": "loops back"}},
		{name: "a hop whose own proxy is not mapped",
			hosts: []sshcfg.Host{jh("gw", "gw", "u", "ProxyCommand nc %h %p"), jh("web", "10.0.1.5", "deploy", "ProxyJump gw")},
			why:   map[string]string{"web": `hop "gw" has a proxy that is not mapped`}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := MapRoutes(tt.hosts, tt.manifest)
			for alias, want := range tt.via {
				if got := r.Via(alias); got != want {
					t.Errorf("Via(%s) = %q, want %q", alias, got, want)
				}
				if why, bad := r.NotMapped(alias); bad {
					t.Errorf("%s not mapped: %s", alias, why)
				}
			}
			for alias, want := range tt.why {
				why, bad := r.NotMapped(alias)
				if !bad || !strings.Contains(why, want) || r.Via(alias) != "" {
					t.Errorf("NotMapped(%s) = %q, %v (via %q); want a reason containing %q and no via", alias, why, bad, r.Via(alias), want)
				}
			}
		})
	}
}
