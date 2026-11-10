package config

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// viaFleet: alice (k1); servers and access are the sections verbatim.
func viaFleet(t *testing.T, servers, access string) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\nservers:\n" + servers + "access:\n" + access
}

// loadErr parses y and returns its error text, failing when it loads.
func loadErr(t *testing.T, y string) string {
	t.Helper()
	_, err := Parse([]byte(y))
	if err == nil {
		t.Fatalf("Parse succeeded, want an error:\n%s", y)
	}
	return err.Error()
}

func TestViaValidation(t *testing.T) {
	for _, tt := range []struct {
		name, servers, want string
	}{
		{"unknown via", "  - {name: web-1, host: 10.0.1.5, user: deploy, via: nope}\n",
			`server "web-1": unknown via "nope"`},
		{"via names itself", "  - {name: web-1, host: 10.0.1.5, user: deploy, via: web-1}\n",
			`server "web-1": via names the server itself`},
		{"two-server loop", "  - {name: a, host: 10.0.0.1, user: u, via: b}\n  - {name: b, host: 10.0.0.2, user: u, via: a}\n",
			`server "a": via chain loops (a → b → a)`},
		{"four hops deep",
			"  - {name: e, host: 10.0.0.5, user: u}\n  - {name: d, host: 10.0.0.4, user: u, via: e}\n" +
				"  - {name: c, host: 10.0.0.3, user: u, via: d}\n  - {name: b, host: 10.0.0.2, user: u, via: c}\n" +
				"  - {name: a, host: 10.0.0.1, user: u, via: b}\n",
			`server "a": via chain is 4 hops deep (e → d → c → b); at most 3`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := loadErr(t, viaFleet(t, tt.servers, "  - {user: alice, servers: [\"*\"]}\n"))
			if !strings.Contains(got, tt.want) {
				t.Errorf("error = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

// TestViaThreeHopsAccepted: exactly MaxViaDepth bastions load.
func TestViaThreeHopsAccepted(t *testing.T) {
	mustParse(t, viaFleet(t,
		"  - {name: d, host: 10.0.0.4, user: u}\n  - {name: c, host: 10.0.0.3, user: u, via: d}\n"+
			"  - {name: b, host: 10.0.0.2, user: u, via: c}\n  - {name: a, host: 10.0.0.1, user: u, via: b}\n",
		"  - {user: alice, servers: [\"*\"]}\n"))
}

func TestChainAndDependents(t *testing.T) {
	cfg := mustParse(t, viaFleet(t,
		"  - {name: edge, host: edge.example.com, user: jump, jump_only: true}\n"+
			"  - {name: mid, host: 10.0.0.2, user: ops, via: edge}\n"+
			"  - {name: web-1, host: 10.0.1.5, user: deploy, via: mid}\n"+
			"  - {name: web-2, host: 10.0.1.6, user: deploy, via: mid}\n"+
			"  - {name: db-1, host: 10.0.2.1, user: deploy}\n",
		"  - {user: alice, servers: [\"*\"]}\n"))
	for _, tt := range []struct {
		server string
		want   []string
	}{
		{"web-1", []string{"edge", "mid"}},
		{"mid", []string{"edge"}},
		{"edge", nil},
		{"db-1", nil},
	} {
		s, ok := cfg.ServerNamed(tt.server)
		if !ok {
			t.Fatalf("ServerNamed(%q) not found", tt.server)
		}
		if got := cfg.Chain(s); !slices.Equal(got, tt.want) {
			t.Errorf("Chain(%s) = %v, want %v (root first)", tt.server, got, tt.want)
		}
	}
	var deps []string
	for _, s := range cfg.Dependents("mid") {
		deps = append(deps, s.Name)
	}
	if !slices.Equal(deps, []string{"web-1", "web-2"}) {
		t.Errorf("Dependents(mid) = %v, want [web-1 web-2]", deps)
	}
	if _, ok := cfg.ServerNamed("nope"); ok {
		t.Error("ServerNamed found a server the manifest does not have")
	}
}

// TestOneAddressOneRoute (OP7): known_hosts is keyed by address, so one
// address is one entry, and every entry at one host:port takes one route.
func TestOneAddressOneRoute(t *testing.T) {
	bastions := "  - {name: b1, host: b1.example.com, user: jump}\n  - {name: b2, host: b2.example.com, user: jump}\n"
	route := `servers "a" and "b" both target deploy@10.0.0.5:22 ~/.ssh/authorized_keys through different hops; a manifest holds one entry per address, so remove one`
	for _, tt := range []struct {
		name, servers, want string
	}{
		{"one target, two hops", "  - {name: a, host: 10.0.0.5, user: deploy, via: b1}\n  - {name: b, host: 10.0.0.5, user: deploy, via: b2}\n", route},
		{"one target, direct and a hop", "  - {name: a, host: 10.0.0.5, user: deploy}\n  - {name: b, host: 10.0.0.5, user: deploy, via: b1}\n", route},
		{"one target, one hop", "  - {name: a, host: 10.0.0.5, user: deploy, via: b1}\n  - {name: b, host: 10.0.0.5, user: deploy, via: b1}\n",
			`servers "a" and "b" both target deploy@10.0.0.5:22 ~/.ssh/authorized_keys; merge them into one entry`},
		{"one address, two users, two hops", "  - {name: a, host: 10.0.0.5, user: deploy, via: b1}\n  - {name: b, host: 10.0.0.5, user: ops, via: b2}\n",
			`servers "a" and "b" reach 10.0.0.5:22 through different hops; every entry at one address must use the same route; if these are different machines, give each a hostname its own hop can resolve`},
		{"the address folds case", "  - {name: a, host: Web.Example.com, user: deploy}\n  - {name: b, host: web.example.com, user: ops, via: b1}\n",
			`servers "a" and "b" reach web.example.com:22 through different hops`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := loadErr(t, viaFleet(t, bastions+tt.servers, "  - {user: alice, servers: [\"*\"]}\n"))
			if !strings.Contains(got, tt.want) {
				t.Errorf("error = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

// TestOneRouteManyUsersAccepted: different users or files at one address
// over the same route stay valid, as today.
func TestOneRouteManyUsersAccepted(t *testing.T) {
	mustParse(t, viaFleet(t,
		"  - {name: b1, host: b1.example.com, user: jump}\n"+
			"  - {name: a, host: 10.0.0.5, user: deploy, via: b1}\n"+
			"  - {name: b, host: 10.0.0.5, user: ops, via: b1}\n"+
			"  - {name: c, host: 10.0.0.5, user: ops, via: b1, authorized_keys_file: /etc/ssh/keys/ops}\n",
		"  - {user: alice, servers: [\"*\"]}\n"))
}
