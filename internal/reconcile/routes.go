package reconcile

import (
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
)

// Routes is an ssh config's ProxyJump chains mapped onto server entries
// (spec S5 Import): the via each host gets, how each host is reached, and
// why a host's proxy could not be mapped. The zero value maps nothing.
type Routes struct {
	via map[string]string // alias -> its via, for every imported host on a mapped chain
	key map[string]string // alias -> its route: "" direct, the resolved chain, or "?" + the raw proxy
	why map[string]string // alias -> why its ProxyJump/ProxyCommand is not mapped
}

// Via is the via: a host gets; "" when it is direct or not mapped.
func (r Routes) Via(alias string) string { return r.via[alias] }

// NotMapped reports why alias's proxy is not mapped.
func (r Routes) NotMapped(alias string) (string, bool) {
	why, ok := r.why[alias]
	return why, ok
}

// routeKey is how alias reaches its address: "" direct, its bastions root
// first and comma-joined, or "?" and the raw proxy when that is not mapped.
// Two hosts at one address are one machine only when their keys agree.
func (r Routes) routeKey(alias string) string { return r.key[alias] }

// hopNode is a server a ProxyJump hop can name: an imported host, or a
// manifest server (fixed: the manifest's via wins).
type hopNode struct {
	name, host, user string
	port             int
	fixed            bool
	via              string // the manifest's via (fixed only)
}

// hopIndex is every server a hop can resolve to, manifest servers first.
type hopIndex struct {
	nodes   map[string]hopNode
	order   []string
	proxyOf map[string]string // alias -> its raw Proxy
	// differs holds every alias that names a manifest server and, in the ssh
	// config, a host with another host, port or user (the builder keeps the
	// manifest's and marks the incoming one conflicted). A hop by that alias
	// cannot tell which machine the operator meant, so it is not mapped.
	differs map[string]bool
}

func newHopIndex(hosts []sshcfg.Host, manifest []config.Server) hopIndex {
	x := hopIndex{nodes: map[string]hopNode{}, proxyOf: map[string]string{}, differs: map[string]bool{}}
	for _, s := range manifest {
		x.add(hopNode{name: s.Name, host: s.Host, user: s.User, port: s.Port, fixed: true, via: s.Via})
	}
	for _, h := range hosts {
		x.proxyOf[h.Alias] = h.Proxy
		n, taken := x.nodes[h.Alias]
		switch {
		case h.User == "":
		case !taken:
			x.add(hopNode{name: h.Alias, host: h.HostName, user: h.User, port: h.Port})
		case n.fixed && !sameMachine(n, h):
			x.differs[h.Alias] = true
		}
	}
	return x
}

// sameMachine is the builder's "identical" test (builder.servers): host,
// user and effective port all equal.
func sameMachine(n hopNode, h sshcfg.Host) bool {
	port := h.Port
	if port == 0 {
		port = 22
	}
	return n.host == h.HostName && n.user == h.User && n.port == port
}

func (x *hopIndex) add(n hopNode) {
	if n.port == 0 {
		n.port = 22
	}
	x.nodes[n.name] = n
	x.order = append(x.order, n.name)
}

// MapRoutes maps every server-worthy host's ProxyJump chain onto servers. A
// chain maps when each hop resolves to exactly one imported host or
// manifest server, no server it constrains would need two different
// parents (another chain, its own route, or the manifest's via), and the
// whole route — the first hop's own route included, since ssh connects a
// hop with that hop's own config — neither loops, nor passes a host whose
// proxy is not mapped, nor runs deeper than config.MaxViaDepth. manifest is
// nil for a fresh import; a host the manifest already names keeps the
// manifest's route.
func MapRoutes(hosts []sshcfg.Host, manifest []config.Server) Routes {
	x := newHopIndex(hosts, manifest)
	r := Routes{via: map[string]string{}, key: map[string]string{}, why: map[string]string{}}
	chains := map[string][]string{}
	for _, h := range hosts {
		if h.User == "" || h.Proxy == "" || x.nodes[h.Alias].fixed {
			continue
		}
		if names, why := x.resolveChain(h); why != "" {
			r.why[h.Alias] = why
		} else {
			chains[h.Alias] = names
		}
	}
	need := x.parentNeeds(hosts, chains, r.why)
	for _, alias := range x.order {
		names, ok := chains[alias]
		if !ok {
			continue
		}
		if clash := firstClash(append(slices.Clone(names[1:]), alias), need); clash != "" {
			r.why[alias] = fmt.Sprintf("hop %q would need two different parents", clash)
			continue
		}
		r.via[alias] = names[len(names)-1]
		for i := 1; i < len(names); i++ {
			if !x.nodes[names[i]].fixed {
				r.via[names[i]] = names[i-1]
			}
		}
	}
	x.dropBroken(&r)
	for _, alias := range x.order {
		if _, bad := r.why[alias]; bad {
			r.key[alias] = "?" + x.proxyOf[alias]
			continue
		}
		chain, _ := x.walk(r, alias)
		r.key[alias] = strings.Join(chain, ",")
	}
	return r
}

// resolveChain resolves h's ProxyJump hops to server names, first hop
// first, or says why it cannot.
func (x hopIndex) resolveChain(h sshcfg.Host) ([]string, string) {
	hops, ok := sshcfg.ParseJump(h.Proxy)
	switch {
	case !ok:
		return nil, "only ProxyJump [user@]host[:port] hops are mapped"
	case len(hops) > config.MaxViaDepth:
		return nil, fmt.Sprintf("%d hops; at most %d", len(hops), config.MaxViaDepth)
	}
	names := make([]string, 0, len(hops))
	for _, hop := range hops {
		name, why := x.resolve(hop)
		if why != "" {
			return nil, why
		}
		if name == h.Alias || slices.Contains(names, name) {
			return nil, fmt.Sprintf("the chain loops back to %q", name)
		}
		names = append(names, name)
	}
	return names, ""
}

// resolve finds the one server a hop names: the alias it spells, else the
// servers at its host and port (22 when unset) whose user matches (any
// when unset). An explicit user or port must agree either way.
func (x hopIndex) resolve(hop sshcfg.JumpHop) (string, string) {
	if x.differs[hop.Host] {
		return "", fmt.Sprintf("hop %q names manifest server %q, but the ssh config's host of that name is another machine (host, port or user differ)", hop.String(), hop.Host)
	}
	if n, ok := x.nodes[hop.Host]; ok {
		if (hop.User != "" && hop.User != n.user) || (hop.Port != 0 && hop.Port != n.port) {
			return "", fmt.Sprintf("hop %q names server %q with another user or port", hop.String(), n.name)
		}
		return n.name, ""
	}
	port := hop.Port
	if port == 0 {
		port = 22
	}
	var found []string
	for _, name := range x.order {
		n := x.nodes[name]
		if strings.EqualFold(n.host, hop.Host) && n.port == port && (hop.User == "" || hop.User == n.user) {
			found = append(found, name)
		}
	}
	switch len(found) {
	case 1:
		return found[0], ""
	case 0:
		return "", fmt.Sprintf("hop %q is not a server in the ssh config or the manifest", hop.String())
	}
	return "", fmt.Sprintf("hop %q matches %d servers; name one by its alias", hop.String(), len(found))
}

// parentNeeds collects every parent asked of each server: a manifest
// server's via, an imported host's own route ("" direct, "?" an unmapped
// proxy, else its chain's last hop), and each chain's demand on every hop
// after its first.
func (x hopIndex) parentNeeds(hosts []sshcfg.Host, chains map[string][]string, why map[string]string) map[string]map[string]bool {
	need := map[string]map[string]bool{}
	add := func(name, parent string) {
		if need[name] == nil {
			need[name] = map[string]bool{}
		}
		need[name][parent] = true
	}
	for _, name := range x.order {
		if n := x.nodes[name]; n.fixed {
			add(name, n.via)
		}
	}
	for _, h := range hosts {
		switch {
		case h.User == "" || x.nodes[h.Alias].fixed:
		case h.Proxy == "":
			add(h.Alias, "")
		case why[h.Alias] != "":
			add(h.Alias, "?")
		default:
			names := chains[h.Alias]
			add(h.Alias, names[len(names)-1])
		}
	}
	for _, names := range chains {
		for i := 1; i < len(names); i++ {
			add(names[i], names[i-1])
		}
	}
	return need
}

// firstClash names the first server asked for two different parents.
func firstClash(names []string, need map[string]map[string]bool) string {
	for _, n := range names {
		if len(need[n]) > 1 {
			return n
		}
	}
	return ""
}

// viaOf is a server's via: the manifest's for a manifest server, the
// mapped one for an imported host.
func (x hopIndex) viaOf(r Routes, name string) string {
	if n := x.nodes[name]; n.fixed {
		return n.via
	}
	return r.via[name]
}

// walk lists name's bastions root first, or says why the route is
// unusable: it loops, passes a host whose own proxy is not mapped, or runs
// deeper than config.MaxViaDepth.
func (x hopIndex) walk(r Routes, name string) ([]string, string) {
	var chain []string
	seen := map[string]bool{name: true}
	for v := x.viaOf(r, name); v != ""; v = x.viaOf(r, v) {
		switch {
		case seen[v]:
			return nil, fmt.Sprintf("the chain loops back to %q", v)
		case r.why[v] != "":
			return nil, fmt.Sprintf("hop %q has a proxy that is not mapped", v)
		}
		seen[v] = true
		chain = append(chain, v)
	}
	if len(chain) > config.MaxViaDepth {
		return nil, fmt.Sprintf("the route is %d hops; at most %d", len(chain), config.MaxViaDepth)
	}
	slices.Reverse(chain)
	return chain, ""
}

// dropBroken unmaps every host whose whole route walk refuses. Every
// verdict is taken against the routes as mapped, before any deletion, so
// each host is told its own reason (every host of a loop reads "loops
// back", not "has a proxy that is not mapped" because a sibling was dropped
// first). One pass is a fixed point: a route through a dropped host
// contains that host's whole route, so its own walk refuses in the same
// pass, for the same reason.
func (x hopIndex) dropBroken(r *Routes) {
	broken := map[string]string{}
	for _, name := range x.order {
		if r.via[name] == "" {
			continue
		}
		if _, why := x.walk(*r, name); why != "" {
			broken[name] = why
		}
	}
	for name, why := range broken {
		delete(r.via, name)
		r.why[name] = why
	}
}
