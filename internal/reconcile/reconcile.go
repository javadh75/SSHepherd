// Package reconcile compares freshly-converted ssh-config hosts and
// identity-derived users against an existing manifest and plans the strictly
// additive merge `import --merge` appends: net-new servers and users, access
// extensions for keys the manifest already owns, and grants for the new
// users. Conflicts resolve loudly in the manifest's favor — nothing existing
// is ever removed, reordered, or rewritten. Pure logic, no I/O; the cmd
// layer owns loading, rendering, and logging.
package reconcile

import (
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/naming"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
)

// ServerAdd is one converted host to append to the servers: section. Port is
// 0 when the effective port is 22, mirroring import's omitempty rendering.
type ServerAdd struct {
	Name, Host string
	Port       int
	User       string
	Via        string // the mapped ProxyJump route (spec S5); "" direct
}

// UserAdd is one identity-derived key to append as a new user. Name is
// post-suffix: any rename against the seeded taken-name set already applied.
type UserAdd struct {
	Name        string
	Description string
	Comment     string
	Operator    bool
	Keys        []string
}

// Extension grants an existing manifest user the covered servers their key
// is used for beyond the manifest's current grants — one entry per owning
// user, in cfg.Users order, servers in first-touch order.
type Extension struct {
	User    string   `json:"user"`
	Servers []string `json:"servers"`
}

// Grant is a new user's access entry, post-rename and post-compaction
// (Servers may be ["*"] when the grant covers the entire merged fleet).
type Grant struct {
	User    string
	Servers []string
}

// The Warning kinds reconcile assigns. Consumers ignore kinds they do not
// know.
const (
	KindMergeConflict        = "merge_conflict"
	KindRevokedPubSkipped    = "revoked_pub_skipped"
	KindRevokedAccessSkipped = "revoked_access_skipped"
	KindWildcardGrant        = "wildcard_grant"
	// KindProxyNotMapped is the same kind import's own proxy warnings carry.
	KindProxyNotMapped = "proxy_not_mapped"
)

// Warning is one finding for the operator. Message is the stderr text; the
// other fields are the structured form --json carries, omitted when they do
// not apply. Identity is the .pub path the key came from.
type Warning struct {
	Kind        string `json:"kind"`
	Server      string `json:"server,omitempty"`
	Identity    string `json:"identity,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	User        string `json:"user,omitempty"`
	Date        string `json:"date,omitempty"`
	Message     string `json:"message"`
}

// Plan is everything the merge would append, plus the operator-facing
// findings: Warnings for every conflict, skip, and carve-out
// (marker-comment-ready), Notes for info-level steady-state findings that
// must not warn on every re-run.
type Plan struct {
	NewServers []ServerAdd
	NewUsers   []UserAdd
	Extensions []Extension
	NewGrants  []Grant
	Warnings   []Warning
	Notes      []string

	conflicts int // incoming items dropped by manifest-wins rules
}

// Empty reports whether the plan appends nothing. Warnings may still exist:
// a conflict-only run stays byte-identical, its warnings live on stderr only
// (adjudicated 2026-07-19).
func (p Plan) Empty() bool {
	return len(p.NewServers)+len(p.NewUsers)+len(p.Extensions)+len(p.NewGrants) == 0
}

// ConflictsSkipped counts the incoming items dropped in the manifest's
// favor: conflicted servers, grants referencing them, except carve-out
// pairs, and users skipped entirely. Feeds the cmd layer's summary line.
func (p Plan) ConflictsSkipped() int { return p.conflicts }

// builder accumulates the plan across the phases, which run in dependency
// order: servers first (grants reference them), then users (grants reference
// them), then the aggregated extensions.
type builder struct {
	cfg        *config.Config
	plan       Plan
	conflicted map[string]bool            // aliases dropped by the server-conflict rule
	aliasOf    map[string]string          // incoming alias -> manifest server with the same target
	fleet      map[string]bool            // merged fleet: manifest (less jump_only) ∪ appended server names
	taken      map[string]bool            // claimed user names, seeded with every manifest name
	extSeen    map[string]map[string]bool // owner -> servers already recorded as extensions
	extServers map[string][]string        // owner -> extension servers, first-touch order
	routes     Routes                     // the hosts' ProxyJump chains mapped onto servers (spec S5)
	jumpNoted  map[string]bool            // jump_only servers already noted as never granted
}

// Build reconciles hosts (the server-worthy converted hosts) and users (the
// identity-derived users; nil under --servers-only) against cfg, the loaded
// manifest. Deterministic: hosts and users are processed in input order,
// warnings in discovery order, extensions in cfg.Users order. The only error
// is the locked --operator-key promotion conflict — a marked key owned by an
// existing non-operator user; every other finding is a warning or note in
// the plan.
func Build(cfg *config.Config, hosts []sshcfg.Host, users []identity.User) (Plan, error) {
	b := &builder{
		cfg:        cfg,
		conflicted: map[string]bool{},
		aliasOf:    map[string]string{},
		fleet:      map[string]bool{},
		taken:      map[string]bool{},
		extSeen:    map[string]map[string]bool{},
		extServers: map[string][]string{},
		routes:     MapRoutes(hosts, cfg.Servers),
		jumpNoted:  map[string]bool{},
	}
	for _, s := range cfg.Servers {
		if !s.JumpOnly { // no grant reaches a jump_only server, so "*" need not cover it (OP8)
			b.fleet[s.Name] = true
		}
	}
	for _, u := range cfg.Users {
		b.taken[u.Name] = true
	}
	// An access tombstone keeps its user's name: a new grant under it
	// would be a policy conflict, refused at save.
	for _, t := range cfg.Tombstones {
		if !t.IsKey() {
			b.taken[t.User] = true
		}
	}
	b.servers(hosts)
	b.dropDanglingVia()
	if err := b.users(users); err != nil {
		return Plan{}, err
	}
	b.finishExtensions()
	return b.plan, nil
}

// servers reconciles by name: absent appends, identical skips with a note
// (the idempotent-re-run common case must not accumulate noise), any
// host/port/user difference drops the incoming entry — manifest wins, a
// silent overwrite could redirect a future apply at a different machine.
// An absent name whose target (host, port, user, authorized_keys file) a
// manifest or already-appended server owns is skipped too — config rejects
// two entries for one remote file — and its grants are redirected onto that
// server when both take the same route (the same machine); over another
// route, or at a taken address over another route, it is a conflict and
// its grants are dropped (OP7, newServer).
func (b *builder) servers(hosts []sshcfg.Host) {
	byName := make(map[string]config.Server, len(b.cfg.Servers))
	targets := make(map[target]string, len(b.cfg.Servers))
	at := make(map[string]string, len(b.cfg.Servers)) // address -> first server there
	for _, s := range b.cfg.Servers {
		byName[s.Name] = s
		t := targetOf(s.Host, s.Port, s.User, s.AuthorizedKeysFile)
		if targets[t] == "" {
			targets[t] = s.Name
		}
		if at[t.address()] == "" {
			at[t.address()] = s.Name
		}
	}
	for _, h := range hosts {
		s, exists := byName[h.Alias]
		if !exists {
			b.newServer(h, targets, at)
			continue
		}
		eff := h.Port
		if eff == 0 {
			eff = 22 // compare against the manifest's validation-defaulted 22
		}
		// Manifest-only fields (description, authorized_keys_file) never
		// participate: import cannot produce them, and their presence does
		// not make the entries different machines.
		if s.Host == h.HostName && s.User == h.User && s.Port == eff {
			b.plan.Notes = append(b.plan.Notes, fmt.Sprintf(
				"server %q already in the manifest — identical, skipped", h.Alias))
			continue
		}
		b.conflicted[h.Alias] = true
		b.plan.conflicts++
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: h.Alias,
			Message: fmt.Sprintf("server %q in the ssh config differs from the manifest (host/port/user) — manifest kept", h.Alias)})
	}
}

// newServer appends one incoming host the manifest does not name, unless
// its target or its address is taken: the same route makes it the same
// machine, so its grants move there; another route may be another
// machine (OP7), so it is a conflict and its grants are dropped.
func (b *builder) newServer(h sshcfg.Host, targets map[target]string, at map[string]string) {
	t := targetOf(h.HostName, h.Port, h.User, "")
	route := b.routes.routeKey(h.Alias)
	if owner, dup := targets[t]; dup {
		b.plan.conflicts++
		if route == b.routeOf(owner) {
			b.aliasOf[h.Alias] = owner
			b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: h.Alias,
				Message: sameTarget(h.Alias, owner, "manifest server")})
			return
		}
		b.conflicted[h.Alias] = true
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: h.Alias,
			Message: otherRoute(h.Alias, "manifest server "+strconv.Quote(owner), owner)})
		return
	}
	if owner, there := at[t.address()]; there && route != b.routeOf(owner) {
		b.plan.conflicts++
		b.conflicted[h.Alias] = true
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: h.Alias,
			Message: otherAddressRoute(h.Alias, "manifest server "+strconv.Quote(owner))})
		return
	}
	targets[t] = h.Alias
	if _, there := at[t.address()]; !there {
		at[t.address()] = h.Alias
	}
	port := h.Port
	if port == 22 {
		port = 0 // effective default, omitted on render
	}
	b.plan.NewServers = append(b.plan.NewServers,
		ServerAdd{Name: h.Alias, Host: h.HostName, Port: port, User: h.User, Via: b.routes.Via(h.Alias)})
	b.fleet[h.Alias] = true
}

// routeOf is a server's route key: the manifest's chain for a manifest
// server, the mapped route for one appended in this run.
func (b *builder) routeOf(name string) string {
	if s, ok := b.cfg.ServerNamed(name); ok {
		return strings.Join(b.cfg.Chain(s), ",")
	}
	return b.routes.routeKey(name)
}

// dropDanglingVia fixes a new server's via once every host is decided: a
// via onto a host that collapsed into a manifest server moves there (one
// machine); a via onto a host that was not appended is cleared and warned,
// so the output still loads.
func (b *builder) dropDanglingVia() {
	for i := range b.plan.NewServers {
		s := &b.plan.NewServers[i]
		if to, ok := b.aliasOf[s.Via]; ok {
			s.Via = to
		}
		if s.Via == "" || b.known(s.Via) {
			continue
		}
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindProxyNotMapped, Server: s.Name, Message: fmt.Sprintf(
			"host %q: its bastion %q was not added (it conflicts with the manifest) — dialed directly; add via: by hand", s.Name, s.Via)})
		s.Via = ""
	}
}

// known reports a manifest server or one appended in this run.
func (b *builder) known(name string) bool {
	if _, ok := b.cfg.ServerNamed(name); ok {
		return true
	}
	return slices.ContainsFunc(b.plan.NewServers, func(s ServerAdd) bool { return s.Name == name })
}

// users reconciles by fingerprint — the name is only a label.
func (b *builder) users(users []identity.User) error {
	for _, u := range users {
		k, err := authkeys.ParseLine(u.Key)
		if err != nil {
			return fmt.Errorf("user %q: invalid key line (bug: identity resolution validated it): %w", u.Name, err)
		}
		if k == nil {
			return fmt.Errorf("user %q: invalid key line (bug: identity resolution validated it): blank entry", u.Name)
		}
		if t, revoked := b.cfg.Revoked(k.Fingerprint); revoked {
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, Warning{
				Kind: KindRevokedPubSkipped, Identity: pubPath(u.Source), Fingerprint: k.Fingerprint, User: t.User, Date: t.Date,
				Message: fmt.Sprintf("key %s from %s is REVOKED (%s) — not imported", k.Fingerprint, pubPath(u.Source), t.Label()),
			})
			continue
		}
		if owner, known := b.cfg.OwnerOf(k.Fingerprint); known {
			if err := b.knownKey(u, owner, k.Fingerprint); err != nil {
				return err
			}
			continue
		}
		b.newUser(u)
	}
	return nil
}

// pubPath is the .pub an identity was read from, as written: the
// IdentityFile value itself when it already names the .pub, else value +
// ".pub" (internal/identity's pubPaths rule; only .pub files are read).
func pubPath(source string) string {
	if strings.HasSuffix(source, ".pub") {
		return source
	}
	return source + ".pub"
}

// knownKey handles an incoming key the manifest already owns: the owner
// wins — no new user — and access proceeds against the owner's name. Each
// server is checked in the locked coverage order: conflicted alias (grant
// dropped with the server), jump_only server (never granted, noted),
// fleet-wide operator owner (implicit grant, never
// extended; a scoped operator goes through coverage like anyone), Covers
// (explicit grant or wildcard absorption — a "*" user gains every appended
// server automatically), except carve-out (never
// re-granted), an access tombstone (never re-granted, D1a), else an
// extension pair.
func (b *builder) knownKey(u identity.User, owner config.User, fp string) error {
	if u.Operator && !owner.Operator {
		return fmt.Errorf(
			"--operator-key %s belongs to manifest user %q, who is not an operator — promotion must be an explicit manifest edit",
			fp, owner.Name)
	}
	if u.Operator && b.cfg.FleetWide(owner.Name) {
		return nil // owner already holds the implicit grant: idempotent --operator-key re-run, silent no-op
	}
	extended := false
	for _, srv := range b.redirect(u.Servers) {
		switch {
		case b.conflicted[srv]:
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: srv, User: owner.Name,
				Message: fmt.Sprintf("access for %q to %q dropped: the server conflicts with the manifest", owner.Name, srv)})
		case b.jumpOnly(srv):
			b.noteJumpOnly(srv)
		case b.cfg.FleetWide(owner.Name):
		case b.cfg.Covers(owner.Name, srv):
		case b.cfg.ExceptCarveOut(owner.Name, srv):
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: srv, User: owner.Name,
				Message: fmt.Sprintf("key of %q used for %q in the ssh config, which their except: list deliberately excludes — not re-granted; audit flags this drift",
					owner.Name, srv)})
		default:
			if t, gone := b.cfg.AccessRevoked(owner.Name, srv); gone {
				b.plan.conflicts++
				b.plan.Warnings = append(b.plan.Warnings, Warning{
					Kind: KindRevokedAccessSkipped, Identity: pubPath(u.Source), Server: srv, Fingerprint: fp, User: owner.Name, Date: t.Date,
					Message: fmt.Sprintf("key %s of %q found on %q, whose access was revoked (%s) — not re-granted; audit flags this drift",
						fp, owner.Name, srv, t.Date),
				})
				continue
			}
			extended = b.extend(owner.Name, srv) || extended
		}
	}
	if u.Name != owner.Name {
		// Adjudicated classification: a warning only when the key produces a
		// plan change; the covered steady state is a note, or a deterministic
		// re-run would warn forever.
		if extended {
			b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Fingerprint: fp, User: owner.Name,
				Message: fmt.Sprintf("key %s from the ssh config belongs to manifest user %q — extending their access", fp, owner.Name)})
		} else {
			b.plan.Notes = append(b.plan.Notes, fmt.Sprintf(
				"key %s from the ssh config belongs to manifest user %q — already covered", fp, owner.Name))
		}
	}
	return nil
}

// extend records one (owner, server) extension pair, deduplicating across
// the owner's incoming keys; reports whether the pair was newly added.
func (b *builder) extend(owner, srv string) bool {
	if b.extSeen[owner] == nil {
		b.extSeen[owner] = map[string]bool{}
	}
	if b.extSeen[owner][srv] {
		return false
	}
	b.extSeen[owner][srv] = true
	b.extServers[owner] = append(b.extServers[owner], srv)
	return true
}

// newUser appends an unknown-fingerprint incoming user: grants referencing
// conflicted servers are dropped (the derived rule), the name is suffixed on
// collision — the rename cascades to the grants, which travel on the struct,
// never a name-keyed map — and a grant covering the entire merged fleet
// compacts to the wildcard.
func (b *builder) newUser(u identity.User) {
	if u.Operator {
		b.plan.NewUsers = append(b.plan.NewUsers, UserAdd{
			Name: b.claim(u.Name), Description: describe(u), Comment: u.Comment,
			Operator: true, Keys: []string{u.Key},
		})
		return // fleet-wide grant is implied; no access entry
	}
	var surviving, dropped []string
	for _, srv := range b.redirect(u.Servers) {
		switch {
		case b.jumpOnly(srv):
			b.noteJumpOnly(srv)
		case b.conflicted[srv]:
			dropped = append(dropped, srv)
		default:
			surviving = append(surviving, srv)
		}
	}
	if len(surviving) == 0 {
		// Grantless-user rule: appending a key no server will ever receive
		// is a half-truth the self-check cannot catch. Skipped entirely, so
		// no name is claimed either.
		if len(dropped) > 0 {
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, User: u.Name, Message: notAdded(u.Name, dropped)})
		}
		return
	}
	for _, srv := range dropped {
		b.plan.conflicts++
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, Server: srv, User: u.Name,
			Message: fmt.Sprintf("access for %q to %q dropped: the server conflicts with the manifest", u.Name, srv)})
	}
	name := b.claim(u.Name)
	b.plan.NewUsers = append(b.plan.NewUsers, UserAdd{
		Name: name, Description: describe(u), Comment: u.Comment, Keys: []string{u.Key},
	})
	servers := surviving
	if b.coversFleet(surviving) {
		servers = []string{"*"}
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindWildcardGrant, User: name,
			Message: fmt.Sprintf("access for %q covers every server; emitted as wildcard %q (includes servers added later)", name, "*")})
	}
	b.plan.NewGrants = append(b.plan.NewGrants, Grant{User: name, Servers: servers})
}

// jumpOnly reports a manifest server marked jump_only: no grant may name it
// (spec S5, OP8).
func (b *builder) jumpOnly(srv string) bool {
	s, ok := b.cfg.ServerNamed(srv)
	return ok && s.JumpOnly
}

// noteJumpOnly records, once per server, that a key used on a jump_only
// server added no access there.
func (b *builder) noteJumpOnly(srv string) {
	if b.jumpNoted[srv] {
		return
	}
	b.jumpNoted[srv] = true
	b.plan.Notes = append(b.plan.Notes, fmt.Sprintf("server %q is jump_only in the manifest; no access added", srv))
}

// redirect maps grants on target-duplicate aliases onto the server that
// owns the target, deduplicating while keeping first-touch order.
func (b *builder) redirect(servers []string) []string {
	return remap(servers, b.aliasOf)
}

// notAdded words the grantless-user skip warning.
func notAdded(name string, dropped []string) string {
	if len(dropped) == 1 {
		return fmt.Sprintf("user %q not added: its only server %q conflicts with the manifest", name, dropped[0])
	}
	return fmt.Sprintf("user %q not added: all its servers (%s) conflict with the manifest",
		name, strings.Join(dropped, ", "))
}

// claim reserves a free name for an appended user, warning when the incoming
// name had to be suffixed — the key is never appended to the existing
// same-named user (loud over-splitting beats quiet identity merging). The
// suffix continues any existing -<n> numbering instead of stacking: the
// taken set is seeded with every manifest name up front and incoming users
// claim sequentially in input order, so manifest x plus incoming x, x-2
// resolves to x-2, x-3 (not x-2-2) with no transient collision — the pinned
// rename bookkeeping, shared with import and adopt via internal/naming.
func (b *builder) claim(want string) string {
	name, renamed := naming.Claim(b.taken, want)
	if renamed {
		b.plan.Warnings = append(b.plan.Warnings, Warning{Kind: KindMergeConflict, User: name,
			Message: fmt.Sprintf("user name %q already taken, using %q for the incoming key", want, name)})
	}
	return name
}

// coversFleet reports whether servers covers the entire merged fleet
// (manifest ∪ appended servers) of at least two machines — the only case
// merge compacts a net-new user's grant to ["*"]. Conservative by design:
// "*" opts the user into every future server and, under merge, into
// manifest machines import knows nothing about.
func (b *builder) coversFleet(servers []string) bool {
	if len(b.fleet) < 2 {
		return false
	}
	covered := map[string]bool{}
	for _, s := range servers {
		if b.fleet[s] {
			covered[s] = true
		}
	}
	return len(covered) == len(b.fleet)
}

// finishExtensions emits one aggregated entry per owning manifest user, in
// cfg.Users order. Existing access entries are never edited — a user's new
// servers arrive as a new appended entry; the config layer's union
// semantics make the duplication harmless and the diff reviewable.
func (b *builder) finishExtensions() {
	for _, u := range b.cfg.Users {
		if srvs := b.extServers[u.Name]; len(srvs) > 0 {
			b.plan.Extensions = append(b.plan.Extensions, Extension{User: u.Name, Servers: srvs})
		}
	}
}

// describe renders the appended user's description exactly as non-merge
// import does: the identity source, qualified for --operator-key-created and
// default-identity keys.
func describe(u identity.User) string {
	desc := "imported from " + u.Source
	switch {
	case u.Operator && len(u.Servers) == 0:
		desc += " (--operator-key)"
	case u.Default:
		desc += " (default identity)"
	}
	return desc
}

// defaultAuthorizedKeysFile is the path an entry without
// authorized_keys_file targets; it must equal config's default so target
// equality matches config validation.
const defaultAuthorizedKeysFile = "~/.ssh/authorized_keys"

// target is the remote file a server entry writes — the key config
// validation rejects duplicates of: host lower-cased (hostnames are
// case-insensitive), port defaulted to 22, path defaulted.
type target struct {
	host string
	port int
	user string
	path string
}

func targetOf(host string, port int, user, path string) target {
	if port == 0 {
		port = 22
	}
	if path == "" {
		path = defaultAuthorizedKeysFile
	}
	return target{host: strings.ToLower(host), port: port, user: user, path: path}
}

// sameTarget words the skipped-duplicate warning, naming both aliases.
func sameTarget(alias, owner, ownerKind string) string {
	return fmt.Sprintf(
		"server %q in the ssh config targets the same host, port, user and authorized_keys file as %s %q — skipped (one entry per remote file); its access is granted on %q",
		alias, ownerKind, owner, owner)
}

// otherRoute words the skip of a host whose target another host owns but
// whose route differs: possibly another machine, so its grants stay put.
// who names the owner ("web-a", or manifest server "web-a").
func otherRoute(alias, who, owner string) string {
	return fmt.Sprintf("server %q in the ssh config has the same host, port and user as %s but a different route — skipped, and its access is not moved to %q; a manifest holds one entry per address", alias, who, owner)
}

// otherAddressRoute words the skip of a host at a taken address through
// another route (OP7: every entry at one address uses one route).
func otherAddressRoute(alias, who string) string {
	return fmt.Sprintf("server %q in the ssh config is at the same address as %s but takes a different route — skipped, and its access is not moved; every entry at one address must use the same route", alias, who)
}

// address is the target's host and port: known_hosts' key.
func (t target) address() string { return net.JoinHostPort(t.host, strconv.Itoa(t.port)) }

// remap rewrites servers through aliasOf, dropping repeats in first-touch
// order. The input is never modified.
func remap(servers []string, aliasOf map[string]string) []string {
	if len(aliasOf) == 0 || len(servers) == 0 {
		return servers
	}
	out := make([]string, 0, len(servers))
	seen := make(map[string]bool, len(servers))
	for _, s := range servers {
		if to, ok := aliasOf[s]; ok {
			s = to
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// CollapseTargets enforces one server entry per remote file among freshly
// converted hosts, for both import modes: config validation rejects two
// entries with the same (host, port, user, authorized_keys file), and
// `Host web1 web1.example.com` routinely yields two aliases for one machine.
// The first host (input order) keeps the target. A later one with the same
// route is the same machine: dropped with a warning naming both aliases,
// its users' grants redirected onto the kept alias. A later one with
// another route (MapRoutes), or at the kept host's address over another
// route even for another user, may be another machine (OP7): dropped, its
// grants removed, not moved. Hosts with no User pass through untouched.
// Inputs are not modified; users is nil under --servers-only.
func CollapseTargets(hosts []sshcfg.Host, users []identity.User) ([]sshcfg.Host, []identity.User, []string) {
	var warnings []string
	routes := MapRoutes(hosts, nil)
	owner := make(map[target]string, len(hosts))
	at := make(map[string]string, len(hosts)) // address -> first alias there
	aliasOf := make(map[string]string)
	dropped := make(map[string]bool)
	kept := make([]sshcfg.Host, 0, len(hosts))
	for _, h := range hosts {
		if h.User == "" {
			kept = append(kept, h)
			continue
		}
		t := targetOf(h.HostName, h.Port, h.User, "")
		route := routes.routeKey(h.Alias)
		if first, dup := owner[t]; dup {
			if route == routes.routeKey(first) {
				aliasOf[h.Alias] = first
				warnings = append(warnings, sameTarget(h.Alias, first, "host"))
			} else {
				dropped[h.Alias] = true
				warnings = append(warnings, otherRoute(h.Alias, strconv.Quote(first), first))
			}
			continue
		}
		if first, there := at[t.address()]; there && route != routes.routeKey(first) {
			dropped[h.Alias] = true
			warnings = append(warnings, otherAddressRoute(h.Alias, strconv.Quote(first)))
			continue
		}
		owner[t] = h.Alias
		if _, there := at[t.address()]; !there {
			at[t.address()] = h.Alias
		}
		kept = append(kept, h)
	}
	if len(aliasOf) == 0 && len(dropped) == 0 {
		return kept, users, warnings
	}
	out := make([]identity.User, len(users))
	for i, u := range users {
		u.Servers = slices.DeleteFunc(slices.Clone(remap(u.Servers, aliasOf)), func(s string) bool { return dropped[s] })
		out[i] = u
	}
	return kept, out, warnings
}
