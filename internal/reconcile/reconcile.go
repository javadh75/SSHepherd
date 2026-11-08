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
	User    string
	Servers []string
}

// Grant is a new user's access entry, post-rename and post-compaction
// (Servers may be ["*"] when the grant covers the entire merged fleet).
type Grant struct {
	User    string
	Servers []string
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
	Warnings   []string
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
	fleet      map[string]bool            // merged fleet: manifest ∪ appended server names
	taken      map[string]bool            // claimed user names, seeded with every manifest name
	extSeen    map[string]map[string]bool // owner -> servers already recorded as extensions
	extServers map[string][]string        // owner -> extension servers, first-touch order
}

// Build reconciles hosts (the server-worthy converted hosts) and users (the
// identity-derived users; nil under --servers-only) against cfg, the loaded
// manifest. Deterministic: hosts and users are processed in input order,
// warnings in discovery order, extensions in cfg.Users order. The only error
// is the locked --operator promotion conflict — a marked key owned by an
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
	}
	for _, s := range cfg.Servers {
		b.fleet[s.Name] = true
	}
	for _, u := range cfg.Users {
		b.taken[u.Name] = true
	}
	b.servers(hosts)
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
// server, which is the same machine.
func (b *builder) servers(hosts []sshcfg.Host) {
	byName := make(map[string]config.Server, len(b.cfg.Servers))
	targets := make(map[target]string, len(b.cfg.Servers))
	for _, s := range b.cfg.Servers {
		byName[s.Name] = s
		if t := targetOf(s.Host, s.Port, s.User, s.AuthorizedKeysFile); targets[t] == "" {
			targets[t] = s.Name
		}
	}
	for _, h := range hosts {
		s, exists := byName[h.Alias]
		if !exists {
			t := targetOf(h.HostName, h.Port, h.User, "")
			if owner, dup := targets[t]; dup {
				b.aliasOf[h.Alias] = owner
				b.plan.conflicts++
				b.plan.Warnings = append(b.plan.Warnings, sameTarget(h.Alias, owner, "manifest server"))
				continue
			}
			targets[t] = h.Alias
			port := h.Port
			if port == 22 {
				port = 0 // effective default, omitted on render
			}
			b.plan.NewServers = append(b.plan.NewServers,
				ServerAdd{Name: h.Alias, Host: h.HostName, Port: port, User: h.User})
			b.fleet[h.Alias] = true
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
		b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
			"server %q in the ssh config differs from the manifest (host/port/user) — manifest kept", h.Alias))
	}
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
			b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
				"key %s from %s is REVOKED (%s) — not imported", k.Fingerprint, pubPath(u.Source), t.Label()))
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
// dropped with the server), operator owner (implicit fleet-wide grant, never
// extended), Covers (explicit grant or wildcard absorption — a "*" user
// gains every appended server automatically), except carve-out (never
// re-granted), an access tombstone (never re-granted, D1a), else an
// extension pair.
func (b *builder) knownKey(u identity.User, owner config.User, fp string) error {
	if u.Operator && !owner.Operator {
		return fmt.Errorf(
			"--operator key %s belongs to manifest user %q, who is not an operator — promotion must be an explicit manifest edit",
			fp, owner.Name)
	}
	if u.Operator {
		return nil // owner already an operator: idempotent --operator re-run, silent no-op
	}
	extended := false
	for _, srv := range b.redirect(u.Servers) {
		switch {
		case b.conflicted[srv]:
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
				"access for %q to %q dropped: the server conflicts with the manifest", owner.Name, srv))
		case owner.Operator:
		case b.cfg.Covers(owner.Name, srv):
		case b.cfg.ExceptCarveOut(owner.Name, srv):
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
				"key of %q used for %q in the ssh config, which their except: list deliberately excludes — not re-granted; audit flags this drift",
				owner.Name, srv))
		default:
			if t, gone := b.cfg.AccessRevoked(owner.Name, srv); gone {
				b.plan.conflicts++
				b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
					"key %s of %q found on %q, whose access was revoked (%s) — not re-granted; audit flags this drift",
					fp, owner.Name, srv, t.Date))
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
			b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
				"key %s from the ssh config belongs to manifest user %q — extending their access", fp, owner.Name))
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
		if b.conflicted[srv] {
			dropped = append(dropped, srv)
			continue
		}
		surviving = append(surviving, srv)
	}
	if len(surviving) == 0 {
		// Grantless-user rule: appending a key no server will ever receive
		// is a half-truth the self-check cannot catch. Skipped entirely, so
		// no name is claimed either.
		if len(dropped) > 0 {
			b.plan.conflicts++
			b.plan.Warnings = append(b.plan.Warnings, notAdded(u.Name, dropped))
		}
		return
	}
	for _, srv := range dropped {
		b.plan.conflicts++
		b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
			"access for %q to %q dropped: the server conflicts with the manifest", u.Name, srv))
	}
	name := b.claim(u.Name)
	b.plan.NewUsers = append(b.plan.NewUsers, UserAdd{
		Name: name, Description: describe(u), Comment: u.Comment, Keys: []string{u.Key},
	})
	servers := surviving
	if b.coversFleet(surviving) {
		servers = []string{"*"}
		b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
			"access for %q covers every server; emitted as wildcard %q (includes servers added later)", name, "*"))
	}
	b.plan.NewGrants = append(b.plan.NewGrants, Grant{User: name, Servers: servers})
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
		b.plan.Warnings = append(b.plan.Warnings, fmt.Sprintf(
			"user name %q already taken, using %q for the incoming key", want, name))
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
// import does: the identity source, qualified for --operator-created and
// default-identity keys.
func describe(u identity.User) string {
	desc := "imported from " + u.Source
	switch {
	case u.Operator && len(u.Servers) == 0:
		desc += " (--operator)"
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
// The first host (input order) keeps the target; every later one is dropped
// with a warning naming both aliases, and users' grants on it are
// redirected onto the kept alias — the same machine. Hosts with no User
// pass through untouched (they never become servers). Inputs are not
// modified; users is nil under --servers-only.
func CollapseTargets(hosts []sshcfg.Host, users []identity.User) ([]sshcfg.Host, []identity.User, []string) {
	var warnings []string
	owner := make(map[target]string, len(hosts))
	aliasOf := make(map[string]string)
	kept := make([]sshcfg.Host, 0, len(hosts))
	for _, h := range hosts {
		if h.User == "" {
			kept = append(kept, h)
			continue
		}
		t := targetOf(h.HostName, h.Port, h.User, "")
		if first, dup := owner[t]; dup {
			aliasOf[h.Alias] = first
			warnings = append(warnings, sameTarget(h.Alias, first, "host"))
			continue
		}
		owner[t] = h.Alias
		kept = append(kept, h)
	}
	if len(aliasOf) == 0 {
		return kept, users, warnings
	}
	out := make([]identity.User, len(users))
	for i, u := range users {
		u.Servers = remap(u.Servers, aliasOf)
		out[i] = u
	}
	return kept, out, warnings
}
