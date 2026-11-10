package main

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/reconcile"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
)

// warnFreshDrops: a fresh import replacing an existing manifest with -o
// --force drops what the ssh config cannot reproduce: its revocation memory
// and its manifest-only settings (F1 Q1). --force names the overwrite, so
// this warns rather than refuses. Best effort: a missing or invalid file
// has nothing to lose. fresh is the generated manifest.
func warnFreshDrops(w *importWarnings, out string, force bool, fresh *config.Config) {
	if out == "" || !force {
		return
	}
	raw, err := os.ReadFile(out) // #nosec G304 -- the path the user passed to -o
	if err != nil {
		return
	}
	old, err := config.Parse(raw)
	if err != nil {
		return
	}
	warnMemoryLost(w, out, old)
	warnSettingsLost(w, out, old, fresh)
}

// warnMemoryLost: FILE's serial: and revoked: entries go with it, so every
// revoked key could be re-granted.
func warnMemoryLost(w *importWarnings, out string, old *config.Config) {
	if old.Serial() == 0 && len(old.Tombstones) == 0 {
		return
	}
	w.addAll(importWarnMemoryDropped, fmt.Sprintf("%s holds revocation memory (serial %d, %s) that this fresh import drops: a revoked key could be re-granted; keep it with --merge %s",
		out, old.Serial(), apply.Plural(len(old.Tombstones), "revoked: entry", "revoked: entries"), hintArg(out)))
}

// serverWorthy reports whether a resolved host can become a server entry
// (the manifest requires user). RunE's identity filter and generateManifest's
// skip logic must agree on this predicate.
func serverWorthy(h sshcfg.Host) bool { return h.User != "" }

// dropUnsafeHosts removes hosts whose alias, HostName or User could never
// form a valid server entry (config.ServerFieldIssue: whitespace, control or
// format runes — e.g. a quoted `Host "web 1"`; config.ServerNameIssue also
// reserves an alias like `@web` for tag selectors), warning for each. Filtering
// before identity resolution and target collapse keeps such a host from
// deriving grants or winning a same-target collapse.
func dropUnsafeHosts(w *importWarnings, hosts []sshcfg.Host) []sshcfg.Host {
	kept := hosts[:0:0]
	for _, h := range hosts {
		bad := ""
		for _, f := range []struct {
			field, value string
			issue        func(string) string
		}{
			{"alias", h.Alias, config.ServerNameIssue},
			{"HostName", h.HostName, config.ServerFieldIssue},
			{"User", h.User, config.ServerFieldIssue},
		} {
			if issue := f.issue(f.value); issue != "" {
				bad = fmt.Sprintf("%s %q %s", f.field, f.value, issue)
				break
			}
		}
		if bad != "" {
			w.addAll(importWarnUnsafeHost, fmt.Sprintf("host %q: %s, skipped (not valid in a manifest)", h.Alias, bad))
			continue
		}
		kept = append(kept, h)
	}
	return kept
}

// generateManifest renders hosts and derived identity users as a manifest.
// src is the config path as the user typed it (kept in the header comment;
// the expanded form would leak the local home directory into a committed
// file). Hosts with no resolved User cannot form a valid server entry and are
// returned as notes; because dropping a host affects the manifest's
// completeness, those skips are ALSO embedded as header comments (mirroring
// adopt's unreadable-server warnings), so the product carries its own caveat
// regardless of verbosity. users may be nil (--servers-only). notes also
// covers wildcard-compaction: a non-operator user covering every server is
// emitted as servers: ["*"] and noted for review (stderr-only — it does not
// affect completeness).
func generateManifest(hosts []sshcfg.Host, users []identity.User, routes reconcile.Routes, src string) ([]byte, []reconcile.Warning, error) {
	var (
		servers []config.Server
		mUsers  []config.User
		access  []config.Access
		notes   []reconcile.Warning
		skipped []string // aliases dropped from the manifest, for the header
	)
	for _, h := range hosts {
		if !serverWorthy(h) {
			notes = append(notes, reconcile.Warning{Kind: importWarnSSHConfig, Message: fmt.Sprintf(
				"host %q: no User resolved, skipped (the manifest requires user)", h.Alias)})
			skipped = append(skipped, h.Alias)
			continue
		}
		// The encoder omits port 0 and 22 (both spell the default).
		servers = append(servers, config.Server{Name: h.Alias, Host: h.HostName, Port: h.Port, User: h.User, Via: routes.Via(h.Alias)})
	}
	// Resolve guarantees every derived user has ≥1 server; only users added
	// via --operator-key are grantless (their fleet-wide grant is implied).
	for _, u := range users {
		desc := "imported from " + u.Source
		switch {
		case u.Operator && len(u.Servers) == 0:
			desc += " (--operator-key)"
		case u.Default:
			desc += " (default identity)"
		}
		mUsers = append(mUsers, config.User{
			Name:        u.Name,
			Description: desc,
			Comment:     u.Comment,
			Operator:    u.Operator,
			Keys:        []string{u.Key},
		})
		if u.Operator {
			continue // fleet-wide grant is implied; no access entry
		}
		if len(u.Servers) == 0 {
			continue // its only server was dropped as another route (OP7): no access entry
		}
		if len(servers) >= 2 && len(u.Servers) == len(servers) {
			// Grants only reference server-worthy hosts, so matching the count
			// means covering the fleet. "*" deliberately opts this user into
			// servers added later — flagged so review catches it.
			notes = append(notes, reconcile.Warning{Kind: reconcile.KindWildcardGrant, User: u.Name, Message: fmt.Sprintf(
				"access for %q covers every server; emitted as wildcard %q (includes servers added later)", u.Name, "*")})
			access = append(access, config.Access{User: u.Name, Servers: []string{"*"}})
			continue
		}
		access = append(access, config.Access{User: u.Name, Servers: u.Servers})
	}
	var header strings.Builder
	fmt.Fprintf(&header, "# generated by sshepherd import from %s — review before use\n", src)
	for _, alias := range skipped {
		fmt.Fprintf(&header, "# WARNING: host %q skipped (no User resolved) — not represented in this manifest\n", alias)
	}
	data, err := manifest.Generate(header.String(), mUsers, servers, access)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // "encode manifest: …"
	}
	return data, notes, nil
}

// resolveUsers derives identity users for hosts that resolved a server entry,
// then marks any key named by --operator-key. Resolve failures are warnings (returned
// alongside the users); MarkOperators failures are errors, since operator
// keys are named explicitly on the command line.
func resolveUsers(hosts []sshcfg.Host, operators []string) ([]identity.User, []string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve home for identities: %w", err)
	}
	var withUser []sshcfg.Host
	for _, h := range hosts {
		if serverWorthy(h) { // hosts skipped as servers must not derive grants
			withUser = append(withUser, h)
		}
	}
	r := identity.Resolver{Home: home, LocalUser: localUsername()}
	users, warnings := r.Resolve(withUser)
	if len(operators) > 0 {
		users, err = r.MarkOperators(users, operators)
		if err != nil {
			return nil, nil, fmt.Errorf("operator keys: %w", err)
		}
	}
	return users, warnings, nil
}

// deriveUsers runs identity resolution for the convert pipeline, logging its
// warnings; nil under --servers-only (identity resolution skipped entirely).
func deriveUsers(w *importWarnings, serversOnly bool, hosts []sshcfg.Host, operators []string) ([]identity.User, error) {
	if serversOnly {
		return nil, nil
	}
	users, warnings, err := resolveUsers(hosts, operators)
	if err != nil {
		return nil, err
	}
	w.addAll(importWarnIdentity, warnings...)
	w.log.Info("derived " + apply.Plural(len(users), "user", "users") + " from identity files")
	return users, nil
}

// collapseTargets keeps one server entry per remote file (config rejects
// two entries with one host/port/user/authorized_keys target): later
// aliases for an already-claimed target are dropped with a warning naming
// both, and their derived grants move onto the kept alias. It runs after
// identity resolution so a key used only through a dropped alias still
// reaches the machine.
func collapseTargets(w *importWarnings, hosts []sshcfg.Host, users []identity.User) ([]sshcfg.Host, []identity.User) {
	hosts, users, warnings := reconcile.CollapseTargets(hosts, users)
	w.addAll(importWarnCollapsed, warnings...)
	return hosts, users
}

// warnProxies flags every server-worthy host whose ProxyJump/ProxyCommand
// could not be mapped to a via: (spec S5): it would be dialed directly and
// surface later as an unexplained unreachable. A mapped chain is carried by
// the manifest and warns nothing.
func warnProxies(w *importWarnings, hosts []sshcfg.Host, routes reconcile.Routes) {
	for _, h := range hosts {
		if !serverWorthy(h) || h.Proxy == "" {
			continue
		}
		if why, bad := routes.NotMapped(h.Alias); bad {
			w.addAll(importWarnProxy, fmt.Sprintf("host %q: %s not mapped to via: (%s) — dialed directly; add via: by hand", h.Alias, h.Proxy, why))
		}
	}
}

// manifestServers is the --merge manifest's servers (nil for a fresh
// import): the hops a ProxyJump may name besides the converted hosts.
func manifestServers(mf *manifest.File) []config.Server {
	if mf == nil {
		return nil
	}
	return mf.Config().Servers
}

// renderImport picks the rendering path: a comment-preserving merge append
// when --merge loaded a manifest (mf non-nil), the full generated draft
// otherwise. date feeds the merge marker only. routes carries the mapped
// ProxyJump chains for the fresh draft; a merge maps its own (reconcile.Build).
func renderImport(w *importWarnings, mf *manifest.File, raw []byte, hosts []sshcfg.Host, users []identity.User, routes reconcile.Routes, src, date string) ([]byte, *reconcile.Plan, error) {
	if mf != nil {
		return mergeImport(w, mf, raw, hosts, users, src, date)
	}
	rendered, notes, err := generateManifest(hosts, users, routes, src)
	if err != nil {
		return nil, nil, err
	}
	for _, n := range notes {
		w.add(n)
	}
	return rendered, nil, nil
}

// loadMergeTarget reads the --merge manifest once through the store — the
// bytes are the output when nothing merges and the append base otherwise,
// and an in-place -o FILE --force saves against them — and loads it
// (validation + node tree in one step), surfacing manifest warnings like
// adopt does.
func loadMergeTarget(log *slog.Logger, path string) (manifestTarget, *manifest.File, error) {
	m, err := readManifest(path)
	if err != nil {
		return manifestTarget{}, nil, manifestError("--merge", path, err)
	}
	mf, err := manifest.Load(m.Loaded)
	if err != nil {
		return manifestTarget{}, nil, manifestError("--merge", path, err)
	}
	logManifest(log, mf.Config())
	return m, mf, nil
}

// mergeImport reconciles the converted hosts and identity users against the
// loaded manifest and renders the additions. Warnings go to stderr as WARN,
// notes at info; an empty plan logs the nothing-to-merge note and returns
// the original bytes untouched, otherwise the summary line narrates what
// was appended. Unlike generateManifest, skipped-host warnings stay on
// stderr and are not embedded in the output: the merged file is the
// operator's own document, and only plan warnings ride the marker block.
func mergeImport(w *importWarnings, mf *manifest.File, raw []byte, hosts []sshcfg.Host, users []identity.User, src, date string) ([]byte, *reconcile.Plan, error) {
	var worthy []sshcfg.Host
	for _, h := range hosts {
		if !serverWorthy(h) {
			w.addAll(importWarnSSHConfig, fmt.Sprintf("host %q: no User resolved, skipped (the manifest requires user)", h.Alias))
			continue
		}
		worthy = append(worthy, h)
	}
	plan, err := reconcile.Build(mf.Config(), worthy, users)
	if err != nil {
		return nil, nil, fmt.Errorf("merge: %w", err)
	}
	for _, pw := range plan.Warnings {
		w.add(pw)
	}
	for _, n := range plan.Notes {
		w.log.Info(n)
	}
	if plan.Empty() {
		w.log.Info("nothing to merge: the manifest already covers " + src)
		return raw, &plan, nil
	}
	w.log.Info(mergeSummary(plan))
	rendered, err := renderMergedImport(mf, raw, plan, src, date)
	if err != nil {
		return nil, nil, err
	}
	return rendered, &plan, nil
}

// renderMergedImport renders the plan as a comment-preserving append to the
// original manifest text: existing bytes kept — comments intact, no
// regenerated header — with the plan's additions appended under a dated
// `merged by sshepherd import from <src>` marker carrying the plan's
// warnings as WARNING: comment lines. src is the ssh-config path as typed
// (never home-expanded — the expanded form would leak the local home
// directory); date is injected (never read from the clock here) so goldens
// stay deterministic. An empty plan returns raw unchanged, byte for byte —
// deliberately including conflict-only runs: the warnings live on stderr
// only, because a warnings-only comment block would recur on every re-run
// and break byte-identical idempotency forever (adjudicated 2026-07-19).
// Single-use: a non-empty plan mutates mf's node tree via Append, so a
// second call on the same File would stack the additions.
func renderMergedImport(mf *manifest.File, raw []byte, plan reconcile.Plan, src, date string) ([]byte, error) {
	if plan.Empty() {
		return raw, nil
	}
	comments := []string{fmt.Sprintf("merged by sshepherd import from %s on %s", src, date)}
	for _, w := range plan.Warnings {
		comments = append(comments, "WARNING: "+w.Message)
	}
	users := make([]config.User, 0, len(plan.NewUsers))
	for _, u := range plan.NewUsers {
		users = append(users, config.User{
			Name: u.Name, Description: u.Description, Comment: u.Comment,
			Operator: u.Operator, Keys: u.Keys,
		})
	}
	servers := make([]config.Server, 0, len(plan.NewServers))
	for _, s := range plan.NewServers {
		servers = append(servers, config.Server{Name: s.Name, Host: s.Host, Port: s.Port, User: s.User, Via: s.Via})
	}
	access := make([]config.Access, 0, len(plan.Extensions)+len(plan.NewGrants))
	for _, e := range plan.Extensions {
		access = append(access, config.Access{User: e.User, Servers: e.Servers})
	}
	for _, g := range plan.NewGrants {
		access = append(access, config.Access{User: g.User, Servers: g.Servers})
	}
	if err := mf.Append(comments, users, servers, access); err != nil {
		return nil, fmt.Errorf("merge manifest: %w", err)
	}
	out, err := mf.Encode()
	if err != nil {
		return nil, fmt.Errorf("merge manifest: %w", err)
	}
	return out, nil
}

// mergeSummary renders the info-level outcome line, e.g.
// "merged: +1 server, +2 users, +1 extension, +2 access entries, 1 conflict skipped".
func mergeSummary(plan reconcile.Plan) string {
	return "merged: " + strings.Join([]string{
		"+" + apply.Plural(len(plan.NewServers), "server", "servers"),
		"+" + apply.Plural(len(plan.NewUsers), "user", "users"),
		"+" + apply.Plural(len(plan.Extensions), "extension", "extensions"),
		"+" + apply.Plural(len(plan.NewGrants), "access entry", "access entries"),
		apply.Plural(plan.ConflictsSkipped(), "conflict", "conflicts") + " skipped",
	}, ", ")
}

const defaultSSHConfig = "~/.ssh/config"

// localUsername names generated users. Best-effort: os/user, then $USER.
func localUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		return u.Username
	}
	if s := os.Getenv("USER"); s != "" {
		return s
	}
	return "user"
}

// importOpts are import's flags.
type importOpts struct {
	outPath     string
	force       bool
	serversOnly bool
	operators   []string
	mergePath   string
	json        bool
}

// importRun is one import run.
type importRun struct {
	log    *slog.Logger
	stdout io.Writer
	opts   importOpts
}

func (r *importRun) run(args []string) error {
	if r.opts.serversOnly && len(r.opts.operators) > 0 {
		return fmt.Errorf("--operator-key conflicts with --servers-only (operators are users)")
	}
	src := defaultSSHConfig
	if len(args) == 1 {
		src = args[0]
	}
	srcPath, err := expandHome(src)
	if err != nil {
		return err
	}
	// m stays the zero manifestTarget without --merge: -o is then
	// always a new-file publish.
	var (
		m  manifestTarget
		mf *manifest.File
	)
	if r.opts.mergePath != "" {
		// Read FILE up front: failing fast beats converting first,
		// and the store read is what lets an in-place
		// -o FILE --force refuse a concurrent change.
		m, mf, err = loadMergeTarget(r.log, r.opts.mergePath)
		if err != nil {
			return err
		}
	}
	warns := &importWarnings{log: r.log}
	hosts, sshWarnings, err := sshcfg.Load(srcPath)
	if err != nil {
		return fmt.Errorf("load ssh config: %w", err) // wrapcheck: wrap at package boundary
	}
	parsed := len(hosts)
	r.log.Info("parsed " + src + ": " + apply.Plural(parsed, "host", "hosts"))
	warns.addAll(importWarnSSHConfig, sshWarnings...)
	hosts = dropUnsafeHosts(warns, hosts)
	users, err := deriveUsers(warns, r.opts.serversOnly, hosts, r.opts.operators)
	if err != nil {
		return err
	}
	hosts, users = collapseTargets(warns, hosts, users)
	routes := reconcile.MapRoutes(hosts, manifestServers(mf))
	warnProxies(warns, hosts, routes)
	// The clock is read only here, so tests inject a fixed date.
	rendered, plan, err := renderImport(warns, mf, m.Loaded, hosts, users, routes, src, time.Now().Format("2006-01-02"))
	if err != nil {
		return err
	}
	// Self-check: never emit a manifest our own loader would reject,
	// nor (under --merge) one that keeps a policy conflict (D29).
	saved, err := config.Parse(rendered)
	if err != nil {
		return fmt.Errorf("bug: generated manifest fails validation: %w", err)
	}
	if err := conflictRefusal(formerManifest(m), saved); err != nil {
		return err
	}
	if r.opts.mergePath == "" {
		warnFreshDrops(warns, r.opts.outPath, r.opts.force, saved)
	}
	if !r.opts.json {
		return emitManifest(r.stdout, m, r.opts.outPath, rendered, r.opts.force)
	}
	return r.finishJSON(m, rendered, saved, plan, importStatsOf(parsed, users), warns.list)
}

func newImportCmd(a *app, stdout io.Writer) *cobra.Command {
	var opts importOpts
	cmd := &cobra.Command{
		Use:   "import [ssh-config-path]",
		Short: "Convert an OpenSSH client config into a starter manifest",
		Long: "Reads an OpenSSH client config (default ~/.ssh/config), resolves each\n" +
			"concrete Host to the HostName/Port/User that ssh would use, and emits a\n" +
			"valid SSHepherd manifest. users: and access: are derived from each host's\n" +
			"IdentityFile (or ssh's default identities when none is set) by reading the\n" +
			"matching .pub files on this machine — run import where you actually ssh\n" +
			"from, and review the result before use. Private keys are never read.\n" +
			"Keys named via --operator-key become operator users: granted every server\n" +
			"implicitly (no access entry) and protected from removal by future apply.\n" +
			"With --merge FILE the existing manifest FILE is preserved — comments\n" +
			"intact — and only what is genuinely new is appended; on any conflict the\n" +
			"manifest wins and the incoming entry is dropped with a warning.\n" +
			"Warnings about skipped entries go to stderr.\n\n" + exitCodesImport,
		Example: "  # Servers only, as the starting point for adopt\n" +
			"  sshepherd import --servers-only -o sshepherd.yaml\n\n" +
			"  # Servers and users from one config, with an operator key\n" +
			"  sshepherd import ~/.ssh/config --operator-key ~/.ssh/ops.pub -o sshepherd.yaml\n\n" +
			"  # Add hosts that are new in the ssh config to an existing manifest\n" +
			"  sshepherd import --merge sshepherd.yaml -o merged.yaml\n\n" +
			"  # A report for a script; the manifest goes to the file\n" +
			"  sshepherd import --json -o sshepherd.yaml",
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			r := &importRun{log: a.logger, stdout: stdout, opts: opts}
			return r.run(args)
		},
	}
	cmd.Flags().StringVarP(&opts.outPath, "output", "o", "", "write the manifest to this file instead of stdout")
	cmd.Flags().BoolVar(&opts.force, "force", false, "allow --output to overwrite an existing file")
	cmd.Flags().BoolVar(&opts.serversOnly, "servers-only", false, "leave the users and access sections empty (skip identity resolution)")
	cmd.Flags().StringArrayVar(&opts.operators, "operator-key", nil,
		"key file `PATH` whose owner is an operator: granted every server and protected from removal (repeatable)")
	cmd.Flags().StringVar(&opts.mergePath, "merge", "",
		"merge into `FILE`: preserve its text and append what is new")
	cmd.Flags().BoolVar(&opts.json, "json", false, "emit a machine-readable report on stdout (the manifest goes to -o, or into the report's manifest field)")
	return cmd
}
