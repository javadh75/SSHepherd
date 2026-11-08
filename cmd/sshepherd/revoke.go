package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
)

func newRevokeCmd(a *app, stdout io.Writer) *cobra.Command {
	var (
		f       editFlags
		keys    []string
		servers []string
	)
	cmd := &cobra.Command{
		Use:   "revoke {USER... [--server NAME...] | --key KEY...}",
		Short: "Remove users or keys from the manifest and push the change to the servers it affects",
		Long: "Edits the manifest — comments preserved — and pushes the edit through\n" +
			"apply's pipeline, restricted to the servers whose rendered\n" +
			"authorized_keys changes. 'revoke USER...' removes each user and every\n" +
			"access entry naming them (offboarding); 'revoke --key KEY...' removes\n" +
			"single keys (a lost laptop): KEY is a SHA256: fingerprint, a public-key\n" +
			"line, or a .pub file path. 'revoke USER... --server NAME...' removes only\n" +
			"the users' access to those servers (a wildcard grant gains an except:\n" +
			"entry); the users and their keys stay. Operator users (and their keys)\n" +
			"need --operator. The plan is shown and confirmed once; the manifest is\n" +
			"saved after confirmation and before the first write, so commit and push\n" +
			"it afterwards. --dry-run changes nothing; --no-apply saves the edit\n" +
			"without contacting any server. A server whose only grantee is revoked is\n" +
			"never emptied: the key stays installed there (a warning says so).\n\n" + exitCodesWrite,
		Example: "  # Offboard a user everywhere\n" +
			"  sshepherd revoke alice\n\n" +
			"  # Lost laptop: revoke one key, keep the user\n" +
			"  sshepherd revoke --key ~/alice-laptop.pub\n\n" +
			"  # Remove a user's access to one server only\n" +
			"  sshepherd revoke alice --server db-1\n\n" +
			"  # Record the edit now, push it later\n" +
			"  sshepherd revoke alice --no-apply",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := f.validate(cmd)
			if err != nil {
				return err
			}
			users, keyArgs, trim, err := revokeTargets(args, keys, servers, f.operator)
			if err != nil {
				return err
			}
			m, mf, err := loadForEdit(a.logger, f.run.cfgPath)
			if err != nil {
				return err
			}
			if err := checkUserArgs(mf.Config(), users); err != nil {
				return err
			}
			var ep editPlan
			h := f.run.followUp()
			memo := f.memo()
			switch {
			case len(trim) > 0:
				ep, err = planRevokeAccess(mf, users, trim, h, memo)
			case len(users) > 0:
				ep, err = planRevokeUsers(mf, users, f.operator, h, memo)
			default:
				ep, err = planRevokeKeys(mf, keyArgs, f.operator, memo)
			}
			if err != nil {
				return err
			}
			ep.target = m
			return runEdit(cmd, a, stdout, &f, ids, ep)
		},
	}
	f.register(cmd)
	cmd.Flags().StringArrayVar(&keys, "key", nil,
		"`KEY` to revoke: a SHA256: fingerprint, a public-key line, or a .pub file path (repeatable)")
	cmd.Flags().StringArrayVar(&servers, "server", nil,
		"remove the users' access to this server only (repeatable); the users and their keys stay")
	return cmd
}

// revokeTargets applies revoke's usage rules (revokeUsage) and classifies
// --key arguments (step 1); duplicate users, keys and servers are dropped
// silently. User arguments are checked against the manifest later
// (checkUserArgs), so a user called tunnel is never mistaken for a key.
func revokeTargets(args, keys, servers []string, operator bool) (users []string, keyArgs []keyArg, trim []string, err error) {
	if err := revokeUsage(args, keys, servers, operator); err != nil {
		return nil, nil, nil, err
	}
	for _, k := range keys {
		ka, err := parseKeyArg(roleKey, k)
		if err != nil {
			return nil, nil, nil, err
		}
		if !slices.ContainsFunc(keyArgs, func(o keyArg) bool { return o.Fingerprint == ka.Fingerprint }) {
			keyArgs = append(keyArgs, ka)
		}
	}
	return unique(args), keyArgs, unique(servers), nil
}

// checkUserArgs: an argument naming a manifest user is that user, whatever
// it looks like (a service account called tunnel, "Alice Smith"). Only an
// unknown name that looks like a key is reported as a probable --key
// mistake; other unknown names reach planRevokeUsers' "unknown users" error.
func checkUserArgs(cfg *config.Config, users []string) error {
	for _, u := range users {
		known := slices.ContainsFunc(cfg.Users, func(x config.User) bool { return x.Name == u })
		if !known && looksLikeKey(u) {
			return fmt.Errorf("%s looks like a key — did you mean --key?", u)
		}
	}
	return nil
}

// revokeUsage is revoke's flag/argument combination rules, before the
// manifest is read; the first that matches wins. Users and keys are
// exclusive and one is required; --server goes with users only — never
// with --key or --operator, and never '*'.
func revokeUsage(args, keys, servers []string, operator bool) error {
	switch {
	case len(args) > 0 && len(keys) > 0:
		return errors.New("revoke takes users or --key, not both")
	case len(args) == 0 && len(keys) == 0:
		return errors.New("nothing to revoke: name the users, or pass --key KEY")
	case len(servers) > 0 && len(keys) > 0:
		return errors.New("access is granted per user, not per key — use 'sshepherd revoke USER --server NAME'")
	case len(servers) > 0 && operator:
		return errors.New("--operator cannot be combined with --server: operators have access to every server by definition")
	case slices.Contains(servers, "*"):
		return errors.New("--server takes server names; to remove all of a user's access use 'sshepherd revoke USER'")
	}
	return nil
}

// unique returns in without repeats, first occurrence kept (nil for none).
func unique(in []string) []string {
	var out []string
	for _, s := range in {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// planRevokeUsers resolves and applies 'revoke USER...': each user and its
// access entries go, and each of its keys is tombstoned (D1). A name not in
// users: that a key tombstone labels was already revoked (D1c): a note, no
// edit. A name never seen is refused (exit 3) with what a retried revoke
// needs, carrying the run's flags (h).
func planRevokeUsers(mf *manifest.File, users []string, operator bool, h followUp, memo editMemo) (editPlan, error) {
	cfg := mf.Config()
	live, unknown, already := splitRevokeUsers(cfg, users)
	if len(unknown) > 0 {
		return editPlan{}, fmt.Errorf("unknown %s: %s — not in the manifest (already revoked?); see what is left to push with '%s', verify with '%s'",
			pluralWord(len(unknown), "user", "users"), strings.Join(unknown, ", "),
			h.command("apply", []string{"--dry-run"}), h.command("audit", nil))
	}
	ep := editPlan{former: cfg, summary: apply.EditSummary{AlreadyRevoked: already}}
	for _, a := range already {
		ep.already = append(ep.already, userKeyTombstones(cfg, a.User)...)
	}
	if len(live) == 0 {
		ep.noop = true
		return ep, nil
	}
	ops, err := operatorGate(cfg, userNames(live), operator)
	if err != nil {
		return editPlan{}, err
	}
	ep.summary.Operators = ops
	var tombs []config.Tombstone
	for _, u := range live {
		r, err := mf.RemoveUser(u.Name)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{Kind: apply.EditRemoveUser, User: u.Name, Keys: r.Keys, Grants: r.Grants})
		ep.removesKey = ep.removesKey || r.Keys > 0
		for _, fp := range userFingerprints(u) {
			tombs = append(tombs, config.Tombstone{Fingerprint: fp, User: u.Name, Date: memo.date, Reason: memo.reason})
		}
	}
	ep.stillHas = strings.Join(userNames(live), ", ") + " still " + pluralWord(len(live), "has", "have")
	if err := ep.remember(mf, tombs); err != nil {
		return editPlan{}, err
	}
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// splitRevokeUsers sorts revoke's user arguments: in users: (live, manifest
// entries), already revoked (a key tombstone labels the name; D1c), or
// unknown.
func splitRevokeUsers(cfg *config.Config, names []string) (live []config.User, unknown []string, already []apply.AlreadyRevoked) {
	for _, name := range names {
		if i := slices.IndexFunc(cfg.Users, func(u config.User) bool { return u.Name == name }); i >= 0 {
			live = append(live, cfg.Users[i])
			continue
		}
		if t, ok := latestUserTombstone(cfg, name); ok {
			already = append(already, apply.AlreadyRevoked{User: name, Date: t.Date})
			continue
		}
		unknown = append(unknown, name)
	}
	return live, unknown, already
}

// latestUserTombstone is the last key tombstone labelled with name.
func latestUserTombstone(cfg *config.Config, name string) (config.Tombstone, bool) {
	var found config.Tombstone
	ok := false
	for _, t := range cfg.Tombstones {
		if t.IsKey() && t.User == name {
			found, ok = t, true
		}
	}
	return found, ok
}

// userKeyTombstones are the key tombstones labelled with name.
func userKeyTombstones(cfg *config.Config, name string) []config.Tombstone {
	var out []config.Tombstone
	for _, t := range cfg.Tombstones {
		if t.IsKey() && t.User == name {
			out = append(out, t)
		}
	}
	return out
}

// userFingerprints lists u's key fingerprints (validated lines).
func userFingerprints(u config.User) []string {
	fps := make([]string, 0, len(u.Keys))
	for _, line := range u.Keys {
		if k, err := authkeys.ParseLine(line); err == nil && k != nil {
			fps = append(fps, k.Fingerprint)
		}
	}
	return fps
}

func userNames(us []config.User) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Name)
	}
	return out
}

// planRevokeKeys resolves and applies 'revoke --key KEY...'. An owned key
// is removed and tombstoned under its owner (an operator losing its last
// key loses the flag first: operator: true with no keys fails validation).
// A key no user has is tombstoned with no label and writes no server (D1b);
// one already tombstoned is a no-op note.
func planRevokeKeys(mf *manifest.File, keys []keyArg, operator bool, memo editMemo) (editPlan, error) {
	cfg := mf.Config()
	ep := editPlan{former: cfg}
	var owned []keyArg
	var unowned, owners []string
	removing := map[string]int{}
	for _, k := range keys {
		u, ok := cfg.OwnerOf(k.Fingerprint)
		switch {
		case ok:
			owned = append(owned, k)
			if !slices.Contains(owners, u.Name) {
				owners = append(owners, u.Name)
			}
			removing[u.Name]++
		default:
			if t, done := cfg.Revoked(k.Fingerprint); done {
				ep.summary.AlreadyRevoked = append(ep.summary.AlreadyRevoked, apply.AlreadyRevoked{Fingerprint: k.Fingerprint, Date: t.Date})
				ep.already = append(ep.already, t)
			} else {
				unowned = append(unowned, k.Fingerprint)
			}
		}
	}
	if len(owned)+len(unowned) == 0 {
		ep.noop = true
		return ep, nil
	}
	ops, err := operatorGate(cfg, owners, operator)
	if err != nil {
		return editPlan{}, err
	}
	cleared, err := clearEmptiedOperators(mf, cfg, ops, removing)
	if err != nil {
		return editPlan{}, err
	}
	ep.summary.Operators, ep.removesKey = ops, true
	var tombs []config.Tombstone
	for _, k := range owned {
		owner, last, err := mf.RemoveKey(k.Fingerprint)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{
			Kind: apply.EditRemoveKey, User: owner, Fingerprint: k.Fingerprint,
			NoKeysLeft: last, ClearsOperator: last && cleared[owner],
		})
		tombs = append(tombs, config.Tombstone{Fingerprint: k.Fingerprint, User: owner, Date: memo.date, Reason: memo.reason})
	}
	for _, fp := range unowned {
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{Kind: apply.EditRecordKey, Fingerprint: fp})
		tombs = append(tombs, config.Tombstone{Fingerprint: fp, Date: memo.date, Reason: memo.reason})
	}
	ep.stillHas = "the revoked " + pluralWord(len(owned)+len(unowned), "key still has", "keys still have")
	if err := ep.remember(mf, tombs); err != nil {
		return editPlan{}, err
	}
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// clearEmptiedOperators clears operator: on each operator target that
// loses every key in this edit, and reports which.
func clearEmptiedOperators(mf *manifest.File, cfg *config.Config, ops []string, removing map[string]int) (map[string]bool, error) {
	cleared := map[string]bool{}
	for _, name := range ops {
		for _, u := range cfg.Users {
			if u.Name == name && removing[name] == len(u.Keys) {
				if err := mf.SetOperator(name, false); err != nil {
					return nil, fmt.Errorf("edit manifest: %w", err)
				}
				cleared[name] = true
			}
		}
	}
	return cleared, nil
}

// planRevokeAccess resolves and applies 'revoke USER... --server NAME...'.
// There is no operator gate: an operator target is refused outright
// (access to every server by definition). Every problem is listed in one
// refusal before any edit (accessProblems). A pair an access tombstone
// already records is a note (D1c). Servers removed from an explicit list
// are tombstoned (D1a); a server that only gained an except: entry needs
// none — the except: already remembers it.
func planRevokeAccess(mf *manifest.File, users, servers []string, h followUp, memo editMemo) (editPlan, error) {
	cfg := mf.Config()
	problems, trims, already := accessProblems(cfg, users, servers, h)
	if len(problems) > 0 {
		return editPlan{}, errors.New(strings.Join(problems, "; "))
	}
	ep := editPlan{former: cfg, summary: apply.EditSummary{AlreadyRevoked: already}}
	var trimmed []string
	for _, name := range users {
		if len(trims[name]) > 0 {
			trimmed = append(trimmed, name)
		}
	}
	if len(trimmed) == 0 {
		ep.noop = true
		return ep, nil
	}
	ep.stillHas = strings.Join(trimmed, ", ") + " still " + pluralWord(len(trimmed), "has", "have")
	for _, name := range trimmed {
		r, err := mf.RemoveAccess(name, trims[name])
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{
			Kind: apply.EditRemoveAccess, User: name, AccessServers: trims[name],
			EntriesChanged: r.EntriesChanged, EntriesRemoved: r.EntriesRemoved,
			ServersExcepted: r.ServersExcepted, WildcardsRemoved: r.WildcardsRemoved,
		})
	}
	_, mid, err := encodeEdit(mf) // only to see which servers an except: now remembers
	if err != nil {
		return editPlan{}, err
	}
	if err := ep.remember(mf, accessTombstones(cfg, mid, trimmed, trims, memo)); err != nil {
		return editPlan{}, err
	}
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	for i, e := range ep.summary.Edits {
		ep.summary.Edits[i].NoGrantsLeft = !slices.ContainsFunc(ep.edited.Access, func(a config.Access) bool { return a.User == e.User })
		// What is left, said in the header: a "web-1 first" trim must not
		// read as an offboarding.
		for _, srv := range ep.edited.Servers {
			if ep.edited.Covers(e.User, srv.Name) {
				ep.summary.Edits[i].KeepsServers++
			}
		}
	}
	return ep, nil
}

// accessTombstones: one entry per user, naming the trimmed servers no
// wildcard except: remembers in mid (the manifest after the access edit).
// A wildcard this trim deleted took its except: list with it, so a server
// only that list remembered is tombstoned too, or a later adopt --merge
// would re-grant it (D1a); the original date is unknown, so this run's is
// recorded. Only the former manifest's servers are named (a tombstone for
// a server it does not have would only warn).
func accessTombstones(former, mid *config.Config, users []string, trims map[string][]string, memo editMemo) []config.Tombstone {
	var tombs []config.Tombstone
	for _, name := range users {
		var lost []string
		for _, s := range trims[name] {
			if !mid.ExceptCarveOut(name, s) {
				lost = append(lost, s)
			}
		}
		for _, s := range former.Servers {
			if forgottenCarveOut(former, mid, name, s.Name) && !slices.Contains(lost, s.Name) {
				lost = append(lost, s.Name)
			}
		}
		if len(lost) > 0 {
			tombs = append(tombs, config.Tombstone{User: name, Servers: lost, Date: memo.date, Reason: memo.reason})
		}
	}
	return tombs
}

// forgottenCarveOut reports a server only a deleted wildcard's except:
// remembered: excluded in former, neither excluded nor covered in mid, and
// not already recorded by an access tombstone.
func forgottenCarveOut(former, mid *config.Config, user, server string) bool {
	if former.Covers(user, server) || !former.ExceptCarveOut(user, server) {
		return false
	}
	if mid.ExceptCarveOut(user, server) || mid.Covers(user, server) {
		return false
	}
	_, recorded := former.AccessRevoked(user, server)
	return !recorded
}

// accessProblems lists why 'revoke USER... --server NAME...' cannot run,
// in this order: unknown users (one entry, the existing wording), unknown
// servers, operator targets, then every non-operator user × known server
// pair the user has no access to and no access tombstone records
// (config.Covers: wildcards and except: included). It also returns, per
// user, the servers to trim, and the pairs already revoked (D1c). h
// carries the run's flags into the operator hint.
func accessProblems(cfg *config.Config, users, servers []string, h followUp) (problems []string, trims map[string][]string, already []apply.AlreadyRevoked) {
	var unknown, ops []string
	for _, name := range users {
		i := slices.IndexFunc(cfg.Users, func(u config.User) bool { return u.Name == name })
		switch {
		case i < 0:
			unknown = append(unknown, name)
		case cfg.Users[i].Operator:
			ops = append(ops, name)
		}
	}
	if len(unknown) > 0 {
		problems = append(problems, fmt.Sprintf("unknown %s: %s", pluralWord(len(unknown), "user", "users"), strings.Join(unknown, ", ")))
	}
	var known []string
	for _, s := range servers {
		if slices.ContainsFunc(cfg.Servers, func(c config.Server) bool { return c.Name == s }) {
			known = append(known, s)
		} else {
			problems = append(problems, fmt.Sprintf("no server named %q in the manifest", s))
		}
	}
	for _, name := range ops {
		problems = append(problems, fmt.Sprintf("%s is an operator (access to every server by definition); remove the user with '%s', or clear operator: true by hand",
			name, h.command("revoke", []string{hintArg(name)}, "--operator")))
	}
	trims = map[string][]string{}
	for _, name := range users {
		if slices.Contains(unknown, name) || slices.Contains(ops, name) {
			continue
		}
		trim, gone, date, missing := classifyPairs(cfg, name, known)
		trims[name] = trim
		problems = append(problems, missing...)
		if len(gone) > 0 {
			already = append(already, apply.AlreadyRevoked{User: name, Servers: gone, Date: date})
		}
	}
	return problems, trims, already
}

// classifyPairs sorts one user's --server targets: covered (trim), already
// revoked by an access tombstone (gone, with the latest date), or a problem.
func classifyPairs(cfg *config.Config, name string, servers []string) (trim, gone []string, date string, problems []string) {
	for _, s := range servers {
		if cfg.Covers(name, s) {
			trim = append(trim, s)
			continue
		}
		if t, ok := cfg.AccessRevoked(name, s); ok {
			gone, date = append(gone, s), t.Date
			continue
		}
		problems = append(problems, fmt.Sprintf("%s has no access to %s", name, s))
	}
	return trim, gone, date, problems
}

// pluralWord picks the singular or plural form for n.
func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
