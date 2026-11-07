package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
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
			"never emptied: the key stays installed there (a warning says so).",
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
			var ep editPlan
			switch {
			case len(trim) > 0:
				ep, err = planRevokeAccess(mf, users, trim)
			case len(users) > 0:
				ep, err = planRevokeUsers(mf, users, f.operator)
			default:
				ep, err = planRevokeKeys(mf, keyArgs, f.operator)
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
// --key arguments (step 1): a user argument that looks like a key is a
// mistake, and duplicate users, keys and servers are dropped silently.
func revokeTargets(args, keys, servers []string, operator bool) (users []string, keyArgs []keyArg, trim []string, err error) {
	if err := revokeUsage(args, keys, servers, operator); err != nil {
		return nil, nil, nil, err
	}
	for _, u := range args {
		if looksLikeKey(u) {
			return nil, nil, nil, fmt.Errorf("%s looks like a key — did you mean --key?", u)
		}
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

// planRevokeUsers resolves and applies 'revoke USER...'.
func planRevokeUsers(mf *manifest.File, users []string, operator bool) (editPlan, error) {
	cfg := mf.Config()
	var unknown []string
	for _, name := range users {
		if !slices.ContainsFunc(cfg.Users, func(u config.User) bool { return u.Name == name }) {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return editPlan{}, fmt.Errorf("unknown %s: %s", pluralWord(len(unknown), "user", "users"), strings.Join(unknown, ", "))
	}
	ops, err := operatorGate(cfg, users, operator)
	if err != nil {
		return editPlan{}, err
	}
	ep := editPlan{former: cfg, summary: apply.EditSummary{Operators: ops}}
	for _, name := range users {
		r, err := mf.RemoveUser(name)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{Kind: apply.EditRemoveUser, User: name, Keys: r.Keys, Grants: r.Grants})
		ep.removesKey = ep.removesKey || r.Keys > 0
	}
	ep.stillHas = strings.Join(users, ", ") + " still " + pluralWord(len(users), "has", "have")
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// planRevokeKeys resolves and applies 'revoke --key KEY...'. Keys are
// unique across users (config rejects duplicates), so each owner is
// unambiguous. An operator losing its last key loses the flag first
// (operator: true with no keys fails validation).
func planRevokeKeys(mf *manifest.File, keys []keyArg, operator bool) (editPlan, error) {
	cfg := mf.Config()
	var missing []string
	var owners []string
	removing := map[string]int{}
	for _, k := range keys {
		u, ok := cfg.OwnerOf(k.Fingerprint)
		if !ok {
			missing = append(missing, fmt.Sprintf("%s is not in the manifest; apply already removes keys the manifest does not grant — run 'sshepherd audit' to find where it is installed", keyName(k)))
			continue
		}
		if !slices.Contains(owners, u.Name) {
			owners = append(owners, u.Name)
		}
		removing[u.Name]++
	}
	if len(missing) > 0 {
		return editPlan{}, errors.New(strings.Join(missing, "; "))
	}
	ops, err := operatorGate(cfg, owners, operator)
	if err != nil {
		return editPlan{}, err
	}
	cleared := map[string]bool{}
	for _, name := range ops {
		for _, u := range cfg.Users {
			if u.Name == name && removing[name] == len(u.Keys) {
				if err := mf.SetOperator(name, false); err != nil {
					return editPlan{}, fmt.Errorf("edit manifest: %w", err)
				}
				cleared[name] = true
			}
		}
	}
	ep := editPlan{former: cfg, removesKey: true, summary: apply.EditSummary{Operators: ops}}
	for _, k := range keys {
		owner, last, err := mf.RemoveKey(k.Fingerprint)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{
			Kind: apply.EditRemoveKey, User: owner, Fingerprint: k.Fingerprint,
			NoKeysLeft: last, ClearsOperator: last && cleared[owner],
		})
	}
	ep.stillHas = "the revoked " + pluralWord(len(keys), "key still has", "keys still have")
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// planRevokeAccess resolves and applies 'revoke USER... --server NAME...'.
// There is no operator gate: an operator target is refused outright
// (access to every server by definition). Every problem is listed in one
// refusal before any edit (accessProblems).
func planRevokeAccess(mf *manifest.File, users, servers []string) (editPlan, error) {
	cfg := mf.Config()
	if problems := accessProblems(cfg, users, servers); len(problems) > 0 {
		return editPlan{}, errors.New(strings.Join(problems, "; "))
	}
	ep := editPlan{
		former:   cfg,
		stillHas: strings.Join(users, ", ") + " still " + pluralWord(len(users), "has", "have"),
		saveNote: "an apply from a copy without this edit re-grants the removed access",
	}
	for _, name := range users {
		r, err := mf.RemoveAccess(name, servers)
		if err != nil {
			return editPlan{}, fmt.Errorf("edit manifest: %w", err)
		}
		ep.summary.Edits = append(ep.summary.Edits, apply.Edit{
			Kind: apply.EditRemoveAccess, User: name, AccessServers: servers,
			EntriesChanged: r.EntriesChanged, EntriesRemoved: r.EntriesRemoved,
			ServersExcepted: r.ServersExcepted, WildcardsRemoved: r.WildcardsRemoved,
		})
	}
	var err error
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	for i, e := range ep.summary.Edits {
		ep.summary.Edits[i].NoGrantsLeft = !slices.ContainsFunc(ep.edited.Access, func(a config.Access) bool { return a.User == e.User })
	}
	return ep, nil
}

// accessProblems lists why 'revoke USER... --server NAME...' cannot run,
// in this order: unknown users (one entry, the existing wording), unknown
// servers, operator targets, then every non-operator user × known server
// pair the user has no access to (config.Covers: wildcards and except:
// included).
func accessProblems(cfg *config.Config, users, servers []string) []string {
	var problems, unknown, ops []string
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
		problems = append(problems, fmt.Sprintf("%s is an operator (access to every server by definition); remove the user with 'sshepherd revoke %s --operator', or clear operator: true by hand", name, name))
	}
	for _, name := range users {
		if slices.Contains(unknown, name) || slices.Contains(ops, name) {
			continue
		}
		for _, s := range known {
			if !cfg.Covers(name, s) {
				problems = append(problems, fmt.Sprintf("%s has no access to %s", name, s))
			}
		}
	}
	return problems
}

// pluralWord picks the singular or plural form for n.
func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
