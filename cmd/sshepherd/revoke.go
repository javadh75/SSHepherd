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
		f    editFlags
		keys []string
	)
	cmd := &cobra.Command{
		Use:   "revoke {USER... | --key KEY...}",
		Short: "Remove users or keys from the manifest and push the change to the servers it affects",
		Long: "Edits the manifest — comments preserved — and pushes the edit through\n" +
			"apply's pipeline, restricted to the servers whose rendered\n" +
			"authorized_keys changes. 'revoke USER...' removes each user and every\n" +
			"access entry naming them (offboarding); 'revoke --key KEY...' removes\n" +
			"single keys (a lost laptop): KEY is a SHA256: fingerprint, a public-key\n" +
			"line, or a .pub file path. Operator users (and their keys) need\n" +
			"--operator. The plan is shown and confirmed once; the manifest is saved\n" +
			"after confirmation and before the first write, so commit and push it\n" +
			"afterwards. --dry-run changes nothing; --no-apply saves the edit without\n" +
			"contacting any server. A server whose only grantee is revoked is never\n" +
			"emptied: the key stays installed there (a warning says so).",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := f.validate(cmd)
			if err != nil {
				return err
			}
			users, keyArgs, err := revokeTargets(args, keys)
			if err != nil {
				return err
			}
			m, mf, err := loadForEdit(a.logger, f.run.cfgPath)
			if err != nil {
				return err
			}
			var ep editPlan
			if len(users) > 0 {
				ep, err = planRevokeUsers(mf, users, f.operator)
			} else {
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
	return cmd
}

// revokeTargets applies revoke's usage rules and classifies --key
// arguments (step 1): users and keys are exclusive, one is required, a
// user argument that looks like a key is a mistake, and duplicates are
// dropped silently.
func revokeTargets(args, keys []string) ([]string, []keyArg, error) {
	switch {
	case len(args) > 0 && len(keys) > 0:
		return nil, nil, errors.New("revoke takes users or --key, not both")
	case len(args) == 0 && len(keys) == 0:
		return nil, nil, errors.New("nothing to revoke: name the users, or pass --key KEY")
	}
	var users []string
	for _, u := range args {
		if looksLikeKey(u) {
			return nil, nil, fmt.Errorf("%s looks like a key — did you mean --key?", u)
		}
		if !slices.Contains(users, u) {
			users = append(users, u)
		}
	}
	var out []keyArg
	for _, k := range keys {
		ka, err := parseKeyArg(roleKey, k)
		if err != nil {
			return nil, nil, err
		}
		if !slices.ContainsFunc(out, func(o keyArg) bool { return o.Fingerprint == ka.Fingerprint }) {
			out = append(out, ka)
		}
	}
	return users, out, nil
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

// pluralWord picks the singular or plural form for n.
func pluralWord(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
