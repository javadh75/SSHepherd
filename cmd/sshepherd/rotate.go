package main

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
)

// rotateNow is the clock the expiry-time check reads (a test seam).
var rotateNow = time.Now

func newRotateCmd(a *app, stdout io.Writer) *cobra.Command {
	var (
		f       editFlags
		oldFlag []string
		newFlag []string
		keepOld bool
	)
	cmd := &cobra.Command{
		Use:   "rotate USER --old KEY --new KEY",
		Short: "Replace one of a user's keys in the manifest and push the swap to the servers it affects",
		Long: "Replaces USER's --old key with --new in the manifest, in place — the old\n" +
			"line's options (from=, command=, restrict, …) carry over; the comment is\n" +
			"the new key's, else the old line's — and pushes the swap through\n" +
			"apply's pipeline on the servers that grant USER. The old key is dead\n" +
			"fleet-wide in the same run (unless --keep-old). --old is a SHA256:\n" +
			"fingerprint, a public-key line, or a .pub path; --new is a public-key\n" +
			"line or a .pub path. Rotating the key you log in with? Pass the new\n" +
			"private key with --identity, so the lockout guard and the post-write\n" +
			"login probe can use it. Operators need --operator (the flag is kept).\n" +
			"Saves and confirms like revoke.\n\n" + exitCodesWrite,
		Example: "  # Replace a key in place\n" +
			"  sshepherd rotate alice --old ~/.ssh/alice_old.pub --new ~/.ssh/alice_new.pub\n\n" +
			"  # Overlap old and new while clients switch, finish later with revoke --key\n" +
			"  sshepherd rotate deploy --old ~/.ssh/deploy_old.pub --new ~/.ssh/deploy_2027.pub --keep-old\n\n" +
			"  # Headless rotation of the key this machine logs in with\n" +
			"  sshepherd rotate ci --operator --old ~/.ssh/ci_old.pub --new ~/.ssh/ci_new.pub --yes --identity ~/.ssh/ci_old --identity ~/.ssh/ci_new",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("rotate takes exactly one USER (got %d)", len(args))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := f.validate(cmd)
			if err != nil {
				return err
			}
			if len(oldFlag) == 0 || len(newFlag) == 0 {
				return errors.New("rotate needs both --old KEY and --new KEY")
			}
			// Declared repeatable only so a repeat is refused rather than
			// silently resolved to the last value.
			if len(oldFlag) > 1 {
				return fmt.Errorf("rotate takes exactly one --old (got %d)", len(oldFlag))
			}
			if len(newFlag) > 1 {
				return fmt.Errorf("rotate takes exactly one --new (got %d)", len(newFlag))
			}
			oldArg, err := parseKeyArg(roleOld, oldFlag[0])
			if err != nil {
				return err
			}
			newArg, err := parseKeyArg(roleNew, newFlag[0])
			if err != nil {
				return err
			}
			m, mf, err := loadForEdit(a.logger, f.run.cfgPath)
			if err != nil {
				return err
			}
			ep, err := planRotate(mf, args[0], oldArg, newArg, rotateOpts{operator: f.operator, keepOld: keepOld, now: rotateNow()})
			if err != nil {
				return err
			}
			ep.target = m
			return runEdit(cmd, a, stdout, &f, ids, ep)
		},
	}
	f.register(cmd)
	cmd.Flags().StringArrayVar(&oldFlag, "old", nil, "the `KEY` to rotate out: a SHA256: fingerprint, a public-key line, or a .pub file path")
	cmd.Flags().StringArrayVar(&newFlag, "new", nil, "the `KEY` to rotate in: a public-key line or a .pub file path")
	cmd.Flags().BoolVar(&keepOld, "keep-old", false,
		"add the new key alongside the old one instead of replacing it (overlap; the new key keeps the old line's options, expiry-time included); finish later with 'sshepherd revoke --key OLD'")
	return cmd
}

// rotateOpts are planRotate's flags and clock.
type rotateOpts struct {
	operator bool      // --operator
	keepOld  bool      // --keep-old: add the new key after the old one
	now      time.Time // the expiry-time= check's clock
}

// planRotate resolves and applies 'rotate USER --old --new' against the
// as-loaded config: ownership, novelty, operator and expiry checks, then
// the one edit — an in-place replacement, or with --keep-old an insert
// right after the old key (an overlap; the old key stays).
func planRotate(mf *manifest.File, user string, oldArg, newArg keyArg, opts rotateOpts) (editPlan, error) {
	cfg := mf.Config()
	var u *config.User
	for i := range cfg.Users {
		if cfg.Users[i].Name == user {
			u = &cfg.Users[i]
		}
	}
	if u == nil {
		return editPlan{}, fmt.Errorf("unknown user: %s", user)
	}
	owner, ok := cfg.OwnerOf(oldArg.Fingerprint)
	switch {
	case !ok:
		return editPlan{}, fmt.Errorf("--old %s is not in the manifest", keyName(oldArg))
	case owner.Name != user:
		return editPlan{}, fmt.Errorf("--old %s belongs to %s, not %s", keyName(oldArg), owner.Name, user)
	case newArg.Fingerprint == oldArg.Fingerprint:
		return editPlan{}, errors.New("--new is the same key as --old")
	}
	if o, taken := cfg.OwnerOf(newArg.Fingerprint); taken {
		return editPlan{}, fmt.Errorf("--new %s is already in the manifest (owned by %s)", keyName(newArg), o.Name)
	}
	ops, err := operatorGate(cfg, []string{user}, opts.operator)
	if err != nil {
		return editPlan{}, err
	}
	line, expiry, err := rotatedLine(*u, oldArg, newArg, opts.now)
	if err != nil {
		return editPlan{}, err
	}
	ep := editPlan{
		former: cfg,
		summary: apply.EditSummary{Operators: ops, Edits: []apply.Edit{{
			Kind: apply.EditRotate, User: user, Fingerprint: oldArg.Fingerprint,
			NewFingerprint: newArg.Fingerprint, KeepsExpiry: expiry, KeepOld: opts.keepOld,
		}}},
	}
	if opts.keepOld {
		err = mf.AddKeyAfter(user, oldArg.Fingerprint, line)
		ep.stillHas = user + "'s new key would get no"
		ep.saveNote = "an apply from a copy without this edit removes the new key — clients that already switched would be locked out"
		ep.overlap = &overlapFinish{user: user, oldFP: oldArg.Fingerprint, operator: u.Operator}
	} else {
		err = mf.ReplaceKey(user, oldArg.Fingerprint, line)
		ep.formerNote, ep.removesKey, ep.stillHas = "rotated out", true, user+"'s old key still has"
	}
	if err != nil {
		return editPlan{}, fmt.Errorf("edit manifest: %w", err)
	}
	if ep.encoded, ep.edited, err = encodeEdit(mf); err != nil {
		return editPlan{}, err
	}
	return ep, nil
}

// rotatedLine composes the replacement manifest line: the new key with
// the old line's options and the comment rule (the new key's comment, else
// the old line's). A carried-over expiry-time= that has passed at now is
// refused; the option is returned for the header ("" when none).
func rotatedLine(u config.User, oldArg, newArg keyArg, now time.Time) (line, expiry string, err error) {
	oldKey, err := manifestKey(u, oldArg.Fingerprint)
	if err != nil {
		return "", "", err
	}
	expiry = expiryOption(oldKey.Options)
	if expiry != "" {
		passed, err := expiryPassed(expiry, now)
		if err != nil {
			return "", "", fmt.Errorf("--old %s: %w", keyName(oldArg), err)
		}
		if passed {
			return "", "", fmt.Errorf("the old line's %s has passed; the new key would be rejected by sshd — update or remove expiry-time in the manifest first", expiry)
		}
	}
	comment := newArg.Key.Comment
	if comment == "" {
		comment = oldKey.Comment
	}
	if issue := authkeys.RenderTextIssue(comment); issue != "" {
		return "", "", fmt.Errorf("--new %s: the key's comment %s", keyName(newArg), issue)
	}
	line, err = authkeys.RenderLine(authkeys.RenderEntry{
		Key:     authkeys.Key{Raw: newArg.Key.Raw, Options: oldKey.Options, Fingerprint: newArg.Fingerprint},
		Comment: comment,
	})
	if err != nil {
		return "", "", fmt.Errorf("--new %s: %w", keyName(newArg), err)
	}
	return line, expiry, nil
}

// manifestKey parses u's manifest line for fingerprint fp.
func manifestKey(u config.User, fp string) (authkeys.Key, error) {
	for _, line := range u.Keys {
		if k, err := authkeys.ParseLine(line); err == nil && k != nil && k.Fingerprint == fp {
			return *k, nil
		}
	}
	return authkeys.Key{}, fmt.Errorf("bug: %s's key %s not found in the manifest", u.Name, fp)
}
