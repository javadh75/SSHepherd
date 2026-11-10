package main

import (
	"fmt"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/config"
)

// conflictRefusal is the save refusal of adopt (both modes) and import
// --merge (D29). former is the manifest as loaded (nil for a new one), saved
// the manifest as it would be written. It is editConflictRefusal, then a
// restriction conflict (spec S7, OP6) refuses only when the save adds one: a
// clash on a (user, server) pair former did not have. A clash already there
// does not stop the save.
func conflictRefusal(former, saved *config.Config) error {
	if err := editConflictRefusal(former, saved); err != nil {
		return err
	}
	if added := addedClashes(former, saved); len(added) > 0 {
		return fmt.Errorf("refusing to write the manifest — it would add %s: %s",
			apply.Plural(len(added), "restriction conflict", "restriction conflicts"), strings.Join(added, "; "))
	}
	return nil
}

// editConflictRefusal is the save refusal of revoke and rotate, and the
// first half of conflictRefusal. A revoked-kind conflict refuses while it
// remains (exit 3, nothing written), so 'sshepherd revoke --key FP' of a
// revoked key still listed is the natural fix. A weak key refuses only when
// the save adds one (OP4): an unrelated revoke saves while another user holds
// a DSA key, and the weak key's own rotate or revoke always saves. A
// restriction conflict never refuses here: an edit never adds a grant, and a
// leaver's revoke must save while a clash holds a server (OP6).
func editConflictRefusal(former, saved *config.Config) error {
	var msgs []string
	for _, c := range saved.Conflicts() {
		if c.Kind != config.ConflictWeakKey && c.Kind != config.ConflictRestriction {
			msgs = append(msgs, c.Message)
		}
	}
	if len(msgs) > 0 {
		return fmt.Errorf("refusing to write the manifest — it would keep %s: %s",
			apply.Plural(len(msgs), "policy conflict", "policy conflicts"), strings.Join(msgs, "; "))
	}
	held := make(map[string]bool)
	if former != nil {
		for _, w := range former.WeakKeys() {
			held[w.Fingerprint] = true
		}
	}
	var added []string
	for _, w := range saved.WeakKeys() {
		if !held[w.Fingerprint] {
			added = append(added, w.Message)
		}
	}
	if len(added) > 0 {
		return fmt.Errorf("refusing to write the manifest — it would add a weak key: %s", strings.Join(added, "; "))
	}
	return nil
}

// addedClashes lists the message of every restriction conflict of saved
// that names a (user, server) pair no restriction conflict of former names.
func addedClashes(former, saved *config.Config) []string {
	had := make(map[[2]string]bool)
	if former != nil {
		for _, c := range former.Conflicts() {
			if c.Kind != config.ConflictRestriction {
				continue
			}
			for _, s := range c.Servers {
				had[[2]string{c.User, s}] = true
			}
		}
	}
	var added []string
	for _, c := range saved.Conflicts() {
		if c.Kind == config.ConflictRestriction && slices.ContainsFunc(c.Servers, func(s string) bool { return !had[[2]string{c.User, s}] }) {
			added = append(added, c.Message)
		}
	}
	return added
}

// formerManifest is the manifest m loaded, for the save rule; nil when m
// holds none (a plain import: the output is a new manifest).
func formerManifest(m manifestTarget) *config.Config {
	cfg, err := config.Parse(m.Loaded)
	if err != nil || len(m.Loaded) == 0 {
		return nil
	}
	return cfg
}
