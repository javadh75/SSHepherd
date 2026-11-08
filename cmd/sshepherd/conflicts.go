package main

import (
	"fmt"
	"strings"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/config"
)

// conflictRefusal is the save refusal of every command that writes the
// manifest: revoke, rotate, adopt (both modes), import --merge (D29). former
// is the manifest as loaded (nil for a new one), saved the manifest as it
// would be written. A revoked-kind conflict refuses while it remains (exit
// 3, nothing written), so 'sshepherd revoke --key FP' of a revoked key still
// listed is the natural fix. A weak key refuses only when the save adds one
// (OP4): an unrelated revoke saves while another user holds a DSA key, and
// the weak key's own rotate or revoke always saves.
func conflictRefusal(former, saved *config.Config) error {
	var msgs []string
	for _, c := range saved.Conflicts() {
		if c.Kind != config.ConflictWeakKey {
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

// formerManifest is the manifest m loaded, for the save rule; nil when m
// holds none (a plain import: the output is a new manifest).
func formerManifest(m manifestTarget) *config.Config {
	cfg, err := config.Parse(m.Loaded)
	if err != nil || len(m.Loaded) == 0 {
		return nil
	}
	return cfg
}
