package main

import (
	"fmt"
	"strings"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/config"
)

// conflictRefusal is the save refusal of every command that writes the
// manifest — revoke, rotate, adopt (both modes), import --merge (D29): nil
// when cfg, the manifest as it would be written, has no policy conflict;
// otherwise one error naming every conflict (exit 3, nothing written). An
// edit that resolves the conflicts passes, so 'sshepherd revoke --key FP'
// of a revoked key still listed is the natural fix.
func conflictRefusal(cfg *config.Config) error {
	cs := cfg.Conflicts()
	if len(cs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(cs))
	for _, c := range cs {
		msgs = append(msgs, c.Message)
	}
	return fmt.Errorf("refusing to write the manifest — it would keep %s: %s",
		apply.Plural(len(cs), "policy conflict", "policy conflicts"), strings.Join(msgs, "; "))
}
