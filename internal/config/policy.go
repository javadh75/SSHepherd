package config

import (
	"fmt"
	"slices"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// now is the clock of the passed-expiry warning, a seam so tests pin it.
var now = time.Now

// WeakKey is a manifest key that fails the strength policy
// (authkeys.StrengthIssue), whether or not it is granted anywhere.
type WeakKey struct {
	User        string
	Index       int // 1-based position in the user's keys
	Fingerprint string
	Issue       string // authkeys.WeakDSA or authkeys.WeakRSAUnder2K
	Bits        int
	Servers     []string // every server the key renders on; never nil
	Message     string   // the conflict text (what is wrong, then the way out)
}

// WeakKeys lists every weak key in the manifest, in users order: granted
// ones are also policy conflicts, ungranted ones load warnings. The save
// rule (does this write add a weak key?) reads this, so an ungranted weak
// key cannot slip into a saved manifest unnoticed.
func (c *Config) WeakKeys() []WeakKey { return slices.Clone(c.weak) }

// weakConflicts records every weak key and returns the conflicts of the
// ones rendered somewhere. A weak key on a user with no grants renders
// nowhere, so no human must act now (D28): a load warning, not a conflict.
func (c *Config) weakConflicts() []Conflict {
	var out []Conflict
	c.weak = nil
	for _, u := range c.Users {
		for i, k := range c.keysByUser[u.Name] {
			if k.Weak == "" {
				continue
			}
			w := WeakKey{User: u.Name, Index: i + 1, Fingerprint: k.Fingerprint, Issue: k.Weak, Bits: k.WeakBits,
				Servers: c.serversRendering(u), Message: weakMessage(u.Name, i+1, k)}
			c.weak = append(c.weak, w)
			if len(w.Servers) == 0 {
				c.warn(ManifestWarning{Kind: WarnWeakKeyUngranted, Message: fmt.Sprintf("user %q key %d (%s): %s key, granted on no server", u.Name, i+1, k.Fingerprint, k.Weak)})
				continue
			}
			out = append(out, Conflict{Kind: ConflictWeakKey, User: u.Name, Fingerprint: k.Fingerprint, Servers: w.Servers, Message: w.Message})
		}
	}
	return out
}

func weakMessage(user string, index int, k authkeys.Key) string {
	what := "dsa keys are not allowed"
	if k.Weak == authkeys.WeakRSAUnder2K {
		what = fmt.Sprintf("rsa keys under 2048 bits are not allowed (%d)", k.WeakBits)
	}
	return fmt.Sprintf("user %q key %d (%s): %s: replace it with 'sshepherd rotate' or remove it with 'sshepherd revoke --key'",
		user, index, k.Fingerprint, what)
}

// warnExpired adds one load warning per desired key line, and per access:
// entry, whose expiry-time has passed: sshd no longer accepts that line, but
// the manifest stays valid.
func (c *Config) warnExpired() {
	for _, u := range c.Users {
		for i, k := range c.keysByUser[u.Name] {
			if authkeys.Expired(k.Options, now(), time.Local) {
				opt, _, _ := authkeys.EarliestExpiry(k.Options, time.Local)
				c.warn(ManifestWarning{Kind: WarnKeyExpired, Message: fmt.Sprintf("user %q key %d: %s has passed; sshd no longer accepts this key", u.Name, i+1, opt)})
			}
		}
	}
	for i, a := range c.Access {
		if authkeys.Expired(a.Options, now(), time.Local) {
			opt, _, _ := authkeys.EarliestExpiry(a.Options, time.Local)
			c.warn(ManifestWarning{Kind: WarnKeyExpired, Message: fmt.Sprintf("access[%d]: %s has passed; sshd no longer accepts the keys this entry grants", i, opt)})
		}
	}
}
