// Package testkeys generates deterministic SSH public keys for tests.
// Public keys are not secret, so fixed seeds are fine and keep tests hermetic.
package testkeys

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Line returns a valid ssh-ed25519 authorized_keys line derived from seed.
// Different seeds yield different keys; the same seed always yields the same key.
func Line(tb testing.TB, seed byte) string {
	tb.Helper()
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(raw).Public())
	if err != nil {
		tb.Fatalf("testkeys: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}
