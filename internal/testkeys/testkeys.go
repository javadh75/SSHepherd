// Package testkeys generates deterministic SSH public keys for tests.
// Public keys are not secret, so fixed seeds are fine and keep tests hermetic.
package testkeys

import (
	"crypto/ed25519"
	"crypto/rsa"
	"math/big"
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

// RSALine returns a parseable ssh-rsa authorized_keys line with a modulus of
// exactly bits bits, derived from seed. The modulus is not a real RSA
// modulus: enough for parsing, fingerprints and the key-strength policy,
// which is all tests need, and free of crypto/rsa's minimum-size checks.
func RSALine(tb testing.TB, seed byte, bits int) string {
	tb.Helper()
	n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1)) // #nosec G115 -- bits is a small positive test constant
	n.Or(n, big.NewInt(int64(seed)<<1|1))
	pub, err := ssh.NewPublicKey(&rsa.PublicKey{N: n, E: 65537})
	if err != nil {
		tb.Fatalf("testkeys: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// DSALine returns a parseable ssh-dss authorized_keys line derived from
// seed, built from the wire format because crypto/dsa is deprecated. The
// values are not a valid DSA group; x/crypto only checks P's and Q's sizes.
func DSALine(tb testing.TB, seed byte) string {
	tb.Helper()
	blob := ssh.Marshal(struct {
		Name       string
		P, Q, G, Y *big.Int
	}{
		"ssh-dss",
		new(big.Int).Lsh(big.NewInt(1), 1023),
		new(big.Int).Lsh(big.NewInt(1), 159),
		big.NewInt(2),
		big.NewInt(int64(seed) + 3),
	})
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		tb.Fatalf("testkeys: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}
