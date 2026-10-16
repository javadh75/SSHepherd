package keyfile

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// edKey is a deterministic ed25519 key.
func edKey(seed byte) ed25519.PrivateKey {
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	return ed25519.NewKeyFromSeed(raw)
}

// opensshPEM marshals priv as an OpenSSH key, encrypted (aes256-ctr,
// bcrypt, 16 rounds — x/crypto's choice) when pass is non-nil.
func opensshPEM(t testing.TB, priv any, pass []byte) []byte {
	t.Helper()
	var (
		block *pem.Block
		err   error
	)
	if pass == nil {
		block, err = ssh.MarshalPrivateKey(priv, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "test", pass)
	}
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// editOpenSSH rewrites an OpenSSH key's header — the formats x/crypto
// cannot produce (other ciphers, many rounds, several keys, a mismatched
// or hardware public section) are made from a real key this way.
func editOpenSSH(t testing.TB, data []byte, edit func(h *opensshHeader)) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	var h opensshHeader
	if err := ssh.Unmarshal(block.Bytes[len(opensshMagic):], &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	edit(&h)
	block.Bytes = append([]byte(opensshMagic), ssh.Marshal(h)...)
	return pem.EncodeToMemory(block)
}

// withRounds sets the bcrypt rounds of an encrypted OpenSSH key's header.
func withRounds(t testing.TB, data []byte, rounds uint32) []byte {
	t.Helper()
	return editOpenSSH(t, data, func(h *opensshHeader) {
		var o bcryptOpts
		if err := ssh.Unmarshal([]byte(h.KdfOpts), &o); err != nil {
			t.Fatalf("kdf opts: %v", err)
		}
		o.Rounds = rounds
		h.KdfOpts = string(ssh.Marshal(o))
	})
}

// pubBlob marshals a public-key wire blob of an arbitrary type name.
func pubBlob(typ string) []byte {
	return ssh.Marshal(struct {
		Type string
		Key  []byte
	}{typ, make([]byte, 32)})
}

// dssBlob marshals an ssh-dss public-key wire blob.
func dssBlob() []byte {
	one := big.NewInt(1)
	return ssh.Marshal(struct {
		Type       string
		P, Q, G, Y *big.Int
	}{"ssh-dss", one, one, one, one})
}

// ecKey is a fresh P-256 key (legacy PEM fixtures).
func ecKey(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa: %v", err)
	}
	return k
}

// legacyPEM marshals k as SEC1 "EC PRIVATE KEY", encrypted with
// AES-256-CBC (RFC 1423) when pass is non-nil.
func legacyPEM(t testing.TB, k *ecdsa.PrivateKey, pass []byte) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatalf("marshal ec: %v", err)
	}
	if pass == nil {
		return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	//nolint:staticcheck // SA1019: legacy encrypted PEM is exactly the format under test
	block, err := x509.EncryptPEMBlock(rand.Reader, "EC PRIVATE KEY", der, pass, x509.PEMCipherAES256)
	if err != nil {
		t.Fatalf("encrypt pem: %v", err)
	}
	return pem.EncodeToMemory(block)
}

// sharedPass unlocks sharedEncrypted.
const sharedPass = "right"

// encryptedOnce caches one bcrypt-encrypted OpenSSH key. x/crypto always
// marshals with 16 bcrypt rounds — about a second per marshal or decrypt
// under -race — so tests share this one key, and prefer legacy PEM (whose
// KDF is cheap) wherever the container does not matter.
var encryptedOnce struct {
	sync.Once
	data []byte
}

// sharedEncrypted is edKey(2) as an aes256-ctr/bcrypt OpenSSH key
// encrypted with sharedPass.
func sharedEncrypted(t testing.TB) []byte {
	t.Helper()
	encryptedOnce.Do(func() { encryptedOnce.data = opensshPEM(t, edKey(2), []byte(sharedPass)) })
	return bytes.Clone(encryptedOnce.data)
}
