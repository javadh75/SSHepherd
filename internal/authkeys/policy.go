package authkeys

import (
	"crypto/rsa"

	"golang.org/x/crypto/ssh"
)

// The StrengthIssue verdicts: Key.Weak values, and the JSON key_issues names.
const (
	WeakDSA        = "dsa"
	WeakRSAUnder2K = "rsa_under_2048"
)

// minRSABits is the smallest RSA modulus the key policy accepts.
const minRSABits = 2048

// keyTypeDSA is ssh.KeyAlgoDSA's value, spelled here because x/crypto marks
// the constant deprecated (staticcheck SA1019).
const keyTypeDSA = "ssh-dss"

// certTypeDSA is ssh.CertAlgoDSAv01's value, spelled for the same reason.
const certTypeDSA = "ssh-dss-cert-v01@openssh.com"

// StrengthIssue names a key too weak to use: WeakDSA, or WeakRSAUnder2K with
// the modulus size; "" otherwise. A certificate's own type never matches,
// so a certificate line is judged by nothing here.
func StrengthIssue(pub ssh.PublicKey) (issue string, bits int) {
	switch pub.Type() {
	case keyTypeDSA:
		return WeakDSA, 0
	case ssh.KeyAlgoRSA:
		cpk, ok := pub.(ssh.CryptoPublicKey)
		if !ok {
			return "", 0
		}
		if k, ok := cpk.CryptoPublicKey().(*rsa.PublicKey); ok && k.N.BitLen() < minRSABits {
			return WeakRSAUnder2K, k.N.BitLen()
		}
	}
	return "", 0
}

// LinesByFingerprint indexes parsed lines by fingerprint, in file order. Diff
// keeps only the first line per fingerprint; sshd reads them all.
func LinesByFingerprint(keys []Key) map[string][]Key {
	m := make(map[string][]Key, len(keys))
	for _, k := range keys {
		m[k.Fingerprint] = append(m[k.Fingerprint], k)
	}
	return m
}
