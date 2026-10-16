// Package keyfile loads the private key files named by --identity. Each
// file is opened once and checked on that descriptor (OpenSSH's permission
// rule, bounded reads); the container is classified before any prompt;
// passphrases resolve from a per-key file, then the default file, then the
// controlling terminal; and every key is fingerprinted from its decrypted
// form. Passphrases, passphrase-file contents and key bytes never reach a
// log line or an error message.
package keyfile

import "golang.org/x/crypto/ssh"

// Identity is one loaded --identity key. Path is the cleaned absolute path
// the operator named; Fingerprint is ssh.FingerprintSHA256 of the DECRYPTED
// key's public half (never a label read before decryption).
type Identity struct {
	Path        string
	Fingerprint string
	Signer      ssh.Signer
}
