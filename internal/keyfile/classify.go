package keyfile

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// format is a key file's container.
type format int

const (
	formatOpenSSH format = iota + 1 // "OPENSSH PRIVATE KEY" (openssh-key-v1)
	formatPEM                       // legacy PEM: PKCS#1 RSA, SEC1 EC, unencrypted PKCS#8
)

// maxBcryptRounds is x/crypto's cap on the bcrypt KDF's rounds.
const maxBcryptRounds = 2048

// opensshMagic opens every openssh-key-v1 payload.
const opensshMagic = "openssh-key-v1\x00"

// opensshHeader mirrors the openssh-key-v1 layout (PROTOCOL.key) up to the
// encrypted private section, so the container can be judged before any
// passphrase is asked for — x/crypto's API cannot tell these cases apart.
type opensshHeader struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
	Rest         []byte `ssh:"rest"`
}

// bcryptOpts is the bcrypt KDF's option string.
type bcryptOpts struct {
	Salt   []byte
	Rounds uint32
}

// classification is what classify learned without a passphrase.
type classification struct {
	format    format
	encrypted bool
	pub       ssh.PublicKey // OpenSSH's embedded public key; nil for PEM
	rounds    uint32        // bcrypt rounds (OpenSSH, encrypted); 0 otherwise
}

// classify judges a key file's container before any prompt: formats
// x/crypto cannot use (or that sshepherd refuses) are refused with a
// conversion hint, so an operator never types a passphrase for a key that
// was never going to work. Every file-controlled string in an error is
// %q-quoted.
func classify(path string, data []byte) (classification, error) {
	if bytes.HasPrefix(data, []byte("PuTTY-User-Key-File-")) {
		return classification{}, fmt.Errorf("%s is a PuTTY key — convert it with `puttygen %s -O private-openssh -o NEWFILE`", path, path)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return classification{}, refuse(path, "not a private key file (no PEM block found)")
	}
	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		return classifyOpenSSH(path, block.Bytes)
	case "ENCRYPTED PRIVATE KEY":
		return classification{}, refuse(path, "encrypted PKCS#8 keys are not supported")
	case "DSA PRIVATE KEY":
		return classification{}, dsaRefusal(path)
	case "RSA PRIVATE KEY", "EC PRIVATE KEY", "PRIVATE KEY":
		return classifyPEM(path, block)
	default:
		return classification{}, refuse(path, fmt.Sprintf("unsupported key block %q", block.Type))
	}
}

// refuse is the generic refusal, carrying the rewrite hint.
func refuse(path, reason string) error {
	return fmt.Errorf("%s: %s — rewrite it in a supported format with `ssh-keygen -p -f %s`", path, reason, path)
}

func dsaRefusal(path string) error {
	return fmt.Errorf("%s: DSA (ssh-dss) keys are not supported — ssh-dss is disabled by default in OpenSSH; generate a new key with `ssh-keygen -t ed25519`", path)
}

func classifyOpenSSH(path string, payload []byte) (classification, error) {
	var h opensshHeader
	if !bytes.HasPrefix(payload, []byte(opensshMagic)) || ssh.Unmarshal(payload[len(opensshMagic):], &h) != nil {
		return classification{}, refuse(path, "malformed OpenSSH private key")
	}
	cls := classification{format: formatOpenSSH, encrypted: h.CipherName != "none"}
	if err := checkOpenSSHEncryption(path, h, &cls); err != nil {
		return classification{}, err
	}
	if h.NumKeys != 1 {
		return classification{}, refuse(path, fmt.Sprintf("the file holds %d keys; exactly one is supported", h.NumKeys))
	}
	var typed struct {
		Type string
		Rest []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(h.PubKey, &typed) != nil {
		return classification{}, refuse(path, "malformed embedded public key")
	}
	switch {
	case typed.Type == "ssh-dss":
		return classification{}, dsaRefusal(path)
	case strings.HasPrefix(typed.Type, "sk-"):
		return classification{}, fmt.Errorf("%s: %q is a hardware (FIDO) key — hardware keys must be used via ssh-agent", path, typed.Type)
	}
	pub, err := ssh.ParsePublicKey(h.PubKey)
	if err != nil {
		return classification{}, refuse(path, fmt.Sprintf("unsupported embedded public key %q", typed.Type))
	}
	cls.pub = pub
	return cls, nil
}

// checkOpenSSHEncryption validates the cipher/KDF pair x/crypto can
// decrypt: none/none, or aes256-ctr|aes256-cbc with bcrypt at most
// maxBcryptRounds rounds.
func checkOpenSSHEncryption(path string, h opensshHeader, cls *classification) error {
	switch h.CipherName {
	case "none", "aes256-ctr", "aes256-cbc":
	default:
		return refuse(path, fmt.Sprintf("cipher %q is not supported (supported: aes256-ctr, aes256-cbc)", h.CipherName))
	}
	switch h.KdfName {
	case "none":
		if h.CipherName != "none" {
			return refuse(path, "malformed OpenSSH private key (cipher without a KDF)")
		}
		return nil
	case "bcrypt":
	default:
		return refuse(path, fmt.Sprintf("KDF %q is not supported (supported: bcrypt)", h.KdfName))
	}
	if h.CipherName == "none" {
		return refuse(path, "malformed OpenSSH private key (KDF without a cipher)")
	}
	var opts bcryptOpts
	if ssh.Unmarshal([]byte(h.KdfOpts), &opts) != nil {
		return refuse(path, "malformed bcrypt KDF options")
	}
	if opts.Rounds > maxBcryptRounds {
		return fmt.Errorf("%s: bcrypt KDF rounds %d exceed the supported maximum of %d — re-encrypt with fewer rounds: `ssh-keygen -p -a 100 -f %s`", path, opts.Rounds, maxBcryptRounds, path)
	}
	cls.rounds = opts.Rounds
	return nil
}

// pemIVSize maps the legacy PEM ciphers x509 decrypts to their IV size.
var pemIVSize = map[string]int{
	"DES-CBC":      8,
	"DES-EDE3-CBC": 8,
	"AES-128-CBC":  16,
	"AES-192-CBC":  16,
	"AES-256-CBC":  16,
}

// classifyPEM checks a legacy PEM key; an encrypted one must name a cipher
// and IV x509 can use, so a later decryption failure can only mean a wrong
// passphrase.
func classifyPEM(path string, block *pem.Block) (classification, error) {
	cls := classification{format: formatPEM}
	if !strings.Contains(block.Headers["Proc-Type"], "ENCRYPTED") {
		return cls, nil
	}
	if block.Type == "PRIVATE KEY" {
		return classification{}, refuse(path, "encrypted PKCS#8 keys are not supported")
	}
	alg, ivHex, ok := strings.Cut(block.Headers["DEK-Info"], ",")
	size, known := pemIVSize[alg]
	if !ok || !known {
		return classification{}, refuse(path, fmt.Sprintf("PEM encryption %q is not supported", block.Headers["DEK-Info"]))
	}
	if iv, err := hex.DecodeString(ivHex); err != nil || len(iv) != size {
		return classification{}, refuse(path, "malformed PEM encryption header (bad IV)")
	}
	cls.encrypted = true
	return cls, nil
}
