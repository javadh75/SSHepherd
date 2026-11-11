package authkeys

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// This file reads one authorized_keys line the way sshd does (review F002):
// auth2-pubkeyfile.c's auth_check_authkey_line and sshkey.c's sshkey_read.
// x/crypto's ParseAuthorizedKey reads differently in ways a hostile line can
// use: it refuses a NUL tail and whitespace inside the key field, which sshd
// accepts (so a revoked key could log in unnamed), and it trims Unicode
// spaces and accepts non-zero base64 padding bits, which sshd refuses.

// fieldSeparators are the only bytes sshd splits an authorized_keys line at.
const fieldSeparators = " \t"

// keyFieldSpace are the bytes sshd's base64 decoder (b64_pton) skips inside
// the key field: C isspace, less the field separators.
const keyFieldSpace = "\n\v\f\r"

var (
	errNoKey        = errors.New("no key found")
	errOpenQuote    = errors.New("unterminated quote in the options")
	errNotKeyType   = errors.New("not a key type")
	errBase64       = errors.New("key material is not valid base64")
	errEmptyKeyBlob = errors.New("key material is empty")
)

// sshdLine is one authorized_keys line as sshd reads it.
type sshdLine struct {
	options []string // split at commas outside quotes, empty items dropped
	pub     ssh.PublicKey
	comment string // what follows the key field, untrimmed
}

// cString is s up to its first NUL: sshd reads each line as a C string.
func cString(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}

// readLine reads s (already cut at its first NUL) as sshd does: a key at
// the line's start, else an options field, then a key. The error is the
// attempt whose type token named a key type (the more useful one), else the
// second attempt's.
func readLine(s string) (sshdLine, error) {
	cp := strings.TrimLeft(s, fieldSeparators)
	pub, comment, err := readKey(cp)
	if err == nil {
		return sshdLine{pub: pub, comment: comment}, nil
	}
	end, ok := optionsEnd(cp)
	if !ok {
		return sshdLine{}, firstUseful(err, errOpenQuote)
	}
	pub, comment, err2 := readKey(strings.TrimLeft(cp[end:], fieldSeparators))
	if err2 != nil {
		return sshdLine{}, firstUseful(err, err2)
	}
	return sshdLine{options: splitOptions(cp[:end]), pub: pub, comment: comment}, nil
}

// firstUseful prefers first when it is about a named key type, since the
// second attempt then only read the type token as options.
func firstUseful(first, second error) error {
	if errors.Is(first, errNoKey) || errors.Is(first, errNotKeyType) {
		return second
	}
	return first
}

// readKey reads "TYPE KEYFIELD[ COMMENT]" at the start of s, as sshkey_read
// does: the type token must name a key type that matches the blob, and the
// key field is base64 with whitespace inside skipped.
func readKey(s string) (ssh.PublicKey, string, error) {
	i := strings.IndexAny(s, fieldSeparators)
	if i < 0 {
		return nil, "", errNoKey
	}
	name := s[:i]
	want, known := keyTypeFor(name)
	if !known {
		return nil, "", fmt.Errorf("%w: %q", errNotKeyType, name)
	}
	rest := strings.TrimLeft(s[i:], fieldSeparators)
	if rest == "" {
		return nil, "", errNoKey
	}
	field, comment := rest, ""
	if j := strings.IndexAny(rest, fieldSeparators); j >= 0 {
		field, comment = rest[:j], strings.TrimLeft(rest[j:], fieldSeparators)
	}
	blob, err := decodeKeyField(field)
	if err != nil {
		return nil, "", err
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, "", fmt.Errorf("key material: %w", err)
	}
	if pub.Type() != want {
		return nil, "", fmt.Errorf("key type mismatch: declared %q, key material %q", name, pub.Type())
	}
	return pub, comment, nil
}

// decodeKeyField decodes the key field as b64_pton does: whitespace
// anywhere is skipped, padding is required, and spare bits in the last
// group must be zero (Go's strict mode, which b64_pton matches once the
// whitespace is gone).
func decodeKeyField(field string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if strings.ContainsRune(keyFieldSpace, r) {
			return -1
		}
		return r
	}, field)
	if clean == "" {
		return nil, errEmptyKeyBlob
	}
	blob, err := base64.StdEncoding.Strict().DecodeString(clean)
	if err != nil {
		return nil, errBase64
	}
	return blob, nil
}

// optionsEnd is sshkey_advance_past_options: the options field runs to the
// first space or tab outside double quotes; \" never toggles quoting. ok is
// false when a quote is still open at the end.
func optionsEnd(s string) (end int, ok bool) {
	quoted := false
	i := 0
	for ; i < len(s) && (quoted || !strings.ContainsRune(fieldSeparators, rune(s[i]))); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] == '"':
			i++
		case s[i] == '"':
			quoted = !quoted
		}
	}
	return i, !quoted
}

// splitOptions splits an options field at commas outside double quotes,
// dropping empty items (sshd skips an empty clause between commas).
func splitOptions(field string) []string {
	var out []string
	quoted, start := false, 0
	for i := 0; i < len(field); i++ {
		switch {
		case field[i] == '\\' && i+1 < len(field) && field[i+1] == '"':
			i++
		case field[i] == '"':
			quoted = !quoted
		case field[i] == ',' && !quoted:
			if i > start {
				out = append(out, field[start:i])
			}
			start = i + 1
		}
	}
	if start < len(field) {
		out = append(out, field[start:])
	}
	return out
}

// keyTypeNames maps each type token sshd's sshkey_type_from_name matches
// exactly to the type of the blob it requires: every key and certificate
// type, and the signature-only names (rsa-sha2-*, webauthn), which name the
// RSA or sk-ecdsa key type.
var keyTypeNames = map[string]string{
	ssh.KeyAlgoED25519:                            ssh.KeyAlgoED25519,
	ssh.KeyAlgoSKED25519:                          ssh.KeyAlgoSKED25519,
	ssh.KeyAlgoECDSA256:                           ssh.KeyAlgoECDSA256,
	ssh.KeyAlgoECDSA384:                           ssh.KeyAlgoECDSA384,
	ssh.KeyAlgoECDSA521:                           ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoSKECDSA256:                         ssh.KeyAlgoSKECDSA256,
	keyTypeDSA:                                    keyTypeDSA, // sshd before 10.0 reads DSA lines
	ssh.KeyAlgoRSA:                                ssh.KeyAlgoRSA,
	ssh.KeyAlgoRSASHA256:                          ssh.KeyAlgoRSA,
	ssh.KeyAlgoRSASHA512:                          ssh.KeyAlgoRSA,
	ssh.CertAlgoED25519v01:                        ssh.CertAlgoED25519v01,
	ssh.CertAlgoSKED25519v01:                      ssh.CertAlgoSKED25519v01,
	ssh.CertAlgoECDSA256v01:                       ssh.CertAlgoECDSA256v01,
	ssh.CertAlgoECDSA384v01:                       ssh.CertAlgoECDSA384v01,
	ssh.CertAlgoECDSA521v01:                       ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoSKECDSA256v01:                     ssh.CertAlgoSKECDSA256v01,
	certTypeDSA:                                   certTypeDSA,
	ssh.CertAlgoRSAv01:                            ssh.CertAlgoRSAv01,
	ssh.CertAlgoRSASHA256v01:                      ssh.CertAlgoRSAv01,
	ssh.CertAlgoRSASHA512v01:                      ssh.CertAlgoRSAv01,
	"webauthn-sk-ecdsa-sha2-nistp256@openssh.com": ssh.KeyAlgoSKECDSA256,
}

// keyTypeFor returns the blob type a line's type token requires. A short
// name (ED25519, RSA) is not a type token: OpenSSH 10.5's sshkey_read
// refuses it, though releases long before it matched those in any case.
func keyTypeFor(name string) (string, bool) {
	t, ok := keyTypeNames[name]
	return t, ok
}

// asciiLower lower-cases A-Z only: sshd's name matching is strcasecmp in the
// C locale, where U+212A KELVIN SIGN and U+0130 are not k and i, though Go's
// strings.ToLower says they are.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
