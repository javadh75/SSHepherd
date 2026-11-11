package sshconn

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// KnownHosts is one parsed snapshot of a known_hosts file, loaded once per
// run and shared by the preflight and every connection (the parsed database
// is read-only, so concurrent use is safe). One snapshot means every server
// in a run is judged against the same trust store, even if known_hosts is
// edited mid-run.
type KnownHosts struct {
	Path     string
	callback ssh.HostKeyCallback
	// authorities are the @cert-authority keys, used only to decide whether
	// to offer certificate host-key algorithms (matching stays knownhosts').
	authorities []ssh.PublicKey
	// revoked are the @revoked keys, used only to name why a host
	// certificate was refused (revokedCertPart); the refusal is knownhosts'.
	revoked []ssh.PublicKey
}

// LoadKnownHosts parses path under strict semantics (knownhosts.New) and
// collects its @cert-authority keys.
func LoadKnownHosts(path string) (*KnownHosts, error) {
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", path, err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is the user's own --known-hosts flag
	if err != nil {
		return nil, fmt.Errorf("load known_hosts %s: %w", path, err)
	}
	return &KnownHosts{Path: path, callback: cb,
		authorities: markedKeys(data, "cert-authority"), revoked: markedKeys(data, "revoked")}, nil
}

// markedKeys extracts the keys of the lines carrying @marker
// ("cert-authority" or "revoked"). Lines that do not parse are skipped:
// knownhosts.New has already accepted the file.
func markedKeys(data []byte, marker string) []ssh.PublicKey {
	var keys []ssh.PublicKey
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := bytes.TrimLeft(sc.Bytes(), " \t")
		if !bytes.HasPrefix(line, []byte("@"+marker)) {
			continue
		}
		got, _, key, _, _, err := ssh.ParseKnownHosts(line)
		if err == nil && got == marker {
			keys = append(keys, key)
		}
	}
	return keys
}

// Host-key algorithm preference tables. Plain algorithms are ordered by
// strength; certificate algorithms are offered only to hosts a matching
// @cert-authority line vouches for. DSA is omitted (x/crypto marks it
// insecure and OpenSSH no longer ships it).
var (
	plainHostKeyAlgos = []string{
		ssh.KeyAlgoED25519,
		ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA,
	}
	certHostKeyAlgos = []string{
		ssh.CertAlgoED25519v01,
		ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01,
		ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01, ssh.CertAlgoRSAv01,
	}
)

// algosForKeyType maps a recorded key type to the signature algorithms that
// verify against it: an ssh-rsa key is served as rsa-sha2-512/256 too.
func algosForKeyType(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	}
	if slices.Contains(plainHostKeyAlgos, keyType) {
		return []string{keyType}
	}
	return nil
}

// probeKey is a public key no known_hosts file records: verifying it makes
// knownhosts report every entry matching an address (KeyError.Want).
var probeKey = func() ssh.PublicKey {
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, "sshepherd known_hosts probe key")
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		panic(err) // a valid ed25519 key always converts
	}
	return pub
}()

// probeRemote is a placeholder peer address: knownhosts prefers the
// hostname argument and only needs this to parse.
var probeRemote = &net.TCPAddr{IP: net.IPv4zero}

// noAuthorityPrefix is x/crypto CertChecker's verdict when no authority
// vouches for a certificate's signer at an address.
const noAuthorityPrefix = "ssh: no authorities for hostname"

// HostKeyAlgorithms derives the ClientConfig.HostKeyAlgorithms for addr
// (host:port, exactly as handed to ssh.NewClientConn), the way OpenSSH
// orders them from known_hosts: certificate algorithms first, and only when
// a matching @cert-authority line exists; then the algorithms for the key
// types recorded for this host; then the remaining plain algorithms, so a
// host that lost its recorded type still fails as a diagnosable key-type
// mismatch rather than a bare negotiation error. A host with no entries at
// all gets nil (x/crypto's defaults) so verification can name the presented
// key in its "not in known_hosts" hint.
//
// Without this, x/crypto's default order (certificates first, ed25519 last)
// makes a host serving an sshd HostCertificate fail with "no authorities"
// even though its plain key is pinned, and an ed25519-pinned host that also
// serves ECDSA fail as an unrecorded type.
func (k *KnownHosts) HostKeyAlgorithms(addr string) []string {
	recorded := k.recordedTypes(addr)
	hasCA := k.authorityMatches(addr)
	if len(recorded) == 0 && !hasCA {
		return nil
	}
	var algos []string
	if hasCA {
		algos = append(algos, certHostKeyAlgos...)
	}
	for _, alg := range plainHostKeyAlgos {
		for _, t := range recorded {
			if slices.Contains(algosForKeyType(t), alg) && !slices.Contains(algos, alg) {
				algos = append(algos, alg)
			}
		}
	}
	for _, alg := range plainHostKeyAlgos {
		if !slices.Contains(algos, alg) {
			algos = append(algos, alg)
		}
	}
	return algos
}

// recordedTypes lists the plain key types known_hosts records for addr.
func (k *KnownHosts) recordedTypes(addr string) []string {
	var ke *knownhosts.KeyError
	if !errors.As(k.callback(addr, probeRemote, probeKey), &ke) {
		return nil
	}
	var types []string
	for _, w := range ke.Want {
		if w.Key == nil || k.isAuthority(w.Key) || slices.Contains(types, w.Key.Type()) {
			continue
		}
		types = append(types, w.Key.Type())
	}
	return types
}

func (k *KnownHosts) isAuthority(key ssh.PublicKey) bool {
	for _, ca := range k.authorities {
		if bytes.Equal(ca.Marshal(), key.Marshal()) {
			return true
		}
	}
	return false
}

// revokedCertPart names what of a presented host certificate an @revoked
// line marks: "CA" for its signing key, "key" for the key it certifies, ""
// for neither or for a presented key that is no certificate. x/crypto
// refuses such a certificate with plain text ("certificate serial N
// revoked"), not a RevokedError, and a revoked CA whose @cert-authority
// line is gone fails earlier as "no authorities"; this reads the snapshot
// instead of either text. Keys compare as knownhosts compares them: a
// certificate by the key it certifies.
func (k *KnownHosts) revokedCertPart(presented ssh.PublicKey) string {
	cert, ok := presented.(*ssh.Certificate)
	switch {
	case !ok:
		return ""
	case k.isRevoked(cert.SignatureKey):
		return "CA"
	case k.isRevoked(cert.Key):
		return "key"
	}
	return ""
}

// isRevoked reports whether an @revoked line names key (a plain key: a
// certificate's SignatureKey or Key). An @revoked line holding a
// certificate revokes the key it certifies, as in knownhosts.
func (k *KnownHosts) isRevoked(key ssh.PublicKey) bool {
	want := key.Marshal()
	for _, r := range k.revoked {
		if bytes.Equal(plainKey(r).Marshal(), want) {
			return true
		}
	}
	return false
}

// plainKey is key, or for a certificate the key it certifies.
func plainKey(key ssh.PublicKey) ssh.PublicKey {
	if cert, ok := key.(*ssh.Certificate); ok {
		return cert.Key
	}
	return key
}

// authorityMatches reports whether any @cert-authority line applies to addr.
// It asks knownhosts itself (so host-pattern matching, hashing, and
// negation are exactly the verifier's) with an unsigned probe certificate
// naming each authority as signer: an unmatched authority is refused with
// noAuthorityPrefix; a matched one proceeds to the validity check, which the
// never-valid probe fails with a different error — before any signature
// would be verified.
func (k *KnownHosts) authorityMatches(addr string) bool {
	for _, ca := range k.authorities {
		cert := &ssh.Certificate{
			Key:          probeKey,
			CertType:     ssh.HostCert,
			SignatureKey: ca,
			ValidAfter:   math.MaxUint64,
		}
		err := k.callback(addr, probeRemote, cert)
		if err != nil && !strings.HasPrefix(err.Error(), noAuthorityPrefix) {
			return true
		}
	}
	return false
}
