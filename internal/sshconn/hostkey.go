package sshconn

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
)

// hostKeyHint classifies a known_hosts verification failure and attaches
// actionable remediation as the error's separate Hint (never part of the
// message: reports print it on its own line, JSON as `hint`), using the key the server actually presented
// to tell a genuinely changed key apart from a merely unrecorded key type.
// known_hosts entries are keyed by the exact host form used, so hints name
// the configured host:port verbatim — ShQuote-d wherever they enter a
// suggested command. No hint ever pipes unauthenticated ssh-keyscan output
// straight into known_hosts: that is trust-on-first-use through the back
// door. Every hint asks for out-of-band verification of the presented
// fingerprint first. The result is always an *Error.
//
// A host that once had a key type x/crypto can verify and now presents only
// another type is host_key_type_changed (exit 2), and so is a certificate
// from a signer no matching @cert-authority line vouches for on a CA-vouched
// host: negotiation offers the recorded types and the CA's certificates
// first, so a genuine server reaches either case only by dropping them all.
func hostKeyHint(err error, presented ssh.PublicKey, srv config.Server, route []config.Server, kh *KnownHosts) error {
	if presented != nil {
		err = fmt.Errorf("presented %s key %s: %w", presented.Type(), ssh.FingerprintSHA256(presented), err)
	}
	var revoked *knownhosts.RevokedError
	if errors.As(err, &revoked) {
		return classifyHint(fleet.ErrorKindHostKeyRevoked, fmt.Sprintf(
			"this key is marked @revoked in %s — do not connect until the host is re-keyed and the new key verified out of band",
			kh.Path), err)
	}
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		if strings.Contains(err.Error(), noAuthorityPrefix) {
			if kh.authorityMatches(net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))) {
				return classifyHint(fleet.ErrorKindHostKeyTypeChanged, fmt.Sprintf(
					"HOST KEY TYPE CHANGED for %s:%d — the server presented a certificate no @cert-authority line for this host vouches for; possible impersonation; verify the CA out of band before touching known_hosts",
					srv.Host, srv.Port), err)
			}
			return classifyHint(fleet.ErrorKindHostKey, fmt.Sprintf(
				"the host presented a certificate but no @cert-authority line in %s vouches for it here; record the host's plain key or its CA (verified out of band)",
				kh.Path), err)
		}
		return classify(fleet.ErrorKindHostKey, err)
	}
	if len(ke.Want) == 0 {
		return classifyHint(fleet.ErrorKindHostKeyUnknown, fmt.Sprintf(
			"host is not in %s; verify the presented fingerprint out of band (on the server console: %s, or the cloud provider's console output), then compare before recording: %s — append only a line whose fingerprint matches",
			kh.Path, consoleFingerprintCmd(presented), keyscanCompareCmd(presented, srv, route)), err)
	}
	if presented != nil && !typeRecorded(ke, presented.Type()) {
		if anyVerifiableType(ke) {
			return classifyHint(fleet.ErrorKindHostKeyTypeChanged, fmt.Sprintf(
				"HOST KEY TYPE CHANGED for %s:%d — the server no longer presents any recorded key type (recorded: %s); possible impersonation; verify the presented fingerprint out of band (console: %s; compare with: %s) before touching known_hosts",
				srv.Host, srv.Port, strings.Join(recordedTypes(ke, kh), ", "),
				consoleFingerprintCmd(presented), keyscanCompareCmd(presented, srv, route)), err)
		}
		return classifyHint(fleet.ErrorKindHostKeyTypeUnrecorded, fmt.Sprintf(
			"host key type %s is not recorded in known_hosts for this host (recorded: %s) — unverified, not proof of a change; verify the presented fingerprint out of band (%s on the console), compare with: %s — and append only a matching line",
			presented.Type(), strings.Join(recordedTypes(ke, kh), ", "),
			consoleFingerprintCmd(presented), keyscanCompareCmd(presented, srv, route)), err)
	}
	return classifyHint(fleet.ErrorKindHostKeyChanged, fmt.Sprintf(
		"HOST KEY CHANGED for %s:%d — possible impersonation; investigate and verify the new fingerprint out of band before touching %s",
		srv.Host, srv.Port, kh.Path), err)
}

// anyVerifiableType reports whether known_hosts records, for this host, a
// key type x/crypto can verify (Want holds the host's plain lines and its
// @cert-authority lines). A host recorded only under an unsupported type
// (ssh-dss) stays host_key_type_unrecorded: nothing is known to have changed.
func anyVerifiableType(ke *knownhosts.KeyError) bool {
	for _, k := range ke.Want {
		if k.Key != nil && algosForKeyType(k.Key.Type()) != nil {
			return true
		}
	}
	return false
}

// consoleFingerprintCmd names the on-server command that prints the host
// key fingerprint matching the presented key's type.
func consoleFingerprintCmd(presented ssh.PublicKey) string {
	name := "*"
	if presented != nil {
		if t := keyscanType(presented.Type()); t != presented.Type() {
			name = t
		}
	}
	return "ssh-keygen -lf /etc/ssh/ssh_host_" + name + "_key.pub"
}

// keyscanCompareCmd builds the fingerprint-comparison pipeline: scanned
// keys go to ssh-keygen -lf - for display, never into the trust store. For
// a server behind bastions (route, root first) the scan runs on its own
// bastion, since the operator's machine cannot reach it, and is labelled as
// that bastion's view; outer bastions go in one -J.
func keyscanCompareCmd(presented ssh.PublicKey, srv config.Server, route []config.Server) string {
	typ := ""
	if presented != nil {
		typ = "-t " + keyscanType(presented.Type()) + " " // x/crypto-parsed type: a fixed algorithm name
	}
	if len(route) == 0 {
		return "ssh-keyscan " + typ + "-p " + strconv.Itoa(srv.Port) + " " + ShQuote(srv.Host) + " | ssh-keygen -lf -"
	}
	hop := route[len(route)-1]
	jump := ""
	if outer := route[:len(route)-1]; len(outer) > 0 {
		hops := make([]string, 0, len(outer))
		for _, h := range outer {
			hops = append(hops, h.User+"@"+net.JoinHostPort(h.Host, strconv.Itoa(h.Port)))
		}
		jump = "-J " + localWord(strings.Join(hops, ",")) + " "
	}
	return "ssh " + jump + "-p " + strconv.Itoa(hop.Port) + " " + localWord(hop.User+"@"+hop.Host) +
		" ssh-keyscan " + typ + "-p " + strconv.Itoa(srv.Port) + " " + remoteWord(srv.Host) +
		" | ssh-keygen -lf - (as seen by the bastion; still compare with the console)"
}

// plainWord is what every shell reads as one literal word: no globs, no
// quotes, no expansions.
var plainWord = regexp.MustCompile(`^[A-Za-z0-9._:@,-]+$`)

// localWord is s as one word for the operator's shell.
func localWord(s string) string {
	if plainWord.MatchString(s) {
		return s
	}
	return ShQuote(s)
}

// remoteWord is s as one word for the bastion's shell too: ssh joins its
// arguments into one command line the far side parses again, so a word
// that is not plain is quoted twice.
func remoteWord(s string) string {
	if plainWord.MatchString(s) {
		return s
	}
	return ShQuote(ShQuote(s))
}

// keyscanType maps a key type to ssh-keyscan's -t vocabulary.
func keyscanType(keyType string) string {
	switch {
	case keyType == ssh.KeyAlgoED25519:
		return "ed25519"
	case strings.HasPrefix(keyType, "ecdsa-"):
		return "ecdsa"
	case keyType == ssh.KeyAlgoRSA:
		return "rsa"
	}
	return keyType
}

// typeRecorded reports whether known_hosts already records a key of the
// presented type for this host.
func typeRecorded(ke *knownhosts.KeyError, keyType string) bool {
	for _, k := range ke.Want {
		if k.Key != nil && k.Key.Type() == keyType {
			return true
		}
	}
	return false
}

// recordedTypes lists the distinct key types known_hosts records for the
// host, a CA line's type marked "(CA)".
func recordedTypes(ke *knownhosts.KeyError, kh *KnownHosts) []string {
	var types []string
	seen := make(map[string]bool)
	for _, k := range ke.Want {
		if k.Key == nil {
			continue
		}
		label := k.Key.Type()
		if kh.isAuthority(k.Key) {
			label += " (CA)"
		}
		if !seen[label] {
			seen[label] = true
			types = append(types, label)
		}
	}
	return types
}
