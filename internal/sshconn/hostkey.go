package sshconn

import (
	"errors"
	"fmt"
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
func hostKeyHint(err error, presented ssh.PublicKey, srv config.Server, knownHostsPath string) error {
	if presented != nil {
		err = fmt.Errorf("presented %s key %s: %w", presented.Type(), ssh.FingerprintSHA256(presented), err)
	}
	var revoked *knownhosts.RevokedError
	if errors.As(err, &revoked) {
		return classifyHint(fleet.ErrorKindHostKeyRevoked, fmt.Sprintf(
			"this key is marked @revoked in %s — do not connect until the host is re-keyed and the new key verified out of band",
			knownHostsPath), err)
	}
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		if strings.Contains(err.Error(), noAuthorityPrefix) {
			return classifyHint(fleet.ErrorKindHostKey, fmt.Sprintf(
				"the host presented a certificate but no @cert-authority line in %s vouches for it here; record the host's plain key or its CA (verified out of band)",
				knownHostsPath), err)
		}
		return classify(fleet.ErrorKindHostKey, err)
	}
	if len(ke.Want) == 0 {
		return classifyHint(fleet.ErrorKindHostKeyUnknown, fmt.Sprintf(
			"host is not in %s; verify the presented fingerprint out of band (on the server console: %s, or the cloud provider's console output), then compare before recording: %s — append only a line whose fingerprint matches",
			knownHostsPath, consoleFingerprintCmd(presented), keyscanCompareCmd(presented, srv)), err)
	}
	if presented != nil && !typeRecorded(ke, presented.Type()) {
		return classifyHint(fleet.ErrorKindHostKeyTypeUnrecorded, fmt.Sprintf(
			"host key type %s is not recorded in known_hosts for this host (recorded: %s) — unverified, not proof of a change; verify the presented fingerprint out of band (%s on the console), compare with: %s — and append only a matching line",
			presented.Type(), strings.Join(recordedTypes(ke), ", "),
			consoleFingerprintCmd(presented), keyscanCompareCmd(presented, srv)), err)
	}
	return classifyHint(fleet.ErrorKindHostKeyChanged, fmt.Sprintf(
		"HOST KEY CHANGED for %s:%d — possible impersonation; investigate and verify the new fingerprint out of band before touching %s",
		srv.Host, srv.Port, knownHostsPath), err)
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
// keys go to ssh-keygen -lf - for display, never into the trust store.
func keyscanCompareCmd(presented ssh.PublicKey, srv config.Server) string {
	typ := ""
	if presented != nil {
		typ = "-t " + keyscanType(presented.Type()) + " " // x/crypto-parsed type: a fixed algorithm name
	}
	return "ssh-keyscan " + typ + "-p " + strconv.Itoa(srv.Port) + " " + ShQuote(srv.Host) + " | ssh-keygen -lf -"
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

// recordedTypes lists the distinct key types known_hosts records for the host.
func recordedTypes(ke *knownhosts.KeyError) []string {
	var types []string
	seen := make(map[string]bool)
	for _, k := range ke.Want {
		if k.Key == nil || seen[k.Key.Type()] {
			continue
		}
		seen[k.Key.Type()] = true
		types = append(types, k.Key.Type())
	}
	return types
}
