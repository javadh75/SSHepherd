package sshconn

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
)

// hostKeyHint augments knownhosts verification failures with actionable
// remediation, using the key the server actually presented to tell a
// genuinely changed key apart from a merely unrecorded key type. known_hosts
// entries are keyed by the exact host form used, so hints name the configured
// host:port verbatim. Unrelated errors pass through untouched.
func hostKeyHint(err error, presented ssh.PublicKey, srv config.Server, knownHostsPath string) error {
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		return err
	}
	if presented != nil {
		err = fmt.Errorf("presented %s key %s: %w", presented.Type(), ssh.FingerprintSHA256(presented), err)
	}
	if len(ke.Want) == 0 {
		return fmt.Errorf(
			"%w\n  hint: host is not in %s; if you trust it, run: ssh-keyscan -p %d %s >> %s",
			err, knownHostsPath, srv.Port, srv.Host, knownHostsPath)
	}
	if presented != nil && !typeRecorded(ke, presented.Type()) {
		return fmt.Errorf(
			"%w\n  hint: host key type %s is not recorded in known_hosts for this host (recorded: %s); if the host is healthy, re-run ssh-keyscan to record all key types",
			err, presented.Type(), strings.Join(recordedTypes(ke), ", "))
	}
	return fmt.Errorf("%w\n  hint: HOST KEY CHANGED for %s:%d — investigate before trusting this host",
		err, srv.Host, srv.Port)
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
