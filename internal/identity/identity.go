// Package identity resolves the public keys behind ssh_config identities:
// explicit IdentityFile values, plus OpenSSH's default identity files for
// hosts that set none. It reads only .pub files — never private keys — and
// groups hosts by key so `sshepherd import` can emit users: and access:
// entries mirroring exactly which key the config uses where.
package identity

import (
	"fmt"
	"path/filepath"
	"strings"
)

// Resolver locates public keys on the machine running import.
type Resolver struct {
	Home      string // for ~ / %d expansion and the default-identity scan
	LocalUser string // for %u expansion and generated user names
}

// expand resolves the host-independent subset of IdentityFile syntax: a
// leading tilde plus the %d (home), %u (local user) and %% tokens. Any other
// token depends on the connection and cannot be resolved statically.
func (r Resolver) expand(raw string) (string, error) {
	if raw == "~" {
		return r.Home, nil
	}
	if strings.HasPrefix(raw, "~/") {
		raw = filepath.Join(r.Home, raw[2:])
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] != '%' {
			b.WriteByte(raw[i])
			continue
		}
		i++
		if i == len(raw) {
			return "", fmt.Errorf("dangling %% at end of value")
		}
		switch raw[i] {
		case 'd':
			b.WriteString(r.Home)
		case 'u':
			b.WriteString(r.LocalUser)
		case '%':
			b.WriteByte('%')
		default:
			return "", fmt.Errorf("unsupported token %%%c", raw[i])
		}
	}
	return b.String(), nil
}
