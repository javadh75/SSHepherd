// Package identity resolves the public keys behind ssh_config identities:
// explicit IdentityFile values, plus OpenSSH's default identity files for
// hosts that set none. It reads only .pub files — never private keys — and
// groups hosts by key so `sshepherd import` can emit users: and access:
// entries mirroring exactly which key the config uses where.
//
// Relative IdentityFile paths (no ~, %, or leading /) resolve against the
// working directory, as in OpenSSH.
package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
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
	if strings.HasPrefix(raw, "~") { // "~" and "~/" handled above; ~user is not supported
		return "", fmt.Errorf("unsupported ~user syntax")
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
			tok, _ := utf8.DecodeRuneInString(raw[i:])
			return "", fmt.Errorf("unsupported token %%%c", tok)
		}
	}
	return b.String(), nil
}

// User is one generated manifest user: a single public key and the host
// aliases that use it, in first-appearance order.
type User struct {
	Name    string   // <LocalUser>-<key file basename>, -2/-3/… on collision
	Source  string   // IdentityFile value as written (defaults: ~/.ssh/<name>)
	Default bool     // found by the default-identity scan, not an explicit IdentityFile
	Comment string   // trailing comment of the .pub, "" when none
	Key     string   // the full public key line from the .pub
	Servers []string // granted aliases, appearance order
}

// candidate is one identity to try: the expanded private-key path plus the
// value it came from (for warnings and descriptions).
type candidate struct {
	path   string
	source string
	isDflt bool
}

// resolution accumulates users and warnings across hosts.
type resolution struct {
	r             Resolver
	users         []User
	warnings      []string
	byFingerprint map[string]int  // fingerprint -> index into users
	taken         map[string]bool // user names already assigned
	failed        map[string]bool // expanded paths already warned about
}

// Resolve maps hosts to generated users. Callers pass only hosts that became
// server entries, so every returned user is granted at least one server.
// Failures are warnings, never errors: a host whose identities cannot be
// resolved derives no access and keeps its server entry.
func (r Resolver) Resolve(hosts []sshcfg.Host) ([]User, []string) {
	res := &resolution{
		r:             r,
		byFingerprint: map[string]int{},
		taken:         map[string]bool{},
		failed:        map[string]bool{},
	}
	for _, h := range hosts {
		granted := false
		for _, c := range res.candidates(h) {
			if res.grant(c, h.Alias) {
				granted = true
			}
		}
		if !granted {
			res.warnf("no access derived for host %q", h.Alias)
		}
	}
	return res.users, res.warnings
}

func (res *resolution) warnf(format string, args ...any) {
	res.warnings = append(res.warnings, fmt.Sprintf(format, args...))
}

// candidates returns the host's explicit identities, expanded. Unsupported
// tokens warn and skip that path.
func (res *resolution) candidates(h sshcfg.Host) []candidate {
	var out []candidate
	for _, raw := range h.Identities {
		p, err := res.r.expand(raw)
		if err != nil {
			res.warnf("host %q: IdentityFile %q: %v, skipped", h.Alias, raw, err)
			continue
		}
		out = append(out, candidate{path: p, source: raw})
	}
	return out
}

// grant reads the candidate's .pub, creating or reusing its user (keys are
// deduplicated by fingerprint), and grants alias. Returns false when the key
// could not be resolved.
func (res *resolution) grant(c candidate, alias string) bool {
	if res.failed[c.path] {
		return false
	}
	pubPath := c.path + ".pub"
	data, err := os.ReadFile(pubPath) // #nosec G304 -- path comes from the user's own ssh config
	if err != nil {
		res.failed[c.path] = true
		res.warnf("identity %s: %v, skipped (only .pub files are read)", c.source, err)
		return false
	}
	line, extra, _ := strings.Cut(strings.TrimSpace(string(data)), "\n")
	if extra != "" {
		res.failed[c.path] = true
		res.warnf("identity %s: %s has more than one line, skipped", c.source, pubPath)
		return false
	}
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		res.failed[c.path] = true
		if err != nil {
			res.warnf("identity %s: %s is not a valid public key, skipped: %v", c.source, pubPath, err)
		} else {
			res.warnf("identity %s: %s is not a valid public key, skipped", c.source, pubPath)
		}
		return false
	}
	i, ok := res.byFingerprint[k.Fingerprint]
	if !ok {
		i = len(res.users)
		res.byFingerprint[k.Fingerprint] = i
		res.users = append(res.users, User{
			Name:    res.name(filepath.Base(c.path)),
			Source:  c.source,
			Default: c.isDflt,
			Comment: k.Comment,
			Key:     line,
		})
	}
	u := &res.users[i]
	if !slices.Contains(u.Servers, alias) {
		u.Servers = append(u.Servers, alias)
	}
	return true
}

// name assigns <LocalUser>-<base>, appending -2, -3, … when a different key
// already claimed the name.
func (res *resolution) name(base string) string {
	name := res.r.LocalUser + "-" + base
	if !res.taken[name] {
		res.taken[name] = true
		return name
	}
	for n := 2; ; n++ {
		cand := fmt.Sprintf("%s-%d", name, n)
		if !res.taken[cand] {
			res.taken[cand] = true
			res.warnf("user name %q already taken by another key, using %q", name, cand)
			return cand
		}
	}
}
