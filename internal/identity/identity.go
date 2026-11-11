// Package identity resolves the public keys behind ssh_config identities:
// explicit IdentityFile values, plus OpenSSH's default identity files for
// hosts that set none. It reads only .pub files — never private keys — and
// groups hosts by key so `sshepherd import` can emit users: and access:
// entries mirroring exactly which key the config uses where.
//
// Relative IdentityFile paths (no ~, %, or leading /) resolve against the
// working directory, as in OpenSSH. An IdentityFile may name the .pub itself
// (agent-held or hardware keys: 1Password, Secretive, YubiKey), which is
// read directly.
package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/naming"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
)

// Resolver locates public keys on the machine running import.
type Resolver struct {
	Home      string // for ~ / %d expansion and the default-identity scan
	LocalUser string // for %u expansion and generated user names
}

// expand resolves the statically known subset of IdentityFile syntax: a
// leading tilde plus the %d (home), %u (local user) and %% tokens, and —
// when h is non-nil (Resolve, per host) — %n (alias), %h (resolved
// HostName), %r (remote user) and %p (port, default 22). h is nil for
// --operator-key paths, which name keys independent of any host. Any other token
// depends on the live connection and cannot be resolved statically.
func (r Resolver) expand(raw string, h *sshcfg.Host) (string, error) {
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
		v, ok := r.token(raw[i], h)
		if !ok {
			tok, _ := utf8.DecodeRuneInString(raw[i:])
			if h == nil && strings.IndexByte(hostTokens, raw[i]) >= 0 {
				return "", fmt.Errorf("unsupported token %%%c (host-dependent; not available here)", tok)
			}
			return "", fmt.Errorf("unsupported token %%%c", tok)
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

// hostTokens are the IdentityFile tokens that need a resolved host.
const hostTokens = "nhrp"

// token returns the expansion of one %-token, reporting false when it is
// unsupported (or host-dependent with no host).
func (r Resolver) token(c byte, h *sshcfg.Host) (string, bool) {
	switch c {
	case 'd':
		return r.Home, true
	case 'u':
		return r.LocalUser, true
	case '%':
		return "%", true
	}
	if h == nil {
		return "", false
	}
	switch c {
	case 'n':
		return h.Alias, true
	case 'h':
		return h.HostName, true
	case 'r':
		return h.User, true
	case 'p':
		if h.Port == 0 {
			return "22", true
		}
		return strconv.Itoa(h.Port), true
	}
	return "", false
}

// pubPaths maps an expanded IdentityFile value to the .pub to read and the
// key path naming derives from: a value already ending in .pub (the
// agent-held-key convention) is read as is, anything else gains .pub.
func pubPaths(p string) (pubPath, keyPath string) {
	if strings.HasSuffix(p, ".pub") {
		return p, strings.TrimSuffix(p, ".pub")
	}
	return p + ".pub", p
}

// defaultIdentityNames is OpenSSH's default identity list in its try order
// (ssh_config(5), IdentityFile), used when a host sets no IdentityFile.
var defaultIdentityNames = []string{
	"id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_xmss", "id_dsa",
}

// User is one generated manifest user: a single public key and the host
// aliases that use it, in first-appearance order.
type User struct {
	Name     string   // <LocalUser>-<key file basename>, -2/-3/… on collision
	Source   string   // IdentityFile value as written (defaults: ~/.ssh/<name>)
	Default  bool     // found by the default-identity scan, not an explicit IdentityFile
	Operator bool     // marked via --operator-key: fleet-wide grant, no access entry
	Comment  string   // trailing comment of the .pub, "" when none
	Key      string   // the full public key line from the .pub
	Servers  []string // granted aliases, appearance order
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
	if len(h.Identities) == 0 {
		var out []candidate
		for _, name := range defaultIdentityNames {
			p := filepath.Join(res.r.Home, ".ssh", name)
			if _, err := os.Stat(p + ".pub"); err == nil {
				out = append(out, candidate{path: p, source: "~/.ssh/" + name, isDflt: true})
			}
		}
		return out
	}
	var out []candidate
	for _, raw := range h.Identities {
		p, err := res.r.expand(raw, &h)
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
	pubPath, keyPath := pubPaths(c.path)
	data, err := os.ReadFile(pubPath) // #nosec G304 -- path comes from the user's own ssh config
	if err != nil {
		res.failed[c.path] = true
		res.warnf("identity %s: %v, skipped (only .pub files are read)", c.source, err)
		return false
	}
	line := strings.TrimSpace(string(data))
	if strings.ContainsAny(line, "\r\n") {
		res.failed[c.path] = true
		res.warnf("identity %s: %s contains a line break, skipped", c.source, pubPath)
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
	if k.Weak != "" {
		// Importing it would produce a manifest with a policy conflict.
		res.failed[c.path] = true
		shown, _ := pubPaths(c.source) // as written, so a ~ path reads as the user spelled it
		res.warnf("identity %s: %s key not imported", shown, k.Weak)
		return false
	}
	if issue := authkeys.RenderTextIssue(k.Comment); issue != "" {
		// The manifest rejects such an inline comment; skipping here keeps
		// one odd .pub from failing the whole import's self-check.
		res.failed[c.path] = true
		res.warnf("identity %s: %s comment %s, skipped", c.source, pubPath, issue)
		return false
	}
	if issue := authkeys.LineTextIssue(line); issue != "" {
		// sshd reads past a NUL and whitespace inside the key field
		// (ParseLine does too), but the manifest refuses such bytes.
		res.failed[c.path] = true
		res.warnf("identity %s: %s line %s, skipped", c.source, pubPath, issue)
		return false
	}
	i, ok := res.byFingerprint[k.Fingerprint]
	if !ok {
		i = len(res.users)
		res.byFingerprint[k.Fingerprint] = i
		res.users = append(res.users, User{
			Name:    res.name(filepath.Base(keyPath)),
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
	want := res.r.LocalUser + "-" + base
	got, collided := naming.Claim(res.taken, want)
	if collided {
		res.warnf("user name %q already taken by another key, using %q", want, got)
	}
	return got
}

// MarkOperators flags the users owning the given key files as operators,
// appending a new grantless operator user for any key no resolved host uses
// (operator means "every server" regardless of what the config references).
// Paths expand like IdentityFile values and may name the private key or the
// .pub; only the .pub is ever read. Unlike Resolve, failures are errors, not
// warnings — the operator named these keys explicitly. Repeated paths that
// resolve to the same key dedupe silently.
//
// MarkOperators modifies users in place (matched entries gain Operator) and
// returns the possibly-grown slice. A created user whose name collides with
// an existing one is suffixed -2, -3, … silently — the manifest is a
// reviewed draft, and both users remain visible in it.
func (r Resolver) MarkOperators(users []User, paths []string) ([]User, error) {
	byFP := make(map[string]int, len(users))
	taken := make(map[string]bool, len(users))
	for i, u := range users {
		k, err := authkeys.ParseLine(u.Key)
		if err != nil {
			return nil, fmt.Errorf("user %q: invalid key line (bug: Resolve validated it): %w", u.Name, err)
		}
		if k == nil {
			return nil, fmt.Errorf("user %q: invalid key line (bug: Resolve validated it): blank entry", u.Name)
		}
		byFP[k.Fingerprint] = i
		taken[u.Name] = true
	}
	seen := make(map[string]bool, len(paths))
	for _, raw := range paths {
		p, err := r.expand(raw, nil)
		if err != nil {
			return nil, fmt.Errorf("operator key %q: %w", raw, err)
		}
		pubPath, p := pubPaths(p)
		data, err := os.ReadFile(pubPath) // #nosec G304 -- path is the user's own --operator-key flag
		if err != nil {
			return nil, fmt.Errorf("operator key %q: %w (only .pub files are read)", raw, err)
		}
		line := strings.TrimSpace(string(data))
		if strings.ContainsAny(line, "\r\n") {
			return nil, fmt.Errorf("operator key %q: %s contains a line break", raw, pubPath)
		}
		k, err := authkeys.ParseLine(line)
		if err != nil {
			return nil, fmt.Errorf("operator key %q: %s is not a valid public key: %w", raw, pubPath, err)
		}
		if k == nil {
			return nil, fmt.Errorf("operator key %q: %s is not a valid public key", raw, pubPath)
		}
		if k.Weak != "" {
			return nil, fmt.Errorf("operator key %q: %s is a weak key (%s); generate a stronger one", raw, pubPath, k.Weak)
		}
		if issue := authkeys.RenderTextIssue(k.Comment); issue != "" {
			return nil, fmt.Errorf("operator key %q: %s comment %s", raw, pubPath, issue)
		}
		if issue := authkeys.LineTextIssue(line); issue != "" {
			return nil, fmt.Errorf("operator key %q: %s line %s", raw, pubPath, issue)
		}
		if seen[k.Fingerprint] {
			continue
		}
		seen[k.Fingerprint] = true
		if i, ok := byFP[k.Fingerprint]; ok {
			users[i].Operator = true
			continue
		}
		name, _ := naming.Claim(taken, r.LocalUser+"-"+filepath.Base(p))
		users = append(users, User{
			Name:     name,
			Source:   raw,
			Operator: true,
			Comment:  k.Comment,
			Key:      line,
		})
	}
	return users, nil
}
