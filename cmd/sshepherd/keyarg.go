package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// keyRole is which flag a KEY argument came from: it decides the accepted
// forms (--new carries a key, so no fingerprint) and whether options are
// allowed (never on --new: rotate keeps the old line's options).
type keyRole string

const (
	roleKey keyRole = "--key"
	roleOld keyRole = "--old"
	roleNew keyRole = "--new"
)

// keyArg is one classified KEY argument.
type keyArg struct {
	Arg         string        // the argument as given, for messages
	Fingerprint string        // SHA256:…, always set
	Key         *authkeys.Key // the parsed line; nil for a fingerprint argument
}

// maxKeyFile caps a .pub read: a public key file is a line or two.
const maxKeyFile = 64 << 10

var (
	hexColonFP = regexp.MustCompile(`^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2})+$`)
	// keyTypePrefixes are the key types (and type families) that mark a
	// bare argument as a (possibly broken) key line rather than a path:
	// whole type names, so a path like ssh-keys/alice.pub or a user named
	// ssh-admin is not mistaken for a key.
	keyTypePrefixes = []string{"ssh-ed25519", "ssh-ed448", "ssh-rsa", "ssh-dss", "ecdsa-sha2-", "sk-ssh-ed25519", "sk-ecdsa-sha2-"}
	// keyOptionNames mirrors config's authorized_keys option allow-list:
	// an argument starting with one ("restrict,…", "from=…") is a key line.
	keyOptionNames = []string{
		"agent-forwarding", "cert-authority", "command", "environment", "expiry-time", "from",
		"no-agent-forwarding", "no-port-forwarding", "no-pty", "no-touch-required", "no-user-rc",
		"no-x11-forwarding", "permitlisten", "permitopen", "port-forwarding", "principals", "pty",
		"restrict", "tunnel", "user-rc", "verify-required", "x11-forwarding",
	}
)

// parseKeyArg classifies a KEY argument from the real filesystem: ~/
// expands from $HOME (as --identity does) and a path is read with a 64 KiB
// cap.
func parseKeyArg(role keyRole, arg string) (keyArg, error) {
	home, _ := os.UserHomeDir() // "" makes a ~/ path fail with a clear error
	return classifyKeyArg(role, arg, home, readKeyFile)
}

// readKeyFile reads at most maxKeyFile+1 bytes of path, so an oversized
// file is detected without reading it whole.
func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- the operator's own KEY argument
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	return data, nil
}

// classifyKeyArg implements the spec's KEY classification, in order:
// SHA256 fingerprint; pasted `ssh-keygen -lf` output; MD5 (refused); key
// line; path. read is the file seam. Errors name the argument and never
// quote file contents.
func classifyKeyArg(role keyRole, arg, home string, read func(string) ([]byte, error)) (keyArg, error) {
	a := keyArg{Arg: arg}
	switch {
	case strings.HasPrefix(arg, "SHA256:"):
		return fingerprintArg(role, arg, arg)
	case strings.Contains(arg, " SHA256:"):
		for _, f := range strings.Fields(arg) {
			if strings.HasPrefix(f, "SHA256:") {
				return fingerprintArg(role, arg, f)
			}
		}
	case strings.HasPrefix(arg, "MD5:") || hexColonFP.MatchString(arg):
		return a, fmt.Errorf("%s %s: MD5 fingerprints are not supported — use ssh-keygen -l -E sha256 -f FILE", role, arg)
	case looksLikeKeyLine(arg):
		k, err := parseKeyLine(role, arg)
		if err != nil {
			return a, fmt.Errorf("%s: %w", role, err)
		}
		a.Key, a.Fingerprint = k, k.Fingerprint
		return a, nil
	}
	return pathArg(role, arg, home, read)
}

// looksLikeKey reports whether arg classifies as a fingerprint or a key
// line (steps 1–4): a revoke USER argument that does is a usage error.
func looksLikeKey(arg string) bool {
	return strings.HasPrefix(arg, "SHA256:") || strings.Contains(arg, " SHA256:") ||
		strings.HasPrefix(arg, "MD5:") || hexColonFP.MatchString(arg) || looksLikeKeyLine(arg)
}

// looksLikeKeyLine: whitespace, a key-type prefix, or an option prefix.
func looksLikeKeyLine(arg string) bool {
	if strings.ContainsAny(arg, " \t") {
		return true
	}
	for _, p := range keyTypePrefixes {
		if strings.HasPrefix(arg, p) {
			return true
		}
	}
	name := strings.ToLower(arg)
	if i := strings.IndexAny(name, "=,"); i >= 0 {
		name = name[:i]
	}
	for _, o := range keyOptionNames {
		if name == o {
			return true
		}
	}
	return false
}

// fingerprintArg validates a SHA256 fingerprint token: 43 characters of
// unpadded base64 (one trailing "=" is stripped).
func fingerprintArg(role keyRole, arg, token string) (keyArg, error) {
	a := keyArg{Arg: arg}
	if role == roleNew {
		return a, fmt.Errorf("--new %s: a fingerprint carries no key — pass the new public key line or its .pub file", arg)
	}
	b64 := strings.TrimSuffix(strings.TrimPrefix(token, "SHA256:"), "=")
	if raw, err := base64.RawStdEncoding.DecodeString(b64); err != nil || len(b64) != 43 || len(raw) != 32 {
		return a, fmt.Errorf("%s %s: malformed fingerprint (want SHA256: followed by 43 base64 characters)", role, arg)
	}
	a.Fingerprint = "SHA256:" + b64
	return a, nil
}

// parseKeyLine parses a key-line argument (typed by the operator, so the
// parse error may be shown).
func parseKeyLine(role keyRole, line string) (*authkeys.Key, error) {
	if isCertLine(line) {
		return nil, certError(line)
	}
	k, err := authkeys.ParseLine(line)
	if err != nil {
		return nil, fmt.Errorf("not a valid public key line: %w; quote the whole line", err)
	}
	if k == nil {
		return nil, errors.New("not a valid public key line: blank or a comment; quote the whole line")
	}
	if isCertType(k.Type) {
		return nil, certError(line)
	}
	if role == roleNew && len(k.Options) > 0 {
		return nil, errors.New("rotate keeps the old line's options; edit them in the manifest")
	}
	return k, nil
}

// pathArg reads a .pub file: exactly one key line (blank and # lines
// ignored). Messages never quote the file's contents.
func pathArg(role keyRole, arg, home string, read func(string) ([]byte, error)) (keyArg, error) {
	a := keyArg{Arg: arg}
	path := arg
	if strings.HasPrefix(path, "~/") {
		if home == "" {
			return a, fmt.Errorf("%s %s: cannot expand ~/ (no home directory)", role, arg)
		}
		path = filepath.Join(home, path[2:])
	}
	data, err := read(path)
	if err != nil {
		forms := "a SHA256: fingerprint, a public-key line, or a .pub file path"
		if role == roleNew {
			forms = "a public-key line or a .pub file path"
		}
		return a, fmt.Errorf("%s %s: %w — pass %s", role, arg, err, forms)
	}
	return keyFileArg(role, arg, data)
}

// keyFileArg checks a .pub file's contents: at most 64 KiB, not a private
// key, exactly one plain public-key line, no options for --new. Messages
// name the argument and never quote the contents.
func keyFileArg(role keyRole, arg string, data []byte) (keyArg, error) {
	a := keyArg{Arg: arg}
	if len(data) > maxKeyFile {
		return a, fmt.Errorf("%s %s: larger than 64 KiB — not a public key file", role, arg)
	}
	if isPrivateKey(data) {
		return a, fmt.Errorf("%s %s is a private key — pass the public key (%s.pub)", role, arg, arg)
	}
	var lines []string
	for _, l := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(l); t != "" && !strings.HasPrefix(t, "#") {
			lines = append(lines, t)
		}
	}
	if len(lines) != 1 {
		return a, fmt.Errorf("%s %s: holds %d key lines — want exactly one", role, arg, len(lines))
	}
	if isCertLine(lines[0]) {
		return a, fmt.Errorf("%s %s is an SSH certificate, not a public key — pass the plain key (id_ed25519.pub, not id_ed25519-cert.pub)", role, arg)
	}
	k, err := authkeys.ParseLine(lines[0])
	if err != nil || k == nil {
		return a, fmt.Errorf("%s %s: does not hold a valid public key line", role, arg)
	}
	if isCertType(k.Type) {
		return a, fmt.Errorf("%s %s is an SSH certificate, not a public key — pass the plain key (id_ed25519.pub, not id_ed25519-cert.pub)", role, arg)
	}
	if role == roleNew && len(k.Options) > 0 {
		return a, fmt.Errorf("%s %s: rotate keeps the old line's options; edit them in the manifest", role, arg)
	}
	a.Key, a.Fingerprint = k, k.Fingerprint
	return a, nil
}

// isPrivateKey: the first non-blank line opens a PEM/OpenSSH or PuTTY
// private key, or the file mentions PRIVATE KEY anywhere.
func isPrivateKey(data []byte) bool {
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		return true
	}
	for _, l := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(l)
		if t == "" {
			continue
		}
		return strings.HasPrefix(t, "-----BEGIN") || strings.HasPrefix(t, "PuTTY-User-Key-File")
	}
	return false
}

// isCertLine reports whether any of a line's first two fields is a
// certificate key type (the second covers a line with options).
func isCertLine(line string) bool {
	f := strings.Fields(line)
	for i := 0; i < len(f) && i < 2; i++ {
		if isCertType(f[i]) {
			return true
		}
	}
	return false
}

func isCertType(t string) bool { return strings.HasSuffix(t, "-cert-v01@openssh.com") }

func certError(arg string) error {
	return fmt.Errorf("%s is an SSH certificate, not a public key — pass the plain key (id_ed25519.pub, not id_ed25519-cert.pub)", arg)
}

// expiryOption returns the expiry-time= option of a key line's options,
// verbatim ("" when none).
func expiryOption(options []string) string {
	for _, o := range options {
		if strings.HasPrefix(strings.ToLower(o), "expiry-time=") {
			return o
		}
	}
	return ""
}

// expiryPassed reports whether an expiry-time="…" option (sshd's
// YYYYMMDD[HHMM[SS]] format, local time unless suffixed Z for UTC) is at
// or before now.
func expiryPassed(option string, now time.Time) (bool, error) {
	_, v, _ := strings.Cut(option, "=")
	v = strings.Trim(v, `"`)
	loc := time.Local
	if strings.HasSuffix(v, "Z") || strings.HasSuffix(v, "z") {
		v, loc = v[:len(v)-1], time.UTC
	}
	layouts := map[int]string{8: "20060102", 12: "200601021504", 14: "20060102150405"}
	layout, ok := layouts[len(v)]
	if !ok {
		return false, fmt.Errorf("cannot read %s (want YYYYMMDD[HHMM[SS]][Z])", option)
	}
	t, err := time.ParseInLocation(layout, v, loc)
	if err != nil {
		return false, fmt.Errorf("cannot read %s (want YYYYMMDD[HHMM[SS]][Z])", option)
	}
	return !t.After(now), nil
}
