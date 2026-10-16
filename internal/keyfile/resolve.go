package keyfile

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// Resolve validates the three identity flags and builds Load's inputs.
// Path matching is lexical: "~/" expands from home, a relative path is
// joined to cwd, and the result is filepath.Clean-ed — no symlink
// resolution, case sensitive. A --identity-passphrase mapping (split at the
// FIRST "=") attaches to its exact --identity path; duplicate --identity
// paths are then dropped silently. home and cwd are injected
// (os.UserHomeDir, os.Getwd) so the rule is testable.
func Resolve(identities []string, defaultFile string, perKey []string, home, cwd string) ([]Spec, Passphrases, error) {
	var pp Passphrases
	if len(identities) == 0 {
		if defaultFile != "" || len(perKey) > 0 {
			return nil, pp, errors.New("passphrase flags need --identity")
		}
		return nil, pp, nil
	}
	var specs []Spec
	seen := make(map[string]bool, len(identities))
	for _, raw := range identities {
		p, err := cleanPath(raw, home, cwd)
		if err != nil {
			return nil, pp, fmt.Errorf("--identity: %w", err)
		}
		if !seen[p] {
			seen[p] = true
			specs = append(specs, Spec{Path: p})
		}
	}
	if defaultFile != "" {
		p, err := cleanPath(defaultFile, home, cwd)
		if err != nil {
			return nil, pp, fmt.Errorf("--identity-passphrase-file: %w", err)
		}
		pp.Default = p
	}
	for _, kv := range perKey {
		key, file, err := splitMapping(kv, home, cwd)
		if err != nil {
			return nil, pp, err
		}
		if _, dup := pp.PerKey[key]; dup {
			return nil, pp, fmt.Errorf("--identity-passphrase: %s is given twice", key)
		}
		if !seen[key] {
			return nil, pp, fmt.Errorf("--identity-passphrase: %s matches no --identity (--identity paths: %s)", key, joinPaths(specs))
		}
		if pp.PerKey == nil {
			pp.PerKey = make(map[string]string)
		}
		pp.PerKey[key] = file
	}
	return specs, pp, nil
}

// splitMapping splits KEY=FILE at the first "=" and cleans both halves.
func splitMapping(kv, home, cwd string) (key, file string, err error) {
	k, f, ok := strings.Cut(kv, "=")
	if !ok || k == "" || f == "" {
		return "", "", fmt.Errorf("--identity-passphrase %q: want KEY=FILE", kv)
	}
	if key, err = cleanPath(k, home, cwd); err != nil {
		return "", "", fmt.Errorf("--identity-passphrase: %w", err)
	}
	if file, err = cleanPath(f, home, cwd); err != nil {
		return "", "", fmt.Errorf("--identity-passphrase: %w", err)
	}
	return key, file, nil
}

// cleanPath is the lexical rule: ~/ expansion, absolute against cwd, Clean.
func cleanPath(p, home, cwd string) (string, error) {
	if p == "~" || strings.HasPrefix(p, "~/") {
		if home == "" {
			return "", fmt.Errorf("cannot expand %s: home directory unknown", p)
		}
		p = filepath.Join(home, p[1:])
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(cwd, p)
	}
	return filepath.Clean(p), nil
}

func joinPaths(specs []Spec) string {
	paths := make([]string, 0, len(specs))
	for _, s := range specs {
		paths = append(paths, s.Path)
	}
	return strings.Join(paths, ", ")
}
