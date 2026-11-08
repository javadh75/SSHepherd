package sshcfg

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// sshG returns `ssh -G -F cfg alias` as key -> values (identityfile repeats).
// -F makes ssh skip /etc/ssh/ssh_config, so only the fixture is read.
func sshG(t *testing.T, bin, cfg, alias string) (map[string][]string, error) {
	t.Helper()
	out, err := exec.CommandContext(t.Context(), bin, "-G", "-F", cfg, alias).Output() // #nosec G204 -- test-only: fixed ssh binary, fixture args
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, err //nolint:wrapcheck // test helper
	}
	m := map[string][]string{}
	for _, l := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(l, " "); ok {
			m[k] = append(m[k], v)
		}
	}
	return m, nil
}

// diffHost lists where sshcfg's resolution of h disagrees with ssh -G.
func diffHost(h Host, g map[string][]string, me *user.User) []string {
	var d []string
	first := func(k string) string {
		if v := g[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if !strings.EqualFold(h.HostName, first("hostname")) {
		d = append(d, "hostname "+h.HostName+" vs "+first("hostname"))
	}
	wantUser := h.User
	if wantUser == "" {
		wantUser = me.Username
	}
	if wantUser != first("user") {
		d = append(d, "user "+wantUser+" vs "+first("user"))
	}
	wantPort := h.Port
	if wantPort == 0 {
		wantPort = 22
	}
	if strconv.Itoa(wantPort) != first("port") {
		d = append(d, "port "+strconv.Itoa(wantPort)+" vs "+first("port"))
	}
	// Only literal identities: tokens are import's job (identity package),
	// and with none set ssh lists its defaults.
	if len(h.Identities) > 0 && !slices.ContainsFunc(h.Identities, func(s string) bool { return strings.Contains(s, "%") }) {
		norm := func(s string) string { // ssh may print ~ expanded with pw_dir
			if rest, ok := strings.CutPrefix(s, me.HomeDir+"/"); ok {
				return "~/" + rest
			}
			return s
		}
		var a, b []string
		for _, s := range h.Identities {
			a = append(a, norm(s))
		}
		for _, s := range g["identityfile"] {
			b = append(b, norm(s))
		}
		if !slices.Equal(a, b) {
			d = append(d, "identityfile "+strings.Join(a, ",")+" vs "+strings.Join(b, ","))
		}
	}
	return d
}

var includeArg = regexp.MustCompile(`(?m)^(\s*Include\s+)([^\s~/]\S*)`)

// absolutize rewrites relative Include args against dir: under -F, ssh
// resolves them against ~/.ssh, while the fixtures assume dir.
func absolutize(dir, content string) string {
	return includeArg.ReplaceAllString(content, "${1}"+dir+"/${2}")
}

func TestResolutionMatchesSSHG(t *testing.T) {
	bin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not installed")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user:", err)
	}
	check := func(t *testing.T, files map[string]string, reason string) {
		t.Helper()
		if reason != "" {
			t.Skip("known deviation: " + reason)
		}
		dir := t.TempDir()
		for name, c := range files {
			p := filepath.Join(dir, name)
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(absolutize(dir, c)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		cfg := filepath.Join(dir, "config")
		hosts, _, err := load(cfg, dir, dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, h := range hosts {
			g, err := sshG(t, bin, cfg, h.Alias)
			if err != nil {
				t.Fatalf("ssh -G %s: %v (set sshG on the fixture if this is a documented deviation)", h.Alias, err)
			}
			if d := diffHost(h, g, me); len(d) > 0 {
				t.Errorf("%s: sshcfg vs ssh -G: %v", h.Alias, d)
			}
		}
	}
	for _, tc := range loadResolutionCases {
		t.Run(tc.name, func(t *testing.T) { check(t, map[string]string{"config": tc.config}, tc.sshG) })
	}
	for _, tc := range includeContextCases {
		t.Run(tc.name, func(t *testing.T) { check(t, tc.files, tc.sshG) })
	}
}

// The oracle must actually catch a difference: sshcfg skips Match, ssh
// evaluates it, so a Match-only User diverges.
func TestSSHGOracleDetectsDivergence(t *testing.T) {
	bin, err := exec.LookPath("ssh")
	if err != nil {
		t.Skip("ssh not installed")
	}
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user:", err)
	}
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	if err := os.WriteFile(cfg, []byte("Match all\n  User zz-match\nHost a\n  HostName 10.0.0.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hosts, _, err := load(cfg, dir, dir)
	if err != nil || len(hosts) != 1 {
		t.Fatalf("load = %+v, %v; want one host", hosts, err)
	}
	g, err := sshG(t, bin, cfg, "a")
	if err != nil {
		t.Fatal(err)
	}
	if len(diffHost(hosts[0], g, me)) == 0 {
		t.Error("diffHost found no difference on a Match-only User; the oracle is blind")
	}
}
