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
	if got := sshGProxy(g); h.Proxy != got {
		d = append(d, "proxy "+strconv.Quote(h.Proxy)+" vs "+strconv.Quote(got))
	}
	return d
}

// sshGProxy is ssh -G's ProxyJump/ProxyCommand in Host.Proxy's form:
// "ProxyJump X", "ProxyCommand Y", or "" when neither is set (or none).
func sshGProxy(g map[string][]string) string {
	for _, kw := range []string{"ProxyJump", "ProxyCommand"} {
		if v := g[strings.ToLower(kw)]; len(v) > 0 && !strings.EqualFold(v[0], "none") {
			return kw + " " + v[0]
		}
	}
	return ""
}

// fixtureAliases is the set of concrete aliases the fixture's Host lines
// name (no wildcard, not negated, up to a trailing comment): the hosts a
// user would expect import to find. It reads the fixture text, not
// sshcfg's parse, so it can catch sshcfg dropping a host.
func fixtureAliases(files map[string]string) map[string]bool {
	set := map[string]bool{}
	for _, c := range files {
		for line := range strings.Lines(c) {
			f := strings.Fields(line)
			if len(f) == 0 || !strings.EqualFold(f[0], "Host") {
				continue
			}
			for _, pat := range f[1:] {
				if strings.HasPrefix(pat, "#") {
					break
				}
				if !strings.ContainsAny(pat, "*?") && !strings.HasPrefix(pat, "!") {
					set[pat] = true
				}
			}
		}
	}
	return set
}

// skippedOnPurpose records, per fixture, the aliases a Host line names that
// sshcfg deliberately leaves out of its result (with why). Every other
// fixture alias must come back from sshcfg, and a recorded one must stay
// skipped: an entry that no longer applies fails the test, so the record
// cannot rot.
var skippedOnPurpose = map[string]map[string]string{
	"HostName with an unsupported token skips the host": {
		"a": "HostName %r cannot be expanded statically; sshcfg warns and skips the host",
	},
	"HostName with a dangling percent skips the host": {
		"a": "HostName ends in a dangling %; sshcfg warns and skips the host",
	},
	"Include inside a Host block": {
		"b": "Host b sits in a file included from Host a, which never matches b; sshcfg warns and skips it",
	},
}

// diffAliases compares sshcfg's aliases with the fixture's both ways,
// allowing exactly the recorded skips.
func diffAliases(hosts []Host, files map[string]string, skipped map[string]string) []string {
	got := map[string]bool{}
	for _, h := range hosts {
		got[h.Alias] = true
	}
	want := fixtureAliases(files)
	var d []string
	for a := range got {
		if !want[a] {
			d = append(d, "sshcfg returned "+a+", which no Host line names")
		}
	}
	for a := range want {
		_, skip := skipped[a]
		switch {
		case !got[a] && !skip:
			d = append(d, "sshcfg dropped "+a+" (record it in skippedOnPurpose if deliberate)")
		case got[a] && skip:
			d = append(d, "sshcfg now returns "+a+"; drop its skippedOnPurpose entry")
		}
	}
	for a := range skipped {
		if !want[a] {
			d = append(d, "skippedOnPurpose names "+a+", which no Host line names")
		}
	}
	slices.Sort(d)
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
	check := func(t *testing.T, name string, files map[string]string, reason string) {
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
		if d := diffAliases(hosts, files, skippedOnPurpose[name]); len(d) > 0 {
			t.Errorf("alias set: %v", d)
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
	names := map[string]bool{}
	for _, tc := range loadResolutionCases {
		names[tc.name] = true
		t.Run(tc.name, func(t *testing.T) { check(t, tc.name, map[string]string{"config": tc.config}, tc.sshG) })
	}
	for _, tc := range includeContextCases {
		names[tc.name] = true
		t.Run(tc.name, func(t *testing.T) { check(t, tc.name, tc.files, tc.sshG) })
	}
	for name := range skippedOnPurpose {
		if !names[name] {
			t.Errorf("skippedOnPurpose names %q, which is no fixture", name)
		}
	}
}

// TestDiffAliasesBothWays: the alias-set check fails when sshcfg drops a
// named host, returns one no Host line names, or keeps a host recorded as
// skipped — so the differential cannot pass by comparing nothing.
func TestDiffAliasesBothWays(t *testing.T) {
	files := map[string]string{"config": "Host a b # c\nHost web-* !d\n"}
	for _, tt := range []struct {
		name    string
		hosts   []Host
		skipped map[string]string
		want    int
	}{
		{"agree", []Host{{Alias: "a"}, {Alias: "b"}}, nil, 0},
		{"recorded skip", []Host{{Alias: "a"}}, map[string]string{"b": "why"}, 0},
		{"dropped", []Host{{Alias: "a"}}, nil, 1},
		{"none at all", nil, nil, 2},
		{"extra", []Host{{Alias: "a"}, {Alias: "b"}, {Alias: "c"}}, nil, 1},
		{"stale skip", []Host{{Alias: "a"}, {Alias: "b"}}, map[string]string{"b": "why"}, 1},
		{"skip names no host", []Host{{Alias: "a"}, {Alias: "b"}}, map[string]string{"z": "why"}, 1},
	} {
		if d := diffAliases(tt.hosts, files, tt.skipped); len(d) != tt.want {
			t.Errorf("%s: diffAliases = %v, want %d difference(s)", tt.name, d, tt.want)
		}
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
