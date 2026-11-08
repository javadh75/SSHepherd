package sshcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// parseString writes content to a temp config and loads it with the temp dir
// as the Include base, so include tests can drop sibling files.
func parseString(t *testing.T, content string) ([]Host, []string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	hosts, warnings, err := load(path, dir, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return hosts, warnings
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// resolutionCase is one single-file config fixture. TestLoadResolution pins
// sshcfg's result; TestResolutionMatchesSSHG checks it against `ssh -G`.
type resolutionCase struct {
	name    string
	config  string
	want    []Host
	warning string // "" = expect no warnings
	sshG    string // "" = ssh -G agrees; else why sshcfg differs on purpose
}

// includeCase is one multi-file config fixture ("config" is the top level;
// relative Includes resolve against the fixture dir).
type includeCase struct {
	name    string
	files   map[string]string
	want    []Host
	warning string // "" = expect no warnings
	sshG    string // "" = ssh -G agrees; else why sshcfg differs on purpose
}

var loadResolutionCases = []resolutionCase{
	{
		name:   "basic block",
		config: "Host web-1\n  HostName 10.0.0.1\n  Port 2222\n  User deploy\n",
		want:   []Host{{Alias: "web-1", HostName: "10.0.0.1", Port: 2222, User: "deploy"}},
	},
	{
		name:   "hostname falls back to alias",
		config: "Host bastion\n  User ops\n",
		want:   []Host{{Alias: "bastion", HostName: "bastion", User: "ops"}},
	},
	{
		name:   "Host * supplies defaults",
		config: "Host a\n  HostName 1.2.3.4\nHost *\n  User admin\n  Port 2200\n",
		want:   []Host{{Alias: "a", HostName: "1.2.3.4", Port: 2200, User: "admin"}},
	},
	{
		name:   "first-obtained-wins: specific block seen first",
		config: "Host a\n  User specific\nHost *\n  User general\n",
		want:   []Host{{Alias: "a", HostName: "a", User: "specific"}},
	},
	{
		name: "first-obtained-wins: leading global settings win",
		// OpenSSH semantics: settings before any Host line apply to every
		// host and, being first, beat later per-host values.
		config: "User admin\nHost a\n  User later\n  HostName h\n",
		want:   []Host{{Alias: "a", HostName: "h", User: "admin"}},
	},
	{
		name:   "pattern-only block yields no entry",
		config: "Host web-*\n  User deploy\n",
		want:   nil,
	},
	{
		name: "negated pattern excludes from defaults",
		config: "Host web-1 web-2\n  HostName 10.0.0.1\n" +
			"Host web-* !web-2\n  User deploy\n",
		want: []Host{
			{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
			{Alias: "web-2", HostName: "10.0.0.1"},
		},
	},
	{
		name:    "duplicate alias: first definition wins",
		config:  "Host a\n  User u1\nHost a\n  User u2\n",
		want:    []Host{{Alias: "a", HostName: "a", User: "u1"}},
		warning: "duplicate host",
	},
	{
		name: "Match block skipped until next Host",
		config: "Host a\n  User u\nMatch host a\n  Port 9\n" +
			"Host b\n  User v\n",
		want: []Host{
			{Alias: "a", HostName: "a", User: "u"},
			{Alias: "b", HostName: "b", User: "v"},
		},
		warning: "Match block skipped",
		sshG:    "ssh evaluates Match (a gets Port 9); sshcfg skips Match blocks statically",
	},
	{
		name:    "Host with no patterns warns",
		config:  "Host\nHost a\n  User u\n",
		want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
		warning: "Host with no patterns",
		sshG:    `ssh is fatal on a bare Host ("no argument after keyword"); sshcfg warns and skips it`,
	},
	{
		name: "orphaned settings under bare Host are dropped",
		// The stray User must not leak into the preceding (worst case:
		// global) block and apply to every host.
		config:  "Host\n  User stray\nHost a\n  HostName h\n",
		want:    []Host{{Alias: "a", HostName: "h"}},
		warning: "Host with no patterns",
		sshG:    `ssh is fatal on a bare Host ("no argument after keyword"); sshcfg warns and skips it`,
	},
	{
		name:    "invalid port warns and is ignored",
		config:  "Host a\n  User u\n  Port notanum\n  Port 99999\n",
		want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
		warning: "invalid port",
		sshG:    `ssh is fatal on an invalid Port ("Bad port"); sshcfg warns and ignores it`,
	},
	{
		name:    "setting with no value warns",
		config:  "Host a\n  HostName\n  User u\n",
		want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
		warning: "no value",
		sshG:    `ssh is fatal on a keyword with no value ("no argument after keyword"); sshcfg warns and ignores it`,
	},
	{
		name: "IdentityFile accumulates across matching blocks",
		config: "Host a\n  User u\n  IdentityFile ~/.ssh/first\n" +
			"Host *\n  IdentityFile %d/.ssh/second\n",
		want: []Host{{Alias: "a", HostName: "a", User: "u",
			Identities: []string{"~/.ssh/first", "%d/.ssh/second"}}},
	},
	{
		name:   "IdentityFile repeats dedupe",
		config: "Host a\n  User u\n  IdentityFile k\n  IdentityFile k\n",
		want:   []Host{{Alias: "a", HostName: "a", User: "u", Identities: []string{"k"}}},
	},
	{
		name:   "IdentityFile key=value form",
		config: "Host a\n  User u\n  IdentityFile=~/.ssh/k\n",
		want:   []Host{{Alias: "a", HostName: "a", User: "u", Identities: []string{"~/.ssh/k"}}},
	},
	{
		name: "IdentityFile inside Match block is skipped",
		config: "Host a\n  User u\nMatch host a\n  IdentityFile ~/.ssh/hidden\n" +
			"Host b\n  User v\n  IdentityFile ~/.ssh/k\n",
		want: []Host{
			{Alias: "a", HostName: "a", User: "u"},
			{Alias: "b", HostName: "b", User: "v", Identities: []string{"~/.ssh/k"}},
		},
		warning: "Match block skipped",
	},
	{
		name:   "IdentityFile before first Host orders first",
		config: "IdentityFile ~/.ssh/top\nHost a\n  User u\n  IdentityFile ~/.ssh/mine\n",
		want: []Host{{Alias: "a", HostName: "a", User: "u",
			Identities: []string{"~/.ssh/top", "~/.ssh/mine"}}},
	},
	{
		name:   "trailing comment on a Host line is not a pattern",
		config: "Host web1 web1.example.com # prod box\n  HostName 10.0.0.5\n  User u\n",
		want: []Host{
			{Alias: "web1", HostName: "10.0.0.5", User: "u"},
			{Alias: "web1.example.com", HostName: "10.0.0.5", User: "u"},
		},
	},
	{
		name:   "HostName %h expands to the alias",
		config: "Host db.corp\n  User u\nHost *.corp\n  HostName %h.example.com\n",
		want:   []Host{{Alias: "db.corp", HostName: "db.corp.example.com", User: "u"}},
	},
	{
		name:   "HostName %% is a literal percent",
		config: "Host a\n  User u\n  HostName x%%y-%h\n",
		want:   []Host{{Alias: "a", HostName: "x%y-a", User: "u"}},
	},
	{
		name:    "HostName with an unsupported token skips the host",
		config:  "Host a\n  User u\n  HostName %r.example.com\nHost b\n  User v\n",
		want:    []Host{{Alias: "b", HostName: "b", User: "v"}},
		warning: `host "a": HostName "%r.example.com": unsupported token %r, skipped`,
	},
	{
		name:    "HostName with a dangling percent skips the host",
		config:  "Host a\n  User u\n  HostName h%\n",
		want:    nil,
		warning: "dangling %",
	},
	{
		name: "ProxyJump recorded, first of ProxyJump/ProxyCommand wins",
		config: "Host a\n  User u\n  ProxyJump bastion\n" +
			"Host *\n  ProxyCommand ssh -W %h:%p gw\n",
		want: []Host{{Alias: "a", HostName: "a", User: "u", Proxy: "ProxyJump bastion"}},
	},
	{
		name:   "ProxyCommand keeps its whole command line",
		config: "Host a\n  User u\n  ProxyCommand ssh -W %h:%p gw\n",
		want:   []Host{{Alias: "a", HostName: "a", User: "u", Proxy: "ProxyCommand ssh -W %h:%p gw"}},
	},
	{
		name:   "ProxyJump none disables a later default",
		config: "Host a\n  User u\n  ProxyJump none\nHost *\n  ProxyJump bastion\n",
		want:   []Host{{Alias: "a", HostName: "a", User: "u"}},
	},
	{
		name:    "IdentityFile with no value warns",
		config:  "Host a\n  User u\n  IdentityFile\n",
		want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
		warning: "no value",
		sshG:    `ssh is fatal on a keyword with no value ("no argument after keyword"); sshcfg warns and ignores it`,
	},
}

func TestLoadResolution(t *testing.T) {
	for _, tt := range loadResolutionCases {
		t.Run(tt.name, func(t *testing.T) {
			hosts, warnings := parseString(t, tt.config)
			if !reflect.DeepEqual(hosts, tt.want) {
				t.Errorf("hosts = %+v, want %+v", hosts, tt.want)
			}
			if tt.warning == "" && len(warnings) > 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
			if tt.warning != "" && !hasWarning(warnings, tt.warning) {
				t.Errorf("warnings %v missing %q", warnings, tt.warning)
			}
		})
	}
}

func TestLoadMissingTopLevelFile(t *testing.T) {
	dir := t.TempDir()
	_, _, err := load(filepath.Join(dir, "nope"), dir, dir)
	if err == nil {
		t.Fatal("load of missing file: err = nil, want error")
	}
}

func TestWarningsCarryFileAndLine(t *testing.T) {
	_, warnings := parseString(t, "Host a\n  User u\nMatch all\n")
	if len(warnings) != 1 || !strings.Contains(warnings[0], "config:3:") {
		t.Errorf("warnings = %v, want one prefixed with \"config:3:\"", warnings)
	}
}

// writeFiles lays out a config tree in a temp dir and returns the dir.
func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func loadDir(t *testing.T, dir string) ([]Host, []string) {
	t.Helper()
	hosts, warnings, err := load(filepath.Join(dir, "config"), dir, dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return hosts, warnings
}

func TestIncludeTildeExpandsHome(t *testing.T) {
	// OpenSSH expands a leading ~/ in Include against the home directory,
	// not against ~/.ssh. Point includeDir somewhere else so only tilde
	// expansion can find the included file.
	home := writeFiles(t, map[string]string{
		"config": "Include ~/inc\n",
		"inc":    "Host a\n  User u\n",
	})
	hosts, warnings, err := load(filepath.Join(home, "config"), filepath.Join(home, "ssh"), home)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []Host{{Alias: "a", HostName: "a", User: "u"}}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %+v, want %+v", hosts, want)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestIncludeRelative(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"config": "Include sub\n",
		"sub":    "Host a\n  User u\n",
	})
	hosts, warnings := loadDir(t, dir)
	want := []Host{{Alias: "a", HostName: "a", User: "u"}}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %+v, want %+v", hosts, want)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestIncludeGlobSorted(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"config":      "Include conf.d/*\n",
		"conf.d/10-a": "Host a\n  User u\n",
		"conf.d/20-b": "Host b\n  User v\n",
	})
	hosts, _ := loadDir(t, dir)
	if len(hosts) != 2 || hosts[0].Alias != "a" || hosts[1].Alias != "b" {
		t.Errorf("hosts = %+v, want [a b] in glob order", hosts)
	}
}

// includeContextCases pins OpenSSH's save/restore of the active state
// around Include: lines after an Include belong to the block that was
// current before it, not to whatever block the included file opened last,
// and a Match ending the included file does not swallow them.
// TestResolutionMatchesSSHG checks every case against `ssh -G`.
var includeContextCases = []includeCase{
	{
		// Included lines inline at position: bare settings join the
		// enclosing block. A Host line in a file included from inside Host a
		// only applies to aliases a matches too, so b never matches: b gets
		// no User from this config.
		name: "Include inside a Host block",
		files: map[string]string{
			"config": "Host a\n  Include extra\nHost c\n  User w\n",
			"extra":  "  User u\nHost b\n  User v\n",
		},
		want: []Host{
			{Alias: "a", HostName: "a", User: "u"},
			{Alias: "c", HostName: "c", User: "w"},
		},
		warning: `host "b" is in a file included from a Host block that does not match it`,
	},
	{
		name: "global setting after Include applies to every included host",
		files: map[string]string{
			"config":   "Include d/b.conf\nUser globaluser\n",
			"d/b.conf": "Host acme-db\n  Port 2\nHost acme-web\n  Port 3\n",
		},
		want: []Host{
			{Alias: "acme-db", HostName: "acme-db", Port: 2, User: "globaluser"},
			{Alias: "acme-web", HostName: "acme-web", Port: 3, User: "globaluser"},
		},
	},
	{
		name: "Match at the end of an included file does not drop later lines",
		files: map[string]string{
			"config": "Include inc\nUser globaluser\n",
			"inc":    "Host a\n  Port 2\nMatch all\n  Port 9\n",
		},
		want:    []Host{{Alias: "a", HostName: "a", Port: 2, User: "globaluser"}},
		warning: "Match block skipped",
	},
	{
		name: "setting after Include inside a Host block stays with that block",
		files: map[string]string{
			"config": "Host a\n  Include inc\n  User ua\nHost *\n  User other\n",
			"inc":    "Host a\n  Port 7\n",
		},
		want:    []Host{{Alias: "a", HostName: "a", Port: 7, User: "ua"}},
		warning: "duplicate host", // inc's Host a repeats the alias
	},
	{
		name: "each globbed file starts from the enclosing context",
		files: map[string]string{
			"config":      "Include conf.d/*\nHost b\n  User v\n",
			"conf.d/10-a": "Host a\n  User u\nMatch all\n",
			"conf.d/20-g": "Port 2200\n",
		},
		// 20-g's bare Port is global again, not swallowed by 10-a's Match.
		want: []Host{
			{Alias: "a", HostName: "a", Port: 2200, User: "u"},
			{Alias: "b", HostName: "b", Port: 2200, User: "v"},
		},
		warning: "Match block skipped",
	},
}

func TestIncludeRestoresContext(t *testing.T) {
	for _, tt := range includeContextCases {
		t.Run(tt.name, func(t *testing.T) {
			hosts, warnings := loadDir(t, writeFiles(t, tt.files))
			if !reflect.DeepEqual(hosts, tt.want) {
				t.Errorf("hosts = %+v, want %+v", hosts, tt.want)
			}
			if tt.warning == "" && len(warnings) > 0 {
				t.Errorf("unexpected warnings: %v", warnings)
			}
			if tt.warning != "" && !hasWarning(warnings, tt.warning) {
				t.Errorf("warnings %v missing %q", warnings, tt.warning)
			}
		})
	}
}

func TestIncludeNoMatchWarns(t *testing.T) {
	dir := writeFiles(t, map[string]string{"config": "Include missing-*\nHost a\n  User u\n"})
	hosts, warnings := loadDir(t, dir)
	if len(hosts) != 1 {
		t.Errorf("hosts = %+v, want just a", hosts)
	}
	if !hasWarning(warnings, "matched no files") {
		t.Errorf("warnings = %v, want 'matched no files'", warnings)
	}
}

func TestIncludeDirectoryWarns(t *testing.T) {
	dir := writeFiles(t, map[string]string{"config": "Include conf.d\nHost a\n  User u\n"})
	if err := os.MkdirAll(filepath.Join(dir, "conf.d"), 0o750); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, warnings := loadDir(t, dir)
	if !hasWarning(warnings, "unreadable") {
		t.Errorf("warnings = %v, want 'unreadable' for directory include", warnings)
	}
}

func TestIncludeDepthCapTerminates(t *testing.T) {
	// A self-including file is a cycle: it is skipped, not re-read to the cap.
	dir := writeFiles(t, map[string]string{"config": "Include config\nHost a\n  User u\n"})
	hosts, warnings := loadDir(t, dir)
	if len(hosts) != 1 || hosts[0].Alias != "a" {
		t.Errorf("hosts = %+v, want exactly one 'a'", hosts)
	}
	if !hasWarning(warnings, "Include cycle") {
		t.Errorf("warnings = %v, want an Include cycle warning", warnings)
	}
}

// SEC-4: mutually self-including fragments end fast with a bounded number
// of warnings (today: 2^16 parses and ~196k warnings; with 3 fragments, a hang).
func TestIncludeCycleSkipped(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"config":      "Include " + filepath.Join(dir, "frag", "*.conf") + "\n",
		"frag/a.conf": "Host a\n  User u\n  Include " + filepath.Join(dir, "frag", "*.conf") + "\n",
		"frag/b.conf": "Host b\n  User v\n  Include " + filepath.Join(dir, "frag", "*.conf") + "\n",
	}
	for name, c := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	start := time.Now()
	hosts, warnings := loadDir(t, dir)
	if d := time.Since(start); d > time.Second {
		t.Errorf("load took %v, want < 1s", d)
	}
	if len(hosts) != 2 || hosts[0].Alias != "a" || hosts[1].Alias != "b" {
		t.Errorf("hosts = %+v, want [a b]", hosts)
	}
	if len(warnings) > 8 || !hasWarning(warnings, "Include cycle") {
		t.Errorf("warnings (%d) = %v, want a few 'Include cycle' warnings", len(warnings), warnings)
	}
}

func TestIncludeCycleThroughSymlink(t *testing.T) {
	dir := writeFiles(t, map[string]string{"config": "Include link\nHost a\n  User u\n"})
	if err := os.Symlink(filepath.Join(dir, "config"), filepath.Join(dir, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	_, warnings := loadDir(t, dir)
	if !hasWarning(warnings, "Include cycle") {
		t.Errorf("warnings = %v, want the symlinked self-include seen as a cycle", warnings)
	}
}

func TestIncludeReadBudget(t *testing.T) {
	files := map[string]string{"config": "Include conf.d/*\n"}
	for i := range maxIncludeReads + 10 {
		files[fmt.Sprintf("conf.d/%05d", i)] = fmt.Sprintf("Host h%d\n  User u\n", i)
	}
	hosts, warnings := loadDir(t, writeFiles(t, files))
	if len(hosts) != maxIncludeReads || !hasWarning(warnings, "Include file reads") {
		t.Errorf("hosts = %d, warnings = %v, want %d hosts and one budget warning", len(hosts), warnings, maxIncludeReads)
	}
}

func TestIncludeSizeCap(t *testing.T) {
	big := "Host big\n  User u\n" + strings.Repeat("#", maxIncludeBytes)
	hosts, warnings := loadDir(t, writeFiles(t, map[string]string{"config": "Include big\nHost a\n", "big": big}))
	if len(hosts) != 1 || hosts[0].Alias != "a" || !hasWarning(warnings, "larger than") {
		t.Errorf("hosts = %+v, warnings = %v, want the oversized include skipped", hosts, warnings)
	}
}

// A non-cyclic chain deeper than OpenSSH's cap still stops at the depth cap.
func TestIncludeDepthCapNonCyclic(t *testing.T) {
	files := map[string]string{"config": "Include f0\n"}
	for i := range maxIncludeDepth + 2 {
		files[fmt.Sprintf("f%d", i)] = fmt.Sprintf("Host h%d\nInclude f%d\n", i, i+1)
	}
	_, warnings := loadDir(t, writeFiles(t, files))
	if !hasWarning(warnings, "depth") {
		t.Errorf("warnings = %v, want a depth-cap warning", warnings)
	}
}
