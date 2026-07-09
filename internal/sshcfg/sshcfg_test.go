package sshcfg

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
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
	hosts, warnings, err := load(path, dir)
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

func TestLoadResolution(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		want    []Host
		warning string // "" = expect no warnings
	}{
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
		},
		{
			name:    "Host with no patterns warns",
			config:  "Host\nHost a\n  User u\n",
			want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
			warning: "Host with no patterns",
		},
		{
			name: "orphaned settings under bare Host are dropped",
			// The stray User must not leak into the preceding (worst case:
			// global) block and apply to every host.
			config:  "Host\n  User stray\nHost a\n  HostName h\n",
			want:    []Host{{Alias: "a", HostName: "h"}},
			warning: "Host with no patterns",
		},
		{
			name:    "invalid port warns and is ignored",
			config:  "Host a\n  User u\n  Port notanum\n  Port 99999\n",
			want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
			warning: "invalid port",
		},
		{
			name:    "setting with no value warns",
			config:  "Host a\n  HostName\n  User u\n",
			want:    []Host{{Alias: "a", HostName: "a", User: "u"}},
			warning: "no value",
		},
	}
	for _, tt := range tests {
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
	_, _, err := load(filepath.Join(t.TempDir(), "nope"), t.TempDir())
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
	hosts, warnings, err := load(filepath.Join(dir, "config"), dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return hosts, warnings
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

func TestIncludeInsideHostBlock(t *testing.T) {
	// Included lines inline at position: bare settings join the enclosing
	// block; a Host line in the included file starts a new block.
	dir := writeFiles(t, map[string]string{
		"config": "Host a\n  Include extra\nHost c\n  User w\n",
		"extra":  "  User u\nHost b\n  User v\n",
	})
	hosts, _ := loadDir(t, dir)
	want := []Host{
		{Alias: "a", HostName: "a", User: "u"},
		{Alias: "b", HostName: "b", User: "v"},
		{Alias: "c", HostName: "c", User: "w"},
	}
	if !reflect.DeepEqual(hosts, want) {
		t.Errorf("hosts = %+v, want %+v", hosts, want)
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
	// A self-including file must terminate at the depth cap, not hang.
	dir := writeFiles(t, map[string]string{"config": "Include config\nHost a\n  User u\n"})
	hosts, warnings := loadDir(t, dir)
	if len(hosts) != 1 || hosts[0].Alias != "a" {
		t.Errorf("hosts = %+v, want exactly one 'a'", hosts)
	}
	if !hasWarning(warnings, "depth") {
		t.Errorf("warnings = %v, want a depth-cap warning", warnings)
	}
}
