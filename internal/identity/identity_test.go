package identity

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestExpand(t *testing.T) {
	r := Resolver{Home: "/home/j", LocalUser: "javad"}
	tests := []struct {
		in, want, wantErr string
	}{
		{in: "~", want: "/home/j"},
		{in: "~/.ssh/id_ed25519", want: "/home/j/.ssh/id_ed25519"},
		{in: "%d/.ssh/key", want: "/home/j/.ssh/key"},
		{in: "/keys/%u/id", want: "/keys/javad/id"},
		{in: "/k/100%%", want: "/k/100%"},
		{in: "/abs/plain", want: "/abs/plain"},
		{in: "%h/key", wantErr: "unsupported token %h"},
		{in: "/key%", wantErr: "dangling %"},
		{in: "~x/key", wantErr: "unsupported ~user"},
		{in: "~/%u/key", want: "/home/j/javad/key"},
		{in: "/a/~/b", want: "/a/~/b"},
		{in: "/kéys/%u", want: "/kéys/javad"},
		{in: "/key/%é", wantErr: "unsupported token %é"},
		{in: "", want: ""},
	}
	for _, tt := range tests {
		got, err := r.expand(tt.in)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expand(%q) err = %v, want containing %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("expand(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}

// writePub writes <dir>/<name>.pub and returns the key line. It never writes
// a private key: Resolve must work from .pub files alone.
func writePub(t *testing.T, dir, name string, seed byte, comment string) string {
	t.Helper()
	line := testkeys.Line(t, seed)
	if comment != "" {
		line += " " + comment
	}
	path := filepath.Join(dir, name+".pub")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return line
}

func hasWarning(warnings []string, substr string) bool {
	for _, w := range warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

func TestResolveExplicitIdentity(t *testing.T) {
	home := t.TempDir()
	key := writePub(t, home, ".ssh/work", 1, "javad@laptop")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "web-1", User: "deploy", Identities: []string{"~/.ssh/work"}},
		{Alias: "web-2", User: "deploy", Identities: []string{"~/.ssh/work"}},
	})
	want := []User{{
		Name:    "javad-work",
		Source:  "~/.ssh/work",
		Comment: "javad@laptop",
		Key:     key,
		Servers: []string{"web-1", "web-2"},
	}}
	if !reflect.DeepEqual(users, want) {
		t.Errorf("users = %+v, want %+v", users, want)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestResolveMissingPub(t *testing.T) {
	r := Resolver{Home: t.TempDir(), LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/nope"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	if !hasWarning(warnings, "skipped") || !hasWarning(warnings, `no access derived for host "a"`) {
		t.Errorf("warnings = %v, want a skip note and a no-access note", warnings)
	}
}

func TestResolveInvalidPub(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "bad.pub"), []byte("not a key\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/bad"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	if !hasWarning(warnings, "not a valid public key") {
		t.Errorf("warnings = %v, want an invalid-key note", warnings)
	}
}

func TestResolveMultiLinePub(t *testing.T) {
	home := t.TempDir()
	content := testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2)
	path := filepath.Join(home, ".ssh", "multi.pub")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/multi"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none (User.Key must never contain a newline)", users)
	}
	if !hasWarning(warnings, "more than one line") {
		t.Errorf("warnings = %v, want a more-than-one-line note", warnings)
	}
}

func TestResolveFingerprintDedup(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, ".ssh/a", 1, "")
	writePub(t, home, ".ssh/b", 1, "") // same key material, different file
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "h1", User: "u", Identities: []string{"~/.ssh/a"}},
		{Alias: "h2", User: "u", Identities: []string{"~/.ssh/b"}},
	})
	if len(users) != 1 || users[0].Name != "javad-a" ||
		!reflect.DeepEqual(users[0].Servers, []string{"h1", "h2"}) {
		t.Errorf("users = %+v, want one javad-a granted [h1 h2]", users)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestResolveNameCollision(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, "one/id", 1, "")
	writePub(t, home, "two/id", 2, "")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "h1", User: "u", Identities: []string{"~/one/id"}},
		{Alias: "h2", User: "u", Identities: []string{"~/two/id"}},
	})
	if len(users) != 2 || users[0].Name != "javad-id" || users[1].Name != "javad-id-2" {
		t.Errorf("users = %+v, want names javad-id and javad-id-2", users)
	}
	if !hasWarning(warnings, "javad-id-2") {
		t.Errorf("warnings = %v, want a collision note mentioning javad-id-2", warnings)
	}
}

func TestResolveUnsupportedToken(t *testing.T) {
	r := Resolver{Home: t.TempDir(), LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"%h/key"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	if !hasWarning(warnings, "unsupported token") || !hasWarning(warnings, "no access derived") {
		t.Errorf("warnings = %v, want token + no-access notes", warnings)
	}
}
