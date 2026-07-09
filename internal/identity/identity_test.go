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
	if !hasWarning(warnings, "contains a line break") {
		t.Errorf("warnings = %v, want a contains-a-line-break note", warnings)
	}

	crPath := filepath.Join(home, ".ssh", "cr.pub")
	crContent := testkeys.Line(t, 3) + " foo\rbar"
	if err := os.WriteFile(crPath, []byte(crContent+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	users, warnings = r.Resolve([]sshcfg.Host{
		{Alias: "b", User: "u", Identities: []string{"~/.ssh/cr"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none (a bare CR is also a line break)", users)
	}
	if !hasWarning(warnings, "contains a line break") {
		t.Errorf("warnings = %v, want a contains-a-line-break note", warnings)
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

func TestResolveDefaultScan(t *testing.T) {
	home := t.TempDir()
	rsa := writePub(t, home, ".ssh/id_rsa", 3, "")
	ed := writePub(t, home, ".ssh/id_ed25519", 4, "javad@laptop")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{{Alias: "plain", User: "u"}})
	want := []User{
		{Name: "javad-id_rsa", Source: "~/.ssh/id_rsa", Default: true,
			Key: rsa, Servers: []string{"plain"}},
		{Name: "javad-id_ed25519", Source: "~/.ssh/id_ed25519", Default: true,
			Comment: "javad@laptop", Key: ed, Servers: []string{"plain"}},
	}
	if !reflect.DeepEqual(users, want) {
		t.Errorf("users = %+v, want %+v (ssh try order: id_rsa first)", users, want)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestResolveDefaultScanNothingFound(t *testing.T) {
	r := Resolver{Home: t.TempDir(), LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{{Alias: "plain", User: "u"}})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	if !hasWarning(warnings, `no access derived for host "plain"`) {
		t.Errorf("warnings = %v, want a no-access note", warnings)
	}
}

func TestResolveExplicitSuppressesDefaults(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, ".ssh/id_ed25519", 4, "")
	writePub(t, home, ".ssh/work", 5, "")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/work"}},
	})
	if len(users) != 1 || users[0].Name != "javad-work" {
		t.Errorf("users = %+v, want only javad-work (defaults suppressed)", users)
	}
	if len(warnings) > 0 {
		t.Errorf("unexpected warnings: %v", warnings)
	}
}

func TestResolveServersDedupWithinHost(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, ".ssh/a", 1, "")
	writePub(t, home, ".ssh/b", 1, "") // same key, second path
	r := Resolver{Home: home, LocalUser: "javad"}
	users, _ := r.Resolve([]sshcfg.Host{
		{Alias: "h1", User: "u", Identities: []string{"~/.ssh/a", "~/.ssh/b"}},
	})
	if len(users) != 1 || !reflect.DeepEqual(users[0].Servers, []string{"h1"}) {
		t.Errorf("users = %+v, want one user granted [h1] exactly once", users)
	}
}

func TestResolveFailedPathWarnsOnce(t *testing.T) {
	r := Resolver{Home: t.TempDir(), LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "h1", User: "u", Identities: []string{"~/.ssh/nope"}},
		{Alias: "h2", User: "u", Identities: []string{"~/.ssh/nope"}},
	})
	if len(users) != 0 {
		t.Errorf("users = %+v, want none", users)
	}
	skips := 0
	for _, w := range warnings {
		if strings.Contains(w, "only .pub files are read") {
			skips++
		}
	}
	if skips != 1 {
		t.Errorf("warnings = %v, want exactly one skip note for the shared path", warnings)
	}
	if !hasWarning(warnings, `no access derived for host "h1"`) || !hasWarning(warnings, `no access derived for host "h2"`) {
		t.Errorf("warnings = %v, want no-access notes for both hosts", warnings)
	}
}

func TestResolveEmptyPub(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "empty.pub"), []byte("\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/empty"}},
	})
	if len(users) != 0 || !hasWarning(warnings, "not a valid public key") {
		t.Errorf("users = %+v, warnings = %v; want none + invalid-key note", users, warnings)
	}
}

func TestResolveMixedHost(t *testing.T) {
	home := t.TempDir()
	writePub(t, home, ".ssh/good", 1, "")
	r := Resolver{Home: home, LocalUser: "javad"}
	users, warnings := r.Resolve([]sshcfg.Host{
		{Alias: "a", User: "u", Identities: []string{"~/.ssh/missing", "~/.ssh/good"}},
	})
	if len(users) != 1 || !reflect.DeepEqual(users[0].Servers, []string{"a"}) {
		t.Errorf("users = %+v, want one user granted [a]", users)
	}
	if !hasWarning(warnings, "skipped") || hasWarning(warnings, "no access derived") {
		t.Errorf("warnings = %v, want a skip note but NO no-access note", warnings)
	}
}

// FuzzExpand asserts expand never panics and never returns both a value and
// an error, for arbitrary input.
func FuzzExpand(f *testing.F) {
	for _, s := range []string{"~", "~/.ssh/k", "%d/%u", "%%", "%h", "~x", "a%"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		r := Resolver{Home: "/h", LocalUser: "u"}
		got, err := r.expand(in)
		if err != nil && got != "" {
			t.Errorf("expand(%q) returned both %q and error %v", in, got, err)
		}
	})
}
