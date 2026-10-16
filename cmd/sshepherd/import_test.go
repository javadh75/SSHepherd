package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestGenerateManifestGolden(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web-1", HostName: "10.0.0.1", Port: 2222, User: "deploy"},
		{Alias: "web-2", HostName: "10.0.0.2", Port: 22, User: "deploy"}, // port 22 omitted
		{Alias: "bastion", HostName: "bastion", User: "ops"},             // port 0 omitted
		{Alias: "nouser", HostName: "10.0.0.9"},                          // skipped
	}
	got, skipped, err := generateManifest(hosts, nil, "~/.ssh/config")
	if err != nil {
		t.Fatalf("generateManifest: %v", err)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "nouser") {
		t.Errorf("skipped = %v, want one note about nouser", skipped)
	}
	if _, err := config.Parse(got); err != nil {
		t.Errorf("generated manifest rejected by config.Parse: %v", err)
	}
	checkGolden(t, "import_manifest.golden", got)
}

func TestGenerateManifestUsersGolden(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
		{Alias: "ci", HostName: "ci.internal", Port: 2222, User: "git"},
	}
	users := []identity.User{
		{Name: "javad-id_ed25519", Source: "~/.ssh/id_ed25519", Default: true,
			Comment: "javad@laptop", Key: testkeys.Line(t, 1) + " javad@laptop",
			Servers: []string{"web-1"}},
		{Name: "javad-work", Source: "~/.ssh/work",
			Key: testkeys.Line(t, 2), Servers: []string{"web-1", "ci"}},
	}
	got, notes, err := generateManifest(hosts, users, "~/.ssh/config")
	if err != nil {
		t.Fatalf("generateManifest: %v", err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "wildcard") {
		t.Errorf("notes = %v, want one wildcard-compaction note for javad-work", notes)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	if n := len(c.DesiredFor("web-1")); n != 2 {
		t.Errorf("DesiredFor(web-1) = %d keys, want 2", n)
	}
	checkGolden(t, "import_manifest_users.golden", got)
}

func TestGenerateManifestOperatorGolden(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"},
		{Alias: "ci", HostName: "ci.internal", User: "git"},
	}
	users := []identity.User{
		// Matched operator (also a default identity): keeps its description
		// suffix, gains operator: true, loses its access entry.
		{Name: "javad-id_ed25519", Source: "~/.ssh/id_ed25519", Default: true, Operator: true,
			Key: testkeys.Line(t, 1), Servers: []string{"web-1", "ci"}},
		// Created by --operator: grantless, gets the (--operator) description.
		{Name: "javad-spare", Source: "~/.ssh/spare", Operator: true,
			Key: testkeys.Line(t, 2)},
		// Plain user, partial coverage: explicit list, no compaction.
		{Name: "javad-work", Source: "~/.ssh/work",
			Key: testkeys.Line(t, 3), Servers: []string{"web-1"}},
	}
	got, notes, err := generateManifest(hosts, users, "~/.ssh/config")
	if err != nil {
		t.Fatalf("generateManifest: %v", err)
	}
	if len(notes) != 0 {
		t.Errorf("notes = %v, want none (operators never compact; javad-work doesn't cover the fleet)", notes)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	if n := len(c.DesiredFor("ci")); n != 2 {
		t.Errorf("DesiredFor(ci) = %d keys, want 2 (both operators, no access entries)", n)
	}
	if strings.Contains(string(got), "user: javad-id_ed25519") {
		t.Errorf("operator must not get an access entry:\n%s", got)
	}
	if !strings.Contains(string(got), "(--operator)") {
		t.Errorf("created operator lacks the (--operator) description:\n%s", got)
	}
	checkGolden(t, "import_manifest_operators.golden", got)
}

func TestGenerateManifestNoCompactionSingleServer(t *testing.T) {
	hosts := []sshcfg.Host{{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"}}
	users := []identity.User{{Name: "javad-work", Source: "~/.ssh/work",
		Key: testkeys.Line(t, 1), Servers: []string{"web-1"}}}
	got, notes, err := generateManifest(hosts, users, "x")
	if err != nil || len(notes) != 0 {
		t.Fatalf("notes %v, err %v — a single-server fleet says nothing about \"everywhere\"", notes, err)
	}
	if strings.Contains(string(got), `"*"`) {
		t.Errorf("single-server fleet compacted to wildcard:\n%s", got)
	}
}

func TestGenerateManifestEmpty(t *testing.T) {
	got, skipped, err := generateManifest(nil, nil, "x")
	if err != nil || len(skipped) != 0 {
		t.Fatalf("generateManifest(nil) = skipped %v, err %v", skipped, err)
	}
	if _, err := config.Parse(got); err != nil {
		t.Errorf("empty manifest rejected by config.Parse: %v", err)
	}
	if !strings.Contains(string(got), "servers: []") {
		t.Errorf("output %q missing explicit empty servers list", got)
	}
}

func writeSSHConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write ssh config: %v", err)
	}
	return path
}

func TestImportMissingSource(t *testing.T) {
	hermeticHome(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", "/no/such/ssh_config"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
}

// hermeticHome points HOME at a temp dir so import's default-identity scan
// never sees the developer's real ~/.ssh.
func hermeticHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	return home
}

func TestImportBasic(t *testing.T) {
	home := hermeticHome(t)
	key := testkeys.Line(t, 9)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519.pub"), []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	path := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "-q"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if _, err := config.Parse(out.Bytes()); err != nil {
		t.Errorf("stdout is not a valid manifest: %v", err)
	}
	if !strings.Contains(out.String(), "name: web-1") {
		t.Errorf("stdout = %q, want server web-1", out.String())
	}
	if !strings.Contains(out.String(), "(default identity)") {
		t.Errorf("stdout = %q, want a default-identity user", out.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty for a clean import", errBuf.String())
	}
}

func TestImportWarningsGoToStderrOnly(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host nouser\n  HostName 10.0.0.9\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (zero importable servers is still success)", code)
	}
	if !strings.Contains(out.String(), "servers: []") {
		t.Errorf("stdout = %q, want empty servers list", out.String())
	}
	if !strings.Contains(errBuf.String(), "nouser") {
		t.Errorf("stderr = %q, want a skip warning naming nouser", errBuf.String())
	}
	// Completeness-affecting skips are also embedded in the manifest itself,
	// so a quiet import still documents what it dropped (adopt's precedent).
	if !strings.Contains(out.String(), `# WARNING: host "nouser" skipped`) {
		t.Errorf("stdout = %q, want a skipped-host header warning", out.String())
	}
	if strings.Contains(out.String(), "warn:") {
		t.Errorf("stdout = %q, must not carry stderr log lines", out.String())
	}
}

// TestImportQuietKeepsHeaderWarning: -q silences the stderr warn, but the
// manifest still carries the skipped-host caveat in its header — the product
// self-documents regardless of verbosity.
func TestImportQuietKeepsHeaderWarning(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host nouser\n  HostName 10.0.0.9\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "-q"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty under -q", errBuf.String())
	}
	if !strings.Contains(out.String(), `# WARNING: host "nouser" skipped`) {
		t.Errorf("stdout = %q, want the skipped-host header warning to survive -q", out.String())
	}
}

func TestImportOutputFile(t *testing.T) {
	hermeticHome(t)
	src := writeSSHConfig(t, "Host a\n  User u\n")
	dst := filepath.Join(t.TempDir(), "sshepherd.yaml")

	var out, errBuf bytes.Buffer
	if code := run([]string{"import", src, "-o", dst}, &out, &errBuf); code != 0 {
		t.Fatalf("first write: exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty when -o is used", out.String())
	}
	data, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	if _, err := config.Parse(data); err != nil {
		t.Errorf("written manifest invalid: %v", err)
	}

	// Second run must refuse to clobber...
	errBuf.Reset()
	if code := run([]string{"import", src, "-o", dst}, &out, &errBuf); code != 3 {
		t.Fatalf("overwrite without --force: exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "--force") {
		t.Errorf("stderr = %q, want --force hint", errBuf.String())
	}

	// ...and --force allows it, tightening loose permissions back to 0600
	// (O_TRUNC alone would keep whatever mode the file already had).
	if err := os.Chmod(dst, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if code := run([]string{"import", src, "-o", dst, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("overwrite with --force: exit = %d, want 0", code)
	}
	info, err := os.Stat(dst)
	if err != nil {
		t.Fatalf("stat output: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode after --force overwrite = %o, want 600", perm)
	}
}

func TestImportDerivesUsersAndAccess(t *testing.T) {
	home := hermeticHome(t)
	key := testkeys.Line(t, 7)
	keyPath := filepath.Join(home, "work")
	if err := os.WriteFile(keyPath+".pub", []byte(key+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	cfg := writeSSHConfig(t, "Host web-1\n  User deploy\n  IdentityFile "+keyPath+"\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	c, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("stdout is not a valid manifest: %v", err)
	}
	if n := len(c.DesiredFor("web-1")); n != 1 {
		t.Errorf("DesiredFor(web-1) = %d keys, want 1", n)
	}
	if wantName := "name: " + localUsername() + "-work"; !strings.Contains(out.String(), wantName) {
		t.Errorf("stdout = %q, want %q", out.String(), wantName)
	}
	if !strings.Contains(errBuf.String(), "derived") {
		t.Errorf("stderr = %q, want a derived-users phase line", errBuf.String())
	}
	if strings.Contains(errBuf.String(), "warn:") || strings.Contains(errBuf.String(), "error:") {
		t.Errorf("stderr = %q, want no warnings for a clean import", errBuf.String())
	}
}

func TestImportServersOnly(t *testing.T) {
	hermeticHome(t)
	cfg := writeSSHConfig(t, "Host web-1\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "users: []") || !strings.Contains(out.String(), "access: []") {
		t.Errorf("stdout = %q, want empty users and access", out.String())
	}
	if strings.Contains(errBuf.String(), "warn:") || strings.Contains(errBuf.String(), "error:") {
		t.Errorf("stderr = %q, want no warnings for a clean import", errBuf.String())
	}
}

func TestImportNoIdentitiesWarns(t *testing.T) {
	hermeticHome(t) // empty home: no default keys to find
	cfg := writeSSHConfig(t, "Host web-1\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "no access derived") {
		t.Errorf("stderr = %q, want a no-access warning", errBuf.String())
	}
	if !strings.Contains(out.String(), "users: []") {
		t.Errorf("stdout = %q, want empty users", out.String())
	}
	if _, err := config.Parse(out.Bytes()); err != nil {
		t.Errorf("stdout is not a valid manifest: %v", err)
	}
}

func TestGenerateManifestQuotesSpecialChars(t *testing.T) {
	users := []identity.User{{
		Name:    "javad-odd",
		Source:  "~/.ssh/a: b #x",
		Comment: "note: primary #key",
		Key:     testkeys.Line(t, 8) + " note: primary #key",
		Servers: []string{"web-1"},
	}}
	hosts := []sshcfg.Host{{Alias: "web-1", HostName: "10.0.0.1", User: "deploy"}}
	got, _, err := generateManifest(hosts, users, "~/.ssh/config")
	if err != nil {
		t.Fatalf("generateManifest: %v", err)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("special-char manifest rejected by config.Parse: %v", err)
	}
	if len(c.Users) != 1 || c.Users[0].Comment != "note: primary #key" {
		t.Errorf("round-tripped users = %+v, want the comment preserved exactly", c.Users)
	}
}

func TestImportOperator(t *testing.T) {
	home := hermeticHome(t)
	referenced := filepath.Join(home, "work")
	if err := os.WriteFile(referenced+".pub", []byte(testkeys.Line(t, 1)+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	spare := filepath.Join(home, "spare")
	if err := os.WriteFile(spare+".pub", []byte(testkeys.Line(t, 2)+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	cfg := writeSSHConfig(t, "Host web-1\n  User deploy\n  IdentityFile "+referenced+"\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"import", cfg, "--operator", referenced, "--operator", spare}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	c, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("stdout is not a valid manifest: %v", err)
	}
	if n := len(c.DesiredFor("web-1")); n != 2 {
		t.Errorf("DesiredFor(web-1) = %d keys, want 2 (both operators)", n)
	}
	if !strings.Contains(out.String(), "operator: true") {
		t.Errorf("stdout = %q, want operator: true", out.String())
	}
	if strings.Contains(out.String(), "user: "+localUsername()+"-work") {
		t.Errorf("stdout = %q, an operator must not get an access entry", out.String())
	}
	if !strings.Contains(out.String(), "(--operator)") {
		t.Errorf("stdout = %q, want the (--operator) description on the created user", out.String())
	}
}

func TestImportOperatorConflictsServersOnly(t *testing.T) {
	hermeticHome(t)
	cfg := writeSSHConfig(t, "Host a\n  User u\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg, "--servers-only", "--operator", "x"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "--servers-only") {
		t.Errorf("stderr = %q, want a conflict message naming --servers-only", errBuf.String())
	}
}

func TestImportOperatorMissingKey(t *testing.T) {
	home := hermeticHome(t)
	cfg := writeSSHConfig(t, "Host a\n  User u\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"import", cfg, "--operator", filepath.Join(home, "nope")}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (an explicitly named operator key must exist)", code)
	}
}

// TestImportPhaseLogs: normal mode narrates parsing on stderr.
func TestImportPhaseLogs(t *testing.T) {
	cfg := writeSSHConfig(t, "Host web-1\n  User deploy\n") // reuse the fixture helper the clean-import test uses
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "parsed") || !strings.Contains(errBuf.String(), "hosts") {
		t.Errorf("stderr = %q, want a parsed-hosts phase line", errBuf.String())
	}
}

// TestImportCollapsesSameTargetAliases: `Host web1 web1.example.com` is two
// aliases for one remote file, which the manifest rejects as duplicate
// targets. The first alias is kept, the second dropped loudly, and a key
// used only through the dropped alias is granted on the kept one.
func TestImportCollapsesSameTargetAliases(t *testing.T) {
	home := hermeticHome(t)
	keyPath := filepath.Join(home, "only-via-fqdn")
	if err := os.WriteFile(keyPath+".pub", []byte(testkeys.Line(t, 7)+"\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	path := writeSSHConfig(t, "Host web1 web1.example.com\n  HostName 10.0.0.5\n  User deploy\n"+
		"Host web1.example.com\n  IdentityFile "+keyPath+"\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	c, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("stdout is not a valid manifest: %v\n%s", err, out.String())
	}
	if len(c.Servers) != 1 || c.Servers[0].Name != "web1" {
		t.Errorf("servers = %+v, want only web1", c.Servers)
	}
	if n := len(c.DesiredFor("web1")); n != 1 {
		t.Errorf("DesiredFor(web1) = %d keys, want the key used via web1.example.com", n)
	}
	if !strings.Contains(errBuf.String(), `server "web1.example.com" in the ssh config targets the same host, port, user and authorized_keys file as host "web1"`) {
		t.Errorf("stderr = %q, want a same-target warning naming both aliases", errBuf.String())
	}
}

// TestImportWarnsProxyHosts: bastion-only hosts are imported but flagged,
// since SSHepherd dials every server directly.
func TestImportWarnsProxyHosts(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host inner\n  HostName 10.1.0.5\n  User u\n  ProxyJump bastion\n"+
		"Host cmd\n  User u\n  ProxyCommand ssh -W %h:%p gw\nHost direct\n  User u\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	for _, want := range []string{
		`host "inner": ProxyJump bastion set — dialed directly; bastion hosts are not supported yet`,
		`host "cmd": ProxyCommand ssh -W %h:%p gw set — dialed directly`,
	} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("stderr = %q, want %q", errBuf.String(), want)
		}
	}
	if strings.Contains(errBuf.String(), `"direct"`) {
		t.Errorf("stderr = %q, direct host must not be flagged", errBuf.String())
	}
}

// TestImportSkipsUnsafeHostFields: a quoted alias with a space, or a
// HostName/User the manifest would reject, is skipped with a warning; the
// import succeeds instead of failing its self-check as a "bug:", and the
// skipped alias does not win a same-target collapse over a valid one.
func TestImportSkipsUnsafeHostFields(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host \"web 1\" web1\n  HostName 10.0.0.1\n  User deploy\n"+
		"Host badhost\n  HostName \"a b\"\n  User u\n"+
		"Host baduser\n  User \"x y\"\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	for _, want := range []string{
		`host "web 1": alias "web 1" contains whitespace, skipped`,
		`host "badhost": HostName "a b" contains whitespace, skipped`,
		`host "baduser": User "x y" contains whitespace, skipped`,
	} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("stderr = %q, want %q", errBuf.String(), want)
		}
	}
	if !strings.Contains(out.String(), "name: web1") {
		t.Errorf("manifest = %q, want the valid alias web1 kept", out.String())
	}
	if strings.Contains(out.String(), "badhost") || strings.Contains(out.String(), "baduser") {
		t.Errorf("manifest = %q, want unsafe hosts left out", out.String())
	}
}

// TestImportUnsafePubCommentWarns: a .pub whose comment the manifest would
// reject (here a tab) is skipped with a warning; the import still succeeds
// instead of failing its self-check as a "bug:".
func TestImportUnsafePubCommentWarns(t *testing.T) {
	home := hermeticHome(t)
	keyPath := filepath.Join(home, "odd")
	if err := os.WriteFile(keyPath+".pub", []byte(testkeys.Line(t, 7)+" alice\tlaptop\n"), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	path := writeSSHConfig(t, "Host a\n  User u\n  IdentityFile "+keyPath+"\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "bug:") || !strings.Contains(errBuf.String(), "comment contains control or format characters, skipped") {
		t.Errorf("stderr = %q, want an unsafe-comment skip warning and no bug error", errBuf.String())
	}
}
