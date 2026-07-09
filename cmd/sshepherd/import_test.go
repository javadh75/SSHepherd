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
	got, skipped, err := generateManifest(hosts, users, "~/.ssh/config")
	if err != nil || len(skipped) != 0 {
		t.Fatalf("generateManifest: skipped %v, err %v", skipped, err)
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
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", "/no/such/ssh_config"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, errBuf.String())
	}
}

func TestImportBasic(t *testing.T) {
	path := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if _, err := config.Parse(out.Bytes()); err != nil {
		t.Errorf("stdout is not a valid manifest: %v", err)
	}
	if !strings.Contains(out.String(), "name: web-1") {
		t.Errorf("stdout = %q, want server web-1", out.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty for a clean import", errBuf.String())
	}
}

func TestImportWarningsGoToStderrOnly(t *testing.T) {
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
	if strings.Contains(out.String(), "warning") {
		t.Errorf("stdout = %q, must not carry warnings", out.String())
	}
}

func TestImportOutputFile(t *testing.T) {
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
	if code := run([]string{"import", src, "-o", dst}, &out, &errBuf); code != 2 {
		t.Fatalf("overwrite without --force: exit = %d, want 2", code)
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
