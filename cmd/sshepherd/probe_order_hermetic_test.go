package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestApplyThenAuditUsesPlainKeyFirst (WP-5): the manifest lists a
// forced-command key first. After apply writes it, the next audit must log
// in with the plain key and read the real file. Before the fix, audit
// offers the forced-command key first, sshd runs `echo forced`, and audit
// fails to parse the file.
func TestApplyThenAuditUsesPlainKeyFirst(t *testing.T) {
	home := shortHome(t)
	k1, k2 := sshtest.Key(1), sshtest.Key(2)
	line := func(k any) string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, k).PublicKey())))
	}
	akf := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(akf), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(akf, []byte(line(k2)+"\n"), 0o600); err != nil { // only the plain key today
		t.Fatal(err)
	}
	host := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys: []ssh.Signer{host}, AuthorizedKeysFile: akf, Handle: sshtest.ShellHandler(home),
	})
	t.Setenv("SSH_AUTH_SOCK", sshtest.Agent(t, k1, k2))
	cfg := writeConfig(t, fmt.Sprintf(`
users:
  - {name: backup, keys: ["command=\"echo forced\" %s"]}
  - {name: admin, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: backup, servers: [web-1]}
  - {user: admin, servers: [web-1]}
`, line(k1), line(k2), srv.Port))
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey()))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("apply exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("audit after apply exit = %d, want 0 (a forced-command key captured the session)\nstdout: %s\nstderr: %s",
			code, out.String(), errBuf.String())
	}
}
