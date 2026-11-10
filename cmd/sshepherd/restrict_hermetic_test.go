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

// TestGrantCommandOfferedLast (spec S7 Render, WP-5's twin): a grant puts
// command= on the first-listed key, so the post-write login check and the
// next audit must offer the plain key first. Against a server that
// authorizes from the written file and forces command= per login, a probe
// or read that logged in with the forced-command key would run `echo
// forced` and fail.
func TestGrantCommandOfferedLast(t *testing.T) {
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
  - {name: backup, keys: ["%s"]}
  - {name: admin, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: backup, servers: [web-1], options: ['command="echo forced"']}
  - {user: admin, servers: [web-1]}
`, line(k1), line(k2), srv.Port))
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey()))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("apply exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if got, err := os.ReadFile(akf); err != nil || !strings.Contains(string(got), `command="echo forced" `+line(k1)+" backup\n") { // #nosec G304 -- t.TempDir-backed path
		t.Fatalf("written file (err %v):\n%s", err, got)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("audit after apply exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
}
