package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestPreserveHermetic (spec S6): against an in-process server that
// authorizes from the file apply writes, apply keeps a Gitea line and the
// comment above it under the marker, the post-write login check passes, a
// re-apply is a no-op, audit lists the line as externally managed (exit 0,
// rule in JSON), and adopt neither adopts its key nor drops the rule.
func TestPreserveHermetic(t *testing.T) {
	home := shortHome(t)
	line := func(k any) string {
		return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, k).PublicKey())))
	}
	alice, giteaKey := sshtest.Key(1), sshtest.Key(7)
	gitea := `command="/usr/local/bin/gitea --config=/etc/gitea/app.ini serv key-7",no-port-forwarding,no-pty ` + line(giteaKey) + " git@laptop"
	akf := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(akf), 0o700); err != nil {
		t.Fatal(err)
	}
	// Managed and converged except for the marker: the first write after
	// adding preserve: changes nothing else (F1 Q3, the owner's case).
	if err := os.WriteFile(akf, []byte(authkeys.ManagedHeader+"\n"+line(alice)+" alice\n# gitea public key\n"+gitea+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	host := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{host}, AuthorizedKeysFile: akf, Handle: sshtest.ShellHandler(home)})
	t.Setenv("SSH_AUTH_SOCK", sshtest.Agent(t, alice))
	cfg := writeConfig(t, fmt.Sprintf(`
users:
  - {name: alice, keys: ["%s"]}
servers:
  - {name: gitea, host: 127.0.0.1, port: %d, user: git, preserve: [{command: '/usr/local/bin/gitea --config=/etc/gitea/app.ini serv key-[0-9]+'}]}
access:
  - {user: alice, servers: [gitea]}
`, line(alice), srv.Port))
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey()))
	cli := func(args ...string) (int, string, string) {
		var out, errBuf bytes.Buffer
		code := run(append(args, "--config", cfg, "--known-hosts", kh), &out, &errBuf)
		return code, out.String(), errBuf.String()
	}

	// F1 Q3: the first apply after adding preserve: shows the marker as its
	// own row, never as a formatting drift (exit 1: a pending change). The
	// marker is the only difference, so no other row explains the bytes.
	if code, out, _ := cli("apply", "--dry-run"); code != 1 || !strings.Contains(out, "(preserve:)") ||
		!strings.Contains(out, "add the externally-managed section marker") || strings.Contains(out, "(formatting)") ||
		!strings.Contains(out, "→ 1 key desired · 0 add · 0 remove · 0 rewrite") {
		t.Errorf("first apply --dry-run exit = %d, want 1 with only the marker row (no formatting or rewrite row):\n%s", code, out)
	}
	if code, out, stderr := cli("apply", "--yes"); code != 0 {
		t.Fatalf("apply exit = %d\nstdout: %s\nstderr: %s", code, out, stderr)
	}
	want := authkeys.ManagedHeader + "\n" + line(alice) + " alice\n" + authkeys.PreserveMarker + "\n# gitea public key\n" + gitea + "\n"
	if got, err := os.ReadFile(akf); err != nil || string(got) != want { // #nosec G304 -- t.TempDir-backed path
		t.Fatalf("written file (err %v):\n%s\nwant\n%s", err, got, want)
	}
	if code, out, _ := cli("apply", "--dry-run"); code != 0 || !strings.Contains(out, fmt.Sprintf("gitea (git@127.0.0.1:%d)  converged (no changes)", srv.Port)) {
		t.Errorf("re-apply exit = %d, want a converged no-op:\n%s", code, out)
	}
	if code, out, _ := cli("audit"); code != 0 || !strings.Contains(out, "externally managed (preserve: command)") {
		t.Errorf("audit exit = %d:\n%s", code, out)
	}
	code, out, _ := cli("audit", "--json")
	var doc struct {
		Servers []struct {
			Keys struct {
				External []struct {
					Rule  string  `json:"rule"`
					Owner *string `json:"owner"`
				} `json:"external"`
			} `json:"keys"`
		} `json:"servers"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 0 || len(doc.Servers) != 1 ||
		len(doc.Servers[0].Keys.External) != 1 || doc.Servers[0].Keys.External[0].Rule != "command" || doc.Servers[0].Keys.External[0].Owner != nil {
		t.Errorf("audit --json exit = %d (err %v):\n%s", code, err, out)
	}
	code, out, stderr := cli("adopt")
	if code != 0 || strings.Contains(out, strings.Fields(line(giteaKey))[1]) || !strings.Contains(out, "preserve:") {
		t.Errorf("adopt exit = %d; it must keep preserve: and not adopt the Gitea key\nstdout: %s\nstderr: %s", code, out, stderr)
	}
}
