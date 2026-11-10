package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// bastionFleet: a jump_only bastion that forwards and a target whose file
// holds alice's key; the agent holds that key. It returns both servers,
// their host keys, the target's HOME and a manifest granting alice the
// target.
func bastionFleet(t *testing.T) (hop, target *sshtest.Server, hopKey, targetKey ssh.Signer, home, cfg string) {
	t.Helper()
	user := sshtest.Key(1)
	pub := sshtest.Signer(t, user).PublicKey()
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
	home = shortHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hopKey, targetKey = sshtest.Signer(t, sshtest.Key(40)), sshtest.Signer(t, sshtest.Key(41))
	hop = sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{hopKey}, Authorized: []ssh.PublicKey{pub}, Forward: sshtest.DialForward})
	target = sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{targetKey}, Authorized: []ssh.PublicKey{pub}, Handle: sshtest.ShellHandler(home)})
	t.Setenv("SSH_AUTH_SOCK", sshtest.Agent(t, user))
	cfg = writeConfig(t, fmt.Sprintf(`
users:
  - {name: alice, keys: ["%s"]}
servers:
  - {name: bastion, host: 127.0.0.1, port: %d, user: jump, jump_only: true}
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy, via: bastion}
access:
  - {user: alice, servers: ["*"]}
`, line, hop.Port, target.Port))
	return hop, target, hopKey, targetKey, home, cfg
}

// TestAuditThroughBastionHermetic: audit reads the target over the
// bastion, never reads the bastion, and pages once on a changed bastion
// key with via_failed on the dependent.
func TestAuditThroughBastionHermetic(t *testing.T) {
	t.Run("compliant", func(t *testing.T) {
		hop, target, hopKey, targetKey, _, cfg := bastionFleet(t)
		kh := sshtest.KnownHostsFile(t, hop.KnownHostsLine(hopKey.PublicKey()), target.KnownHostsLine(targetKey.PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
		}
		for _, want := range []string{
			fmt.Sprintf("bastion (jump@127.0.0.1:%d)  jump only (not audited: nothing reads its authorized_keys)", hop.Port),
			fmt.Sprintf("web-1 (deploy@127.0.0.1:%d via bastion)", target.Port),
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("report lacks %q:\n%s", want, out.String())
			}
		}
		if !strings.Contains(errBuf.String(), "1 read, 0 unreachable, 1 jump only") {
			t.Errorf("stderr lacks the jump-only read count:\n%s", errBuf.String())
		}
		if len(hop.Commands()) != 0 || !slices.Equal(hop.Forwards(), []string{target.Addr()}) {
			t.Errorf("bastion ran %q and forwarded %v; want no command and one forward", hop.Commands(), hop.Forwards())
		}
	})
	t.Run("changed bastion key", func(t *testing.T) {
		hop, target, _, targetKey, _, cfg := bastionFleet(t)
		kh := sshtest.KnownHostsFile(t, hop.KnownHostsLine(sshtest.Signer(t, sshtest.Key(42)).PublicKey()), target.KnownHostsLine(targetKey.PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--json"}, &out, &errBuf); code != 2 {
			t.Fatalf("exit = %d, want 2\nstdout: %s", code, out.String())
		}
		for _, want := range []string{`"via_failed": "bastion"`, `"host_key_alerts": 1`, `"error_kind": "host_key_changed"`} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("JSON lacks %s:\n%s", want, out.String())
			}
		}
		if len(target.Attempts()) != 0 {
			t.Error("the target was reached past a changed bastion key")
		}
	})
	t.Run("changed target key", func(t *testing.T) {
		// The bastion is fine; the server behind it presents another key:
		// the server's own alarm, exit 2, and no via_failed.
		hop, target, hopKey, _, _, cfg := bastionFleet(t)
		kh := sshtest.KnownHostsFile(t, hop.KnownHostsLine(hopKey.PublicKey()), target.KnownHostsLine(sshtest.Signer(t, sshtest.Key(43)).PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--json"}, &out, &errBuf); code != 2 {
			t.Fatalf("exit = %d, want 2\nstdout: %s", code, out.String())
		}
		if !strings.Contains(out.String(), `"host_key_alerts": 1`) || !strings.Contains(out.String(), `"error_kind": "host_key_changed"`) {
			t.Errorf("JSON lacks the target's own alert:\n%s", out.String())
		}
		if strings.Contains(out.String(), `"via_failed"`) {
			t.Errorf("a target's own changed key carries via_failed:\n%s", out.String())
		}
	})
	t.Run("a run that selects no server behind the bastion", func(t *testing.T) {
		// spec S5: such a run opens no connection to the bastion at all.
		hop, target, hopKey, targetKey, home, _ := bastionFleet(t)
		pub := sshtest.Signer(t, sshtest.Key(1)).PublicKey()
		direct := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{targetKey}, Authorized: []ssh.PublicKey{pub}, Handle: sshtest.ShellHandler(home)})
		cfg := writeConfig(t, fmt.Sprintf(`
users:
  - {name: alice, keys: ["%s"]}
servers:
  - {name: bastion, host: 127.0.0.1, port: %d, user: jump, jump_only: true}
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy, via: bastion}
  - {name: db-1, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: alice, servers: ["*"]}
`, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), hop.Port, target.Port, direct.Port))
		kh := sshtest.KnownHostsFile(t, hop.KnownHostsLine(hopKey.PublicKey()), target.KnownHostsLine(targetKey.PublicKey()),
			direct.KnownHostsLine(targetKey.PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit", "--server", "db-1", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
		}
		if len(hop.Attempts()) != 0 || len(hop.Forwards()) != 0 {
			t.Errorf("bastion saw attempts %v and forwards %v; a run selecting only db-1 must not touch it", hop.Attempts(), hop.Forwards())
		}
	})
}
