package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestApplyAdoptSweepNeverTouchJumpOnly (spec S5 Tests): apply writes the
// dependent through the bastion and lists the bastion as jump only; adopt
// reads 1 of 1; revoke --sweep prints not swept. The bastion runs no
// command in any of them: it only forwards.
func TestApplyAdoptSweepNeverTouchJumpOnly(t *testing.T) {
	t.Run("apply", func(t *testing.T) {
		hop, target, hopKey, targetKey, _, cfg := bastionFleet(t)
		kh := sshtest.KnownHostsFile(t, hop.KnownHostsLine(hopKey.PublicKey()), target.KnownHostsLine(targetKey.PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), fmt.Sprintf("bastion (jump@127.0.0.1:%d)  jump only (never read or written)", hop.Port)) ||
			!strings.Contains(out.String(), "web-1: applied · verified") {
			t.Errorf("report:\n%s", out.String())
		}
		if len(hop.Commands()) != 0 || len(hop.Forwards()) < 2 {
			t.Errorf("bastion ran %q, forwarded %v; want no command, and the read, write and probe forwarded", hop.Commands(), hop.Forwards())
		}
	})
	t.Run("adopt", func(t *testing.T) {
		hop, target, hopKey, targetKey, _, cfg := bastionFleet(t)
		kh := sshtest.KnownHostsFile(t, hop.KnownHostsLine(hopKey.PublicKey()), target.KnownHostsLine(targetKey.PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\nstderr: %s", code, errBuf.String())
		}
		if !strings.Contains(errBuf.String(), "read 1 of 1 server") || !strings.Contains(out.String(), "jump_only: true") {
			t.Errorf("stderr:\n%s\nmanifest:\n%s", errBuf.String(), out.String())
		}
		if len(hop.Commands()) != 0 {
			t.Errorf("adopt ran %q on the bastion", hop.Commands())
		}
	})
	t.Run("revoke --sweep", func(t *testing.T) {
		hop, target, hopKey, targetKey, home, _ := bastionFleet(t)
		bob := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, sshtest.Key(2)).PublicKey())))
		alice := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, sshtest.Key(1)).PublicKey())))
		if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(alice+"\n"+bob+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg := writeConfig(t, fmt.Sprintf(`
users:
  - {name: alice, keys: ["%s"]}
  - {name: bob, keys: ["%s"]}
servers:
  - {name: bastion, host: 127.0.0.1, port: %d, user: jump, jump_only: true}
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy, via: bastion}
access:
  - {user: alice, servers: ["*"]}
  - {user: bob, servers: [web-1]}
`, alice, bob, hop.Port, target.Port))
		kh := sshtest.KnownHostsFile(t, hop.KnownHostsLine(hopKey.PublicKey()), target.KnownHostsLine(targetKey.PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), "not swept: bastion (jump only)\n") {
			t.Errorf("report lacks the not-swept line:\n%s", out.String())
		}
		// A repeated revoke --sweep (D1c: exit 0) in JSON: sweep.jump_only.
		out.Reset()
		errBuf.Reset()
		if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("--json: exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
		}
		var doc struct {
			Sweep struct {
				JumpOnly []string `json:"jump_only"`
			} `json:"sweep"`
		}
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil || !slices.Equal(doc.Sweep.JumpOnly, []string{"bastion"}) {
			t.Errorf("sweep.jump_only = %v (err %v), want [bastion]:\n%s", doc.Sweep.JumpOnly, err, out.String())
		}
		if len(hop.Commands()) != 0 {
			t.Errorf("the sweep ran %q on the bastion", hop.Commands())
		}
	})
	t.Run("changed jump_only bastion key", func(t *testing.T) {
		// D28: a bastion's changed key pages audit only; the write commands
		// and adopt exit 1, with via_failed naming the bastion.
		hop, target, _, targetKey, _, cfg := bastionFleet(t)
		kh := sshtest.KnownHostsFile(t, hop.KnownHostsLine(sshtest.Signer(t, sshtest.Key(42)).PublicKey()), target.KnownHostsLine(targetKey.PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--dry-run", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 ||
			!strings.Contains(out.String(), `"via_failed": "bastion"`) {
			t.Errorf("apply: exit = %d, want 1 with via_failed\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
		}
		out.Reset()
		errBuf.Reset()
		if code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Errorf("adopt: exit = %d, want 1\nstderr: %s", code, errBuf.String())
		}
		bob := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, sshtest.Key(2)).PublicKey())))
		alice := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, sshtest.Key(1)).PublicKey())))
		withBob := writeConfig(t, fmt.Sprintf(`
users:
  - {name: alice, keys: ["%s"]}
  - {name: bob, keys: ["%s"]}
servers:
  - {name: bastion, host: 127.0.0.1, port: %d, user: jump, jump_only: true}
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy, via: bastion}
access:
  - {user: alice, servers: ["*"]}
  - {user: bob, servers: [web-1]}
`, alice, bob, hop.Port, target.Port))
		out.Reset()
		errBuf.Reset()
		if code := run([]string{"revoke", "bob", "--yes", "--config", withBob, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Errorf("revoke: exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
		}
		if len(target.Attempts()) != 0 {
			t.Error("the target was reached past a changed bastion key")
		}
	})
	t.Run("changed target key", func(t *testing.T) {
		// The target's own changed key behind a working bastion: exit 1 for
		// apply (it never pages a write command in phase 1), no via_failed.
		hop, target, hopKey, _, _, cfg := bastionFleet(t)
		kh := sshtest.KnownHostsFile(t, hop.KnownHostsLine(hopKey.PublicKey()), target.KnownHostsLine(sshtest.Signer(t, sshtest.Key(43)).PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--dry-run", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("apply: exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), `"error_kind": "host_key_changed"`) || strings.Contains(out.String(), `"via_failed"`) {
			t.Errorf("want the target's own host_key_changed and no via_failed:\n%s", out.String())
		}
	})
}
