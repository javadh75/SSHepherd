package sshread

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestReadThroughHop: the reader resolves via: through Client.Server and
// reads the target's authorized_keys over the tunnel; the bastion runs
// nothing.
func TestReadThroughHop(t *testing.T) {
	user := sshtest.Signer(t, sshtest.Key(1))
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(user.PublicKey())))
	home, err := os.MkdirTemp("", "home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hopKey, targetKey := sshtest.Signer(t, sshtest.Key(40)), sshtest.Signer(t, sshtest.Key(41))
	hop := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{hopKey}, Authorized: []ssh.PublicKey{user.PublicKey()}, Forward: sshtest.DialForward})
	target := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{targetKey}, Authorized: []ssh.PublicKey{user.PublicKey()}, Handle: sshtest.ShellHandler(home)})
	bastion := config.Server{Name: "bastion", Host: hop.Host, Port: hop.Port, User: "jump", JumpOnly: true}
	c := &Client{
		KnownHostsPath: sshtest.KnownHostsFile(t, hop.KnownHostsLine(hopKey.PublicKey()), target.KnownHostsLine(targetKey.PublicKey())),
		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))},
		DialTimeout:    5 * time.Second,
		Server: func(name string) (config.Server, bool) {
			return bastion, name == bastion.Name
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "web-1", Host: target.Host, Port: target.Port, User: "deploy", Via: "bastion"})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if strings.TrimSpace(string(res.Content)) != line {
		t.Errorf("content = %q, want the seeded key", res.Content)
	}
	if !slices.Equal(hop.Forwards(), []string{target.Addr()}) || len(hop.Commands()) != 0 {
		t.Errorf("bastion forwards %v and ran %q; want one forward and no command", hop.Forwards(), hop.Commands())
	}
}
