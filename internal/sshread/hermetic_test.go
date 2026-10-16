package sshread

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// hermeticClient serves a real SSH exchange in-process: an x/crypto server
// running each command through the local /bin/sh with HOME=home, an agent
// holding the login key, and a known_hosts pinning the server.
func hermeticClient(t *testing.T, home string) (*Client, *sshtest.Server, config.Server) {
	t.Helper()
	user := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		Handle:     sshtest.ShellHandler(home),
	})
	c := &Client{
		KnownHostsPath: sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey())),
		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(2), user)},
		DialTimeout:    5 * time.Second,
	}
	return c, srv, config.Server{Name: "web-1", Host: srv.Host, Port: srv.Port, User: "deploy"}
}

func writeHomeFile(t *testing.T, home, rel, content string) {
	t.Helper()
	p := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestReadReportsAuthorizedKeys2(t *testing.T) {
	tests := []struct {
		name     string
		ak2      string // "" = absent
		override string
		want     bool
	}{
		{"default path, no authorized_keys2", "", "", false},
		{"default path, empty authorized_keys2", "\x00", "", false},
		{"default path, planted authorized_keys2", "ssh-ed25519 AAAA planted\n", "", true},
		{"explicit default path is still probed", "ssh-ed25519 AAAA planted\n", "~/.ssh/authorized_keys", true},
		{"override path is not probed", "ssh-ed25519 AAAA planted\n", "~/keys/deploy", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := shortTempDir(t)
			writeHomeFile(t, home, ".ssh/authorized_keys", "key-line\n")
			writeHomeFile(t, home, "keys/deploy", "key-line\n")
			switch tt.ak2 {
			case "":
			case "\x00":
				writeHomeFile(t, home, ".ssh/authorized_keys2", "")
			default:
				writeHomeFile(t, home, ".ssh/authorized_keys2", tt.ak2)
			}
			c, fake, srv := hermeticClient(t, home)
			srv.AuthorizedKeysFile = tt.override
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			res, err := c.ReadAuthorizedKeys(ctx, srv)
			if err != nil {
				t.Fatalf("ReadAuthorizedKeys: %v", err)
			}
			if string(res.Content) != "key-line\n" {
				t.Errorf("content = %q", res.Content)
			}
			if res.AuthorizedKeys2 != tt.want {
				t.Errorf("AuthorizedKeys2 = %v, want %v", res.AuthorizedKeys2, tt.want)
			}
			for _, cmd := range fake.Commands() {
				if !strings.HasPrefix(cmd, "exec /bin/sh -c '") {
					t.Errorf("remote command not wrapped in /bin/sh: %q", cmd)
				}
			}
		})
	}
}

// TestClientSharesOneSnapshotAndPrefersGrantedKeys: the Client hands its
// PreferKeys to the one Dialer it builds, and a preloaded KnownHosts
// snapshot is used as given (KnownHostsPath is never re-read).
func TestClientSharesOneSnapshotAndPrefersGrantedKeys(t *testing.T) {
	home := shortTempDir(t)
	writeHomeFile(t, home, ".ssh/authorized_keys", "key-line\n")
	c, fake, srv := hermeticClient(t, home)
	snap, err := LoadKnownHosts(c.KnownHostsPath)
	if err != nil {
		t.Fatal(err)
	}
	c.KnownHosts = snap
	c.KnownHostsPath = "/nonexistent"
	granted := sshtest.Fingerprint(t, sshtest.Key(1))
	c.PreferKeys = func(config.Server) []string { return []string{granted} }
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range 2 {
		if _, err := c.ReadAuthorizedKeys(ctx, srv); err != nil {
			t.Fatalf("ReadAuthorizedKeys: %v", err)
		}
	}
	if got := fake.Attempts(); len(got) != 2 || got[0] != granted || got[1] != granted {
		t.Errorf("auth attempts = %v, want only the granted key, once per read", got)
	}
}

// TestReadWithKeyFileNoAgent: the Client's Creds carry an --identity key
// and no agent at all — the headless read path.
func TestReadWithKeyFileNoAgent(t *testing.T) {
	home := shortTempDir(t)
	writeHomeFile(t, home, ".ssh/authorized_keys", "key-line\n")
	c, _, srv := hermeticClient(t, home)
	c.Creds = &sshconn.Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/keys/ci", sshtest.Key(1))}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, srv)
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys with a key file and no agent: %v", err)
	}
	if res.SessionKeyFP != sshtest.Fingerprint(t, sshtest.Key(1)) {
		t.Errorf("SessionKeyFP = %q, want the key file's fingerprint", res.SessionKeyFP)
	}
}
