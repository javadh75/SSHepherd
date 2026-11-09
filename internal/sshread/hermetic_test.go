package sshread

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
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
		{"absolute default path is probed", "ssh-ed25519 AAAA planted\n", "$HOME/.ssh/authorized_keys", true},
		{"absolute non-default path is not flagged", "ssh-ed25519 AAAA planted\n", "$HOME/keys/deploy", false},
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
			srv.AuthorizedKeysFile = strings.ReplaceAll(tt.override, "$HOME", home)
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

// TestReadKeys2Content: with ReadKeys2 the reader returns a non-empty
// authorized_keys2's bytes (the post-revoke sweep reads it); without it, or
// when the file is empty or absent, Keys2 stays nil.
func TestReadKeys2Content(t *testing.T) {
	home := t.TempDir()
	writeHomeFile(t, home, ".ssh/authorized_keys", "ssh-ed25519 AAAA main\n")
	writeHomeFile(t, home, ".ssh/authorized_keys2", "ssh-ed25519 AAAA planted\n")
	c, _, srv := hermeticClient(t, home)
	res, err := c.ReadAuthorizedKeys(t.Context(), srv)
	if err != nil || res.Keys2 != nil {
		t.Fatalf("without ReadKeys2: Keys2 = %q, err %v; want nil", res.Keys2, err)
	}
	c.ReadKeys2 = true
	res, err = c.ReadAuthorizedKeys(t.Context(), srv)
	if err != nil || string(res.Keys2) != "ssh-ed25519 AAAA planted\n" || res.Keys2Err != nil || !res.AuthorizedKeys2 {
		t.Fatalf("ReadKeys2: %+v, err %v", res, err)
	}
	writeHomeFile(t, home, ".ssh/authorized_keys2", "")
	res, err = c.ReadAuthorizedKeys(t.Context(), srv)
	if err != nil || res.Keys2 != nil || res.AuthorizedKeys2 {
		t.Fatalf("empty keys2: %+v, err %v", res, err)
	}
}

// TestReadPosture: the probe's findings reach ReadResult.Posture through a
// real SSH session and a real shell.
func TestReadPosture(t *testing.T) {
	tests := []struct {
		name  string
		chmod func(t *testing.T, home string)
		want  string // "" = clean
	}{
		{"0700 is clean", func(*testing.T, string) {}, ""},
		{"0777 ~/.ssh is world-writable", func(t *testing.T, h string) { mustChmod(t, filepath.Join(h, ".ssh"), 0o777) }, fleet.PostureWorldWritable},
		{"0775 ~/.ssh is group-writable", func(t *testing.T, h string) { mustChmod(t, filepath.Join(h, ".ssh"), 0o775) }, fleet.PostureGroupWritable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := shortTempDir(t)
			mustChmod(t, home, 0o700)
			writeHomeFile(t, home, ".ssh/authorized_keys", "key-line\n")
			tt.chmod(t, home)
			c, _, srv := hermeticClient(t, home)
			res := readHermetic(t, c, srv)
			if tt.want == "" {
				if len(res.Posture) != 0 {
					t.Fatalf("posture = %+v, want clean", res.Posture)
				}
				return
			}
			if !slices.ContainsFunc(res.Posture, func(i fleet.PostureIssue) bool { return i.Issue == tt.want }) {
				t.Errorf("posture = %+v, want a %s finding", res.Posture, tt.want)
			}
		})
	}
	t.Run("symlinked file", func(t *testing.T) {
		home := shortTempDir(t)
		mustChmod(t, home, 0o700)
		writeHomeFile(t, home, ".ssh/real", "key-line\n")
		if err := os.Symlink("real", filepath.Join(home, ".ssh", "authorized_keys")); err != nil {
			t.Fatal(err)
		}
		c, _, srv := hermeticClient(t, home)
		res := readHermetic(t, c, srv)
		if string(res.Content) != "key-line\n" {
			t.Errorf("content = %q", res.Content)
		}
		if !slices.ContainsFunc(res.Posture, func(i fleet.PostureIssue) bool { return i.Issue == fleet.PostureSymlink }) {
			t.Errorf("posture = %+v, want a symlink finding", res.Posture)
		}
	})
	t.Run("absent file is clean", func(t *testing.T) {
		home := shortTempDir(t)
		mustChmod(t, home, 0o700)
		c, _, srv := hermeticClient(t, home)
		res := readHermetic(t, c, srv)
		if !res.FileAbsent || len(res.Posture) != 0 {
			t.Errorf("FileAbsent=%v posture=%+v, want absent and clean", res.FileAbsent, res.Posture)
		}
	})
	t.Run("override path outside HOME", func(t *testing.T) {
		home := shortTempDir(t)
		mustChmod(t, home, 0o700)
		outside := shortTempDir(t)
		mustChmod(t, outside, 0o777)
		if err := os.WriteFile(filepath.Join(outside, "keys"), []byte("key-line\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		c, _, srv := hermeticClient(t, home)
		srv.AuthorizedKeysFile = filepath.Join(outside, "keys")
		res := readHermetic(t, c, srv)
		if !slices.ContainsFunc(res.Posture, func(i fleet.PostureIssue) bool {
			return i.Issue == fleet.PostureWorldWritable && filepath.Base(i.Path) == filepath.Base(outside)
		}) {
			t.Errorf("posture = %+v, want the override's directory reported", res.Posture)
		}
	})
}

// TestReadCostsTwoSessions: the posture session replaced the keys2 probe, so
// a read stays at two sessions on the default path and on an override.
func TestReadCostsTwoSessions(t *testing.T) {
	for _, override := range []string{"", "~/keys/deploy"} {
		home := shortTempDir(t)
		mustChmod(t, home, 0o700)
		writeHomeFile(t, home, ".ssh/authorized_keys", "key-line\n")
		writeHomeFile(t, home, "keys/deploy", "key-line\n")
		c, fake, srv := hermeticClient(t, home)
		srv.AuthorizedKeysFile = override
		readHermetic(t, c, srv)
		if got := len(fake.Commands()); got != 2 {
			t.Errorf("override %q: %d sessions, want 2", override, got)
		}
	}
}

// TestReadFailsClosedOnBadPosture: a probe that exits non-zero or prints
// garbage fails the read as ErrorKindRemote (D14b).
func TestReadFailsClosedOnBadPosture(t *testing.T) {
	tests := []struct {
		name   string
		stdout string
		code   int
		want   string
	}{
		{"garbage output", "not a record\n", 0, "posture probe output malformed"},
		{"failed tool", "", 7, "posture probe failed (exit 7)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, host := sshtest.Key(1), sshtest.Signer(t, sshtest.Key(40))
			srv := sshtest.NewServer(t, sshtest.ServerConfig{
				HostKeys:   []ssh.Signer{host},
				Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
				Handle: func(_ context.Context, cmd string, _ io.Reader, stdout, _ io.Writer) int {
					if strings.Contains(cmd, "SSHEPHERD-POSTURE") {
						_, _ = io.WriteString(stdout, tt.stdout)
						return tt.code
					}
					_, _ = io.WriteString(stdout, "key-line\n")
					return 0
				},
			})
			c := &Client{
				KnownHostsPath: sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey())),
				Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, user)},
				DialTimeout:    5 * time.Second,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "web-1", Host: srv.Host, Port: srv.Port, User: "deploy"})
			if fleet.ErrorKindOf(err) != fleet.ErrorKindRemote || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want a remote error containing %q", err, tt.want)
			}
		})
	}
}

// TestPostureSessionFailureFailsClosed: when the posture probe's session dies
// at the transport level, the read fails with the probe named. It must never
// grade the server from a probe that did not run.
func TestPostureSessionFailureFailsClosed(t *testing.T) {
	user, host := sshtest.Key(1), sshtest.Signer(t, sshtest.Key(40))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		Handle: func(hctx context.Context, cmd string, _ io.Reader, stdout, _ io.Writer) int {
			if strings.Contains(cmd, "SSHEPHERD-POSTURE") {
				cancel() // the probe's session dies while it runs
				<-hctx.Done()
				return 1
			}
			_, _ = io.WriteString(stdout, "key-line\n")
			return 0
		},
	})
	c := &Client{
		KnownHostsPath: sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey())),
		Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, user)},
		DialTimeout:    5 * time.Second,
	}
	_, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "web-1", Host: srv.Host, Port: srv.Port, User: "deploy"})
	if err == nil || !strings.Contains(err.Error(), "posture probe on ") || fleet.ErrorKindOf(err) != fleet.ErrorKindCanceled {
		t.Errorf("err = %v, want a canceled posture probe error", err)
	}
}

func mustChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readHermetic(t *testing.T, c *Client, srv config.Server) fleet.ReadResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, srv)
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	return res
}
