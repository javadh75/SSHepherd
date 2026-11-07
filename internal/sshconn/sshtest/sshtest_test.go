package sshtest

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m) }

// dialAs logs in to s as signer, verifying the host key strictly against a
// known_hosts file that records host (the repo bans FixedHostKey).
func dialAs(t *testing.T, s *Server, host ssh.PublicKey, signer ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	hostKeys, err := knownhosts.New(KnownHostsFile(t, s.KnownHostsLine(host)))
	if err != nil {
		t.Fatal(err)
	}
	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	cc, chans, reqs, err := ssh.NewClientConn(c, s.Addr(), &ssh.ClientConfig{
		User: "u", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: hostKeys,
	})
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	cl := ssh.NewClient(cc, chans, reqs)
	t.Cleanup(func() { _ = cl.Close() })
	return cl, nil
}

func run(t *testing.T, cl *ssh.Client, cmd string) string {
	t.Helper()
	sess, err := cl.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sess.Close() }()
	out, _ := sess.Output(cmd)
	return string(out)
}

func TestAuthorizedKeysFileMode(t *testing.T) {
	hk := Signer(t, Key(200))
	user := Signer(t, Key(1))
	line := string(bytes.TrimSpace(ssh.MarshalAuthorizedKey(user.PublicKey())))
	echo := func(_ context.Context, cmd string, _ io.Reader, stdout, _ io.Writer) int {
		_, _ = io.WriteString(stdout, "ran:"+cmd)
		return 0
	}
	tests := []struct {
		name, file string
		wantAuth   bool
		wantOut    string
	}{
		{"listed key logs in", line + "\n", true, "ran:probe"},
		{"unlisted key is refused", "# empty\n", false, ""},
		{"command= forces the command", `command="forced" ` + line + "\n", true, "ran:forced"},
		{"from= that cannot match refuses", `from="10.255.255.1" ` + line + "\n", false, ""},
		{"from= matching the client accepts", `from="10.0.0.1,127.0.0.*" ` + line + "\n", true, "ran:probe"},
		{"negated from= refuses", `from="!127.0.0.1,*" ` + line + "\n", false, ""},
		{"restrict alone still runs the command", `restrict ` + line + "\n", true, "ran:probe"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "authorized_keys")
			if err := os.WriteFile(file, []byte(tt.file), 0o600); err != nil {
				t.Fatal(err)
			}
			s := NewServer(t, ServerConfig{HostKeys: []ssh.Signer{hk}, AuthorizedKeysFile: file, Handle: echo})
			cl, err := dialAs(t, s, hk.PublicKey(), user)
			if (err == nil) != tt.wantAuth {
				t.Fatalf("auth err = %v, want auth %v", err, tt.wantAuth)
			}
			if err == nil {
				if got := run(t, cl, "probe"); got != tt.wantOut {
					t.Errorf("output = %q, want %q", got, tt.wantOut)
				}
			}
		})
	}
	t.Run("file is re-read on every login", func(t *testing.T) {
		file := filepath.Join(t.TempDir(), "authorized_keys")
		if err := os.WriteFile(file, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := NewServer(t, ServerConfig{HostKeys: []ssh.Signer{hk}, AuthorizedKeysFile: file, Handle: echo})
		if _, err := dialAs(t, s, hk.PublicKey(), user); err != nil {
			t.Fatalf("first login: %v", err)
		}
		if err := os.WriteFile(file, []byte("# key removed\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := dialAs(t, s, hk.PublicKey(), user); err == nil {
			t.Fatal("second login succeeded after the key was removed from the file")
		}
	})
}
