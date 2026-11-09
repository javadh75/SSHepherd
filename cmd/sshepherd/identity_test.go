package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// emptyKnownHosts writes an empty (valid) known_hosts and returns its path.
func emptyKnownHosts(t *testing.T) string {
	t.Helper()
	return sshtest.KnownHostsFile(t)
}

// scriptedPrompter is the cmd-level prompter fake.
type scriptedPrompter struct {
	avail    bool
	answers  []string
	prompts  int
	onPrompt func()
}

func (p *scriptedPrompter) Available() bool { return p.avail }

func (p *scriptedPrompter) ReadPassphrase(ctx context.Context, _ string) ([]byte, error) {
	p.prompts++
	if p.onPrompt != nil {
		p.onPrompt()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(p.answers) == 0 {
		return nil, errors.New("no answer scripted")
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return []byte(a), nil
}

// usePrompter swaps the passphrase prompter for the test.
func usePrompter(t *testing.T, p keyfile.Prompter) {
	t.Helper()
	saved := newPrompter
	newPrompter = func() keyfile.Prompter { return p }
	t.Cleanup(func() { newPrompter = saved })
}

// neverPrompt fails the test if anything prompts.
func neverPrompt(t *testing.T) *scriptedPrompter {
	t.Helper()
	p := &scriptedPrompter{avail: true}
	usePrompter(t, p)
	t.Cleanup(func() {
		if p.prompts != 0 {
			t.Errorf("prompted %d times, want never", p.prompts)
		}
	})
	return p
}

// encryptedKey writes an encrypted OpenSSH key (passphrase "pw") and returns its path.
func encryptedKey(t *testing.T, seed byte) string {
	t.Helper()
	return sshtest.WriteKeyFile(t, t.TempDir(), "id_enc", sshtest.Key(seed), []byte("pw"))
}

// keyFleet runs one in-process server that accepts only key's public half
// (no agent anywhere: SSH_AUTH_SOCK is unset), with HOME=home for its
// shell, and returns the manifest granting that key, a known_hosts, and
// the server.
func keyFleet(t *testing.T, home string, seed byte) (cfg, kh string, srv *sshtest.Server) {
	t.Helper()
	t.Setenv("SSH_AUTH_SOCK", "")
	user := sshtest.Key(seed)
	host := sshtest.Signer(t, sshtest.Key(40))
	srv = sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		Handle:     sshtest.ShellHandler(home),
	})
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, user).PublicKey())))
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = writeConfig(t, fmt.Sprintf(`
users:
  - {name: ci, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: ci, servers: [web-1]}
`, line, srv.Port))
	return cfg, sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey())), srv
}

func TestIdentityFlagValidation(t *testing.T) {
	// Validation is step 1: it fails before the (missing) manifest loads.
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"passphrase file without --identity", []string{"--identity-passphrase-file", "/pw"}, "passphrase flags need --identity"},
		{"mapping without --identity", []string{"--identity-passphrase", "/k=/pw"}, "passphrase flags need --identity"},
		{"unmatched KEY lists the cleaned paths", []string{"--identity", "/keys/./a", "--identity-passphrase", "/keys/b=/pw"},
			"--identity-passphrase: /keys/b matches no --identity (--identity paths: /keys/a)"},
		{"same KEY twice", []string{"--identity", "/k", "--identity-passphrase", "/k=/a", "--identity-passphrase", "/k=/b"}, "/k is given twice"},
		{"malformed mapping", []string{"--identity", "/k", "--identity-passphrase", "/k"}, "want PATH=FILE"},
	}
	for _, cmd := range []string{"audit", "adopt", "apply"} {
		for _, tt := range tests {
			t.Run(cmd+"/"+tt.name, func(t *testing.T) {
				var out, errBuf bytes.Buffer
				args := append([]string{cmd, "--config", "no-such-file.yaml"}, tt.args...)
				if code := run(args, &out, &errBuf); code != 3 {
					t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
				}
				if !strings.Contains(errBuf.String(), tt.want) || strings.Contains(errBuf.String(), "load manifest") {
					t.Errorf("stderr = %q, want the flag error %q before any manifest load", errBuf.String(), tt.want)
				}
			})
		}
	}
}

func TestIdentityFirstEqualsSplit(t *testing.T) {
	// PATH=FILE splits at the first "=": the FILE may contain "=", the PATH
	// may not (documented) — here the mapping names a file "pw=x".
	t.Setenv("SSH_AUTH_SOCK", "")
	key := encryptedKey(t, 7)
	pwFile := filepath.Join(t.TempDir(), "pw=x")
	if err := os.WriteFile(pwFile, []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	neverPrompt(t)
	path := writeConfig(t, `
servers:
  - {name: web-1, host: 127.0.0.1, port: `+fmt.Sprint(closedPort(t))+`, user: deploy}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"audit", "--config", path, "--known-hosts", emptyKnownHosts(t),
		"--identity", key, "--identity-passphrase", key + "=" + pwFile}, &out, &errBuf)
	if code != 1 { // unlocked, then the server is unreachable: drift, not a tool error
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "identity loaded") {
		t.Errorf("stderr = %q, want the identity-loaded line", errBuf.String())
	}
}

func TestIdentityOrderOfOperations(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Run("empty fleet never reads a key or prompts", func(t *testing.T) {
		key := encryptedKey(t, 7)
		path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
		for _, cmd := range []string{"audit", "adopt", "apply"} {
			neverPrompt(t)
			var out, errBuf bytes.Buffer
			if code := run([]string{cmd, "--config", path, "--identity", key}, &out, &errBuf); code != 0 {
				t.Fatalf("%s exit = %d, want 0 (stderr: %s)", cmd, code, errBuf.String())
			}
		}
	})
	t.Run("a missing key file is never opened when nothing is targeted", func(t *testing.T) {
		neverPrompt(t)
		path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--config", path, "--identity", "/nonexistent/key"}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
		}
	})
	t.Run("a manifest or --server error fails before any key is read", func(t *testing.T) {
		key := encryptedKey(t, 7)
		bad := writeConfig(t, "servers: [")
		for _, cmd := range []string{"audit", "adopt", "apply"} {
			neverPrompt(t)
			var out, errBuf bytes.Buffer
			code := run([]string{cmd, "--config", bad, "--known-hosts", emptyKnownHosts(t), "--identity", key}, &out, &errBuf)
			if code != 3 || !strings.Contains(errBuf.String(), "parse manifest") {
				t.Fatalf("%s exit = %d, stderr = %q; want the manifest error before any prompt", cmd, code, errBuf.String())
			}
		}
		neverPrompt(t)
		path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
		var out, errBuf bytes.Buffer
		code := run([]string{"apply", "--config", path, "--known-hosts", emptyKnownHosts(t), "--server", "nope", "--identity", key}, &out, &errBuf)
		if code != 3 || !strings.Contains(errBuf.String(), `--server: unknown server "nope"`) {
			t.Fatalf("exit = %d, stderr = %q; want the --server error before any prompt", code, errBuf.String())
		}
	})
	t.Run("bad --known-hosts fails before any prompt", func(t *testing.T) {
		key := encryptedKey(t, 7)
		path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
		for _, cmd := range []string{"audit", "adopt", "apply"} {
			neverPrompt(t)
			var out, errBuf bytes.Buffer
			code := run([]string{cmd, "--config", path, "--known-hosts", "/nonexistent/kh", "--identity", key}, &out, &errBuf)
			if code != 3 || !strings.Contains(errBuf.String(), "known_hosts preflight") {
				t.Fatalf("%s exit = %d, stderr = %q; want the known_hosts error first", cmd, code, errBuf.String())
			}
		}
	})
	t.Run("headless encrypted key with no passphrase source", func(t *testing.T) {
		usePrompter(t, &scriptedPrompter{avail: false})
		key := encryptedKey(t, 7)
		path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
		var out, errBuf bytes.Buffer
		code := run([]string{"audit", "--config", path, "--known-hosts", emptyKnownHosts(t), "--identity", key}, &out, &errBuf)
		if code != 3 || !strings.Contains(errBuf.String(), "is encrypted and no passphrase source is available") {
			t.Fatalf("exit = %d, stderr = %q; want the no-source exit 3", code, errBuf.String())
		}
	})
	t.Run("--yes still allows the passphrase prompt", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), []byte("pw"))
		p := &scriptedPrompter{avail: true, answers: []string{"pw"}}
		usePrompter(t, p)
		var out, errBuf bytes.Buffer
		code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf)
		if code != 0 || p.prompts != 1 {
			t.Fatalf("exit = %d, prompts = %d (stderr: %s)\n%s", code, p.prompts, errBuf.String(), out.String())
		}
	})
}

func TestIdentityInterruptedAtPrompt(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	home := shortHome(t)
	cfg, kh, srv := keyFleet(t, home, 3)
	key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), []byte("pw"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	usePrompter(t, &scriptedPrompter{avail: true, onPrompt: cancel})
	var out, errBuf bytes.Buffer
	code := runContext(ctx, []string{"audit", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf)
	if code != 3 || !strings.Contains(errBuf.String(), "interrupted") {
		t.Fatalf("exit = %d, stderr = %q; want the interrupted exit 3", code, errBuf.String())
	}
	if len(srv.Attempts()) != 0 {
		t.Error("an interrupted prompt still connected")
	}
}

// TestIdentityHermetic drives audit, adopt and apply end to end with a key
// file and no agent at all.
func TestIdentityHermetic(t *testing.T) {
	t.Run("audit --identity, unencrypted key", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), nil)
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d (stderr: %s)\n%s", code, errBuf.String(), out.String())
		}
	})
	t.Run("adopt --identity", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), nil)
		var out, errBuf bytes.Buffer
		if code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
		}
	})
	t.Run("apply --identity, encrypted key, passphrase file", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		dir := t.TempDir()
		key := sshtest.WriteKeyFile(t, dir, "id", sshtest.Key(3), []byte("s3cret"))
		pw := filepath.Join(dir, "pw")
		if err := os.WriteFile(pw, []byte("s3cret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		neverPrompt(t)
		var out, errBuf bytes.Buffer
		code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh, "--identity", key, "--identity-passphrase-file", pw}, &out, &errBuf)
		if code != 0 || !strings.Contains(out.String(), "applied · verified") {
			t.Fatalf("exit = %d (stderr: %s)\n%s", code, errBuf.String(), out.String())
		}
		if strings.Contains(errBuf.String(), "s3cret") || strings.Contains(out.String(), "s3cret") {
			t.Error("the passphrase reached the output")
		}
	})
	t.Run("apply refuses a loose key file", func(t *testing.T) {
		home := shortHome(t)
		cfg, kh, _ := keyFleet(t, home, 3)
		key := sshtest.WriteKeyFile(t, t.TempDir(), "id", sshtest.Key(3), nil)
		if err := os.Chmod(key, 0o644); err != nil {
			t.Fatal(err)
		}
		var out, errBuf bytes.Buffer
		code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh, "--identity", key}, &out, &errBuf)
		if code != 3 || !strings.Contains(errBuf.String(), "are too open (chmod 600") {
			t.Fatalf("exit = %d, stderr = %q; want the permission refusal", code, errBuf.String())
		}
	})
}
