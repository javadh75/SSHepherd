package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// hermeticFleet runs one in-process SSH server (commands through the local
// /bin/sh, HOME=home) with an agent holding the login key on
// SSH_AUTH_SOCK, and returns a manifest granting that key on it.
func hermeticFleet(t *testing.T, home string) (*sshtest.Server, ssh.PublicKey, string) {
	t.Helper()
	user := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		Handle:     sshtest.ShellHandler(home),
	})
	t.Setenv("SSH_AUTH_SOCK", sshtest.Agent(t, user))
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, user).PublicKey())))
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, fmt.Sprintf(`
users:
  - {name: alice, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`, line, srv.Port))
	return srv, host.PublicKey(), cfg
}

// TestAuditHermetic drives the real audit wiring end to end against an
// in-process server: compliant, an unmanaged authorized_keys2 (exit 1), and
// a changed host key (exit 2 with the kind on the report).
func TestAuditHermetic(t *testing.T) {
	t.Run("compliant", func(t *testing.T) {
		srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
		kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
		}
	})
	t.Run("authorized_keys2 present", func(t *testing.T) {
		home := shortHome(t)
		srv, hostKey, cfg := hermeticFleet(t, home)
		if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys2"), []byte("ssh-ed25519 AAAA planted\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d, want 1\nstdout: %s", code, out.String())
		}
		if !strings.Contains(out.String(), "unmanaged authorized_keys2 present") {
			t.Errorf("report lacks the authorized_keys2 drift:\n%s", out.String())
		}
	})
	t.Run("changed host key", func(t *testing.T) {
		srv, _, cfg := hermeticFleet(t, shortHome(t))
		kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(sshtest.Signer(t, sshtest.Key(41)).PublicKey()))
		var out, errBuf bytes.Buffer
		if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--json"}, &out, &errBuf); code != 2 {
			t.Fatalf("exit = %d, want 2\nstdout: %s", code, out.String())
		}
		if !strings.Contains(out.String(), `"error_kind": "host_key_changed"`) {
			t.Errorf("JSON lacks error_kind host_key_changed:\n%s", out.String())
		}
		if len(srv.Attempts()) != 0 {
			t.Error("credentials were offered to a host whose key changed")
		}
	})
}

// TestRunContextCancellationReachesCommands: the ctx run() builds from
// SIGINT/SIGTERM is the one commands see — a canceled run aborts the
// preflight instead of proceeding as if nothing happened.
func TestRunContextCancellationReachesCommands(t *testing.T) {
	srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errBuf bytes.Buffer
	code := runContext(ctx, []string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "canceled") {
		t.Errorf("stderr = %q, want the cancellation surfaced", errBuf.String())
	}
	if len(srv.Attempts()) != 0 {
		t.Error("a canceled run still dialed the fleet")
	}
}

// shortHome is a HOME for the hermetic server's shell.
func shortHome(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// interruptingFleet is hermeticFleet whose server cancels the returned ctx
// from inside the read — an interrupt that lands mid-fan-out, after the
// preflights passed — and then holds the session until the client closes.
func interruptingFleet(t *testing.T) (context.Context, string, string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	user := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		Handle: func(hctx context.Context, _ string, _ io.Reader, _, _ io.Writer) int {
			cancel()
			<-hctx.Done()
			return 1
		},
	})
	t.Setenv("SSH_AUTH_SOCK", sshtest.Agent(t, user))
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, user).PublicKey())))
	cfg := writeConfig(t, fmt.Sprintf(`
users:
  - {name: alice, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`, line, srv.Port))
	return ctx, cfg, sshtest.KnownHostsFile(t, srv.KnownHostsLine(host.PublicKey()))
}

// TestAuditInterruptedMidFanOutExits3: Ctrl-C after the preflights must not
// be rendered as an unreachable fleet (exit 1) — the run is interrupted,
// exit 3, and no report claims to describe the fleet.
func TestAuditInterruptedMidFanOutExits3(t *testing.T) {
	ctx, cfg, kh := interruptingFleet(t)
	var out, errBuf bytes.Buffer
	code := runContext(ctx, []string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("an interrupted audit rendered a report:\n%s", out.String())
	}
	if !strings.Contains(errBuf.String(), "interrupted") {
		t.Errorf("stderr = %q, want the interrupt surfaced", errBuf.String())
	}
	if strings.Contains(errBuf.String(), "warn:") {
		t.Errorf("a canceled read must not warn (one \"interrupted\" line only):\n%s", errBuf.String())
	}
}

// TestAdoptInterruptedMidFanOutWritesNothing: Ctrl-C during adopt --partial
// must not turn the canceled servers into "unreadable" and overwrite -o with
// a manifest lacking their access.
func TestAdoptInterruptedMidFanOutWritesNothing(t *testing.T) {
	ctx, cfg, kh := interruptingFleet(t)
	outPath := filepath.Join(t.TempDir(), "out.yaml")
	if err := os.WriteFile(outPath, []byte("precious\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := runContext(ctx, []string{"adopt", "--config", cfg, "--known-hosts", kh, "--partial", "-o", outPath, "--force"}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3\nstderr: %s", code, errBuf.String())
	}
	got, err := os.ReadFile(outPath) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "precious\n" {
		t.Errorf("interrupted adopt overwrote --output:\n%s", got)
	}
	if !strings.Contains(errBuf.String(), "interrupted") {
		t.Errorf("stderr = %q, want the interrupt surfaced", errBuf.String())
	}
}

// TestApplyInterruptedDuringPlanExits3: Ctrl-C during phase 1 is an
// interrupted run (exit 3, nothing written), not a plan of unreachable
// servers.
func TestApplyInterruptedDuringPlanExits3(t *testing.T) {
	ctx, cfg, kh := interruptingFleet(t)
	var out, errBuf bytes.Buffer
	code := runContext(ctx, []string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "interrupted") {
		t.Errorf("stderr = %q, want the interrupt surfaced", errBuf.String())
	}
}

// TestAuditClosedPortsHintOnce: the real transport through the real CLI —
// two refused servers give two clean [dial] heads, one hint line, and
// stderr warn lines without the hint. Its stdout is the README's source for
// real dial-error samples.
func TestAuditClosedPortsHintOnce(t *testing.T) {
	fakeAgent(t)
	kh := writeEmptyKnownHosts(t)
	p1, p2 := closedPort(t), closedPort(t)
	path := writeConfig(t, fmt.Sprintf(`
users:
  - {name: alice, keys: ["%s"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}
  - {name: web-2, host: 127.0.0.1, port: %d, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
`, testkeys.Line(t, 1), p1, p2))
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	for _, p := range []int{p1, p2} {
		want := fmt.Sprintf("ERROR [dial]: dial tcp 127.0.0.1:%d: connect: connection refused\n", p)
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if n := strings.Count(out.String(), "  hint: "+sshconn.DialHint+"\n"); n != 1 {
		t.Errorf("hint printed %d times on stdout, want 1:\n%s", n, out.String())
	}
	if strings.Contains(errBuf.String(), "hint") {
		t.Errorf("live warn lines must not repeat the hint:\n%s", errBuf.String())
	}
	t.Logf("README sample source:\n%s", out.String())
}
