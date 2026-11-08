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
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// offerFleet: two servers accepting agent key 1. The manifest grants key
// grantSeed, so the run's agent (key 1, key 2) may hold none of it.
func offerFleet(t *testing.T, grantSeed byte) (cfgPath, kh string, servers []*sshtest.Server) {
	t.Helper()
	agentKey, other := sshtest.Key(1), sshtest.Key(2)
	host := sshtest.Signer(t, sshtest.Key(40))
	t.Setenv("SSH_AUTH_SOCK", sshtest.Agent(t, agentKey, other))
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, agentKey).PublicKey())))
	var lines []string
	var body strings.Builder
	body.WriteString("users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, grantSeed) + "\"]}\nservers:\n")
	for _, name := range []string{"web-1", "web-2"} {
		home := shortHome(t)
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		srv := sshtest.NewServer(t, sshtest.ServerConfig{
			HostKeys:   []ssh.Signer{host},
			Authorized: []ssh.PublicKey{sshtest.Signer(t, agentKey).PublicKey()},
			Handle:     sshtest.ShellHandler(home),
		})
		servers = append(servers, srv)
		lines = append(lines, srv.KnownHostsLine(host.PublicKey()))
		fmt.Fprintf(&body, "  - {name: %s, host: 127.0.0.1, port: %d, user: deploy}\n", name, srv.Port)
	}
	body.WriteString("access:\n  - {user: alice, servers: [web-1, web-2]}\n")
	return writeConfig(t, body.String()), sshtest.KnownHostsFile(t, lines...), servers
}

// TestPreflightWarnsOnceWhenNothingGranted (D17b, OP6): one line for the
// whole run, and the per-server fallback lines are silent.
func TestPreflightWarnsOnceWhenNothingGranted(t *testing.T) {
	cfg, kh, servers := offerFleet(t, 9) // key 9 is held by nobody
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (drift), stderr: %s", code, errBuf.String())
	}
	want := "none of the loaded keys is granted on any target server; each server will be offered all 2 held keys"
	if n := strings.Count(errBuf.String(), want); n != 1 {
		t.Errorf("preflight warning appeared %d times, want once:\n%s", n, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "none of the keys granted here") {
		t.Errorf("per-server fallback warning printed after the preflight:\n%s", errBuf.String())
	}
	if got := len(servers[0].Attempts()); got == 0 {
		t.Error("the fallback offered nothing")
	}
}

// TestPreflightSilentWhenAnyServerGranted pins the negative: one granted
// key anywhere keeps the preflight quiet. It passes before Task 19 (no
// preflight exists yet) and guards against one that warns too eagerly.
func TestPreflightSilentWhenAnyServerGranted(t *testing.T) {
	cfg, kh, _ := offerFleet(t, 1) // key 1 is held
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0, stderr: %s\n%s", code, errBuf.String(), out.String())
	}
	if strings.Contains(errBuf.String(), "none of the loaded keys") {
		t.Errorf("unexpected preflight warning:\n%s", errBuf.String())
	}
}

// TestOfferAllKeysSkipsPreflight: --offer-all-keys asks for the old offer,
// so neither warning is printed.
func TestOfferAllKeysSkipsPreflight(t *testing.T) {
	cfg, kh, _ := offerFleet(t, 9)
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--offer-all-keys"}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1, stderr: %s", code, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "none of the") {
		t.Errorf("unexpected warning under --offer-all-keys:\n%s", errBuf.String())
	}
}

// TestApplyNoGrantedKeyRefusedByGuard: no granted key held — the read falls
// back and the plan is computed, but the self-lockout guard refuses the
// write. One preflight line, one connection (one auth attempt: the first
// held key is accepted) and the two read sessions: no write dial.
func TestApplyNoGrantedKeyRefusedByGuard(t *testing.T) {
	cfg, kh, servers := offerFleet(t, 9)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", cfg, "--known-hosts", kh, "--yes"}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1, stdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "REFUSED") {
		t.Errorf("report lacks the guard's refusal:\n%s", out.String())
	}
	if n := strings.Count(errBuf.String(), "none of the loaded keys is granted on any target server"); n != 1 {
		t.Errorf("preflight warning appeared %d times, want once:\n%s", n, errBuf.String())
	}
	for _, srv := range servers {
		if got := srv.Attempts(); len(got) != 1 {
			t.Errorf("auth attempts = %v, want one connection's single attempt", got)
		}
		if got := srv.Commands(); len(got) != 2 {
			t.Errorf("commands = %q, want the two read sessions and no write", got)
		}
	}
}

// TestPreflightWarnsOnceOnRevoke: the edit path has its own preflight call
// site, with the former-and-edited grants. Every server is refused (revoke
// never empties one), so a dry run ends at exit 1.
func TestPreflightWarnsOnceOnRevoke(t *testing.T) {
	cfg, kh, _ := offerFleet(t, 9)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "alice", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1, stdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if n := strings.Count(errBuf.String(), "none of the loaded keys is granted on any target server"); n != 1 {
		t.Errorf("preflight warning appeared %d times, want once:\n%s", n, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "none of the keys granted here") {
		t.Errorf("per-server fallback warning printed after the preflight:\n%s", errBuf.String())
	}
}

// TestAuditAuthFailureHintsFlag: a granted key held but not installed fails
// auth with a hint naming the flag, which then reads the server.
func TestAuditAuthFailureHintsFlag(t *testing.T) {
	cfg, kh, _ := offerFleet(t, 2) // key 2 is held and granted, but the server accepts only key 1
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1, stdout: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "re-run with --offer-all-keys") {
		t.Errorf("report lacks the hint:\n%s", out.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--offer-all-keys"}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (the read now works and shows drift), stdout: %s", code, out.String())
	}
	if strings.Contains(out.String(), "ERROR") || !strings.Contains(out.String(), "UNAUTHORIZED") {
		t.Errorf("the flag should read the server and show drift:\n%s", out.String())
	}
}

// TestFollowUpCarriesOfferAll: paste-ready hints repeat the flag.
func TestFollowUpCarriesOfferAll(t *testing.T) {
	f := connFlags{cfgPath: defaultConfigPath, knownHosts: defaultKnownHosts, offerAll: true}
	if got := f.followUp().command("apply", nil); got != "sshepherd apply --offer-all-keys" {
		t.Errorf("command = %q", got)
	}
}
