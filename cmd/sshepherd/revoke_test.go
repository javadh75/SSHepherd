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

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// editHost is one hermetic server of an edit fleet.
type editHost struct {
	home string
	srv  *sshtest.Server
}

// editFleet starts one in-process server per name, each accepting logins
// from the keys of the given seeds and running commands under its own
// HOME, with an agent holding key 1 on SSH_AUTH_SOCK. It returns the hosts
// and a known_hosts file covering them all; the agent socket path is
// returned so a test can make the agent vanish.
func editFleet(t *testing.T, accept []byte, names ...string) (map[string]editHost, string, string) {
	t.Helper()
	host := sshtest.Signer(t, sshtest.Key(40))
	var authorized []ssh.PublicKey
	for _, seed := range accept {
		authorized = append(authorized, sshtest.Signer(t, sshtest.Key(seed)).PublicKey())
	}
	hosts := make(map[string]editHost, len(names))
	var lines []string
	for _, name := range names {
		home := shortHome(t)
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		srv := sshtest.NewServer(t, sshtest.ServerConfig{
			HostKeys:   []ssh.Signer{host},
			Authorized: authorized,
			Handle:     sshtest.ShellHandler(home),
		})
		hosts[name] = editHost{home: home, srv: srv}
		lines = append(lines, srv.KnownHostsLine(host.PublicKey()))
	}
	sock := sshtest.Agent(t, sshtest.Key(1))
	t.Setenv("SSH_AUTH_SOCK", sock)
	return hosts, sshtest.KnownHostsFile(t, lines...), sock
}

// install writes h's authorized_keys: one plain line per seed, plus extra
// raw lines.
func (h editHost) install(t *testing.T, seeds []byte, extra ...string) {
	t.Helper()
	var b strings.Builder
	for _, s := range seeds {
		b.WriteString(testkeys.Line(t, s) + "\n")
	}
	for _, l := range extra {
		b.WriteString(l + "\n")
	}
	if err := os.WriteFile(filepath.Join(h.home, ".ssh", "authorized_keys"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

// keys returns h's authorized_keys.
func (h editHost) keys(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// line is h's servers: entry.
func (h editHost) line(name string) string {
	return fmt.Sprintf("  - {name: %s, host: 127.0.0.1, port: %d, user: deploy}\n", name, h.srv.Port)
}

// qk is a quoted manifest key line for seed.
func qk(t *testing.T, seed byte) string { return `"` + testkeys.Line(t, seed) + `"` }

// readCfg parses the manifest at path.
func readCfg(t *testing.T, path string) *config.Config {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(raw)
	if err != nil {
		t.Fatalf("saved manifest invalid: %v\n%s", err, raw)
	}
	return cfg
}

// fileBytes reads path.
func fileBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// twoUserFleet: alice (k1, held by the agent) and bob (k2) both granted
// web-1 and web-2, both keys installed on both.
func twoUserFleet(t *testing.T) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1, 2})
	}
	cfg := writeConfig(t, "# fleet manifest — hand-maintained\nusers:\n"+
		"  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
		"  # bob leaves on Friday\n"+
		"  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1, web-2]}\n")
	return hosts, kh, cfg
}

func TestRevokeUserHermetic(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"manifest edit: remove user bob (1 key, 1 access grant) — 2 servers affected\n",
		"bob (revoked)",
		"remove (unauthorized)",
		"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit is refused on the servers this run writes (serial 1)\n",
		"web-1: applied · verified",
		"web-2: applied · verified",
		"check every server: sshepherd audit --config " + cfg + " --known-hosts " + kh + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	saved := readCfg(t, cfg)
	if len(saved.Users) != 1 || saved.Users[0].Name != "alice" || len(saved.Access) != 1 {
		t.Errorf("saved manifest = %+v, want alice only", saved)
	}
	if raw := string(fileBytes(t, cfg)); !strings.Contains(raw, "# fleet manifest — hand-maintained") {
		t.Errorf("the file header comment was lost:\n%s", raw)
	}
	for name, h := range hosts {
		got := h.keys(t)
		if strings.Contains(got, testkeys.Line(t, 2)) || !strings.Contains(got, testkeys.Line(t, 1)) {
			t.Errorf("%s authorized_keys = %q, want alice only", name, got)
		}
	}
}

// TestRevokeHeaderBeforePreflight: the edit header prints before the
// preflight (which may prompt for a passphrase), so a run whose preflight
// fails — here no agent and no --identity — still shows what it was about
// to do, and saves and contacts nothing.
func TestRevokeHeaderBeforePreflight(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	t.Setenv("SSH_AUTH_SOCK", "")
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (preflight failure)\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if want := "manifest edit: remove user bob (1 key, 1 access grant) — 2 servers affected\n"; !strings.HasPrefix(out.String(), want) {
		t.Errorf("stdout = %q, want it to start with the edit header %q", out.String(), want)
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("a failed preflight changed the manifest")
	}
	for name, h := range hosts {
		if n := len(h.srv.Attempts()); n != 0 {
			t.Errorf("%s: %d login attempts, want none", name, n)
		}
	}
}

// TestRevokeAlreadyConverged: the edit changes the desired file, but the
// server already holds the new render — no write, yet the manifest edit is
// itself a change: always confirmed, then saved, exit 0.
func TestRevokeAlreadyConverged(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	render := authkeys.Header(1) + "\n" + testkeys.Line(t, 1) + " alice\n"
	for _, h := range hosts {
		h.install(t, nil, strings.TrimSuffix(render, "\n"))
	}
	before := fileBytes(t, cfg)

	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
		!strings.Contains(errBuf.String(), "confirmation required") {
		t.Fatalf("non-TTY without --yes: exit %d, stderr %q; want 3 (the edit always asks)", code, errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Fatal("manifest saved without confirmation")
	}

	var prompt bytes.Buffer
	usePromptStreams(t, strings.NewReader("y\n"), &prompt)
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(prompt.String(), "save manifest edit (no servers need a write)? [y/N]") {
		t.Errorf("prompt = %q", prompt.String())
	}
	if !strings.Contains(out.String(), "converged (no changes)") || !strings.Contains(out.String(), "updated — commit and push it") {
		t.Errorf("stdout = %s", out.String())
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
}

func TestRevokeDryRun(t *testing.T) {
	t.Run("pending change: exit 1, nothing saved or written", func(t *testing.T) {
		hosts, kh, cfg := twoUserFleet(t)
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d, want 1\n%s", code, out.String())
		}
		if !bytes.Equal(fileBytes(t, cfg), before) || strings.Contains(out.String(), "updated") {
			t.Error("--dry-run saved the manifest")
		}
		if !strings.Contains(out.String(), "2 pending  → exit 1") {
			t.Errorf("stdout lacks the apply-style summary:\n%s", out.String())
		}
		if !strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
			t.Error("--dry-run wrote a server")
		}
	})
	t.Run("already converged: exit 0", func(t *testing.T) {
		hosts, kh, cfg := twoUserFleet(t)
		for _, h := range hosts {
			h.install(t, nil, authkeys.Header(1), testkeys.Line(t, 1)+" alice")
		}
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errBuf.String())
		}
	})
	t.Run("zero affected: exit 0, no connection", func(t *testing.T) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: dave, keys: ["+qk(t, 5)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "dave", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), "manifest edit: remove user dave (1 key, 0 access grants) — no servers affected") {
			t.Errorf("stdout = %s", out.String())
		}
		if len(hosts["web-1"].srv.Attempts()) != 0 {
			t.Error("a zero-affected run connected")
		}
	})
}

// TestRevokeDeduplicates: a user or a key named twice is one edit.
func TestRevokeDeduplicates(t *testing.T) {
	_, _, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "bob", "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if out.String() != "manifest edit: remove user bob (1 key, 1 access grant) — 2 servers affected\ncheck every server: sshepherd audit --config "+cfg+"\n" {
		t.Errorf("stdout = %q", out.String())
	}
	out.Reset()
	if code := run([]string{"revoke", "--key", fpOf(t, 2), "--key", testkeys.Line(t, 2), "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if strings.Count(out.String(), "manifest edit: remove key") != 1 {
		t.Errorf("stdout = %q, want one key edit", out.String())
	}
}

func TestRevokeDeclined(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	before := fileBytes(t, cfg)
	var prompt bytes.Buffer
	usePromptStreams(t, strings.NewReader("n\n"), &prompt)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, errBuf.String())
	}
	if !strings.Contains(prompt.String(), "save manifest edit and write 2 of 2 affected servers? [y/N]") {
		t.Errorf("prompt = %q", prompt.String())
	}
	if !strings.Contains(errBuf.String(), "aborted; manifest not changed, nothing written") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) || !strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("a declined revoke changed something")
	}
}

// TestRevokeCASConflict: the manifest rewritten after the plan and before
// the save (the seam stands in for a concurrent edit) — exit 3, nothing
// saved, no server written.
func TestRevokeCASConflict(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	saved := beforeManifestSave
	beforeManifestSave = func(m manifestTarget) {
		if err := os.WriteFile(m.Resolved, append(fileBytes(t, m.Resolved), "# concurrent\n"...), 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeManifestSave = saved })
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "changed since it was read; re-run") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !strings.Contains(string(fileBytes(t, cfg)), "bob") || !strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
		t.Error("a refused save still edited the manifest or wrote a server")
	}
}

func TestRevokeSymlinkedManifest(t *testing.T) {
	_, kh, cfg := twoUserFleet(t)
	link := filepath.Join(t.TempDir(), "sshepherd.yaml")
	if err := os.Symlink(cfg, link); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", link, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("the symlink was replaced")
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("the link target was not saved")
	}
}

// TestRevokeNothingCanLand: every affected server refused — no prompt,
// nothing saved, exit 1.
func TestRevokeNothingCanLand(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	for _, h := range hosts {
		h.install(t, []byte{1, 2}, "this line is not a key")
	}
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "nothing saved — bob still has access on 2 servers; fix the refusals and re-run, or record the change without touching servers with --no-apply") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("manifest saved although nothing could land")
	}
}

// TestRevokeSoleGrantee: db-1's only grantee is revoked — warned in the
// header before any connection, refused (apply never empties a server),
// excluded from the finish hint; web-1 converges; the manifest is saved.
func TestRevokeSoleGrantee(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "db-1")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["db-1"].install(t, []byte{2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["db-1"].line("db-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1, db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	s := out.String()
	warn := "warning: db-1 would have no granted keys — apply never empties a server, so bob's key stays installed there"
	if !strings.Contains(s, warn) || strings.Index(s, warn) > strings.Index(s, "db-1 (deploy@") {
		t.Errorf("the emptied-server warning must head the report:\n%s", s)
	}
	if !strings.Contains(s, "web-1: applied · verified") || strings.Contains(s, "finish with:") {
		t.Errorf("want web-1 applied and no finish hint (db-1 is excluded):\n%s", s)
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
	if !strings.Contains(hosts["db-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("db-1 was emptied")
	}
}

// TestRevokePartialFailure: one affected server unreachable — exit 1, the
// manifest saved, and the hint names the server left to converge.
func TestRevokePartialFailure(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+
		fmt.Sprintf("  - {name: web-2, host: 127.0.0.1, port: %d, user: deploy}\n", closedPort(t))+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1, web-2]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	if want := "manifest updated; 1 server not converged — finish with: sshepherd apply --config " + cfg + " --known-hosts " + kh + " --server web-2\n"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
}

// TestRevokeHintsCarryRunFlags: a run with a key file, a passphrase file
// and its own known_hosts prints hints that repeat all of them (paths
// only), so the finish and the check commands can be pasted as is.
func TestRevokeHintsCarryRunFlags(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2})
	id := encryptedKey(t, 1)
	pp := filepath.Join(t.TempDir(), "pp")
	if err := os.WriteFile(pp, []byte("pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		fmt.Sprintf("  - {name: web-2, host: 127.0.0.1, port: %d, user: deploy}\n", closedPort(t))+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1, web-2]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh, "--identity", id, "--identity-passphrase-file", pp}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	flags := " --config " + cfg + " --known-hosts " + kh + " --identity " + id + " --identity-passphrase-file " + pp
	for _, want := range []string{
		"finish with: sshepherd apply" + flags + " --server web-2\n",
		"check every server: sshepherd audit" + flags + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
}

// TestRevokeNoApplyExcludesEmptied: the --no-apply push hint names only
// the servers apply would write — an emptied server (bob was its sole
// grantee) is refused by apply, so it is left out; when every affected
// server is emptied there is nothing to push.
func TestRevokeNoApplyExcludesEmptied(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.2, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1, db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if want := "run 'sshepherd apply --config " + cfg + " --server web-1' to push\n"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
	if strings.Contains(out.String(), "--server db-1") {
		t.Errorf("the push hint names the emptied db-1:\n%s", out.String())
	}

	t.Run("all emptied", func(t *testing.T) {
		cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
			"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.2, user: deploy}\n"+
			"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [db-1]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		want := "no servers contacted — nothing to push: every affected server would be left with no granted keys (see the warnings above)\n"
		if !strings.Contains(out.String(), want) || strings.Contains(out.String(), "to push\n") {
			t.Errorf("stdout = %s\nwant %q and no push hint", out.String(), want)
		}
	})
}

// TestRevokeRetryAfterSave: a revoke whose save landed but whose push did
// not is retried as is; the retry exits 0 with the already-revoked note
// (D1c), changes nothing, contacts no server, and points at the apply that
// finishes the job.
func TestRevokeRetryAfterSave(t *testing.T) {
	fixedEditClock(t)
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("first run exit = %d\n%s", code, errBuf.String())
	}
	before := fileBytes(t, cfg)
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("retry exit = %d, want 0 (D1c)\n%s", code, errBuf.String())
	}
	want := "bob was already revoked (2026-11-09); run 'sshepherd apply --config " + cfg + " --known-hosts " + kh + "' to converge any server that still has the key\n"
	if out.String() != want {
		t.Errorf("stdout = %q, want %q", out.String(), want)
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("the retry changed the manifest")
	}
	for name, h := range hosts {
		if len(h.srv.Attempts()) != 0 {
			t.Errorf("the retry connected to %s", name)
		}
	}
}

// TestRevokeHeldKeysGoneAfterPrompt: the agent vanishes while the prompt
// waits — no change-planned server keeps a held key, none is converged:
// nothing saved, exit 1.
func TestRevokeHeldKeysGoneAfterPrompt(t *testing.T) {
	hosts, kh, sock := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n")
	before := fileBytes(t, cfg)
	usePromptStreams(t, &actionReader{act: func() { _ = os.Remove(sock) }, r: strings.NewReader("y\n")}, io.Discard)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "nothing saved — none of the keys you hold would survive on any server") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("manifest saved without a surviving held key")
	}
}

// TestRevokeHeldKeysGoneAfterPromptConverged: the agent vanishes while the
// prompt waits, but one affected server already holds the edited render —
// the edit has landed there, so the save goes ahead (the commit guard's
// converged escape); the change-planned server fails its write-time guard
// and keeps its file: exit 1.
func TestRevokeHeldKeysGoneAfterPromptConverged(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	render := authkeys.Header(1) + "\n" + testkeys.Line(t, 1) + " alice\n"
	hosts["web-1"].install(t, nil, strings.TrimSuffix(render, "\n"))
	sock := os.Getenv("SSH_AUTH_SOCK") // editFleet's agent
	usePromptStreams(t, &actionReader{act: func() { _ = os.Remove(sock) }, r: strings.NewReader("y\n")}, io.Discard)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if strings.Contains(errBuf.String(), "nothing saved") {
		t.Errorf("the save was withheld although web-1 is converged:\n%s", errBuf.String())
	}
	if users := readCfg(t, cfg).Users; len(users) != 1 || users[0].Name != "alice" {
		t.Errorf("manifest users = %+v, want the edit saved (alice only)", users)
	}
	if got := hosts["web-1"].keys(t); got != render {
		t.Errorf("web-1 = %q, want its converged render untouched", got)
	}
	if !strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
		t.Error("web-2 was written with no held key surviving")
	}
}

// TestRevokeInterruptedAtPrompt: Ctrl-C before the save — exit 3, nothing
// saved or written.
func TestRevokeInterruptedAtPrompt(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	before := fileBytes(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pw.Close() })
	usePromptStreams(t, &actionReader{act: cancel, r: pr}, io.Discard)
	var out, errBuf bytes.Buffer
	if code := runContext(ctx, []string{"revoke", "bob", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) || !strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("an interrupted revoke changed something")
	}
}

// TestRevokeInterruptedBeforeSave: Ctrl-C lands after the confirmation
// (--yes) and before the save — beforeWrite's first step stops the run:
// exit 3, nothing saved or written.
func TestRevokeInterruptedBeforeSave(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	before := fileBytes(t, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	saved := promptStreams
	promptStreams = func(*cobra.Command) (io.Reader, io.Writer, bool) {
		cancel() // the gate is reached; --yes answers without reading
		return strings.NewReader(""), io.Discard, false
	}
	t.Cleanup(func() { promptStreams = saved })
	var out, errBuf bytes.Buffer
	if code := runContext(ctx, []string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "interrupted: context canceled — manifest not saved, nothing written") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) || !strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) ||
		!strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
		t.Error("an interrupted revoke changed something")
	}
}

// TestRevokeInterruptedAfterSave: Ctrl-C lands while the manifest is being
// saved — the save completes (it is not interruptible once started), no
// write starts, and the finish hint names every server not started: exit 1.
func TestRevokeInterruptedAfterSave(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	saved := beforeManifestSave
	beforeManifestSave = func(manifestTarget) { cancel() }
	t.Cleanup(func() { beforeManifestSave = saved })
	var out, errBuf bytes.Buffer
	if code := runContext(ctx, []string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"manifest " + cfg + " updated — commit and push it",
		"manifest updated; 2 servers not converged — finish with: sshepherd apply --config " + cfg + " --known-hosts " + kh + " --server web-1 --server web-2\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if !strings.Contains(errBuf.String(), "interrupted: 2 servers not started") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
	for name, h := range hosts {
		if !strings.Contains(h.keys(t), testkeys.Line(t, 2)) {
			t.Errorf("%s was written after the interrupt", name)
		}
	}
}

func TestRevokeNoApply(t *testing.T) {
	hosts, _, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if want := "no servers contacted — 2 affected servers still carry the old keys; run 'sshepherd apply --config " + cfg + " --server web-1 --server web-2' to push\n"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
	for name, h := range hosts {
		if len(h.srv.Attempts()) != 0 {
			t.Errorf("--no-apply connected to %s", name)
		}
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}

	t.Run("--dry-run --no-apply prints the header and the check line", func(t *testing.T) {
		_, _, cfg := twoUserFleet(t)
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if out.String() != "manifest edit: remove user bob (1 key, 1 access grant) — 2 servers affected\ncheck every server: sshepherd audit --config "+cfg+"\n" {
			t.Errorf("stdout = %q", out.String())
		}
		if !bytes.Equal(fileBytes(t, cfg), before) {
			t.Error("--dry-run --no-apply saved")
		}
	})
}

func TestRevokeOperator(t *testing.T) {
	setup := func(t *testing.T) (editHost, string, string) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		hosts["web-1"].install(t, []byte{2, 1, 3})
		cfg := writeConfig(t, "users:\n  - {name: ops-bot, operator: true, keys: ["+qk(t, 2)+"]}\n"+
			"  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: carol, keys: ["+qk(t, 3)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n  - {user: carol, servers: [web-1]}\n")
		return hosts["web-1"], kh, cfg
	}
	t.Run("mixed targets without --operator: whole command refused", func(t *testing.T) {
		h, kh, cfg := setup(t)
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "carol", "ops-bot", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3", code)
		}
		if !strings.Contains(errBuf.String(), "ops-bot is an operator (fleet-wide, protected); pass --operator to confirm") {
			t.Errorf("stderr = %q", errBuf.String())
		}
		if !bytes.Equal(fileBytes(t, cfg), before) || len(h.srv.Attempts()) != 0 {
			t.Error("a refused revoke edited or connected")
		}
	})
	t.Run("--operator without an operator target", func(t *testing.T) {
		_, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "carol", "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
			!strings.Contains(errBuf.String(), "--operator given but no target is an operator; drop the flag") {
			t.Fatalf("exit = %d, stderr %q", code, errBuf.String())
		}
	})
	t.Run("--operator: header and prompt prefix", func(t *testing.T) {
		h, kh, cfg := setup(t)
		var prompt bytes.Buffer
		usePromptStreams(t, strings.NewReader("y\n"), &prompt)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "ops-bot", "--operator", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), "OPERATOR: ops-bot is an operator (fleet-wide, protected); --operator given") {
			t.Errorf("stdout = %s", out.String())
		}
		if !strings.Contains(prompt.String(), "OPERATOR ops-bot: save manifest edit and write 1 of 1 affected server? [y/N]") {
			t.Errorf("prompt = %q", prompt.String())
		}
		if strings.Contains(h.keys(t), testkeys.Line(t, 2)) {
			t.Error("the operator key is still installed")
		}
	})
	t.Run("--key of an operator's last key clears the flag", func(t *testing.T) {
		_, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "--key", fpOf(t, 2), "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(out.String(), "note: ops-bot has no keys left, so its operator flag is cleared") {
			t.Errorf("stdout = %s", out.String())
		}
		saved := readCfg(t, cfg)
		if saved.Users[0].Name != "ops-bot" || saved.Users[0].Operator || len(saved.Users[0].Keys) != 0 {
			t.Errorf("ops-bot = %+v, want a keyless non-operator", saved.Users[0])
		}
	})
}

// TestRevokeKeyLeavesUngrantedDrift: bob's key is also installed on web-2,
// which never granted it — revoke --key contacts only web-1, so web-2
// keeps it, and the scope line says so.
func TestRevokeKeyLeavesUngrantedDrift(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1]}\n")
	pub := filepath.Join(t.TempDir(), "bob.pub")
	if err := os.WriteFile(pub, []byte(testkeys.Line(t, 2)+" bob@laptop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", pub, "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"manifest edit: remove key " + fpOf(t, 2) + " from bob — 1 server affected\n",
		"note: bob has no keys left — 'sshepherd revoke bob --config " + cfg + " --known-hosts " + kh + "' removes the user\n",
		"check every server: sshepherd audit --config " + cfg + " --known-hosts " + kh + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if len(hosts["web-2"].srv.Attempts()) != 0 || !strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
		t.Error("web-2 was contacted or changed")
	}
	if strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("web-1 still holds the revoked key")
	}
}

// A real user name is always that user — even when it reads like an option
// word, a key-type prefix, a hex-colon pair or has a space.
func TestRevokeUserNamedLikeKey(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, name := range []string{"tunnel", "pty", "Alice Smith", "ssh-rsa-legacy", "ab:cd"} {
		t.Run(name, func(t *testing.T) {
			cfg := writeConfig(t, "users:\n  - {name: \""+name+"\", keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n")
			var out, errBuf bytes.Buffer
			if code := run([]string{"revoke", name, "--config", cfg, "--no-apply", "--yes"}, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d, want 0\n%s", code, errBuf.String())
			}
			for _, u := range readCfg(t, cfg).Users {
				if u.Name == name {
					t.Errorf("user %q still in the manifest", name)
				}
			}
		})
	}
}

func TestRevokeUsage(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	cfgBody := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n"
	tests := []struct {
		name string
		args []string
		body string
		want string
	}{
		{"no target", []string{"revoke"}, cfgBody, "nothing to revoke"},
		{"users and --key", []string{"revoke", "bob", "--key", fpOf(t, 2)}, cfgBody, "users or --key, not both"},
		{"user that looks like a key", []string{"revoke", fpOf(t, 2)}, cfgBody, "looks like a key — did you mean --key?"},
		{"unknown option word", []string{"revoke", "tunnel"}, cfgBody, "tunnel looks like a key — did you mean --key?"},
		{"unknown option word with --server", []string{"revoke", "tunnel", "--server", "web-1"}, cfgBody, "tunnel looks like a key — did you mean --key?"},
		{"--dry-run with --yes", []string{"revoke", "bob", "--dry-run", "--yes"}, cfgBody, "dry-run"},
		{"--no-apply with --identity", []string{"revoke", "bob", "--no-apply", "--identity", "/k/id"}, cfgBody, "--no-apply contacts no server, so --identity would be unused"},
		{"--no-apply with --known-hosts", []string{"revoke", "bob", "--no-apply", "--known-hosts", "/x"}, cfgBody, "--known-hosts would be unused"},
		{"--no-apply with --parallel", []string{"revoke", "bob", "--no-apply", "--parallel", "2"}, cfgBody, "--parallel would be unused"},
		{"--no-apply with --offer-all-keys", []string{"revoke", "bob", "--no-apply", "--offer-all-keys"}, cfgBody, "--offer-all-keys would be unused"},
		{"unknown users listed", []string{"revoke", "carol", "bob", "dave"}, cfgBody,
			"unknown users: carol, dave — not in the manifest (already revoked?); see what is left to push with 'sshepherd apply --dry-run --config CFG', verify with 'sshepherd audit --config CFG'"},
		{"malformed --key", []string{"revoke", "--key", "SHA256:nope"}, cfgBody, "malformed fingerprint"},
		{"anchors cannot be edited", []string{"revoke", "bob"}, "users: &u []\nservers: []\naccess: []\n",
			"cannot edit CFG: manifest contains a YAML anchor or alias (line 1); comment-preserving edits do not support them — edit the manifest by hand and run 'sshepherd apply --config CFG'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, tt.body)
			before := fileBytes(t, cfg)
			var out, errBuf bytes.Buffer
			args := append(append([]string{}, tt.args...), "--config", cfg)
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
			}
			if want := strings.ReplaceAll(tt.want, "CFG", cfg); !strings.Contains(errBuf.String(), want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), want)
			}
			if !bytes.Equal(fileBytes(t, cfg), before) {
				t.Error("a usage error changed the manifest")
			}
		})
	}
	t.Run("missing manifest", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--config", filepath.Join(t.TempDir(), "none.yaml")}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3", code)
		}
	})
}
