package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// writePub writes a .pub file holding line and returns its path.
func writePub(t *testing.T, name, line string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRotateOwnKeyWithNewIdentity: alice rotates the key the agent logs in
// with; the new private key is passed with --identity so the guard and
// the post-write probe can use it. The old line's options and inline
// comment carry over (the new .pub has no comment).
func TestRotateOwnKeyWithNewIdentity(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1, 5}, "web-1")
	h := hosts["web-1"]
	h.install(t, nil, "no-pty "+testkeys.Line(t, 1)+" alice@old")
	cfg := writeConfig(t, "users:\n  - name: alice\n    keys:\n      # alice's laptop\n      - 'no-pty "+testkeys.Line(t, 1)+" alice@old'\n"+
		"servers:\n"+h.line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
	newKey := sshtest.WriteKeyFile(t, t.TempDir(), "id_new", sshtest.Key(5), nil)
	var out, errBuf bytes.Buffer
	code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newKey + ".pub", "--yes",
		"--config", cfg, "--known-hosts", kh, "--identity", newKey}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"manifest edit: rotate alice key " + fpOf(t, 1) + " → " + fpOf(t, 5) + " — 1 server affected\n",
		"alice (rotated out)",
		"removes the key this session logged in with",
		"web-1: applied · verified",
		"scope: only servers whose grants changed were contacted (1 of 1)",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	wantLine := "no-pty " + testkeys.Line(t, 5) + " alice@old"
	if got := readCfg(t, cfg).Users[0].Keys; len(got) != 1 || got[0] != wantLine {
		t.Errorf("manifest keys = %q, want [%q]", got, wantLine)
	}
	if !strings.Contains(string(fileBytes(t, cfg)), "# alice's laptop") {
		t.Error("the key's head comment was lost")
	}
	if got := h.keys(t); !strings.Contains(got, wantLine) || strings.Contains(got, testkeys.Line(t, 1)) {
		t.Errorf("authorized_keys = %q, want only the new key", got)
	}
	// The server accepts both keys, so each dial's first offer is the one
	// it logs in with: the read and the write prefer what is installed now
	// (the old config's grant, k1 from the agent) over the key file the
	// credentials list first (k5); the probe offers only the survivor (k5).
	if got, want := h.srv.Attempts(), []string{fpOf(t, 1), fpOf(t, 1), fpOf(t, 5)}; !slices.Equal(got, want) {
		t.Errorf("offered keys = %q, want %q (read, write: old grant first; probe: survivor)", got, want)
	}
}

// TestRotateCommentRule: the new key's comment wins; without one, the old
// line's inline comment; operator: true is kept.
func TestRotateCommentRule(t *testing.T) {
	body := "users:\n  - {name: ops, operator: true, keys: ['" + testkeys.Line(t, 1) + " ops@old']}\n"
	for _, tt := range []struct {
		name, newLine, want string
	}{
		{"new comment wins", testkeys.Line(t, 5) + " ops@new", testkeys.Line(t, 5) + " ops@new"},
		{"old comment kept", testkeys.Line(t, 5), testkeys.Line(t, 5) + " ops@old"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, body)
			var out, errBuf bytes.Buffer
			code := run([]string{"rotate", "ops", "--old", fpOf(t, 1), "--new", writePub(t, "n.pub", tt.newLine),
				"--operator", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf)
			if code != 0 {
				t.Fatalf("exit = %d\n%s", code, errBuf.String())
			}
			u := readCfg(t, cfg).Users[0]
			if !u.Operator || len(u.Keys) != 1 || u.Keys[0] != tt.want {
				t.Errorf("ops = %+v, want operator with [%q]", u, tt.want)
			}
			if !strings.Contains(out.String(), "OPERATOR: ops is an operator") || !strings.Contains(out.String(), "no servers contacted — no server's desired keys changed") {
				t.Errorf("stdout = %s", out.String())
			}
		})
	}
}

// TestRotateKeepsExpiry: a future expiry-time= carries over and is named
// in the header; a passed one refuses before any edit.
func TestRotateKeepsExpiry(t *testing.T) {
	saved := rotateNow
	rotateNow = func() time.Time { return time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { rotateNow = saved })
	mk := func(expiry string) string {
		return writeConfig(t, "users:\n  - {name: deploy, keys: ['expiry-time=\""+expiry+"\" "+testkeys.Line(t, 1)+"']}\n")
	}
	newPub := writePub(t, "n.pub", testkeys.Line(t, 5))

	cfg := mk("20990101")
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "deploy", "--old", fpOf(t, 1), "--new", newPub, "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `(keeps expiry-time="20990101") — no servers affected`) {
		t.Errorf("stdout = %s", out.String())
	}

	cfg = mk("20200101")
	before := fileBytes(t, cfg)
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"rotate", "deploy", "--old", fpOf(t, 1), "--new", newPub, "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), `the old line's expiry-time="20200101" has passed; the new key would be rejected by sshd — update or remove expiry-time in the manifest first`) {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("a refused rotation edited the manifest")
	}
}

func TestRotateRefusals(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	body := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: ops, operator: true, keys: [" + qk(t, 3) + "]}\n"
	newPub := writePub(t, "n.pub", testkeys.Line(t, 5))
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no USER", []string{"rotate", "--old", fpOf(t, 1), "--new", newPub}, "rotate takes exactly one USER (got 0)"},
		{"two USERs", []string{"rotate", "alice", "bob", "--old", fpOf(t, 1), "--new", newPub}, "rotate takes exactly one USER (got 2)"},
		{"missing --new", []string{"rotate", "alice", "--old", fpOf(t, 1)}, "rotate needs both --old KEY and --new KEY"},
		{"--old twice", []string{"rotate", "alice", "--old", fpOf(t, 1), "--old", fpOf(t, 2), "--new", newPub}, "rotate takes exactly one --old (got 2)"},
		{"--new twice", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub, "--new", testkeys.Line(t, 6)}, "rotate takes exactly one --new (got 2)"},
		{"--new as a fingerprint", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", fpOf(t, 5)}, "a fingerprint carries no key"},
		{"options on --new", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", "restrict " + testkeys.Line(t, 5)}, "rotate keeps the old line's options; edit them in the manifest"},
		{"unknown user", []string{"rotate", "carol", "--old", fpOf(t, 1), "--new", newPub}, "unknown user: carol"},
		{"--old owned by someone else", []string{"rotate", "alice", "--old", fpOf(t, 2), "--new", newPub}, "--old " + fpOf(t, 2) + " belongs to bob, not alice"},
		{"--old not in the manifest", []string{"rotate", "alice", "--old", fpOf(t, 9), "--new", newPub}, "--old " + fpOf(t, 9) + " is not in the manifest"},
		{"--new already owned", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", testkeys.Line(t, 2)}, "is already in the manifest (owned by bob)"},
		{"--new same as --old", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", testkeys.Line(t, 1)}, "--new is the same key as --old"},
		{"operator without --operator", []string{"rotate", "ops", "--old", fpOf(t, 3), "--new", newPub}, "ops is an operator (fleet-wide, protected); pass --operator to confirm"},
		{"--operator on a non-operator", []string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub, "--operator"}, "--operator given but no target is an operator"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, body)
			var out, errBuf bytes.Buffer
			args := append(append([]string{}, tt.args...), "--no-apply", "--yes", "--config", cfg)
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), tt.want)
			}
			if !bytes.Equal(fileBytes(t, cfg), []byte(body)) {
				t.Error("a refused rotation edited the manifest")
			}
		})
	}
}
