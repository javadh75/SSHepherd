package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// appendKey adds one raw line to h's authorized_keys, header kept.
func appendKey(t *testing.T, h editHost, line string) {
	t.Helper()
	p := filepath.Join(h.home, ".ssh", "authorized_keys")
	cur, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, append(cur, []byte(line+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestApplyStaleCopyCannotBumpPastRefusal (PRD-2): a copy taken before a
// revoke is refused on the revoked server. A stray key elsewhere must not
// let that same run bump the copy past the refusing serial, or the next
// apply from the copy re-grants the revoked key with no hand edit.
func TestApplyStaleCopyCannotBumpPastRefusal(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "x", "z")
	hosts["x"].install(t, []byte{1, 2})
	hosts["z"].install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["x"].line("x")+hosts["z"].line("z")+
		"access:\n  - {user: alice, servers: [x, z]}\n  - {user: bob, servers: [x]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("seed apply: exit %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	stale := writeConfig(t, string(fileBytes(t, cfg)))
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("revoke: exit %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	appendKey(t, hosts["z"], testkeys.Line(t, 9)+" stray")

	out.Reset()
	if code := run([]string{"apply", "--dry-run", "--config", stale, "--known-hosts", kh}, &out, &errBuf); code != 1 || strings.Contains(out.String(), "would bump serial") {
		t.Fatalf("dry run: exit %d, want 1 and no would-bump line\n%s", code, out.String())
	}
	for i := range 2 {
		out.Reset()
		if code := run([]string{"apply", "--yes", "--config", stale, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("apply %d from the stale copy: exit %d, want 1 (x refused)\n%s\n%s", i, code, out.String(), errBuf.String())
		}
		if !strings.Contains(out.String(), "written by manifest serial 1, this manifest is 0") || strings.Contains(out.String(), "manifest serial:") {
			t.Errorf("apply %d: want the refusal and no bump:\n%s", i, out.String())
		}
		if got := readCfg(t, stale).Serial(); got != 0 {
			t.Fatalf("apply %d lifted the stale copy to serial %d", i, got)
		}
		if strings.Contains(hosts["x"].keys(t), testkeys.Line(t, 2)) {
			t.Fatalf("apply %d re-granted bob's revoked key on x:\n%s", i, hosts["x"].keys(t))
		}
	}
}

// TestApplySerialStoreFailureExit3 (spec §6): a failed save at the store
// itself — the lock sidecar is a symlink — stops the run: exit 3, nothing
// written, the manifest untouched.
func TestApplySerialStoreFailureExit3(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	h := hosts["web-1"]
	h.install(t, nil, authkeys.Header(0), testkeys.Line(t, 1)+" alice", testkeys.Line(t, 9)+" stray")
	before := h.keys(t)
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
		"servers:\n"+h.line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
	resolved, err := filepath.EvalSymlinks(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere"), manifest.LockPath(resolved)); err != nil {
		t.Fatal(err)
	}
	manifestBefore := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), "symlink") {
		t.Fatalf("exit = %d, want 3 with the lock refusal\n%s\n%s", code, out.String(), errBuf.String())
	}
	if h.keys(t) != before || !bytes.Equal(fileBytes(t, cfg), manifestBefore) {
		t.Error("a failed serial save wrote the server or the manifest")
	}
}
