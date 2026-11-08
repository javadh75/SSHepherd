package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestApplyBumpsSerialOnHandRemoval (D4b): a confirmed apply that removes
// a key from a server whose header serial is not above the manifest's
// bumps serial: once, saves it before the first write, and writes the new
// serial; --dry-run only says it would.
func TestApplyBumpsSerialOnHandRemoval(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	target := filepath.Join(home, ".ssh", "authorized_keys")
	cur, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, append(cur, []byte(testkeys.Line(t, 9)+" handed\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 ||
		!strings.Contains(out.String(), "would bump serial: 0 → 1 (this apply removes keys)\n") || !bytes.Equal(fileBytes(t, cfg), before) {
		t.Fatalf("dry-run: exit %d\n%s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "manifest serial: 0 → 1 (saved; this apply removes keys)\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
	if readCfg(t, cfg).Serial() != 1 {
		t.Error("serial not saved")
	}
	if got, _ := os.ReadFile(target); !strings.HasPrefix(string(got), authkeys.Header(1)+"\n") {
		t.Errorf("server file = %q, want the (serial 1) header", got)
	}
}

// TestApplySerialSaveUnavailable: a pipe and an anchored manifest (plan
// decision 8) cannot be saved in place — and the dry run classifies them
// the same way, so it warns instead of promising a bump.
func TestApplySerialSaveUnavailable(t *testing.T) {
	if _, err := saveSerialBump(manifestTarget{manifest.Store{Stream: true}}); !errors.Is(err, errNoSerialSave) {
		t.Errorf("stream: err = %v, want errNoSerialSave", err)
	}
	anchored := writeConfig(t, "users: &u []\nservers: []\naccess: []\n")
	m, err := readManifest(anchored)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := saveSerialBump(m); !errors.Is(err, errNoSerialSave) {
		t.Errorf("anchored manifest: err = %v, want errNoSerialSave", err)
	}
	cfg, err := config.Parse(m.Loaded)
	if err != nil {
		t.Fatal(err)
	}
	removal := []apply.ServerPlan{{Class: apply.ClassChange, Remove: []authkeys.Key{{Fingerprint: "SHA256:x"}}}}
	if b := dryRunBump(m, cfg, removal); b == nil || b.To != nil || b.Warning != noBumpWarning {
		t.Errorf("dry run on an anchored manifest = %+v, want the no-bump warning (as the real run)", b)
	}
}

// TestApplySerialSaveFailsExit3 (spec §6, §8, §9): a D4b save that fails —
// here BumpSerial at the upper bound — is exit 3 with nothing written,
// and under --json no document.
func TestApplySerialSaveFailsExit3(t *testing.T) {
	for _, extra := range [][]string{nil, {"--json"}} {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		h := hosts["web-1"]
		h.install(t, nil, authkeys.Header(authkeys.MaxHeaderSerial), testkeys.Line(t, 1)+" alice", testkeys.Line(t, 9)+" stray")
		before := h.keys(t)
		cfg := writeConfig(t, "serial: 9007199254740991\nusers:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
			"servers:\n"+h.line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
		manifestBefore := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		args := append([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, extra...)
		if code := run(args, &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), "cannot be bumped") {
			t.Fatalf("%v: exit = %d, want 3 with the bound error\n%s\n%s", extra, code, out.String(), errBuf.String())
		}
		if h.keys(t) != before || !bytes.Equal(fileBytes(t, cfg), manifestBefore) {
			t.Errorf("%v: a failed serial save wrote the server or the manifest", extra)
		}
		if len(extra) > 0 && out.Len() != 0 {
			t.Errorf("--json wrote a document on exit 3:\n%s", out.String())
		}
	}
}
