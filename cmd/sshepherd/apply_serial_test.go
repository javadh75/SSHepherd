package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
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

// bumpOverLimit is a hermetic fleet where one extra installed key forces a
// D4b bump and alice's comment leaves the render 5 bytes under the limit,
// so the bump's 11-byte header growth would overflow it.
func bumpOverLimit(t *testing.T) (cfg, kh, target string) {
	t.Helper()
	home := shortHome(t)
	srv, hostKey, c := hermeticFleet(t, home)
	kh = sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	target = filepath.Join(home, ".ssh", "authorized_keys")
	line := strings.TrimSpace(string(fileBytes(t, target)))
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("ParseLine: %v", err)
	}
	base, err := authkeys.RenderSerial([]authkeys.RenderEntry{{Key: *k, Comment: "x"}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	pad := strings.Repeat("x", 1+fleet.MaxRemoteOutput-5-len(base))
	text := strings.Replace(string(fileBytes(t, c)), `keys: ["`+line+`"]`, `keys: ["`+line+` `+pad+`"]`, 1)
	if err := os.WriteFile(c, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte(line+"\n"+testkeys.Line(t, 9)+" handed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return c, kh, target
}

// TestOversizedBumpOnlyForABumpThatHappens (spec §7): a render the bumped
// header would overflow withholds the run only when the run would bump and
// can save it. Without a bump the header does not grow.
func TestOversizedBumpOnlyForABumpThatHappens(t *testing.T) {
	head := authkeys.Header(0)
	rendered := []byte(head + "\n" + strings.Repeat("k", fleet.MaxRemoteOutput-5-len(head)-1))
	srv := config.Server{Name: "web-1"}
	removal := apply.ServerPlan{Server: srv, Class: apply.ClassChange, Remove: []authkeys.Key{{Fingerprint: "SHA256:x"}}, Rendered: rendered}
	addOnly := apply.ServerPlan{Server: srv, Class: apply.ClassChange, Rendered: rendered}
	target := func(t *testing.T, text string) manifestTarget {
		t.Helper()
		m, err := readManifest(writeConfig(t, text))
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	const editable = "users: []\nservers: []\naccess: []\n"
	const anchored = "users: &u []\nservers: []\naccess: []\n"
	for _, tt := range []struct {
		name     string
		m        manifestTarget
		plan     apply.ServerPlan
		withheld bool
	}{
		{"a removal on an editable manifest", target(t, editable), removal, true},
		{"no removal means no bump", target(t, editable), addOnly, false},
		{"an anchored manifest gets no bump", target(t, anchored), removal, false},
		{"a piped manifest gets no bump", manifestTarget{manifest.Store{Stream: true}}, removal, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			pa := &plainApply{m: tt.m, cfg: &config.Config{}}
			if got := pa.oversizedBump([]apply.ServerPlan{tt.plan}); (len(got) > 0) != tt.withheld {
				t.Errorf("oversizedBump = %q, want withheld %v", got, tt.withheld)
			}
		})
	}
}

// TestReserialOversizeWithholdsBeforeSave (spec §7): nothing saved or
// written, exit 1, the message on stderr and in serial_bump.warning; a dry
// run reports the same warning.
func TestReserialOversizeWithholdsBeforeSave(t *testing.T) {
	const wantMsg = "web-1: the serial bump to 1 would make the rendered file"
	cfg, kh, target := bumpOverLimit(t)
	manifestBefore, serverBefore := fileBytes(t, cfg), fileBytes(t, target)
	unchanged := func(t *testing.T) {
		t.Helper()
		if !bytes.Equal(fileBytes(t, cfg), manifestBefore) || !bytes.Equal(fileBytes(t, target), serverBefore) {
			t.Error("a withheld run changed the manifest or the server")
		}
	}
	warning := func(t *testing.T, out []byte) {
		t.Helper()
		var doc struct {
			SerialBump struct {
				To      *uint64 `json:"to"`
				Warning string  `json:"warning"`
			} `json:"serial_bump"`
		}
		if err := json.Unmarshal(out, &doc); err != nil {
			t.Fatalf("json: %v", err)
		}
		if doc.SerialBump.To != nil || !strings.Contains(doc.SerialBump.Warning, wantMsg) {
			t.Errorf("serial_bump = %+v", doc.SerialBump)
		}
	}
	t.Run("text", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(errBuf.String(), wantMsg) || !strings.Contains(errBuf.String(), "nothing saved or written") {
			t.Errorf("stderr = %.400s", errBuf.String())
		}
		unchanged(t)
	})
	t.Run("json", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		warning(t, out.Bytes())
		unchanged(t)
	})
	t.Run("dry run", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if !strings.Contains(errBuf.String(), wantMsg) || strings.Contains(out.String(), "would bump serial") {
			t.Errorf("a dry run must warn instead of promising the bump\nstdout %.400s\nstderr %.400s", out.String(), errBuf.String())
		}
		out.Reset()
		if code := run([]string{"apply", "--json", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("json dry run exit = %d", code)
		}
		warning(t, out.Bytes())
		unchanged(t)
	})
}
