package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func mustKey(t *testing.T, seed byte) authkeys.Key {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatal(err)
	}
	return *k
}

func TestSweepTargets(t *testing.T) {
	cfg := &config.Config{Servers: []config.Server{{Name: "a"}, {Name: "b"}, {Name: "c"}, {Name: "d"}}}
	plans := []apply.ServerPlan{
		{Server: config.Server{Name: "a"}, Class: apply.ClassChange, Outcome: apply.OutcomeApplied},
		{Server: config.Server{Name: "b"}, Class: apply.ClassConverged},
		{Server: config.Server{Name: "c"}, Class: apply.ClassUnreachable},
	}
	var names []string
	for _, s := range sweepTargets(cfg, plans) {
		names = append(names, s.Name)
	}
	if !reflect.DeepEqual(names, []string{"c", "d"}) {
		t.Errorf("targets = %v, want [c d] (an unreachable affected server is swept again)", names)
	}
}

func TestClassifySweep(t *testing.T) {
	bob, stray := mustKey(t, 2), mustKey(t, 9)
	tombs := []config.Tombstone{{Fingerprint: bob.Fingerprint, User: "bob", Date: "2026-11-08"}, {User: "x", Servers: []string{"db-1"}, Date: "2026-11-08"}}
	results := []audit.ServerResult{
		{Server: config.Server{Name: "db-1"}, Diff: authkeys.Result{Unauthorized: []authkeys.Key{bob, stray}}},
		{Server: config.Server{Name: "db-2"}, AuthorizedKeys2: true, Keys2: []byte(testkeys.Line(t, 2) + "\n")},
		{Server: config.Server{Name: "db-3"}, Err: errors.New("dial: refused")},
		{Server: config.Server{Name: "db-4"}, AuthorizedKeys2: true, Keys2Err: errors.New("exit 1")},
		{Server: config.Server{Name: "db-5"}, AuthorizedKeys2: true, Keys2: []byte("not a key\n")},
	}
	got := classifySweep(results, tombs)
	want := apply.SweepReport{
		Checked: 5,
		StillInstalled: []apply.SweepHit{
			{Server: "db-1", Fingerprint: bob.Fingerprint, User: "bob", File: "authorized_keys"},
			{Server: "db-2", Fingerprint: bob.Fingerprint, User: "bob", File: "authorized_keys2"},
		},
		Unreachable: []string{"db-3"},
		Unprovable: []apply.SweepUnprovable{
			{Server: "db-4", Reason: "authorized_keys2 unreadable"},
			{Server: "db-5", Reason: "authorized_keys2 unreadable"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("report = %+v\nwant   %+v", got, want)
	}
}

func TestRenderSweep(t *testing.T) {
	cfg, err := config.Parse([]byte("users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: db-2, host: h2, user: u}\n  - {name: db-7, host: h7, user: u}\n  - {name: db-9, host: h9, user: u}\n" +
		"access:\n  - {user: alice, servers: [db-2, db-7]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	fp := mustKey(t, 2).Fingerprint
	rep := apply.SweepReport{Checked: 3,
		StillInstalled: []apply.SweepHit{
			{Server: "db-2", Fingerprint: fp, User: "bob", File: "authorized_keys"},
			{Server: "db-7", Fingerprint: fp, User: "bob", File: "authorized_keys"},
			{Server: "db-9", Fingerprint: fp, User: "bob", File: "authorized_keys"},
		},
		Unprovable: []apply.SweepUnprovable{{Server: "db-7", Reason: "authorized_keys2 unreadable"}},
	}
	var b bytes.Buffer
	renderSweep(&b, rep, cfg, followUp{config: "--config f.yaml"}, 4)
	want := "REVOKED KEY STILL INSTALLED: bob " + fp + " on db-2, db-7 — run 'sshepherd apply --config f.yaml --server db-2 --server db-7'\n" +
		"REVOKED KEY STILL INSTALLED: bob " + fp + " on db-9 — remove it by hand or grant another user there first\n" +
		"cannot prove removal on db-7 (authorized_keys2 unreadable)\n" +
		"swept 3 of 4 servers: 3 still have a revoked key, 0 unreachable\n"
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}

// sweepFleet: alice (k1, the agent's key) on web-1 and web-2; bob (k2)
// granted web-1 only, with a hand copy of his key on web-2.
func sweepFleet(t *testing.T) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1]}\n")
	return hosts, kh, cfg
}

func TestRevokeSweepFindsStrayExit2(t *testing.T) {
	_, kh, cfg := sweepFleet(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"web-1: applied · verified",
		"REVOKED KEY STILL INSTALLED: bob " + fpOf(t, 2) + " on web-2 — run 'sshepherd apply --config " + cfg + " --known-hosts " + kh + " --server web-2'\n",
		"swept 1 of 2 servers: 1 still has a revoked key, 0 unreachable\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "check every server:") {
		t.Error("the check line prints only when no sweep ran")
	}
}

func TestRevokeSweepFindsKeyInKeys2(t *testing.T) {
	hosts, kh, cfg := sweepFleet(t)
	hosts["web-2"].install(t, []byte{1})
	if err := os.WriteFile(filepath.Join(hosts["web-2"].home, ".ssh", "authorized_keys2"), []byte(testkeys.Line(t, 2)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "REVOKED KEY STILL INSTALLED (authorized_keys2): bob "+fpOf(t, 2)+" on web-2") {
		t.Errorf("stdout:\n%s", out.String())
	}
}

func TestSweepSkippedOnDryRunAndNoApply(t *testing.T) {
	for _, mode := range [][]string{{"--dry-run"}, {"--no-apply", "--yes"}} {
		hosts, kh, cfg := sweepFleet(t)
		args := append([]string{"revoke", "bob", "--sweep", "--config", cfg}, mode...)
		if mode[0] == "--dry-run" {
			args = append(args, "--known-hosts", kh)
		}
		var out, errBuf bytes.Buffer
		run(args, &out, &errBuf)
		if len(hosts["web-2"].srv.Attempts()) != 0 || strings.Contains(out.String(), "swept ") {
			t.Errorf("%v: the sweep ran\n%s", mode, out.String())
		}
		if !strings.Contains(out.String(), "check every server: sshepherd audit --config "+cfg) {
			t.Errorf("%v: the skipped sweep must print the audit command\n%s", mode, out.String())
		}
	}
}

func TestRevokeSweepUnreachable(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2})
	closed := closedPort(t) // adopt_test.go's helper: a just-released local port
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+fmt.Sprintf("  - {name: web-3, host: 127.0.0.1, port: %d, user: deploy}\n", closed)+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (the sweep could not read web-3)\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "cannot prove removal on web-3 (unreachable)\n") || !strings.Contains(out.String(), "1 unreachable\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
}

// TestRevokeSweepDefaultFlags: with the default --config (sshepherd.yaml
// in the working directory) and --known-hosts (~/.ssh/known_hosts) the
// sweep's hint carries no flags — the form the README shows; Task 40
// Step 3 copies the README sample from this test's log.
func TestRevokeSweepDefaultFlags(t *testing.T) {
	_, kh, cfg := sweepFleet(t)
	home, dir := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), fileBytes(t, kh), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sshepherd.yaml"), fileBytes(t, cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Chdir(dir)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"REVOKED KEY STILL INSTALLED: bob " + fpOf(t, 2) + " on web-2 — run 'sshepherd apply --server web-2'\n",
		"swept 1 of 2 servers: 1 still has a revoked key, 0 unreachable\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	t.Logf("stdout (the README sample):\n%s", out.String())
}

// TestRevokeUnownedKeySweep: D1b's save-only path sweeps every server.
func TestRevokeUnownedKeySweep(t *testing.T) {
	hosts, kh, cfg := sweepFleet(t)
	hosts["web-2"].install(t, []byte{1, 9})
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", fpOf(t, 9), "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "REVOKED KEY STILL INSTALLED: "+fpOf(t, 9)+" on web-2") || !strings.Contains(out.String(), "swept 2 of 2 servers") {
		t.Errorf("stdout:\n%s", out.String())
	}
}

func TestRevokeSweepJSON(t *testing.T) {
	_, kh, cfg := sweepFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s", code, errBuf.String())
	}
	var doc struct {
		Edit    map[string]any `json:"edit"`
		Summary struct {
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
		Sweep struct {
			StillInstalled []map[string]string `json:"still_installed"`
		} `json:"sweep"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not one document: %v\n%s", err, out.String())
	}
	if doc.Summary.ExitCode != 2 || len(doc.Sweep.StillInstalled) != 1 || doc.Sweep.StillInstalled[0]["server"] != "web-2" {
		t.Errorf("document = %s", out.String())
	}
	if _, ok := doc.Edit["check_command"]; ok {
		t.Error("check_command is present only when --sweep was not given")
	}
}
