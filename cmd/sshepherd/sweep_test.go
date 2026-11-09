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

// TestRevokeUnownedKeySweepJSON: D1b's save-only path under --json still
// exits 2 for a key the sweep found, with the document as the only output.
func TestRevokeUnownedKeySweepJSON(t *testing.T) {
	hosts, kh, cfg := sweepFleet(t)
	hosts["web-2"].install(t, []byte{1, 9})
	var out, errBuf bytes.Buffer
	code := run([]string{"revoke", "--key", fpOf(t, 9), "--sweep", "--yes", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 2 {
		t.Fatalf("exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
	}
	var doc struct {
		Edit struct {
			Saved bool `json:"saved"`
		} `json:"edit"`
		Summary struct {
			ExitCode int `json:"exit_code"`
		} `json:"summary"`
		Sweep apply.SweepReport `json:"sweep"`
	}
	oneJSONDoc(t, out.String())
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Edit.Saved || doc.Summary.ExitCode != 2 {
		t.Errorf("document = %s", out.String())
	}
	want := []apply.SweepHit{{Server: "web-2", Fingerprint: fpOf(t, 9), File: "authorized_keys"}}
	if !reflect.DeepEqual(doc.Sweep.StillInstalled, want) {
		t.Errorf("still_installed = %+v, want %+v", doc.Sweep.StillInstalled, want)
	}
}

// doneFleet: alice (k1, the agent's key) and bob (k2) granted web-1 and
// web-2 and applied, then web-2 hand-brought to exactly what revoking bob
// renders (serial 1): that revoke writes web-1 and finds web-2 converged.
func doneFleet(t *testing.T) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [web-1, web-2]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("seed apply: exit %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	var b strings.Builder
	b.WriteString(authkeys.Header(1) + "\n")
	for _, l := range strings.SplitAfter(hosts["web-2"].keys(t), "\n")[1:] {
		if !strings.Contains(l, testkeys.Line(t, 2)) {
			b.WriteString(l)
		}
	}
	if err := os.WriteFile(filepath.Join(hosts["web-2"].home, ".ssh", "authorized_keys"), []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return hosts, kh, cfg
}

// TestRevokeSweepNothingLeftToRead (spec §7): when every server was applied
// or found converged, --sweep has no target. It must not fall through to
// audit.Run, which reads the whole fleet on an empty server list: no login
// beyond the same revoke without --sweep, and a report of 0 swept.
func TestRevokeSweepNothingLeftToRead(t *testing.T) {
	revoke := func(t *testing.T, extra ...string) (int, map[string]int, string) {
		t.Helper()
		hosts, kh, cfg := doneFleet(t)
		before := map[string]int{"web-1": len(hosts["web-1"].srv.Attempts()), "web-2": len(hosts["web-2"].srv.Attempts())}
		var out, errBuf bytes.Buffer
		code := run(append([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, extra...), &out, &errBuf)
		if !strings.Contains(out.String(), "web-1: applied") {
			t.Fatalf("web-1 must be applied: exit %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		return code, map[string]int{
			"web-1": len(hosts["web-1"].srv.Attempts()) - before["web-1"],
			"web-2": len(hosts["web-2"].srv.Attempts()) - before["web-2"],
		}, out.String()
	}
	_, plain, _ := revoke(t)
	code, swept, out := revoke(t, "--sweep")
	if code != 0 {
		t.Fatalf("exit = %d, want 0\n%s", code, out)
	}
	if !reflect.DeepEqual(swept, plain) {
		t.Errorf("logins with --sweep = %v, without = %v: the sweep read a server it had no reason to", swept, plain)
	}
	if !strings.Contains(out, "swept 0 of 2 servers: 0 still have a revoked key, 0 unreachable\n") {
		t.Errorf("want the empty sweep's report:\n%s", out)
	}
	for _, unwanted := range []string{"REVOKED KEY STILL INSTALLED", "cannot prove removal"} {
		if strings.Contains(out, unwanted) {
			t.Errorf("false report %q:\n%s", unwanted, out)
		}
	}
}

// TestRevokeServerSweepAddsNoServers (spec §7): an access tombstone only
// names servers the run already wrote, so revoke USER --from-server NAME --sweep
// has no key to look for and contacts nothing beyond the affected server.
func TestRevokeServerSweepAddsNoServers(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2", "web-3")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, []byte{1, 2})
	hosts["web-3"].install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+hosts["web-3"].line("web-3")+
		"access:\n  - {user: alice, servers: [web-1, web-2, web-3]}\n  - {user: bob, servers: [web-1, web-2]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "web-1: applied") {
		t.Errorf("web-1 must be applied:\n%s", out.String())
	}
	if strings.Contains(out.String(), "swept ") {
		t.Errorf("an access tombstone must not start a sweep:\n%s", out.String())
	}
	for _, name := range []string{"web-2", "web-3"} {
		if n := len(hosts[name].srv.Attempts()); n != 0 {
			t.Errorf("%s saw %d login attempts; the run affects web-1 only", name, n)
		}
	}
}
