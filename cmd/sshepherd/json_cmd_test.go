package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestJSONNeedsDryRunOrYes: every write command refuses --json without
// --dry-run/--yes, exit 3, before the manifest is read (a missing manifest
// would otherwise be the error) and with nothing on stdout — also for a
// readable manifest with zero targets, which would otherwise exit 0.
func TestJSONNeedsDryRunOrYes(t *testing.T) {
	empty := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n")
	for _, args := range [][]string{
		{"apply", "--json", "--config", "/nonexistent.yaml"},
		{"apply", "--json", "--config", empty},
		{"revoke", "bob", "--json", "--config", "/nonexistent.yaml"},
		{"revoke", "bob", "--json", "--no-apply", "--config", "/nonexistent.yaml"},
		{"rotate", "bob", "--old", "SHA256:x", "--new", "/x.pub", "--json", "--config", "/nonexistent.yaml"},
	} {
		var out, errBuf bytes.Buffer
		if code := run(args, &out, &errBuf); code != 3 {
			t.Errorf("%v: exit = %d, want 3", args, code)
		}
		if !strings.Contains(errBuf.String(), "--json needs --dry-run or --yes (a script cannot answer the confirmation prompt)") {
			t.Errorf("%v: stderr = %q", args, errBuf.String())
		}
		if out.Len() != 0 {
			t.Errorf("%v: stdout = %q, want empty", args, out.String())
		}
	}
}

// oneJSONDoc asserts stdout is exactly one JSON value and returns it.
func oneJSONDoc(t *testing.T, stdout string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
	}
	if dec.More() {
		t.Fatalf("stdout carries more than one JSON value:\n%s", stdout)
	}
	if rest := strings.TrimSpace(stdout[dec.InputOffset():]); rest != "" {
		t.Fatalf("trailing text after the document: %q", rest)
	}
	if doc["schema"] != float64(1) {
		t.Errorf("schema = %v, want 1", doc["schema"])
	}
	return doc
}

// TestApplyJSONEmptyFleet: zero targets (apply returns before runWorkflow)
// still writes the empty-fleet document, exit 0, and no text report.
func TestApplyJSONEmptyFleet(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--json", "--dry-run", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	if doc["command"] != "apply" || doc["dry_run"] != true || doc["edit"] != nil || len(doc["servers"].([]any)) != 0 {
		t.Errorf("doc = %v", doc)
	}
	wantSummary(t, doc, map[string]int{"servers": 0, "skipped": 0, "converged": 0, "applied": 0, "pending": 0,
		"failed": 0, "refused": 0, "unreachable": 0, "exit_code": 0})
}

// TestApplyJSONHermetic: a real --yes write reports class change, outcome
// applied, exit 0; the --dry-run re-run reports the server converged.
func TestApplyJSONHermetic(t *testing.T) {
	srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))

	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	servers := doc["servers"].([]any)
	if len(servers) != 1 {
		t.Fatalf("servers = %v", servers)
	}
	if s0 := servers[0].(map[string]any); s0["name"] != "web-1" || s0["class"] != "change" || s0["outcome"] != "applied" ||
		s0["error"] != nil {
		t.Errorf("server = %v", s0)
	}
	wantSummary(t, doc, map[string]int{"servers": 1, "skipped": 0, "converged": 1, "applied": 1, "pending": 0,
		"failed": 0, "refused": 0, "unreachable": 0, "exit_code": 0})
	if doc["command"] != "apply" || doc["dry_run"] != false || doc["edit"] != nil ||
		doc["summary"].(map[string]any)["exit_code"] != float64(0) {
		t.Errorf("doc = %v", doc)
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"apply", "--json", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("re-run exit = %d\n%s", code, errBuf.String())
	}
	doc = oneJSONDoc(t, out.String())
	s0 := doc["servers"].([]any)[0].(map[string]any)
	if doc["dry_run"] != true || s0["class"] != "converged" || s0["outcome"] != nil {
		t.Errorf("dry-run doc = %v", doc)
	}
	wantSummary(t, doc, map[string]int{"servers": 1, "converged": 1, "applied": 0, "pending": 0, "exit_code": 0})
}

// TestApplyJSONSkipped: --server exclusions land in summary.skipped, the
// text "(N skipped by --server)" line is not printed, and the skipped
// server is not in the document. web-1 is unreachable (closed port), so
// the run exits 1 with a document.
func TestApplyJSONSkipped(t *testing.T) {
	fakeAgent(t)
	kh := writeEmptyKnownHosts(t)
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
  - {name: web-2, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--json", "--dry-run", "--config", path, "--known-hosts", kh, "--server", "web-1"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	summary := doc["summary"].(map[string]any)
	if summary["skipped"] != float64(1) || summary["servers"] != float64(1) || summary["unreachable"] != float64(1) ||
		summary["exit_code"] != float64(1) {
		t.Errorf("summary = %v", summary)
	}
	wantSummary(t, doc, map[string]int{"converged": 0, "applied": 0, "pending": 0, "failed": 0, "refused": 0})
	if s := docServers(doc); len(s) != 1 || s[0]["name"] != "web-1" || s[0]["class"] != "unreachable" ||
		s[0]["outcome"] != nil || s[0]["error"] == nil || s[0]["error_kind"] == nil {
		t.Errorf("servers = %v", s)
	}
	if s := docServers(doc); s[0]["error_kind"] != "dial" || s[0]["hint"] != sshconn.DialHint ||
		strings.Contains(s[0]["error"].(string), "hint") || strings.Count(s[0]["error"].(string), "dial") != 1 {
		t.Errorf("web-1 error/hint = %v / %v", s[0]["error"], s[0]["hint"])
	}
	if strings.Contains(out.String(), "skipped by --server") || strings.Contains(out.String(), "web-2") {
		t.Errorf("text leaked into the document:\n%s", out.String())
	}
}

// TestApplyJSONInterruptedAfterPlan: Ctrl-C after the plan (here: as --yes
// reaches the gate) — apply's commit does not check the context, so
// Execute marks the server not started and finish still writes the
// document: exit 1, the server pending, nothing written.
func TestApplyJSONInterruptedAfterPlan(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	target := filepath.Join(home, ".ssh", "authorized_keys")
	before := fileBytes(t, target)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	saved := promptStreams
	promptStreams = func(*cobra.Command) (io.Reader, io.Writer, bool) {
		cancel() // the gate is reached; --yes answers without reading
		return strings.NewReader(""), io.Discard, false
	}
	t.Cleanup(func() { promptStreams = saved })
	var out, errBuf bytes.Buffer
	if code := runContext(ctx, []string{"apply", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	doc := oneJSONDoc(t, out.String())
	s0 := doc["servers"].([]any)[0].(map[string]any)
	if s0["class"] != "change" || s0["outcome"] != "pending" || s0["error_kind"] != "canceled" || s0["error"] == nil {
		t.Errorf("doc = %v", doc)
	}
	wantSummary(t, doc, map[string]int{"servers": 1, "pending": 1, "applied": 0, "exit_code": 1})
	if !bytes.Equal(fileBytes(t, target), before) {
		t.Error("a server was written after the interrupt")
	}
}

// TestApplyJSONToolErrorsLeaveStdoutEmpty: exit 3 never writes a document.
func TestApplyJSONToolErrorsLeaveStdoutEmpty(t *testing.T) {
	t.Run("missing manifest", func(t *testing.T) {
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--json", "--yes", "--config", "/nonexistent.yaml"}, &out, &errBuf); code != 3 || out.Len() != 0 {
			t.Errorf("exit = %d, stdout = %q", code, out.String())
		}
	})
	t.Run("unknown --server", func(t *testing.T) {
		_, _, cfg := hermeticFleet(t, shortHome(t))
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--json", "--dry-run", "--config", cfg, "--server", "nope"}, &out, &errBuf); code != 3 || out.Len() != 0 {
			t.Errorf("exit = %d, stdout = %q", code, out.String())
		}
	})
	t.Run("interrupted during plan", func(t *testing.T) {
		ctx, cfg, kh := interruptingFleet(t)
		var out, errBuf bytes.Buffer
		if code := runContext(ctx, []string{"apply", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 || out.Len() != 0 {
			t.Errorf("exit = %d, stdout = %q", code, out.String())
		}
	})
	t.Run("manifest changed since read", func(t *testing.T) {
		srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
		kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
		saved := promptStreams
		promptStreams = func(*cobra.Command) (io.Reader, io.Writer, bool) {
			raw, err := os.ReadFile(cfg)
			if err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(cfg, append(raw, "# edited by a concurrent run\n"...), 0o600); err != nil {
				t.Error(err)
			}
			return strings.NewReader(""), io.Discard, false
		}
		t.Cleanup(func() { promptStreams = saved })
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 || out.Len() != 0 {
			t.Errorf("exit = %d, stdout = %q\nstderr: %s", code, out.String(), errBuf.String())
		}
	})
}

// runJSONDoc runs a command and returns its one JSON document after
// checking the exit code.
func runJSONDoc(ctx context.Context, t *testing.T, want int, args ...string) map[string]any {
	t.Helper()
	var out, errBuf bytes.Buffer
	if code := runContext(ctx, args, &out, &errBuf); code != want {
		t.Fatalf("%v: exit = %d, want %d\nstdout: %s\nstderr: %s", args, code, want, out.String(), errBuf.String())
	}
	return oneJSONDoc(t, out.String())
}

// wantSummary checks the named summary counts (absent keys unchecked).
func wantSummary(t *testing.T, doc map[string]any, want map[string]int) {
	t.Helper()
	summary := doc["summary"].(map[string]any)
	for k, v := range want {
		if summary[k] != float64(v) {
			t.Errorf("summary.%s = %v, want %d (summary = %v)", k, summary[k], v, summary)
		}
	}
}

func docServers(doc map[string]any) []map[string]any {
	var out []map[string]any
	for _, s := range doc["servers"].([]any) {
		out = append(out, s.(map[string]any))
	}
	return out
}

func TestRevokeJSONHermetic(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh)
	edit := doc["edit"].(map[string]any)
	if doc["command"] != "revoke" || doc["dry_run"] != false || edit["saved"] != true || edit["affected"] != float64(2) {
		t.Errorf("doc = %v", doc)
	}
	if edits := edit["edits"].([]any); len(edits) != 1 {
		t.Errorf("edits = %v", edits)
	} else if e := edits[0].(map[string]any); e["kind"] != "remove-user" || e["user"] != "bob" ||
		e["keys"] != float64(1) || e["grants"] != float64(1) || e["fingerprint"] != nil {
		t.Errorf("edit entry = %v", e)
	}
	if ops, emptied := edit["operators"].([]any), edit["emptied"].([]any); len(ops) != 0 || len(emptied) != 0 {
		t.Errorf("operators = %v, emptied = %v", ops, emptied)
	}
	wantSummary(t, doc, map[string]int{"servers": 2, "skipped": 0, "converged": 2, "applied": 2, "pending": 0, "exit_code": 0})
	servers := docServers(doc)
	if len(servers) != 2 {
		t.Fatalf("servers = %v", servers)
	}
	for _, sm := range servers {
		if sm["class"] != "change" || sm["outcome"] != "applied" {
			t.Errorf("%v: class/outcome = %v/%v", sm["name"], sm["class"], sm["outcome"])
		}
		removed := sm["changes"].(map[string]any)["remove"].([]any)
		if len(removed) != 1 || removed[0].(map[string]any)["former_owner"] != "bob" {
			t.Errorf("%v remove = %v", sm["name"], removed)
		}
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
	for name, h := range hosts {
		if strings.Contains(h.keys(t), testkeys.Line(t, 2)) {
			t.Errorf("%s still carries bob's key", name)
		}
	}
}

func TestRevokeJSONDryRun(t *testing.T) {
	_, kh, cfg := twoUserFleet(t)
	before := fileBytes(t, cfg)
	doc := runJSONDoc(context.Background(), t, 1, "revoke", "bob", "--json", "--dry-run", "--config", cfg, "--known-hosts", kh)
	if doc["dry_run"] != true || doc["edit"].(map[string]any)["saved"] != false {
		t.Errorf("doc = %v", doc)
	}
	for _, sm := range docServers(doc) {
		if sm["outcome"] != "pending" {
			t.Errorf("%v outcome = %v, want pending", sm["name"], sm["outcome"])
		}
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("--dry-run saved")
	}
}

// TestRevokeJSONNothingCanLand: the prompt hook's errNonCompliant (every
// affected server refused) still writes the document: saved false, exit 1.
func TestRevokeJSONNothingCanLand(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	for _, h := range hosts {
		h.install(t, []byte{1, 2}, "this line is not a key")
	}
	before := fileBytes(t, cfg)
	doc := runJSONDoc(context.Background(), t, 1, "revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh)
	if doc["edit"].(map[string]any)["saved"] != false {
		t.Errorf("edit = %v", doc["edit"])
	}
	for _, sm := range docServers(doc) {
		if sm["class"] != "refused" || sm["outcome"] != nil || sm["error"] == nil {
			t.Errorf("server = %v, want refused", sm)
		}
	}
	wantSummary(t, doc, map[string]int{"servers": 2, "refused": 2, "applied": 0, "exit_code": 1})
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("manifest saved although nothing could land")
	}
}

// TestRevokeJSONSaveWithheld: the agent vanishes between the plan and the
// write (here: as --yes reaches the gate) — the commit's workflow.ErrWithheld
// (no held key survives anywhere) still writes the document: saved false,
// the change server pending, exit 1.
func TestRevokeJSONSaveWithheld(t *testing.T) {
	hosts, kh, sock := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n")
	before := fileBytes(t, cfg)
	saved := promptStreams
	promptStreams = func(*cobra.Command) (io.Reader, io.Writer, bool) {
		_ = os.Remove(sock)
		return strings.NewReader(""), io.Discard, false
	}
	t.Cleanup(func() { promptStreams = saved })
	doc := runJSONDoc(context.Background(), t, 1, "revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh)
	if doc["edit"].(map[string]any)["saved"] != false {
		t.Errorf("edit = %v", doc["edit"])
	}
	if s := docServers(doc); len(s) != 1 || s[0]["class"] != "change" || s[0]["outcome"] != "pending" {
		t.Errorf("servers = %v", s)
	}
	wantSummary(t, doc, map[string]int{"servers": 1, "pending": 1, "applied": 0, "exit_code": 1})
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("manifest saved without a surviving held key")
	}
}

// TestRevokeJSONInterruptedAfterSave: Ctrl-C during the save — the save
// completes, no write starts: the document says saved, servers pending.
func TestRevokeJSONInterruptedAfterSave(t *testing.T) {
	_, kh, cfg := twoUserFleet(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	saved := beforeManifestSave
	beforeManifestSave = func(manifestTarget) { cancel() }
	t.Cleanup(func() { beforeManifestSave = saved })
	doc := runJSONDoc(ctx, t, 1, "revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh)
	if doc["edit"].(map[string]any)["saved"] != true {
		t.Errorf("edit = %v", doc["edit"])
	}
	for _, sm := range docServers(doc) {
		if sm["outcome"] != "pending" || sm["error_kind"] != "canceled" {
			t.Errorf("%v outcome/error_kind = %v/%v, want pending/canceled", sm["name"], sm["outcome"], sm["error_kind"])
		}
	}
	wantSummary(t, doc, map[string]int{"servers": 2, "pending": 2, "applied": 0, "exit_code": 1})
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
}

// TestRevokeJSONNoApply: the edit-only path (--no-apply) writes the edit
// section with servers [] — saved under --yes, not under --dry-run.
func TestRevokeJSONNoApply(t *testing.T) {
	for _, dry := range []bool{false, true} {
		hosts, _, cfg := twoUserFleet(t)
		before := fileBytes(t, cfg)
		args := []string{"revoke", "bob", "--json", "--no-apply", "--config", cfg}
		if dry {
			args = append(args, "--dry-run")
		} else {
			args = append(args, "--yes")
		}
		doc := runJSONDoc(context.Background(), t, 0, args...)
		edit := doc["edit"].(map[string]any)
		if edits := edit["edits"].([]any); len(edits) != 1 || edits[0].(map[string]any)["kind"] != "remove-user" {
			t.Errorf("dry=%v edits = %v", dry, edits)
		}
		if edit["saved"] != !dry || edit["affected"] != float64(2) || len(doc["servers"].([]any)) != 0 ||
			doc["dry_run"] != dry || doc["summary"].(map[string]any)["exit_code"] != float64(0) {
			t.Errorf("dry=%v doc = %v", dry, doc)
		}
		if changed := !bytes.Equal(fileBytes(t, cfg), before); changed == dry {
			t.Errorf("dry=%v: manifest changed = %v", dry, changed)
		}
		for name, h := range hosts {
			if len(h.srv.Attempts()) != 0 {
				t.Errorf("--no-apply connected to %s", name)
			}
		}
	}
}

// TestRevokeJSONNoServerAffected: an edit no server's desired keys depend
// on (bob holds no grant) takes the edit-only path without --no-apply.
func TestRevokeJSONNoServerAffected(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
	doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh)
	edit := doc["edit"].(map[string]any)
	if edit["saved"] != true || edit["affected"] != float64(0) || len(doc["servers"].([]any)) != 0 {
		t.Errorf("doc = %v", doc)
	}
	if len(readCfg(t, cfg).Users) != 1 {
		t.Error("manifest not saved")
	}
}

func TestRotateJSONHermetic(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1, 5}, "web-1")
	h := hosts["web-1"]
	h.install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
		"servers:\n"+h.line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
	newKey := sshtest.WriteKeyFile(t, t.TempDir(), "id_new", sshtest.Key(5), nil)
	doc := runJSONDoc(context.Background(), t, 0, "rotate", "alice", "--old", fpOf(t, 1), "--new", newKey+".pub",
		"--json", "--yes", "--config", cfg, "--known-hosts", kh, "--identity", newKey)
	edit := doc["edit"].(map[string]any)
	if doc["command"] != "rotate" || edit["saved"] != true || edit["affected"] != float64(1) {
		t.Errorf("doc = %v", doc)
	}
	if edits := edit["edits"].([]any); len(edits) != 1 {
		t.Errorf("edits = %v", edits)
	} else if e := edits[0].(map[string]any); e["kind"] != "rotate" || e["user"] != "alice" ||
		e["fingerprint"] != fpOf(t, 1) || e["new_fingerprint"] != fpOf(t, 5) || e["keys"] != nil {
		t.Errorf("edit entry = %v", e)
	}
	wantSummary(t, doc, map[string]int{"servers": 1, "converged": 1, "applied": 1, "exit_code": 0})
	s := docServers(doc)
	if len(s) != 1 || s[0]["outcome"] != "applied" {
		t.Fatalf("servers = %v", s)
	}
	removed := s[0]["changes"].(map[string]any)["remove"].([]any)
	if len(removed) != 1 || removed[0].(map[string]any)["former_owner"] != "alice" ||
		removed[0].(map[string]any)["fingerprint"] != fpOf(t, 1) {
		t.Errorf("remove = %v", removed)
	}
	if added := s[0]["changes"].(map[string]any)["add"].([]any); len(added) != 1 ||
		added[0].(map[string]any)["owner"] != "alice" || added[0].(map[string]any)["fingerprint"] != fpOf(t, 5) {
		t.Errorf("add = %v", added)
	}
}

// TestEditJSONToolErrorsLeaveStdoutEmpty: revoke/rotate's exit-3 refusals
// never write a document, and never save.
func TestEditJSONToolErrorsLeaveStdoutEmpty(t *testing.T) {
	_, kh, cfg := twoUserFleet(t)
	before := fileBytes(t, cfg)
	for _, args := range [][]string{
		{"revoke", "carol", "--json", "--yes", "--config", cfg, "--known-hosts", kh},
		{"revoke", "--key", fpOf(t, 7), "--json", "--dry-run", "--config", cfg, "--known-hosts", kh},
		{"revoke", "bob", "--operator", "--json", "--yes", "--config", cfg, "--known-hosts", kh},
		{"revoke", "bob", "--json", "--yes", "--config", "/nonexistent.yaml"},
		{"rotate", "bob", "--old", fpOf(t, 7), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)), "--json", "--yes", "--config", cfg, "--known-hosts", kh},
	} {
		var out, errBuf bytes.Buffer
		if code := run(args, &out, &errBuf); code != 3 || out.Len() != 0 {
			t.Errorf("%v: exit = %d, stdout = %q\nstderr: %s", args, code, out.String(), errBuf.String())
		}
	}
	t.Run("interrupted before save", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		saved := promptStreams
		promptStreams = func(*cobra.Command) (io.Reader, io.Writer, bool) {
			cancel()
			return strings.NewReader(""), io.Discard, false
		}
		t.Cleanup(func() { promptStreams = saved })
		var out, errBuf bytes.Buffer
		if code := runContext(ctx, []string{"revoke", "bob", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 || out.Len() != 0 {
			t.Errorf("exit = %d, stdout = %q", code, out.String())
		}
	})
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("a refused edit saved the manifest")
	}
}
