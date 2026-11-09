package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// validateCLI runs validate and returns its exit code, stdout and stderr.
func validateCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(append([]string{"validate"}, args...), &out, &errBuf)
	return code, out.String(), errBuf.String()
}

func validateManifest(t *testing.T) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n" +
		"access:\n  - {user: alice, servers: [web-1]}\n"
}

// recordedKnownHosts is a known_hosts file holding a key for each host.
func recordedKnownHosts(t *testing.T, hosts ...string) string {
	t.Helper()
	var lines []string
	for _, h := range hosts {
		lines = append(lines, h+" "+testkeys.Line(t, 40))
	}
	return sshtest.KnownHostsFile(t, lines...)
}

func TestValidateValid(t *testing.T) {
	code, out, stderr := validateCLI(t, "--config", writeConfig(t, validateManifest(t)), "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if want := "manifest OK: 1 user, 1 server, 1 grant (0 warnings)\n"; out != want {
		t.Errorf("stdout = %q, want %q", out, want)
	}
}

func TestValidateInvalid(t *testing.T) {
	path := writeConfig(t, "users: []\nservers: []\naccess:\n  - {user: ghost, servers: [web-9]}\n")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if !strings.Contains(stderr, "invalid manifest "+path+":") || !strings.Contains(stderr, `access: unknown user "ghost"`) {
		t.Errorf("stderr = %q", stderr)
	}
}

func TestValidateUnreadableManifest(t *testing.T) {
	code, out, stderr := validateCLI(t, "--config", "/nonexistent.yaml", "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" || !strings.Contains(stderr, "no manifest at /nonexistent.yaml") {
		t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
}

func TestValidateWarningsAndStrict(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: alice, comment: c, keys: [\""+testkeys.Line(t, 1)+"\", \""+testkeys.Line(t, 2)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n")
	kh := recordedKnownHosts(t, "10.0.1.5")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "(1 warning)") {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if !strings.Contains(stderr, `user "alice": comment is set on a user with 2 keys`) {
		t.Errorf("stderr = %q", stderr)
	}
	if code, out, _ := validateCLI(t, "--strict", "--config", path, "--known-hosts", kh); code != 1 || !strings.HasPrefix(out, "manifest OK:") {
		t.Errorf("--strict: exit = %d, stdout = %q; want 1 with the summary", code, out)
	}
}

func TestValidateAnchorsWarn(t *testing.T) {
	code, out, stderr := validateCLI(t, "--config", writeConfig(t, "users: &u []\nservers: []\naccess: []\n"), "--known-hosts", recordedKnownHosts(t))
	if code != 0 || out != "manifest OK: 0 users, 0 servers, 0 grants (1 warning)\n" {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	want := "revoke, rotate and --merge cannot edit this manifest: manifest contains a YAML anchor or alias (line 1); comment-preserving edits do not support them"
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
}

func TestValidateConflictExit3(t *testing.T) {
	k, err := authkeys.ParseLine(testkeys.Line(t, 1))
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\nrevoked:\n  - {fingerprint: "+k.Fingerprint+", date: 2026-11-08}\n")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if !strings.Contains(stderr, "manifest has 1 policy conflict: key "+k.Fingerprint) {
		t.Errorf("stderr = %q", stderr)
	}
}

// TestValidateWeakKeys: a granted weak key is a policy conflict (exit 3) and
// an ungranted one is a warning (exit 0); P09 plan decision 14 assigned these
// two cases to this command.
func TestValidateWeakKeys(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	base := "users:\n  - {name: old, keys: [\"" + dsa + "\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n"
	kh := recordedKnownHosts(t, "10.0.1.5")
	t.Run("granted", func(t *testing.T) {
		code, out, stderr := validateCLI(t, "--config", writeConfig(t, base+"access:\n  - {user: old, servers: [web-1]}\n"), "--known-hosts", kh)
		if code != 3 || out != "" || !strings.Contains(stderr, `manifest has 1 policy conflict: user "old" key 1 (`) {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
	t.Run("ungranted", func(t *testing.T) {
		code, out, stderr := validateCLI(t, "--config", writeConfig(t, base), "--known-hosts", kh)
		if code != 0 || !strings.Contains(out, "(1 warning)") || !strings.Contains(stderr, "dsa key, granted on no server") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
}

// TestValidateConflictsPlural: several conflicts are counted and joined.
func TestValidateConflictsPlural(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(dsa)
	if err != nil {
		t.Fatal(err)
	}
	path := writeConfig(t, "users:\n  - {name: old, keys: [\""+dsa+"\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n"+
		"access:\n  - {user: old, servers: [web-1]}\nrevoked:\n  - {fingerprint: "+k.Fingerprint+", user: old, date: 2026-11-08}\n")
	code, _, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 3 || !strings.Contains(stderr, "manifest has 2 policy conflicts: ") || !strings.Contains(stderr, "; ") {
		t.Errorf("exit = %d, stderr = %q", code, stderr)
	}
}

func TestValidateKnownHostsGap(t *testing.T) {
	manifest := "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n  - {name: web-2, host: 10.0.1.6, port: 2222, user: deploy}\n"
	path := writeConfig(t, manifest)
	kh := recordedKnownHosts(t, "10.0.1.5")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "(1 warning)") {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if want := `server "web-2": no host key recorded for 10.0.1.6:2222 in ` + kh; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if strings.Contains(stderr, `server "web-1"`) {
		t.Errorf("recorded host reported as a gap: %q", stderr)
	}
	if code, _, _ := validateCLI(t, "--strict", "--config", path, "--known-hosts", kh); code != 1 {
		t.Errorf("--strict exit = %d, want 1", code)
	}
}

// TestValidateKnownHostsNonDefaultPortAndCA: a [host]:port entry and a host
// matched only by @cert-authority both count as recorded; a port-22 entry does
// not record the same host on another port.
func TestValidateKnownHostsNonDefaultPortAndCA(t *testing.T) {
	path := writeConfig(t, "users: []\nservers:\n  - {name: web-1, host: 10.0.1.5, port: 2222, user: deploy}\n  - {name: web-2, host: 10.0.1.6, user: deploy}\n  - {name: web-3, host: 10.0.1.7, port: 2222, user: deploy}\n")
	kh := sshtest.KnownHostsFile(t, "[10.0.1.5]:2222 "+testkeys.Line(t, 40), "@cert-authority 10.0.1.6 "+testkeys.Line(t, 41), "10.0.1.7 "+testkeys.Line(t, 42))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "(1 warning)") {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	if want := `server "web-3": no host key recorded for 10.0.1.7:2222`; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	for _, recorded := range []string{`server "web-1"`, `server "web-2"`} {
		if strings.Contains(stderr, recorded) {
			t.Errorf("%s reported as a gap: %q", recorded, stderr)
		}
	}
}

// TestValidateMissingDefaultKnownHosts (OP1): a warning that fails --strict.
func TestValidateMissingDefaultKnownHosts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := writeConfig(t, validateManifest(t))
	code, out, stderr := validateCLI(t, "--config", path)
	if code != 0 || !strings.Contains(out, "(1 warning)") {
		t.Fatalf("exit = %d, stdout = %q", code, out)
	}
	if want := "no known_hosts at ~/.ssh/known_hosts; host keys were not checked"; !strings.Contains(stderr, want) {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if code, _, _ := validateCLI(t, "--strict", "--config", path); code != 1 {
		t.Errorf("--strict exit = %d, want 1", code)
	}
}

func TestValidateBadKnownHosts(t *testing.T) {
	path := writeConfig(t, validateManifest(t))
	bad := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(bad, []byte("not a known hosts line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte("not a known hosts line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Run("explicit path missing", func(t *testing.T) {
		code, out, stderr := validateCLI(t, "--json", "--config", path, "--known-hosts", filepath.Join(t.TempDir(), "missing"))
		if code != 3 || out != "" || !strings.Contains(stderr, "known_hosts preflight:") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
	t.Run("explicit file malformed", func(t *testing.T) {
		code, out, stderr := validateCLI(t, "--json", "--config", path, "--known-hosts", bad)
		if code != 3 || out != "" || !strings.Contains(stderr, "known_hosts preflight:") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
	// Text mode: exit 3 and nothing on stdout. Task 9 pins the --json document.
	t.Run("default file malformed", func(t *testing.T) {
		t.Setenv("HOME", home)
		code, out, stderr := validateCLI(t, "--config", path)
		if code != 3 || out != "" || !strings.Contains(stderr, "known_hosts preflight:") {
			t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
		}
	})
}

func TestValidateJSONValid(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--config", writeConfig(t, validateManifest(t)), "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	doc := oneJSONDoc(t, out)
	wantSummary(t, doc, map[string]int{"users": 1, "servers": 1, "grants": 1, "warnings": 0, "exit_code": 0})
	if doc["valid"] != true || doc["host_keys_checked"] != true {
		t.Errorf("doc = %v", doc)
	}
	if errs, ok := doc["errors"].([]any); !ok || len(errs) != 0 {
		t.Errorf("errors must be present and empty: %v", doc["errors"])
	}
	for _, absent := range []string{"policy_conflicts", "manifest_warnings"} {
		if _, ok := doc[absent]; ok {
			t.Errorf("%s must be omitted when empty: %v", absent, doc)
		}
	}
}

// TestValidateJSONWarningGolden pins the design's "valid with one warning"
// document. The temporary path is rewritten so the README can copy it.
func TestValidateJSONWarningGolden(t *testing.T) {
	kh := writeEmptyKnownHosts(t)
	code, out, _ := validateCLI(t, "--json", "--config", writeConfig(t, validateManifest(t)), "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("exit = %d", code)
	}
	checkGolden(t, "validate_warning.golden.json", []byte(strings.ReplaceAll(out, kh, "~/.ssh/known_hosts")))
}

func TestValidateJSONInvalidGolden(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-9]}\n")
	code, out, stderr := validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || !strings.Contains(stderr, `access for "alice": unknown server "web-9"`) {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	checkGolden(t, "validate_invalid.golden.json", []byte(out))
}

func TestValidateJSONStrict(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: alice, comment: c, keys: [\""+testkeys.Line(t, 1)+"\", \""+testkeys.Line(t, 2)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n")
	code, out, _ := validateCLI(t, "--json", "--strict", "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	doc := oneJSONDoc(t, out)
	if doc["valid"] != true {
		t.Errorf("valid = %v: a run failing only under --strict is valid", doc["valid"])
	}
	wantSummary(t, doc, map[string]int{"warnings": 1, "exit_code": 1})
	ws := doc["manifest_warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["kind"] != "comment_on_multi_key" {
		t.Errorf("manifest_warnings = %v", ws)
	}
}

func TestValidateJSONConflict(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	path := writeConfig(t, "users:\n  - {name: old, keys: [\""+dsa+"\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\naccess:\n  - {user: old, servers: [web-1]}\n")
	code, out, stderr := validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 3 || !strings.Contains(stderr, "manifest has 1 policy conflict:") {
		t.Fatalf("exit = %d, stderr = %q", code, stderr)
	}
	doc := oneJSONDoc(t, out)
	wantSummary(t, doc, map[string]int{"users": 1, "servers": 1, "grants": 1, "warnings": 0, "exit_code": 3})
	if doc["valid"] != false || doc["host_keys_checked"] != true {
		t.Errorf("doc = %v", doc)
	}
	cs := doc["policy_conflicts"].([]any)
	if len(cs) != 1 || cs[0].(map[string]any)["kind"] != "weak_key" {
		t.Errorf("policy_conflicts = %v", cs)
	}
	if errs, ok := doc["errors"].([]any); !ok || len(errs) != 0 {
		t.Errorf("errors = %v, want []", doc["errors"])
	}
}

func TestValidateJSONUngrantedWeakKey(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: old, keys: [\""+testkeys.DSALine(t, 7)+"\"]}\n")
	code, out, _ := validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	ws := oneJSONDoc(t, out)["manifest_warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["kind"] != "weak_key_ungranted" {
		t.Errorf("manifest_warnings = %v", ws)
	}
}

// TestValidateJSONParseFailure: a syntax error is one errors entry, and
// counts stay zero.
func TestValidateJSONParseFailure(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--config", writeConfig(t, "users: [\n"), "--known-hosts", recordedKnownHosts(t))
	if code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	doc := oneJSONDoc(t, out)
	if errs := doc["errors"].([]any); len(errs) != 1 || doc["valid"] != false || doc["host_keys_checked"] != false {
		t.Errorf("doc = %v", doc)
	}
	wantSummary(t, doc, map[string]int{"users": 0, "servers": 0, "grants": 0, "warnings": 0, "exit_code": 3})
}

// TestValidateJSONMissingDefaultKnownHosts (OP1): no known_hosts was loaded,
// so host_keys_checked is false on a parsed manifest.
func TestValidateJSONMissingDefaultKnownHosts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	path := writeConfig(t, validateManifest(t))
	code, out, _ := validateCLI(t, "--json", "--config", path)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	doc := oneJSONDoc(t, out)
	wantSummary(t, doc, map[string]int{"users": 1, "servers": 1, "grants": 1, "warnings": 1, "exit_code": 0})
	if doc["valid"] != true || doc["host_keys_checked"] != false {
		t.Errorf("doc = %v", doc)
	}
	ws := doc["manifest_warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["kind"] != "known_hosts_missing" {
		t.Errorf("manifest_warnings = %v", ws)
	}
	code, out, _ = validateCLI(t, "--json", "--strict", "--config", path)
	if code != 1 {
		t.Fatalf("--strict exit = %d, want 1", code)
	}
	if strict := oneJSONDoc(t, out); strict["valid"] != true {
		t.Errorf("--strict valid = %v, want true", strict["valid"])
	}
}

// TestValidateJSONDefaultKnownHostsLoadFailure (O1): a default-path file that
// exists but cannot be loaded is exit 3, and unlike a bad explicit file it
// still writes the document, with the reason in errors.
func TestValidateJSONDefaultKnownHostsLoadFailure(t *testing.T) {
	path := writeConfig(t, validateManifest(t))
	for _, tc := range []struct {
		name string
		home func(t *testing.T) string
	}{
		{"malformed", func(t *testing.T) string {
			home := t.TempDir()
			if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte("not a known hosts line\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return home
		}},
		{"~/.ssh is a file", func(t *testing.T) string {
			home := t.TempDir()
			if err := os.WriteFile(filepath.Join(home, ".ssh"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return home
		}},
		{"HOME unset", func(_ *testing.T) string { return "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", tc.home(t))
			code, out, stderr := validateCLI(t, "--json", "--config", path)
			if code != 3 || !strings.Contains(stderr, "known_hosts preflight:") {
				t.Fatalf("exit = %d, stderr = %q", code, stderr)
			}
			doc := oneJSONDoc(t, out)
			wantSummary(t, doc, map[string]int{"users": 1, "servers": 1, "grants": 1, "warnings": 0, "exit_code": 3})
			if doc["valid"] != true || doc["host_keys_checked"] != false {
				t.Errorf("doc = %v", doc)
			}
			errs, ok := doc["errors"].([]any)
			if !ok || len(errs) != 1 || !strings.Contains(errs[0].(string), "known_hosts preflight:") {
				t.Errorf("errors = %v", doc["errors"])
			}
		})
	}
}

// TestValidateConflictAndDefaultKnownHostsFailure: both are reported, and the
// conflict decides valid.
func TestValidateConflictAndDefaultKnownHostsFailure(t *testing.T) {
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".ssh"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	path := writeConfig(t, "users:\n  - {name: old, keys: [\""+testkeys.DSALine(t, 7)+"\"]}\nservers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\naccess:\n  - {user: old, servers: [web-1]}\n")
	code, out, stderr := validateCLI(t, "--config", path)
	if code != 3 || out != "" || !strings.Contains(stderr, "manifest has 1 policy conflict:") || !strings.Contains(stderr, "known_hosts preflight:") {
		t.Errorf("text: exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	code, out, _ = validateCLI(t, "--json", "--config", path)
	if code != 3 {
		t.Fatalf("json exit = %d, want 3", code)
	}
	doc := oneJSONDoc(t, out)
	if doc["valid"] != false || doc["host_keys_checked"] != false {
		t.Errorf("doc = %v", doc)
	}
	if errs := doc["errors"].([]any); len(errs) != 1 {
		t.Errorf("errors = %v", errs)
	}
	if cs := doc["policy_conflicts"].([]any); len(cs) != 1 {
		t.Errorf("policy_conflicts = %v", cs)
	}
}

func TestValidateJSONAnchors(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--config", writeConfig(t, "users: &u []\nservers: []\naccess: []\n"), "--known-hosts", recordedKnownHosts(t))
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	doc := oneJSONDoc(t, out)
	wantSummary(t, doc, map[string]int{"warnings": 1, "exit_code": 0})
	if doc["valid"] != true {
		t.Errorf("doc = %v", doc)
	}
	ws := doc["manifest_warnings"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["kind"] != "manifest_not_editable" {
		t.Errorf("manifest_warnings = %v", ws)
	}
}

// TestValidateJSONBadFlagWritesNoDocument: a bad flag never reaches the run.
func TestValidateJSONBadFlagWritesNoDocument(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--nope")
	if code != 3 || out != "" {
		t.Errorf("exit = %d, stdout = %q", code, out)
	}
}

func TestValidateJSONUnreadableManifestWritesNoDocument(t *testing.T) {
	code, out, _ := validateCLI(t, "--json", "--config", "/nonexistent.yaml", "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" {
		t.Errorf("exit = %d, stdout = %q", code, out)
	}
}

// TestValidateJSONSanitizesManifestText: a D1e warning can name a server with
// control runes, and they must not reach the document.
func TestValidateJSONSanitizesManifestText(t *testing.T) {
	path := writeConfig(t, "users: []\nservers: []\nrevoked:\n  - {user: bob, servers: [\"db\\e9\"], date: 2026-11-08}\n")
	code, out, _ := validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if strings.ContainsRune(out, 0x1b) || strings.Contains(out, `\u001b`) {
		t.Errorf("a control rune reached the document:\n%s", out)
	}
}

func TestSplitErrors(t *testing.T) {
	joined := errors.Join(errors.New("first"), errors.New("sec\x1bond"))
	if got, want := splitErrors(joined), []string{"first", "second"}; !reflect.DeepEqual(got, want) {
		t.Errorf("joined: got %q, want %q", got, want)
	}
	if got, want := splitErrors(errors.New("one")), []string{"one"}; !reflect.DeepEqual(got, want) {
		t.Errorf("single: got %q, want %q", got, want)
	}
}

// TestValidateOpensNoSocket: a server in the manifest and SSH_AUTH_SOCK both
// point at counting listeners, and validate touches neither.
func TestValidateOpensNoSocket(t *testing.T) {
	var dials atomic.Int32
	serve := func(ln net.Listener) (stop func()) {
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				dials.Add(1)
				_ = c.Close()
			}
		}()
		return func() {
			_ = ln.Close()
			<-done
		}
	}
	tcp, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stopTCP := serve(tcp)
	sock, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", filepath.Join(shortHome(t), "a"))
	if err != nil {
		t.Fatal(err)
	}
	stopSock := serve(sock)
	t.Setenv("SSH_AUTH_SOCK", sock.Addr().String())
	path := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 127.0.0.1, port: "+strconvItoa(tcp.Addr().(*net.TCPAddr).Port)+", user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	code, _, stderr := validateCLI(t, "--config", path, "--known-hosts", writeEmptyKnownHosts(t))
	stopTCP()
	stopSock()
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("validate opened %d connections", n)
	}
}
