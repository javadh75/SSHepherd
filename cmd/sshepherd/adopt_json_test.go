package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// adoptJSONDoc is what the tests read of adopt's document. The pointers tell
// an absent field from an empty one.
type adoptJSONDoc struct {
	Schema  int    `json:"schema"`
	Command string `json:"command"`
	Mode    string `json:"mode"`
	Emitted bool   `json:"emitted"`
	Output  *struct {
		Path    string `json:"path"`
		Written bool   `json:"written"`
	} `json:"output"`
	Manifest *string `json:"manifest"`
	Summary  struct {
		Servers    int `json:"servers"`
		Read       int `json:"read"`
		PartlyRead int `json:"partly_read"`
		NewUsers   int `json:"new_users"`
		Extensions int `json:"extensions"`
		Warnings   int `json:"warnings"`
		ExitCode   int `json:"exit_code"`
	} `json:"summary"`
	NewUsers []struct {
		Name        string   `json:"name"`
		Fingerprint string   `json:"fingerprint"`
		Type        string   `json:"type"`
		FoundOn     []string `json:"found_on"`
	} `json:"new_users"`
	Unreadable []struct {
		Server    string `json:"server"`
		ErrorKind string `json:"error_kind"`
		Detail    string `json:"detail"`
		Hint      string `json:"hint"`
	} `json:"unreadable"`
	LineIssues []struct {
		Server string `json:"server"`
		Detail string `json:"detail"`
	} `json:"line_issues"`
	Warnings []adoptJSONWarning `json:"warnings"`
}

// adoptJSONWarning is one warning as a script reads it.
type adoptJSONWarning struct {
	Kind        string `json:"kind"`
	Server      string `json:"server"`
	Fingerprint string `json:"fingerprint"`
	User        string `json:"user"`
	Date        string `json:"date"`
}

// adoptJSONCLI runs adopt --json and decodes stdout, which must be exactly
// one document.
func adoptJSONCLI(t *testing.T, args ...string) (int, adoptJSONDoc, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(append([]string{"adopt", "--json"}, args...), &out, &errBuf)
	dec := json.NewDecoder(&out)
	var doc adoptJSONDoc
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("exit %d: stdout is not a document: %v (stderr: %s)", code, err, errBuf.String())
	}
	if dec.More() {
		t.Fatalf("stdout holds more than one document")
	}
	return code, doc, errBuf.String()
}

// adoptFixture is one reachable server holding keys 1 and 7, where the
// manifest knows only key 1.
func adoptFixture(t *testing.T) (cfg, kh string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 7})
	cfg = writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	return cfg, kh
}

// TestAdoptJSONManifestMatchesPlainRun is OP3: with no -o the manifest is in
// the document, byte for byte what a plain run prints, and logs stay on
// stderr.
func TestAdoptJSONManifestMatchesPlainRun(t *testing.T) {
	cfg, kh := adoptFixture(t)
	var plain, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh}, &plain, &errBuf); code != 0 {
		t.Fatalf("plain exit = %d (stderr: %s)", code, errBuf.String())
	}
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if doc.Manifest == nil || *doc.Manifest != plain.String() {
		t.Errorf("manifest = %v\nwant %q", doc.Manifest, plain.String())
	}
	if doc.Output != nil {
		t.Errorf("output = %+v, want none without -o", doc.Output)
	}
	if doc.Schema != 1 || doc.Command != "adopt" || doc.Mode != "generate" || !doc.Emitted {
		t.Errorf("doc = %+v", doc)
	}
	if s := doc.Summary; s.Servers != 1 || s.Read != 1 || s.PartlyRead != 0 || s.NewUsers != 1 || s.Extensions != 0 || s.Warnings != 0 || s.ExitCode != 0 {
		t.Errorf("summary = %+v", s)
	}
	if len(doc.NewUsers) != 1 || doc.NewUsers[0].Type != "ssh-ed25519" || doc.NewUsers[0].Fingerprint == "" ||
		len(doc.NewUsers[0].FoundOn) != 1 || doc.NewUsers[0].FoundOn[0] != "web-1" {
		t.Errorf("new_users = %+v", doc.NewUsers)
	}
	if !strings.Contains(stderr, "read 1 of 1 server") {
		t.Errorf("stderr = %q, want the logs there", stderr)
	}
}

// TestAdoptJSONOutputFile: with -o the file holds a plain run's bytes, in
// generate mode and for a --merge that really appends.
func TestAdoptJSONOutputFile(t *testing.T) {
	for name, extra := range map[string][]string{
		"generate":           nil,
		"merge that appends": {"--merge"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, kh := adoptFixture(t)
			flags := append([]string{"--config", cfg, "--known-hosts", kh}, extra...)
			plain := plainManifestFile(t, append([]string{"adopt"}, flags...)...)
			dst := filepath.Join(t.TempDir(), "adopted.yaml")
			code, doc, stderr := adoptJSONCLI(t, append(slices.Clone(flags), "-o", dst)...)
			if code != 0 {
				t.Fatalf("exit = %d (stderr: %s)", code, stderr)
			}
			if doc.Output == nil || doc.Output.Path != dst || !doc.Output.Written || doc.Manifest != nil {
				t.Errorf("output = %+v, manifest = %v", doc.Output, doc.Manifest)
			}
			got, err := os.ReadFile(dst)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Errorf("-o bytes differ from a plain run:\n--- got ---\n%s\n--- want ---\n%s", got, plain)
			}
			if parsed := readCfg(t, dst); len(parsed.Users) != 2 {
				t.Errorf("written manifest has %d users, want 2", len(parsed.Users))
			}
		})
	}
}

// TestAdoptJSONInPlaceNoChange: nothing to adopt, so the in-place update
// writes nothing, and the document says so.
func TestAdoptJSONInPlaceNoChange(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	before, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	code, doc, stderr := adoptJSONCLI(t, "--merge", "--config", cfg, "--known-hosts", kh, "-o", cfg, "--force")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if doc.Mode != "merge" || !doc.Emitted || doc.Output == nil || doc.Output.Written {
		t.Errorf("doc = %+v, output = %+v, want merge, emitted, written false", doc, doc.Output)
	}
	after, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("manifest changed:\n%s", after)
	}
}

// TestAdoptJSONStoppedByUnreadable: exit 1, a document, nothing emitted.
func TestAdoptJSONStoppedByUnreadable(t *testing.T) {
	cfg, kh := unreachableFleet(t)
	dst := filepath.Join(t.TempDir(), "adopted.yaml")
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh, "-o", dst)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, stderr)
	}
	if doc.Emitted || doc.Output != nil || doc.Manifest != nil {
		t.Errorf("doc = %+v, want nothing emitted", doc)
	}
	if doc.Summary.Servers != 1 || doc.Summary.Read != 0 || doc.Summary.ExitCode != 1 {
		t.Errorf("summary = %+v", doc.Summary)
	}
	if len(doc.Unreadable) != 1 || doc.Unreadable[0].Server != "web-1" || doc.Unreadable[0].ErrorKind != "dial" ||
		doc.Unreadable[0].Detail == "" || doc.Unreadable[0].Hint == "" {
		t.Errorf("unreadable = %+v", doc.Unreadable)
	}
	if !strings.Contains(stderr, "could not be fully read") {
		t.Errorf("stderr = %q, want the strict-gate verdict", stderr)
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Errorf("%s was written", dst)
	}
}

// TestAdoptJSONPartialSomeRead: exit 1, emitted, the gap in the manifest.
func TestAdoptJSONPartialSomeRead(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"  - {name: web-2, host: 127.0.0.1, port: "+strconv.Itoa(closedPort(t))+", user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n")
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh, "--partial")
	if code != adoptPartialExit {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, adoptPartialExit, stderr)
	}
	if !doc.Emitted || doc.Manifest == nil || !strings.Contains(*doc.Manifest, "# WARNING: server web-2 unreadable") {
		t.Errorf("doc = %+v, want the partial manifest", doc)
	}
	if doc.Summary.Servers != 2 || doc.Summary.Read != 1 || doc.Summary.ExitCode != adoptPartialExit {
		t.Errorf("summary = %+v", doc.Summary)
	}
}

// TestAdoptJSONPartialNothingRead is the one exit 3 with a document.
func TestAdoptJSONPartialNothingRead(t *testing.T) {
	cfg, kh := unreachableFleet(t)
	dst := filepath.Join(t.TempDir(), "adopted.yaml")
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh, "--partial", "-o", dst)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, stderr)
	}
	if doc.Emitted || doc.Output != nil || doc.Manifest != nil || doc.Summary.ExitCode != 3 || len(doc.Unreadable) != 1 {
		t.Errorf("doc = %+v", doc)
	}
	if !strings.Contains(stderr, "read 0 of 1 server — nothing could be adopted") {
		t.Errorf("stderr = %q", stderr)
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Errorf("%s was written", dst)
	}
}

// TestAdoptJSONPartlyRead: a line adopt cannot use leaves the server read:
// it is a row of line_issues, not of unreadable, and the run exits 0.
func TestAdoptJSONPartlyRead(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1}, "ssh-ed25519 !!!notbase64 broken")
	cfg := writeConfig(t, "users: []\nservers:\n"+hosts["web-1"].line("web-1")+"access: []\n")
	code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh, "--partial")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if doc.Summary.Read != 1 || doc.Summary.PartlyRead != 1 || doc.Summary.ExitCode != 0 || !doc.Emitted {
		t.Errorf("doc = %+v", doc)
	}
	if len(doc.Unreadable) != 0 {
		t.Errorf("unreadable = %+v, want none: the server was read", doc.Unreadable)
	}
	if len(doc.LineIssues) != 1 || doc.LineIssues[0].Server != "web-1" || doc.LineIssues[0].Detail == "" {
		t.Errorf("line_issues = %+v, want one row for web-1", doc.LineIssues)
	}
}

// TestAdoptJSONReportsSkippedKey: each P04 skip reaches the document in its
// shape.
func TestAdoptJSONReportsSkippedKey(t *testing.T) {
	fp4, fp7 := fingerprintOf(t, testkeys.Line(t, 4)), fingerprintOf(t, testkeys.Line(t, 7))
	for _, tt := range []struct {
		name    string
		seed    byte   // the installed key the run skips
		users   string // user lines added after alice
		revoked string
		want    adoptJSONWarning
	}{
		{
			name:    "revoked key",
			seed:    7,
			revoked: "revoked:\n  - {fingerprint: " + fp7 + ", user: old, date: 2026-11-08}\n",
			want:    adoptJSONWarning{Kind: "revoked_key_skipped", Server: "web-1", Fingerprint: fp7, User: "old", Date: "2026-11-08"},
		},
		{
			name:    "access tombstone",
			seed:    4,
			users:   "  - {name: bob, keys: [" + qk(t, 4) + "]}\n",
			revoked: "revoked:\n  - {user: bob, servers: [web-1], date: 2026-11-08}\n",
			want:    adoptJSONWarning{Kind: "revoked_access_skipped", Server: "web-1", Fingerprint: fp4, User: "bob", Date: "2026-11-08"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
			hosts["web-1"].install(t, []byte{1, tt.seed})
			cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+tt.users+"servers:\n"+hosts["web-1"].line("web-1")+
				"access:\n  - {user: alice, servers: [web-1]}\n"+tt.revoked)
			code, doc, stderr := adoptJSONCLI(t, "--config", cfg, "--known-hosts", kh)
			if code != 0 {
				t.Fatalf("exit = %d (stderr: %s)", code, stderr)
			}
			if len(doc.Warnings) != 1 || doc.Summary.Warnings != 1 {
				t.Fatalf("warnings = %+v, summary = %+v", doc.Warnings, doc.Summary)
			}
			if got := doc.Warnings[0]; got != tt.want {
				t.Errorf("warning = %+v, want %+v", got, tt.want)
			}
		})
	}
}

// TestAdoptJSONToolErrorNoDocument: exit 3 is a message on stderr, not a
// document. want pins the message, so an unknown --json flag (also exit 3
// with empty stdout) cannot pass.
func TestAdoptJSONToolErrorNoDocument(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	alice := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n"
	rest := "servers:\n" + hosts["web-1"].line("web-1") + "access:\n  - {user: alice, servers: [web-1]}\n"
	cfg := writeConfig(t, alice+rest)
	// carol's key stays listed while revoked: a policy conflict, refused only
	// after the render.
	conflicted := writeConfig(t, alice+"  - {name: carol, keys: ["+qk(t, 7)+"]}\n"+rest+
		"revoked:\n  - {fingerprint: "+fingerprintOf(t, testkeys.Line(t, 7))+", user: old, date: 2026-11-08}\n")
	taken := filepath.Join(t.TempDir(), "taken.yaml")
	if err := os.WriteFile(taken, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		args []string
		want string
	}{
		"missing manifest":        {[]string{"adopt", "--json", "--config", "/nonexistent.yaml", "--known-hosts", kh}, "no manifest at"},
		"bad --identity":          {[]string{"adopt", "--json", "--config", cfg, "--known-hosts", kh, "--identity", "/no/such/id"}, "identity: "},
		"-o exists, no --force":   {[]string{"adopt", "--json", "--config", cfg, "--known-hosts", kh, "-o", taken}, "already exists; pass --force"},
		"keeps a policy conflict": {[]string{"adopt", "--json", "--config", conflicted, "--known-hosts", kh}, "refusing to write the manifest"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			if code := run(tt.args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
			}
			if out.Len() != 0 {
				t.Errorf("stdout = %q, want no document", out.String())
			}
			if !strings.Contains(errBuf.String(), tt.want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), tt.want)
			}
		})
	}
}

// TestAdoptJSONMergeEmptyManifest: a no-op merge of a 0-byte file emits zero
// bytes, and the document still has the field (OP3).
func TestAdoptJSONMergeEmptyManifest(t *testing.T) {
	cfg := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--json", "--merge", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), `"manifest": ""`) || !strings.Contains(out.String(), `"emitted": true`) {
		t.Errorf("stdout = %s, want an emitted, empty manifest field", out.String())
	}
}

// TestAdoptJSONHostileRemoteComment: a comment read from a server reaches
// neither the report nor its manifest with C1 or Cf runes in it.
func TestAdoptJSONHostileRemoteComment(t *testing.T) {
	csi, bidi := string(rune(0x9b)), string(rune(0x202e))
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1}, testkeys.Line(t, 7)+" x"+csi+bidi+"y")
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if strings.Contains(out.String(), csi) || strings.Contains(out.String(), bidi) {
		t.Errorf("hostile runes survived on stdout:\n%q", out.String())
	}
	var doc adoptJSONDoc
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Warnings) != 1 || doc.Warnings[0].Kind != "comment_dropped" {
		t.Errorf("warnings = %+v, want one comment_dropped", doc.Warnings)
	}
}

func fingerprintOf(t *testing.T, line string) string {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return k.Fingerprint
}

// plainManifestFile runs args (a command and its flags, no --json) with -o
// and returns the bytes it wrote.
func plainManifestFile(t *testing.T, args ...string) []byte {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "plain.yaml")
	var out, errBuf bytes.Buffer
	if code := run(append(slices.Clone(args), "-o", dst), &out, &errBuf); code != 0 {
		t.Fatalf("plain exit = %d (stderr: %s)", code, errBuf.String())
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	return got
}
