package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestValidateUnderstandsProtected(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: ci, protected: true, keys: []}\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n"+
		"access:\n  - {user: ci, servers: [web-1]}\n  - {user: alice, servers: [web-1]}\n")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 0 || out != "manifest OK: 2 users, 1 server, 1 grant (0 warnings)\n" {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
}

func TestValidateOperatorGrantRedundant(t *testing.T) {
	const text = `operator "op": this access entry adds nothing; operator: true still grants every server`
	path := writeConfig(t, "users:\n  - {name: op, operator: true, keys: ["+qk(t, 1)+"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: deploy}\n"+
		"access:\n  - {user: op, servers: [web-1]}\n")
	kh := recordedKnownHosts(t, "10.0.1.5")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
	if code != 0 || !strings.Contains(out, "(1 warning)") || !strings.Contains(stderr, text) {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	code, out, _ = validateCLI(t, "--strict", "--json", "--config", path, "--known-hosts", kh)
	if code != 1 {
		t.Fatalf("--strict: exit = %d, want 1", code)
	}
	ws, _ := oneJSONDoc(t, out)["manifest_warnings"].([]any)
	want := []any{map[string]any{"kind": "operator_grant_redundant", "user": "op", "message": text}}
	if !reflect.DeepEqual(ws, want) {
		t.Errorf("manifest_warnings = %v, want %v", ws, want)
	}
}

// TestAdoptMergeKeepsProtected: an unknown key makes the plan non-empty, so
// the merge goes through Append and Encode; the protected flag and its
// comment survive and the protected key stays granted.
func TestAdoptMergeKeepsProtected(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2, 5})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - name: ci\n    protected: true # keep\n    keys: ["+qk(t, 2)+"]\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: ci, servers: [web-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--merge", "--config", cfg, "-o", cfg, "--force", "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(string(fileBytes(t, cfg)), "protected: true # keep") {
		t.Errorf("the flag or its comment was lost:\n%s", fileBytes(t, cfg))
	}
	saved := readCfg(t, cfg)
	if !saved.Users[1].Protected || !saved.Covers("ci", "web-1") {
		t.Errorf("ci = %+v, covers web-1 %v", saved.Users[1], saved.Covers("ci", "web-1"))
	}
	if owner, ok := saved.OwnerOf(fpOf(t, 5)); !ok || !saved.Covers(owner.Name, "web-1") {
		t.Errorf("the unknown key was not adopted:\n%s", fileBytes(t, cfg))
	}
}

// TestImportMergeKeepsProtected: merge is additive: a protected user's new
// server is appended, the flag and every existing grant stay.
func TestImportMergeKeepsProtected(t *testing.T) {
	home := hermeticHome(t)
	ciKey := filepath.Join(home, "ci")
	if err := os.WriteFile(ciKey+".pub", []byte(testkeys.Line(t, 4)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := writeConfig(t, "users:\n  - name: ci\n    protected: true # keep\n    keys: ["+qk(t, 4)+"]\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"+
		"access:\n  - {user: ci, servers: [web-1]}\n")
	path := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n  IdentityFile "+ciKey+"\n"+
		"Host web-2\n  HostName 10.0.0.2\n  User deploy\n  IdentityFile "+ciKey+"\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--merge", m, "-o", m, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(string(fileBytes(t, m)), "protected: true # keep") {
		t.Errorf("the flag or its comment was lost:\n%s", fileBytes(t, m))
	}
	saved := readCfg(t, m)
	if !saved.Users[0].Protected || !saved.Covers("ci", "web-1") || !saved.Covers("ci", "web-2") {
		t.Errorf("manifest:\n%s", fileBytes(t, m))
	}
}
