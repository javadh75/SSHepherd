package adopt

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
)

var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

// goldenPlan holds one of everything the document reports.
func goldenPlan() Plan {
	return Plan{
		NewUsers:   []NewUser{{Name: "u-laptop", Line: "ssh-ed25519 AAAA", Fingerprint: "SHA256:fpLaptop", Type: "ssh-ed25519", FoundOn: []string{"web-1"}}},
		Extensions: []Extension{{User: "bob", Servers: []string{"db-1"}}},
		Issues: []Issue{
			{Server: "db-3", Kind: fleet.ErrorKindDial, Detail: "dial 10.0.0.3:22: connection refused", Hint: "check the host, port, and firewall"},
			{Server: "web-9", Detail: "line 3: invalid key"},
		},
		Warnings: []Warning{{
			Kind: WarnRevokedKeySkipped, Server: "web-2", Fingerprint: "SHA256:fpOld", User: "alice", Date: "2026-11-08",
			Message: "key SHA256:fpOld on web-2 is REVOKED (2026-11-08, alice) — not adopted; run 'sshepherd apply --server web-2' to remove it",
		}},
	}
}

func TestWriteJSONEmittedGolden(t *testing.T) {
	var out bytes.Buffer
	err := WriteJSON(&out, goldenPlan(), Report{
		Mode: ModeMerge, Emitted: true,
		Placement: Placement{Output: &Output{Path: "fleet.yaml", Written: true}},
		Servers:   12, Read: 11, PartlyRead: 1, ExitCode: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_emitted.golden.json", out.Bytes())
}

func TestWriteJSONStoppedGolden(t *testing.T) {
	var out bytes.Buffer
	if err := WriteJSON(&out, goldenPlan(), Report{Mode: ModeGenerate, Servers: 2, Read: 1, ExitCode: 1}); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_stopped.golden.json", out.Bytes())
}

// TestWriteJSONZeroReadGolden is the one exit 3 with a document.
func TestWriteJSONZeroReadGolden(t *testing.T) {
	var out bytes.Buffer
	p := Plan{Issues: []Issue{{Server: "web-1", Kind: fleet.ErrorKindDial, Detail: "dial 10.0.0.1:22: connection refused", Hint: "check the host, port, and firewall"}}}
	if err := WriteJSON(&out, p, Report{Mode: ModeGenerate, Servers: 1, Read: 0, ExitCode: 3}); err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_zero_read.golden.json", out.Bytes())
}

// TestWriteJSONManifestGolden is an exit 0 run with no -o.
func TestWriteJSONManifestGolden(t *testing.T) {
	var out bytes.Buffer
	yaml := "# generated\nusers: []\n"
	err := WriteJSON(&out, Plan{}, Report{Mode: ModeGenerate, Emitted: true, Placement: Placement{Manifest: &yaml}, Servers: 1, Read: 1, ExitCode: 0})
	if err != nil {
		t.Fatal(err)
	}
	checkGolden(t, "json_manifest.golden.json", out.Bytes())
}

// TestWriteJSONManifestField: with no -o the YAML is in the document.
func TestWriteJSONManifestField(t *testing.T) {
	var out bytes.Buffer
	yaml := "# generated\nusers: []\n"
	if err := WriteJSON(&out, Plan{}, Report{Mode: ModeGenerate, Emitted: true, Placement: Placement{Manifest: &yaml}}); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["manifest"] != yaml {
		t.Errorf("manifest = %v, want the YAML unchanged", doc["manifest"])
	}
	if _, ok := doc["output"]; ok {
		t.Errorf("document has output alongside manifest: %s", out.String())
	}
}

// TestWriteJSONListsAreNeverNull: a script's .warnings[] must not fail.
func TestWriteJSONListsAreNeverNull(t *testing.T) {
	var out bytes.Buffer
	if err := WriteJSON(&out, Plan{}, Report{Mode: ModeGenerate}); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"new_users": []`, `"extensions": []`, `"unreadable": []`, `"line_issues": []`, `"warnings": []`} {
		if !strings.Contains(out.String(), field) {
			t.Errorf("document lacks %s:\n%s", field, out.String())
		}
	}
	for _, field := range []string{`"output"`, `"manifest"`} {
		if strings.Contains(out.String(), field) {
			t.Errorf("a stopped run's document must not carry %s:\n%s", field, out.String())
		}
	}
}

// TestWriteJSONSanitizes: encoding/json does not escape C1 or Cf runes, so
// remote text is stripped before it reaches a terminal through jq.
func TestWriteJSONSanitizes(t *testing.T) {
	csi, bidi := string(rune(0x9b)), string(rune(0x202e))
	hostile := "x" + csi + bidi + "y"
	p := Plan{
		Issues: []Issue{
			{Server: hostile, Kind: fleet.ErrorKindDial, Detail: hostile, Hint: hostile},
			{Server: hostile, Detail: hostile},
		},
		Warnings: []Warning{{Kind: WarnCommentDropped, Server: hostile, User: hostile, Date: hostile, Message: hostile}},
	}
	var out bytes.Buffer
	if err := WriteJSON(&out, p, Report{Mode: ModeGenerate}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), csi) || strings.Contains(out.String(), bidi) {
		t.Errorf("hostile runes survived:\n%q", out.String())
	}
	if got := strings.Count(out.String(), `"detail": "xy"`); got != 2 {
		t.Errorf("sanitized detail appears %d times, want 2 (unreadable and line_issues):\n%s", got, out.String())
	}
	if !strings.Contains(out.String(), `"hint": "xy"`) || !strings.Contains(out.String(), `"message": "xy"`) {
		t.Errorf("sanitized text missing:\n%s", out.String())
	}
	if got := strings.Count(out.String(), `"server": "xy"`); got != 3 {
		t.Errorf("sanitized server appears %d times, want 3 (one issue row each, one warning):\n%s", got, out.String())
	}
}
