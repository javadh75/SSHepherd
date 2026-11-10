package main

import (
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestAdoptRegenerateKeepsJumpOnly: the round-trip sample keeps JumpOnly
// false, so this pins that a jump_only bastion and its dependent's via
// survive generateAdoptManifest (spec S5 "Manifest tooling").
func TestAdoptRegenerateKeepsJumpOnly(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	cfg.Servers = []config.Server{
		{Name: "bastion-eu", Host: "bastion.example.com", Port: 22, User: "jump", JumpOnly: true},
		{Name: "web-1", Host: "10.0.1.5", Port: 22, User: "deploy", Via: "bastion-eu"},
	}
	cfg.Access = []config.Access{{User: "bob", Servers: []string{"web-1"}}}
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err != nil || !reflect.DeepEqual(got.Servers, cfg.Servers) {
		t.Errorf("adopt changed the servers (err %v):\n%s", err, out)
	}
}

// TestValidateJumpOnly: validate counts a jump_only server, warns that its
// host key is not recorded, and reports jump_only_unused (exit 0, 1 under
// --strict).
func TestValidateJumpOnly(t *testing.T) {
	path := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n"+
		"servers:\n  - {name: bastion-eu, host: 10.9.0.1, user: jump, jump_only: true}\n  - {name: web-1, host: 10.0.1.5, user: deploy, via: bastion-eu}\n"+
		"access:\n  - {user: alice, servers: [\"*\"]}\n")
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 0 || out != "manifest OK: 1 user, 2 servers, 1 grant (1 warning)\n" || !strings.Contains(stderr, "bastion-eu") {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	unused := writeConfig(t, "users: []\nservers:\n  - {name: bastion-eu, host: 10.9.0.1, user: jump, jump_only: true}\n")
	code, out, _ = validateCLI(t, "--strict", "--json", "--config", unused, "--known-hosts", recordedKnownHosts(t, "10.9.0.1"))
	if code != 1 {
		t.Fatalf("--strict: exit = %d, want 1", code)
	}
	ws, _ := oneJSONDoc(t, out)["manifest_warnings"].([]any)
	want := map[string]any{"kind": "jump_only_unused", "server": "bastion-eu",
		"message": `server "bastion-eu": jump_only but no server has via: bastion-eu; nothing connects through it and nothing checks it`}
	if len(ws) != 1 || !reflect.DeepEqual(ws[0], want) {
		t.Errorf("manifest_warnings = %v, want exactly %v", ws, want)
	}
}
