package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// manifest builds a minimal valid YAML manifest with the given key lines.
func manifest(keyA, keyB string) string {
	return fmt.Sprintf(`
users:
  - name: alice
    description: "Platform team lead"
    comment: "alice@sshepherd"
    keys:
      - "%s"
  - name: bob
    keys:
      - "%s"
servers:
  - name: web-1
    description: "Primary web frontend"
    host: 10.0.0.1
    user: deploy
  - name: web-2
    host: 10.0.0.2
    port: 2222
    user: deploy
access:
  - user: alice
    servers: [web-1, web-2]
  - user: bob
    servers: [web-1]
`, keyA, keyB)
}

func TestParseValid(t *testing.T) {
	cfg, err := Parse([]byte(manifest(testkeys.Line(t, 1), testkeys.Line(t, 2))))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Users) != 2 || len(cfg.Servers) != 2 || len(cfg.Access) != 2 {
		t.Fatalf("counts = %d users, %d servers, %d access; want 2/2/2",
			len(cfg.Users), len(cfg.Servers), len(cfg.Access))
	}
	if cfg.Servers[0].Port != 22 {
		t.Errorf("web-1 Port = %d, want default 22", cfg.Servers[0].Port)
	}
	if cfg.Servers[1].Port != 2222 {
		t.Errorf("web-2 Port = %d, want 2222", cfg.Servers[1].Port)
	}
	if cfg.Users[0].Comment != "alice@sshepherd" {
		t.Errorf("alice Comment = %q", cfg.Users[0].Comment)
	}
}

func TestParseEmptyManifest(t *testing.T) {
	cfg, err := Parse(nil)
	if err != nil {
		t.Fatalf("Parse(empty): %v", err)
	}
	if len(cfg.Servers) != 0 {
		t.Errorf("empty manifest has %d servers", len(cfg.Servers))
	}
}

func TestParseInvalid(t *testing.T) {
	kA := func(t *testing.T) string { return testkeys.Line(t, 1) }
	tests := []struct {
		name, yaml, wantErr string
	}{
		{"yaml syntax", "users: [", "parse manifest"},
		{"unknown field", "userz:\n  - name: x\n", "field userz not found"},
		{"dup user name", `
users:
  - {name: alice, keys: ["` + "KEYA" + `"]}
  - {name: alice, keys: ["` + "KEYB" + `"]}
`, "duplicate user"},
		{"dup server name", `
servers:
  - {name: s, host: h, user: u}
  - {name: s, host: h2, user: u}
`, "duplicate server"},
		{"bad key", `
users:
  - {name: alice, keys: ["not a key"]}
`, "not a key"},
		{"dup key same user", `
users:
  - name: alice
    keys: ["KEYA", "KEYA"]
`, "duplicate key"},
		{"dup key across users", `
users:
  - {name: alice, keys: ["KEYA"]}
  - {name: bob, keys: ["KEYA"]}
`, "duplicate key"},
		{"access unknown user", `
access:
  - {user: ghost, servers: []}
`, "unknown user"},
		{"access unknown server", `
users:
  - {name: alice, keys: ["KEYA"]}
access:
  - {user: alice, servers: [nope]}
`, "unknown server"},
		{"server missing host", `
servers:
  - {name: s, user: u}
`, "host"},
		{"server bad port", `
servers:
  - {name: s, host: h, user: u, port: 70000}
`, "port"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := strings.ReplaceAll(tt.yaml, "KEYA", kA(t))
			y = strings.ReplaceAll(y, "KEYB", testkeys.Line(t, 2))
			_, err := Parse([]byte(y))
			if err == nil {
				t.Fatal("Parse succeeded, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("does-not-exist.yaml"); err == nil {
		t.Error("Load(missing) = nil error, want error")
	}
}
