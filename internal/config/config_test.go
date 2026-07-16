package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
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
		{"key with line break", `
users:
  - {name: alice, keys: ["KEYA\nKEYB"]}
`, "line break"},
		{"comment with line break", `
users:
  - {name: alice, comment: "a\nb", keys: ["KEYA"]}
`, "comment contains a line break"},
		{"keyless operator", `
users:
  - {name: op, operator: true}
`, "operator requires at least one valid key"},
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
		{"wildcard not alone", `
users:
  - {name: alice, keys: ["KEYA"]}
servers:
  - {name: s1, host: h, user: u}
access:
  - {user: alice, servers: ["*", s1]}
`, "must be the only servers entry"},
		{"except without wildcard", `
users:
  - {name: alice, keys: ["KEYA"]}
servers:
  - {name: s1, host: h, user: u}
  - {name: s2, host: h2, user: u}
access:
  - {user: alice, servers: [s1], except: [s2]}
`, "except requires servers"},
		{"unknown except server", `
users:
  - {name: alice, keys: ["KEYA"]}
servers:
  - {name: s1, host: h, user: u}
access:
  - {user: alice, servers: ["*"], except: [nope]}
`, "unknown except server"},
		{"wildcard grants nothing", `
users:
  - {name: alice, keys: ["KEYA"]}
servers:
  - {name: s1, host: h, user: u}
access:
  - {user: alice, servers: ["*"], except: [s1]}
`, "grants no servers"},
		{"wildcard empty fleet", `
users:
  - {name: alice, keys: ["KEYA"]}
access:
  - {user: alice, servers: ["*"]}
`, "grants no servers"},
		{"reserved server name", `
servers:
  - {name: "*", host: h, user: u}
`, "reserved"},
		{"authorized_keys_file bare relative", `
servers:
  - {name: s, host: h, user: u, authorized_keys_file: .ssh/authorized_keys}
`, "absolute path or start with ~/"},
		{"authorized_keys_file lone tilde", `
servers:
  - {name: s, host: h, user: u, authorized_keys_file: "~"}
`, "absolute path or start with ~/"},
		{"authorized_keys_file bare tilde-slash", `
servers:
  - {name: s, host: h, user: u, authorized_keys_file: "~/"}
`, "absolute path or start with ~/"},
		{"authorized_keys_file tilde-user", `
servers:
  - {name: s, host: h, user: u, authorized_keys_file: "~deploy/.ssh/authorized_keys"}
`, "absolute path or start with ~/"},
		{"authorized_keys_file embedded newline", `
servers:
  - {name: s, host: h, user: u, authorized_keys_file: "/etc/keys\nrm -rf /"}
`, "control characters"},
		{"authorized_keys_file embedded ESC", `
servers:
  - {name: s, host: h, user: u, authorized_keys_file: "/etc/keys\u001b[31m"}
`, "control characters"},
		{"authorized_keys_file C1 CSI", `
servers:
  - {name: s, host: h, user: u, authorized_keys_file: "/etc/keys\u009bx"}
`, "control characters"},
		{"authorized_keys_file bidi override (Cf)", `
servers:
  - {name: s, host: h, user: u, authorized_keys_file: "/etc/keys\u202ex"}
`, "control characters"},
		{"authorized_keys_file too long", `
servers:
  - {name: s, host: h, user: u, authorized_keys_file: "/` + strings.Repeat("a", 4096) + `"}
`, "too long"},
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

// TestAuthorizedKeysFileAccepted pins the accept side of the override
// validation: absolute and ~/-prefixed paths pass, including paths with
// spaces and single quotes (rendering those inert is the quoting layer's
// job, not validation's), and the parsed field round-trips verbatim.
func TestAuthorizedKeysFileAccepted(t *testing.T) {
	tests := []struct {
		name, path string
	}{
		{"unset", ""},
		{"absolute", "/etc/ssh/authorized_keys.d/deploy"},
		{"home-relative", "~/.ssh/keys2"},
		{"explicit default is an override", "~/.ssh/authorized_keys"},
		{"spaces", "/etc/ssh keys/deploy"},
		{"single quote", "/etc/o'brien/keys"},
		{"tilde-double-slash allowed, resolves to $HOME/x (POSIX collapses //)", "~//x"},
		{"trailing slash allowed, fails at runtime", "/etc/keys/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			y := `
servers:
  - {name: s, host: h, user: u`
			if tt.path != "" {
				y += `, authorized_keys_file: "` + tt.path + `"`
			}
			y += "}\n"
			cfg, err := Parse([]byte(y))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := cfg.Servers[0].AuthorizedKeysFile; got != tt.path {
				t.Errorf("AuthorizedKeysFile = %q, want %q", got, tt.path)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("does-not-exist.yaml"); err == nil {
		t.Error("Load(missing) = nil error, want error")
	}
}

func TestAccessUnion(t *testing.T) {
	y := `
users:
  - {name: alice, keys: ["` + "KEYA" + `"]}
servers:
  - {name: s1, host: h1, user: u}
  - {name: s2, host: h2, user: u}
access:
  - {user: alice, servers: [s1]}
  - {user: alice, servers: [s2, s1]}
`
	cfg, err := Parse([]byte(strings.ReplaceAll(y, "KEYA", testkeys.Line(t, 1))))
	if err != nil {
		t.Fatalf("Parse: %v (multiple access entries for one user must union, not error)", err)
	}
	if got := len(cfg.DesiredFor("s2")); got != 1 {
		t.Errorf("DesiredFor(s2) = %d keys, want 1", got)
	}
}

func TestDesiredForAndOwnerOf(t *testing.T) {
	cfg, err := Parse([]byte(manifest(testkeys.Line(t, 1), testkeys.Line(t, 2))))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	web1 := cfg.DesiredFor("web-1") // alice + bob
	if len(web1) != 2 {
		t.Fatalf("DesiredFor(web-1) = %d keys, want 2", len(web1))
	}
	web2 := cfg.DesiredFor("web-2") // alice only
	if len(web2) != 1 {
		t.Fatalf("DesiredFor(web-2) = %d keys, want 1", len(web2))
	}
	if len(cfg.DesiredFor("nonexistent")) != 0 {
		t.Error("DesiredFor(nonexistent) should be empty")
	}

	owner, ok := cfg.OwnerOf(web2[0].Fingerprint)
	if !ok || owner.Name != "alice" {
		t.Errorf("OwnerOf = %q, %v; want alice, true", owner.Name, ok)
	}
	if _, ok := cfg.OwnerOf("SHA256:nope"); ok {
		t.Error("OwnerOf(unknown) = true, want false")
	}
}

// mustFingerprint parses a key line and returns its SHA256 fingerprint.
func mustFingerprint(t *testing.T, line string) string {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("mustFingerprint(%q): %v", line, err)
	}
	return k.Fingerprint
}

func TestDesiredForOrdering(t *testing.T) {
	// bob is granted access before alice; each user has two keys.
	// DesiredFor must emit keys in access-grant order, and within each user
	// in manifest key order — a refactor to map iteration must fail here.
	k1, k2 := testkeys.Line(t, 1), testkeys.Line(t, 2) // alice's keys
	k3, k4 := testkeys.Line(t, 3), testkeys.Line(t, 4) // bob's keys
	y := `
users:
  - {name: alice, keys: ["` + k1 + `", "` + k2 + `"]}
  - {name: bob, keys: ["` + k3 + `", "` + k4 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
access:
  - {user: bob, servers: [s1]}
  - {user: alice, servers: [s1]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := []string{ // bob first (access order), each user's keys in manifest order
		mustFingerprint(t, k3),
		mustFingerprint(t, k4),
		mustFingerprint(t, k1),
		mustFingerprint(t, k2),
	}
	got := cfg.DesiredFor("s1")
	if len(got) != len(want) {
		t.Fatalf("DesiredFor(s1) = %d keys, want %d", len(got), len(want))
	}
	for i, k := range got {
		if k.Fingerprint != want[i] {
			t.Errorf("DesiredFor(s1)[%d] = %s, want %s", i, k.Fingerprint, want[i])
		}
	}
}

func TestOperatorImplicitGrant(t *testing.T) {
	k1, k2 := testkeys.Line(t, 1), testkeys.Line(t, 2)
	y := `
users:
  - {name: op, operator: true, keys: ["` + k1 + `"]}
  - {name: alice, keys: ["` + k2 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
  - {name: s2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [s1]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !cfg.Users[0].Operator {
		t.Error("op.Operator = false, want true")
	}
	// s2 has no access entries at all — the operator is still desired there.
	s2 := cfg.DesiredFor("s2")
	if len(s2) != 1 || s2[0].Fingerprint != mustFingerprint(t, k1) {
		t.Fatalf("DesiredFor(s2) = %d keys, want exactly the operator key", len(s2))
	}
	// s1: operator first, then alice via her grant.
	want := []string{mustFingerprint(t, k1), mustFingerprint(t, k2)}
	got := cfg.DesiredFor("s1")
	if len(got) != len(want) {
		t.Fatalf("DesiredFor(s1) = %d keys, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Fingerprint != want[i] {
			t.Errorf("DesiredFor(s1)[%d] = %s, want %s", i, got[i].Fingerprint, want[i])
		}
	}
}

func TestOperatorOrderingUsersOrderFirst(t *testing.T) {
	// alice appears first in users AND access, yet both operators must come
	// first (in users order) — a refactor to grant-order-only must fail here.
	k1, k2, k3 := testkeys.Line(t, 1), testkeys.Line(t, 2), testkeys.Line(t, 3)
	y := `
users:
  - {name: alice, keys: ["` + k1 + `"]}
  - {name: op-a, operator: true, keys: ["` + k2 + `"]}
  - {name: op-b, operator: true, keys: ["` + k3 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [s1]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{mustFingerprint(t, k2), mustFingerprint(t, k3), mustFingerprint(t, k1)}
	got := cfg.DesiredFor("s1")
	if len(got) != len(want) {
		t.Fatalf("DesiredFor(s1) = %d keys, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Fingerprint != want[i] {
			t.Errorf("DesiredFor(s1)[%d] = %s, want %s", i, got[i].Fingerprint, want[i])
		}
	}
}

func TestOperatorRedundantGrantNotDuplicated(t *testing.T) {
	k1 := testkeys.Line(t, 1)
	y := `
users:
  - {name: op, operator: true, keys: ["` + k1 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
access:
  - {user: op, servers: [s1]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v (a redundant grant for an operator must union silently)", err)
	}
	if got := len(cfg.DesiredFor("s1")); got != 1 {
		t.Errorf("DesiredFor(s1) = %d keys, want 1 (no duplicate emission)", got)
	}
}

func TestWildcardAccess(t *testing.T) {
	k1 := testkeys.Line(t, 1)
	// except lists s2 twice: duplicates are tolerated, not errors.
	y := `
users:
  - {name: alice, keys: ["` + k1 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
  - {name: s2, host: 10.0.0.2, user: deploy}
  - {name: s3, host: 10.0.0.3, user: deploy}
access:
  - {user: alice, servers: ["*"], except: [s2, s2]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for name, want := range map[string]int{"s1": 1, "s2": 0, "s3": 1} {
		if got := len(cfg.DesiredFor(name)); got != want {
			t.Errorf("DesiredFor(%s) = %d keys, want %d", name, got, want)
		}
	}
}

func TestOperatorAndWildcardCompose(t *testing.T) {
	k1, k2 := testkeys.Line(t, 1), testkeys.Line(t, 2)
	// An operator and a wildcard-granted user in one manifest: every server
	// desires the operator's key first, then the wildcard user's.
	y := `
users:
  - {name: op, operator: true, keys: ["` + k1 + `"]}
  - {name: alice, keys: ["` + k2 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
  - {name: s2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: ["*"]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{mustFingerprint(t, k1), mustFingerprint(t, k2)}
	for _, srv := range []string{"s1", "s2"} {
		got := cfg.DesiredFor(srv)
		if len(got) != len(want) {
			t.Fatalf("DesiredFor(%s) = %d keys, want %d", srv, len(got), len(want))
		}
		for i := range want {
			if got[i].Fingerprint != want[i] {
				t.Errorf("DesiredFor(%s)[%d] = %s, want %s", srv, i, got[i].Fingerprint, want[i])
			}
		}
	}
}

func TestWildcardAndExplicitEntriesUnion(t *testing.T) {
	k1 := testkeys.Line(t, 1)
	// A wildcard-with-except entry and a later explicit entry for the same
	// user must union: s2 is excepted by the first grant but restored by the
	// second, so alice ends up on every server exactly once.
	y := `
users:
  - {name: alice, keys: ["` + k1 + `"]}
servers:
  - {name: s1, host: 10.0.0.1, user: deploy}
  - {name: s2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: ["*"], except: [s2]}
  - {user: alice, servers: [s2]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, name := range []string{"s1", "s2"} {
		if got := len(cfg.DesiredFor(name)); got != 1 {
			t.Errorf("DesiredFor(%s) = %d keys, want 1", name, got)
		}
	}
}
