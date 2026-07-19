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
`, "comment contains control or format characters"},
		{"name with newline", `
users:
  - {name: "x\nEVIL", keys: ["KEYA"]}
`, "name contains control or format characters"},
		{"name with escape byte", `
users:
  - {name: "x\u001B[31m", keys: ["KEYA"]}
`, "name contains control or format characters"},
		{"name with bidi override", `
users:
  - {name: "x\u202Evil", keys: ["KEYA"]}
`, "name contains control or format characters"},
		{"name with trailing space", `
users:
  - {name: "alice ", keys: ["KEYA"]}
`, "name has leading or trailing whitespace"},
		{"comment with control char", `
users:
  - {name: alice, comment: "a\u0007b", keys: ["KEYA"]}
`, "comment contains control or format characters"},
		{"comment untrimmed", `
users:
  - {name: alice, comment: " alice@work", keys: ["KEYA"]}
`, "comment has leading or trailing whitespace"},
		{"comment all whitespace", `
users:
  - {name: alice, comment: "   ", keys: ["KEYA"]}
`, "comment has leading or trailing whitespace"},
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

// TestDesiredComment pins the decided write-time comment order
// (2026-07-16 comment-policy memo, Option A): user comment: → the key's own
// inline comment → the user's name.
func TestDesiredComment(t *testing.T) {
	tests := []struct {
		name     string
		userName string
		comment  string // users[].comment
		inline   string // the key line's own trailing comment
		want     string
	}{
		{"user comment wins over inline", "alice", "alice@corp", "alice@laptop", "alice@corp"},
		{"user comment wins with no inline", "alice", "alice@corp", "", "alice@corp"},
		{"inline comment is the fallback", "alice", "", "alice@laptop", "alice@laptop"},
		{"name is the last resort", "alice", "", "", "alice"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := User{Name: tt.userName, Comment: tt.comment}
			k := authkeys.Key{Comment: tt.inline}
			if got := DesiredComment(u, k); got != tt.want {
				t.Errorf("DesiredComment = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestCommentMultiKeyWarning: comment: on a multi-key user collapses every
// key to one comment at apply time — validation must warn (never error) so
// the collapse is a conscious choice.
func TestCommentMultiKeyWarning(t *testing.T) {
	k1, k2 := testkeys.Line(t, 1), testkeys.Line(t, 2)
	t.Run("comment with two keys warns", func(t *testing.T) {
		y := `
users:
  - {name: alice, comment: "alice@corp", keys: ["` + k1 + `", "` + k2 + `"]}
`
		cfg, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("Parse: %v (multi-key comment must warn, not error)", err)
		}
		want := `user "alice": comment is set on a user with 2 keys; apply will write the same comment on every key`
		if len(cfg.Warnings) != 1 || cfg.Warnings[0] != want {
			t.Errorf("Warnings = %q, want exactly [%q]", cfg.Warnings, want)
		}
	})
	t.Run("comment with one key: no warning", func(t *testing.T) {
		y := `
users:
  - {name: alice, comment: "alice@corp", keys: ["` + k1 + `"]}
`
		cfg, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(cfg.Warnings) != 0 {
			t.Errorf("Warnings = %q, want none", cfg.Warnings)
		}
	})
	t.Run("two keys without comment: no warning", func(t *testing.T) {
		y := `
users:
  - {name: alice, keys: ["` + k1 + `", "` + k2 + `"]}
`
		cfg, err := Parse([]byte(y))
		if err != nil {
			t.Fatalf("Parse: %v", err)
		}
		if len(cfg.Warnings) != 0 {
			t.Errorf("Warnings = %q, want none", cfg.Warnings)
		}
	})
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

// coverageCfg exercises every grant shape Covers must see: an operator with
// no access entries, an explicit grant, a wildcard with an except carve-out,
// and a wildcard whose except is restored by a later explicit entry.
func coverageCfg(t *testing.T) *Config {
	t.Helper()
	y := `
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 7) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
  - {name: db-1, host: 10.0.0.3, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: ["*"], except: [db-1]}
  - {user: carol, servers: ["*"], except: [db-1]}
  - {user: carol, servers: [db-1]}
`
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func TestCovers(t *testing.T) {
	cfg := coverageCfg(t)
	cases := []struct {
		name         string
		user, server string
		want         bool
	}{
		{"explicit grant", "alice", "web-1", true},
		{"explicit grant does not spread", "alice", "web-2", false},
		{"wildcard covers existing server", "bob", "web-2", true},
		{"wildcard covers not-yet-existing server", "bob", "new-9", true},
		{"except carve-out", "bob", "db-1", false},
		{"except restored by explicit entry", "carol", "db-1", true},
		{"explicit grant, not-yet-existing server", "alice", "new-9", false},
		{"unknown user", "mallory", "web-1", false},
		// The doc-comment contract: an operator's implicit fleet-wide grant
		// is deliberately excluded — callers check Operator first.
		{"operator implicit grant excluded", "op", "web-1", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfg.Covers(tc.user, tc.server); got != tc.want {
				t.Errorf("Covers(%q, %q) = %v, want %v", tc.user, tc.server, got, tc.want)
			}
		})
	}
}

func TestExceptCarveOut(t *testing.T) {
	cfg := coverageCfg(t)
	cases := []struct {
		name         string
		user, server string
		want         bool
	}{
		{"wildcard except", "bob", "db-1", true},
		{"wildcard, server not excepted", "bob", "web-1", false},
		{"explicit-only user has no carve-outs", "alice", "db-1", false},
		{"unknown user", "mallory", "db-1", false},
		{"not-yet-existing server", "bob", "new-9", false},
		// Out-of-contract pin (the caveat): carol's carve-out reports true
		// even though a later explicit entry restores the grant — callers
		// must ask only about pairs the grant union does not cover
		// (i.e. after Covers returned false).
		{"caveat: excepted but explicitly re-granted", "carol", "db-1", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cfg.ExceptCarveOut(tc.user, tc.server); got != tc.want {
				t.Errorf("ExceptCarveOut(%q, %q) = %v, want %v", tc.user, tc.server, got, tc.want)
			}
		})
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
