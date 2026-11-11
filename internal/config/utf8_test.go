package config

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestParseRefusesInvalidUTF8 (review F008): YAML text is UTF-8, so only a
// !!binary scalar can put other bytes in a string field. A raw 0x9B is an
// 8-bit CSI for a terminal in an 8-bit locale, and every string field is
// printed somewhere (reports, plans, errors), so any such field is a load
// error naming its path.
func TestParseRefusesInvalidUTF8(t *testing.T) {
	key := testkeys.Line(t, 1)
	tests := []struct{ name, yaml, want string }{
		{"server host", `
servers:
  - {name: web-1, host: !!binary MTAuMC4wLjGbMkqbMzFtRkFLRQ==, user: deploy}
`, "servers[0].host is not valid UTF-8"},
		{"user comment", `
users:
  - {name: alice, comment: !!binary YWybMzFtaWNl, keys: ["` + key + `"]}
`, "users[0].comment is not valid UTF-8"},
		{"user description", `
users:
  - {name: alice, description: !!binary d2Vi/w==, keys: ["` + key + `"]}
`, "users[0].description is not valid UTF-8"},
		{"key line", `
users:
  - name: alice
    keys:
      - "` + key + `"
      - !!binary b3Bzmw==
`, "users[0].keys[1] is not valid UTF-8"},
		{"server tag", `
servers:
  - {name: web-1, host: h, user: deploy, tags: [!!binary ZGVwbG95ww==]}
`, "servers[0].tags[0] is not valid UTF-8"},
		{"access option", `
users:
  - {name: alice, keys: ["` + key + `"]}
servers:
  - {name: web-1, host: h, user: deploy}
access:
  - {user: alice, servers: [web-1], options: [!!binary b3Bzmw==]}
`, "access[0].options[0] is not valid UTF-8"},
		{"revoked reason", `
revoked:
  - {user: carol, servers: [web-1], date: 2026-11-08, reason: !!binary YWybMzFtaWNl}
`, "revoked[0].reason is not valid UTF-8"},
		{"preserve rule", `
servers:
  - name: web-1
    host: h
    user: deploy
    preserve:
      - {command: !!binary YWybMzFtaWNl}
`, "servers[0].preserve[0].command is not valid UTF-8"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse = %v, want an error containing %q", err, tt.want)
			}
			if strings.IndexByte(err.Error(), 0x9b) >= 0 || strings.IndexByte(err.Error(), 0xff) >= 0 {
				t.Errorf("error %q carries the raw bytes", err)
			}
		})
	}
	// A !!binary scalar holding valid UTF-8 is only an odd spelling.
	if _, err := Parse([]byte("users:\n  - {name: !!binary YWxpY2U=, keys: [\"" + key + "\"]}\n")); err != nil {
		t.Errorf("Parse(valid UTF-8 !!binary) = %v, want nil", err)
	}
}

// TestServerFieldIssueInvalidUTF8: import feeds ssh config values (any
// bytes) through ServerFieldIssue, and authorized_keys_file reaches a remote
// shell; neither may carry invalid UTF-8.
func TestServerFieldIssueInvalidUTF8(t *testing.T) {
	for _, s := range []string{"10.0.0.1\x9b2J", "web\xff", "deploy\xc3"} {
		if got := ServerFieldIssue(s); got != "contains control or format characters" {
			t.Errorf("ServerFieldIssue(%q) = %q, want the unsafe-text refusal", s, got)
		}
		if errs := validateAuthorizedKeysFile("s", "/etc/keys/"+s); len(errs) == 0 || !strings.Contains(errs[0].Error(), "control characters") {
			t.Errorf("validateAuthorizedKeysFile(%q) = %v, want the control-character refusal", s, errs)
		}
	}
}
