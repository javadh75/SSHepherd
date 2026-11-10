package config

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// giteaRule is the design's command: example.
const giteaRule = `/usr/local/bin/gitea --config=/etc/gitea/app.ini serv key-[0-9]+`

// preserveFleet: alice (k1) granted gitea, whose preserve: value is
// preserve verbatim (a YAML flow sequence); extra is more server entries.
func preserveFleet(t *testing.T, preserve, extra string) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: gitea, host: git.example.com, user: git, preserve: " + preserve + "}\n" + extra +
		"access:\n  - {user: alice, servers: [gitea]}\n"
}

// TestPreserveAccepted: valid rules load and every one is compiled under the
// server's name; a server without preserve: has no entry.
func TestPreserveAccepted(t *testing.T) {
	for name, preserve := range map[string]string{
		"command":              "[{command: '" + giteaRule + "'}]",
		"comment":              "[{comment: 'google-ssh .*'}]",
		"both kinds":           "[{command: '" + giteaRule + "'}, {comment: 'google-ssh .*'}]",
		"anchors written":      "[{command: '^/usr/local/bin/gitea serv key-[0-9]+$'}]",
		"factored alternation": "[{command: 'gitea serv|gitea hook'}]", // LiteralPrefix "gitea " (gap 6)
		"exact command":        "[{command: '/usr/bin/rrsync'}]",       // anchored: no probe is this exact text
		"512 bytes":            "[{comment: 'gitea " + strings.Repeat("a", 506) + "'}]",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := mustParse(t, preserveFleet(t, preserve, "  - {name: web-1, host: 10.0.1.5, user: deploy}\n"))
			if got, want := len(cfg.preserve["gitea"]), len(cfg.Servers[0].Preserve); got != want || want == 0 {
				t.Errorf("compiled %d rules, want %d", got, want)
			}
			if _, ok := cfg.preserve["web-1"]; ok {
				t.Error("web-1 has no preserve: but got compiled rules")
			}
		})
	}
}

// TestPreserveRefused (spec S6 Validation): every rule that could keep a
// stranger's key is a load error naming the server and the rule's index.
func TestPreserveRefused(t *testing.T) {
	const prefixErr = "must start with at least 4 literal bytes"
	for _, tc := range []struct{ name, preserve, want string }{
		{"neither field", "[{}]", `server "gitea": preserve[0]: set exactly one of command: or comment:`},
		{"both fields", "[{command: 'gitea serv', comment: 'gitea .*'}]", `server "gitea": preserve[0]: set exactly one of command: or comment:`},
		{"second rule", "[{comment: 'google-ssh .*'}, {comment: '.*'}]", `server "gitea": preserve[1]: pattern ".*" ` + prefixErr},
		{"too long", "[{comment: '" + strings.Repeat("a", 513) + "'}]", `preserve[0]: pattern is 513 bytes, at most 512`},
		{"bad regex", "[{command: 'gitea serv ('}]", `preserve[0]: pattern does not compile`},
		{"unterminated \\Q", `[{command: '\Qgitea serv'}]`, `preserve[0]: pattern does not compile`},
		{"empty match (refused by the prefix rule)", "[{command: '(abcd)?'}]", prefixErr}, // gap 6: "" and "x" are subsumed
		{".+", "[{command: '.+'}]", prefixErr},
		{".{10,}", "[{comment: '.{10,}'}]", prefixErr},
		{"email-ish", `[{comment: '.+@.+\..+'}]`, prefixErr},
		{"/.*", "[{command: '/.*'}]", prefixErr},
		{"(?i)", "[{command: '(?i)gitea serv'}]", prefixErr},
		{"short shared prefix", "[{command: 'gitea|gitlab'}]", prefixErr}, // LiteralPrefix "git"
		{"user@host", "[{comment: 'user@[a-z]+'}]", `also matches "user@host"`},
		{"laptop", "[{comment: 'alice@.*'}]", `also matches "alice@laptop.local"`},
		{"ec2", "[{comment: 'root@ip-.*'}]", `also matches "root@ip-10-0-0-1.ec2.internal"`},
		{"keygen default", "[{comment: 'ed25519-key-[0-9]+'}]", `also matches "ed25519-key-20260101"`},
		{"64 a", "[{comment: 'aaaa+'}]", `also matches "` + strings.Repeat("a", 64) + `"`},
		{"/bin/sh", "[{command: '/bin/.*'}]", `also matches "/bin/sh"`},
		{"rrsync", "[{command: '/usr/bin/rrsync .*'}]", `also matches "/usr/bin/rrsync /srv"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(preserveFleet(t, tc.preserve, "")))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

// TestPreserveOnJumpOnly: a jump_only server has no managed file, so a rule
// there could keep nothing; the design's message, verbatim.
func TestPreserveOnJumpOnly(t *testing.T) {
	y := "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: edge, host: edge.example.com, user: jump, jump_only: true, preserve: [{comment: 'google-ssh .*'}]}\n" +
		"  - {name: web-1, host: 10.0.1.5, user: deploy, via: edge}\n" +
		"access:\n  - {user: alice, servers: [web-1]}\n"
	_, err := Parse([]byte(y))
	if want := `server "edge": jump_only has no managed file; remove preserve`; err == nil || !strings.Contains(err.Error(), want) {
		t.Errorf("err = %v, want %q", err, want)
	}
}
