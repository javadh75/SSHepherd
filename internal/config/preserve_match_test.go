package config

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestPreserveRuleFor (spec S6 "What a line is"): a command rule matches the
// whole dequoted command="…" value, a comment rule the whole comment; the
// first matching rule names the kind; another server's rules never apply.
func TestPreserveRuleFor(t *testing.T) {
	cfg := mustParse(t, preserveFleet(t,
		"[{command: '/usr/local/bin/gitea serv key-[0-9]+'}, {comment: 'google-ssh .*'}]",
		"  - {name: web-1, host: 10.0.1.5, user: deploy}\n"))
	k7 := testkeys.Line(t, 7)
	for _, tc := range []struct{ name, server, line, want string }{
		{"command", "gitea", `command="/usr/local/bin/gitea serv key-12",no-pty ` + k7, PreserveCommand},
		{"command is a full match", "gitea", `command="/usr/local/bin/gitea serv key-12; sh" ` + k7, ""},
		{"quoted quote", "gitea", `command="/usr/local/bin/gitea serv key-1\"" ` + k7, ""},
		{"comment", "gitea", k7 + ` google-ssh {"userName":"a@example.com"}`, PreserveComment},
		{"comment is a full match", "gitea", k7 + " x google-ssh y", ""},
		{"a comment never matches a command rule", "gitea", k7 + " /usr/local/bin/gitea serv key-1", ""},
		{"no command=", "gitea", k7, ""},
		{"first rule wins", "gitea", `command="/usr/local/bin/gitea serv key-1" ` + k7 + " google-ssh x", PreserveCommand},
		{"another server's rules", "web-1", `command="/usr/local/bin/gitea serv key-12" ` + k7, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k, err := authkeys.ParseLine(tc.line)
			if err != nil || k == nil {
				t.Fatalf("ParseLine: %v", err)
			}
			if got := cfg.PreserveRuleFor(tc.server, *k); got != tc.want {
				t.Errorf("PreserveRuleFor = %q, want %q", got, tc.want)
			}
		})
	}
}
