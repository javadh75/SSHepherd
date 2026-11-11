package config

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestOptionValuesRefusedAtLoad (review F003): a value sshd rejects makes it
// skip the line, so the manifest refuses it at load, on a key line and on a
// grant, and accepts the good spellings of both. F025's names load too.
func TestOptionValuesRefusedAtLoad(t *testing.T) {
	key := testkeys.Line(t, 1)
	manifest := func(keyOpts, grantOpts string) string {
		y := "users:\n  - {name: alice, keys: ['" + keyOpts + key + "']}\n" +
			"servers:\n  - {name: web-1, host: h, user: u}\n" +
			"access:\n  - {user: alice, servers: [web-1]"
		if grantOpts != "" {
			y += ", options: ['" + grantOpts + "']"
		}
		return y + "}\n"
	}
	const (
		wantPort = "has an invalid value (want host:port or host:*, port 1-65535)"
		wantEnv  = "has an invalid value (want NAME=value, NAME of letters, digits and _)"
		wantTun  = "has an invalid value (want a number up to 2147483645 or any)"
		wantList = "has an invalid value (want [host:]port or *, port 1-65535)"
	)
	for _, tt := range []struct{ name, yaml, want string }{
		{"key line permitopen", manifest(`permitopen="db.internal" `, ""), wantPort},
		{"key line permitlisten", manifest(`permitlisten="nope" `, ""), wantList},
		{"key line environment", manifest(`environment="FOO" `, ""), wantEnv},
		{"key line tunnel", manifest(`tunnel="abc" `, ""), wantTun},
		{"grant permitopen", manifest("", `permitopen="db.internal"`), wantPort},
		{"grant permitlisten", manifest("", `permitlisten="nope"`), wantList},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Parse([]byte(tt.yaml)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Parse = %v, want an error containing %q", err, tt.want)
			}
		})
	}
	for _, y := range []string{
		manifest(`permitopen="db.internal:5432" `, ""),
		manifest(`permitlisten="8080",environment="FOO=1",tunnel="any" `, ""),
		manifest("touch-required ", ""),
		manifest("no-verify-required ", ""),
		manifest("", `permitopen="db.internal:*"`),
		manifest("", "touch-required"),
	} {
		if _, err := Parse([]byte(y)); err != nil {
			t.Errorf("Parse(%s) = %v, want nil", y, err)
		}
	}
	// no-verify-required is not a restriction, so a grant may not add it.
	if _, err := Parse([]byte(manifest("", "no-verify-required"))); err == nil {
		t.Error("Parse(grant no-verify-required) = nil, want a refusal (it restricts nothing)")
	}
}
