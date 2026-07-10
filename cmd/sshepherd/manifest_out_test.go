package main

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// Adopt must copy an existing wildcard entry's except: carve-out through to
// the generated manifest; entries without except must not emit the key.
func TestEncodeManifestExceptRoundTrip(t *testing.T) {
	m := manifestOut{
		Users: []userOut{
			{Name: "alice", Keys: []string{testkeys.Line(t, 1)}},
			{Name: "bob", Keys: []string{testkeys.Line(t, 2)}},
		},
		Servers: []serverOut{
			{Name: "db-1", Host: "10.0.0.2", User: "deploy"},
			{Name: "web-1", Host: "10.0.0.1", User: "deploy"},
		},
		Access: []accessOut{
			{User: "alice", Servers: []string{"*"}, Except: []string{"db-1"}},
			{User: "bob", Servers: []string{"web-1"}},
		},
	}
	got, err := encodeManifest("# header\n", m)
	if err != nil {
		t.Fatalf("encodeManifest: %v", err)
	}
	if !strings.HasPrefix(string(got), "# header\n") {
		t.Errorf("output %q lacks the header", got)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("round-trip rejected by config.Parse: %v", err)
	}
	if len(c.Access) != 2 || len(c.Access[0].Except) != 1 || c.Access[0].Except[0] != "db-1" {
		t.Errorf("Access = %+v, want alice's except [db-1] preserved", c.Access)
	}
	if strings.Contains(string(got), "except: []") {
		t.Errorf("output %q emits an explicit empty except for bob", got)
	}
}
