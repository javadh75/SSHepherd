package manifest

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

const keptLine = "protected: true # keep"

// protectedEditFixture: ci (seed 2, block style) is protected with a comment;
// bob (seed 4) is a plain grantee.
func protectedEditFixture(tb testing.TB) string {
	tb.Helper()
	return `users:
  - name: ci
    # the deploy runner
    ` + keptLine + `
    keys:
      - ` + testkeys.Line(tb, 2) + `
  - {name: bob, keys: ["` + testkeys.Line(tb, 4) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - user: ci
    servers: [web-1, web-2]
  - {user: bob, servers: [web-1]}
# end of manifest
`
}

// TestEditsKeepProtectedField: every edit that touches a sibling entry or key
// keeps protected: true and its comment.
func TestEditsKeepProtectedField(t *testing.T) {
	newLine := testkeys.Line(t, 6)
	for _, tc := range []struct {
		name string
		edit func(*File) error
	}{
		{"RemoveKey of another user's key", func(f *File) error { _, _, err := f.RemoveKey(keyFP(t, 4)); return err }},
		{"RemoveKey of the last key", func(f *File) error { _, _, err := f.RemoveKey(keyFP(t, 2)); return err }},
		{"ReplaceKey", func(f *File) error { return f.ReplaceKey("ci", keyFP(t, 2), newLine) }},
		{"AddKeyAfter", func(f *File) error { return f.AddKeyAfter("ci", keyFP(t, 2), newLine) }},
		{"RemoveAccess", func(f *File) error { _, err := f.RemoveAccess("ci", []string{"web-1"}); return err }},
		{"SetOperator off is a no-op on protected", func(f *File) error { return f.SetOperator("ci", false) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := Load([]byte(protectedEditFixture(t)))
			if err != nil {
				t.Fatal(err)
			}
			if err := tc.edit(f); err != nil {
				t.Fatalf("edit: %v", err)
			}
			out, err := f.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if !strings.Contains(string(out), keptLine) || !strings.Contains(string(out), "# the deploy runner") {
				t.Errorf("the protected field or its comment was lost:\n%s", out)
			}
		})
	}
}

// TestRemoveUserTakesProtectedField: a manifest edit that removes a user
// removes the flag with it.
func TestRemoveUserTakesProtectedField(t *testing.T) {
	f, err := Load([]byte(protectedEditFixture(t)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.RemoveUser("ci"); err != nil {
		t.Fatal(err)
	}
	out, err := f.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "protected:") {
		t.Errorf("the entry was not removed:\n%s", out)
	}
}
