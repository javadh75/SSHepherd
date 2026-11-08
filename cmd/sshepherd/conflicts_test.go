package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// conflictedManifest lists alice's key and also remembers it as revoked: a
// D29 policy conflict. No servers, so adopt needs no credentials.
func conflictedManifest(t *testing.T) (path, fp string) {
	t.Helper()
	fp = fpOf(t, 1)
	return writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n"+
		"revoked:\n  - {fingerprint: "+fp+", user: alice, date: 2026-11-08}\n"), fp
}

// TestSaveRefusedWhileConflictRemains (D29): adopt (both modes) and import
// --merge refuse, exit 3, writing nothing, while the manifest they would
// write still has a policy conflict.
func TestSaveRefusedWhileConflictRemains(t *testing.T) {
	path, fp := conflictedManifest(t)
	want := "refusing to write the manifest — it would keep 1 policy conflict: key " + fp + ` of user "alice" is revoked (2026-11-08, alice)`
	for name, args := range map[string][]string{
		"adopt":         {"adopt", "--config", path},
		"adopt --merge": {"adopt", "--merge", "--config", path},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("SSH_AUTH_SOCK", "")
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
			}
			if out.Len() != 0 || !strings.Contains(errBuf.String(), want) {
				t.Errorf("stdout %q; stderr %q, want %q", out.String(), errBuf.String(), want)
			}
		})
	}
	t.Run("import --merge", func(t *testing.T) {
		hermeticHome(t)
		sshCfg := writeSSHConfig(t, "Host web-1\n  User deploy\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", sshCfg, "--merge", path, "--servers-only"}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
		}
		if out.Len() != 0 || !strings.Contains(errBuf.String(), want) {
			t.Errorf("stdout %q; stderr %q", out.String(), errBuf.String())
		}
	})
}
