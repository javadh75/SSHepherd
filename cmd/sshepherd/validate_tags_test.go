package main

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// validateTagManifest: alice granted "@web", web-1 root, web-2 deploy.
func validateTagManifest(t *testing.T, access, extra string) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: root, tags: [web]}\n  - {name: web-2, host: 10.0.1.6, user: deploy, tags: [web]}\n" +
		"access:\n" + access + extra
}

func TestValidateUnderstandsTags(t *testing.T) {
	path := writeConfig(t, validateTagManifest(t, "  - {user: alice, servers: [\"@web\"]}\n", ""))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5", "10.0.1.6"))
	if code != 0 || out != "manifest OK: 1 user, 2 servers, 2 grants (0 warnings)\n" {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
}

func TestValidateUnknownTagExit3(t *testing.T) {
	path := writeConfig(t, validateTagManifest(t, "  - {user: alice, servers: [\"@wbe\"]}\n", ""))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" || !strings.Contains(stderr, `access for "alice": unknown tag "@wbe"`) {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	code, out, _ = validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	doc := oneJSONDoc(t, out)
	if code != 3 || doc["valid"] != false {
		t.Fatalf("--json: exit = %d, doc = %v", code, doc)
	}
	errs, _ := doc["errors"].([]any)
	if len(errs) != 1 || errs[0] != `access for "alice": unknown tag "@wbe"` {
		t.Errorf("errors = %v", doc["errors"])
	}
}

// TestValidateTagWarnings: wildcard_root and tombstone_blocks_grant are
// warnings: exit 0, exit 1 only under --strict, one JSON object each. The
// exact object pins which fields each kind carries (spec "Manifest warnings
// in JSON": the tombstone fields stay omitted for other kinds).
func TestValidateTagWarnings(t *testing.T) {
	for _, tc := range []struct {
		name, access, extra, kind, stderr string
		fields                            map[string]any
	}{
		{"root wildcard", "  - {user: alice, servers: [\"*\"]}\n", "", "wildcard_root",
			`access for "alice": servers ["*"] includes the root account on web-1; list the servers or use an @tag that excludes root accounts`, nil},
		{"blocked grant", "  - {user: alice, servers: [\"@web\"]}\n", "revoked:\n  - {user: alice, servers: [web-2], date: 2026-11-08}\n", "tombstone_blocks_grant",
			`access[0]: "alice" is not granted "web-2" through @web: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
			map[string]any{"revoked_index": float64(0), "user": "alice", "server": "web-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, validateTagManifest(t, tc.access, tc.extra))
			kh := recordedKnownHosts(t, "10.0.1.5", "10.0.1.6")
			code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
			if code != 0 || !strings.Contains(out, "(1 warning)") || !strings.Contains(stderr, tc.stderr) {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
			}
			code, out, _ = validateCLI(t, "--strict", "--json", "--config", path, "--known-hosts", kh)
			if code != 1 {
				t.Fatalf("--strict: exit = %d, want 1", code)
			}
			ws, _ := oneJSONDoc(t, out)["manifest_warnings"].([]any)
			if len(ws) != 1 {
				t.Fatalf("manifest_warnings = %v", ws)
			}
			want := map[string]any{"kind": tc.kind, "message": tc.stderr}
			for k, v := range tc.fields {
				want[k] = v
			}
			if !reflect.DeepEqual(ws[0], want) {
				t.Errorf("warning = %v\nwant %v", ws[0], want)
			}
		})
	}
}

// blockedTagFleet: alice (k1, held) holds web-1 and web-2 by name, bob (k2)
// holds @web, a tombstone blocks him on web-2, and each server holds exactly
// the keys the manifest grants there (bob's key is absent from web-2).
func blockedTagFleet(t *testing.T) (string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, []byte{1})
	tagged := func(name string) string {
		return strings.TrimSuffix(hosts[name].line(name), "}\n") + ", tags: [web]}\n"
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+tagged("web-1")+tagged("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [\"@web\"]}\n"+
		"revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n")
	return cfg, kh
}

// wantBlockedWarning checks the one tombstone_blocks_grant object of a run
// against blockedTagFleet; revoked_index 0 is why that field is a pointer.
func wantBlockedWarning(t *testing.T, doc map[string]any) {
	t.Helper()
	ws, _ := doc["manifest_warnings"].([]any)
	if len(ws) != 1 {
		t.Fatalf("manifest_warnings = %v", doc["manifest_warnings"])
	}
	w := ws[0].(map[string]any)
	if w["kind"] != "tombstone_blocks_grant" || w["revoked_index"] != float64(0) || w["user"] != "bob" || w["server"] != "web-2" {
		t.Errorf("warning = %v", w)
	}
}

// TestBlockedGrantNeverChangesTheExit (spec Shared rules): with the key absent
// a blocked grant is a warning and exit 0, on audit and on apply. apply goes
// through its own cleanMemory copy of the warnings.
func TestBlockedGrantNeverChangesTheExit(t *testing.T) {
	cfg, kh := blockedTagFleet(t)
	wantBlockedWarning(t, runJSONDoc(context.Background(), t, 0, "audit", "--json", "--config", cfg, "--known-hosts", kh))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("apply: exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	wantBlockedWarning(t, runJSONDoc(context.Background(), t, 0, "apply", "--dry-run", "--json", "--config", cfg, "--known-hosts", kh))
}

// TestUnknownTagExit3EveryCommand: an unknown @tag is a manifest load error,
// so every command that reads the manifest exits 3 before it dials.
func TestUnknownTagExit3EveryCommand(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, validateTagManifest(t, "  - {user: alice, servers: [\"@wbe\"]}\n", ""))
	for _, args := range [][]string{
		{"audit", "--config", path},
		{"apply", "--dry-run", "--config", path},
		{"revoke", "alice", "--dry-run", "--config", path},
		{"adopt", "--config", path},
	} {
		t.Run(args[0], func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := run(args, &out, &errBuf)
			if code != 3 || out.Len() != 0 || !strings.Contains(errBuf.String(), `access for "alice": unknown tag "@wbe"`) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out.String(), errBuf.String())
			}
		})
	}
}
