package main

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// validateGroupManifest: alice and bob; web-1 on root, web-2 on deploy, both
// tagged web. groups, access and extra are spliced in.
func validateGroupManifest(t *testing.T, groups, access, extra string) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n  - {name: bob, keys: [\"" + testkeys.Line(t, 2) + "\"]}\n" +
		"groups:\n" + groups +
		"servers:\n  - {name: web-1, host: 10.0.1.5, user: root, tags: [web]}\n  - {name: web-2, host: 10.0.1.6, user: deploy, tags: [web]}\n" +
		"access:\n" + access + extra
}

// TestValidateUnderstandsGroups also proves the editor accepts groups:
// notEditable would otherwise add a manifest_not_editable warning.
func TestValidateUnderstandsGroups(t *testing.T) {
	path := writeConfig(t, validateGroupManifest(t, "  - {name: team, members: [alice, bob]}\n", "  - {group: team, servers: [\"@web\"]}\n", ""))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t, "10.0.1.5", "10.0.1.6"))
	if code != 0 || out != "manifest OK: 2 users, 2 servers, 4 grants (0 warnings)\n" {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
}

func TestValidateUnknownGroupExit3(t *testing.T) {
	const want = `access: unknown group "nope"`
	path := writeConfig(t, validateGroupManifest(t, "", "  - {group: nope, servers: [web-1]}\n", ""))
	code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", recordedKnownHosts(t))
	if code != 3 || out != "" || !strings.Contains(stderr, want) {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	code, out, _ = validateCLI(t, "--json", "--config", path, "--known-hosts", recordedKnownHosts(t))
	doc := oneJSONDoc(t, out)
	errs, _ := doc["errors"].([]any)
	if code != 3 || doc["valid"] != false || len(errs) != 1 || errs[0] != want {
		t.Fatalf("--json: exit = %d, doc = %v", code, doc)
	}
}

// TestUnknownGroupExit3EveryCommand: an unknown group is a manifest load
// error, so every command that reads the manifest exits 3 before it dials.
func TestUnknownGroupExit3EveryCommand(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, validateGroupManifest(t, "", "  - {group: nope, servers: [web-1]}\n", ""))
	for _, args := range [][]string{
		{"audit", "--config", path},
		{"apply", "--dry-run", "--config", path},
		{"revoke", "alice", "--dry-run", "--config", path},
		{"adopt", "--config", path},
		{"rotate", "alice", "--old", fpOf(t, 1), "--new", writePub(t, "id_new.pub", testkeys.Line(t, 6)), "--dry-run", "--config", path},
		{"import", writeSSHConfig(t, "Host a\n  HostName 10.0.0.9\n  User deploy\n"), "--merge", path},
	} {
		t.Run(args[0], func(t *testing.T) {
			var out, errBuf bytes.Buffer
			code := run(args, &out, &errBuf)
			if code != 3 || out.Len() != 0 || !strings.Contains(errBuf.String(), `access: unknown group "nope"`) {
				t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out.String(), errBuf.String())
			}
		})
	}
}

// TestValidateGroupWarnings: empty_group, the group wildcard_root and the
// group tombstone_blocks_grant are warnings: exit 0, exit 1 only under
// --strict, one JSON object each with exactly these fields.
func TestValidateGroupWarnings(t *testing.T) {
	const team = "  - {name: team, members: [alice]}\n"
	for _, tc := range []struct {
		name, groups, access, extra, kind, text string
		fields                                  map[string]any
	}{
		{"empty group", "  - {name: none, members: []}\n", "  - {user: alice, servers: [web-2]}\n", "", "empty_group",
			`group "none" has no members; its grants add nothing`, nil},
		{"root wildcard", team, "  - {group: team, servers: [\"*\"]}\n", "", "wildcard_root",
			`access for group "team": servers ["*"] includes the root account on web-1; list the servers or use an @tag that excludes root accounts`, nil},
		{"blocked member", team, "  - {group: team, servers: [\"@web\"]}\n", "revoked:\n  - {user: alice, servers: [web-2], date: 2026-11-08}\n", "tombstone_blocks_grant",
			`access[0]: "alice" is not granted "web-2" through group team: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
			map[string]any{"revoked_index": float64(0), "user": "alice", "server": "web-2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeConfig(t, validateGroupManifest(t, tc.groups, tc.access, tc.extra))
			kh := recordedKnownHosts(t, "10.0.1.5", "10.0.1.6")
			code, out, stderr := validateCLI(t, "--config", path, "--known-hosts", kh)
			if code != 0 || !strings.Contains(out, "(1 warning)") || !strings.Contains(stderr, tc.text) {
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
			want := map[string]any{"kind": tc.kind, "message": tc.text}
			for k, v := range tc.fields {
				want[k] = v
			}
			if !reflect.DeepEqual(ws[0], want) {
				t.Errorf("warning = %v\nwant %v", ws[0], want)
			}
		})
	}
}

// TestGroupWarningsInAuditAndApplyJSON (spec Shared rules): the group warnings
// reach audit's and apply's JSON as well as validate's, and change no exit
// code. apply goes through its own cleanMemory copy of the warnings. The plan
// is converged first, because apply --dry-run exits 1 on a pending change.
func TestGroupWarningsInAuditAndApplyJSON(t *testing.T) {
	for _, tc := range []struct {
		name, groups, extra string
		want                map[string]any
	}{
		{"empty group", "  - {name: none, members: []}\n", "", map[string]any{
			"kind": "empty_group", "message": `group "none" has no members; its grants add nothing`,
		}},
		{"blocked member", "", "revoked:\n  - {user: bob, servers: [web-2], date: 2026-11-08}\n", map[string]any{
			"kind": "tombstone_blocks_grant", "revoked_index": float64(0), "user": "bob", "server": "web-2",
			"message": `access[1]: "bob" is not granted "web-2" through group web-team: revoked[0] removed that access (2026-11-08); delete the revoked: entry to restore it deliberately`,
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts, kh, cfg := groupFleetManifest(t, tc.groups, "", tc.extra)
			if tc.extra != "" {
				hosts["web-2"].install(t, []byte{1, 3}) // the blocked member's key is gone
			}
			check := func(command string, doc map[string]any) {
				t.Helper()
				ws, _ := doc["manifest_warnings"].([]any)
				if len(ws) != 1 || !reflect.DeepEqual(ws[0], tc.want) {
					t.Errorf("%s: manifest_warnings = %v\nwant one %v", command, ws, tc.want)
				}
			}
			check("audit", runJSONDoc(context.Background(), t, 0, "audit", "--json", "--config", cfg, "--known-hosts", kh))
			var out, errBuf bytes.Buffer
			if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
				t.Fatalf("apply: exit = %d\n%s\n%s", code, out.String(), errBuf.String())
			}
			check("apply", runJSONDoc(context.Background(), t, 0, "apply", "--dry-run", "--json", "--config", cfg, "--known-hosts", kh))
		})
	}
}
