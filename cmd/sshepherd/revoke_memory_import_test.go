package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestRevokeServerLastWildcardTrimRemembersExcept (PRD-1, D1a): a trim that
// deletes a wildcard also deletes its except: list, the only record of an
// earlier revoke --from-server. Each server it remembered becomes a tombstone,
// or adopt --merge re-grants it from the key still installed there.
func TestRevokeServerLastWildcardTrimRemembersExcept(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, []byte{1, 2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [\"*\"]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--from-server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("first trim: exit %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if len(readCfg(t, cfg).Tombstones) != 0 || !readCfg(t, cfg).ExceptCarveOut("bob", "web-1") {
		t.Fatal("the first trim should record web-1 in except: only")
	}
	if code := run([]string{"revoke", "bob", "--from-server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("second trim: exit %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	for _, s := range []string{"web-1", "web-2"} {
		if _, ok := saved.AccessRevoked("bob", s); !ok {
			t.Errorf("no access tombstone for %s: %+v", s, saved.Tombstones)
		}
	}
	errBuf.Reset()
	if code := run([]string{"adopt", "--merge", "--config", cfg, "-o", cfg, "--force", "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("adopt --merge: exit %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if readCfg(t, cfg).Covers("bob", "web-1") {
		t.Errorf("adopt --merge re-granted web-1:\n%s", fileBytes(t, cfg))
	}
	if !strings.Contains(errBuf.String(), "whose access was revoked") {
		t.Errorf("stderr lacks the not-re-granted warning:\n%s", errBuf.String())
	}
}

// TestImportForceWarnsMemoryLost (PRD-1): a fresh import replacing a
// manifest that holds revocation memory says so; one without memory stays
// quiet, and --merge keeps the memory so it never warns.
func TestImportForceWarnsMemoryLost(t *testing.T) {
	sshCfg := writeConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n")
	withMemory := "serial: 7\nusers: []\nservers: []\naccess: []\nrevoked:\n  - {fingerprint: " + fpOf(t, 9) + ", user: bob, date: 2026-11-08}\n"
	for _, tc := range []struct {
		name, manifest string
		warns          bool
	}{
		{"memory", withMemory, true},
		{"no memory", "users: []\nservers: []\naccess: []\n", false},
	} {
		m := writeConfig(t, tc.manifest)
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", sshCfg, "--servers-only", "-o", m, "--force"}, &out, &errBuf); code != 0 {
			t.Fatalf("%s: exit %d\n%s\n%s", tc.name, code, out.String(), errBuf.String())
		}
		if got := strings.Contains(errBuf.String(), "revocation memory"); got != tc.warns {
			t.Errorf("%s: warned = %v, want %v\n%s", tc.name, got, tc.warns, errBuf.String())
		}
		if tc.warns && !strings.Contains(errBuf.String(), "--merge") {
			t.Errorf("%s: the warning must name --merge:\n%s", tc.name, errBuf.String())
		}
	}

	merged := writeConfig(t, withMemory)
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", sshCfg, "--servers-only", "--merge", merged, "-o", merged, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("--merge: exit %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if strings.Contains(errBuf.String(), "revocation memory") {
		t.Errorf("--merge warned:\n%s", errBuf.String())
	}
}
