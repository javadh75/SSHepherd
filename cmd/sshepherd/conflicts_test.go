package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
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

// TestImportSkipsWeakIdentity (OP5): plain import and --merge both skip a
// weak .pub with a warning and still exit 0.
func TestImportSkipsWeakIdentity(t *testing.T) {
	for _, merge := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "merge"}[merge], func(t *testing.T) {
			home := hermeticHome(t)
			key := filepath.Join(home, "old")
			if err := os.WriteFile(key+".pub", []byte(testkeys.DSALine(t, 7)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			args := []string{"import", writeSSHConfig(t, "Host web-1\n  User deploy\n  IdentityFile "+key+"\n")}
			if merge {
				args = append(args, "--merge", writeConfig(t, "users: []\nservers: []\naccess: []\n"))
			}
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), "dsa key not imported") {
				t.Errorf("stderr lacks the warning: %s", errBuf.String())
			}
			if strings.Contains(out.String(), "ssh-dss") {
				t.Errorf("the weak key reached the manifest:\n%s", out.String())
			}
		})
	}
}

// TestImportOperatorWeakKeyExits3: --operator naming a weak key stops.
func TestImportOperatorWeakKeyExits3(t *testing.T) {
	home := hermeticHome(t)
	key := filepath.Join(home, "old")
	if err := os.WriteFile(key+".pub", []byte(testkeys.DSALine(t, 7)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	code := run([]string{"import", writeSSHConfig(t, "Host web-1\n  User deploy\n"), "--operator", key}, &out, &errBuf)
	if code != 3 || !strings.Contains(errBuf.String(), "weak key (dsa)") {
		t.Fatalf("exit = %d, stderr %s", code, errBuf.String())
	}
}

// withWeakUser adds user old (a DSA key, granted web-1) to a hermeticFleet
// manifest and returns its fingerprint.
func withWeakUser(t *testing.T, cfgPath string) string {
	t.Helper()
	dsa := testkeys.DSALine(t, 7)
	b, err := os.ReadFile(cfgPath) // #nosec G304 -- a test temp file
	if err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(string(b), "servers:\n", "  - {name: old, keys: [\""+dsa+"\"]}\nservers:\n", 1)
	y = strings.Replace(y, "access:\n", "access:\n  - {user: old, servers: [web-1]}\n", 1)
	if err := os.WriteFile(cfgPath, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	k, err := authkeys.ParseLine(dsa)
	if err != nil {
		t.Fatal(err)
	}
	return k.Fingerprint
}

// TestGrantedWeakKeyAuditExits2: the manifest loads, the conflict prints,
// and the exit is 2 (D29).
func TestGrantedWeakKeyAuditExits2(t *testing.T) {
	srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
	withWeakUser(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "dsa keys are not allowed") {
		t.Errorf("report lacks the conflict:\n%s", out.String())
	}
	out.Reset()
	if code := run([]string{"audit", "--json", "--config", cfg, "--known-hosts", sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))}, &out, &errBuf); code != 2 {
		t.Fatalf("--json exit = %d, want 2\n%s", code, errBuf.String())
	}
	var doc struct {
		PolicyConflicts []struct {
			Kind string `json:"kind"`
		} `json:"policy_conflicts"`
		Summary struct {
			PolicyConflicts int `json:"policy_conflicts"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if len(doc.PolicyConflicts) != 1 || doc.PolicyConflicts[0].Kind != "weak_key" || doc.Summary.PolicyConflicts != 1 {
		t.Errorf("doc = %+v, want one weak_key conflict, counted in the summary", doc)
	}
}

// TestGrantedWeakKeyApplyJSON: apply's document names the conflict and
// marks the server refused.
func TestGrantedWeakKeyApplyJSON(t *testing.T) {
	srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
	withWeakUser(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--json", "--dry-run", "--config", cfg, "--known-hosts", sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	var doc struct {
		PolicyConflicts []struct {
			Kind string `json:"kind"`
		} `json:"policy_conflicts"`
		Servers []struct {
			Class string `json:"class"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if len(doc.PolicyConflicts) != 1 || doc.PolicyConflicts[0].Kind != "weak_key" || len(doc.Servers) != 1 || doc.Servers[0].Class != "refused" {
		t.Errorf("doc = %+v, want a weak_key conflict and a refused server", doc)
	}
}

// TestUngrantedWeakKeyWarnsAndKeepsTheExit: no server renders it, so no
// human must act now (D28): a warning, exit unchanged.
func TestUngrantedWeakKeyWarnsAndKeepsTheExit(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: old, keys: [\""+testkeys.DSALine(t, 7)+"\"]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "dsa key, granted on no server") {
		t.Errorf("stderr lacks the warning: %s", errBuf.String())
	}
}

// TestRotateReplacesWeakKeyWhileApplyRefuses: apply on the original refuses
// the server (exit 1); rotate of the weak key saves and pushes.
func TestRotateReplacesWeakKeyWhileApplyRefuses(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	fp := withWeakUser(t, cfg)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", cfg, "--known-hosts", kh, "--yes"}, &out, &errBuf); code != 1 {
		t.Fatalf("apply exit = %d, want 1\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "dsa keys are not allowed") {
		t.Errorf("apply did not name the weak key:\n%s", out.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"rotate", "old", "--old", fp, "--new", testkeys.Line(t, 8), "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("rotate exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	saved, err := config.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Conflicts()) != 0 || len(saved.WeakKeys()) != 0 {
		t.Errorf("the rotate should clear the conflict: %+v, %+v", saved.Conflicts(), saved.WeakKeys())
	}
}

// weakPushFleet is one server every affected plan refuses over user old's
// DSA key: alice (key 1, held), carol (key 2) and old are granted web-1,
// bob (key 3) too when withBob. The server holds keys 1 and 2 and the DSA key.
func weakPushFleet(t *testing.T, withBob bool, extraUser string) (kh, cfg string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	host := hosts["web-1"]
	dsa := testkeys.DSALine(t, 7)
	y := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: carol, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: old, keys: [\"" + dsa + "\"]}\n" + extraUser
	access := "access:\n  - {user: alice, servers: [web-1]}\n  - {user: carol, servers: [web-1]}\n  - {user: old, servers: [web-1]}\n"
	if withBob {
		y += "  - {name: bob, keys: [" + qk(t, 3) + "]}\n"
		access += "  - {user: bob, servers: [web-1]}\n"
	}
	host.install(t, []byte{1, 2}, dsa)
	return kh, writeConfig(t, y+"servers:\n"+host.line("web-1")+access)
}

// checkSavedAndRefused runs a save whose only server is weak-refused: the
// edit saves, the server is refused, exit 1.
func checkSavedAndRefused(t *testing.T, args []string, cfg string) {
	t.Helper()
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run(args, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if strings.Contains(errBuf.String(), "nothing saved") || bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("the edit was not saved\nstderr: %s", errBuf.String())
	}
	if !strings.Contains(out.String(), "REFUSED") || !strings.Contains(out.String(), "dsa keys are not allowed") {
		t.Errorf("the push was not refused over the weak key:\n%s", out.String())
	}
}

// TestRotateSavesWhileAnotherWeakKeyRefusesThePush: rotate carol adds a
// key on a server granting someone else's weak key.
func TestRotateSavesWhileAnotherWeakKeyRefusesThePush(t *testing.T) {
	kh, cfg := weakPushFleet(t, false, "")
	checkSavedAndRefused(t, []string{"rotate", "carol", "--old", fpOf(t, 2), "--new", testkeys.Line(t, 5), "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
}

// TestRotateWeakKeySavesBesideASecondWeakKey: with two weak keys, replacing
// one is not removal-only, and its save must not deadlock.
func TestRotateWeakKeySavesBesideASecondWeakKey(t *testing.T) {
	kh, cfg := weakPushFleet(t, false, "  - {name: op2, operator: true, keys: [\""+testkeys.DSALine(t, 8)+"\"]}\n")
	k, err := authkeys.ParseLine(testkeys.DSALine(t, 7))
	if err != nil {
		t.Fatal(err)
	}
	checkSavedAndRefused(t, []string{"rotate", "old", "--old", k.Fingerprint, "--new", testkeys.Line(t, 5), "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
	if got := readCfg(t, cfg).WeakKeys(); len(got) != 1 || got[0].User != "op2" {
		t.Errorf("WeakKeys = %+v, want only op2's", got)
	}
}

// TestRevokeSavesBesideWeakKeyWhenItsKeyIsAlreadyGone: bob's key is not on the server,
// so nothing is unauthorized and the removal-only exception does not apply;
// the tombstone is still saved.
func TestRevokeSavesBesideWeakKeyWhenItsKeyIsAlreadyGone(t *testing.T) {
	kh, cfg := weakPushFleet(t, true, "")
	checkSavedAndRefused(t, []string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
	if _, ok := readCfg(t, cfg).Revoked(fpOf(t, 3)); !ok {
		t.Error("the tombstone for bob's key was not saved")
	}
}

// parseManifest parses a test manifest or fails.
func parseManifest(t *testing.T, y string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cfg
}

// weakAndGrant: alice holds line, granted on web-1.
func weakAndGrant(line string) string {
	return "users:\n  - {name: alice, keys: [\"" + line + "\"]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n"
}

// TestSaveRefusedWhenAddingWeakKey (OP4): a save that adds a weak key is
// refused, even when that key is granted nowhere.
func TestSaveRefusedWhenAddingWeakKey(t *testing.T) {
	strong, weak := testkeys.Line(t, 1), testkeys.DSALine(t, 7)
	former := parseManifest(t, weakAndGrant(strong))
	granted := parseManifest(t, weakAndGrant(weak))
	ungranted := parseManifest(t, "users:\n  - {name: alice, keys: [\""+weak+"\"]}\n")
	for name, saved := range map[string]*config.Config{"granted": granted, "ungranted": ungranted} {
		t.Run(name, func(t *testing.T) {
			err := conflictRefusal(former, saved)
			if err == nil || !strings.Contains(err.Error(), "refusing to write the manifest — it would add a weak key: ") ||
				!strings.Contains(err.Error(), "dsa keys are not allowed") {
				t.Fatalf("err = %v", err)
			}
		})
	}
	if err := conflictRefusal(nil, granted); err == nil {
		t.Error("a new manifest holding a weak key must be refused too")
	}
}

// TestAdoptKeepsAWeakKeyTheManifestHolds (OP4): adopt re-emits a key the
// manifest already holds, so that key was not added and the save is allowed.
func TestAdoptKeepsAWeakKeyTheManifestHolds(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, _ := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	weak := testkeys.DSALine(t, 7)
	cfg := writeConfig(t, fmt.Sprintf("users:\n  - {name: alice, keys: [\"%s\", \"%s\"]}\nservers:\n  - {name: web-1, host: 127.0.0.1, port: %d, user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n",
		testkeys.Line(t, 1), weak, srv.Port))
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if strings.Contains(errBuf.String(), "would add a weak key") {
		t.Errorf("a held weak key must not count as added:\n%s", errBuf.String())
	}
	if !strings.Contains(out.String(), strings.TrimSpace(weak)) {
		t.Errorf("the adopted manifest lacks the held weak key:\n%s", out.String())
	}
}

// TestImportMergeKeepsAWeakKeyTheManifestHolds (OP4): import --merge keeps
// what the manifest holds, so its weak key was not added and the save is
// allowed.
func TestImportMergeKeepsAWeakKeyTheManifestHolds(t *testing.T) {
	hermeticHome(t)
	weak := testkeys.DSALine(t, 7)
	path := filepath.Join(t.TempDir(), "sshepherd.yaml")
	manifest := "users:\n  - {name: alice, keys: [\"" + weak + "\"]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n"
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	sshCfg := writeSSHConfig(t, "Host app-1\n  HostName 10.0.0.5\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", sshCfg, "--merge", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if strings.Contains(errBuf.String(), "would add a weak key") {
		t.Errorf("a held weak key must not count as added:\n%s", errBuf.String())
	}
	if !strings.Contains(out.String(), strings.TrimSpace(weak)) {
		t.Errorf("the merged manifest lacks the held weak key:\n%s", out.String())
	}
}

// TestRevokeUnrelatedSavesWithWeakKeyPresent (OP4): a weak key the manifest
// already holds never blocks an unrelated save, nor its own removal.
func TestRevokeUnrelatedSavesWithWeakKeyPresent(t *testing.T) {
	weak := testkeys.DSALine(t, 7)
	former := parseManifest(t, weakAndGrant(weak))
	if err := conflictRefusal(former, parseManifest(t, weakAndGrant(weak))); err != nil {
		t.Errorf("unrelated save refused: %v", err)
	}
	if err := conflictRefusal(former, parseManifest(t, weakAndGrant(testkeys.Line(t, 1)))); err != nil {
		t.Errorf("the remediation (rotate away from the weak key) refused: %v", err)
	}
}

// TestRevokedConflictStillRefusesSave pins P04's rule, unchanged for the
// revoked kinds whatever the former manifest held; it passes as soon as the
// new signature compiles.
func TestRevokedConflictStillRefusesSave(t *testing.T) {
	line := testkeys.Line(t, 1)
	y := weakAndGrant(line) + "revoked:\n  - {fingerprint: " + fpOf(t, 1) + ", user: alice, date: 2026-11-08}\n"
	if err := conflictRefusal(parseManifest(t, y), parseManifest(t, y)); err == nil || !strings.Contains(err.Error(), "it would keep 1 policy conflict") {
		t.Fatalf("err = %v", err)
	}
}
