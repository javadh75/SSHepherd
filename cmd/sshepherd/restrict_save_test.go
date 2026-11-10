package main

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// clashPushFleet is one server a restriction conflict holds: alice (key 1,
// held) and bob (key 3) are granted web-1, and deploy (key 2) twice with
// different options. The server holds all three keys.
func clashPushFleet(t *testing.T) (kh, cfg string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	host := hosts["web-1"]
	host.install(t, []byte{1, 2, 3})
	y := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: deploy, keys: [" + qk(t, 2) + "]}\n  - {name: bob, keys: [" + qk(t, 3) + "]}\n" +
		"servers:\n" + host.line("web-1") +
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: deploy, servers: [web-1], options: [no-pty]}\n" +
		"  - {user: deploy, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n"
	return kh, writeConfig(t, y)
}

// checkSavedClashRefused runs an edit whose only server a restriction
// conflict holds: the edit saves (OP6), the push is refused there, exit 1.
func checkSavedClashRefused(t *testing.T, args []string, cfg string) {
	t.Helper()
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run(args, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if strings.Contains(errBuf.String(), "nothing saved") || bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("the edit was not saved\nstderr: %s", errBuf.String())
	}
	want := `REFUSED: user "deploy": server "web-1" is granted by access[1] with [no-pty] and by access[2] with no options`
	if !strings.Contains(out.String(), want) {
		t.Errorf("the push was not refused over the clash:\n%s", out.String())
	}
}

// TestRevokeSavesOverRestrictionClash (OP6): a leaver's revoke saves while
// a clash holds its only server; the push is refused there.
func TestRevokeSavesOverRestrictionClash(t *testing.T) {
	kh, cfg := clashPushFleet(t)
	checkSavedClashRefused(t, []string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
	if _, ok := readCfg(t, cfg).Revoked(fpOf(t, 3)); !ok {
		t.Error("bob's tombstone was not saved")
	}
}

// TestRotateSavesOverRestrictionClash (OP6): rotate saves too.
func TestRotateSavesOverRestrictionClash(t *testing.T) {
	kh, cfg := clashPushFleet(t)
	checkSavedClashRefused(t, []string{"rotate", "bob", "--old", fpOf(t, 3), "--new", testkeys.Line(t, 5), "--yes", "--config", cfg, "--known-hosts", kh}, cfg)
}

// TestRevokeJSONSavesOverRestrictionClash (OP6; owner rule: schema 1,
// additive): the --json document of a revoke that saves while a clash holds
// its only server says so: edit.saved, the server refused, and the conflict
// as a restriction_conflict with no fingerprint.
func TestRevokeJSONSavesOverRestrictionClash(t *testing.T) {
	kh, cfg := clashPushFleet(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"revoke", "bob", "--yes", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	var doc struct {
		Schema int `json:"schema"`
		Edit   struct {
			Saved bool `json:"saved"`
		} `json:"edit"`
		Summary struct {
			Refused int `json:"refused"`
		} `json:"summary"`
		PolicyConflicts []map[string]any `json:"policy_conflicts"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || code != 1 {
		t.Fatalf("exit = %d, want 1 with a document (err %v)\nstdout: %s\nstderr: %s", code, err, out.String(), errBuf.String())
	}
	if doc.Schema != 1 || !doc.Edit.Saved || doc.Summary.Refused != 1 || len(doc.PolicyConflicts) != 1 ||
		doc.PolicyConflicts[0]["kind"] != "restriction_conflict" || doc.PolicyConflicts[0]["fingerprint"] != nil {
		t.Errorf("document:\n%s", out.String())
	}
}

// TestRevokeSweepOverRestrictionClash (OP6, D28): the leaver's key stays on
// the server the clash holds, so --sweep finds it there: exit 2, and the
// tombstone is saved.
func TestRevokeSweepOverRestrictionClash(t *testing.T) {
	kh, cfg := clashPushFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if _, ok := readCfg(t, cfg).Revoked(fpOf(t, 3)); !ok {
		t.Error("bob's tombstone was not saved")
	}
	if want := "REVOKED KEY STILL INSTALLED: bob " + fpOf(t, 3) + " on web-1"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
}

// wildcardPair: deploy (k2) holds two "*" entries that do not meet today:
// web-1 only through the first (no-pty), db-1 only through the second.
// extra (server lines) is spliced in after db-1; any server it adds is
// reached by both entries.
func wildcardPair(t *testing.T, extra string) string {
	t.Helper()
	return "users:\n  - {name: deploy, keys: [\"" + testkeys.Line(t, 2) + "\"]}\nservers:\n" +
		"  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n" + extra +
		"access:\n  - {user: deploy, servers: [\"*\"], except: [db-1], options: [no-pty]}\n" +
		"  - {user: deploy, servers: [\"*\"], except: [web-1]}\n"
}

// TestImportMergeRefusesAddedClash (spec S7 save row): the new host is
// reached by both "*" entries with different options: exit 3 and nothing
// saved, whether the merge goes to stdout or in place.
func TestImportMergeRefusesAddedClash(t *testing.T) {
	const want = `it would add 1 restriction conflict: user "deploy": server "web-3"`
	t.Run("stdout", func(t *testing.T) {
		hermeticHome(t)
		path := writeConfig(t, wildcardPair(t, ""))
		sshCfg := writeSSHConfig(t, "Host web-3\n  HostName 10.0.0.3\n  User deploy\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", sshCfg, "--merge", path, "--servers-only"}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
		}
		if out.Len() != 0 || !strings.Contains(errBuf.String(), want) {
			t.Errorf("stdout %q; stderr %q", out.String(), errBuf.String())
		}
	})
	t.Run("in place", func(t *testing.T) {
		hermeticHome(t)
		path := writeConfig(t, wildcardPair(t, ""))
		before := fileBytes(t, path)
		sshCfg := writeSSHConfig(t, "Host web-3\n  HostName 10.0.0.3\n  User deploy\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", sshCfg, "--merge", path, "--servers-only", "-o", path, "--force"}, &out, &errBuf); code != 3 {
			t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
		}
		if !strings.Contains(errBuf.String(), want) || !bytes.Equal(fileBytes(t, path), before) {
			t.Errorf("the manifest changed or the refusal is missing; stderr %q", errBuf.String())
		}
	})
}

// TestImportMergeKeepsExistingClash: a clash the manifest already has does
// not stop the save, and its options: survive the merge.
func TestImportMergeKeepsExistingClash(t *testing.T) {
	hermeticHome(t)
	path := writeConfig(t, "users:\n  - {name: deploy, keys: [\""+testkeys.Line(t, 2)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"+
		"access:\n  - {user: deploy, servers: [web-1], options: [no-pty]}\n  - {user: deploy, servers: [web-1]}\n")
	sshCfg := writeSSHConfig(t, "Host web-3\n  HostName 10.0.0.3\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", sshCfg, "--merge", path, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "web-3") || !strings.Contains(out.String(), "options: [no-pty]") {
		t.Errorf("merged manifest:\n%s", out.String())
	}
}

// appendAccess adds one access: line at the end of the manifest at path,
// whose last section is access:.
func appendAccess(t *testing.T, path, entry string) {
	t.Helper()
	if err := os.WriteFile(path, append(fileBytes(t, path), entry...), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestAdoptSavesOverExistingClash (spec S7, plan gap 15): adopt, both modes,
// re-emits a clash the manifest already holds; the regenerate carries
// options: through the encoder.
func TestAdoptSavesOverExistingClash(t *testing.T) {
	for _, merge := range []bool{false, true} {
		t.Run(map[bool]string{false: "regenerate", true: "merge"}[merge], func(t *testing.T) {
			srv, hostKey, cfg := hermeticFleet(t, shortHome(t))
			appendAccess(t, cfg, "  - {user: alice, servers: [web-1], options: [no-pty]}\n")
			if len(readCfg(t, cfg).Conflicts()) != 1 {
				t.Fatal("the fixture must hold one restriction conflict")
			}
			args := []string{"adopt", "--config", cfg, "--known-hosts", sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))}
			if merge {
				args = append(args, "--merge")
			}
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
			}
			if !strings.Contains(out.String(), "no-pty") {
				t.Errorf("the grant's options were not carried:\n%s", out.String())
			}
		})
	}
}

// clashTail ends every restriction conflict's message (spec S7 wording).
const clashTail = "; a key gets one set of restrictions on a server: make them match, or move one grant to a separate user"

// TestRestrictionSaveRule (spec S7 save rows, OP6): adopt and import --merge
// refuse a save that adds a clash on a (user, server) pair; a clash already
// there saves; revoke and rotate never refuse one.
func TestRestrictionSaveRule(t *testing.T) {
	web3 := "  - {name: web-3, host: 10.0.0.3, user: deploy}\n"
	former := parseManifest(t, wildcardPair(t, ""))
	added := parseManifest(t, wildcardPair(t, web3))
	want := `refusing to write the manifest — it would add 1 restriction conflict: user "deploy": server "web-3" is granted by access[0] with [no-pty] and by access[1] with no options` + clashTail
	if err := conflictRefusal(former, added); err == nil || err.Error() != want {
		t.Errorf("added clash: err = %v\nwant %s", err, want)
	}
	if err := conflictRefusal(added, added); err != nil {
		t.Errorf("a clash already there must save: %v", err)
	}
	if err := editConflictRefusal(former, added); err != nil {
		t.Errorf("revoke and rotate never refuse over a clash: %v", err)
	}
	// One more server on a pair former already had is a clash on a new (user, server) pair.
	more := parseManifest(t, wildcardPair(t, web3+"  - {name: web-4, host: 10.0.0.4, user: deploy}\n"))
	if err := conflictRefusal(added, more); err == nil || !strings.Contains(err.Error(), `servers "web-3" and 1 more are granted`) {
		t.Errorf("web-4 joining an existing clash: err = %v", err)
	}
	if err := conflictRefusal(nil, added); err == nil {
		t.Error("a new manifest holding a clash adds it")
	}
}

// TestApplyRefusesOnlyClashedServer (spec S7 apply row, D28): plain apply
// refuses the server a restriction conflict holds and writes the other,
// exit 1; its --json document carries the conflict as a
// restriction_conflict with no fingerprint (owner rule: schema 1).
func TestApplyRefusesOnlyClashedServer(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1})
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: deploy, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: deploy, servers: [web-1, web-2], options: [no-pty]}\n"+
		"  - {user: deploy, servers: [web-1]}\n")
	web1 := hosts["web-1"].keys(t)

	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--dry-run", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	var doc struct {
		Schema  int `json:"schema"`
		Summary struct {
			Refused int `json:"refused"`
		} `json:"summary"`
		PolicyConflicts []map[string]any `json:"policy_conflicts"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil || code != 1 || doc.Schema != 1 || doc.Summary.Refused != 1 ||
		len(doc.PolicyConflicts) != 1 || doc.PolicyConflicts[0]["kind"] != "restriction_conflict" || doc.PolicyConflicts[0]["fingerprint"] != nil {
		t.Errorf("apply --dry-run --json exit = %d (err %v):\n%s\nstderr: %s", code, err, out.String(), errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("apply exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if want := `REFUSED: user "deploy": server "web-1" is granted by access[1] with [no-pty] and by access[2] with no options`; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
	if got := hosts["web-1"].keys(t); got != web1 {
		t.Errorf("web-1 was written:\n%s", got)
	}
	if got := hosts["web-2"].keys(t); !strings.Contains(got, "no-pty "+testkeys.Line(t, 2)) {
		t.Errorf("web-2 lacks deploy's restricted line:\n%s", got)
	}
}

// TestRotateKeepsGrantOptions (spec S7 Render): rotate and rotate --keep-old
// touch the key line only, so a grant's options carry over to the new key
// (and stay on the old one under --keep-old).
func TestRotateKeepsGrantOptions(t *testing.T) {
	for _, keepOld := range []bool{false, true} {
		t.Run(map[bool]string{false: "plain", true: "--keep-old"}[keepOld], func(t *testing.T) {
			hosts, _, _ := editFleet(t, []byte{1}, "web-1")
			cfg := writeConfig(t, "users:\n  - {name: deploy, keys: ["+qk(t, 2)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
				"access:\n  - {user: deploy, servers: [web-1], options: [no-pty]}\n")
			args := []string{"rotate", "deploy", "--old", fpOf(t, 2), "--new", testkeys.Line(t, 5), "--no-apply", "--yes", "--config", cfg}
			want := []string{fpOf(t, 5)}
			if keepOld {
				args = append(args, "--keep-old")
				want = []string{fpOf(t, 2), fpOf(t, 5)}
			}
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
			}
			saved := readCfg(t, cfg)
			if got := saved.Access[0].Options; !slices.Equal(got, []string{"no-pty"}) {
				t.Errorf("access[0].options = %q, want [no-pty]", got)
			}
			var got []string
			for _, k := range saved.DesiredFor("web-1") {
				if !slices.Equal(k.Options, []string{"no-pty"}) {
					t.Errorf("%s renders %q on web-1, want [no-pty]", k.Fingerprint, k.Options)
				}
				got = append(got, k.Fingerprint)
			}
			if !slices.Equal(got, want) {
				t.Errorf("web-1 renders %q, want %q", got, want)
			}
		})
	}
}

// TestRevokeFromServerClearsClash (spec S7 Tests): trimming the clashed
// server from deploy's entries removes the clash; the tagged entry keeps its
// options on web-2.
func TestRevokeFromServerClearsClash(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: deploy, keys: ["+qk(t, 2)+"]}\nservers:\n"+
		"  - {name: web-1, host: 10.0.0.1, user: deploy, tags: [web]}\n  - {name: web-2, host: 10.0.0.2, user: deploy, tags: [web]}\n"+
		"access:\n  - {user: alice, servers: [\"@web\"]}\n  - {user: deploy, servers: [\"@web\"], options: [no-pty]}\n  - {user: deploy, servers: [web-1]}\n")
	if n := len(readCfg(t, cfg).Conflicts()); n != 1 {
		t.Fatalf("fixture conflicts = %d, want 1", n)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "deploy", "--from-server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	if len(saved.Conflicts()) != 0 {
		t.Errorf("conflicts left: %+v", saved.Conflicts())
	}
	if d := saved.DesiredFor("web-2"); len(d) != 2 || strings.Join(d[1].Options, ",") != "no-pty" {
		t.Errorf("web-2 desired = %+v, want alice, then deploy with no-pty", d)
	}
}

// TestValidateRestrictionConflict (spec S7 validate row): exit 3, and the
// JSON document says valid: false with the conflict, no fingerprint.
func TestValidateRestrictionConflict(t *testing.T) {
	hermeticHome(t)
	cfg := writeConfig(t, wildcardPair(t, "  - {name: web-3, host: 10.0.0.3, user: deploy}\n"))
	code, _, stderr := validateCLI(t, "--config", cfg)
	if code != 3 || !strings.Contains(stderr, `manifest has 1 policy conflict: user "deploy": server "web-3" is granted by`) {
		t.Errorf("exit = %d, stderr %s", code, stderr)
	}
	code, out, _ := validateCLI(t, "--config", cfg, "--json")
	var doc struct {
		Valid           bool             `json:"valid"`
		PolicyConflicts []map[string]any `json:"policy_conflicts"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != 3 || doc.Valid || len(doc.PolicyConflicts) != 1 ||
		doc.PolicyConflicts[0]["kind"] != "restriction_conflict" || doc.PolicyConflicts[0]["fingerprint"] != nil {
		t.Errorf("--json exit = %d (err %v):\n%s", code, err, out)
	}
}

// TestAddedClashesIgnoresOtherConflictKinds: a former conflict of another
// kind (here revoked_access) on the same (user, server) pair does not hide
// a restriction conflict the save adds there (verifier mutant W13).
func TestAddedClashesIgnoresOtherConflictKinds(t *testing.T) {
	former := parseManifest(t, "users:\n  - {name: deploy, keys: [\""+testkeys.Line(t, 2)+"\"]}\nservers:\n"+
		"  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: db-1, host: 10.0.0.9, user: deploy}\n"+
		"  - {name: web-3, host: 10.0.0.3, user: deploy}\n"+
		"access:\n  - {user: deploy, servers: [\"*\"]}\n"+
		"revoked:\n  - {user: deploy, servers: [web-3], date: 2026-11-10}\n")
	kinds := map[string]bool{}
	for _, c := range former.Conflicts() {
		kinds[c.Kind] = slices.Contains(c.Servers, "web-3")
	}
	if !kinds[config.ConflictRevokedAccess] || len(kinds) != 1 {
		t.Fatalf("former conflicts = %v, want only revoked_access on web-3", former.Conflicts())
	}
	saved := parseManifest(t, wildcardPair(t, "  - {name: web-3, host: 10.0.0.3, user: deploy}\n"))
	if got := addedClashes(former, saved); len(got) != 1 || !strings.Contains(got[0], `server "web-3"`) {
		t.Errorf("addedClashes = %q, want the web-3 restriction conflict", got)
	}
}
