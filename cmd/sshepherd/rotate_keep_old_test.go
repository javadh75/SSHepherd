package main

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// keepOldFleet: alice holds k1 (the agent's key) on web-1 and web-2; the
// servers also accept k5, whose private key file is returned.
func keepOldFleet(t *testing.T) (map[string]editHost, string, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1, 5}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1})
	}
	cfg := writeConfig(t, "users:\n  - name: alice\n    keys:\n      # alice's laptop\n      - "+qk(t, 1)+"\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n")
	return hosts, kh, cfg, sshtest.WriteKeyFile(t, t.TempDir(), "id_new", sshtest.Key(5), nil)
}

// inOrderCmd asserts each want occurs in s, in the given order.
func inOrderCmd(t *testing.T, s string, wants ...string) {
	t.Helper()
	at := 0
	for _, w := range wants {
		i := strings.Index(s[at:], w)
		if i < 0 {
			t.Fatalf("output lacks %q after offset %d:\n%s", w, at, s)
		}
		at += i + len(w)
	}
}

// TestRotateKeepOldLifecycle: --keep-old installs both keys (no scope
// line, the keep-old save reminder, the "overlap started" finish hint);
// the printed finish — revoke --key OLD, here with the new key's
// --identity — leaves only the new key, and audit is clean.
func TestRotateKeepOldLifecycle(t *testing.T) {
	hosts, kh, cfg, newKey := keepOldFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newKey + ".pub", "--keep-old", "--yes",
		"--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	finish := "sshepherd revoke --key " + fpOf(t, 1) + " --config " + cfg + " --known-hosts " + kh
	for _, want := range []string{
		"manifest edit: rotate alice key " + fpOf(t, 1) + " → " + fpOf(t, 5) + " (keeps the old key) — 2 servers affected\n",
		"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit removes the new key — clients that already switched would be locked out\n",
		"web-1: applied · verified",
		"web-2: applied · verified",
		"overlap started — every affected server accepts both keys; once every client uses the new key, finish with: " + finish + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "scope:") || strings.Contains(out.String(), "rotated out") || strings.Contains(out.String(), "if the old key") {
		t.Errorf("keep-old prints no scope line, no rotated-out label and no operator line:\n%s", out.String())
	}
	if got := readCfg(t, cfg).Users[0].Keys; !slices.Equal(got, []string{testkeys.Line(t, 1), testkeys.Line(t, 5)}) {
		t.Errorf("manifest keys = %q, want old then new", got)
	}
	if !strings.Contains(string(fileBytes(t, cfg)), "# alice's laptop") {
		t.Error("the old key's head comment was lost")
	}
	for name, h := range hosts {
		if got := h.keys(t); !strings.Contains(got, testkeys.Line(t, 1)) || !strings.Contains(got, testkeys.Line(t, 5)) {
			t.Errorf("%s authorized_keys = %q, want both keys", name, got)
		}
	}

	out.Reset()
	errBuf.Reset()
	if code := run(append(strings.Fields(finish)[1:], "--yes", "--known-hosts", kh, "--identity", newKey), &out, &errBuf); code != 0 {
		t.Fatalf("finish exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if strings.Contains(out.String(), "has no keys left") {
		t.Errorf("the finish must not leave alice keyless:\n%s", out.String())
	}
	if got := readCfg(t, cfg).Users[0].Keys; !slices.Equal(got, []string{testkeys.Line(t, 5)}) {
		t.Errorf("manifest keys after the finish = %q, want the new key only", got)
	}
	for name, h := range hosts {
		if got := h.keys(t); strings.Contains(got, testkeys.Line(t, 1)) || !strings.Contains(got, testkeys.Line(t, 5)) {
			t.Errorf("%s authorized_keys = %q, want the new key only", name, got)
		}
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--config", cfg, "--known-hosts", kh, "--identity", newKey}, &out, &errBuf); code != 0 {
		t.Fatalf("audit exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
}

// TestRotateKeepOldExpiryNoGrants: the new key carries the old line's
// options, expiry-time included (named in the header); a user with no
// grants gets the "new key recorded" hint (--no-apply included); the
// multi-key comment: warning surfaces as for any edit.
func TestRotateKeepOldExpiryNoGrants(t *testing.T) {
	saved := rotateNow
	rotateNow = func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { rotateNow = saved })
	cfg := writeConfig(t, "users:\n  - {name: deploy, comment: deploy@ci, keys: ['expiry-time=\"20990101\" "+testkeys.Line(t, 1)+"']}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "deploy", "--old", fpOf(t, 1), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)),
		"--keep-old", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	for _, want := range []string{
		`(keeps the old key; keeps expiry-time="20990101") — no servers affected` + "\n",
		"no servers contacted — no server's desired keys changed\n",
		"new key recorded — deploy has no grants yet, so no server was contacted; finish the overlap with: sshepherd revoke --key " + fpOf(t, 1) + " --config " + cfg + "\n",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if !strings.Contains(errBuf.String(), `user "deploy": comment is set on a user with 2 keys; apply will write the same comment on every key`) {
		t.Errorf("stderr lacks the multi-key comment warning: %q", errBuf.String())
	}
	want := []string{`expiry-time="20990101" ` + testkeys.Line(t, 1), `expiry-time="20990101" ` + testkeys.Line(t, 5)}
	if got := readCfg(t, cfg).Users[0].Keys; !slices.Equal(got, want) {
		t.Errorf("keys = %q, want %q", got, want)
	}
}

// TestRotateKeepOldHintRows: the --no-apply row (after the apply hint),
// the "overlap incomplete" row (after the finish line), the operator's
// --identity line, and no hint under --dry-run, on nothing-can-land, or
// on a declined prompt.
func TestRotateKeepOldHintRows(t *testing.T) {
	newPub := func(t *testing.T) string { return writePub(t, "n.pub", testkeys.Line(t, 5)) }
	t.Run("--no-apply", func(t *testing.T) {
		_, _, cfg, _ := keepOldFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		inOrderCmd(t, out.String(),
			"no servers contacted — 2 affected servers still carry the old keys; run 'sshepherd apply --config "+cfg+" --server web-1 --server web-2' to push\n",
			"overlap recorded, not pushed — run the apply hint above, then, once every client uses the new key, finish with: sshepherd revoke --key "+fpOf(t, 1)+" --config "+cfg+"\n")
	})
	t.Run("overlap incomplete", func(t *testing.T) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		hosts["web-1"].install(t, []byte{1})
		cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
			fmt.Sprintf("  - {name: web-2, host: 127.0.0.1, port: %d, user: deploy}\n", closedPort(t))+
			"access:\n  - {user: alice, servers: [web-1, web-2]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
		}
		inOrderCmd(t, out.String(),
			"manifest updated; 1 server not converged — finish with: sshepherd apply --config "+cfg+" --known-hosts "+kh+" --server web-2\n",
			"overlap incomplete — 1 server does not have the new key yet; push it first (see the apply hint above), then finish with: sshepherd revoke --key "+fpOf(t, 1)+" --config "+cfg+" --known-hosts "+kh+"\n")
	})
	t.Run("operator", func(t *testing.T) {
		cfg := writeConfig(t, "users:\n  - {name: ops, operator: true, keys: ["+qk(t, 1)+"]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "ops", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--operator", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		inOrderCmd(t, out.String(),
			"finish with: sshepherd revoke --key "+fpOf(t, 1)+" --config "+cfg+" --operator\n"+
				"if the old key is how this machine logs in, run the finish with --identity pointing at the new key's private key, or the lockout guard will refuse it\n")
		if u := readCfg(t, cfg).Users[0]; !u.Operator || len(u.Keys) != 2 {
			t.Errorf("ops = %+v, want an operator with both keys", u)
		}
	})
	t.Run("no hint: --dry-run, nothing-can-land, declined", func(t *testing.T) {
		hosts, kh, cfg, _ := keepOldFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("--dry-run exit = %d, want 1\n%s", code, errBuf.String())
		}
		if strings.Contains(out.String(), "overlap") || strings.Contains(out.String(), "new key recorded") {
			t.Errorf("--dry-run printed a finish hint:\n%s", out.String())
		}
		var prompt bytes.Buffer
		usePromptStreams(t, strings.NewReader("n\n"), &prompt)
		out.Reset()
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("declined exit = %d, want 1", code)
		}
		if strings.Contains(out.String(), "overlap") {
			t.Errorf("a declined run printed a finish hint:\n%s", out.String())
		}
		for _, h := range hosts {
			h.install(t, []byte{1}, "this line is not a key")
		}
		out.Reset()
		errBuf.Reset()
		if code := run([]string{"rotate", "alice", "--old", fpOf(t, 1), "--new", newPub(t), "--keep-old", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("nothing-can-land exit = %d, want 1", code)
		}
		if !strings.Contains(errBuf.String(), "nothing saved — alice's new key would get no access on 2 servers;") || strings.Contains(out.String(), "overlap") {
			t.Errorf("stdout = %s\nstderr = %q", out.String(), errBuf.String())
		}
	})
}

// TestRotateKeepOldRepeat: during an overlap, --keep-old on the same old
// key inserts the third key right after it; a plain rotate of the old key
// replaces it in place.
func TestRotateKeepOldRepeat(t *testing.T) {
	cfg := writeConfig(t, "users:\n  - {name: bob, keys: ["+qk(t, 1)+"]}\n")
	for _, step := range []struct {
		args []string
		want []byte
	}{
		{[]string{"--new", testkeys.Line(t, 5), "--keep-old"}, []byte{1, 5}},
		{[]string{"--new", testkeys.Line(t, 6), "--keep-old"}, []byte{1, 6, 5}},
		{[]string{"--new", testkeys.Line(t, 7)}, []byte{7, 6, 5}},
	} {
		var out, errBuf bytes.Buffer
		args := append([]string{"rotate", "bob", "--old", fpOf(t, 1)}, step.args...)
		if code := run(append(args, "--no-apply", "--yes", "--config", cfg), &out, &errBuf); code != 0 {
			t.Fatalf("%v: exit = %d\n%s", step.args, code, errBuf.String())
		}
		var want []string
		for _, s := range step.want {
			want = append(want, testkeys.Line(t, s))
		}
		if got := readCfg(t, cfg).Users[0].Keys; !slices.Equal(got, want) {
			t.Errorf("%v: keys = %q, want seeds %v", step.args, got, step.want)
		}
	}
}

// TestRotateKeepOldRefusals: --keep-old changes only the edit — plain
// rotate's refusals (operator gate, novelty, passed expiry) all apply.
func TestRotateKeepOldRefusals(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	saved := rotateNow
	rotateNow = func() time.Time { return time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { rotateNow = saved })
	body := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: ops, operator: true, keys: [" + qk(t, 3) + "]}\n" +
		"  - {name: old, keys: ['expiry-time=\"20200101\" " + testkeys.Line(t, 4) + "']}\n"
	newPub := writePub(t, "n.pub", testkeys.Line(t, 5))
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"operator without --operator", []string{"ops", "--old", fpOf(t, 3), "--new", newPub}, "ops is an operator (fleet-wide, protected); pass --operator to confirm"},
		{"--new already owned", []string{"alice", "--old", fpOf(t, 1), "--new", testkeys.Line(t, 2)}, "is already in the manifest (owned by bob)"},
		{"passed expiry", []string{"old", "--old", fpOf(t, 4), "--new", newPub}, `the old line's expiry-time="20200101" has passed`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, body)
			var out, errBuf bytes.Buffer
			args := append(append([]string{"rotate"}, tt.args...), "--keep-old", "--no-apply", "--yes", "--config", cfg)
			if code := run(args, &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), tt.want) {
				t.Errorf("exit = %d, stderr = %q; want 3 and %q", code, errBuf.String(), tt.want)
			}
			if !bytes.Equal(fileBytes(t, cfg), []byte(body)) {
				t.Error("a refused rotation edited the manifest")
			}
		})
	}
}

// TestRotateKeepOldJSON: keep_old true on the edit entry; the server adds
// the new key and removes nothing; the text hint never reaches stdout.
func TestRotateKeepOldJSON(t *testing.T) {
	_, kh, cfg, newKey := keepOldFleet(t)
	doc := runJSONDoc(context.Background(), t, 0, "rotate", "alice", "--old", fpOf(t, 1), "--new", newKey+".pub", "--keep-old",
		"--json", "--yes", "--config", cfg, "--known-hosts", kh)
	e := doc["edit"].(map[string]any)["edits"].([]any)[0].(map[string]any)
	if e["kind"] != "rotate" || e["keep_old"] != true {
		t.Errorf("edit entry = %v", e)
	}
	for _, s := range docServers(doc) {
		ch := s["changes"].(map[string]any)
		if len(ch["add"].([]any)) != 1 || len(ch["remove"].([]any)) != 0 || s["outcome"] != "applied" {
			t.Errorf("%v: changes = %v", s["name"], ch)
		}
	}
}
