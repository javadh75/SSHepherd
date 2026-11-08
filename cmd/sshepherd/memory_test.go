package main

// Imports grow with the file: this task uses only these four; Task 30 adds
// internal/authkeys, internal/config and reflect, Task 33 adds io and
// internal/testkeys — the first tasks that use them (an unused import does
// not compile).
import (
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fixedEditClock pins the tombstone date (rotateNow is the edit clock).
func fixedEditClock(t *testing.T) {
	t.Helper()
	saved := rotateNow
	rotateNow = func() time.Time { return time.Date(2026, 11, 8, 23, 30, 0, 0, time.FixedZone("x", -5*3600)) } // 2026-11-09 UTC
	t.Cleanup(func() { rotateNow = saved })
}

func TestReasonValidation(t *testing.T) {
	cfg := writeConfig(t, "users: []\n")
	for _, tc := range []struct{ reason, want string }{
		{"a\x1bb", "--reason contains control or format characters"},
		{" padded", "--reason has leading or trailing whitespace"},
		{strings.Repeat("x", 257), "--reason is 257 bytes, over the 256-byte limit"},
	} {
		reason, want := tc.reason, tc.want
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--reason", reason, "--config", cfg}, &out, &errBuf); code != 3 ||
			!strings.Contains(errBuf.String(), want) {
			t.Errorf("--reason %q: exit %d, stderr %q; want 3 and %q", reason, code, errBuf.String(), want)
		}
	}
}

// conflictFleet: alice (k1, the agent's key), bob (k2) and carol (k3) on
// web-1, and bob's key is also in revoked: — a D29 policy conflict that
// revoking carol does not resolve. Returns the manifest body too.
func conflictFleet(t *testing.T) (map[string]editHost, string, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1, 2, 3})
	body := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n  - {name: carol, keys: [" + qk(t, 3) + "]}\n" +
		"servers:\n" + hosts["web-1"].line("web-1") +
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n  - {user: carol, servers: [web-1]}\n" +
		"revoked:\n  - {fingerprint: " + fpOf(t, 2) + ", user: bob, date: 2026-11-01}\n"
	return hosts, kh, writeConfig(t, body), body
}

// TestSaveRefusedWhileConflictRemainsOnRevoke: an unrelated policy
// conflict blocks the save (exit 3, nothing saved or written).
func TestSaveRefusedWhileConflictRemainsOnRevoke(t *testing.T) {
	hosts, kh, cfg, body := conflictFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "carol", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
		!strings.Contains(errBuf.String(), "refusing to write the manifest — it would keep 1 policy conflict: key "+fpOf(t, 2)) {
		t.Fatalf("exit %d, stderr %q", code, errBuf.String())
	}
	if string(fileBytes(t, cfg)) != body || len(hosts["web-1"].srv.Attempts()) != 0 {
		t.Fatal("a refused save changed the manifest or contacted a server")
	}
}

// TestRevokeKeyResolvesConflict (spec Testing, D29): revoke --key of the
// conflicting key is the fix — the manifest it would save has no conflict,
// so it saves, and the earliest tombstone wins (no duplicate entry).
func TestRevokeKeyResolvesConflict(t *testing.T) {
	_, kh, cfg, _ := conflictFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", fpOf(t, 2), "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("revoke --key exit %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	if len(saved.Conflicts()) != 0 || len(saved.Tombstones) != 1 || saved.Tombstones[0].Date != "2026-11-01" || saved.Serial() != 1 {
		t.Errorf("saved = serial %d, %+v (the earliest tombstone wins, no conflict left, one bump)", saved.Serial(), saved.Tombstones)
	}
}

func TestRevokeWritesTombstoneAndBumpsSerial(t *testing.T) {
	fixedEditClock(t)
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--reason", "offboarded", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	saved := readCfg(t, cfg)
	want := []config.Tombstone{{Fingerprint: fpOf(t, 2), User: "bob", Date: "2026-11-09", Reason: "offboarded"}}
	if saved.Serial() != 1 || !reflect.DeepEqual(saved.Tombstones, want) {
		t.Errorf("saved serial %d, revoked %+v; want 1, %+v", saved.Serial(), saved.Tombstones, want)
	}
	for _, s := range []string{
		"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit is refused on the servers this run writes (serial 1)\n",
		"check every server: sshepherd audit --config " + cfg + " --known-hosts " + kh + "\n",
	} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("stdout lacks %q:\n%s", s, out.String())
		}
	}
	if strings.Contains(out.String(), "scope:") {
		t.Errorf("the scope line is gone (D3):\n%s", out.String())
	}
	for name, h := range hosts {
		if got := h.keys(t); !strings.HasPrefix(got, authkeys.Header(1)+"\n") {
			t.Errorf("%s = %q, want the (serial 1) header", name, got)
		}
	}
}

func TestRevokeAlreadyRevokedExits0(t *testing.T) {
	fixedEditClock(t)
	_, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("first revoke exit = %d\n%s", code, errBuf.String())
	}
	before := fileBytes(t, cfg)
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("repeat exit = %d, want 0 (D1c)\n%s", code, errBuf.String())
	}
	want := "bob was already revoked (2026-11-09); run 'sshepherd apply --config " + cfg + " --known-hosts " + kh + "' to converge any server that still has the key\n"
	if out.String() != want {
		t.Errorf("stdout = %q\nwant %q", out.String(), want)
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("a repeated revoke saved (or bumped) the manifest")
	}
	errBuf.Reset()
	if code := run([]string{"revoke", "carol", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
		!strings.Contains(errBuf.String(), "unknown user: carol — not in the manifest") {
		t.Errorf("never-revoked name: exit %d, stderr %q; want today's exit 3", code, errBuf.String())
	}
	// D1c with several users: the already-revoked ones get the note, the
	// rest are revoked as usual — one save, exactly one serial bump, exit 0.
	t.Run("already revoked and live in one run", func(t *testing.T) {
		hosts, kh2, _ := editFleet(t, []byte{1}, "web-1")
		hosts["web-1"].install(t, []byte{1, 2, 3})
		cfg2 := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n  - {name: carol, keys: ["+qk(t, 3)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+
			"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1]}\n  - {user: carol, servers: [web-1]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--yes", "--config", cfg2, "--known-hosts", kh2}, &out, &errBuf); code != 0 {
			t.Fatalf("revoke bob exit = %d\n%s", code, errBuf.String())
		}
		out.Reset()
		if code := run([]string{"revoke", "bob", "carol", "--yes", "--config", cfg2, "--known-hosts", kh2}, &out, &errBuf); code != 0 {
			t.Fatalf("revoke bob carol exit = %d, want 0\n%s\n%s", code, out.String(), errBuf.String())
		}
		note := "bob was already revoked (2026-11-09); run 'sshepherd apply --config " + cfg2 + " --known-hosts " + kh2 + "' to converge any server that still has the key\n"
		if !strings.Contains(out.String(), note) || strings.Contains(out.String(), "carol was already revoked") {
			t.Errorf("stdout lacks bob's note (and only bob's):\n%s", out.String())
		}
		saved := readCfg(t, cfg2)
		want := []config.Tombstone{
			{Fingerprint: fpOf(t, 2), User: "bob", Date: "2026-11-09"},
			{Fingerprint: fpOf(t, 3), User: "carol", Date: "2026-11-09"},
		}
		if saved.Serial() != 2 || !reflect.DeepEqual(saved.Tombstones, want) {
			t.Errorf("saved = serial %d, %+v; want serial 2 (one bump per saving run) and carol's tombstone after bob's", saved.Serial(), saved.Tombstones)
		}
		if _, still := saved.OwnerOf(fpOf(t, 3)); still {
			t.Error("carol's key is still in users:")
		}
		if got := hosts["web-1"].keys(t); !strings.HasPrefix(got, authkeys.Header(2)+"\n") {
			t.Errorf("web-1 = %q, want the (serial 2) header", got)
		}
	})
}

func TestRevokeUnownedKeyRecordsTombstone(t *testing.T) {
	fixedEditClock(t)
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", fpOf(t, 9), "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (D1b)\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "manifest edit: record revoked key "+fpOf(t, 9)+" (no user has it; no server is written) — no servers affected\n") ||
		!strings.Contains(out.String(), "check every server: sshepherd audit --config "+cfg) {
		t.Errorf("stdout:\n%s", out.String())
	}
	saved := readCfg(t, cfg)
	if saved.Serial() != 1 || len(saved.Tombstones) != 1 || !reflect.DeepEqual(saved.Tombstones[0], config.Tombstone{Fingerprint: fpOf(t, 9), Date: "2026-11-09"}) {
		t.Errorf("saved = serial %d, %+v", saved.Serial(), saved.Tombstones)
	}
	for _, h := range hosts {
		if len(h.srv.Attempts()) != 0 {
			t.Error("D1b contacted a server")
		}
	}
	before := fileBytes(t, cfg)
	out.Reset()
	if code := run([]string{"revoke", "--key", fpOf(t, 9), "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 ||
		out.String() != fpOf(t, 9)+" was already revoked (2026-11-09)\n" || !bytes.Equal(fileBytes(t, cfg), before) {
		t.Errorf("repeat: exit %d, stdout %q (want a no-op note, nothing saved)", code, out.String())
	}
}

func TestRevokeServerRecordsAccessTombstone(t *testing.T) {
	fixedEditClock(t)
	t.Run("explicit grant: a tombstone", func(t *testing.T) {
		_, kh, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		saved := readCfg(t, cfg)
		want := []config.Tombstone{{User: "bob", Servers: []string{"web-2"}, Date: "2026-11-09"}}
		if saved.Serial() != 1 || !reflect.DeepEqual(saved.Tombstones, want) {
			t.Errorf("saved = serial %d, %+v", saved.Serial(), saved.Tombstones)
		}
		before := fileBytes(t, cfg)
		out.Reset()
		if code := run([]string{"revoke", "bob", "--server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 ||
			!strings.HasPrefix(out.String(), "bob's access to web-2 was already revoked (2026-11-09); run 'sshepherd apply") ||
			!bytes.Equal(fileBytes(t, cfg), before) {
			t.Errorf("repeat: exit %d, stdout %q", code, out.String())
		}
	})
	t.Run("wildcard grant: except: remembers, no tombstone", func(t *testing.T) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
		for _, h := range hosts {
			h.install(t, []byte{1, 2})
		}
		cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
			"access:\n  - {user: alice, servers: [\"*\"]}\n  - {user: bob, servers: [\"*\"]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if saved := readCfg(t, cfg); saved.Serial() != 1 || len(saved.Tombstones) != 0 {
			t.Errorf("saved = serial %d, %+v; want a bump and no tombstone", saved.Serial(), saved.Tombstones)
		}
	})
}

func TestRotateTombstonesOldKey(t *testing.T) {
	fixedEditClock(t)
	for _, tc := range []struct {
		name   string
		args   []string
		reason string
	}{
		{"default reason", nil, "rotated out"},
		{"--reason", []string{"--reason", "laptop stolen"}, "laptop stolen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, kh, cfg := twoUserFleet(t)
			args := append([]string{"rotate", "bob", "--old", fpOf(t, 2), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)),
				"--yes", "--config", cfg, "--known-hosts", kh}, tc.args...)
			var out, errBuf bytes.Buffer
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
			}
			saved := readCfg(t, cfg)
			want := []config.Tombstone{{Fingerprint: fpOf(t, 2), User: "bob", Date: "2026-11-09", Reason: tc.reason}}
			if saved.Serial() != 1 || !reflect.DeepEqual(saved.Tombstones, want) {
				t.Errorf("saved = serial %d, %+v", saved.Serial(), saved.Tombstones)
			}
		})
	}
	t.Run("--keep-old: no tombstone, still a bump", func(t *testing.T) {
		_, kh, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"rotate", "bob", "--old", fpOf(t, 2), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)),
			"--keep-old", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if saved := readCfg(t, cfg); saved.Serial() != 1 || len(saved.Tombstones) != 0 {
			t.Errorf("saved = serial %d, %+v", saved.Serial(), saved.Tombstones)
		}
	})
	t.Run("--new of a revoked key is refused", func(t *testing.T) {
		_, kh, cfg := twoUserFleet(t)
		if code := run([]string{"revoke", "--key", fpOf(t, 5), "--yes", "--config", cfg, "--known-hosts", kh}, io.Discard, io.Discard); code != 0 {
			t.Fatal("recording key 5 failed")
		}
		var errBuf bytes.Buffer
		if code := run([]string{"rotate", "bob", "--old", fpOf(t, 2), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)),
			"--yes", "--config", cfg, "--known-hosts", kh}, io.Discard, &errBuf); code != 3 ||
			!strings.Contains(errBuf.String(), "refusing to write the manifest — it would keep 1 policy conflict: key "+fpOf(t, 5)) {
			t.Errorf("exit %d, stderr %q", code, errBuf.String())
		}
	})
}

// TestRevokeHeaderOnlyWriteOnConvergedAffected (the PRD-2 fix, hermetic):
// alice is granted web-1 and web-2 but her key is already missing on
// web-2; revoking her writes web-2's header with the new serial and leaves
// its keys byte-identical.
func TestRevokeHeaderOnlyWriteOnConvergedAffected(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	opLine := testkeys.Line(t, 1) + " op"
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["web-2"].install(t, nil, authkeys.ManagedHeader, opLine)
	cfg := writeConfig(t, "users:\n  - {name: op, operator: true, keys: ["+qk(t, 1)+"]}\n  - {name: alice, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "alice", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if got, want := hosts["web-2"].keys(t), authkeys.Header(1)+"\n"+opLine+"\n"; got != want {
		t.Errorf("web-2 = %q, want %q", got, want)
	}
	for _, s := range []string{"update header: no serial → 1 (keys unchanged)", "web-2: applied · verified"} {
		if !strings.Contains(out.String(), s) {
			t.Errorf("stdout lacks %q:\n%s", s, out.String())
		}
	}
}

// TestRevokeWithoutSweepPrintsAuditCommand (D3): every run that removes a
// key prints the exact follow-up audit with the run's own flags —
// --dry-run and --no-apply included.
func TestRevokeWithoutSweepPrintsAuditCommand(t *testing.T) {
	t.Run("--dry-run", func(t *testing.T) {
		_, kh, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		run([]string{"revoke", "bob", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
		if want := "check every server: sshepherd audit --config " + cfg + " --known-hosts " + kh + "\n"; !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	})
	t.Run("--no-apply", func(t *testing.T) {
		_, _, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		for _, want := range []string{
			"check every server: sshepherd audit --config " + cfg + "\n",
			"servers learn serial 1 only when an apply writes them; until then a copy without this edit can re-grant there\n",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("stdout lacks %q:\n%s", want, out.String())
			}
		}
	})
}
