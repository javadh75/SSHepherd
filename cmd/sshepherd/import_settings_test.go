package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// settingsFixture holds every manifest-only setting a fresh import cannot
// derive from an ssh config: ops (k1) operator, alice (k2) protected, bob
// (k3) in group web-team, db-1 tagged db and reached via the jump_only
// bastion, and gitea with an authorized_keys_file: override and a preserve:
// rule.
func settingsFixture(t *testing.T) string {
	t.Helper()
	return "users:\n" +
		"  - {name: ops, operator: true, keys: [" + qk(t, 1) + "]}\n" +
		"  - {name: alice, protected: true, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: bob, keys: [" + qk(t, 3) + "]}\n" +
		"groups:\n  - {name: web-team, members: [bob]}\n" +
		"servers:\n" +
		"  - {name: bastion, host: 10.0.0.9, user: jump, jump_only: true}\n" +
		"  - {name: db-1, host: 10.0.1.5, user: deploy, via: bastion, tags: [db]}\n" +
		"  - {name: gitea, host: 10.0.0.2, user: git, authorized_keys_file: /var/lib/gitea/.ssh/authorized_keys, preserve: [{command: '/usr/local/bin/gitea serv key-[0-9]+'}]}\n" +
		"access:\n" +
		"  - {user: alice, servers: [gitea]}\n" +
		"  - {group: web-team, servers: [\"@db\"]}\n"
}

// parseManifest is the package's existing helper (cmd/sshepherd/conflicts_test.go:291).

// lossesOf runs every settingLosses entry, keyed by what it names.
func lossesOf(old, fresh *config.Config) map[string][]string {
	got := map[string][]string{}
	for _, l := range settingLosses {
		if names := l.lost(old, fresh); len(names) > 0 {
			got[l.what] = names
		}
	}
	return got
}

// TestSettingLossesCompare (F1 Q1, gap 2): a setting the fresh output
// reproduces is not lost; users are matched by key, never by name; each
// flag is compared on its own field; a server setting is lost when the
// server is missing (labelled "[not in this import]") or its value differs.
func TestSettingLossesCompare(t *testing.T) {
	fixture := settingsFixture(t)
	old := parseManifest(t, fixture)
	everything := map[string][]string{
		"operator: true users":  {"ops"},
		"protected: true users": {"alice"},
		"groups:":               {"web-team"},
		"authorized_keys_file: overrides on servers": {"gitea"},
		"tags: on servers":                           {"db-1"},
		"via: routes":                                {"db-1 via bastion"},
		"jump_only: true servers":                    {"bastion"},
		"preserve: rules on servers":                 {"gitea"},
	}
	missing := map[string][]string{
		"operator: true users":  {"ops"},
		"protected: true users": {"alice"},
		"groups:":               {"web-team"},
		"authorized_keys_file: overrides on servers": {"gitea [not in this import]"},
		"tags: on servers":                           {"db-1 [not in this import]"},
		"via: routes":                                {"db-1 via bastion [not in this import]"},
		"jump_only: true servers":                    {"bastion [not in this import]"},
		"preserve: rules on servers":                 {"gitea [not in this import]"},
	}
	changed := "users:\n" +
		"  - {name: ops, keys: [" + qk(t, 1) + "]}\n" +
		"  - {name: alice, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: bob, keys: [" + qk(t, 3) + "]}\n" +
		"groups:\n  - {name: ops-team, members: [bob]}\n" +
		"servers:\n" +
		"  - {name: bastion, host: 10.0.0.9, user: jump}\n" +
		"  - {name: edge, host: 10.0.0.8, user: jump}\n" +
		"  - {name: db-1, host: 10.0.1.5, user: deploy, via: edge, tags: [db2]}\n" +
		"  - {name: gitea, host: 10.0.0.2, user: git, authorized_keys_file: ~/.ssh/gitea_keys, preserve: [{command: '/usr/local/bin/gitea hook key-[0-9]+'}]}\n" +
		"access:\n" +
		"  - {user: alice, servers: [gitea]}\n" +
		"  - {group: ops-team, servers: [\"@db2\"]}\n"
	// If the hook pattern is ever refused at load (a probe), use any other
	// rule that loads: the row needs only a preserve: value that differs.
	renamed := strings.Replace(fixture, "{name: ops, operator: true", "{name: k1-user, operator: true", 1)
	for _, tt := range []struct {
		name  string
		fresh string
		want  map[string][]string
	}{
		{"everything reproduced", fixture, map[string][]string{}},
		{"an operator renamed but holding the same key", renamed, map[string][]string{}},
		{"every value changed", changed, everything},
		{"nothing at all (a --servers-only import of other hosts)", "users: []\nservers: []\naccess: []\n", missing},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := lossesOf(old, parseManifest(t, tt.fresh))
			if len(got) != len(tt.want) {
				t.Fatalf("losses = %v, want %v", got, tt.want)
			}
			for what, names := range tt.want {
				if !slices.Equal(got[what], names) {
					t.Errorf("%s: %v, want %v", what, got[what], names)
				}
			}
		})
	}
	if order := []string{"operator: true users", "protected: true users", "groups:", "authorized_keys_file: overrides on servers", "tags: on servers", "via: routes", "jump_only: true servers", "preserve: rules on servers"}; !slices.EqualFunc(settingLosses, order, func(l settingLoss, w string) bool { return l.what == w }) {
		t.Errorf("settingLosses order differs from manifest order %v (gap 3)", order)
	}
}

// TestSettingLossesMultiKeyUser (F1 Q1 repair): a marked user keeps its
// mark only when every one of its keys is held by a fresh user with the
// mark; one key re-marked is not enough, because the other key loses its
// fleet-wide grant. Each key may be re-marked under a different fresh name.
func TestSettingLossesMultiKeyUser(t *testing.T) {
	old := parseManifest(t, "users:\n  - {name: ops, operator: true, keys: ["+qk(t, 1)+", "+qk(t, 4)+"]}\nservers: []\naccess: []\n")
	for _, tt := range []struct {
		name  string
		fresh string
		want  []string
	}{
		{"both keys re-marked under new names",
			"users:\n  - {name: laptop, operator: true, keys: [" + qk(t, 1) + "]}\n  - {name: ci, operator: true, keys: [" + qk(t, 4) + "]}\nservers: []\naccess: []\n", nil},
		{"one key re-marked, the other imported plain",
			"users:\n  - {name: laptop, operator: true, keys: [" + qk(t, 1) + "]}\n  - {name: ci, keys: [" + qk(t, 4) + "]}\nservers: []\naccess: []\n", []string{"ops"}},
		{"one key re-marked, the other not imported",
			"users:\n  - {name: laptop, operator: true, keys: [" + qk(t, 1) + "]}\nservers: []\naccess: []\n", []string{"ops"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := lossesOf(old, parseManifest(t, tt.fresh))["operator: true users"]
			if !slices.Equal(got, tt.want) {
				t.Errorf("operator: true users = %v, want %v", got, tt.want)
			}
		})
	}
	// A protected user with no keys (revoke keeps the flag) has nothing a
	// fresh import could mark: its mark is lost, never vacuously kept.
	idle := parseManifest(t, "users:\n  - {name: idle, protected: true, keys: []}\nservers: []\naccess: []\n")
	if got := lossesOf(idle, parseManifest(t, "users: []\nservers: []\naccess: []\n"))["protected: true users"]; !slices.Equal(got, []string{"idle"}) {
		t.Errorf("a keyless protected user: %v, want [idle]", got)
	}
}

// wantSettingLines are the fixture's warnings over FILE m, in order (gap 3).
func wantSettingLines(m string) []string {
	h := hintArg(m)
	return []string{
		m + " holds operator: true users (ops) that this fresh import does not mark: they lose their fleet-wide grant; re-mark them with --operator-key PATH, or keep them with --merge " + h,
		m + " holds protected: true users (alice) that this fresh import does not mark: their keys lose the critical audit tier and the --operator gate; keep them with --merge " + h,
		m + " holds groups: (web-team) that this fresh import drops: their members lose the grants made through them; keep them with --merge " + h,
		m + " holds authorized_keys_file: overrides on servers (gitea) that this fresh import drops: where they stay, apply and audit would use ~/.ssh/authorized_keys; keep them with --merge " + h,
		m + " holds tags: on servers (db-1) that this fresh import drops: @tag grants no longer reach them; keep them with --merge " + h,
		m + " holds via: routes (db-1 via bastion) that this fresh import does not reproduce: where they stay, they would be dialed another way; keep them with --merge " + h,
		m + " holds jump_only: true servers (bastion [not in this import]) that this fresh import does not mark: where they stay, apply would manage their authorized_keys; keep them with --merge " + h,
		m + " holds preserve: rules on servers (gitea) that this fresh import drops: where they stay, apply would remove the lines they keep; keep them with --merge " + h,
	}
}

// settingLines returns stderr's manifest_settings_dropped lines, in order.
func settingLines(stderr string) []string {
	var got []string
	for _, line := range strings.Split(stderr, "\n") {
		if i := strings.Index(line, " that this fresh import "); i >= 0 && !strings.Contains(line, "revocation memory") {
			got = append(got, line)
		}
	}
	return got
}

// TestImportForceWarnsSettingsLost (F1 Q1): a fresh import -o FILE --force
// over a manifest holding manifest-only settings warns once per kind, in
// manifest order, exit 0, the file is still replaced; a via: the ssh
// config reproduces is not named; --merge (in place or into another FILE),
// a FILE without such settings, a run without -o and a run refused for
// lack of --force (exit 3) stay quiet.
func TestImportForceWarnsSettingsLost(t *testing.T) {
	hermeticHome(t)
	direct := writeSSHConfig(t, "Host gitea\n  HostName 10.0.0.2\n  User git\nHost db-1\n  HostName 10.0.1.5\n  User deploy\n")
	routed := writeSSHConfig(t, "Host bastion\n  HostName 10.0.0.9\n  User jump\nHost db-1\n  HostName 10.0.1.5\n  User deploy\n  ProxyJump bastion\nHost gitea\n  HostName 10.0.0.2\n  User git\n")
	other := writeSSHConfig(t, "Host web-9\n  HostName 10.0.9.9\n  User deploy\n")
	t.Run("every kind, one line each", func(t *testing.T) {
		m := writeConfig(t, settingsFixture(t))
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", direct, "--servers-only", "-o", m, "--force"}, &out, &errBuf); code != 0 {
			t.Fatalf("exit %d\n%s", code, errBuf.String())
		}
		got, want := settingLines(errBuf.String()), wantSettingLines(m)
		if len(got) != len(want) {
			t.Fatalf("got %d lines, want %d:\n%s", len(got), len(want), errBuf.String())
		}
		for i := range want {
			if !strings.HasSuffix(got[i], want[i]) {
				t.Errorf("line %d = %q\nwant suffix %q", i, got[i], want[i])
			}
		}
		if strings.Contains(fileString(t, m), "groups:") {
			t.Error("FILE was not replaced by the fresh manifest")
		}
	})
	// A FILE path with a space: the --merge hint is quoted, so the line
	// stays paste-ready (hintArg, not the bare path).
	t.Run("a FILE path with a space is quoted", func(t *testing.T) {
		m := filepath.Join(t.TempDir(), "fleet manifest.yaml")
		if err := os.WriteFile(m, []byte(settingsFixture(t)), 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", direct, "--servers-only", "-o", m, "--force"}, &out, &errBuf); code != 0 {
			t.Fatalf("exit %d\n%s", code, errBuf.String())
		}
		got := settingLines(errBuf.String())
		if len(got) == 0 || !strings.HasSuffix(got[0], ` with --merge "`+m+`"`) {
			t.Errorf("want the hint quoted:\n%s", errBuf.String())
		}
	})
	t.Run("a reproduced via: is not named", func(t *testing.T) {
		m := writeConfig(t, settingsFixture(t))
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", routed, "--servers-only", "-o", m, "--force"}, &out, &errBuf); code != 0 {
			t.Fatalf("exit %d\n%s", code, errBuf.String())
		}
		got := settingLines(errBuf.String())
		if len(got) != 7 || strings.Contains(errBuf.String(), "via: routes") || !strings.Contains(errBuf.String(), "jump_only: true servers (bastion)") {
			t.Errorf("want seven lines, no via: line, the jump_only: line still there:\n%s", errBuf.String())
		}
	})
	plainFile := "users:\n  - {name: bob, keys: [" + qk(t, 3) + "]}\nservers:\n  - {name: gitea, host: 10.0.0.2, user: git}\naccess:\n  - {user: bob, servers: [gitea]}\n"
	plain := writeConfig(t, plainFile) // a --merge source with no manifest-only setting
	for _, tt := range []struct {
		name     string
		args     func(m string) []string
		file     string
		wantCode int
	}{
		{"--merge keeps every setting", func(m string) []string {
			return []string{"import", other, "--servers-only", "--merge", m, "-o", m, "--force"}
		}, settingsFixture(t), 0},
		// Kills a freshDrops call moved outside `if mergePath == ""`: -o names
		// a different existing FILE holding every setting, which a merge run
		// replaces with --force but never compares (R1-1).
		{"--merge into another FILE stays quiet", func(m string) []string {
			return []string{"import", other, "--servers-only", "--merge", plain, "-o", m, "--force"}
		}, settingsFixture(t), 0},
		{"a FILE without such settings", func(m string) []string { return []string{"import", direct, "--servers-only", "-o", m, "--force"} },
			plainFile, 0},
		{"no -o", func(string) []string { return []string{"import", direct, "--servers-only"} }, settingsFixture(t), 0},
		// Without --force the write is refused (exit 3): no "drops" line may
		// precede the refusal, and FILE is untouched (R0-2).
		{"no --force (refused)", func(m string) []string { return []string{"import", direct, "--servers-only", "-o", m} },
			settingsFixture(t), 3},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := writeConfig(t, tt.file)
			var out, errBuf bytes.Buffer
			if code := run(tt.args(m), &out, &errBuf); code != tt.wantCode {
				t.Fatalf("exit %d, want %d\n%s", code, tt.wantCode, errBuf.String())
			}
			if got := settingLines(errBuf.String()); len(got) != 0 {
				t.Errorf("warned:\n%s", strings.Join(got, "\n"))
			}
			if tt.wantCode != 0 && fileString(t, m) != tt.file {
				t.Error("a refused run changed FILE")
			}
		})
	}
}

// TestImportForceRefusedWriteStaysQuiet (F1 Q1 repair, R0-2): a fresh
// import -o LINK --force is refused at the write (LINK is a symlink, exit
// 3, nothing replaced), so no "drops" line — the settings lines or the
// revocation-memory line — may come before the refusal, as text or --json.
func TestImportForceRefusedWriteStaysQuiet(t *testing.T) {
	hermeticHome(t)
	direct := writeSSHConfig(t, "Host gitea\n  HostName 10.0.0.2\n  User git\nHost db-1\n  HostName 10.0.1.5\n  User deploy\n")
	file := "serial: 4\n" + settingsFixture(t) + "revoked:\n  - {fingerprint: " + fingerprintOf(t, testkeys.Line(t, 9)) + ", user: old, date: 2026-11-08}\n"
	for _, tt := range []struct {
		name  string
		extra []string
	}{
		{"text", nil},
		{"--json", []string{"--json"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			target := writeConfig(t, file)
			link := filepath.Join(filepath.Dir(target), "link.yaml")
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			var out, errBuf bytes.Buffer
			args := append([]string{"import", direct, "--servers-only", "-o", link, "--force"}, tt.extra...)
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit %d, want 3\n%s", code, errBuf.String())
			}
			stderr := errBuf.String()
			if strings.Contains(stderr, " that this fresh import ") || !strings.Contains(stderr, "is a symlink; refusing to replace it") {
				t.Errorf("want only the refusal, no drops line:\n%s", stderr)
			}
			if out.Len() != 0 {
				t.Errorf("a refused run wrote stdout:\n%s", out.String())
			}
			if fileString(t, target) != file {
				t.Error("a refused run changed the link's target")
			}
		})
	}
}

// TestImportForceOperatorKeyOneOfTwoKeys (F1 Q1 repair): FILE's operator
// ops holds keys laptop (k1) and ci (k4); a fresh import re-marks only
// laptop, so ci loses its fleet-wide grant and ops is named.
func TestImportForceOperatorKeyOneOfTwoKeys(t *testing.T) {
	home := hermeticHome(t)
	laptop, ci := filepath.Join(home, "laptop"), filepath.Join(home, "ci")
	for path, n := range map[string]byte{laptop: 1, ci: 4} {
		if err := os.WriteFile(path+".pub", []byte(testkeys.Line(t, n)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sshCfg := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n  IdentityFile "+laptop+
		"\nHost web-2\n  HostName 10.0.0.2\n  User deploy\n  IdentityFile "+ci+"\n")
	m := writeConfig(t, "users:\n  - {name: ops, operator: true, keys: ["+qk(t, 1)+", "+qk(t, 4)+"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: web-2, host: 10.0.0.2, user: deploy}\naccess: []\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", sshCfg, "-o", m, "--force", "--operator-key", laptop}, &out, &errBuf); code != 0 {
		t.Fatalf("exit %d\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "holds operator: true users (ops) that this fresh import does not mark") {
		t.Errorf("want the operator line for ops:\n%s", errBuf.String())
	}
}

// TestImportForceOperatorKeyReMarks (F1 Q1, gap 2): --operator-key with
// the operator's key re-marks it under the fresh name, so no operator line;
// the same import without --operator-key names the FILE user.
func TestImportForceOperatorKeyReMarks(t *testing.T) {
	home := hermeticHome(t)
	work := filepath.Join(home, "work")
	if err := os.WriteFile(work+".pub", []byte(testkeys.Line(t, 1)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sshCfg := writeSSHConfig(t, "Host web-1\n  HostName 10.0.0.1\n  User deploy\n  IdentityFile "+work+"\n")
	file := "users:\n  - {name: legacy-ops, operator: true, keys: [" + qk(t, 1) + "]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\naccess: []\n"
	for _, tt := range []struct {
		name  string
		extra []string
		warns bool
	}{
		{"re-marked by --operator-key", []string{"--operator-key", work}, false},
		{"imported as a plain user", nil, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := writeConfig(t, file)
			var out, errBuf bytes.Buffer
			args := append([]string{"import", sshCfg, "-o", m, "--force"}, tt.extra...)
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit %d\n%s", code, errBuf.String())
			}
			wantLines := 0
			if tt.warns {
				wantLines = 1
			}
			got := strings.Contains(errBuf.String(), "holds operator: true users (legacy-ops)")
			if got != tt.warns || len(settingLines(errBuf.String())) != wantLines {
				t.Errorf("operator line = %v, want %v:\n%s", got, tt.warns, errBuf.String())
			}
		})
	}
}

// TestImportJSONSettingsDroppedWarning (F1 Q1): --json carries one
// manifest_settings_dropped entry per line, counted in summary.warnings,
// each message exactly what stderr printed.
func TestImportJSONSettingsDroppedWarning(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host gitea\n  HostName 10.0.0.2\n  User git\nHost db-1\n  HostName 10.0.1.5\n  User deploy\n")
	dst := writeConfig(t, settingsFixture(t))
	code, doc, stderr := importJSONCLI(t, path, "--servers-only", "-o", dst, "--force")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	want := wantSettingLines(dst)
	if len(doc.Warnings) != len(want) || doc.Summary.Warnings != len(want) {
		t.Fatalf("warnings = %+v (summary %d), want %d", doc.Warnings, doc.Summary.Warnings, len(want))
	}
	for i, w := range doc.Warnings {
		if w.Kind != importWarnSettingsDropped || w.Message != want[i] || !strings.Contains(stderr, w.Message) {
			t.Errorf("warning %d = %+v, want kind %s, message %q", i, w, importWarnSettingsDropped, want[i])
		}
	}
}

func fileString(t *testing.T, path string) string { t.Helper(); return string(fileBytes(t, path)) }

// TestImportForceMemoryWarningFirst (F1 Q1, gap 3): a FILE holding both
// revocation memory and manifest-only settings prints the memory line
// first, then the settings lines, in stderr and in --json warnings[].
func TestImportForceMemoryWarningFirst(t *testing.T) {
	hermeticHome(t)
	direct := writeSSHConfig(t, "Host gitea\n  HostName 10.0.0.2\n  User git\nHost db-1\n  HostName 10.0.1.5\n  User deploy\n")
	file := "serial: 4\n" + settingsFixture(t) + "revoked:\n  - {fingerprint: " + fingerprintOf(t, testkeys.Line(t, 9)) + ", user: old, date: 2026-11-08}\n"
	t.Run("text", func(t *testing.T) {
		m := writeConfig(t, file)
		var out, errBuf bytes.Buffer
		if code := run([]string{"import", direct, "--servers-only", "-o", m, "--force"}, &out, &errBuf); code != 0 {
			t.Fatalf("exit %d\n%s", code, errBuf.String())
		}
		stderr := errBuf.String()
		mem := strings.Index(stderr, "holds revocation memory")
		set := strings.Index(stderr, "holds groups:")
		if mem < 0 || set < 0 || mem > set {
			t.Errorf("want the memory line before the settings lines:\n%s", stderr)
		}
	})
	t.Run("--json", func(t *testing.T) {
		m := writeConfig(t, file)
		code, doc, stderr := importJSONCLI(t, direct, "--servers-only", "-o", m, "--force")
		if code != 0 {
			t.Fatalf("exit = %d (stderr: %s)", code, stderr)
		}
		if len(doc.Warnings) < 2 || doc.Warnings[0].Kind != importWarnMemoryDropped || doc.Warnings[1].Kind != importWarnSettingsDropped {
			t.Errorf("warnings = %+v, want %s first, then %s", doc.Warnings, importWarnMemoryDropped, importWarnSettingsDropped)
		}
	})
}
