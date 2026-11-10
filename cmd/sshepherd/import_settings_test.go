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
		// Kills a warnFreshDrops call moved outside `if mergePath == ""`: -o names
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
