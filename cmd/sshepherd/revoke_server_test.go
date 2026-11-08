package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRevokeServerUsage: the usage refusals, first match wins, all before
// the manifest is read (the missing manifest would otherwise be the
// error) and with nothing on stdout.
func TestRevokeServerUsage(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	const (
		both     = "revoke takes users or --key, not both"
		perUser  = "access is granted per user, not per key — use 'sshepherd revoke USER --server NAME'"
		operator = "--operator cannot be combined with --server: operators have access to every server by definition"
		star     = "--server takes server names; to remove all of a user's access use 'sshepherd revoke USER'"
	)
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"users, --key and --server", []string{"bob", "--key", fpOf(t, 2), "--server", "web-1"}, both},
		{"--server with --key", []string{"--key", fpOf(t, 2), "--server", "web-1"}, perUser},
		{"--server with --key, --operator and '*'", []string{"--key", fpOf(t, 2), "--server", "*", "--operator"}, perUser},
		{"--server with --operator", []string{"bob", "--server", "web-1", "--operator"}, operator},
		{"--server '*' with --operator", []string{"bob", "--server", "*", "--operator"}, operator},
		{"--server '*'", []string{"bob", "--server", "web-1", "--server", "*"}, star},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			args := append(append([]string{"revoke"}, tt.args...), "--config", "/nonexistent.yaml")
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), tt.want) || out.Len() != 0 {
				t.Errorf("stderr = %q, stdout = %q; want %q", errBuf.String(), out.String(), tt.want)
			}
		})
	}
}

// accessRefusalBody: alice explicit on web-1/web-2, bob wildcard minus
// db-1, ops-bot an operator with no access: entry.
func accessRefusalBody(t *testing.T) string {
	return "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: ops-bot, operator: true, keys: [" + qk(t, 3) + "]}\n" +
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: web-2, host: 10.0.0.2, user: deploy}\n" +
		"  - {name: db-1, host: 10.0.0.9, user: deploy}\n" +
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n  - {user: bob, servers: [\"*\"], except: [db-1]}\n"
}

// TestRevokeServerRefusals: after the manifest is read, every problem is
// listed in one exit-3 message, in order (unknown users, unknown servers,
// operators, ungranted pairs); operators are refused without the
// --operator gate; nothing is edited and nothing is printed on stdout.
func TestRevokeServerRefusals(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	const opMsg = "ops-bot is an operator (access to every server by definition); remove the user with 'sshepherd revoke ops-bot --config CFG --operator', or clear operator: true by hand"
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"unknown server", []string{"bob", "--server", "db-9"}, `no server named "db-9" in the manifest`},
		{"operator target, no gate", []string{"ops-bot", "--server", "web-1"}, opMsg},
		{"every ungranted pair listed", []string{"alice", "bob", "--server", "web-1", "--server", "db-1"},
			"alice has no access to db-1; bob has no access to db-1"},
		{"all problems, in order", []string{"carol", "ops-bot", "alice", "--server", "db-9", "--server", "db-1"},
			`unknown user: carol; no server named "db-9" in the manifest; ` + opMsg + "; alice has no access to db-1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := writeConfig(t, accessRefusalBody(t))
			before := fileBytes(t, cfg)
			var out, errBuf bytes.Buffer
			args := append(append([]string{"revoke"}, tt.args...), "--yes", "--config", cfg)
			if code := run(args, &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
			}
			if want := strings.ReplaceAll(tt.want, "CFG", cfg); !strings.Contains(errBuf.String(), want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), want)
			}
			if strings.Contains(errBuf.String(), "pass --operator to confirm") {
				t.Errorf("the --server path must not run the operator gate: %q", errBuf.String())
			}
			if out.Len() != 0 || !bytes.Equal(fileBytes(t, cfg), before) {
				t.Error("a refused trim printed or edited something")
			}
		})
	}
}

// TestRevokeServerPrintsKeptAccess: 'revoke alice --server web-1' says how
// much access alice keeps, so a "web-1 first" run cannot pass for an
// offboarding (UX-7's minimal fix).
func TestRevokeServerPrintsKeptAccess(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n  - {name: web-2, host: 10.0.0.2, user: deploy}\n  - {name: db-1, host: 10.0.0.3, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1, web-2, db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "alice", "--server", "web-1", "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
	if want := "alice keeps access to 2 other servers"; !strings.Contains(out.String(), want) {
		t.Errorf("stdout lacks %q:\n%s", want, out.String())
	}
}

// TestRevokeServerHermetic: bob loses web-1 only — his entry keeps web-2,
// his user entry and key stay, only web-1 is contacted, the reminder names
// the removed access, and there is no scope line (servers not named are
// genuinely unaffected).
func TestRevokeServerHermetic(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{
		"manifest edit: remove bob's access to web-1 (1 access entry changed); bob keeps access to 1 other server — 1 server affected\n",
		"manifest " + cfg + " updated — commit and push it: an apply from a copy without this edit is refused on the servers this run writes (serial 1)\n",
		"web-1: applied · verified",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "scope:") || strings.Contains(out.String(), "web-2:") {
		t.Errorf("a trim prints no scope line and never touches web-2:\n%s", out.String())
	}
	raw := string(fileBytes(t, cfg))
	for _, want := range []string{"  # bob leaves on Friday\n", "  - {user: bob, servers: [web-2]}\n", "  - {user: alice, servers: [web-1, web-2]}\n"} {
		if !strings.Contains(raw, want) {
			t.Errorf("manifest lacks %q:\n%s", want, raw)
		}
	}
	if len(readCfg(t, cfg).Users) != 2 {
		t.Error("the trim removed a user")
	}
	if got := hosts["web-1"].keys(t); strings.Contains(got, testkeys.Line(t, 2)) || !strings.Contains(got, testkeys.Line(t, 1)) {
		t.Errorf("web-1 authorized_keys = %q, want alice only", got)
	}
	if len(hosts["web-2"].srv.Attempts()) != 0 || !strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
		t.Error("web-2 was contacted or changed")
	}
}

// TestRevokeServerWildcard: a wildcard grant gains except: (created in the
// entry's flow style); a wildcard left covering no current server is
// deleted with the warning and the no-access-left note.
func TestRevokeServerWildcard(t *testing.T) {
	setup := func(t *testing.T, bobAccess string) (map[string]editHost, string, string) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
		for _, h := range hosts {
			h.install(t, []byte{1, 2})
		}
		cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
			"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
			"access:\n  - {user: alice, servers: [web-1, web-2]}\n"+bobAccess)
		return hosts, kh, cfg
	}
	t.Run("except created", func(t *testing.T) {
		hosts, kh, cfg := setup(t, "  - user: bob\n    servers: [\"*\"]\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		if want := "manifest edit: remove bob's access to web-1 (1 access entry changed, 1 server excepted); bob keeps access to 1 other server — 1 server affected\n"; !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
		if raw := string(fileBytes(t, cfg)); !strings.Contains(raw, "  - user: bob\n    servers: [\"*\"]\n    except: [web-1]\n") {
			t.Errorf("manifest:\n%s", raw)
		}
		if strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) || !strings.Contains(hosts["web-2"].keys(t), testkeys.Line(t, 2)) {
			t.Error("want bob's key gone from web-1 only")
		}
	})
	t.Run("wildcard left covering nothing", func(t *testing.T) {
		_, kh, cfg := setup(t, "  - {user: bob, servers: [\"*\"], except: [web-2]}\n")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		for _, want := range []string{
			"manifest edit: remove bob's access to web-1 (1 access entry removed) — 1 server affected\n",
			"warning: bob's wildcard grant is removed — it would cover no current server; servers added later are no longer granted to bob automatically\n",
			"note: bob has no access left — 'sshepherd revoke bob --config " + cfg + " --known-hosts " + kh + "' removes the user\n",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("stdout lacks %q:\n%s", want, out.String())
			}
		}
		saved := readCfg(t, cfg)
		if len(saved.Users) != 2 || len(saved.Access) != 1 || saved.Access[0].User != "alice" {
			t.Errorf("saved = %+v, want bob kept with no access entry", saved)
		}
	})
}

// TestRevokeServerSoleGrantee: db-1's only grantee loses it — the emptied
// warning heads the report, db-1 is refused and keeps the key, web-1
// converges, and the emptied entry is gone with the no-access-left note.
func TestRevokeServerSoleGrantee(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "db-1")
	hosts["web-1"].install(t, []byte{1, 2})
	hosts["db-1"].install(t, []byte{2})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: bob, keys: ["+qk(t, 2)+"]}\n"+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["db-1"].line("db-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n  - {user: bob, servers: [web-1, db-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--server", "web-1", "--server", "db-1", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	s := out.String()
	for _, want := range []string{
		"manifest edit: remove bob's access to web-1, db-1 (1 access entry removed) — 2 servers affected\n",
		"note: bob has no access left — 'sshepherd revoke bob --config " + cfg + " --known-hosts " + kh + "' removes the user\n",
		"warning: db-1 would have no granted keys — apply never empties a server, so bob's key stays installed there",
		"web-1: applied · verified",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout lacks %q:\n%s", want, s)
		}
	}
	if !strings.Contains(hosts["db-1"].keys(t), testkeys.Line(t, 2)) {
		t.Error("db-1 was emptied")
	}
	if saved := readCfg(t, cfg); len(saved.Users) != 2 || len(saved.Access) != 1 {
		t.Errorf("saved = %+v", saved)
	}
}

// TestRevokeServerNoApplyDryRun: --no-apply saves and names the apply that
// pushes it (no scope line); --dry-run saves and writes nothing; a
// repeated --server is one server; --dry-run --no-apply prints the header
// only.
func TestRevokeServerNoApplyDryRun(t *testing.T) {
	t.Run("--no-apply", func(t *testing.T) {
		hosts, _, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--no-apply", "--yes", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		for _, want := range []string{
			"servers learn serial 1 only when an apply writes them; until then a copy without this edit can re-grant there\n",
			"no servers contacted — 1 affected server still carries the old keys; run 'sshepherd apply --config " + cfg + " --server web-1' to push\n",
		} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("stdout lacks %q:\n%s", want, out.String())
			}
		}
		if strings.Contains(out.String(), "scope:") {
			t.Errorf("no scope line on a trim:\n%s", out.String())
		}
		for name, h := range hosts {
			if len(h.srv.Attempts()) != 0 {
				t.Errorf("--no-apply connected to %s", name)
			}
		}
	})
	t.Run("--dry-run", func(t *testing.T) {
		hosts, kh, cfg := twoUserFleet(t)
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
			t.Fatalf("exit = %d, want 1 (pending)\n%s", code, errBuf.String())
		}
		if !bytes.Equal(fileBytes(t, cfg), before) || !strings.Contains(hosts["web-1"].keys(t), testkeys.Line(t, 2)) {
			t.Error("--dry-run changed something")
		}
	})
	t.Run("duplicate --server, --dry-run --no-apply", func(t *testing.T) {
		_, _, cfg := twoUserFleet(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "bob", "--server", "web-1", "--server", "web-1", "--no-apply", "--dry-run", "--config", cfg}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		if out.String() != "manifest edit: remove bob's access to web-1 (1 access entry changed); bob keeps access to 1 other server — 1 server affected\n" {
			t.Errorf("stdout = %q", out.String())
		}
	})
}

// TestRevokeServerNothingCanLand: every affected server refused — the
// refusal reads "bob still has access on N servers", nothing saved.
func TestRevokeServerNothingCanLand(t *testing.T) {
	hosts, kh, cfg := twoUserFleet(t)
	for _, h := range hosts {
		h.install(t, []byte{1, 2}, "this line is not a key")
	}
	before := fileBytes(t, cfg)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--server", "web-1", "--server", "web-2", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "nothing saved — bob still has access on 2 servers;") {
		t.Errorf("stderr = %q", errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("manifest saved although nothing could land")
	}
}

// TestRevokeServerJSON: the remove-access entry and its fields; the
// removed key is still bob's, so it carries owner, not former_owner.
func TestRevokeServerJSON(t *testing.T) {
	_, kh, cfg := twoUserFleet(t)
	doc := runJSONDoc(context.Background(), t, 0, "revoke", "bob", "--server", "web-1", "--json", "--yes", "--config", cfg, "--known-hosts", kh)
	edit := doc["edit"].(map[string]any)
	if edit["saved"] != true || edit["affected"] != float64(1) {
		t.Errorf("edit = %v", edit)
	}
	e := edit["edits"].([]any)[0].(map[string]any)
	if e["kind"] != "remove-access" || e["user"] != "bob" || e["entries_changed"] != float64(1) ||
		e["entries_removed"] != float64(0) || e["no_grants_left"] != false || e["keys"] != nil {
		t.Errorf("edit entry = %v", e)
	}
	if s := e["access_servers"].([]any); len(s) != 1 || s[0] != "web-1" {
		t.Errorf("access_servers = %v", s)
	}
	servers := docServers(doc)
	if len(servers) != 1 || servers[0]["name"] != "web-1" || servers[0]["outcome"] != "applied" {
		t.Fatalf("servers = %v", servers)
	}
	removed := servers[0]["changes"].(map[string]any)["remove"].([]any)
	if len(removed) != 1 || removed[0].(map[string]any)["owner"] != "bob" {
		t.Errorf("remove = %v", removed)
	}
}
