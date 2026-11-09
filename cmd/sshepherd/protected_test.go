package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// gateCfg: ops and ops2 are fleet-wide operators, ci is protected, scoped is
// an operator with its own "*", alice is plain.
func gateCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte("users:\n" +
		"  - {name: ops, operator: true, keys: [" + qk(t, 1) + "]}\n" +
		"  - {name: ops2, operator: true, keys: [" + qk(t, 2) + "]}\n" +
		"  - {name: ci, protected: true, keys: [" + qk(t, 3) + "]}\n" +
		"  - {name: scoped, operator: true, keys: [" + qk(t, 4) + "]}\n" +
		"  - {name: alice, keys: [" + qk(t, 5) + "]}\n" +
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n" +
		"access:\n  - {user: scoped, servers: [\"*\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestOperatorGateWording(t *testing.T) {
	cfg := gateCfg(t)
	for _, tc := range []struct {
		name    string
		targets []string
		want    string
	}{
		{"one fleet-wide operator", []string{"ops"}, "ops is an operator (fleet-wide, protected); pass --operator to confirm"},
		{"two fleet-wide operators", []string{"ops", "ops2"}, "ops, ops2 are operators (fleet-wide, protected); pass --operator to confirm"},
		{"one protected", []string{"ci"}, "ci is protected; pass --operator to confirm"},
		{"a scoped operator", []string{"scoped"}, "scoped is protected; pass --operator to confirm"},
		{"two protected", []string{"ci", "scoped"}, "ci, scoped are protected; pass --operator to confirm"},
		{"a mix uses the protected form", []string{"ops", "ci"}, "ops, ci are protected; pass --operator to confirm"},
		{"a plain target is not named", []string{"alice", "ci"}, "ci is protected; pass --operator to confirm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := operatorGate(cfg, tc.targets, false)
			if err == nil || err.Error() != tc.want {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := operatorGate(cfg, []string{"alice"}, true); err == nil || err.Error() != "--operator given but no target is an operator; drop the flag" {
		t.Errorf("err = %v", err)
	}
	got, err := operatorGate(cfg, []string{"alice", "ci", "ops", "ci"}, true)
	if err != nil || !reflect.DeepEqual(got, []string{"ci", "ops"}) {
		t.Errorf("operatorGate = (%v, %v), want [ci ops], target order, once each", got, err)
	}
}

func TestAcknowledgeSortsByWhatMayBeSaid(t *testing.T) {
	cfg := gateCfg(t)
	var ep editPlan
	ep.acknowledge(cfg, []string{"ci", "ops", "scoped"})
	if !reflect.DeepEqual(ep.summary.Operators, []string{"ops"}) || !reflect.DeepEqual(ep.summary.Protected, []string{"ci", "scoped"}) {
		t.Errorf("Operators = %v, Protected = %v", ep.summary.Operators, ep.summary.Protected)
	}
}

// protectedFleetManifest: alice (k1, held) is a plain grantee of both
// servers; ci (k2) is protected, granted by ciAccess; both keys are installed
// on both servers. users and extra are spliced in.
func protectedFleetManifest(t *testing.T, users, ciAccess, extra string) (map[string]editHost, string, string) {
	t.Helper()
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1", "web-2")
	for _, h := range hosts {
		h.install(t, []byte{1, 2})
	}
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n  - {name: ci, protected: true, keys: ["+qk(t, 2)+"]}\n"+users+
		"servers:\n"+hosts["web-1"].line("web-1")+hosts["web-2"].line("web-2")+
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n"+ciAccess+extra)
	return hosts, kh, cfg
}

const ciByName = "  - {user: ci, servers: [web-1, web-2]}\n"

// TestProtectedTargetRefusedEveryPath: without --operator every path that
// could take a protected user's access or key away is refused: exit 3,
// nothing printed on stdout, nothing saved, nothing dialed. The gate is per
// target, so it applies whether or not the user holds a grant.
func TestProtectedTargetRefusedEveryPath(t *testing.T) {
	newPub := writePub(t, "id_new.pub", testkeys.Line(t, 6))
	for _, tc := range []struct {
		name, ciAccess string
		args           []string
	}{
		{"revoke USER", ciByName, []string{"revoke", "ci"}},
		{"revoke --key", ciByName, []string{"revoke", "--key", fpOf(t, 2)}},
		{"revoke --from-server", ciByName, []string{"revoke", "ci", "--from-server", "web-1"}},
		{"rotate", ciByName, []string{"rotate", "ci", "--old", fpOf(t, 2), "--new", newPub}},
		{"rotate --keep-old", ciByName, []string{"rotate", "ci", "--old", fpOf(t, 2), "--new", newPub, "--keep-old"}},
		{"revoke USER with no grant", "", []string{"revoke", "ci"}},
		{"rotate with no grant", "", []string{"rotate", "ci", "--old", fpOf(t, 2), "--new", newPub}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts, kh, cfg := protectedFleetManifest(t, "", tc.ciAccess, "")
			before := fileBytes(t, cfg)
			var out, errBuf bytes.Buffer
			code := run(append(tc.args, "--yes", "--config", cfg, "--known-hosts", kh), &out, &errBuf)
			if code != 3 || out.Len() != 0 || !strings.Contains(errBuf.String(), "ci is protected; pass --operator to confirm") {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, out.String(), errBuf.String())
			}
			if !bytes.Equal(fileBytes(t, cfg), before) {
				t.Errorf("the manifest changed:\n%s", fileBytes(t, cfg))
			}
			for name, h := range hosts {
				if len(h.srv.Attempts()) != 0 {
					t.Errorf("%s was dialed", name)
				}
			}
		})
	}
}

func TestRevokeProtectedWithOperator(t *testing.T) {
	hosts, kh, cfg := protectedFleetManifest(t, "", ciByName, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "ci", "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "PROTECTED: ci is protected; --operator given") || strings.Contains(out.String(), "OPERATOR:") {
		t.Errorf("stdout:\n%s", out.String())
	}
	blob := strings.Fields(testkeys.Line(t, 2))[1]
	for name, h := range hosts {
		if strings.Contains(h.keys(t), blob) {
			t.Errorf("%s still holds ci's key", name)
		}
	}
	if _, ok := readCfg(t, cfg).Revoked(fpOf(t, 2)); !ok {
		t.Error("the key was not tombstoned")
	}
}

func TestRevokeProtectedJSON(t *testing.T) {
	_, kh, cfg := protectedFleetManifest(t, "", ciByName, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "ci", "--operator", "--json", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	edit, _ := oneJSONDoc(t, out.String())["edit"].(map[string]any)
	if ops, _ := edit["operators"].([]any); len(ops) != 0 {
		t.Errorf("operators = %v", edit["operators"])
	}
	if p, _ := edit["protected"].([]any); len(p) != 1 || p[0] != "ci" {
		t.Errorf("protected = %v", edit["protected"])
	}
}

func TestRevokeProtectedPrompt(t *testing.T) {
	_, kh, cfg := protectedFleetManifest(t, "", ciByName, "")
	var prompt bytes.Buffer
	usePromptStreams(t, strings.NewReader("y\n"), &prompt)
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "ci", "--operator", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(prompt.String(), "PROTECTED ci: save manifest edit and write 2 of 2 affected servers? [y/N]") {
		t.Errorf("prompt = %q", prompt.String())
	}
}

// TestRevokeKeyProtectedKeepsFlag: a protected non-operator losing its last
// key keeps protected: true, is not told an operator flag was cleared, and is
// told a command that works: without --operator the hint would exit 3.
func TestRevokeKeyProtectedKeepsFlag(t *testing.T) {
	_, kh, cfg := protectedFleetManifest(t, "", ciByName, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", fpOf(t, 2), "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "note: ci has no keys left — 'sshepherd revoke ci") || !strings.Contains(out.String(), "--operator' removes the user") ||
		strings.Contains(out.String(), "operator flag is cleared") {
		t.Errorf("stdout:\n%s", out.String())
	}
	saved := readCfg(t, cfg)
	if !saved.Users[1].Protected || len(saved.Users[1].Keys) != 0 {
		t.Errorf("ci = %+v", saved.Users[1])
	}
}

// TestRevokeKeyScopedOperatorClearsFlag: a scoped operator is printed as
// protected but is still an operator, so its last key still clears the flag,
// and once cleared nothing protects it: the hint needs no --operator.
func TestRevokeKeyScopedOperatorClearsFlag(t *testing.T) {
	users := "  - {name: root-op, operator: true, keys: [" + qk(t, 3) + "]}\n"
	_, kh, cfg := protectedFleetManifest(t, users, ciByName+"  - {user: root-op, servers: [\"*\"], except: [web-2]}\n", "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "--key", fpOf(t, 3), "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "PROTECTED: root-op is protected") || !strings.Contains(out.String(), "its operator flag is cleared") ||
		strings.Contains(out.String(), "--operator' removes the user") {
		t.Errorf("stdout:\n%s", out.String())
	}
	if readCfg(t, cfg).Users[2].Operator {
		t.Error("the operator flag was not cleared")
	}
}

func TestRotateProtected(t *testing.T) {
	hosts, kh, cfg := protectedFleetManifest(t, "", ciByName, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "ci", "--old", fpOf(t, 2), "--new", writePub(t, "id_new.pub", testkeys.Line(t, 6)), "--operator", "--yes",
		"--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "PROTECTED: ci is protected; --operator given") {
		t.Errorf("stdout:\n%s", out.String())
	}
	added := strings.Fields(testkeys.Line(t, 6))[1]
	if !strings.Contains(hosts["web-1"].keys(t), added) {
		t.Errorf("web-1:\n%s", hosts["web-1"].keys(t))
	}
	if !readCfg(t, cfg).Users[1].Protected {
		t.Error("rotate lost protected: true")
	}
}

// TestRotateKeepOldProtectedFinishHint: finishing the overlap needs the
// acknowledgement, so the printed command carries --operator.
func TestRotateKeepOldProtectedFinishHint(t *testing.T) {
	_, kh, cfg := protectedFleetManifest(t, "", ciByName, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"rotate", "ci", "--old", fpOf(t, 2), "--new", writePub(t, "id_new.pub", testkeys.Line(t, 6)), "--keep-old", "--operator", "--yes",
		"--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "--operator\n") {
		t.Errorf("the finish hint lacks --operator:\n%s", out.String())
	}
}

// TestRevokeProtectedGroupMember: a membership change is an access removal.
// revoke USER drops a protected member from its groups only with --operator,
// and a trim a group reaches is refused by the group rule, not the gate.
func TestRevokeProtectedGroupMember(t *testing.T) {
	const viaGroup = "  - {group: team, servers: [web-1, web-2]}\n"
	const team = "groups:\n  - {name: team, members: [ci]}\n"
	t.Run("refused without --operator", func(t *testing.T) {
		_, kh, cfg := protectedFleetManifest(t, "", viaGroup, team)
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "ci", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
			!strings.Contains(errBuf.String(), "ci is protected; pass --operator to confirm") {
			t.Fatalf("exit = %d, stderr = %q", code, errBuf.String())
		}
		if !bytes.Equal(fileBytes(t, cfg), before) {
			t.Error("the manifest changed")
		}
	})
	t.Run("dropped from the group with --operator", func(t *testing.T) {
		_, kh, cfg := protectedFleetManifest(t, "", viaGroup, team)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "ci", "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		if got := readCfg(t, cfg).Groups[0].Members; len(got) != 0 {
			t.Errorf("members = %v", got)
		}
	})
	t.Run("a trim a group reaches is the group refusal", func(t *testing.T) {
		_, kh, cfg := protectedFleetManifest(t, "", viaGroup, team)
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "ci", "--from-server", "web-1", "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
			!strings.Contains(errBuf.String(), "ci's access to web-1 comes from group team") {
			t.Fatalf("exit = %d, stderr = %q", code, errBuf.String())
		}
	})
}

// TestRevokeProtectedFromServer pins D21a: a protected non-operator can be
// trimmed with --operator and follows the normal tombstone rules; an operator
// stays refused; a D1c no-op needs no acknowledgement, though --operator still
// needs a protected target among the named users.
func TestRevokeProtectedFromServer(t *testing.T) {
	trim := func(t *testing.T, cfg, kh string, extra ...string) (int, string, string) {
		t.Helper()
		var out, errBuf bytes.Buffer
		args := append([]string{"revoke", "ci", "--from-server", "web-1", "--yes", "--config", cfg, "--known-hosts", kh}, extra...)
		code := run(args, &out, &errBuf)
		return code, out.String(), errBuf.String()
	}
	t.Run("a literal grant gets a tombstone", func(t *testing.T) {
		hosts, kh, cfg := protectedFleetManifest(t, "", ciByName, "")
		code, out, stderr := trim(t, cfg, kh, "--operator")
		if code != 0 || !strings.Contains(out, "PROTECTED: ci is protected; --operator given") {
			t.Fatalf("exit = %d\n%s\n%s", code, out, stderr)
		}
		saved := readCfg(t, cfg)
		if _, ok := saved.AccessRevoked("ci", "web-1"); !ok || !saved.Users[1].Protected || !saved.Covers("ci", "web-2") {
			t.Errorf("saved:\n%s", fileBytes(t, cfg))
		}
		blob := strings.Fields(testkeys.Line(t, 2))[1]
		if strings.Contains(hosts["web-1"].keys(t), blob) || !strings.Contains(hosts["web-2"].keys(t), blob) {
			t.Errorf("web-1:\n%s\nweb-2:\n%s", hosts["web-1"].keys(t), hosts["web-2"].keys(t))
		}
	})
	t.Run("a selector grant gets except and the plan warns", func(t *testing.T) {
		_, kh, cfg := protectedFleetManifest(t, "", `  - {user: ci, servers: ["*"]}`+"\n", "")
		code, out, stderr := trim(t, cfg, kh, "--operator")
		if code != 0 || !strings.Contains(out, `removes protected key of "ci" (its except: excludes this server)`) {
			t.Fatalf("exit = %d\n%s\n%s", code, out, stderr)
		}
		saved := readCfg(t, cfg)
		if _, ok := saved.AccessRevoked("ci", "web-1"); ok || !saved.ExceptCarveOut("ci", "web-1") {
			t.Errorf("saved:\n%s", fileBytes(t, cfg))
		}
	})
	t.Run("--operator on a plain target is refused", func(t *testing.T) {
		_, kh, cfg := protectedFleetManifest(t, "", ciByName, "")
		var out, errBuf bytes.Buffer
		if code := run([]string{"revoke", "alice", "--from-server", "web-1", "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 3 ||
			!strings.Contains(errBuf.String(), "--operator given but no target is an operator; drop the flag") {
			t.Fatalf("exit = %d, stderr = %q", code, errBuf.String())
		}
	})
	t.Run("an operator stays refused, even with --operator", func(t *testing.T) {
		users := "  - {name: ops, operator: true, keys: [" + qk(t, 3) + "]}\n"
		_, kh, cfg := protectedFleetManifest(t, users, ciByName+"  - {user: ops, servers: [\"*\"], except: [web-2]}\n", "")
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		code := run([]string{"revoke", "ops", "--from-server", "web-1", "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
		for _, want := range []string{"ops is an operator: --from-server cannot trim it; remove the user with 'sshepherd revoke ops", "--operator', or edit its access by hand"} {
			if code != 3 || !strings.Contains(errBuf.String(), want) {
				t.Errorf("exit = %d, stderr = %q, want %q", code, errBuf.String(), want)
			}
		}
		if !bytes.Equal(fileBytes(t, cfg), before) {
			t.Error("the manifest changed")
		}
	})
	t.Run("trimming every server: the note's command carries --operator", func(t *testing.T) {
		_, kh, cfg := protectedFleetManifest(t, "", ciByName, "")
		code, out, stderr := trim(t, cfg, kh, "--operator", "--from-server", "web-2")
		if code != 0 || !strings.Contains(out, "note: ci has no access left — 'sshepherd revoke ci") || !strings.Contains(out, "--operator' removes the user") {
			t.Fatalf("exit = %d\n%s\n%s", code, out, stderr)
		}
	})
	const memo = "revoked:\n  - {user: ci, servers: [web-1], date: 2026-11-08}\n"
	bob := "  - {name: bob, keys: [" + qk(t, 3) + "]}\n"
	t.Run("a D1c no-op needs no acknowledgement", func(t *testing.T) {
		for _, flags := range [][]string{nil, {"--operator"}} {
			_, kh, cfg := protectedFleetManifest(t, "", "  - {user: ci, servers: [web-2]}\n", memo)
			before := fileBytes(t, cfg)
			code, out, stderr := trim(t, cfg, kh, flags...)
			if code != 0 || !strings.Contains(out, "already revoked") || !bytes.Equal(fileBytes(t, cfg), before) {
				t.Errorf("flags %v: exit = %d\n%s\n%s", flags, code, out, stderr)
			}
		}
	})
	t.Run("--operator on a plain target's D1c no-op is refused", func(t *testing.T) {
		_, kh, cfg := protectedFleetManifest(t, bob, "  - {user: bob, servers: [web-2]}\n", "revoked:\n  - {user: bob, servers: [web-1], date: 2026-11-08}\n")
		before := fileBytes(t, cfg)
		var out, errBuf bytes.Buffer
		code := run([]string{"revoke", "bob", "--from-server", "web-1", "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
		if code != 3 || !strings.Contains(errBuf.String(), "--operator given but no target is an operator; drop the flag") || !bytes.Equal(fileBytes(t, cfg), before) {
			t.Fatalf("exit = %d, stderr = %q", code, errBuf.String())
		}
	})
	t.Run("a named protected target satisfies --operator though its pair is a no-op", func(t *testing.T) {
		_, kh, cfg := protectedFleetManifest(t, bob, "  - {user: ci, servers: [web-2]}\n  - {user: bob, servers: [web-1]}\n", memo)
		var out, errBuf bytes.Buffer
		code := run([]string{"revoke", "ci", "bob", "--from-server", "web-1", "--operator", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
		if code != 0 || !strings.Contains(out.String(), "already revoked") || strings.Contains(out.String(), "PROTECTED:") {
			t.Fatalf("exit = %d\n%s\n%s", code, out.String(), errBuf.String())
		}
		if readCfg(t, cfg).Covers("bob", "web-1") {
			t.Errorf("bob was not trimmed:\n%s", fileBytes(t, cfg))
		}
	})
}
