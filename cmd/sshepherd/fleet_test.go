package main

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/clog"
)

// TestConnFlagsRegister: one registration gives every connecting command the
// same names and defaults, and each command keeps its own --parallel wording
// (the help goldens pin the rest).
func TestConnFlagsRegister(t *testing.T) {
	var f connFlags
	cmd := &cobra.Command{Use: "x"}
	f.register(cmd, "max concurrent server audits")
	for name, def := range map[string]string{
		"config": "sshepherd.yaml", "known-hosts": "~/.ssh/known_hosts", "parallel": "32",
		"identity": "[]", "identity-passphrase-file": "", "identity-passphrase": "[]",
	} {
		fl := cmd.Flags().Lookup(name)
		if fl == nil || fl.DefValue != def {
			t.Errorf("--%s = %+v, want default %q", name, fl, def)
		}
	}
	if u := cmd.Flags().Lookup("parallel").Usage; u != "max concurrent server audits" {
		t.Errorf("--parallel usage = %q", u)
	}
	if defaultConfigPath != "sshepherd.yaml" {
		t.Errorf("defaultConfigPath = %q", defaultConfigPath)
	}
}

// TestFollowUp: hints carry only flags the run set to non-defaults, quoted
// like hintArg; identity passphrases appear as file paths only.
func TestFollowUp(t *testing.T) {
	def := connFlags{cfgPath: defaultConfigPath, knownHosts: defaultKnownHosts}
	all := connFlags{cfgPath: "my fleet.yaml", knownHosts: "/tmp/kh", idf: identityFlags{
		paths: []string{"~/.ssh/ci"}, defaultFile: "/run/pp", perKey: []string{"/k/a=/k/a.pass"}}}
	for _, tt := range []struct {
		name string
		f    connFlags
		want string
	}{
		{"defaults", def, "sshepherd apply --server web-1"},
		{"all", all, "sshepherd apply --config 'my fleet.yaml' --known-hosts /tmp/kh --identity '~/.ssh/ci' " +
			"--identity-passphrase-file /run/pp --identity-passphrase /k/a=/k/a.pass --server web-1"},
	} {
		if got := tt.f.followUp().command("apply", nil, "--server web-1"); got != tt.want {
			t.Errorf("%s:\n got %q\nwant %q", tt.name, got, tt.want)
		}
	}
	if got := def.followUp().suffix(); got != "" {
		t.Errorf("default suffix = %q, want empty", got)
	}
	if got, want := all.followUp().suffix(), " --config 'my fleet.yaml' --known-hosts /tmp/kh --identity '~/.ssh/ci' "+
		"--identity-passphrase-file /run/pp --identity-passphrase /k/a=/k/a.pass"; got != want {
		t.Errorf("suffix:\n got %q\nwant %q", got, want)
	}
}

func TestLogManifestPluralized(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(clog.NewHandler(&buf, clog.Options{Level: slog.LevelInfo}))
	cfg := readCfg(t, writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"))
	logManifest(log, cfg)
	if want := "• loaded manifest: 1 user, 1 server\n"; buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}

// TestOpenFleetKnownHostsFirst: a bad known_hosts fails before any key file
// is read, so a typo never costs a passphrase prompt.
func TestOpenFleetKnownHostsFirst(t *testing.T) {
	usePrompter(t, neverPrompt(t))
	cf := connFlags{knownHosts: filepath.Join(t.TempDir(), "missing"), parallel: 1,
		idf: identityFlags{paths: []string{encryptedKey(t, 1)}}}
	ids, err := cf.validate()
	if err != nil {
		t.Fatal(err)
	}
	_, err = openFleet(context.Background(), slog.New(slog.DiscardHandler), &cf, ids, false)
	if err == nil || !strings.HasPrefix(err.Error(), "known_hosts preflight:") {
		t.Fatalf("err = %v, want the known_hosts preflight", err)
	}
}

// TestFleetSessionRead: the phase line (pluralized), the done line, and the
// interrupt check all live in Read.
func TestFleetSessionRead(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	path := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	cfg := readCfg(t, path)
	var buf bytes.Buffer
	log := slog.New(clog.NewHandler(&buf, clog.Options{Level: slog.LevelInfo}))
	cf := connFlags{knownHosts: kh, parallel: 4}
	ids, _ := cf.validate()
	s, err := openFleet(context.Background(), log, &cf, ids, false)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.Read(context.Background(), "auditing", cfg, cfg.Servers, nil)
	if err != nil || len(res) != 1 || res[0].Err != nil {
		t.Fatalf("Read = %+v, %v", res, err)
	}
	for _, want := range []string{"auditing 1 server (parallelism 4)…", "1 read, 0 unreachable"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, buf.String())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Read(ctx, "auditing", cfg, cfg.Servers, nil); err == nil || !strings.HasPrefix(err.Error(), "interrupted:") {
		t.Errorf("canceled Read err = %v, want interrupted", err)
	}
}
