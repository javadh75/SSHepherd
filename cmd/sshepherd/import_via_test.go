package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestImportMapsProxyJumpGolden: a two-hop ProxyJump chain becomes via:
// on the target and on the inner hop; the output loads.
func TestImportMapsProxyJumpGolden(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host bastion\n  HostName bastion.example.com\n  User jump\n"+
		"Host inner\n  HostName 10.0.0.9\n  User ops\n  ProxyJump bastion\n"+
		"Host web\n  HostName 10.0.1.5\n  User deploy\n  ProxyJump bastion,inner\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	got := strings.ReplaceAll(out.String(), path, "SSHCONFIG")
	checkGolden(t, "import_manifest_via.golden", []byte(got))
	cfg, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("output does not load: %v", err)
	}
	web, _ := cfg.ServerNamed("web")
	if chain := cfg.Chain(web); strings.Join(chain, ",") != "bastion,inner" {
		t.Errorf("Chain(web) = %v, want [bastion inner]", chain)
	}
}

// TestImportDropsSameIPBehindAnotherRoute: the same IP direct and behind a
// bastion keeps one entry, moves no grant, and the output loads (OP7).
func TestImportDropsSameIPBehindAnotherRoute(t *testing.T) {
	home := hermeticHome(t)
	keyPath := filepath.Join(home, "webb") // not a default identity: only web-b uses it
	if err := os.WriteFile(keyPath+".pub", []byte(testkeys.Line(t, 7)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := writeSSHConfig(t, "Host bastion\n  HostName bastion.example.com\n  User jump\n"+
		"Host web-a\n  HostName 10.0.0.5\n  User deploy\n"+
		"Host web-b\n  HostName 10.0.0.5\n  User deploy\n  ProxyJump bastion\n  IdentityFile "+keyPath+"\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), `server "web-b" in the ssh config has the same host, port and user as "web-a" but a different route — skipped, and its access is not moved to "web-a"`) {
		t.Errorf("stderr lacks the route warning: %s", errBuf.String())
	}
	cfg, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("output does not load: %v\n%s", err, out.String())
	}
	if len(cfg.Access) != 0 {
		t.Errorf("access = %+v, want none: web-b's grant must not move to web-a", cfg.Access)
	}
}

// TestImportHopOnDroppedHostNotMapped: a ProxyJump naming a host that was
// dropped as another route is not mapped (proxy_not_mapped), and the
// dependent stays direct (spec S5 Import).
func TestImportHopOnDroppedHostNotMapped(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host bastion\n  HostName bastion.example.com\n  User jump\n"+
		"Host web-a\n  HostName 10.0.0.5\n  User deploy\n"+
		"Host web-b\n  HostName 10.0.0.5\n  User deploy\n  ProxyJump bastion\n"+
		"Host app\n  HostName 10.0.1.7\n  User deploy\n  ProxyJump web-b\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if want := `host "app": ProxyJump web-b not mapped to via: (hop "web-b" is not a server in the ssh config or the manifest)`; !strings.Contains(errBuf.String(), want) {
		t.Errorf("stderr = %q, want %q", errBuf.String(), want)
	}
	cfg, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("output does not load: %v\n%s", err, out.String())
	}
	if app, ok := cfg.ServerNamed("app"); !ok || app.Via != "" {
		t.Errorf("app = %+v (found %v), want it present with no via", app, ok)
	}
}

// TestImportMergeRouteConflict (spec S5 Import, --merge): an incoming host
// at a manifest server's target by another route is a conflict whose
// grants are not moved; a user left with no servers gets no access entry;
// a new server behind a manifest bastion gets its via; the output loads.
func TestImportMergeRouteConflict(t *testing.T) {
	home := hermeticHome(t)
	keyPath := filepath.Join(home, "webb") // not a default identity: only web-b uses it
	if err := os.WriteFile(keyPath+".pub", []byte(testkeys.Line(t, 7)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n"+
		"servers:\n  - {name: web-a, host: 10.0.0.5, user: deploy}\n  - {name: bastion-eu, host: bastion.eu, user: jump, jump_only: true}\n"+
		"access:\n  - {user: alice, servers: [web-a]}\n")
	path := writeSSHConfig(t, "Host web-b\n  HostName 10.0.0.5\n  User deploy\n  ProxyJump bastion-eu\n  IdentityFile "+keyPath+"\n"+
		"Host app\n  HostName 10.0.1.7\n  User deploy\n  ProxyJump bastion-eu\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--merge", m}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if want := `server "web-b" in the ssh config has the same host, port and user as manifest server "web-a" but a different route — skipped, and its access is not moved to "web-a"`; !strings.Contains(errBuf.String(), want) {
		t.Errorf("stderr lacks %q:\n%s", want, errBuf.String())
	}
	cfg, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("output does not load: %v\n%s", err, out.String())
	}
	if len(cfg.Access) != 1 || cfg.Access[0].User != "alice" {
		t.Errorf("access = %+v, want alice's entry only: web-b's user has no server left", cfg.Access)
	}
	if app, ok := cfg.ServerNamed("app"); !ok || app.Via != "bastion-eu" {
		t.Errorf("app = %+v (found %v), want via: bastion-eu (renderMergedImport carries Via)", app, ok)
	}
	if strings.Contains(errBuf.String(), "not mapped to via") {
		t.Errorf("a hop naming a manifest server was flagged:\n%s", errBuf.String())
	}
}
