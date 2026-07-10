package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeReader returns canned authorized_keys content per server name.
type fakeReader struct {
	byName map[string]audit.ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (audit.ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return audit.ReadResult{}, err
	}
	return f.byName[srv.Name], nil
}

// adoptPlan runs the real pipeline (audit.Run + adopt.Build) over a fake
// fleet — exactly what the command does, minus SSH.
func adoptPlan(t *testing.T, cfg *config.Config, r audit.KeyReader) adopt.Plan {
	t.Helper()
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 4})
	return adopt.Build(cfg, results)
}

// mixedCfg exercises every attribution path at once: an operator, a user to
// extend (alice), a wildcard-except user (bob), a fleet-wide stranger
// (compacts), and an anonymous stranger.
func mixedCfg(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(mixedCfgYAML(t)))
	if err != nil {
		t.Fatalf("test config: %v", err)
	}
	return cfg
}

func mixedCfgYAML(t *testing.T) string {
	t.Helper()
	return `
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, description: hand-written, keys: ["` + testkeys.Line(t, 2) + `", "` + testkeys.Line(t, 3) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: db-1, host: 10.0.0.3, port: 2222, user: deploy, description: primary db}
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: ["*"], except: [db-1]}
`
}

func mixedReader(t *testing.T) *fakeReader {
	t.Helper()
	op, al := testkeys.Line(t, 1), testkeys.Line(t, 2)
	bo := testkeys.Line(t, 4)
	carol := testkeys.Line(t, 7) + " carol@laptop"
	anon := testkeys.Line(t, 8)
	return &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n" + bo + "\n" + carol + "\n" + anon + "\n")},
		"web-1": {Content: []byte(op + "\n" + al + "\n" + carol + "\n")},
		"web-2": {Content: []byte(op + "\n" + al + "\n" + carol + "\n")},
	}}
}

func TestGenerateAdoptManifestMixedGolden(t *testing.T) {
	cfg := mixedCfg(t)
	plan := adoptPlan(t, cfg, mixedReader(t))
	got, err := generateAdoptManifest(cfg, plan, "sshepherd.yaml", nil)
	if err != nil {
		t.Fatalf("generateAdoptManifest: %v", err)
	}
	c, err := config.Parse(got)
	if err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	// web-2 desired: op(1) + bob wildcard(1) + alice extension(2) + carol(1) = 5.
	if n := len(c.DesiredFor("web-2")); n != 5 {
		t.Errorf("DesiredFor(web-2) = %d keys, want 5", n)
	}
	// db-1 desired: op(1) + carol wildcard(1) + adopted-key-1(1) = 3
	// (bob stays excepted; alice's extension is web-2 only).
	if n := len(c.DesiredFor("db-1")); n != 3 {
		t.Errorf("DesiredFor(db-1) = %d keys, want 3", n)
	}
	// bob's carve-out and carol's compaction each warn.
	if len(plan.Warnings) != 2 {
		t.Errorf("Warnings = %v, want two (except carve-out + wildcard note)", plan.Warnings)
	}
	checkGolden(t, "adopt_mixed.golden", got)
}

func TestGenerateAdoptManifestNoopGolden(t *testing.T) {
	cfg := mixedCfg(t)
	op, al := testkeys.Line(t, 1), testkeys.Line(t, 2)
	al2, bo := testkeys.Line(t, 3), testkeys.Line(t, 4)
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"db-1":  {Content: []byte(op + "\n")},
		"web-1": {Content: []byte(op + "\n" + al + "\n" + al2 + "\n" + bo + "\n")},
		"web-2": {Content: []byte(op + "\n" + bo + "\n")},
	}}
	plan := adoptPlan(t, cfg, r)
	if len(plan.NewUsers)+len(plan.Extensions) != 0 {
		t.Fatalf("plan = %+v, want nothing to adopt", plan)
	}
	got, err := generateAdoptManifest(cfg, plan, "sshepherd.yaml", nil)
	if err != nil {
		t.Fatalf("generateAdoptManifest: %v", err)
	}
	if _, err := config.Parse(got); err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	// Content-identical re-render: port 2222 kept, port 22 omitted, alice's
	// and db-1's descriptions and bob's except preserved.
	for _, want := range []string{"port: 2222", "description: hand-written", "description: primary db", "except:"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	checkGolden(t, "adopt_noop.golden", got)
}

func TestGenerateAdoptManifestPartialGolden(t *testing.T) {
	cfg := mixedCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@laptop"
	r := &fakeReader{
		byName: map[string]audit.ReadResult{
			"web-1": {Content: []byte(op + "\n" + stranger + "\n")},
			"web-2": {Content: []byte(op + "\n")},
		},
		errs: map[string]error{"db-1": errors.New("dial tcp 10.0.0.3:2222: connection refused")},
	}
	plan := adoptPlan(t, cfg, r)
	got, err := generateAdoptManifest(cfg, plan, "sshepherd.yaml", plan.UnreadableServers())
	if err != nil {
		t.Fatalf("generateAdoptManifest: %v", err)
	}
	if !strings.Contains(string(got), "# WARNING: server db-1 unreadable — its access is NOT represented") {
		t.Errorf("output lacks the unreadable-server comment block:\n%s", got)
	}
	if _, err := config.Parse(got); err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	checkGolden(t, "adopt_partial.golden", got)
}

func TestAdoptMissingConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", "no-such-file.yaml"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2 (stderr: %s)", code, errBuf.String())
	}
}

func TestAdoptInvalidParallel(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path, "--parallel", "0"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestAdoptNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path}, &out, &errBuf); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr = %q, want agent guidance", errBuf.String())
	}
}

// An empty fleet needs no agent and emits a valid manifest with a note.
func TestAdoptEmptyFleet(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if _, err := config.Parse(out.Bytes()); err != nil {
		t.Errorf("stdout is not a valid manifest: %v", err)
	}
	if !strings.HasPrefix(out.String(), "# generated by sshepherd adopt from "+path) {
		t.Errorf("stdout = %q, want the adopt header", out.String())
	}
	if !strings.Contains(errBuf.String(), "nothing to adopt") {
		t.Errorf("stderr = %q, want a nothing-to-adopt note", errBuf.String())
	}
}

func TestAdoptOutputFileNoClobber(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	src := writeConfig(t, "")
	dst := filepath.Join(t.TempDir(), "adopted.yaml")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", src, "-o", dst}, &out, &errBuf); code != 0 {
		t.Fatalf("first write: exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want empty when -o is used", out.String())
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("output file: %v", err)
	}
	errBuf.Reset()
	if code := run([]string{"adopt", "--config", src, "-o", dst}, &out, &errBuf); code != 2 {
		t.Fatalf("overwrite without --force: exit = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "--force") {
		t.Errorf("stderr = %q, want --force hint", errBuf.String())
	}
	if code := run([]string{"adopt", "--config", src, "-o", dst, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("overwrite with --force: exit = %d, want 0", code)
	}
}

// fakeAgent satisfies the agent preflight without a real ssh-agent: a real
// in-memory keyring holding one generated key, served over a unix socket.
// The socket lives in a short os.MkdirTemp dir, not t.TempDir(): this test's
// name would push the path past the ~104-byte unix sun_path limit on macOS.
func fakeAgent(t *testing.T) {
	t.Helper()
	keyring := agent.NewKeyring()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("keyring add: %v", err)
	}
	dir, err := os.MkdirTemp("", "sshep")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = agent.ServeAgent(keyring, c) // returns on client close (EOF)
				_ = c.Close()
			}()
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
}

// closedPort returns a localhost port that was just released, so dialing it
// fails fast with ECONNREFUSED.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

// The strict gate: an unreachable server aborts with exit 1 and no output;
// --partial proceeds and marks the gap in the manifest itself.
func TestAdoptUnreachableStrictGateAndPartial(t *testing.T) {
	fakeAgent(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: `+strconv.Itoa(closedPort(t))+`, user: deploy}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"adopt", "--config", path, "--known-hosts", kh}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want no output under the strict gate", out.String())
	}
	if !strings.Contains(errBuf.String(), "--partial") || !strings.Contains(errBuf.String(), "web-1") {
		t.Errorf("stderr = %q, want the per-server error and a --partial hint", errBuf.String())
	}

	out.Reset()
	errBuf.Reset()
	code = run([]string{"adopt", "--config", path, "--known-hosts", kh, "--partial"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("--partial exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "# WARNING: server web-1 unreadable") {
		t.Errorf("stdout = %q, want the unreadable-server comment", out.String())
	}
	if _, err := config.Parse(out.Bytes()); err != nil {
		t.Errorf("stdout is not a valid manifest: %v", err)
	}
	// The nothing-to-adopt note must not read as "the whole fleet is clean"
	// when a server went unread.
	if !strings.Contains(errBuf.String(), "on the readable servers") {
		t.Errorf("stderr = %q, want the nothing-to-adopt note qualified for the unread server", errBuf.String())
	}
}
