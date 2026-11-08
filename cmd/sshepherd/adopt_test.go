package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/clog"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestQuickStartBootstrap is README's Quick start step 1, end to end:
// import --servers-only writes a servers-only manifest from the ssh
// config, adopt --merge adds every installed key to that same file, and
// the audit of the result is clean.
func TestQuickStartBootstrap(t *testing.T) {
	hermeticHome(t)
	srv, hostKey, _ := hermeticFleet(t, shortHome(t))
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	sshCfg := writeSSHConfig(t, "Host web-1\n  HostName 127.0.0.1\n  Port "+strconv.Itoa(srv.Port)+"\n  User deploy\n")
	m := filepath.Join(t.TempDir(), "sshepherd.yaml")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", sshCfg, "--servers-only", "-o", m}, &out, &errBuf); code != 0 {
		t.Fatalf("import exit = %d\n%s", code, errBuf.String())
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"adopt", "--merge", "--config", m, "-o", m, "--force", "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("adopt --merge exit = %d\n%s", code, errBuf.String())
	}
	if cfg := readCfg(t, m); len(cfg.Users) != 1 || len(cfg.Servers) != 1 || len(cfg.Access) != 1 {
		t.Errorf("bootstrapped manifest = %+v, want one adopted user granted web-1", cfg)
	}
	out.Reset()
	errBuf.Reset()
	if code := run([]string{"audit", "--config", m, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("audit exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
}

// fakeReader returns canned authorized_keys content per server name.
type fakeReader struct {
	byName map[string]fleet.ReadResult
	errs   map[string]error
}

func (f *fakeReader) ReadAuthorizedKeys(_ context.Context, srv config.Server) (fleet.ReadResult, error) {
	if err, ok := f.errs[srv.Name]; ok {
		return fleet.ReadResult{}, err
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
	return &fakeReader{byName: map[string]fleet.ReadResult{
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
	// db-1 desired: op(1) + carol(1) + adopted-key-1(1) = 3
	// (bob stays excepted; alice's extension is web-2 only).
	if n := len(c.DesiredFor("db-1")); n != 3 {
		t.Errorf("DesiredFor(db-1) = %d keys, want 3", n)
	}
	// bob's carve-out warns; carol is listed by name (D5), with no warning.
	if len(plan.Warnings) != 1 {
		t.Errorf("Warnings = %v, want one (except carve-out)", plan.Warnings)
	}
	checkGolden(t, "adopt_mixed.golden", got)
}

// TestAdoptNeverCopiesHeaderSerial: servers whose files claim "(serial 99)"
// never move the manifest's serial: regenerate emits the loaded manifest's
// value (7), or no serial: at all when it had none. A regression pin — it
// passes at once (adopt reads no header today) and guards the threat note;
// mutation: emit Serial: 99 in generateAdoptManifest → FAIL.
func TestAdoptNeverCopiesHeaderSerial(t *testing.T) {
	// The literal header line: lane header's authkeys.Header lands in the
	// same round, so this lane cannot call it.
	const claims = "# Managed by SSHepherd (serial 99). Manual edits will be overwritten by 'sshepherd apply'."
	r := mixedReader(t)
	for name, res := range r.byName {
		res.Content = append([]byte(claims+"\n"), res.Content...)
		r.byName[name] = res
	}
	for _, serial := range []uint64{7, 0} {
		cfg := mixedCfg(t)
		cfg.ManifestSerial = config.Serial(serial)
		out, err := generateAdoptManifest(cfg, adoptPlan(t, cfg, r), "sshepherd.yaml", nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := config.Parse(out)
		if err != nil {
			t.Fatalf("adopt output does not load: %v\n%s", err, out)
		}
		if got.Serial() != serial || (serial == 0 && strings.Contains(string(out), "serial:")) {
			t.Errorf("manifest serial %d: adopt emitted serial %d\n%s", serial, got.Serial(), out)
		}
	}
}

// TestAdoptMergeNoWildcard (D5): the merged manifest lists carol's three
// servers by name.
func TestAdoptMergeNoWildcard(t *testing.T) {
	src := commentedMergeSrc(t)
	mf, err := manifest.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := renderMergedManifest(mf, src, adoptPlan(t, mf.Config(), mixedReader(t)), nil, "2026-07-16")
	if err != nil {
		t.Fatal(err)
	}
	out, err := config.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range out.Access {
		if a.User == "carol-laptop" && !reflect.DeepEqual(a.Servers, []string{"db-1", "web-1", "web-2"}) {
			t.Errorf("carol-laptop servers = %v, want the three names", a.Servers)
		}
	}
}

func TestGenerateAdoptManifestNoopGolden(t *testing.T) {
	cfg := mixedCfg(t)
	op, al := testkeys.Line(t, 1), testkeys.Line(t, 2)
	al2, bo := testkeys.Line(t, 3), testkeys.Line(t, 4)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
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

// TestGenerateAdoptManifestRoundTripsAuthorizedKeysFile: adopt regenerates
// the full manifest from the loaded config — a server's
// authorized_keys_file override must survive into the output (and re-parse),
// or running adopt would silently strip every override.
func TestGenerateAdoptManifestRoundTripsAuthorizedKeysFile(t *testing.T) {
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy, authorized_keys_file: /etc/ssh/keys/deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("test config: %v", err)
	}
	al := testkeys.Line(t, 2)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(al + "\n")},
		"web-2": {Content: []byte(al + "\n")},
	}}
	got, err := generateAdoptManifest(cfg, adoptPlan(t, cfg, r), "sshepherd.yaml", nil)
	if err != nil {
		t.Fatalf("generateAdoptManifest: %v", err)
	}
	out, err := config.Parse(got)
	if err != nil {
		t.Fatalf("generated manifest rejected by config.Parse: %v", err)
	}
	if p := out.Servers[0].AuthorizedKeysFile; p != "/etc/ssh/keys/deploy" {
		t.Errorf("web-1 authorized_keys_file = %q after round-trip, want /etc/ssh/keys/deploy:\n%s", p, got)
	}
	if p := out.Servers[1].AuthorizedKeysFile; p != "" {
		t.Errorf("web-2 authorized_keys_file = %q, want empty (omitempty must keep unset fields out):\n%s", p, got)
	}
	if strings.Count(string(got), "authorized_keys_file") != 1 {
		t.Errorf("authorized_keys_file must appear exactly once in the output:\n%s", got)
	}
}

func TestGenerateAdoptManifestPartialGolden(t *testing.T) {
	cfg := mixedCfg(t)
	op := testkeys.Line(t, 1)
	stranger := testkeys.Line(t, 7) + " carol@laptop"
	r := &fakeReader{
		byName: map[string]fleet.ReadResult{
			"web-1": {Content: []byte(op + "\n" + stranger + "\n")},
			"web-2": {Content: []byte(op + "\n")},
		},
		errs: map[string]error{"db-1": errors.New("dial tcp 10.0.0.3:2222: connection refused")},
	}
	plan := adoptPlan(t, cfg, r)
	got, err := generateAdoptManifest(cfg, plan, "sshepherd.yaml", gapNotes(plan.UnreadableServers(), nil))
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

// commentedMergeSrc mirrors mixedCfgYAML semantically (so mixedReader
// exercises every attribution path) but is written the way an operator
// would: with comments that a merge must carry through.
func commentedMergeSrc(t *testing.T) []byte {
	t.Helper()
	return []byte(`# fleet manifest — hand-maintained; comments must survive a merge
users:
  # op holds the break-glass key
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, description: hand-written, keys: ["` + testkeys.Line(t, 2) + `", "` + testkeys.Line(t, 3) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 4) + `"]} # wildcard user, except db-1
servers:
  - {name: db-1, host: 10.0.0.3, port: 2222, user: deploy, description: primary db}
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: bob, servers: ["*"], except: [db-1]}
# reviewed 2026-07-01
`)
}

// TestRenderMergedManifestGolden: --merge rendering keeps the original text
// (comments intact, no regenerated header) and appends the plan under a
// dated merge marker; the date is injected so the golden is deterministic.
func TestRenderMergedManifestGolden(t *testing.T) {
	src := commentedMergeSrc(t)
	mf, err := manifest.Load(src)
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	cfg := mf.Config()
	plan := adoptPlan(t, cfg, mixedReader(t))
	got, err := renderMergedManifest(mf, src, plan, gapNotes([]string{"db-9"}, nil), "2026-07-16")
	if err != nil {
		t.Fatalf("renderMergedManifest: %v", err)
	}
	for _, want := range []string{
		"# fleet manifest — hand-maintained; comments must survive a merge",
		"# op holds the break-glass key",
		"# wildcard user, except db-1",
		"# reviewed 2026-07-01",
		"# merged by sshepherd adopt on 2026-07-16",
		"# WARNING: server db-9 unreadable — its access is NOT represented",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("merged output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(string(got), "generated by sshepherd adopt") {
		t.Errorf("merge must not stack a regenerated header:\n%s", got)
	}
	out, err := config.Parse(got)
	if err != nil {
		t.Fatalf("merged manifest rejected by config.Parse: %v", err)
	}
	// Same desired sets as the regenerate-mode mixed golden: web-2 gets
	// op + bob(wildcard grant) + alice(extension, 2 keys) + carol (listed by name); db-1 keeps
	// bob's carve-out.
	if n := len(out.DesiredFor("web-2")); n != 5 {
		t.Errorf("DesiredFor(web-2) = %d keys, want 5", n)
	}
	if n := len(out.DesiredFor("db-1")); n != 3 {
		t.Errorf("DesiredFor(db-1) = %d keys, want 3", n)
	}
	checkGolden(t, "adopt_merge.golden", got)
}

// TestAdoptMergeNothingToAdopt: an empty plan under --merge emits the input
// byte-identical (comments, quirks and all) and keeps the existing
// nothing-to-adopt logging contract.
func TestAdoptMergeNothingToAdopt(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeEmptyFleetManifest(t)
	orig, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--merge", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !bytes.Equal(out.Bytes(), orig) {
		t.Errorf("--merge with nothing to adopt must be byte-identical:\n--- got ---\n%s\n--- want ---\n%s", out.Bytes(), orig)
	}
	if !strings.Contains(errBuf.String(), "nothing to adopt") {
		t.Errorf("stderr = %q, want a nothing-to-adopt note", errBuf.String())
	}
	if strings.Contains(errBuf.String(), "adopting") {
		t.Errorf("stderr = %q, nothing-to-adopt path must not emit the adopting summary", errBuf.String())
	}
}

func TestAdoptMissingConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", "no-such-file.yaml"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
}

func TestAdoptInvalidParallel(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path, "--parallel", "0"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestAdoptNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path, "--known-hosts", emptyKnownHosts(t)}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr = %q, want agent guidance", errBuf.String())
	}
}

// writeEmptyFleetManifest writes a manifest with a user but no servers, so
// adopt has nothing to read and nothing to adopt.
func writeEmptyFleetManifest(t *testing.T) string {
	t.Helper()
	return writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
}

// TestAdoptLogsManifestWarnings: the multi-key comment warning must reach
// stderr on adopt too, not just audit — both commands load the manifest.
func TestAdoptLogsManifestWarnings(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - name: alice
    comment: "alice — platform team"
    keys: ["`+testkeys.Line(t, 1)+`", "`+testkeys.Line(t, 2)+`"]
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "comment is set on a user with 2 keys") {
		t.Errorf("stderr = %q, want the multi-key comment warning", errBuf.String())
	}
}

// An empty fleet needs no agent and emits a valid manifest with a note.
func TestAdoptEmptyFleet(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeEmptyFleetManifest(t)
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
	if strings.Contains(errBuf.String(), "adopting") {
		t.Errorf("stderr = %q, nothing-to-adopt path must not emit the adopting summary", errBuf.String())
	}
}

// TestAdoptQuietKeepsProduct: -q silences the nothing-to-adopt note but the
// manifest still lands on stdout.
func TestAdoptQuietKeepsProduct(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeEmptyFleetManifest(t) // reuse however TestAdoptEmptyFleet builds its manifest
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "-q", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty under -q", errBuf.String())
	}
	if !strings.Contains(out.String(), "generated by sshepherd adopt") {
		t.Errorf("stdout = %q, the manifest must survive -q", out.String())
	}
}

// TestReportPlanPositiveOutcome pins the adopting-summary line and its
// mutual exclusion with the nothing-to-adopt note.
func TestReportPlanPositiveOutcome(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(clog.NewHandler(&buf, clog.Options{Level: slog.LevelInfo}))
	reportPlan(log, adopt.Plan{NewUsers: []adopt.NewUser{{Name: "u1"}}}, nil)
	got := buf.String()
	if !strings.Contains(got, "adopting 1 new user, 0 access extensions") {
		t.Errorf("log = %q, want the adopting summary", got)
	}
	if strings.Contains(got, "nothing to adopt") {
		t.Errorf("log = %q, positive path must not emit the nothing-to-adopt note", got)
	}
}

// TestReportUnreadable pins reportUnreadable's whole output, line for line:
// every per-server issue line first, then each distinct hint once in
// first-seen order, then the strict verdict; no hint line for an issue
// without a remediation; and, in strict mode, every line at error level so
// the hint survives -q.
func TestReportUnreadable(t *testing.T) {
	const (
		dial    = "check the host, port, and firewall"
		hostkey = "add the host key to known_hosts"
		ignored = `key SHA256:z/fSv0Z0RZS+Lccbc6ZoOWwt/fbj1VFJGSBKQbo4icE: sshd ignores this line: option "no-ptty" is not a recognized authorized_keys option`
		verdict = " could not be fully read — nothing written; fix the errors above or re-run with --partial"
	)
	threeDown := adopt.Plan{Issues: []adopt.Issue{
		{Server: "web-1", Detail: "dial: connection refused", Hint: dial},
		{Server: "web-2", Detail: "host key unknown", Hint: hostkey},
		{Server: "web-3", Detail: "dial: connection refused", Hint: dial},
	}}
	tests := []struct {
		name       string
		plan       adopt.Plan
		unreadable []string
		partial    bool
		level      slog.Level
		want       []string
		wantErr    bool
	}{
		{
			name:       "strict: issues, then distinct hints in order, then verdict",
			plan:       threeDown,
			unreadable: []string{"web-1", "web-2", "web-3"},
			level:      slog.LevelInfo,
			want: []string{
				"error: server web-1: dial: connection refused",
				"error: server web-2: host key unknown",
				"error: server web-3: dial: connection refused",
				"error: hint: " + dial,
				"error: hint: " + hostkey,
				"error: 3 servers" + verdict,
			},
			wantErr: true,
		},
		{
			name:       "strict under -q: every line survives, the hint included",
			plan:       threeDown,
			unreadable: []string{"web-1", "web-2", "web-3"},
			level:      slog.LevelError,
			want: []string{
				"error: server web-1: dial: connection refused",
				"error: server web-2: host key unknown",
				"error: server web-3: dial: connection refused",
				"error: hint: " + dial,
				"error: hint: " + hostkey,
				"error: 3 servers" + verdict,
			},
			wantErr: true,
		},
		{
			name:       "partial: same order at warn level, no verdict",
			plan:       threeDown,
			unreadable: []string{"web-1", "web-2", "web-3"},
			partial:    true,
			level:      slog.LevelInfo,
			want: []string{
				"warn: server web-1: dial: connection refused",
				"warn: server web-2: host key unknown",
				"warn: server web-3: dial: connection refused",
				"warn: hint: " + dial,
				"warn: hint: " + hostkey,
			},
		},
		{
			// The README console sample for a line sshd would ignore: the
			// issue has no remediation, so no hint: line at all.
			name:       "hintless issue prints no hint line (README sample)",
			plan:       adopt.Plan{Issues: []adopt.Issue{{Server: "web-1", Detail: ignored}}},
			unreadable: []string{"web-1"},
			level:      slog.LevelInfo,
			want: []string{
				"error: server web-1: " + ignored,
				"error: 1 server" + verdict,
			},
			wantErr: true,
		},
		{
			name:  "nothing unreadable prints nothing",
			plan:  adopt.Plan{},
			level: slog.LevelInfo,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			log := slog.New(clog.NewHandler(&buf, clog.Options{Level: tt.level}))
			err := reportUnreadable(log, tt.plan, tt.unreadable, tt.partial)
			if tt.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, errFleetUnreadable) {
				t.Errorf("err = %v, want errFleetUnreadable", err)
			}
			want := ""
			if len(tt.want) > 0 {
				want = strings.Join(tt.want, "\n") + "\n"
			}
			if got := buf.String(); got != want {
				t.Errorf("output mismatch\ngot:\n%s\nwant:\n%s", got, want)
			}
		})
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
	if code := run([]string{"adopt", "--config", src, "-o", dst}, &out, &errBuf); code != 3 {
		t.Fatalf("overwrite without --force: exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "--force") {
		t.Errorf("stderr = %q, want --force hint", errBuf.String())
	}
	if code := run([]string{"adopt", "--config", src, "-o", dst, "--force"}, &out, &errBuf); code != 0 {
		t.Fatalf("overwrite with --force: exit = %d, want 0", code)
	}
}

// TestAdoptInPlaceKeepsConcurrentRevoke: adopt regenerating its own
// --config in place. An empty fleet needs no SSH; the generated header makes
// the bytes differ, so Save runs and the seam can race it: the concurrent
// revoke is kept and the run refuses (exit 3).
func TestAdoptInPlaceKeepsConcurrentRevoke(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	cfg := writeConfig(t, "users: []\nservers: []\naccess: []\n")
	revoked := []byte("users: []\nservers: []\naccess: []\n# revoked meanwhile\n")
	saved := beforeManifestSave
	beforeManifestSave = func(mt manifestTarget) {
		if err := os.WriteFile(mt.Resolved, revoked, 0o600); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { beforeManifestSave = saved })
	var out, errBuf bytes.Buffer
	code := run([]string{"adopt", "--config", cfg, "-o", cfg, "--force"}, &out, &errBuf)
	if code != 3 || !strings.Contains(errBuf.String(), "changed since it was read; re-run") {
		t.Fatalf("exit = %d, stderr = %q; want 3 and the changed-since-read refusal", code, errBuf.String())
	}
	if got, _ := os.ReadFile(cfg); !bytes.Equal(got, revoked) {
		t.Errorf("manifest = %q, want the concurrent revoke kept", got)
	}
}

// TestAdoptInPlaceAnySpelling: adopt -o naming its own --config under
// another spelling (relative against absolute, either way round) saves in
// place through the store instead of refusing it as a hard link.
func TestAdoptInPlaceAnySpelling(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	for _, tc := range []struct {
		name            string
		absConfig, absO bool
	}{
		{"relative --config, absolute -o", false, true},
		{"absolute --config, relative -o", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			abs, err := filepath.EvalSymlinks(writeConfig(t, "users: []\nservers: []\naccess: []\n"))
			if err != nil {
				t.Fatal(err)
			}
			t.Chdir(filepath.Dir(abs))
			spell := func(absolute bool) string {
				if absolute {
					return abs
				}
				return filepath.Base(abs)
			}
			var out, errBuf bytes.Buffer
			args := []string{"adopt", "--config", spell(tc.absConfig), "-o", spell(tc.absO), "--force"}
			if code := run(args, &out, &errBuf); code != 0 {
				t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
			}
			if _, err := os.Lstat(manifest.LockPath(abs)); err != nil {
				t.Errorf("lock sidecar missing: the in-place write did not go through the store (%v)", err)
			}
		})
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

// unreachableFleet builds the shared unreachable-server fixture: a manifest
// whose single server (web-1) points at a just-closed local port, a fake
// agent so the preflight passes, and an empty known_hosts file. Returns the
// manifest and known_hosts paths.
func unreachableFleet(t *testing.T) (cfgPath, khPath string) {
	t.Helper()
	fakeAgent(t)
	khPath = filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(khPath, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	cfgPath = writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: `+strconv.Itoa(closedPort(t))+`, user: deploy}
`)
	return cfgPath, khPath
}

// TestAdoptPartialPrintsHintOnce: two servers down for the same reason get
// one dial hint, not one per server, while each server still gets its own
// issue line (F-P07-1: the hint left Error() and must not vanish from adopt).
func TestAdoptPartialPrintsHintOnce(t *testing.T) {
	fakeAgent(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	path := writeConfig(t, `
servers:
  - {name: web-1, host: 127.0.0.1, port: `+strconv.Itoa(closedPort(t))+`, user: deploy}
  - {name: web-2, host: 127.0.0.1, port: `+strconv.Itoa(closedPort(t))+`, user: deploy}
`)
	var out, errBuf bytes.Buffer
	// Both down is a zero-read --partial run (exit 3), but the issue and hint
	// lines come first, before the refusal.
	if code := run([]string{"adopt", "--config", path, "--known-hosts", kh, "--partial"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 for a zero-read --partial run (stderr: %s)", code, errBuf.String())
	}
	stderr := errBuf.String()
	if n := strings.Count(stderr, "hint:"); n != 1 {
		t.Errorf("stderr has %d hint: lines, want exactly 1:\n%s", n, stderr)
	}
	if !strings.Contains(stderr, "hint: "+sshconn.DialHint) {
		t.Errorf("stderr = %q, want the dial hint", stderr)
	}
	for _, name := range []string{"web-1", "web-2"} {
		if !strings.Contains(stderr, "server "+name+":") {
			t.Errorf("stderr = %q, want the issue line for %s", stderr, name)
		}
	}
}

// The strict gate: an unreachable server aborts with exit 1 and no output;
// --partial proceeds and marks the gap in the manifest itself.
func TestAdoptUnreachableStrictGateAndPartial(t *testing.T) {
	path, kh := unreachableFleet(t)
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
	if !strings.Contains(errBuf.String(), "1 server could not be fully read — nothing written") {
		t.Errorf("stderr = %q, want the pluralized strict-gate count", errBuf.String())
	}

	// -q suppresses the phase narration but the per-issue ERRORs and the
	// strict abort must survive quiet mode.
	out.Reset()
	errBuf.Reset()
	code = run([]string{"adopt", "-q", "--config", path, "--known-hosts", kh}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("-q strict exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "web-1") {
		t.Errorf("stderr = %q, want the per-server error to survive -q", errBuf.String())
	}
	if strings.Contains(errBuf.String(), "reading") {
		t.Errorf("stderr = %q, phase lines must be suppressed under -q", errBuf.String())
	}
	// The remediation is an error line in strict mode precisely so it
	// survives -q (README: "error: in strict mode, so it survives -q").
	if !strings.Contains(errBuf.String(), "error: hint: "+sshconn.DialHint) {
		t.Errorf("stderr = %q, want the dial hint as an error: line under -q", errBuf.String())
	}

	// With its single server unreachable, --partial read nothing at all:
	// that is a refusal (exit 3, D8a), not an adopted fleet. The partial
	// manifest itself is covered by TestAdoptPartialSomeRead.
	out.Reset()
	errBuf.Reset()
	code = run([]string{"adopt", "--config", path, "--known-hosts", kh, "--partial"}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("--partial exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want no manifest when nothing was read", out.String())
	}
}

// adoptPartialExit is adopt --partial's exit code when some, but not all,
// servers were read: 1 like audit (D8 = yes), with the manifest written.
const adoptPartialExit = 1

// TestAdoptPartialNothingRead: every server unreadable — --partial refuses
// (exit 3, D8a) and nothing reaches stdout.
func TestAdoptPartialNothingRead(t *testing.T) {
	path, kh := unreachableFleet(t)
	var out, errBuf bytes.Buffer
	code := run([]string{"adopt", "--config", path, "--known-hosts", kh, "--partial"}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want no manifest when nothing was read", out.String())
	}
	if !strings.Contains(errBuf.String(), "read 0 of 1 server — nothing could be adopted") {
		t.Errorf("stderr = %q, want the zero-read refusal", errBuf.String())
	}
}

// TestAdoptPartialNothingReadWritesNoFile: the zero-read refusal comes
// before rendering, so -o is never created either.
func TestAdoptPartialNothingReadWritesNoFile(t *testing.T) {
	path, kh := unreachableFleet(t)
	dst := filepath.Join(t.TempDir(), "adopted.yaml")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", path, "--known-hosts", kh, "--partial", "-o", dst}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if _, err := os.Lstat(dst); err == nil {
		t.Errorf("%s was written although no server was read", dst)
	}
}

// TestAdoptPartialSomeRead: one of two read — the manifest is written with
// the gap marked, stderr says "read 1 of 2 servers", and the exit code says
// the result is incomplete (D8).
func TestAdoptPartialSomeRead(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"  - {name: web-2, host: 127.0.0.1, port: "+strconv.Itoa(closedPort(t))+", user: deploy}\naccess:\n  - {user: alice, servers: [web-1]}\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh, "--partial"}, &out, &errBuf)
	if code != adoptPartialExit {
		t.Fatalf("exit = %d, want %d (stderr: %s)", code, adoptPartialExit, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "read 1 of 2 servers — access on the others is NOT in the output") ||
		!strings.Contains(out.String(), "# WARNING: server web-2 unreadable") {
		t.Errorf("stderr = %q / stdout = %q, want the read count and the gap marker", errBuf.String(), out.String())
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

// TestGapNotes: an unreadable server is marked missing whole, a partly read
// one only for the lines adopt could not use; the order follows unreadable.
func TestGapNotes(t *testing.T) {
	results := []audit.ServerResult{
		{Server: config.Server{Name: "web-1"}},
		{Server: config.Server{Name: "db-1"}, Err: errors.New("dial: connection refused")},
	}
	unreadable := []string{"web-1", "db-1"}
	got := gapNotes(unreadable, partlyRead(unreadable, results))
	want := []string{
		"WARNING: server web-1 partly read — keys on lines adopt could not use are NOT represented",
		"WARNING: server db-1 unreadable — its access is NOT represented",
	}
	if !slices.Equal(got, want) {
		t.Errorf("gapNotes = %q, want %q", got, want)
	}
}

// TestAdoptPartialLineIssueOnly: a server read in full except one line adopt
// cannot use is partly read, not unreadable. --partial adopts its other keys
// and exits 0 (the server was read), and neither stderr nor the manifest
// calls it unreadable; both say the line's keys are not in the output.
func TestAdoptPartialLineIssueOnly(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1}, "ssh-ed25519 !!!notbase64 broken")
	cfg := writeConfig(t, "users: []\nservers:\n"+hosts["web-1"].line("web-1")+"access: []\n")
	var out, errBuf bytes.Buffer
	code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh, "--partial"}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "# WARNING: server web-1 partly read — keys on lines adopt could not use are NOT represented") ||
		strings.Contains(out.String(), "web-1 unreadable") {
		t.Errorf("stdout = %q, want the partly-read marker, not the unreadable one", out.String())
	}
	if !strings.Contains(errBuf.String(), "read 1 of 1 server — 1 server partly read: keys on lines adopt could not use are NOT in the output") {
		t.Errorf("stderr = %q, want the read count to flag the partly read server", errBuf.String())
	}
	if !strings.Contains(out.String(), strings.Fields(testkeys.Line(t, 1))[1]) {
		t.Errorf("stdout = %q, want the readable key adopted", out.String())
	}
}

// TestAdoptFullReadCount: a fully read fleet reports its read count at info
// and exits 0.
func TestAdoptFullReadCount(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	hosts["web-1"].install(t, []byte{1})
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\nservers:\n"+hosts["web-1"].line("web-1")+
		"access:\n  - {user: alice, servers: [web-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "read 1 of 1 server\n") {
		t.Errorf("stderr = %q, want the full read count", errBuf.String())
	}
}
