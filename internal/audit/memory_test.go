package audit

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// memoryConfig: serial 7; op (k1) operator; alice (k2) -> web-1, web-2;
// bob (k3) -> web-1 (an access tombstone removed his web-2); carol's key
// (k9) is revoked. extra is appended to revoked:.
func memoryConfig(t *testing.T, extra string) *config.Config {
	t.Helper()
	y := `serial: 7
users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: bob, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: [web-1]}
revoked:
  - {fingerprint: ` + fpOf(t, 9) + `, user: carol, date: 2026-11-08, reason: offboarded}
  - {user: bob, servers: [web-2], date: 2026-11-08}
` + extra
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("memoryConfig: %v", err)
	}
	return cfg
}

// (fpOf is internal/audit/audit_test.go's existing helper.)

// memFiles builds each server's content: a first line, then key lines.
func memFiles(t *testing.T, first string, web1, web2 []byte) *fakeReader {
	t.Helper()
	line := func(seeds []byte) string {
		s := first + "\n"
		for _, b := range seeds {
			s += testkeys.Line(t, b) + "\n"
		}
		return s
	}
	return &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(line(web1))},
		"web-2": {Content: []byte(line(web2))},
	}}
}

func memoryRun(t *testing.T, cfg *config.Config, r KeyReader) []ServerResult {
	t.Helper()
	return Run(context.Background(), cfg, r, Options{Parallel: 2})
}

func TestExitCodeRevokedKeyIsCritical(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3, 9}, []byte{1, 2}))
	if s := statusOf(cfg, res[0]); s != statusCritical {
		t.Errorf("web-1 status = %s, want critical", s)
	}
	if code := ExitCode(cfg, res); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
}

// TestStatusAccessTombstoneIsDrift is a regression pin: the key was already
// unauthorized drift before tombstones. Mutation that fails it: in
// criticalDrift's Unauthorized loop, test cfg.OwnerOf instead of cfg.Revoked.
func TestStatusAccessTombstoneIsDrift(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3}, []byte{1, 2, 3}))
	if s := statusOf(cfg, res[1]); s != statusDrift {
		t.Errorf("web-2 status = %s, want drift (D1d)", s)
	}
	if code := ExitCode(cfg, res); code != 1 {
		t.Errorf("ExitCode = %d, want 1", code)
	}
}

func TestStatusSerialAheadIsDrift(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(8), []byte{1, 2, 3}, []byte{1, 2}))
	if s := statusOf(cfg, res[0]); s != statusDrift {
		t.Errorf("key-compliant web-1 at serial 8 = %s, want drift (D4a)", s)
	}
	if code := ExitCode(cfg, res); code != 1 {
		t.Errorf("ExitCode = %d, want 1", code)
	}
}

func TestForgedSerialIsCritical(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7+authkeys.ForgedMargin+1), []byte{1, 2, 3}, []byte{1, 2}))
	if s := statusOf(cfg, res[0]); s != statusCritical {
		t.Errorf("forged header on a key-compliant server = %s, want critical", s)
	}
	if code := ExitCode(cfg, res); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
}

// TestOlderHeaderSerialIsCompliant is a regression pin: nothing read the
// header before this lane. Mutation that fails it: in serialAhead, compare
// r.HeaderSerial != m instead of r.HeaderSerial > m.
func TestOlderHeaderSerialIsCompliant(t *testing.T) {
	cfg := memoryConfig(t, "")
	for _, first := range []string{authkeys.Header(6), authkeys.ManagedHeader} {
		res := memoryRun(t, cfg, memFiles(t, first, []byte{1, 2, 3}, []byte{1, 2}))
		if code := ExitCode(cfg, res); code != 0 {
			t.Errorf("%q: ExitCode = %d, want 0 (an older header is not drift)", first, code)
		}
	}
}

func TestPolicyConflictIsCritical(t *testing.T) {
	cfg := memoryConfig(t, "  - {fingerprint: "+fpOf(t, 3)+", date: 2026-11-08}\n") // bob's key, still listed
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3}, []byte{1, 2}))
	if s := statusOf(cfg, res[0]); s != statusCritical {
		t.Errorf("web-1 (named by the conflict) = %s, want critical", s)
	}
	if s := statusOf(cfg, res[1]); s != statusCompliant {
		t.Errorf("web-2 = %s, want compliant", s)
	}
	if code := ExitCode(cfg, nil); code != 2 {
		t.Errorf("ExitCode with no servers read = %d, want 2 (a conflict pages on its own)", code)
	}
}

func TestRenderRevokedGolden(t *testing.T) {
	// alice's access to web-1 is tombstoned while her grant (web-1, web-2)
	// still names it: a revoked_access conflict whose Servers is the whole
	// grant (spec §2), so both servers carry the conflict line. Key 8 has an
	// unlabelled tombstone (spec §5: "(REVOKED 2026-11-08)") and sits on web-2.
	cfg := memoryConfig(t, "  - {user: alice, servers: [web-1], date: 2026-11-08}\n  - {fingerprint: "+fpOf(t, 8)+", date: 2026-11-08}\n")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(7), []byte{1, 2, 3, 9}, []byte{1, 2, 3, 8}))
	var b bytes.Buffer
	Render(&b, cfg, res, RenderOptions{})
	checkGolden(t, "report_revoked.golden", b.Bytes())
	for _, want := range []string{
		`‼ manifest: user "alice" is granted "web-1" by access[0], but revoked[2] removed that access (2026-11-08): remove the grant, or delete the revoked: entry to restore it deliberately (CRITICAL: policy conflict)` + "\n\n",
		"carol (REVOKED 2026-11-08)",
		"installed but REVOKED (CRITICAL: revoked key)\n",
		"bob (access revoked 2026-11-08)",
		"→ exit 2\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, b.String())
		}
	}
	if n := strings.Count(b.String(), "  ‼ named by a manifest policy conflict above (CRITICAL: policy conflict)\n"); n != 2 {
		t.Errorf("conflict lines = %d, want 2 (web-1 and web-2: the whole grant)", n)
	}
	// The unlabelled tombstone's row: the label cell is "(REVOKED DATE)" alone.
	if !regexp.MustCompile(`‼ +\(REVOKED 2026-11-08\) +` + regexp.QuoteMeta(fpOf(t, 8))).MatchString(b.String()) {
		t.Errorf("report lacks the unlabelled REVOKED row for key 8:\n%s", b.String())
	}
}

func TestRenderSerialAheadGolden(t *testing.T) {
	cfg := memoryConfig(t, "")
	res := memoryRun(t, cfg, memFiles(t, authkeys.Header(8), []byte{1, 2, 3}, []byte{1, 2}))
	res[1].HeaderSerial = 9999 // web-2: forged (the reader cannot vary per server here)
	var b bytes.Buffer
	Render(&b, cfg, res, RenderOptions{})
	checkGolden(t, "report_serial_ahead.golden", b.Bytes())
	for _, want := range []string{
		"  ⚠ written by newer manifest serial 8 (yours is 7): pull the latest manifest\n",
		"  ‼ header claims serial 9999, far above this manifest's 7 — someone edited this file (CRITICAL: forged header)\n",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, b.String())
		}
	}
}

func TestRenderEmptyFleetShowsConflicts(t *testing.T) {
	cfg, err := config.Parse([]byte("users:\n  - {name: a, keys: [\"" + testkeys.Line(t, 1) + "\"]}\nrevoked:\n  - {fingerprint: " + fpOf(t, 1) + ", date: 2026-11-08}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	Render(&b, cfg, nil, RenderOptions{})
	if !strings.HasPrefix(b.String(), "‼ manifest: key ") || !strings.HasSuffix(b.String(), "Summary: 0 servers configured — nothing to audit\n") {
		t.Errorf("report = %q", b.String())
	}
}
