package config

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fpOfLine is the line's SHA256 fingerprint.
func fpOfLine(t *testing.T, line string) string {
	t.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("ParseLine: %v", err)
	}
	return k.Fingerprint
}

// policyManifest: user old holds line on a one-server fleet; grant, when
// set, is old's access entry.
func policyManifest(t *testing.T, line, grant string) string {
	t.Helper()
	return `users:
  - {name: old, keys: ["` + line + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
` + grant
}

const grantOld = "access:\n  - {user: old, servers: [web-1]}\n"

func TestWeakKeyGrantedIsAConflict(t *testing.T) {
	dsa := testkeys.DSALine(t, 1)
	fp := fpOfLine(t, dsa)
	cfg, err := Parse([]byte(policyManifest(t, dsa, grantOld)))
	if err != nil {
		t.Fatalf("a weak key must not be a load error: %v", err)
	}
	cs := cfg.Conflicts()
	if len(cs) != 1 || cs[0].Kind != ConflictWeakKey || cs[0].User != "old" || cs[0].Fingerprint != fp || !slices.Equal(cs[0].Servers, []string{"web-1"}) {
		t.Fatalf("conflicts = %+v", cs)
	}
	want := `user "old" key 1 (` + fp + `): dsa keys are not allowed: replace it with 'sshepherd rotate' or remove it with 'sshepherd revoke --key'`
	if cs[0].Message != want {
		t.Errorf("message:\n got %s\nwant %s", cs[0].Message, want)
	}
}

func TestWeakRSAMessageNamesTheSize(t *testing.T) {
	cfg, err := Parse([]byte(policyManifest(t, testkeys.RSALine(t, 1, 1024), grantOld)))
	if err != nil {
		t.Fatal(err)
	}
	if cs := cfg.Conflicts(); len(cs) != 1 || !strings.Contains(cs[0].Message, "rsa keys under 2048 bits are not allowed (1024)") {
		t.Fatalf("conflicts = %+v", cs)
	}
}

func TestWeakOperatorNamesEveryServer(t *testing.T) {
	cfg, err := Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.DSALine(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cs := cfg.Conflicts(); len(cs) != 1 || !slices.Equal(cs[0].Servers, []string{"web-1", "web-2"}) {
		t.Fatalf("conflicts = %+v", cs)
	}
}

func TestWeakKeyUngrantedIsAWarning(t *testing.T) {
	dsa := testkeys.DSALine(t, 1)
	fp := fpOfLine(t, dsa)
	cfg, err := Parse([]byte(policyManifest(t, dsa, "")))
	if err != nil {
		t.Fatal(err)
	}
	if cs := cfg.Conflicts(); len(cs) != 0 {
		t.Fatalf("an ungranted weak key renders nowhere: conflicts = %+v", cs)
	}
	want := `user "old" key 1 (` + fp + `): dsa key, granted on no server`
	if !slices.Contains(cfg.Warnings, want) {
		t.Errorf("warnings = %q, want %q", cfg.Warnings, want)
	}
	if ws := cfg.WeakKeys(); len(ws) != 1 || ws[0].Fingerprint != fp || len(ws[0].Servers) != 0 || ws[0].Servers == nil {
		t.Errorf("WeakKeys = %+v, want the ungranted key, Servers empty and non-nil", ws)
	}
}

func TestStrongKeyHasNoPolicyFinding(t *testing.T) {
	cfg, err := Parse([]byte(policyManifest(t, testkeys.Line(t, 1), grantOld)))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Conflicts()) != 0 || len(cfg.WeakKeys()) != 0 || len(cfg.Warnings) != 0 {
		t.Errorf("conflicts %+v, weak %+v, warnings %q", cfg.Conflicts(), cfg.WeakKeys(), cfg.Warnings)
	}
}

// TestWeakAndRevokedYieldTwoConflicts: a key in both lists is one conflict
// per kind, revoked kinds first.
func TestWeakAndRevokedYieldTwoConflicts(t *testing.T) {
	dsa := testkeys.DSALine(t, 1)
	fp := fpOfLine(t, dsa)
	cfg, err := Parse([]byte(policyManifest(t, dsa, grantOld) + "revoked:\n  - {fingerprint: " + fp + ", user: old, date: 2026-11-08}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cs := cfg.Conflicts()
	if len(cs) != 2 || cs[0].Kind != ConflictRevokedKey || cs[1].Kind != ConflictWeakKey {
		t.Fatalf("conflicts = %+v", cs)
	}
}

func pinNow(t *testing.T, when time.Time) {
	t.Helper()
	orig := now
	now = func() time.Time { return when }
	t.Cleanup(func() { now = orig })
}

func TestPassedExpiryWarns(t *testing.T) {
	pinNow(t, time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))
	line := `expiry-time=\"20200101\" ` + testkeys.Line(t, 1) // escaped: the line sits in a YAML double-quoted scalar
	cfg, err := Parse([]byte(policyManifest(t, line, grantOld)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := `user "old" key 1: expiry-time="20200101" has passed; sshd no longer accepts this key`
	if !slices.Contains(cfg.Warnings, want) {
		t.Errorf("warnings = %q, want %q", cfg.Warnings, want)
	}
	if len(cfg.Conflicts()) != 0 {
		t.Errorf("a passed expiry is a warning only: conflicts = %+v", cfg.Conflicts())
	}
}
