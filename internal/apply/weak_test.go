package apply

import (
	"context"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// weakCfg: op (k1, operator); alice (k2) and old (a DSA key) -> web-1; web-2
// holds only the operator.
func weakCfg(t *testing.T) (*config.Config, string) {
	t.Helper()
	dsa := testkeys.DSALine(t, 7)
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
  - {name: old, keys: ["` + dsa + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1]}
  - {user: old, servers: [web-1]}
`))
	if err != nil {
		t.Fatalf("weakCfg: %v", err)
	}
	return cfg, dsa
}

func planWeak(t *testing.T, cfg *config.Config, content string) ServerPlan {
	t.Helper()
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {Content: []byte(content)}, "web-2": {Content: []byte(testkeys.Line(t, 1) + "\n")},
	}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{})
	if err != nil {
		t.Fatalf("BuildWith: %v", err)
	}
	return planFor(t, plans, "web-1")
}

func TestWeakKeyServerIsRefused(t *testing.T) {
	cfg, _ := weakCfg(t)
	p := planWeak(t, cfg, testkeys.Line(t, 1)+"\n") // alice and old are missing: a grant
	if p.Class != ClassRefused || !p.WeakRefused || !strings.Contains(p.Refusal, "dsa keys are not allowed") {
		t.Fatalf("plan = %+v", p)
	}
}

// TestWeakKeyRemovalOnlyWriteProceeds (OP4): every rendered key is present
// and bob's key (k9) is removed, so the write grants nothing and proceeds.
func TestWeakKeyRemovalOnlyWriteProceeds(t *testing.T) {
	cfg, dsa := weakCfg(t)
	p := planWeak(t, cfg, testkeys.Line(t, 1)+"\n"+testkeys.Line(t, 2)+"\n"+dsa+"\n"+testkeys.Line(t, 9)+"\n")
	if p.Class != ClassChange || p.WeakRefused {
		t.Fatalf("class = %s, weakRefused = %v (refusal %q), want a change", p.Class, p.WeakRefused, p.Refusal)
	}
}

// TestWeakKeyConvergedServerStaysRefused: nothing to remove, so the
// exception does not apply and the server is refused (exit 1).
func TestWeakKeyConvergedServerStaysRefused(t *testing.T) {
	cfg, dsa := weakCfg(t)
	p := planWeak(t, cfg, testkeys.Line(t, 1)+"\n"+testkeys.Line(t, 2)+"\n"+dsa+"\n")
	if p.Class != ClassRefused || !p.WeakRefused {
		t.Fatalf("class = %s, weakRefused = %v, want a weak-key refusal", p.Class, p.WeakRefused)
	}
}

// TestRevokedConflictHasNoRemovalException pins P04's behaviour: a server
// named by a revoked-kind conflict is refused even for a removal-only write.
// It passes before this task's code; the exception must not reach it.
func TestRevokedConflictHasNoRemovalException(t *testing.T) {
	line := testkeys.Line(t, 1)
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + line + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
revoked:
  - {fingerprint: ` + fp(t, 1) + `, user: op, date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(line + "\n" + testkeys.Line(t, 9) + "\n")}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p := planFor(t, plans, "web-1"); p.Class != ClassRefused {
		t.Fatalf("class = %s, want refused", p.Class)
	}
}

// TestWeakAndRevokedKeyHasNoRemovalException: a server named by both kinds is
// refused on a removal-only write, and the refusal is not a weak-key one, so
// it still withholds an edit's save.
func TestWeakAndRevokedKeyHasNoRemovalException(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(dsa)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: old, keys: ["` + dsa + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: old, servers: [web-1]}
revoked:
  - {fingerprint: ` + k.Fingerprint + `, user: old, date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n" + dsa + "\n" + testkeys.Line(t, 9) + "\n")}}}
	results := audit.Run(context.Background(), cfg, r, audit.Options{Parallel: 1})
	plans, err := BuildWith(cfg, results, agentHeld(fp(t, 1)), BuildOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if p := planFor(t, plans, "web-1"); p.Class != ClassRefused || p.WeakRefused {
		t.Fatalf("class = %s, weakRefused = %v, want a revoked-kind refusal", p.Class, p.WeakRefused)
	}
}

// TestWeakKeyExceptionKeepsParseRefusal: the removal-only exception hands
// the plan to the ordinary checks; it does not bypass them.
func TestWeakKeyExceptionKeepsParseRefusal(t *testing.T) {
	cfg, dsa := weakCfg(t)
	p := planWeak(t, cfg, testkeys.Line(t, 1)+"\n"+testkeys.Line(t, 2)+"\n"+dsa+"\n"+testkeys.Line(t, 9)+"\nnot a key\n")
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "unparseable") {
		t.Fatalf("plan = %+v", p)
	}
}
