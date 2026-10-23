package apply

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// rotationCfg: user ci holds only ci_new (seed 5) and is granted web-1;
// web-1 still carries ci_old (seed 4) — the headless self-rotation.
func rotationCfg(t *testing.T) (*config.Config, *fakeReader) {
	t.Helper()
	y := `
users:
  - {name: ci, keys: ["` + testkeys.Line(t, 5) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: ci, servers: [web-1]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("rotationCfg: %v", err)
	}
	r := &fakeReader{byName: map[string]audit.ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 4) + " ci_old\n"), SessionKeyFP: fp(t, 4)},
	}}
	return cfg, r
}

func TestHeadlessRotationPlan(t *testing.T) {
	cfg, r := rotationCfg(t)
	oldKey, newKey := fileHeld(fp(t, 4), "/k/ci_old"), fileHeld(fp(t, 5), "/k/ci_new")

	t.Run("old and new held: change, probe proves the new key", func(t *testing.T) {
		p := planFor(t, buildPlansHeld(t, cfg, r, []sshconn.HeldKey{oldKey, newKey}), "web-1")
		if p.Class != ClassChange {
			t.Fatalf("Class = %s (%s), want change", p.Class, p.Refusal)
		}
		if !strings.Contains(p.Note, "removes the key this session logged in with; ci remains") {
			t.Errorf("Note = %q, want the rotate note", p.Note)
		}
		if p.AgentOnly != "" {
			t.Errorf("AgentOnly = %q, want none (an --identity key survives)", p.AgentOnly)
		}
		plans := []ServerPlan{p}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: []sshconn.HeldKey{oldKey, newKey}})
		if got := w.calls["web-1"].Survivors; !slices.Equal(got, []string{fp(t, 5)}) {
			t.Errorf("probe Survivors = %v, want ci_new only", got)
		}
	})
	t.Run("only the old key held: refused, naming the fix", func(t *testing.T) {
		p := planFor(t, buildPlansHeld(t, cfg, r, []sshconn.HeldKey{oldKey}), "web-1")
		if p.Class != ClassRefused {
			t.Fatalf("Class = %s, want refused", p.Class)
		}
		for _, want := range []string{
			"the 1 key you hold (identity files + agent) would not remain in web-1's authorized_keys",
			"(held: " + fp(t, 4) + " (/k/ci_old))",
			"rotating an --identity key? pass the new key with another --identity",
		} {
			if !strings.Contains(p.Refusal, want) {
				t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, want)
			}
		}
	})
}

func TestRefusalListsSources(t *testing.T) {
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	held := []sshconn.HeldKey{fileHeld(fp(t, 9), "/k/x"), fileHeld(fp(t, 9), "/k/x-again"), agentHeld(fp(t, 8))[0], agentHeld(fp(t, 9))[0]}
	p := planFor(t, buildPlansHeld(t, cfg, r, held), "web-1")
	want := "none of the 2 keys you hold (identity files + agent) would remain in web-1's authorized_keys — applying would lock this session out (held: " +
		fp(t, 9) + " (/k/x), " + fp(t, 8) + " (agent))"
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, want) {
		t.Fatalf("Refusal = %q, want it to contain %q", p.Refusal, want)
	}
}

func TestAgentOnlySurvivorWarning(t *testing.T) {
	cfg := planCfg(t) // op (seed 1) is an operator: desired everywhere
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	tests := []struct {
		name string
		held []sshconn.HeldKey
		want string
	}{
		{"identity given, only an agent key survives", []sshconn.HeldKey{fileHeld(fp(t, 9), "/k/ci"), agentHeld(fp(t, 1))[0]},
			"only " + fp(t, 1) + " (agent) keeps access; none of your --identity keys survives — a run without this agent will be locked out"},
		{"two agent survivors", []sshconn.HeldKey{fileHeld(fp(t, 9), "/k/ci"), agentHeld(fp(t, 1))[0], agentHeld(fp(t, 2))[0]},
			"only " + fp(t, 1) + " (agent), " + fp(t, 2) + " (agent) keep access"},
		{"no --identity: no warning", agentHeld(fp(t, 1)), ""},
		{"an --identity key survives: no warning", []sshconn.HeldKey{fileHeld(fp(t, 2), "/k/alice"), agentHeld(fp(t, 1))[0]}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := planFor(t, buildPlansHeld(t, cfg, r, tt.held), "web-1")
			if p.Class != ClassChange {
				t.Fatalf("Class = %s (%s), want change — the warning never refuses", p.Class, p.Refusal)
			}
			if tt.want == "" && p.AgentOnly != "" || tt.want != "" && !strings.Contains(p.AgentOnly, tt.want) {
				t.Errorf("AgentOnly = %q, want %q", p.AgentOnly, tt.want)
			}
		})
	}
}

func TestCertOnlyOperatorRefused(t *testing.T) {
	// A certificate-only agent lists no plain keys (sshconn excludes
	// certificates from Held), so even an additive write is refused.
	cfg := planCfg(t)
	r := &fakeReader{byName: map[string]audit.ReadResult{"web-1": {FileAbsent: true}}}
	p := planFor(t, buildPlansHeld(t, cfg, r, nil), "web-1")
	if p.Class != ClassRefused || !strings.Contains(p.Refusal, "you hold no plain keys (identity files + agent; certificates do not count)") {
		t.Fatalf("plan = %s/%q, want the no-plain-keys refusal", p.Class, p.Refusal)
	}
}

func TestExecuteRecheckAcrossSources(t *testing.T) {
	file, ag := testKey(t, 1), testKey(t, 2)
	fileKey := fileHeld(file.Fingerprint, "/k/ci")
	t.Run("agent broke during the prompt, a file key survives: written", func(t *testing.T) {
		plans := []ServerPlan{changePlan("s", file, ag)}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: []sshconn.HeldKey{fileKey}})
		if plans[0].Outcome != OutcomeApplied || !slices.Equal(w.calls["s"].Survivors, []string{file.Fingerprint}) {
			t.Fatalf("outcome = %s, survivors = %v; want applied, proven by the file key", plans[0].Outcome, w.calls["s"].Survivors)
		}
	})
	t.Run("the only survivor was an agent key: refused", func(t *testing.T) {
		plans := []ServerPlan{changePlan("s", ag)}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: []sshconn.HeldKey{fileKey}})
		if plans[0].Outcome != OutcomeFailed || len(w.calls) != 0 {
			t.Fatalf("outcome = %s, calls = %d; want the guard re-check to block the write", plans[0].Outcome, len(w.calls))
		}
		if !strings.Contains(plans[0].OutcomeErr.Error(), "is still held (identity files + agent") {
			t.Errorf("err = %v, want the neutral re-check wording", plans[0].OutcomeErr)
		}
	})
}

func TestProbeOrder(t *testing.T) {
	keys := []authkeys.Key{testKey(t, 1), testKey(t, 2), testKey(t, 3), testKey(t, 4)}
	restrictedFile := keys[3]
	restrictedFile.Options = []string{`from="10.0.0.1"`}
	desired := []authkeys.Key{keys[0], keys[1], keys[2], restrictedFile}
	src := map[string]string{
		keys[0].Fingerprint: sshconn.SourceAgent,
		keys[1].Fingerprint: "/k/b",
		keys[2].Fingerprint: "/k/c",
		keys[3].Fingerprint: "/k/d",
	}
	files := []string{keys[1].Fingerprint, keys[2].Fingerprint}
	slices.Sort(files)
	want := append(append(files, keys[0].Fingerprint), keys[3].Fingerprint)
	if got := probeOrder(desired, src); !slices.Equal(got, want) {
		t.Errorf("probeOrder = %v, want unrestricted files (by fingerprint), unrestricted agent, then restricted: %v", got, want)
	}
	// Deterministic whatever the desired order.
	rev := slices.Clone(desired)
	slices.Reverse(rev)
	if got := probeOrder(rev, src); !slices.Equal(got, want) {
		t.Errorf("probeOrder(reversed) = %v, want %v", got, want)
	}
}
