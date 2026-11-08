package apply

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeWriter records Apply calls and returns scripted errors per server.
type fakeWriter struct {
	mu     sync.Mutex
	calls  map[string]sshwrite.Request
	errs   map[string]error
	onCall func(name string)
}

func (f *fakeWriter) Apply(_ context.Context, srv config.Server, req sshwrite.Request) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = make(map[string]sshwrite.Request)
	}
	f.calls[srv.Name] = req
	if f.onCall != nil {
		f.onCall(srv.Name)
	}
	return f.errs[srv.Name]
}

func testKey(t *testing.T, seed byte) authkeys.Key {
	t.Helper()
	k, err := authkeys.ParseLine(testkeys.Line(t, seed))
	if err != nil || k == nil {
		t.Fatalf("testKey: %v", err)
	}
	return *k
}

func changePlan(name string, desired ...authkeys.Key) ServerPlan {
	return ServerPlan{
		Server:   config.Server{Name: name},
		Class:    ClassChange,
		Outcome:  OutcomePending,
		Desired:  desired,
		Rendered: []byte("rendered for " + name + "\n"),
		Expect:   sshwrite.SnapshotOf(false, []byte("phase-1 bytes of "+name+"\n")),
	}
}

func TestExecuteOutcomes(t *testing.T) {
	held := testKey(t, 1)
	plans := []ServerPlan{
		changePlan("ok-1", held),
		{Server: config.Server{Name: "already"}, Class: ClassConverged},
		changePlan("boom", held),
		changePlan("sym", held),
		changePlan("changed", held),
		changePlan("locked", held),
		changePlan("lockout", held),
		{Server: config.Server{Name: "refused"}, Class: ClassRefused},
	}
	w := &fakeWriter{errs: map[string]error{
		"boom":    errors.New("write on boom failed"),
		"sym":     &sshwrite.SymlinkError{Path: "/etc/keys"},
		"changed": &sshwrite.ChangedError{Path: "~/.ssh/authorized_keys"},
		"locked":  &sshwrite.LockedError{Path: "~/.ssh/authorized_keys"},
		"lockout": &sshwrite.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("auth failed")},
	}}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 2, Held: agentHeld(held.Fingerprint)})

	if got := planFor(t, plans, "ok-1"); got.Outcome != OutcomeApplied {
		t.Errorf("ok-1 Outcome = %s, want applied", got.Outcome)
	}
	r := w.calls["ok-1"]
	if string(r.Content) != "rendered for ok-1\n" {
		t.Errorf("writer got %q, want exactly the plan's Rendered bytes", r.Content)
	}
	if r.Expect != planFor(t, plans, "ok-1").Expect {
		t.Errorf("writer Expect = %+v, want the plan's phase-1 snapshot (compare-and-swap)", r.Expect)
	}
	if len(r.Survivors) != 1 || r.Survivors[0] != held.Fingerprint {
		t.Errorf("writer Survivors = %v, want the held desired key for the login probe", r.Survivors)
	}
	if got := planFor(t, plans, "boom"); got.Outcome != OutcomeFailed || got.OutcomeErr == nil {
		t.Errorf("boom = %s/%v, want failed with the error retained", got.Outcome, got.OutcomeErr)
	}
	for _, name := range []string{"sym", "changed", "locked"} {
		if got := planFor(t, plans, name); got.Outcome != OutcomeRefused {
			t.Errorf("%s Outcome = %s, want refused (nothing changed on the server)", name, got.Outcome)
		}
	}
	if got := planFor(t, plans, "lockout"); got.Outcome != OutcomeFailed {
		t.Errorf("lockout Outcome = %s, want failed (written, then rolled back)", got.Outcome)
	}
	for _, untouched := range []string{"already", "refused"} {
		if _, called := w.calls[untouched]; called {
			t.Errorf("%s was written despite not being ClassChange", untouched)
		}
	}
}

func TestExecuteGuardRecheck(t *testing.T) {
	keyA, keyB := testKey(t, 1), testKey(t, 2)
	caKey := keyA
	caKey.Options = []string{"cert-authority", `principals="ops"`}
	tests := []struct {
		name     string
		desired  []authkeys.Key
		fresh    []string
		wantFail bool
		wantSurv []string
	}{
		// Build saw A+B held; A expired during the prompt. The plan keeps
		// only A, so the write must not proceed (it would authenticate with
		// B and remove it).
		{"kept key expired during the prompt", []authkeys.Key{keyA}, []string{keyB.Fingerprint}, true, nil},
		{"empty fresh listing", []authkeys.Key{keyA}, nil, true, nil},
		{"cert-authority line is not a login", []authkeys.Key{caKey}, []string{keyA.Fingerprint}, true, nil},
		{"still held", []authkeys.Key{keyA, keyB}, []string{keyB.Fingerprint}, false, []string{keyB.Fingerprint}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plans := []ServerPlan{changePlan("s", tt.desired...)}
			w := &fakeWriter{}
			Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(tt.fresh...)})
			if tt.wantFail {
				if plans[0].Outcome != OutcomeFailed || len(w.calls) != 0 {
					t.Fatalf("outcome = %s, calls = %d — the re-check must block the write", plans[0].Outcome, len(w.calls))
				}
				if !strings.Contains(plans[0].OutcomeErr.Error(), "guard re-check failed") {
					t.Errorf("err = %v, want the guard re-check failure", plans[0].OutcomeErr)
				}
				return
			}
			if plans[0].Outcome != OutcomeApplied {
				t.Fatalf("outcome = %s, want applied", plans[0].Outcome)
			}
			if got := w.calls["s"].Survivors; fmt.Sprint(got) != fmt.Sprint(tt.wantSurv) {
				t.Errorf("Survivors = %v, want %v (only still-held keys are probed)", got, tt.wantSurv)
			}
		})
	}
}

func TestExecuteInterrupted(t *testing.T) {
	held := testKey(t, 1)
	t.Run("canceled before phase 2 starts nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		plans := []ServerPlan{changePlan("a", held), changePlan("b", held)}
		w := &fakeWriter{}
		Execute(ctx, plans, w, ExecOptions{Parallel: 2, Held: agentHeld(held.Fingerprint)})
		if len(w.calls) != 0 {
			t.Fatalf("wrote %d servers after cancellation, want 0", len(w.calls))
		}
		for _, p := range plans {
			if p.Outcome != OutcomePending || p.OutcomeErr == nil {
				t.Errorf("%s = %s/%v, want pending with the interruption recorded", p.Server.Name, p.Outcome, p.OutcomeErr)
			}
		}
		if got := Interrupted(plans); got != 2 {
			t.Errorf("Interrupted = %d, want 2", got)
		}
	})
	t.Run("a started write finishes; later servers do not start", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		plans := []ServerPlan{changePlan("a", held), changePlan("b", held), changePlan("c", held)}
		w := &fakeWriter{onCall: func(string) { cancel() }} // Ctrl-C during the first write
		Execute(ctx, plans, w, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint)})
		if len(w.calls) != 1 {
			t.Fatalf("wrote %d servers, want exactly the one already in flight", len(w.calls))
		}
		applied := 0
		for _, p := range plans {
			if p.Outcome == OutcomeApplied {
				applied++
			}
		}
		if applied != 1 || Interrupted(plans) != 2 {
			t.Errorf("applied = %d, interrupted = %d; want 1 and 2", applied, Interrupted(plans))
		}
	})
	t.Run("writer reporting not-started stays pending", func(t *testing.T) {
		plans := []ServerPlan{changePlan("a", held)}
		w := &fakeWriter{errs: map[string]error{"a": fmt.Errorf("a: %w", sshwrite.ErrNotStarted)}}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint)})
		if plans[0].Outcome != OutcomePending || Interrupted(plans) != 1 {
			t.Errorf("outcome = %s, want pending + interrupted", plans[0].Outcome)
		}
	})
}

// TestExecuteProbesUnrestrictedSurvivorsFirst: the post-write probe now
// runs a command, so a survivor whose line forces command= would fail it.
// Unrestricted survivors are offered first, so an intentionally restricted
// key never causes a spurious rollback while a plain one survives.
func TestExecuteProbesUnrestrictedSurvivorsFirst(t *testing.T) {
	restricted := testKey(t, 1)
	restricted.Options = []string{`command="/bin/false"`}
	plain := testKey(t, 2)
	plans := []ServerPlan{changePlan("s", restricted, plain)}
	w := &fakeWriter{}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(restricted.Fingerprint, plain.Fingerprint)})
	got := w.calls["s"].Survivors
	if fmt.Sprint(got) != fmt.Sprint([]string{plain.Fingerprint, restricted.Fingerprint}) {
		t.Errorf("Survivors = %v, want the unrestricted key first", got)
	}
}

// TestProbeOfferEqualsProductionOffer (WP-5): the probe offers survivors in
// exactly the order every later connection will (GrantedFingerprints
// filtered to held keys), so a key that gains command= and is listed first
// can never pass the probe and then capture the next session.
func TestProbeOfferEqualsProductionOffer(t *testing.T) {
	y := `
users:
  - {name: backup, keys: ["command=\"rrsync -ro /\" ` + testkeys.Line(t, 1) + `"]}
  - {name: admin, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: s, host: 10.0.0.1, user: deploy}
access:
  - {user: backup, servers: [s]}
  - {user: admin, servers: [s]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	held := agentHeld(fp(t, 1), fp(t, 2))
	plans := buildPlansHeld(t, cfg, &fakeReader{byName: map[string]fleet.ReadResult{"s": {FileAbsent: true}}}, held)
	w := &fakeWriter{}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: held})
	isHeld := map[string]bool{}
	for _, h := range held {
		isHeld[h.Fingerprint] = true
	}
	var want []string
	for _, f := range audit.GrantedFingerprints(cfg, "s") {
		if isHeld[f] {
			want = append(want, f)
		}
	}
	if got := w.calls["s"].Survivors; !slices.Equal(got, want) || len(got) == 0 || got[0] != fp(t, 2) {
		t.Errorf("probe offers %v, production offers %v; want equal, admin's plain key first", got, want)
	}
}

// TestExecuteRequestsKeys2Disable: a plan that disables authorized_keys2
// asks the writer to.
func TestExecuteRequestsKeys2Disable(t *testing.T) {
	held := testKey(t, 1)
	plain := changePlan("plain", held)
	k2 := changePlan("k2", held)
	k2.AuthorizedKeys2 = true
	plans := []ServerPlan{plain, k2}
	w := &fakeWriter{}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint)})
	if w.calls["plain"].DisableKeys2 || !w.calls["k2"].DisableKeys2 {
		t.Errorf("DisableKeys2 = plain:%v k2:%v, want false/true", w.calls["plain"].DisableKeys2, w.calls["k2"].DisableKeys2)
	}
}
