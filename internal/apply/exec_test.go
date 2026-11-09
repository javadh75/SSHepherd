package apply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeWriter records Apply calls and returns scripted errors per server.
type fakeWriter struct {
	mu     sync.Mutex
	calls  map[string]fleet.WriteRequest
	errs   map[string]error
	onCall func(name string)
}

func (f *fakeWriter) Apply(_ context.Context, srv config.Server, req fleet.WriteRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = make(map[string]fleet.WriteRequest)
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
		Expect:   fleet.SnapshotOf(false, []byte("phase-1 bytes of "+name+"\n")),
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
		"sym":     fleet.Refused(errors.New("/etc/keys is a symlink")),
		"changed": fleet.Refused(errors.New("~/.ssh/authorized_keys changed since the plan was read")),
		"locked":  fleet.Refused(errors.New("another apply is in progress on ~/.ssh/authorized_keys")),
		"lockout": &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errors.New("auth failed")},
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
	if got := planFor(t, plans, "lockout"); got.Outcome != OutcomeFailed || !got.RolledBack {
		t.Errorf("lockout = %s rolled %v, want failed and rolled back", got.Outcome, got.RolledBack)
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
		w := &fakeWriter{errs: map[string]error{"a": fmt.Errorf("a: %w", fleet.ErrWriteNotStarted)}}
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

func TestExecuteFailureOutcomes(t *testing.T) {
	held := testKey(t, 1)
	plans := []ServerPlan{changePlan("unproven", held), changePlan("unrestored", held), changePlan("reconnect", held), changePlan("rolledback", held), changePlan("keys2", held), changePlan("keys2only", held), changePlan("keys2onlyfailed", held)}
	w := &fakeWriter{errs: map[string]error{
		"unproven":        &fleet.UnprovenError{Attempts: 4, Last: errors.New("dial")},
		"unrestored":      &fleet.LockoutError{Probe: errors.New("auth"), Restore: errors.New("denied")},
		"reconnect":       &fleet.LockoutError{Probe: errors.New("auth"), Restore: fleet.ErrNoSession},
		"rolledback":      &fleet.LockoutError{Probe: errors.New("auth")},
		"keys2":           &fleet.LockoutError{Probe: errors.New("auth"), RestoreKeys2: errors.New("kept")},
		"keys2only":       &fleet.LockoutError{Probe: errors.New("auth"), FileKept: true},
		"keys2onlyfailed": &fleet.LockoutError{Probe: errors.New("auth"), FileKept: true, RestoreKeys2: errors.New("kept")},
	}}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 2, Held: agentHeld(held.Fingerprint)})
	for name, want := range map[string]struct {
		outcome Outcome
		rolled  bool
	}{
		"unproven":        {OutcomeUnproven, false},
		"unrestored":      {OutcomeLockoutUnrestored, false},
		"reconnect":       {OutcomeLockoutUnrestored, false},
		"rolledback":      {OutcomeFailed, true},
		"keys2":           {OutcomeLockoutUnrestored, true},
		"keys2only":       {OutcomeFailed, false},
		"keys2onlyfailed": {OutcomeLockoutUnrestored, false},
	} {
		if got := planFor(t, plans, name); got.Outcome != want.outcome || got.RolledBack != want.rolled || got.OutcomeErr == nil {
			t.Errorf("%s = %s rolled %v err %v", name, got.Outcome, got.RolledBack, got.OutcomeErr)
		}
	}
}

// TestKeys2MoveBackFailureIsUnrestoredLockout: a key whose authorized_keys
// line refuses this client (from=) may have logged in only through
// authorized_keys2, so a failed move-back after a rejected login check can be
// a real lockout. That holds when authorized_keys was restored and on a
// keys2-only (SkipWrite) run alike.
func TestKeys2MoveBackFailureIsUnrestoredLockout(t *testing.T) {
	held, alice := testKey(t, 1), testKey(t, 2)
	refused := &hintedErr{kind: fleet.ErrorKindAuth, err: errors.New("ssh: unable to authenticate")}
	moveBack := errors.New("restore authorized_keys2 on web-1 failed (exit 1): mv: denied")
	for _, tt := range []struct {
		name   string
		err    *fleet.LockoutError
		rolled bool
		row    string
	}{
		{
			name:   "previous file restored",
			err:    &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: refused, RestoreKeys2: moveBack},
			rolled: true,
			row:    "web-1: LOCKOUT — NOT RESTORED: restored previous file (post-write login offering only the surviving keys you hold failed: ssh: unable to authenticate), but restoring authorized_keys2 failed (" + moveBack.Error() + "); it still grants " + audit.UnknownLabel(alice) + " (" + alice.Fingerprint + ", on the revoked: list), which the manifest removed — fix the surviving key and re-run\n",
		},
		{
			name: "keys2-only, authorized_keys never written",
			err:  &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: refused, FileKept: true, RestoreKeys2: moveBack},
			row:  "web-1: LOCKOUT — NOT RESTORED: post-write login offering only the surviving keys you hold failed (ssh: unable to authenticate) and moving authorized_keys2 back failed (" + moveBack.Error() + "); authorized_keys was not changed\n",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			plan := changePlan("web-1", held)
			plan.Remove, plan.RevokedRemovals = []authkeys.Key{alice}, []string{alice.Fingerprint}
			plans := []ServerPlan{plan}
			Execute(context.Background(), plans, &fakeWriter{errs: map[string]error{"web-1": tt.err}}, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint)})

			if got := plans[0]; got.Outcome != OutcomeLockoutUnrestored || got.RolledBack != tt.rolled {
				t.Fatalf("outcome = %s, rolled back = %v, want %s, %v", got.Outcome, got.RolledBack, OutcomeLockoutUnrestored, tt.rolled)
			}
			if got := ExitCode(plans); got != 2 {
				t.Errorf("ExitCode = %d, want 2", got)
			}

			var buf bytes.Buffer
			RenderSummary(&buf, &config.Config{}, plans, RenderOptions{})
			for _, want := range []string{tt.row, "Summary: 0/1 servers converged · 1 lockout not restored  → exit 2\n"} {
				if !strings.Contains(buf.String(), want) {
					t.Errorf("report lacks %q:\n%s", want, buf.String())
				}
			}

			var doc struct {
				Summary struct {
					LockoutUnrestored int `json:"lockout_unrestored"`
					ExitCode          int `json:"exit_code"`
				} `json:"summary"`
				Servers []struct {
					Outcome             string   `json:"outcome"`
					ErrorKind           string   `json:"error_kind"`
					RestoredRevokedKeys []string `json:"restored_revoked_keys"`
				} `json:"servers"`
			}
			if err := json.Unmarshal(renderJSONCfg(t, &config.Config{}, plans, JSONOptions{}), &doc); err != nil {
				t.Fatal(err)
			}
			if doc.Summary.LockoutUnrestored != 1 || doc.Summary.ExitCode != 2 {
				t.Errorf("summary = %+v", doc.Summary)
			}
			if s := doc.Servers[0]; s.Outcome != "lockout_unrestored" || s.ErrorKind != "auth" {
				t.Errorf("server = %+v, want the probe's kind on a lockout_unrestored", s)
			}
			// Only a restored authorized_keys put the revoked key back.
			if got := len(doc.Servers[0].RestoredRevokedKeys); (got == 1) != tt.rolled {
				t.Errorf("restored_revoked_keys = %v with rolled back %v", doc.Servers[0].RestoredRevokedKeys, tt.rolled)
			}
		})
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// blockingWriter holds a write open until release closes.
type blockingWriter struct{ started, release chan struct{} }

func (w blockingWriter) Apply(context.Context, config.Server, fleet.WriteRequest) error {
	close(w.started)
	<-w.release
	return nil
}

// secondBlocksWriter returns from its first write at once and holds its
// second open until release closes.
type secondBlocksWriter struct {
	calls            atomic.Int32
	started, release chan struct{}
}

func (w *secondBlocksWriter) Apply(context.Context, config.Server, fleet.WriteRequest) error {
	if w.calls.Add(1) == 1 {
		return nil
	}
	close(w.started)
	<-w.release
	return nil
}

func TestExecuteInterruptNotice(t *testing.T) {
	held := testKey(t, 1)
	t.Run("a started write gets the notice", func(t *testing.T) {
		var buf syncBuffer
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := blockingWriter{started: make(chan struct{}), release: make(chan struct{})}
		done := make(chan struct{})
		go func() {
			defer close(done)
			Execute(ctx, []ServerPlan{changePlan("web-1", held)}, w, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint),
				Logger: slog.New(slog.NewTextHandler(&buf, nil))})
		}()
		<-w.started
		cancel()
		const want = "finishing 1 in-flight write (write, verify, login check"
		for deadline := time.Now().Add(5 * time.Second); !strings.Contains(buf.String(), want); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("no notice; log:\n%s", buf.String())
			}
		}
		close(w.release)
		<-done
	})
	t.Run("a finished write is not counted", func(t *testing.T) {
		var buf syncBuffer
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		w := &secondBlocksWriter{started: make(chan struct{}), release: make(chan struct{})}
		done := make(chan struct{})
		go func() {
			defer close(done)
			Execute(ctx, []ServerPlan{changePlan("web-1", held), changePlan("web-2", held)}, w, ExecOptions{Parallel: 1, Held: agentHeld(held.Fingerprint),
				Logger: slog.New(slog.NewTextHandler(&buf, nil))})
		}()
		<-w.started // Parallel 1: the first write has returned and been counted out
		cancel()
		const want = "finishing 1 in-flight write (write, verify, login check"
		for deadline := time.Now().Add(5 * time.Second); !strings.Contains(buf.String(), want); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(deadline) {
				close(w.release)
				<-done
				t.Fatalf("no one-write notice; log:\n%s", buf.String())
			}
		}
		close(w.release)
		<-done
	})
	t.Run("nothing in flight, no notice", func(t *testing.T) {
		var buf syncBuffer
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		Execute(ctx, []ServerPlan{{Server: config.Server{Name: "c"}, Class: ClassConverged}}, &fakeWriter{},
			ExecOptions{Parallel: 1, Logger: slog.New(slog.NewTextHandler(&buf, nil))})
		time.Sleep(20 * time.Millisecond) // the callback runs on its own goroutine
		if strings.Contains(buf.String(), "in-flight") {
			t.Errorf("log = %s", buf.String())
		}
	})
}

func TestKeysUnchanged(t *testing.T) {
	cfg := serialCfg(t)
	body := authkeys.Header(7) + "\n" + web1Body(t, cfg)
	keys2 := planWeb1(t, cfg, body, true, false)
	if !keys2.DisableKeys2() || !keys2.KeysUnchanged() {
		t.Fatalf("keys2-only plan: disable %v, unchanged %v", keys2.DisableKeys2(), keys2.KeysUnchanged())
	}
	t.Run("the request carries SkipWrite", func(t *testing.T) {
		w := &fakeWriter{}
		plans := []ServerPlan{keys2}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Held: agentHeld(fp(t, 1))})
		if !w.calls["web-1"].SkipWrite {
			t.Error("SkipWrite = false for a plan that only disables authorized_keys2")
		}
	})
	t.Run("a Reserial header change means the file is written", func(t *testing.T) {
		plans := []ServerPlan{keys2}
		if err := Reserial(plans, 8); err != nil {
			t.Fatal(err)
		}
		if plans[0].KeysUnchanged() {
			t.Error("KeysUnchanged = true after the header changed")
		}
	})
	t.Run("without keys2 a change is never skipped", func(t *testing.T) {
		p := keys2
		p.AuthorizedKeys2 = false
		if p.KeysUnchanged() {
			t.Error("KeysUnchanged = true with nothing to disable")
		}
	})
	t.Run("different bytes are written", func(t *testing.T) {
		p := planWeb1(t, cfg, body+testkeys.Line(t, 9)+"\n", true, false)
		if p.KeysUnchanged() {
			t.Error("KeysUnchanged = true although the file differs")
		}
	})
}

func TestHeadlessProofFor(t *testing.T) {
	agent, plain, restricted := testKey(t, 1), testKey(t, 2), testKey(t, 3)
	restricted.Options = []string{`from="10.0.0.1"`}
	held := []fleet.HeldKey{
		{Fingerprint: agent.Fingerprint, Source: fleet.SourceAgent},
		fileHeld(plain.Fingerprint, "/k/ci"),
		fileHeld(restricted.Fingerprint, "/k/restricted"),
	}
	for _, tt := range []struct {
		name  string
		fps   []string
		keys  []authkeys.Key
		proof []string
		paths []string
	}{
		{"agent first, one unrestricted key file", []string{agent.Fingerprint, plain.Fingerprint}, []authkeys.Key{agent, plain},
			[]string{plain.Fingerprint}, []string{"/k/ci"}},
		{"a key file first: production already proves it", []string{plain.Fingerprint, agent.Fingerprint}, []authkeys.Key{plain, agent}, nil, nil},
		{"only a restricted key file", []string{agent.Fingerprint, restricted.Fingerprint}, []authkeys.Key{agent, restricted}, nil, nil},
		{"agent only", []string{agent.Fingerprint}, []authkeys.Key{agent}, nil, nil},
		{"nothing to offer", nil, nil, nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			proof, paths := headlessProofFor(tt.fps, tt.keys, held)
			if !slices.Equal(proof, tt.proof) || !slices.Equal(paths, tt.paths) {
				t.Errorf("got %v %v, want %v %v", proof, paths, tt.proof, tt.paths)
			}
		})
	}
}

// warningWriter calls OnWarning like the transport does.
type warningWriter struct {
	mu    sync.Mutex
	calls []fleet.WriteRequest
}

func (w *warningWriter) Apply(_ context.Context, _ config.Server, req fleet.WriteRequest) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.calls = append(w.calls, req)
	req.OnWarning("ssh: unable to authenticate")
	return nil
}

func TestApplyOneHeadlessWarning(t *testing.T) {
	agent, plain := testKey(t, 1), testKey(t, 2)
	plans := []ServerPlan{changePlan("web-1", agent, plain)}
	var buf syncBuffer
	w := &warningWriter{}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, Logger: slog.New(slog.NewTextHandler(&buf, nil)),
		Held: []fleet.HeldKey{{Fingerprint: agent.Fingerprint, Source: fleet.SourceAgent}, fileHeld(plain.Fingerprint, "/k/ci")}})
	if got := w.calls[0].HeadlessProof; !slices.Equal(got, []string{plain.Fingerprint}) {
		t.Fatalf("HeadlessProof = %v", got)
	}
	want := "your --identity key /k/ci could not log in on its own (ssh: unable to authenticate); a headless run with only that key would fail"
	if got := planFor(t, plans, "web-1").Warnings; !slices.Equal(got, []string{want}) {
		t.Errorf("Warnings = %q", got)
	}
	if !strings.Contains(buf.String(), "web-1: "+want) {
		t.Errorf("log = %s", buf.String())
	}
}

// causeWriter reports cause through the write's headless-proof warning.
type causeWriter struct{ cause string }

func (w causeWriter) Apply(_ context.Context, _ config.Server, req fleet.WriteRequest) error {
	req.OnWarning(w.cause)
	return nil
}

// TestApplyOneHeadlessWarningIsOneLine: a remote cause can span lines; the
// warning, on stderr and in JSON alike, stays on one.
func TestApplyOneHeadlessWarningIsOneLine(t *testing.T) {
	agent, plain := testKey(t, 1), testKey(t, 2)
	plans := []ServerPlan{changePlan("web-1", agent, plain)}
	var buf syncBuffer
	Execute(context.Background(), plans, causeWriter{cause: "ssh: handshake failed:\n  refused\tby host\n"}, ExecOptions{Parallel: 1, Logger: slog.New(slog.NewTextHandler(&buf, nil)),
		Held: []fleet.HeldKey{{Fingerprint: agent.Fingerprint, Source: fleet.SourceAgent}, fileHeld(plain.Fingerprint, "/k/ci")}})
	want := "your --identity key /k/ci could not log in on its own (ssh: handshake failed: refused by host); a headless run with only that key would fail"
	if got := planFor(t, plans, "web-1").Warnings; !slices.Equal(got, []string{want}) {
		t.Errorf("Warnings = %q", got)
	}
}

func TestHeadlessWarningPlural(t *testing.T) {
	want := "your --identity keys /a, /b could not log in on their own (x); a headless run with only those keys would fail"
	if got := headlessWarning([]string{"/a", "/b"}, "x"); got != want {
		t.Errorf("got %q", got)
	}
}
