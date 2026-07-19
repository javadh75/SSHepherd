package apply

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// fakeWriter records Apply calls and returns scripted errors per server.
type fakeWriter struct {
	mu    sync.Mutex
	calls map[string][]byte
	errs  map[string]error
}

func (f *fakeWriter) Apply(_ context.Context, srv config.Server, content []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.calls == nil {
		f.calls = make(map[string][]byte)
	}
	f.calls[srv.Name] = content
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

func TestExecuteOutcomes(t *testing.T) {
	held := testKey(t, 1)
	change := func(name string) ServerPlan {
		return ServerPlan{
			Server:   config.Server{Name: name},
			Class:    ClassChange,
			Outcome:  OutcomePending,
			Desired:  []authkeys.Key{held},
			Rendered: []byte("rendered for " + name + "\n"),
		}
	}
	plans := []ServerPlan{
		change("ok-1"),
		{Server: config.Server{Name: "already"}, Class: ClassConverged},
		change("boom"),
		change("sym"),
		{Server: config.Server{Name: "refused"}, Class: ClassRefused},
	}
	w := &fakeWriter{errs: map[string]error{
		"boom": errors.New("write on boom failed"),
		"sym":  &sshwrite.SymlinkError{Path: "/etc/keys"},
	}}
	Execute(context.Background(), plans, w, ExecOptions{Parallel: 2, AgentFPs: []string{held.Fingerprint}})

	if got := planFor(t, plans, "ok-1"); got.Outcome != OutcomeApplied {
		t.Errorf("ok-1 Outcome = %s, want applied", got.Outcome)
	}
	if string(w.calls["ok-1"]) != "rendered for ok-1\n" {
		t.Errorf("writer got %q, want exactly the plan's Rendered bytes", w.calls["ok-1"])
	}
	if got := planFor(t, plans, "boom"); got.Outcome != OutcomeFailed || got.OutcomeErr == nil {
		t.Errorf("boom = %s/%v, want failed with the error retained", got.Outcome, got.OutcomeErr)
	}
	if got := planFor(t, plans, "sym"); got.Outcome != OutcomeRefused {
		t.Errorf("sym Outcome = %s, want refused (symlink is a refusal, not a failure)", got.Outcome)
	}
	for _, untouched := range []string{"already", "refused"} {
		if _, called := w.calls[untouched]; called {
			t.Errorf("%s was written despite not being ClassChange", untouched)
		}
	}
}

func TestExecuteGuardRecheck(t *testing.T) {
	notHeld := testKey(t, 2)
	t.Run("no desired key held", func(t *testing.T) {
		plans := []ServerPlan{{
			Server: config.Server{Name: "s"}, Class: ClassChange, Outcome: OutcomePending,
			Desired: []authkeys.Key{notHeld}, Rendered: []byte("x\n"),
		}}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1, AgentFPs: []string{fp(t, 1)}})
		if plans[0].Outcome != OutcomeFailed || len(w.calls) != 0 {
			t.Fatalf("outcome = %s, calls = %d — the re-check must block the write", plans[0].Outcome, len(w.calls))
		}
	})
	t.Run("empty listing blocks removals only", func(t *testing.T) {
		plans := []ServerPlan{
			{Server: config.Server{Name: "removes"}, Class: ClassChange, Outcome: OutcomePending,
				Desired: []authkeys.Key{notHeld}, Remove: []authkeys.Key{testKey(t, 9)}, Rendered: []byte("x\n")},
			{Server: config.Server{Name: "adds"}, Class: ClassChange, Outcome: OutcomePending,
				Desired: []authkeys.Key{notHeld}, Rendered: []byte("y\n")},
		}
		w := &fakeWriter{}
		Execute(context.Background(), plans, w, ExecOptions{Parallel: 1})
		if planFor(t, plans, "removes").Outcome != OutcomeFailed {
			t.Error("a removal must not proceed under an empty agent listing")
		}
		if planFor(t, plans, "adds").Outcome != OutcomeApplied {
			t.Error("an additive write may proceed under an empty agent listing")
		}
	})
}
