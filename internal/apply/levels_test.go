package apply

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
)

// orderWriter records start and end of every write, in one sequence, and
// can fail or hold chosen servers.
type orderWriter struct {
	mu        sync.Mutex
	events    []string
	fail      map[string]bool
	hold      time.Duration
	now, peak atomic.Int32
}

func (w *orderWriter) Apply(_ context.Context, srv config.Server, _ fleet.WriteRequest) error {
	w.add("start " + srv.Name)
	n := w.now.Add(1)
	for { // raise peak to n (revive: no empty loop body)
		p := w.peak.Load()
		if n <= p || w.peak.CompareAndSwap(p, n) {
			break
		}
	}
	time.Sleep(w.hold)
	w.now.Add(-1)
	w.add("end " + srv.Name)
	if w.fail[srv.Name] {
		return errors.New("write failed")
	}
	return nil
}

func (w *orderWriter) add(e string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.events = append(w.events, e)
}

func (w *orderWriter) index(e string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Index(w.events, e)
}

// chainOf is a Chain over fixed bastion lists.
func chainOf(chains map[string][]string) func(config.Server) []string {
	return func(s config.Server) []string { return chains[s.Name] }
}

func levelPlans(t *testing.T, names ...string) []ServerPlan {
	t.Helper()
	k := testKey(t, 1)
	plans := make([]ServerPlan, 0, len(names))
	for _, n := range names {
		plans = append(plans, changePlan(n, k))
	}
	return plans
}

func levelOpts(t *testing.T, chain func(config.Server) []string) ExecOptions {
	t.Helper()
	return ExecOptions{Parallel: 32, Chain: chain, Held: []fleet.HeldKey{{Fingerprint: testKey(t, 1).Fingerprint, Source: fleet.SourceAgent}}}
}

// TestWriteLevels (spec S5 "Apply write order"): A via B via C writes A,
// then B, then C, a level at a time; a converged middle hop still keeps C
// after A; a failed dependent does not stop its bastion; a jump_only
// bastion is in no level.
func TestWriteLevels(t *testing.T) {
	chains := map[string][]string{"a": {"c", "b"}, "b": {"c"}}
	t.Run("dependents first, deepest bastion last", func(t *testing.T) {
		w := &orderWriter{hold: 20 * time.Millisecond}
		Execute(context.Background(), levelPlans(t, "c", "b", "a"), w, levelOpts(t, chainOf(chains)))
		if w.index("end a") >= w.index("start b") || w.index("end b") >= w.index("start c") {
			t.Errorf("events = %v, want a, then b, then c", w.events)
		}
	})
	t.Run("a converged middle hop", func(t *testing.T) {
		w := &orderWriter{hold: 20 * time.Millisecond}
		plans := levelPlans(t, "c", "b", "a")
		plans[1].Class = ClassConverged
		Execute(context.Background(), plans, w, levelOpts(t, chainOf(chains)))
		if w.index("end a") >= w.index("start c") || w.index("start b") >= 0 {
			t.Errorf("events = %v, want a then c, and b untouched", w.events)
		}
	})
	t.Run("a failed dependent does not stop its bastion", func(t *testing.T) {
		w := &orderWriter{fail: map[string]bool{"a": true}}
		plans := levelPlans(t, "c", "b", "a")
		Execute(context.Background(), plans, w, levelOpts(t, chainOf(chains)))
		if plans[2].Outcome != OutcomeFailed || plans[1].Outcome != OutcomeApplied || plans[0].Outcome != OutcomeApplied {
			t.Errorf("outcomes = %s %s %s, want c and b applied after a failed", plans[0].Outcome, plans[1].Outcome, plans[2].Outcome)
		}
	})
	t.Run("a jump_only bastion is in no level", func(t *testing.T) {
		w := &orderWriter{}
		plans := levelPlans(t, "edge", "web")
		plans[0].Class = ClassJumpOnly
		Execute(context.Background(), plans, w, levelOpts(t, chainOf(map[string][]string{"web": {"edge"}})))
		if w.index("start edge") >= 0 || w.index("start web") < 0 {
			t.Errorf("events = %v, want web only", w.events)
		}
	})
}

// TestExecuteTwoSlotWrites (OP2): a write takes two bastion slots (its
// session and its login check), so at most fleet.HopCap/2 writes run
// through one bastion at once.
func TestExecuteTwoSlotWrites(t *testing.T) {
	names := []string{"w1", "w2", "w3", "w4", "w5", "w6", "w7", "w8"}
	chains := map[string][]string{}
	for _, n := range names {
		chains[n] = []string{"edge"}
	}
	w := &orderWriter{hold: 30 * time.Millisecond}
	Execute(context.Background(), levelPlans(t, names...), w, levelOpts(t, chainOf(chains)))
	if p := w.peak.Load(); p > fleet.HopCap/2 || p < 2 {
		t.Errorf("peak writes through edge = %d, want 2..%d", p, fleet.HopCap/2)
	}
}

// TestExecuteSlotsCoverTheWholeChain: a write behind mid1 or mid2 takes
// its two slots on edge too (the whole chain, root first), so the writes in
// flight through edge stay at fleet.HopCap/2 however they split between the
// inner bastions. Server.Via is set as the manifest would, so a fan-out that
// read the plan's own via instead of the chain would let 8 writes through.
func TestExecuteSlotsCoverTheWholeChain(t *testing.T) {
	chains := map[string][]string{}
	var names []string
	for i := range fleet.HopCap {
		for _, mid := range []string{"mid1", "mid2"} {
			n := fmt.Sprintf("%s-w%d", mid, i)
			names = append(names, n)
			chains[n] = []string{"edge", mid}
		}
	}
	plans := levelPlans(t, names...)
	for i := range plans {
		plans[i].Server.Via = chains[plans[i].Server.Name][1]
	}
	w := &orderWriter{hold: 30 * time.Millisecond}
	Execute(context.Background(), plans, w, levelOpts(t, chainOf(chains)))
	if p := w.peak.Load(); p > fleet.HopCap/2 {
		t.Errorf("peak writes through edge = %d, want at most %d", p, fleet.HopCap/2)
	}
}

// TestExecutePassesProbeForward: the plan's forward target reaches the
// writer.
func TestExecutePassesProbeForward(t *testing.T) {
	plans := levelPlans(t, "bastion-eu")
	plans[0].ProbeForward = "10.0.1.5:22"
	f := &fakeWriter{}
	Execute(context.Background(), plans, f, levelOpts(t, nil))
	if got := f.calls["bastion-eu"].ProbeForward; got != "10.0.1.5:22" {
		t.Errorf("ProbeForward = %q, want 10.0.1.5:22", got)
	}
}

// holdWriter holds every write until ctx ends and then a little longer, so
// the bastion slots stay taken while a queued write's wait is canceled.
type holdWriter struct {
	started atomic.Int32
	cancel  context.CancelFunc // called once the bastion's slots are all taken
}

func (w *holdWriter) Apply(ctx context.Context, _ config.Server, _ fleet.WriteRequest) error {
	if w.started.Add(1) == fleet.HopCap/2 {
		w.cancel()
	}
	<-ctx.Done()
	time.Sleep(50 * time.Millisecond)
	return nil
}

// TestExecuteCancelWhileWaitingForBastion: Ctrl-C while a write waits for
// a slot on a full bastion leaves it pending and counted as interrupted,
// never started.
func TestExecuteCancelWhileWaitingForBastion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	names := []string{"w1", "w2", "w3", "w4", "w5"}
	chains := map[string][]string{}
	for _, n := range names {
		chains[n] = []string{"edge"}
	}
	plans := levelPlans(t, names...)
	w := &holdWriter{cancel: cancel}
	Execute(ctx, plans, w, levelOpts(t, chainOf(chains)))
	if got := w.started.Load(); got != fleet.HopCap/2 {
		t.Fatalf("writes started = %d, want %d (the bastion's slots)", got, fleet.HopCap/2)
	}
	if n := Interrupted(plans); n != 1 {
		t.Errorf("Interrupted = %d, want 1: the write waiting for the bastion is pending", n)
	}
}

// TestExecuteCancelBetweenLevels: Ctrl-C during the dependents' level
// leaves the bastion pending, never started.
func TestExecuteCancelBetweenLevels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	plans := levelPlans(t, "b", "a")
	f := &fakeWriter{onCall: func(string) { cancel() }}
	Execute(ctx, plans, f, levelOpts(t, chainOf(map[string][]string{"a": {"b"}})))
	if _, wrote := f.calls["b"]; wrote || Interrupted(plans) != 1 {
		t.Errorf("calls = %v, Interrupted = %d; want only a written and b pending", f.calls, Interrupted(plans))
	}
}
