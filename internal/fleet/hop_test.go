package fleet

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

type hopErr struct{ hop string }

func (e hopErr) Error() string     { return "via " + e.hop + ": refused" }
func (e hopErr) FailedHop() string { return e.hop }

func TestFailedHopOf(t *testing.T) {
	if got := FailedHopOf(fmt.Errorf("read web-1: %w", hopErr{"bastion-eu"})); got != "bastion-eu" {
		t.Errorf("FailedHopOf(wrapped) = %q, want bastion-eu", got)
	}
	if got := FailedHopOf(errors.New("plain")); got != "" {
		t.Errorf("FailedHopOf(plain) = %q, want empty", got)
	}
	if got := FailedHopOf(nil); got != "" {
		t.Errorf("FailedHopOf(nil) = %q, want empty", got)
	}
}

func acquireOK(t *testing.T, l *HopLimiter, chain []string, n int) func() {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	release, err := l.Acquire(ctx, chain, n)
	if err != nil {
		t.Fatalf("Acquire(%v, %d): %v", chain, n, err)
	}
	return release
}

// TestHopLimiterCap (OP2): HopCap holders of one bastion, never more; a
// waiter gets the first released slot; another bastion is unaffected.
func TestHopLimiterCap(t *testing.T) {
	var l HopLimiter
	var releases []func()
	for range HopCap {
		releases = append(releases, acquireOK(t, &l, []string{"edge"}, 1))
	}
	got := make(chan func(), 1)
	go func() {
		release, err := l.Acquire(context.Background(), []string{"edge"}, 1)
		if err != nil {
			release = func() {}
		}
		got <- release
	}()
	select {
	case <-got:
		t.Fatal("a ninth connection through one bastion got a slot")
	case <-time.After(50 * time.Millisecond):
	}
	acquireOK(t, &l, []string{"other"}, 1)()
	releases[0]()
	select {
	case release := <-got:
		release()
	case <-time.After(5 * time.Second):
		t.Fatal("the waiter never got the released slot")
	}
	for _, release := range releases[1:] {
		release()
	}
}

// TestHopLimiterTakesBothSlotsTogether: a write takes its two slots as one,
// so with one slot left it waits instead of holding half, and the free slot
// stays free for a read.
func TestHopLimiterTakesBothSlotsTogether(t *testing.T) {
	var l HopLimiter
	var releases []func()
	for range HopCap - 1 {
		releases = append(releases, acquireOK(t, &l, []string{"edge"}, 1))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := l.Acquire(ctx, []string{"edge"}, 2); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("two-slot Acquire with one slot free = %v, want it to wait out its context", err)
	}
	acquireOK(t, &l, []string{"edge"}, 1)()
	for _, release := range releases {
		release()
	}
}

// TestHopLimiterCancelReleasesWhatItTook: canceled while waiting on the
// second bastion of a chain, Acquire gives the first one's slot back.
func TestHopLimiterCancelReleasesWhatItTook(t *testing.T) {
	var l HopLimiter
	var releases []func()
	for range HopCap {
		releases = append(releases, acquireOK(t, &l, []string{"mid"}, 1))
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	if _, err := l.Acquire(ctx, []string{"edge", "mid"}, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("Acquire = %v, want context.Canceled", err)
	}
	for range HopCap {
		releases = append(releases, acquireOK(t, &l, []string{"edge"}, 1))
	}
	for _, release := range releases {
		release()
	}
}

// TestHopLimiterEmptyChain: a direct server takes nothing.
func TestHopLimiterEmptyChain(t *testing.T) {
	var l HopLimiter
	acquireOK(t, &l, nil, 2)()
}
