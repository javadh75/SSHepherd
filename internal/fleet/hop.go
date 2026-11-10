package fleet

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// HopCap is the most connections SSHepherd keeps open through one bastion at
// a time (OP2): below sshd's default MaxStartups 10:30:100, so a fan-out
// never trips the bastion's own throttling. A constant, with no flag.
const HopCap = 8

// HopFailure is implemented by connection errors that failed at a bastion
// (sshconn.Error with HopStage set): reaching it, or its refusal to forward.
// Domain code reads it through FailedHopOf, never the transport type.
type HopFailure interface {
	error
	FailedHop() string
}

// FailedHopOf names the bastion at which err's connection failed: the JSON
// reports' via_failed. "" when err did not fail at a bastion.
func FailedHopOf(err error) string {
	var h HopFailure
	if errors.As(err, &h) {
		return h.FailedHop()
	}
	return ""
}

// HopLimiter caps the connections in flight through each bastion at HopCap.
// audit.Run and apply.Execute take a server's slots at the fan-out, before
// its per-server budget starts, so waiting for a slot never uses up its
// timeout. Use it by pointer; the zero value is ready.
type HopLimiter struct {
	mu   sync.Mutex
	used map[string]int
	wake chan struct{} // closed on every release; nil while nobody waits
}

// Acquire takes n slots on every bastion of chain, root first as
// config.Config.Chain lists it, waiting while one is full, and returns the
// release. The n slots of one bastion are taken together, and every caller
// walks its chain in the same root-first order, so two callers can never
// each hold part of what the other needs. An empty chain takes nothing.
// When ctx ends during a wait, Acquire gives back what it took and returns
// an error wrapping ctx's.
func (l *HopLimiter) Acquire(ctx context.Context, chain []string, n int) (func(), error) {
	var held []string
	for _, hop := range chain {
		if err := l.take(ctx, hop, n); err != nil {
			l.release(held, n)
			return nil, err
		}
		held = append(held, hop)
	}
	return func() { l.release(held, n) }, nil
}

// take waits until n slots of hop are free and takes them.
func (l *HopLimiter) take(ctx context.Context, hop string, n int) error {
	for {
		l.mu.Lock()
		if l.used == nil {
			l.used = make(map[string]int)
		}
		if l.used[hop]+n <= HopCap {
			l.used[hop] += n
			l.mu.Unlock()
			return nil
		}
		if l.wake == nil {
			l.wake = make(chan struct{})
		}
		wake := l.wake
		l.mu.Unlock()
		select {
		case <-wake:
		case <-ctx.Done():
			return fmt.Errorf("wait for a slot on bastion %s: %w", hop, ctx.Err())
		}
	}
}

// release gives n slots of each hop back and wakes every waiter.
func (l *HopLimiter) release(hops []string, n int) {
	if len(hops) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, hop := range hops {
		l.used[hop] -= n
	}
	if l.wake != nil {
		close(l.wake)
		l.wake = nil
	}
}
