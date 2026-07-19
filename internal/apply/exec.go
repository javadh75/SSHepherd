package apply

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
)

// Writer is the phase-2 seam; sshwrite.FleetWriter is the real one.
type Writer interface {
	Apply(ctx context.Context, srv config.Server, content []byte) error
}

// ExecOptions tunes the phase-2 fan-out; mirrors audit.Options.
type ExecOptions struct {
	Parallel         int           // max concurrent server writes (>= 1)
	PerServerTimeout time.Duration // overall deadline per server; 0 = none
	AgentFPs         []string      // guard re-check ground truth — the same list Build saw
	Logger           *slog.Logger  // optional per-server telemetry; nil discards
}

func (o ExecOptions) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// Execute writes every ClassChange plan through w with a bounded pool,
// mutating each plan's Outcome in place; other classes are untouched.
// Servers proceed independently — no global abort: partial application is
// visible in the report and re-running apply is always safe because the
// render is idempotent.
func Execute(ctx context.Context, plans []ServerPlan, w Writer, opts ExecOptions) {
	if opts.Parallel < 1 {
		opts.Parallel = 1
	}
	log := opts.logger()
	held := make(map[string]bool, len(opts.AgentFPs))
	for _, fp := range opts.AgentFPs {
		held[fp] = true
	}
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	for i := range plans {
		if plans[i].Class != ClassChange {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			applyOne(ctx, &plans[i], w, held, opts.PerServerTimeout, log)
		}()
	}
	wg.Wait()
}

// applyOne writes one server. The guard re-check is authoritative and
// defensive: Build already refused guard failures, but no code path may
// reach a write without the invariant holding right now.
func applyOne(ctx context.Context, p *ServerPlan, w Writer, held map[string]bool, timeout time.Duration, log *slog.Logger) {
	if !guardHolds(p, held) {
		p.Outcome = OutcomeFailed
		p.OutcomeErr = errors.New("guard re-check failed — refusing to write (agent changed mid-run, or a bug)")
		log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, p.OutcomeErr))
		return
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	start := time.Now()
	if err := w.Apply(ctx, p.Server, p.Rendered); err != nil {
		var symErr *sshwrite.SymlinkError
		if errors.As(err, &symErr) {
			p.Outcome = OutcomeRefused
		} else {
			p.Outcome = OutcomeFailed
		}
		p.OutcomeErr = err
		log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, err))
		return
	}
	p.Outcome = OutcomeApplied
	log.Debug("applied", "server", p.Server.Name, "dur", time.Since(start).Round(time.Millisecond))
}

// guardHolds re-asserts the lockout invariant against the preflight agent
// list: some desired key is agent-held — or, under the empty-listing
// fallback, the write removes nothing.
func guardHolds(p *ServerPlan, held map[string]bool) bool {
	if len(held) == 0 {
		return len(p.Remove) == 0
	}
	for _, k := range p.Desired {
		if held[k.Fingerprint] {
			return true
		}
	}
	return false
}
