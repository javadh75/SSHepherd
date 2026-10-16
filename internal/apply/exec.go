package apply

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshwrite"
)

// Writer is the phase-2 seam; sshwrite.FleetWriter is the real one.
type Writer interface {
	Apply(ctx context.Context, srv config.Server, req sshwrite.Request) error
}

// ExecOptions tunes the phase-2 fan-out; mirrors audit.Options.
type ExecOptions struct {
	Parallel         int           // max concurrent server writes (>= 1)
	PerServerTimeout time.Duration // bounds each server's connect; a started write always finishes
	// Held is the held-key listing (sshconn.Credentials.Held) taken AFTER
	// the confirmation prompt — not the one Build saw: agent keys can
	// expire (ssh-add -t), be deleted, or the agent be locked or vanish
	// while the prompt waits. The guard is re-run per plan against it, and
	// its surviving keys are what the post-write login probe offers.
	Held   []sshconn.HeldKey
	Logger *slog.Logger // optional per-server telemetry; nil discards
}

func (o ExecOptions) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// errInterrupted marks a plan phase 2 never started because ctx was
// canceled (Ctrl-C/SIGTERM): it stays OutcomePending.
var errInterrupted = errors.New("interrupted before the write started")

// Execute writes every ClassChange plan through w with a bounded pool,
// mutating each plan's Outcome in place; other classes are untouched.
// Servers proceed independently — no global abort: partial application is
// visible in the report and re-running apply is always safe because the
// render is idempotent and every write is conditional on its plan's
// snapshot. Once ctx is canceled no new server starts (those stay pending
// with OutcomeErr set), while a server whose write already began finishes
// its write, verify and login probe.
func Execute(ctx context.Context, plans []ServerPlan, w Writer, opts ExecOptions) {
	if opts.Parallel < 1 {
		opts.Parallel = 1
	}
	log := opts.logger()
	held := opts.Held
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	for i := range plans {
		if plans[i].Class != ClassChange {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				plans[i].OutcomeErr = errInterrupted
				return
			}
			defer func() { <-sem }()
			if ctx.Err() != nil { // both select cases were ready
				plans[i].OutcomeErr = errInterrupted
				return
			}
			applyOne(ctx, &plans[i], w, held, opts.PerServerTimeout, log)
		}()
	}
	wg.Wait()
}

// applyOne writes one server. The guard re-check is authoritative: Build
// refused guard failures against the pre-prompt listing, and this re-runs
// the same check against the fresh one, so no code path reaches a write
// without the invariant holding right now.
func applyOne(ctx context.Context, p *ServerPlan, w Writer, held []sshconn.HeldKey, timeout time.Duration, log *slog.Logger) {
	surviving := Survivors(p.Desired, heldSet(held))
	if len(surviving) == 0 {
		p.Outcome = OutcomeFailed
		p.OutcomeErr = errors.New("guard re-check failed — none of this server's surviving keys is still held (identity files + agent; a key expired or was removed after the plan?) — refusing to write")
		log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, p.OutcomeErr))
		return
	}
	fps := probeOrder(surviving, sourceMap(held))
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	start := time.Now()
	err := w.Apply(ctx, p.Server, sshwrite.Request{Content: p.Rendered, Expect: p.Expect, Survivors: fps, DisableKeys2: p.DisableKeys2()})
	switch {
	case err == nil:
		p.Outcome = OutcomeApplied
		log.Debug("applied", "server", p.Server.Name, "dur", time.Since(start).Round(time.Millisecond))
		return
	case errors.Is(err, sshwrite.ErrNotStarted):
		p.OutcomeErr = errInterrupted // nothing changed: stays pending
		return
	case sshwrite.IsRefusal(err):
		p.Outcome = OutcomeRefused
	default:
		p.Outcome = OutcomeFailed
	}
	p.OutcomeErr = err
	log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, err))
}

// probeOrder orders the survivors the post-write probe offers,
// deterministically across runs: unrestricted first — the probe runs a
// command, sshd authenticates with the first acceptable key, and one whose
// line forces command= (deliberately, say) would fail the probe and roll
// back a write a plain survivor proves safe — then key files before agent
// keys (so when an --identity key survives, the probe proves THAT key: the
// one the next headless run will have), then fingerprint.
func probeOrder(surviving []authkeys.Key, src map[string]string) []string {
	surviving = slices.Clone(surviving)
	rank := func(k authkeys.Key) int {
		r := 0
		if hasRestrictiveOption(k.Options) {
			r += 2
		}
		if src[k.Fingerprint] == sshconn.SourceAgent {
			r++
		}
		return r
	}
	slices.SortFunc(surviving, func(a, b authkeys.Key) int {
		if c := cmp.Compare(rank(a), rank(b)); c != 0 {
			return c
		}
		return strings.Compare(a.Fingerprint, b.Fingerprint)
	})
	fps := make([]string, 0, len(surviving))
	for _, k := range surviving {
		fps = append(fps, k.Fingerprint)
	}
	return fps
}

// Interrupted counts the change plans phase 2 never started because the
// run was interrupted.
func Interrupted(plans []ServerPlan) int {
	n := 0
	for _, p := range plans {
		if p.Class == ClassChange && p.Outcome == OutcomePending && errors.Is(p.OutcomeErr, errInterrupted) {
			n++
		}
	}
	return n
}
