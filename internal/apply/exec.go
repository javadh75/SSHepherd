package apply

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
)

// Writer is the phase-2 seam; the transport implements it (cmd wires
// sshwrite.FleetWriter).
type Writer interface {
	Apply(ctx context.Context, srv config.Server, req fleet.WriteRequest) error
}

// ExecOptions tunes the phase-2 fan-out; mirrors audit.Options.
type ExecOptions struct {
	Parallel         int           // max concurrent server writes (>= 1)
	PerServerTimeout time.Duration // bounds each server's connect; a started write always finishes
	// Held is the run's held-key listing taken AFTER
	// the confirmation prompt — not the one Build saw: agent keys can
	// expire (ssh-add -t), be deleted, or the agent be locked or vanish
	// while the prompt waits. The guard is re-run per plan against it, and
	// its surviving keys are what the post-write login probe offers.
	Held   []fleet.HeldKey
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
	var inflight atomic.Int32
	stop := context.AfterFunc(ctx, func() { interruptNotice(log, int(inflight.Load())) })
	defer stop()
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
			inflight.Add(1)
			defer inflight.Add(-1)
			applyOne(ctx, &plans[i], w, held, opts.PerServerTimeout, log)
		}()
	}
	wg.Wait()
}

// interruptNotice tells the operator what the first Ctrl-C will not stop.
func interruptNotice(log *slog.Logger, n int) {
	if n > 0 {
		log.Warn(fmt.Sprintf("interrupt: finishing %s (write, verify, login check — up to 2m); a second Ctrl-C abandons their login check and rollback",
			Plural(n, "in-flight write", "in-flight writes")))
	}
}

// applyOne writes one server. The guard re-check is authoritative: Build
// refused guard failures against the pre-prompt listing, and this re-runs
// the same check against the fresh one, so no code path reaches a write
// without the invariant holding right now.
func applyOne(ctx context.Context, p *ServerPlan, w Writer, held []fleet.HeldKey, timeout time.Duration, log *slog.Logger) {
	surviving := Survivors(p.Desired, heldSet(held))
	if len(surviving) == 0 {
		p.Outcome = OutcomeFailed
		p.OutcomeErr = errors.New("guard re-check failed — none of this server's surviving keys is still held (identity files + agent; a key expired or was removed after the plan?) — refusing to write")
		log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, p.OutcomeErr))
		return
	}
	req := requestFor(p, surviving, held, log)
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	start := time.Now()
	err := w.Apply(ctx, p.Server, req)
	switch {
	case err == nil:
		p.Outcome = OutcomeApplied
		log.Debug("applied", "server", p.Server.Name, "dur", time.Since(start).Round(time.Millisecond))
		return
	case errors.Is(err, fleet.ErrWriteNotStarted):
		p.OutcomeErr = errInterrupted // nothing changed: stays pending
		return
	case fleet.IsRefusal(err):
		p.Outcome = OutcomeRefused
	default:
		p.Outcome, p.RolledBack = failureOutcome(err)
	}
	p.OutcomeErr = err
	log.Warn(fmt.Sprintf("%s: %v", p.Server.Name, err))
}

// requestFor builds one server's write request. OnWarning runs on this
// server's goroutine, its only writer.
func requestFor(p *ServerPlan, surviving []authkeys.Key, held []fleet.HeldKey, log *slog.Logger) fleet.WriteRequest {
	fps := probeOrderFor(p.Desired, surviving)
	proof, paths := headlessProofFor(fps, surviving, held)
	return fleet.WriteRequest{
		Content: p.Rendered, Expect: p.Expect, Survivors: fps,
		DisableKeys2: p.DisableKeys2(), SkipWrite: p.KeysUnchanged(), HeadlessProof: proof,
		OnWarning: func(cause string) {
			text := headlessWarning(paths, collapse(cause))
			p.Warnings = append(p.Warnings, text)
			log.Warn(p.Server.Name + ": " + text)
		},
	}
}

// headlessProofFor is D9b's condition: the production order proves an agent
// key first, and a surviving key file's line is unrestricted (OfferRank 0).
// It returns those key files' fingerprints and paths, in production order.
func headlessProofFor(fps []string, surviving []authkeys.Key, held []fleet.HeldKey) (proof, paths []string) {
	src := sourceMap(held)
	if len(fps) == 0 || src[fps[0]] != fleet.SourceAgent {
		return nil, nil
	}
	unrestricted := make(map[string]bool, len(surviving))
	for _, k := range surviving {
		if authkeys.OfferRank(k.Options) == 0 {
			unrestricted[k.Fingerprint] = true
		}
	}
	for _, fp := range fps {
		if unrestricted[fp] && src[fp] != fleet.SourceAgent {
			proof, paths = append(proof, fp), append(paths, src[fp])
		}
	}
	return proof, paths
}

// headlessWarning is the D9b warning's text, on stderr and in JSON alike.
func headlessWarning(paths []string, cause string) string {
	if len(paths) == 1 {
		return fmt.Sprintf("your --identity key %s could not log in on its own (%s); a headless run with only that key would fail", paths[0], cause)
	}
	return fmt.Sprintf("your --identity keys %s could not log in on their own (%s); a headless run with only those keys would fail", strings.Join(paths, ", "), cause)
}

// failureOutcome maps a started write's failure to its outcome, and whether
// the previous file was restored. A failed authorized_keys2 move-back is an
// unrestored lockout even when authorized_keys went back: a key whose
// authorized_keys line refuses this client (from=) may have logged in only
// through authorized_keys2.
func failureOutcome(err error) (Outcome, bool) {
	var unproven *fleet.UnprovenError
	if errors.As(err, &unproven) {
		return OutcomeUnproven, false
	}
	var lockout *fleet.LockoutError
	if errors.As(err, &lockout) {
		restored := lockout.Restore == nil && !lockout.FileKept
		if lockout.Restore != nil || lockout.RestoreKeys2 != nil {
			return OutcomeLockoutUnrestored, restored
		}
		return OutcomeFailed, restored
	}
	return OutcomeFailed, false
}

// probeOrderFor returns what the post-write probe offers: the survivors in
// the order every later connection offers them (authkeys.OfferOrder over the
// plan's desired keys — what GrantedFingerprints hands the Dialer). The
// probe therefore proves exactly the key the next run logs in with, and a
// forced command= line is offered only after every plain survivor.
func probeOrderFor(desired, surviving []authkeys.Key) []string {
	keep := make(map[string]bool, len(surviving))
	for _, k := range surviving {
		keep[k.Fingerprint] = true
	}
	var order []string
	for _, fp := range authkeys.OfferOrder(desired) {
		if keep[fp] {
			order = append(order, fp)
			delete(keep, fp)
		}
	}
	return order
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
