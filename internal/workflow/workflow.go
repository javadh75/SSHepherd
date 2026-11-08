// Package workflow is the write workflow shared by apply, revoke and
// rotate. It owns the ordering every write command relies on — read and
// plan; confirm; re-list held keys; commit the manifest exactly once,
// after confirmation and before the first write; write; report the
// outcome — behind seams, so it imports no transport and no CLI.
package workflow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
)

// Stage tells the caller how far the run got.
type Stage int

// The stages, in the order a run can reach them.
const (
	StagePlanned   Stage = iota // plan shown, nothing confirmed: dry run, or nothing to confirm
	StageDeclined               // the confirmation was declined
	StageConfirmed              // confirmed: the commit passed and the writes (if any) ran
	StageWithheld               // Question or Commit withheld the run: nothing saved or written
)

// ErrWithheld ends the run as StageWithheld when Request.Question or Commit
// returns it (or wraps it); it is not a tool error. The seam logs why.
var ErrWithheld = errors.New("run withheld: nothing saved or written")

// ErrInterrupted wraps ctx's error when the run was interrupted before
// the plan existed (nothing rendered, saved or written).
var ErrInterrupted = errors.New("interrupted")

// Confirmer asks the one confirmation question.
type Confirmer interface {
	Confirm(ctx context.Context, question string) (bool, error)
}

// ManifestCommitter commits the run's manifest side.
type ManifestCommitter interface {
	// Commit runs exactly once, after confirmation and — when a server
	// will be written — after the held-key re-list (fresh), before any
	// write; fresh is nil when nothing will be written. saved reports
	// that the manifest file was written.
	Commit(ctx context.Context, plans []apply.ServerPlan, fresh []fleet.HeldKey) (saved bool, err error)
}

// Reporter receives the report hooks, in run order.
type Reporter interface {
	Header()                                                // before anything connects
	ReadDone(results []audit.ServerResult, start time.Time) // phase 1 finished
	Planned(plans []apply.ServerPlan)                       // the plan report
}

// HeldLister lists the keys the run holds now (identity files + agent).
type HeldLister interface {
	Held(ctx context.Context) ([]fleet.HeldKey, error)
}

// ConfirmFunc adapts a function to Confirmer.
type ConfirmFunc func(context.Context, string) (bool, error)

// Confirm calls f.
func (f ConfirmFunc) Confirm(ctx context.Context, question string) (bool, error) {
	return f(ctx, question)
}

// CommitFunc adapts a function to ManifestCommitter.
type CommitFunc func(context.Context, []apply.ServerPlan, []fleet.HeldKey) (bool, error)

// Commit calls f.
func (f CommitFunc) Commit(ctx context.Context, plans []apply.ServerPlan, fresh []fleet.HeldKey) (bool, error) {
	return f(ctx, plans, fresh)
}

// Request is one write run: what to plan, the seams, and the run's knobs.
type Request struct {
	Cfg              *config.Config  // the config the plan renders (the edited one for revoke/rotate)
	Servers          []config.Server // the servers to plan, manifest order; never empty
	Held             []fleet.HeldKey // preflight listing: the plan-time guard's ground truth
	Reader           audit.KeyReader
	Writer           apply.Writer
	Relister         HeldLister
	RelistLabel      string // failed re-list log prefix
	Parallel         int
	PerServerTimeout time.Duration
	DryRun           bool
	AlwaysConfirm    bool // ask even when nothing is written (the edit is itself a change)
	// Question returns the confirmation question, ErrWithheld (wrapped is
	// fine) to withhold the run, or a tool error.
	Question  func(plans []apply.ServerPlan, toWrite int) (string, error)
	Confirmer Confirmer
	Committer ManifestCommitter
	Reporter  Reporter
	Log       *slog.Logger
}

// Outcome is how far a run got: its stage, whether the manifest was
// saved, and the plans (with phase 2's outcomes when writes ran).
type Outcome struct {
	Stage Stage
	Saved bool
	Plans []apply.ServerPlan
}

// ExitCode is 1 when the run was withheld or declined or any server did
// not converge, else 0 (apply.ExitCode).
func (o Outcome) ExitCode() int {
	if o.Stage == StageWithheld || o.Stage == StageDeclined {
		return 1
	}
	return apply.ExitCode(o.Plans)
}

// Apply runs the write workflow: report header, phase-1 read and plan,
// the plan report, then — unless a dry run or nothing to confirm — the
// question, the confirmation, the held-key re-list (only when a server
// will be written), the commit and the writes. A tool error (a seam's
// own, or ErrInterrupted before the plan) returns a zero Outcome.
func Apply(ctx context.Context, req Request) (Outcome, error) {
	req.Reporter.Header()
	plans, err := plan(ctx, req)
	if err != nil {
		return Outcome{}, err
	}
	req.Reporter.Planned(plans)
	out := Outcome{Plans: plans}
	toWrite := apply.CountChanges(plans)
	if req.DryRun || (toWrite == 0 && !req.AlwaysConfirm) {
		out.Stage = StagePlanned // a preview, or nothing to confirm
		return out, nil
	}
	return confirmAndWrite(ctx, req, out, toWrite)
}

// plan is phase 1: audit's pipeline over req.Servers, then apply.Build.
func plan(ctx context.Context, req Request) ([]apply.ServerPlan, error) {
	req.Log.Info(fmt.Sprintf("planning %s (parallelism %d)…", apply.Plural(len(req.Servers), "server", "servers"), req.Parallel))
	start := time.Now()
	results := audit.Run(ctx, req.Cfg, req.Reader, audit.Options{
		Parallel: req.Parallel, PerServerTimeout: req.PerServerTimeout, Servers: req.Servers, Logger: req.Log,
	})
	req.Reporter.ReadDone(results, start)
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInterrupted, err) // nothing written: phase 2 never started
	}
	plans, err := apply.Build(req.Cfg, results, req.Held)
	if err != nil {
		return nil, fmt.Errorf("plan: %w", err)
	}
	return plans, nil
}

// confirmAndWrite is everything after the plan report. The prompt can
// wait indefinitely: agent keys may expire (ssh-add -t) or be removed, or
// the agent vanish, meanwhile — so when a server will be written the held
// keys are re-listed first, and the per-server guard re-check and the
// post-write login probe use what is held now. A degraded listing (agent
// gone, key files left) is used as is, never replaced; only a failed
// listing leaves it empty, which fails every write through the guard
// rather than guessing. The commit runs after the re-list and before any
// write; its error writes nothing.
func confirmAndWrite(ctx context.Context, req Request, out Outcome, toWrite int) (Outcome, error) {
	question, err := req.Question(out.Plans, toWrite)
	if err != nil {
		return withheld(out, err)
	}
	ok, err := req.Confirmer.Confirm(ctx, question)
	if err != nil {
		return Outcome{}, err //nolint:wrapcheck // the caller's own seam error, returned verbatim (exit-3 text is user-facing)
	}
	if !ok {
		out.Stage = StageDeclined
		return out, nil
	}
	var fresh []fleet.HeldKey
	if toWrite > 0 {
		req.Log.Info(fmt.Sprintf("applying %s (parallelism %d)…", apply.Plural(toWrite, "server", "servers"), req.Parallel))
		if fresh, err = req.Relister.Held(ctx); err != nil {
			req.Log.Error(fmt.Sprintf("%s: %v — no server will be written", req.RelistLabel, err))
			fresh = nil
		}
	}
	if out.Saved, err = req.Committer.Commit(ctx, out.Plans, fresh); err != nil {
		out.Saved = false
		return withheld(out, err)
	}
	if toWrite > 0 {
		apply.Execute(ctx, out.Plans, req.Writer, apply.ExecOptions{
			Parallel: req.Parallel, PerServerTimeout: req.PerServerTimeout, Held: fresh, Logger: req.Log,
		})
		if n := apply.Interrupted(out.Plans); n > 0 {
			req.Log.Error("interrupted: " + apply.Plural(n, "server", "servers") + " not started (nothing written there); started writes finished")
		}
	}
	out.Stage = StageConfirmed
	return out, nil
}

// withheld maps ErrWithheld to StageWithheld (the plans are untouched:
// no write started); any other error is a tool error.
func withheld(out Outcome, err error) (Outcome, error) {
	if errors.Is(err, ErrWithheld) {
		out.Stage = StageWithheld
		return out, nil
	}
	return Outcome{}, err //nolint:wrapcheck // the caller's own seam error, returned verbatim
}
