package workflow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// rec records the seam calls in order. Writes run on Execute's workers,
// so it is locked.
type rec struct {
	mu     sync.Mutex
	events []string
	reads  int // Reporter.ReadDone calls
}

func (r *rec) add(e string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// fakeReader serves each server's file by name; a missing name is an
// unreachable server. onRead, when set, runs before every read.
type fakeReader struct {
	content map[string]string
	onRead  func()
}

func (f fakeReader) ReadAuthorizedKeys(_ context.Context, s config.Server) (fleet.ReadResult, error) {
	if f.onRead != nil {
		f.onRead()
	}
	c, ok := f.content[s.Name]
	if !ok {
		return fleet.ReadResult{}, errors.New("dial: refused")
	}
	return fleet.ReadResult{Content: []byte(c)}, nil
}

// HeldFunc adapts a function to HeldLister. Test-only: cmd passes its
// *sshconn.Credentials, so a production adapter would be dead code.
type HeldFunc func(context.Context) ([]fleet.HeldKey, error)

func (f HeldFunc) Held(ctx context.Context) ([]fleet.HeldKey, error) { return f(ctx) }

type fakeWriter struct{ r *rec }

func (w fakeWriter) Apply(_ context.Context, s config.Server, _ fleet.WriteRequest) error {
	w.r.add("write:" + s.Name)
	return nil
}

// nopReporter records the report hooks it is handed.
type nopReporter struct{ r *rec }

func (n nopReporter) Header() { n.r.add("header") }

func (n nopReporter) ReadDone(results []audit.ServerResult, _ time.Time) {
	n.r.mu.Lock()
	defer n.r.mu.Unlock()
	n.r.reads += len(results)
}

func (n nopReporter) Planned([]apply.ServerPlan) { n.r.add("planned") }

// msgs is a slog handler that keeps each info-or-louder record's message
// (the phase lines; Execute logs from its workers, so it is locked).
type msgs struct {
	mu   *sync.Mutex
	list *[]string
}

func newMsgs() msgs { return msgs{mu: &sync.Mutex{}, list: &[]string{}} }

func (m msgs) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }
func (m msgs) Handle(_ context.Context, rec slog.Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	*m.list = append(*m.list, rec.Message)
	return nil
}
func (m msgs) WithAttrs([]slog.Attr) slog.Handler { return m }
func (m msgs) WithGroup(string) slog.Handler      { return m }

func (m msgs) all() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(*m.list)
}

// seq is a slog handler that records each info-or-louder message into
// the seam recorder as "log:<msg>", so log lines and seam calls share one
// ordered sequence.
type seq struct{ r *rec }

func (s seq) Enabled(_ context.Context, l slog.Level) bool { return l >= slog.LevelInfo }
func (s seq) Handle(_ context.Context, rec slog.Record) error {
	s.r.add("log:" + rec.Message)
	return nil
}
func (s seq) WithAttrs([]slog.Attr) slog.Handler { return s }
func (s seq) WithGroup(string) slog.Handler      { return s }

func (m msgs) has(t *testing.T, want string) {
	t.Helper()
	for _, s := range m.all() {
		if strings.Contains(s, want) {
			return
		}
	}
	t.Errorf("no log line contains %q in %q", want, m.all())
}

// fixture: one server "a" granted key 1, currently empty → one change
// plan; held = key 1 (agent) so the guard passes. Built from testkeys
// like internal/apply's plan tests (testkeys.Line(t, 1)).
func fixture(t *testing.T, r *rec) Request {
	t.Helper()
	line := testkeys.Line(t, 1)
	k, err := authkeys.ParseLine(line)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte("users:\n  - {name: alice, keys: [\"" + line + "\"]}\n" +
		"servers:\n  - {name: a, host: 10.0.0.1, user: deploy}\n" +
		"access:\n  - {user: alice, servers: [a]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	held := []fleet.HeldKey{{Fingerprint: k.Fingerprint, Source: fleet.SourceAgent}}
	return Request{
		Cfg:      cfg,
		Servers:  cfg.Servers,
		Held:     held,
		Reader:   fakeReader{content: map[string]string{"a": ""}},
		Writer:   fakeWriter{r},
		Relister: HeldFunc(func(context.Context) ([]fleet.HeldKey, error) { r.add("relist"); return held, nil }),
		Question: func([]apply.ServerPlan, int) (string, error) { r.add("question"); return "go?", nil },
		Confirmer: ConfirmFunc(func(context.Context, string) (bool, error) {
			r.add("confirm")
			return true, nil
		}),
		Committer: CommitFunc(func(context.Context, []apply.ServerPlan, []fleet.HeldKey) (bool, error) {
			r.add("commit")
			return true, nil
		}),
		Reporter: nopReporter{r},
		Parallel: 2,
		Log:      slog.New(slog.DiscardHandler),
	}
}

func TestApplyOrdering(t *testing.T) {
	r := &rec{}
	req := fixture(t, r)
	req.Log = slog.New(seq{r}) // logs and seam calls in one sequence
	req.RelistLabel = "re-listing agent keys after confirmation"
	var question string
	var gotFresh []fleet.HeldKey
	req.Confirmer = ConfirmFunc(func(_ context.Context, q string) (bool, error) {
		r.add("confirm")
		question = q
		return true, nil
	})
	req.Committer = CommitFunc(func(_ context.Context, _ []apply.ServerPlan, fresh []fleet.HeldKey) (bool, error) {
		r.add("commit")
		gotFresh = fresh
		return true, nil
	})
	out, err := Apply(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	// The "applying" line comes before the held-key re-list: the re-list
	// may take a moment (or fail), and the user should see the write
	// phase has begun.
	want := []string{
		"header", "log:planning 1 server (parallelism 2)…", "planned", "question", "confirm",
		"log:applying 1 server (parallelism 2)…", "relist", "commit", "write:a",
	}
	if !slices.Equal(r.events, want) {
		t.Fatalf("events = %v, want %v", r.events, want)
	}
	if out.Stage != StageConfirmed || !out.Saved || out.ExitCode() != 0 {
		t.Fatalf("outcome = %+v", out)
	}
	if len(out.Plans) != 1 || out.Plans[0].Outcome != apply.OutcomeApplied {
		t.Fatalf("plans = %+v", out.Plans)
	}
	if question != "go?" || !slices.Equal(gotFresh, req.Held) || r.reads != 1 {
		t.Errorf("question = %q, fresh = %v, reads = %d", question, gotFresh, r.reads)
	}
}

// convergedContent is the bytes server a must hold to be converged: the
// fixture's own render, taken from a dry run.
func convergedContent(t *testing.T) string {
	t.Helper()
	req := fixture(t, &rec{})
	req.DryRun = true
	out, err := Apply(context.Background(), req)
	if err != nil || len(out.Plans) != 1 {
		t.Fatalf("dry run: %v %+v", err, out)
	}
	return string(out.Plans[0].Rendered)
}

func TestApplyCases(t *testing.T) {
	converged := convergedContent(t)
	errManifest := errors.New("manifest changed")
	errConfirm := errors.New("confirmation required: re-run with --yes")
	errQuestion := errors.New("question broke")
	errRelist := errors.New("agent gone")
	for _, tt := range []struct {
		name string
		// mod overrides the fixture; cancel cancels the run's context.
		mod    func(req *Request, r *rec, cancel context.CancelFunc)
		events []string
		stage  Stage
		saved  bool
		exit   int
		err    error // errors.Is target; nil = no error
		// wrapped: err may be wrapped (ErrInterrupted). Otherwise the seam's
		// own error must come back verbatim — its text is the exit-3 message.
		wrapped   bool
		outcome   apply.Outcome
		outErrNil bool   // the plan's OutcomeErr must stay nil
		log       string // a log line that must appear
	}{
		{
			name:    "dry run",
			mod:     func(req *Request, _ *rec, _ context.CancelFunc) { req.DryRun = true },
			events:  []string{"header", "planned"},
			stage:   StagePlanned,
			exit:    1, // pending change
			outcome: apply.OutcomePending,
		},
		{
			name: "nothing to confirm",
			mod: func(req *Request, _ *rec, _ context.CancelFunc) {
				req.Reader = fakeReader{content: map[string]string{"a": converged}}
			},
			events:  []string{"header", "planned"},
			stage:   StagePlanned,
			outcome: apply.OutcomePending,
		},
		{
			name: "always-confirm, no writes",
			mod: func(req *Request, r *rec, _ context.CancelFunc) {
				req.Reader = fakeReader{content: map[string]string{"a": converged}}
				req.AlwaysConfirm = true
				req.Committer = CommitFunc(func(_ context.Context, _ []apply.ServerPlan, fresh []fleet.HeldKey) (bool, error) {
					r.add(fmt.Sprintf("commit fresh=%v", fresh != nil))
					return true, nil
				})
			},
			events:  []string{"header", "planned", "question", "confirm", "commit fresh=false"},
			stage:   StageConfirmed,
			saved:   true,
			outcome: apply.OutcomePending,
		},
		{
			name: "declined",
			mod: func(req *Request, r *rec, _ context.CancelFunc) {
				req.Confirmer = ConfirmFunc(func(context.Context, string) (bool, error) { r.add("confirm"); return false, nil })
			},
			events:  []string{"header", "planned", "question", "confirm"},
			stage:   StageDeclined,
			exit:    1,
			outcome: apply.OutcomePending,
		},
		{
			name: "question withholds",
			mod: func(req *Request, r *rec, _ context.CancelFunc) {
				req.Question = func([]apply.ServerPlan, int) (string, error) {
					r.add("question")
					return "", fmt.Errorf("nothing can land: %w", ErrWithheld)
				}
			},
			events:  []string{"header", "planned", "question"},
			stage:   StageWithheld,
			exit:    1,
			outcome: apply.OutcomePending,
		},
		{
			name: "question tool error",
			mod: func(req *Request, r *rec, _ context.CancelFunc) {
				req.Question = func([]apply.ServerPlan, int) (string, error) { r.add("question"); return "", errQuestion }
			},
			events: []string{"header", "planned", "question"},
			err:    errQuestion,
		},
		{
			name: "commit withholds",
			mod: func(req *Request, r *rec, _ context.CancelFunc) {
				req.Committer = CommitFunc(func(context.Context, []apply.ServerPlan, []fleet.HeldKey) (bool, error) {
					r.add("commit")
					return true, fmt.Errorf("x: %w", ErrWithheld)
				})
			},
			events:    []string{"header", "planned", "question", "confirm", "relist", "commit"},
			stage:     StageWithheld,
			exit:      1,
			outcome:   apply.OutcomePending,
			outErrNil: true,
		},
		{
			name: "commit tool error",
			mod: func(req *Request, r *rec, _ context.CancelFunc) {
				req.Committer = CommitFunc(func(context.Context, []apply.ServerPlan, []fleet.HeldKey) (bool, error) {
					r.add("commit")
					return false, errManifest
				})
			},
			events: []string{"header", "planned", "question", "confirm", "relist", "commit"},
			err:    errManifest,
		},
		{
			name: "confirm tool error",
			mod: func(req *Request, r *rec, _ context.CancelFunc) {
				req.Confirmer = ConfirmFunc(func(context.Context, string) (bool, error) { r.add("confirm"); return false, errConfirm })
			},
			events: []string{"header", "planned", "question", "confirm"},
			err:    errConfirm,
		},
		{
			name: "relist fails",
			mod: func(req *Request, r *rec, _ context.CancelFunc) {
				req.RelistLabel = "re-listing the keys you hold after confirmation"
				req.Relister = HeldFunc(func(context.Context) ([]fleet.HeldKey, error) { r.add("relist"); return nil, errRelist })
				req.Committer = CommitFunc(func(_ context.Context, _ []apply.ServerPlan, fresh []fleet.HeldKey) (bool, error) {
					r.add(fmt.Sprintf("commit fresh=%v", fresh != nil))
					return true, nil
				})
			},
			events:  []string{"header", "planned", "question", "confirm", "relist", "commit fresh=false"},
			stage:   StageConfirmed,
			saved:   true,
			exit:    1,
			outcome: apply.OutcomeFailed,
			log:     "re-listing the keys you hold after confirmation: agent gone — no server will be written",
		},
		{
			name: "interrupted before the writes",
			mod: func(req *Request, r *rec, cancel context.CancelFunc) {
				req.Committer = CommitFunc(func(context.Context, []apply.ServerPlan, []fleet.HeldKey) (bool, error) {
					r.add("commit")
					cancel()
					return true, nil
				})
			},
			events:  []string{"header", "planned", "question", "confirm", "relist", "commit"},
			stage:   StageConfirmed,
			saved:   true,
			exit:    1,
			outcome: apply.OutcomePending,
			log:     "interrupted: 1 server not started (nothing written there); started writes finished",
		},
		{
			name: "interrupted after read",
			mod: func(req *Request, _ *rec, cancel context.CancelFunc) {
				req.Reader = fakeReader{content: map[string]string{"a": ""}, onRead: cancel}
			},
			events:  []string{"header"},
			err:     ErrInterrupted,
			wrapped: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &rec{}
			req := fixture(t, r)
			logs := newMsgs()
			req.Log = slog.New(logs)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tt.mod(&req, r, cancel)
			out, err := Apply(ctx, req)
			if !slices.Equal(r.events, tt.events) {
				t.Errorf("events = %v, want %v", r.events, tt.events)
			}
			if tt.log != "" {
				logs.has(t, tt.log)
			}
			if tt.err != nil {
				if !errors.Is(err, tt.err) {
					t.Fatalf("err = %v, want %v", err, tt.err)
				}
				if !tt.wrapped && err.Error() != tt.err.Error() {
					t.Errorf("err = %q, want the seam's error verbatim: %q", err, tt.err)
				}
				if out.Plans != nil {
					t.Errorf("a tool error returns no outcome: %+v", out)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if out.Stage != tt.stage || out.Saved != tt.saved || out.ExitCode() != tt.exit {
				t.Errorf("outcome = stage %v saved %v exit %d, want stage %v saved %v exit %d",
					out.Stage, out.Saved, out.ExitCode(), tt.stage, tt.saved, tt.exit)
			}
			if len(out.Plans) != 1 || out.Plans[0].Outcome != tt.outcome {
				t.Fatalf("plans = %+v, want outcome %v", out.Plans, tt.outcome)
			}
			if tt.outErrNil && out.Plans[0].OutcomeErr != nil {
				t.Errorf("OutcomeErr = %v, want nil", out.Plans[0].OutcomeErr)
			}
		})
	}
}

// TestApplyInterruptedWraps: the interrupt error carries both the marker
// and ctx's own error, and nothing is planned or reported.
func TestApplyInterruptedWraps(t *testing.T) {
	r := &rec{}
	req := fixture(t, r)
	ctx, cancel := context.WithCancel(context.Background())
	req.Reader = fakeReader{content: map[string]string{"a": ""}, onRead: cancel}
	_, err := Apply(ctx, req)
	if !errors.Is(err, ErrInterrupted) || !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if r.reads != 1 {
		t.Errorf("ReadDone saw %d results, want 1 (the done line is logged before the interrupt check)", r.reads)
	}
}

func TestOutcomeExitCode(t *testing.T) {
	conv := []apply.ServerPlan{{Class: apply.ClassConverged}}
	pending := []apply.ServerPlan{{Class: apply.ClassChange, Outcome: apply.OutcomePending}}
	for _, tt := range []struct {
		name string
		out  Outcome
		want int
	}{
		{"planned converged", Outcome{Stage: StagePlanned, Plans: conv}, 0},
		{"planned pending", Outcome{Stage: StagePlanned, Plans: pending}, 1},
		{"confirmed converged", Outcome{Stage: StageConfirmed, Plans: conv}, 0},
		{"withheld converged", Outcome{Stage: StageWithheld, Plans: conv}, 1},
		{"declined converged", Outcome{Stage: StageDeclined, Plans: conv}, 1},
	} {
		if got := tt.out.ExitCode(); got != tt.want {
			t.Errorf("%s: ExitCode = %d, want %d", tt.name, got, tt.want)
		}
	}
}
