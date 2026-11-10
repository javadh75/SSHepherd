package sshwrite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

func TestClassifyProbe(t *testing.T) {
	sanitized := func(err error) error { return sshconn.SanitizedError{Err: err} }
	for _, tt := range []struct {
		name  string
		stage probeStage
		err   error
		want  verdict
	}{
		{"auth refused", stageDial, kinded(fleet.ErrorKindAuth, "unable to authenticate"), verdictRejected},
		{"auth refused, sanitized", stageDial, sanitized(kinded(fleet.ErrorKindAuth, "x")), verdictRejected},
		{"MaxAuthTries", stageDial, sanitized(&sshconn.Error{Kind: fleet.ErrorKindHandshake, Err: errors.New("x"), AuthExhausted: true}), verdictRejected},
		{"dial", stageDial, kinded(fleet.ErrorKindDial, "x"), verdictTransient},
		{"timeout", stageDial, kinded(fleet.ErrorKindTimeout, "x"), verdictTransient},
		{"handshake", stageDial, kinded(fleet.ErrorKindHandshake, "x"), verdictTransient},
		{"agent", stageDial, kinded(fleet.ErrorKindAgent, "x"), verdictAgent},
		{"host_key_unknown", stageDial, kinded(fleet.ErrorKindHostKeyUnknown, "x"), verdictHostKey},
		{"host_key_changed", stageDial, kinded(fleet.ErrorKindHostKeyChanged, "x"), verdictHostKey},
		{"host_key_type_unrecorded", stageDial, kinded(fleet.ErrorKindHostKeyTypeUnrecorded, "x"), verdictHostKey},
		{"host_key_revoked", stageDial, kinded(fleet.ErrorKindHostKeyRevoked, "x"), verdictHostKey},
		{"host_key", stageDial, kinded(fleet.ErrorKindHostKey, "x"), verdictHostKey},
		{"a future host-key kind", stageDial, kinded("host_key_type_changed", "x"), verdictHostKey},
		{"session channel refused", stageAuthed, fmt.Errorf("open session: %w", &ssh.OpenChannelError{}), verdictRejected},
		{"no exit status", stageAuthed, &ssh.ExitMissingError{}, verdictRejected},
		{"EOF after login", stageAuthed, io.EOF, verdictRejected},
		{"wrong output", stageAuthed, errors.New("probe command did not run as sent"), verdictRejected},
		{"exec deadline", stageAuthed, kinded(fleet.ErrorKindTimeout, "x"), verdictRejected},
		// F1 Q4: a session open Exec gave up on runs after a good login, so it
		// is REJECTED and restores (gap 9); documentation pin, as every
		// stageAuthed error without a hop is.
		{"session open given up", stageAuthed, fmt.Errorf("probe command: %w", &sshconn.Error{Kind: fleet.ErrorKindTimeout, Err: fmt.Errorf("%w: no answer from the server within 10s", sshconn.ErrSessionNotOpened)}), verdictRejected},
		{"unknown after auth", stageAuthed, errors.New("x"), verdictRejected},
		{"unknown before auth", stageDial, errors.New("x"), verdictTransient},
		{"canceled before auth", stageDial, kinded(fleet.ErrorKindCanceled, "x"), verdictTransient},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyProbe(tt.stage, tt.err); got != tt.want {
				t.Errorf("classifyProbe = %v, want %v", got, tt.want)
			}
		})
	}
	for v, want := range map[verdict]int{verdictTransient: 4, verdictAgent: 2, verdictHostKey: 1} {
		if got := v.maxAttempts(); got != want {
			t.Errorf("%v.maxAttempts = %d, want %d", v, got, want)
		}
	}
}

var goodWrite = []execResp{{code: 0}, {code: 0, stdout: "x\n"}}

func unprovenFrom(t *testing.T, err error) *fleet.UnprovenError {
	t.Helper()
	var un *fleet.UnprovenError
	if !errors.As(err, &un) {
		t.Fatalf("err = %v, want *fleet.UnprovenError", err)
	}
	return un
}

func TestApplyProbeRetryAndUnproven(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "w"}
	dial := kinded(fleet.ErrorKindDial, "dial tcp 10.0.0.1:22: i/o timeout")
	setup := func(c *seamedConnect) (*FleetWriter, *scriptedExec, *fakeClock) {
		s := &scriptedExec{responses: goodWrite}
		w, clk := seamedWriter(s, c), newClock()
		w.now, w.sleep = clk.now, clk.sleep
		return w, s, clk
	}
	t.Run("a dial failure every attempt is UNPROVEN and restores nothing", func(t *testing.T) {
		c := &seamedConnect{probeErr: dial}
		w, s, clk := setup(c)
		err := w.Apply(ctx, srv, req("x\n"))
		un := unprovenFrom(t, err)
		if un.Attempts != 4 || un.HostKey {
			t.Errorf("unproven = %+v", un)
		}
		if len(c.opts) != 5 || len(s.cmds) != 2 {
			t.Errorf("connects = %d, cmds = %q; want 5 and no restore", len(c.opts), s.cmds)
		}
		if want := []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second}; !slices.Equal(clk.slept, want) {
			t.Errorf("waits = %v, want %v", clk.slept, want)
		}
		if got := fleet.ErrorKindOf(err); got != fleet.ErrorKindDial {
			t.Errorf("kind = %q, want the last failure's", got)
		}
		if !strings.Contains(err.Error(), "after 4 attempts") {
			t.Errorf("err = %q", err)
		}
	})
	t.Run("dial fails twice then succeeds", func(t *testing.T) {
		c := &seamedConnect{onlyErrs: []error{dial, dial, nil}}
		w, s, _ := setup(c)
		if err := w.Apply(ctx, srv, req("x\n")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if c.onlySeen != 3 || s.cmds[len(s.cmds)-1] != probeCmd {
			t.Errorf("only connects = %d, cmds = %q", c.onlySeen, s.cmds)
		}
	})
	t.Run("auth on the first attempt restores with no retry", func(t *testing.T) {
		c := &seamedConnect{probeErr: kinded(fleet.ErrorKindAuth, "unable to authenticate")}
		w, _, clk := setup(c)
		var lo *LockoutError
		if err := w.Apply(ctx, srv, req("x\n")); !errors.As(err, &lo) {
			t.Fatalf("err = %v, want *LockoutError", err)
		}
		if c.onlySeen != 1 || len(clk.slept) != 0 {
			t.Errorf("only connects = %d, waits = %v", c.onlySeen, clk.slept)
		}
	})
	t.Run("MaxAuthTries restores with no retry", func(t *testing.T) {
		c := &seamedConnect{probeErr: &sshconn.Error{Kind: fleet.ErrorKindHandshake, Err: errors.New("too many"), AuthExhausted: true}}
		w, _, _ := setup(c)
		var lo *LockoutError
		if err := w.Apply(ctx, srv, req("x\n")); !errors.As(err, &lo) || c.onlySeen != 1 {
			t.Fatalf("err = %v, only connects = %d", err, c.onlySeen)
		}
	})
	t.Run("an agent failure is retried once", func(t *testing.T) {
		c := &seamedConnect{probeErr: kinded(fleet.ErrorKindAgent, "none of the 1 surviving keys is offered")}
		w, _, _ := setup(c)
		err := w.Apply(ctx, srv, req("x\n"))
		if un := unprovenFrom(t, err); un.Attempts != 2 || c.onlySeen != 2 {
			t.Errorf("unproven = %+v, only connects = %d", un, c.onlySeen)
		}
		if !strings.Contains(err.Error(), "unlock the agent") {
			t.Errorf("err = %q", err)
		}
	})
	t.Run("a host-key alarm is not retried", func(t *testing.T) {
		c := &seamedConnect{probeErr: kinded(fleet.ErrorKindHostKeyChanged, "host key changed")}
		w, s, _ := setup(c)
		err := w.Apply(ctx, srv, req("x\n"))
		un := unprovenFrom(t, err)
		if !un.HostKey || un.Attempts != 1 || c.onlySeen != 1 || len(s.cmds) != 2 {
			t.Errorf("unproven = %+v, only connects = %d, cmds = %q", un, c.onlySeen, s.cmds)
		}
		if got := fleet.ErrorKindOf(err); !fleet.HostKeyAlert(got) {
			t.Errorf("kind = %q, want an alert kind", got)
		}
	})
	t.Run("a wait the context ends stops the retries", func(t *testing.T) {
		c := &seamedConnect{probeErr: dial}
		w, _, _ := setup(c)
		w.sleep = func(context.Context, time.Duration) error { return errors.New("context ended") }
		un := unprovenFrom(t, w.Apply(ctx, srv, req("x\n")))
		if un.Attempts != 1 || c.onlySeen != 1 {
			t.Errorf("unproven = %+v, only connects = %d; want the one finished attempt", un, c.onlySeen)
		}
	})
	t.Run("the probe dial carries the session deadline", func(t *testing.T) {
		c := &seamedConnect{}
		w, _, _ := setup(c)
		if err := w.Apply(ctx, srv, req("x\n")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if got := c.opts[1].SessionTimeout; got != probeExecDeadline {
			t.Errorf("SessionTimeout = %v, want %v", got, probeExecDeadline)
		}
	})
}

// TestProbeExecDeadlineRestores: a login that succeeds and then hangs is a
// REJECTED probe, bounded by its own 15 s context.
func TestProbeExecDeadlineRestores(t *testing.T) {
	var bound time.Duration
	s := &scriptedExec{responses: goodWrite}
	c := &seamedConnect{}
	w := seamedWriter(s, c)
	w.exec = func(ctx context.Context, cl *ssh.Client, cmd string, in io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
		if cmd == probeCmd {
			dl, _ := ctx.Deadline()
			bound = time.Until(dl)
			return 0, nil, nil, kinded(fleet.ErrorKindTimeout, "run remote command: context deadline exceeded")
		}
		return s.exec(ctx, cl, cmd, in)
	}
	var lo *LockoutError
	if err := w.Apply(context.Background(), config.Server{Name: "w"}, req("x\n")); !errors.As(err, &lo) || lo.Restore != nil {
		t.Fatalf("err = %v, want a restored *LockoutError", err)
	}
	if bound <= 0 || bound > probeExecDeadline {
		t.Errorf("exec bound = %v, want within %v", bound, probeExecDeadline)
	}
}

// TestProbeBudget is the spec's arithmetic table: every attempt, including
// the first, starts only while avail ≥ minProbeDial.
func TestProbeBudget(t *testing.T) {
	dial := kinded(fleet.ErrorKindDial, "dial timeout")
	type outcome struct {
		c      *seamedConnect
		bounds []time.Duration
		err    error
	}
	// run performs a write costing writeCost, with every probe dial burning
	// its full bound on the fake clock and then failing.
	run := func(t *testing.T, writeCost time.Duration, errs []error, fallback error) (outcome, *fakeClock, time.Time) {
		t.Helper()
		clk := newClock()
		start := clk.t
		var o outcome
		o.c = &seamedConnect{probeErr: fallback, onlyErrs: errs, onlyHook: func(ctx context.Context) {
			dl, _ := ctx.Deadline()
			d := time.Until(dl).Round(time.Second)
			o.bounds = append(o.bounds, d)
			clk.t = clk.t.Add(d)
		}}
		s := &scriptedExec{responses: goodWrite}
		w := seamedWriter(s, o.c)
		w.now, w.sleep = clk.now, clk.sleep
		w.exec = func(ctx context.Context, cl *ssh.Client, cmd string, in io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
			clk.t = clk.t.Add(writeCost / 2)
			return s.exec(ctx, cl, cmd, in)
		}
		o.err = w.Apply(context.Background(), config.Server{Name: "w"}, req("x\n"))
		return o, clk, start
	}
	t.Run("W≈0: three attempts, the third cut to 18 s", func(t *testing.T) {
		o, _, _ := run(t, 0, nil, dial)
		if un := unprovenFrom(t, o.err); un.Attempts != 3 {
			t.Errorf("attempts = %d, want 3", un.Attempts)
		}
		if want := []time.Duration{30 * time.Second, 30 * time.Second, 18 * time.Second}; !slices.Equal(o.bounds, want) {
			t.Errorf("dial bounds = %v, want %v", o.bounds, want)
		}
	})
	t.Run("W≈20 s: two attempts", func(t *testing.T) {
		o, _, _ := run(t, 20*time.Second, nil, dial)
		if un := unprovenFrom(t, o.err); un.Attempts != 2 || o.c.onlySeen != 2 {
			t.Errorf("attempts = %d, only connects = %d", un.Attempts, o.c.onlySeen)
		}
	})
	t.Run("W > 84 s: no attempt, no first-attempt exception", func(t *testing.T) {
		o, _, _ := run(t, 85*time.Second, nil, dial)
		un := unprovenFrom(t, o.err)
		if un.Attempts != 0 || o.c.onlySeen != 0 {
			t.Errorf("attempts = %d, only connects = %d", un.Attempts, o.c.onlySeen)
		}
		if !strings.Contains(o.err.Error(), "session budget ran out before the login check could start") {
			t.Errorf("err = %q", o.err)
		}
	})
	t.Run("a REJECTED verdict on the last attempt leaves the reserve", func(t *testing.T) {
		o, clk, start := run(t, 0, []error{dial, dial, kinded(fleet.ErrorKindAuth, "refused")}, nil)
		var lo *LockoutError
		if !errors.As(o.err, &lo) {
			t.Fatalf("err = %v", o.err)
		}
		if used := clk.t.Sub(start); 120*time.Second-used < restoreReserve {
			t.Errorf("%v used of 120 s, want at least %v left for the restore", used, restoreReserve)
		}
	})
}

func TestApplyHeadlessProof(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	withProof := func() (Request, *[]string) {
		r := req("x\n", "SHA256:agent")
		var got []string
		r.HeadlessProof, r.OnWarning = []string{"SHA256:file"}, func(cause string) { got = append(got, cause) }
		return r, &got
	}
	t.Run("a passing proof is silent, one extra Only connect", func(t *testing.T) {
		r, got := withProof()
		c := &seamedConnect{}
		if err := seamedWriter(&scriptedExec{responses: goodWrite}, c).Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(c.opts) != 3 || !slices.Equal(c.opts[2].Only, []string{"SHA256:file"}) || len(*got) != 0 {
			t.Errorf("connects = %+v, warnings = %q", c.opts, *got)
		}
	})
	t.Run("a failed proof warns once and never restores", func(t *testing.T) {
		r, got := withProof()
		c := &seamedConnect{onlyErrs: []error{nil, kinded(fleet.ErrorKindAuth, "ssh: unable to authenticate")}}
		s := &scriptedExec{responses: goodWrite}
		if err := seamedWriter(s, c).Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v, want nil: the proof only warns", err)
		}
		if len(*got) != 1 || !strings.Contains((*got)[0], "unable to authenticate") {
			t.Errorf("warnings = %q", *got)
		}
		if len(s.cmds) != 3 { // write, verify, the probe's command
			t.Errorf("cmds = %q, want no restore", s.cmds)
		}
	})
	t.Run("skipped when the budget is too low", func(t *testing.T) {
		r, got := withProof()
		clk := newClock()
		c := &seamedConnect{onlyHook: func(context.Context) { clk.t = clk.t.Add(105 * time.Second) }}
		w := seamedWriter(&scriptedExec{responses: goodWrite}, c)
		w.now, w.sleep = clk.now, clk.sleep
		if err := w.Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if c.onlySeen != 1 || len(*got) != 0 {
			t.Errorf("only connects = %d, warnings = %q", c.onlySeen, *got)
		}
	})
	t.Run("no proof requested means no extra connect", func(t *testing.T) {
		c := &seamedConnect{}
		if err := seamedWriter(&scriptedExec{responses: goodWrite}, c).Apply(ctx, srv, req("x\n")); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if len(c.opts) != 2 {
			t.Errorf("connects = %d, want 2", len(c.opts))
		}
	})
	t.Run("a nil OnWarning is tolerated", func(t *testing.T) {
		r, _ := withProof()
		r.OnWarning = nil
		c := &seamedConnect{onlyErrs: []error{nil, kinded(fleet.ErrorKindAuth, "x")}}
		if err := seamedWriter(&scriptedExec{responses: goodWrite}, c).Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	})
}
