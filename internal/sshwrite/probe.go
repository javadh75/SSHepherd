package sshwrite

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// probeStage is how far a login check got: stageDial is everything inside
// the connect (TCP, key exchange, host key, authentication); stageAuthed is
// after the connect returned a client.
type probeStage int

const (
	stageDial probeStage = iota
	stageAuthed
)

func (s probeStage) String() string {
	if s == stageAuthed {
		return "authed"
	}
	return "dial"
}

// verdict is what a failed login check proves.
type verdict int

const (
	verdictTransient verdict = iota // nothing proved: retry, then UNPROVEN
	verdictAgent                    // a held survivor could not be offered: one retry, then UNPROVEN
	verdictHostKey                  // a host-key alarm: no retry, UNPROVEN
	verdictRejected                 // the survivors cannot be used: restore
)

// maxAttempts is the retry ceiling of a transient verdict.
func (v verdict) maxAttempts() int {
	switch v {
	case verdictAgent:
		return 2
	case verdictHostKey:
		return 1
	}
	return len(probeBackoff)
}

// classifyProbe sorts a login-check failure by the stage it reached, not by
// error kind alone. The static guard only checks that a held key's line is
// present; it never evaluates from= or command=, so nothing after a
// successful login is waved through as a blip: a key that logs in but
// cannot run SSHepherd's command captures every later session.
func classifyProbe(stage probeStage, err error) verdict {
	if stage == stageAuthed || sshconn.AuthExhausted(err) {
		return verdictRejected
	}
	switch kind := fleet.ErrorKindOf(err); {
	case strings.HasPrefix(string(kind), "host_key"):
		return verdictHostKey
	case kind == fleet.ErrorKindAuth:
		return verdictRejected
	case kind == fleet.ErrorKindAgent:
		return verdictAgent
	}
	return verdictTransient
}

// The login-check schedule, all inside the session budget. Numbers are
// fixed so the behaviour is predictable and documented once.
const (
	// probeExecDeadline bounds session open, exec and output after the
	// connect returns; on expiry the verdict is REJECTED.
	probeExecDeadline = 15 * time.Second
	// restoreReserve is kept back after the probe's own time, for a REJECTED
	// restore over the open write connection (the busy-lock waits of
	// 1 + 3 + 6 s, plus the restore and keys2 commands).
	restoreReserve = 20 * time.Second
	// minProbeDial is the least dial time an attempt starts with.
	minProbeDial = 1 * time.Second
	// defaultDialBound is 3×DialTimeout when the Dialer sets none.
	defaultDialBound = 30 * time.Second
)

// probeBackoff is the wait before each login-check attempt.
var probeBackoff = [...]time.Duration{0, 2 * time.Second, 5 * time.Second, 10 * time.Second}

const (
	probeCmd    = `echo sshepherd-probe-ok`
	probeOutput = "sshepherd-probe-ok\n"
)

// errBudget is an UnprovenError's cause when no attempt could start.
var errBudget = errors.New("session budget exhausted before the login check")

// dialBound is 3×DialTimeout, the most one login-check dial may take.
func (w *FleetWriter) dialBound() time.Duration {
	if w.Dialer != nil && w.Dialer.DialTimeout > 0 {
		return 3 * w.Dialer.DialTimeout
	}
	return defaultDialBound
}

// probeOnce logs in offering only the given keys and runs probeCmd: a key
// that authenticates but whose line forces a command would leave sshepherd
// unable to manage the server, so the command must run and print
// probeOutput, not just a handshake. The dial is bounded by bound, the
// exec by probeExecDeadline (which starts when the connect returns).
func (w *FleetWriter) probeOnce(ctx context.Context, srv config.Server, only []string, bound time.Duration) (probeStage, error) {
	dialCtx, cancel := context.WithTimeout(ctx, bound)
	defer cancel()
	probe, err := w.connectFn()(dialCtx, srv, sshconn.ConnectOptions{Only: only, SessionTimeout: probeExecDeadline})
	if err != nil {
		return stageDial, err
	}
	defer func() { _ = probe.Close() }() // errcheck: the verdict is already decided
	execCtx, cancelExec := context.WithTimeout(ctx, probeExecDeadline)
	defer cancelExec()
	code, stdout, _, err := w.execFn()(execCtx, probe.Client, probeCmd, nil)
	switch {
	case err != nil:
		return stageAuthed, fmt.Errorf("probe command: %w", err)
	case code != 0 || stdout.String() != probeOutput:
		return stageAuthed, fmt.Errorf("probe command did not run as sent (exit %d) — a forced command= on the surviving key?", code)
	}
	return stageAuthed, nil
}

// probeResult is a finished login check: err nil means proven.
type probeResult struct {
	err      error
	verdict  verdict
	attempts int
}

// avail is the dial time an attempt may use: the probe's whole life must
// end by deadline − restoreReserve, so the dial ends by that less the exec's
// own deadline.
func (s *writeSession) avail() time.Duration {
	return s.remaining() - probeExecDeadline - restoreReserve
}

// probeWithRetries runs the login check. An attempt, the first included,
// starts only while avail ≥ minProbeDial at the moment it would start,
// after its wait; a wait that would leave too little is not taken.
func (s *writeSession) probeWithRetries() probeResult {
	log := s.w.log()
	res := probeResult{err: errBudget}
	for attempt := 0; attempt < res.verdict.maxAttempts(); attempt++ {
		wait := probeBackoff[attempt]
		if s.avail()-wait < minProbeDial {
			break
		}
		if wait > 0 {
			if err := s.w.sleepFn()(s.ctx, wait); err != nil {
				break
			}
		}
		stage, err := s.w.probeOnce(s.ctx, s.srv, s.req.Survivors, min(s.w.dialBound(), s.avail()))
		res.attempts, res.err = attempt+1, err
		if err == nil {
			return res
		}
		res.verdict = classifyProbe(stage, err)
		log.Debug("login check failed", "server", s.srv.Name, "attempt", attempt+1, "stage", stage.String(), "kind", string(fleet.ErrorKindOf(err)))
		if res.verdict == verdictRejected {
			return res
		}
	}
	return res
}

// proveOrRestore runs the login check and acts on it: a REJECTED verdict
// restores over the still-open connection; anything else that never got
// past authentication keeps the file (*fleet.UnprovenError), because
// restoring could reinstall a key the manifest removed.
func (s *writeSession) proveOrRestore(keys2Name string) error {
	res := s.probeWithRetries()
	switch {
	case res.err == nil:
		s.w.log().Debug("login probe ok", "server", s.srv.Name, "attempts", res.attempts)
		s.headlessProof()
		return nil
	case res.verdict == verdictRejected:
		return s.rollback(keys2Name, res.err)
	}
	return &fleet.UnprovenError{Path: s.path, Attempts: res.attempts, HostKey: res.verdict == verdictHostKey, Last: sshconn.SanitizedError{Err: res.err}}
}

// headlessProof is D9b's warn-only check: one more login offering only the
// unrestricted --identity survivors, for a run whose production order proves
// the agent key first. A failure only warns; it can never roll back a write
// the login check proved or reinstall a revoked key. It needs no restore
// reserve, since it never restores.
func (s *writeSession) headlessProof() {
	if len(s.req.HeadlessProof) == 0 {
		return
	}
	room := s.remaining() - probeExecDeadline
	if room < minProbeDial {
		s.w.log().Debug("headless proof skipped: session budget too low", "server", s.srv.Name)
		return
	}
	_, err := s.w.probeOnce(s.ctx, s.srv, s.req.HeadlessProof, min(s.w.dialBound(), room))
	if err != nil && s.req.OnWarning != nil {
		s.req.OnWarning(sshconn.SanitizedError{Err: err}.Error())
	}
}
