package sshwrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// writeSession is one server's write: the connection in use (replaced by at
// most one reconnect), the budget it all runs under, and the request.
type writeSession struct {
	w           *FleetWriter
	ctx         context.Context // detached from the caller; ends at deadline
	deadline    time.Time
	srv         config.Server
	path        string
	req         Request
	conn        *sshconn.Conn
	reconnected bool
}

func (s *writeSession) close() { _ = s.conn.Close() } // the verdict is already decided

func (s *writeSession) exec(script string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
	return s.w.execFn()(s.ctx, s.conn.Client, script, stdin)
}

func (s *writeSession) remaining() time.Duration { return s.deadline.Sub(s.w.clock()) }

// run is the protocol: write and verify, disable authorized_keys2, prove
// the login. A keys2 failure cannot lock anyone out (the file only ever
// adds keys), so the login check still runs and the failure is reported
// after it.
func (s *writeSession) run() error {
	write := s.writeAndVerify
	if s.req.SkipWrite {
		write = s.checkUnchanged
	}
	if err := write(); err != nil {
		return err
	}
	keys2Name, keys2Err := s.disableKeys2()
	if err := s.proveOrRestore(keys2Name); err != nil {
		return err
	}
	return keys2Err
}

// checkUnchanged replaces the guarded write when authorized_keys already
// holds the render (SkipWrite): nothing is locked, backed up, uploaded or
// renamed, so .bak is not rotated. The byte compare doubles as the
// compare-and-swap, catching a CRC collision too. Nothing was written, so a
// transport error needs no re-check.
func (s *writeSession) checkUnchanged() error {
	code, stdout, stderr, err := s.exec(sshconn.AuthorizedKeysCmdFor(s.path), nil)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("read on %s: %w", s.srv.Name, err)}
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, s.srv.Name, s.w.log())
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("read on %s: %w", s.srv.Name, err)}
	}
	if res.FileAbsent || !bytes.Equal(res.Content, s.req.Content) {
		return fleet.Refused(&ChangedError{Path: s.path}) //nolint:wrapcheck // Refused is the refusal marker itself; the message is the typed error's
	}
	return nil
}

// writeAndVerify is the guarded write (rendered bytes on stdin) and the
// read-back: trusting mv's exit status would leave silent-corruption blind
// spots for the cost of one extra cat.
func (s *writeSession) writeAndVerify() error {
	code, stdout, stderr, err := s.exec(writeCmdFor(s.path, s.req.Expect, len(s.req.Content)), bytes.NewReader(s.req.Content))
	if err != nil {
		// A session that never opened cannot have started the script.
		return s.recheckAfterDrop(fmt.Errorf("write on %s: %w", s.srv.Name, err), !errors.Is(err, sshconn.ErrSessionNotOpened))
	}
	if err := writeExitError(code, s.path, s.srv, stdout, stderr); err != nil {
		return err
	}
	s.w.log().Debug("write ok", "server", s.srv.Name, "bytes", len(s.req.Content))
	if err := s.verify(); err != nil {
		return err
	}
	s.w.log().Debug("verify ok", "server", s.srv.Name)
	return nil
}

// verify re-reads the file and byte-compares it with the render.
func (s *writeSession) verify() error {
	code, stdout, stderr, err := s.exec(sshconn.AuthorizedKeysCmdFor(s.path), nil)
	if err != nil {
		return s.recheckAfterDrop(fmt.Errorf("verify on %s: %w", s.srv.Name, err), true)
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, s.srv.Name, s.w.log())
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("verify on %s: %w", s.srv.Name, err)}
	}
	if res.FileAbsent {
		return fmt.Errorf("verify on %s: file absent after write", s.srv.Name)
	}
	if !bytes.Equal(res.Content, s.req.Content) {
		return fmt.Errorf("verify on %s: file bytes differ from the rendered desired state", s.srv.Name)
	}
	return nil
}

// disableKeys2 moves a non-empty authorized_keys2 aside before the login
// check, so the check proves the survivors log in without it. It returns
// the copy's basename ("" when nothing was moved).
func (s *writeSession) disableKeys2() (string, error) {
	if !s.req.DisableKeys2 {
		return "", nil
	}
	code, stdout, stderr, err := s.exec(disableKeys2Cmd(), nil)
	switch {
	case err != nil:
		return "", sshconn.SanitizedError{Err: fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s failed: %w", s.srv.Name, err)}
	case code == unsafePathExit:
		return "", fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s was refused: its directory fails the ownership/mode walk", s.srv.Name)
	case code != 0:
		return "", fmt.Errorf("authorized_keys written and verified, but %w", stageFailure("disabling authorized_keys2", s.srv.Name, code, stderr))
	}
	name, ok := parseKeys2Name(stdout.String())
	if !ok {
		return "", fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s printed an unrecognized name", s.srv.Name)
	}
	s.w.log().Debug("authorized_keys2 disabled", "server", s.srv.Name)
	return name, nil
}

// rollback restores after a REJECTED login check: the previous file (unless
// this run never wrote it) and the authorized_keys2 copy this run made.
func (s *writeSession) rollback(keys2Name string, probeErr error) error {
	s.w.log().Warn(fmt.Sprintf("%s: post-write login probe failed; restoring the previous file", s.srv.Name))
	lo := &LockoutError{Path: s.path, Probe: sshconn.SanitizedError{Err: probeErr}}
	if !s.req.SkipWrite {
		lo.Restore = s.restoreFile()
	}
	if keys2Name != "" {
		lo.RestoreKeys2 = s.restoreKeys2(keys2Name)
	}
	return lo
}

// lockBackoff is the wait before each retry of a busy lock.
var lockBackoff = [...]time.Duration{time.Second, 3 * time.Second, 6 * time.Second}

// attemptsText is "1 attempt" or "N attempts".
func attemptsText(n int) string {
	if n == 1 {
		return "1 attempt"
	}
	return strconv.Itoa(n) + " attempts"
}

// waitLock waits before the next try at a busy lock; false when the
// schedule or the budget has run out.
func (s *writeSession) waitLock(attempt int) bool {
	if attempt >= len(lockBackoff) || s.remaining() <= lockBackoff[attempt] {
		return false
	}
	return s.w.sleepFn()(s.ctx, lockBackoff[attempt]) == nil
}

// restoreFile puts the previous authorized_keys back, retrying a busy lock
// on the lockBackoff schedule and a dead connection over the one reconnect.
// Any other exit is final.
func (s *writeSession) restoreFile() error {
	script := restoreCmdFor(s.path, s.req.Expect.Absent, SnapshotOf(false, s.req.Content))
	for attempt := 0; ; {
		code, stdout, stderr, err := s.exec(script, nil)
		switch {
		case err != nil:
			if rerr := s.reconnect(); rerr != nil {
				return sshconn.SanitizedError{Err: fmt.Errorf("%w (and no reconnect: %w)", err, rerr)}
			}
		case code == lockedExit:
			if !s.waitLock(attempt) {
				info := parseLockOwner(stdout.String())
				return fmt.Errorf("restore on %s refused: another apply holds the lock (held by %s) after %s", s.srv.Name, heldText(info.owner, info.age), attemptsText(attempt+1))
			}
			attempt++
		case code != 0:
			return restoreExitError(code, s.srv.Name, stderr)
		default:
			return nil
		}
	}
}

// restoreKeys2 moves back the copy this run made.
func (s *writeSession) restoreKeys2(name string) error {
	code, _, stderr, err := s.exec(restoreKeys2Cmd(name), nil)
	switch {
	case err != nil:
		return sshconn.SanitizedError{Err: fmt.Errorf("restore authorized_keys2 on %s: %w", s.srv.Name, err)}
	case code == changedExit:
		return fmt.Errorf("restore authorized_keys2 on %s refused: it was recreated meanwhile (the disabled copy is at %s)", s.srv.Name, name)
	case code != 0:
		return stageFailure("restore authorized_keys2", s.srv.Name, code, stderr)
	}
	return nil
}

// errReconnectSpent: this write already used its one reconnect.
var errReconnectSpent = errors.New("the one reconnect of this write is spent")

// reconnect replaces the connection, once per write. RequireOffer: with
// nothing to offer (a locked agent) the failure is agent-kind, so it can
// never read as a refused login.
func (s *writeSession) reconnect() error {
	if s.reconnected {
		return errReconnectSpent
	}
	s.reconnected = true
	_ = s.conn.Close() // already dead, or about to be replaced
	conn, err := s.w.connectFn()(s.ctx, s.srv, sshconn.ConnectOptions{RequireOffer: true})
	if err != nil {
		return err //nolint:wrapcheck // already an *sshconn.Error carrying its kind
	}
	s.conn = conn
	return nil
}

// unknownStateError is a dropped connection that could not be settled. Its
// message is fixed; Unwrap keeps a failed reconnect's kind for error_kind.
type unknownStateError struct {
	path  string
	cause error
}

func (e *unknownStateError) Error() string {
	return fmt.Sprintf("connection dropped; the file is in an unknown state (previous version at %s%s) — run sshepherd audit", e.path, bakSuffix)
}

func (e *unknownStateError) Unwrap() error { return e.cause }

// recheckAfterDrop settles a transport error on the write connection (stage
// 1 or verify): one fresh connection, then a re-read under the lock. nil
// means the rename happened and the run continues over the new connection.
// started is false only when the stage-1 session never opened.
func (s *writeSession) recheckAfterDrop(cause error, started bool) error {
	s.w.log().Debug("connection dropped; re-checking", "server", s.srv.Name, "cause", sshconn.SanitizeRemote(cause.Error()))
	if err := s.reconnect(); err != nil {
		return s.reconnectFailed(err, started)
	}
	read, ok := s.lockedRead()
	switch {
	case !ok:
		return &unknownStateError{path: s.path}
	case !read.FileAbsent && bytes.Equal(read.Content, s.req.Content):
		return nil
	case SnapshotOf(read.FileAbsent, read.Content) == s.req.Expect:
		return errors.New("connection dropped before the rename; original untouched (re-checked under the lock)")
	}
	return &unknownStateError{path: s.path}
}

// reconnectFailed maps a failed reconnect: a login refused after the upload
// started may mean the new file locked the operator out; anything else
// leaves the file's state unknown.
func (s *writeSession) reconnectFailed(err error, started bool) error {
	clean := sshconn.SanitizedError{Err: err}
	if started && fleet.ErrorKindOf(err) == fleet.ErrorKindAuth {
		return &LockoutError{Path: s.path, Probe: clean, Restore: fleet.ErrNoSession}
	}
	return &unknownStateError{path: s.path, cause: clean}
}

// lockedRead re-reads the file under the lock, waiting out a busy lock on
// the lockBackoff schedule; false when it could not be read.
func (s *writeSession) lockedRead() (fleet.ReadResult, bool) {
	script := lockedReadCmdFor(s.path)
	for attempt := 0; ; attempt++ {
		code, stdout, stderr, err := s.exec(script, nil)
		if err != nil {
			return fleet.ReadResult{}, false
		}
		if code != lockedExit {
			res, err := sshconn.FinishRead(code, stdout, stderr, s.srv.Name, s.w.log())
			return res, err == nil
		}
		if !s.waitLock(attempt) {
			return fleet.ReadResult{}, false
		}
	}
}
