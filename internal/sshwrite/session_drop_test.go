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

// TestApplyRestoreThatLandedLostItsStatus: the dropped restore's mv may have
// run, so the retry's compare-and-swap exits 46. A re-read under the lock
// that finds the previous snapshot is a restore that happened (WP-6).
func TestApplyRestoreThatLandedLostItsStatus(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	drop := execResp{err: errors.New("EOF")}
	changed := execResp{code: changedExit}
	busy := execResp{code: lockedExit}
	wrote := []execResp{{code: 0}, {stdout: "x\n"}}
	read := lockedReadCmdFor(sshconn.DefaultAuthorizedKeysPath)
	script := func(after ...execResp) *scriptedExec {
		return &scriptedExec{responses: append(append([]execResp{}, wrote...), after...)}
	}
	t.Run("the previous bytes are back: restored", func(t *testing.T) {
		s, c := script(drop, changed, execResp{stdout: "old\n"}), rejected()
		lo := lockoutOf(t, seamedWriter(s, c).Apply(ctx, srv, req("x\n")))
		if lo.Restore != nil || c.fullSeen != 2 || s.cmds[len(s.cmds)-1] != read {
			t.Errorf("Restore = %v, full connects = %d, cmds = %q", lo.Restore, c.fullSeen, s.cmds)
		}
		if !strings.Contains(lo.Error(), "lockout prevented") {
			t.Errorf("err = %q", lo)
		}
	})
	t.Run("a first-contact file is gone again: restored", func(t *testing.T) {
		r := req("x\n")
		r.Expect = Snapshot{Absent: true}
		s := script(drop, changed, execResp{code: sshconn.FileAbsentExit})
		if lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, r)); lo.Restore != nil {
			t.Errorf("Restore = %v", lo.Restore)
		}
	})
	t.Run("the dropped script still held the lock: restored", func(t *testing.T) {
		s := script(drop, busy, changed, execResp{stdout: "old\n"})
		if lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, req("x\n"))); lo.Restore != nil {
			t.Errorf("Restore = %v", lo.Restore)
		}
	})
	const refused = "the file changed since this apply wrote it"
	t.Run("other bytes stay refused", func(t *testing.T) {
		s := script(drop, changed, execResp{stdout: "other\n"})
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || !strings.Contains(lo.Restore.Error(), refused) {
			t.Errorf("Restore = %v", lo.Restore)
		}
	})
	t.Run("a re-read that drops stays refused", func(t *testing.T) {
		s := script(drop, changed, drop)
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || !strings.Contains(lo.Restore.Error(), refused) {
			t.Errorf("Restore = %v", lo.Restore)
		}
	})
	t.Run("without a drop 46 is final and nothing is re-read", func(t *testing.T) {
		s := script(changed)
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || slices.Contains(s.cmds, read) {
			t.Errorf("Restore = %v, cmds = %q", lo.Restore, s.cmds)
		}
	})
}

// TestApplySkipWriteRefusesUnsafePaths: a keys2-only plan keeps the write
// path's symlink and ownership refusals, and authorized_keys2 stays put.
func TestApplySkipWriteRefusesUnsafePaths(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	r := req("x\n")
	r.DisableKeys2, r.SkipWrite = true, true
	t.Run("a symlinked target", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: symlinkExit}}}
		err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r)
		var sym *SymlinkError
		if !errors.As(err, &sym) || !fleet.IsRefusal(err) || len(s.cmds) != 1 {
			t.Fatalf("err = %v, cmds = %q", err, s.cmds)
		}
	})
	t.Run("an unsafe path", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: unsafePathExit}}}
		err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r)
		var unsafe *UnsafePathError
		if !errors.As(err, &unsafe) || !fleet.IsRefusal(err) || len(s.cmds) != 1 {
			t.Fatalf("err = %v, cmds = %q", err, s.cmds)
		}
	})
}

// TestApplySkipWriteRollbackClaimsNoFileRestore: a keys2-only run wrote no
// file, so its failure text must not say one was restored.
func TestApplySkipWriteRollbackClaimsNoFileRestore(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	const moved = "sshepherd-keys2 authorized_keys2" + fleet.Keys2DisabledSuffix + "\n"
	r := req("x\n")
	r.DisableKeys2, r.SkipWrite = true, true
	t.Run("the move-back worked", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "x\n"}, {stdout: moved}, {code: 0}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, r))
		if strings.Contains(lo.Error(), "restored previous file") || !strings.Contains(lo.Error(), "moved authorized_keys2 back") {
			t.Errorf("err = %q", lo)
		}
	})
	t.Run("the move-back failed", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "x\n"}, {stdout: moved}, {code: changedExit}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, r))
		if strings.Contains(lo.Error(), "lockout prevented") || strings.Contains(lo.Error(), "restored previous file") {
			t.Errorf("err = %q", lo)
		}
		want := "restore authorized_keys2 on web-1 refused: it was recreated meanwhile (the disabled copy is at authorized_keys2" + fleet.Keys2DisabledSuffix + ")"
		if lo.RestoreKeys2 == nil || lo.RestoreKeys2.Error() != want {
			t.Errorf("RestoreKeys2 = %v, want %q", lo.RestoreKeys2, want)
		}
	})
}

// closableConn lets a test hand out a distinct, closable *ssh.Client.
type closableConn struct{ ssh.Conn }

func (closableConn) Close() error { return nil }

// TestApplyUsesTheReconnectedClient: every command after a reconnect runs
// on the new connection, not the dead one.
func TestApplyUsesTheReconnectedClient(t *testing.T) {
	first, second := &ssh.Client{Conn: closableConn{}}, &ssh.Client{Conn: closableConn{}}
	clients := []*ssh.Client{first, second}
	s := &scriptedExec{responses: []execResp{{err: errors.New("EOF")}, {stdout: "x\n"}}}
	c := &seamedConnect{}
	var used []*ssh.Client
	w := seamedWriter(s, c)
	w.connect = func(ctx context.Context, srv config.Server, opts sshconn.ConnectOptions) (*sshconn.Conn, error) {
		conn, err := c.connect(ctx, srv, opts)
		if err == nil && len(opts.Only) == 0 {
			conn.Client = clients[c.fullSeen-1]
		}
		return conn, err
	}
	w.exec = func(ctx context.Context, cl *ssh.Client, cmd string, in io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
		if cmd != probeCmd {
			used = append(used, cl)
		}
		return s.exec(ctx, cl, cmd, in)
	}
	if err := w.Apply(context.Background(), config.Server{Name: "web-1"}, req("x\n")); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if want := []*ssh.Client{first, second}; !slices.Equal(used, want) {
		t.Errorf("clients used = %v, want the first then the reconnected one", used)
	}
}

// TestAbsentIsNeverAnEmptyRender: an absent file reads back as empty bytes,
// so only the explicit FileAbsent tests tell it from an empty render.
func TestAbsentIsNeverAnEmptyRender(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	t.Run("SkipWrite refuses", func(t *testing.T) {
		r := req("")
		r.DisableKeys2, r.SkipWrite = true, true
		s := &scriptedExec{responses: []execResp{{code: sshconn.FileAbsentExit}}}
		if err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r); !fleet.IsRefusal(err) {
			t.Fatalf("err = %v, want a refusal", err)
		}
	})
	t.Run("a re-check after a drop is an unknown state", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{err: errors.New("EOF")}, {code: sshconn.FileAbsentExit}}}
		err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, req(""))
		if err == nil || !strings.Contains(err.Error(), "unknown state") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestApplyDisableKeys2TransportError(t *testing.T) {
	r := req("x\n")
	r.DisableKeys2 = true
	s := &scriptedExec{responses: []execResp{{code: 0}, {stdout: "x\n"}, {err: errors.New("EOF")}}}
	err := seamedWriter(s, &seamedConnect{}).Apply(context.Background(), config.Server{Name: "web-1"}, r)
	if err == nil || !strings.Contains(err.Error(), "authorized_keys written and verified, but disabling authorized_keys2 on web-1 failed") {
		t.Fatalf("err = %v", err)
	}
}

func TestProbeNonzeroExitWithRightOutputIsRejected(t *testing.T) {
	s := &scriptedExec{responses: []execResp{{code: 0}, {stdout: "x\n"}, {code: 1, stdout: probeOutput}, {code: 0}}}
	lo := lockoutOf(t, seamedWriter(s, &seamedConnect{}).Apply(context.Background(), config.Server{Name: "web-1"}, req("x\n")))
	if lo.Restore != nil {
		t.Errorf("Restore = %v", lo.Restore)
	}
}

func TestProbeStartsWithOneSecondOfDialLeft(t *testing.T) {
	clk := newClock()
	c := &seamedConnect{probeErr: kinded(fleet.ErrorKindDial, "dial timeout")}
	s := &scriptedExec{responses: goodWrite}
	w := seamedWriter(s, c)
	w.now, w.sleep = clk.now, clk.sleep
	w.exec = func(ctx context.Context, cl *ssh.Client, cmd string, in io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
		clk.t = clk.t.Add(83500 * time.Millisecond / 2) // leaves 1.5 s of dial time
		return s.exec(ctx, cl, cmd, in)
	}
	err := w.Apply(context.Background(), config.Server{Name: "w"}, req("x\n"))
	if un := unprovenFrom(t, err); un.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", un.Attempts)
	}
}

func TestApplyRestoreLockWaitSchedule(t *testing.T) {
	busy := execResp{code: lockedExit, stdout: busyOwner}
	s := &scriptedExec{responses: []execResp{{code: 0}, {stdout: "x\n"}, busy, busy, busy, busy}}
	w, clk := seamedWriter(s, rejected()), newClock()
	w.now, w.sleep = clk.now, clk.sleep
	lockoutOf(t, w.Apply(context.Background(), config.Server{Name: "web-1"}, req("x\n")))
	if want := []time.Duration{time.Second, 3 * time.Second, 6 * time.Second}; !slices.Equal(clk.slept, want) {
		t.Errorf("waits = %v, want %v", clk.slept, want)
	}
}

func TestParseLockOwnerIsAnchored(t *testing.T) {
	for name, out := range map[string]string{
		"trailing text": "sshepherd-lock 1010\nv1 h 1 2 1000 extra\n",
		"leading text":  "sshepherd-lock 1010\njunk v1 h 1 2 1000\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := parseLockOwner(out); got.known || got.owner != ownerUnrecognized {
				t.Errorf("parseLockOwner = %+v", got)
			}
		})
	}
}

// TestFirstContactMessagesNeverPointAtABackup (F010): a write over an absent
// file has no previous version; the undo is deleting the file.
func TestFirstContactMessagesNeverPointAtABackup(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	first := req("x\n")
	first.Expect = Snapshot{Absent: true}
	drop := execResp{err: errors.New("EOF")}
	check := func(t *testing.T, msg string) {
		t.Helper()
		if strings.Contains(msg, bakSuffix) || !strings.Contains(msg, "no previous file") || !strings.Contains(msg, "deleting") {
			t.Errorf("message = %q", msg)
		}
	}
	t.Run("the re-check after a drop is inconclusive", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{drop, {stdout: "other\n"}}}
		check(t, seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, first).Error())
	})
	t.Run("the reconnect after a drop failed", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{drop}}
		c := &seamedConnect{fullErrs: []error{kinded(fleet.ErrorKindDial, "refused")}}
		check(t, seamedWriter(s, c).Apply(ctx, srv, first).Error())
	})
	t.Run("the reconnect after a drop was refused", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{drop}}
		c := &seamedConnect{fullErrs: []error{kinded(fleet.ErrorKindAuth, "denied")}}
		lo := lockoutOf(t, seamedWriter(s, c).Apply(ctx, srv, first))
		if !lo.Created {
			t.Error("Created must be set")
		}
		check(t, lo.Error())
	})
	t.Run("a removal that failed after a rejected login", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {stdout: "x\n"}, {code: changedExit}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, first))
		if lo.Restore == nil || !lo.Created {
			t.Fatalf("lockout = %+v", lo)
		}
		check(t, lo.Error())
	})
	t.Run("a removal that worked after a rejected login", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {stdout: "x\n"}, {code: 0}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, first))
		if lo.Restore != nil || strings.Contains(lo.Error(), "restored previous file") || !strings.Contains(lo.Error(), "lockout prevented") {
			t.Errorf("lockout = %q", lo)
		}
	})
	t.Run("a file with a previous version keeps its .bak text", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{drop, {stdout: "other\n"}}}
		if msg := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, req("x\n")).Error(); !strings.Contains(msg, bakSuffix) {
			t.Errorf("message = %q", msg)
		}
	})
}

// TestApplyKeys2LostReply (F004): the move may have happened when the reply
// is lost, so a REJECTED login recovers the copy by listing it, and reports
// an unrestored move-back when it cannot. "Lockout prevented" is never said
// while the state of authorized_keys2 is unknown.
func TestApplyKeys2LostReply(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	copyName := "authorized_keys2" + fleet.Keys2DisabledSuffix
	listed := "sshepherd-keys2 " + copyName + "\n"
	drop := execResp{err: errors.New("EOF")}
	keys2Only := req("x\n")
	keys2Only.DisableKeys2, keys2Only.SkipWrite = true, true
	full := req("x\n")
	full.DisableKeys2 = true
	// run scripts the disable reply, then what follows the file restore: a
	// full write's restoreFile takes one response before the listing.
	run := func(t *testing.T, r Request, c *seamedConnect, after ...execResp) (*scriptedExec, *LockoutError) {
		t.Helper()
		resp := []execResp{{stdout: "x\n"}}
		if !r.SkipWrite {
			resp = []execResp{{code: 0}, {stdout: "x\n"}}
		}
		resp = append(resp, after[0])
		if !r.SkipWrite {
			resp = append(resp, execResp{code: 0})
		}
		resp = append(resp, after[1:]...)
		s := &scriptedExec{responses: resp}
		return s, lockoutOf(t, seamedWriter(s, c).Apply(ctx, srv, r))
	}
	moved := func(s *scriptedExec, name string) bool { return slices.Contains(s.cmds, restoreKeys2Cmd(name)) }
	listings := func(s *scriptedExec) int {
		n := 0
		for _, c := range s.cmds {
			if c == listKeys2Cmd() {
				n++
			}
		}
		return n
	}
	for name, r := range map[string]Request{"keys2-only": keys2Only, "full write": full} {
		t.Run(name, func(t *testing.T) {
			t.Run("the copy is found and moved back", func(t *testing.T) {
				s, lo := run(t, r, rejected(), drop, execResp{stdout: listed}, execResp{code: 0})
				if lo.RestoreKeys2 != nil || !moved(s, copyName) {
					t.Fatalf("RestoreKeys2 = %v, cmds = %q", lo.RestoreKeys2, s.cmds)
				}
				if !strings.Contains(lo.Error(), "lockout prevented") {
					t.Errorf("err = %q", lo)
				}
			})
			t.Run("an unparseable reply is the same unknown state", func(t *testing.T) {
				s, lo := run(t, r, rejected(), execResp{stdout: "garbage\n"}, execResp{stdout: listed}, execResp{code: 0})
				if lo.RestoreKeys2 != nil || !moved(s, copyName) {
					t.Fatalf("RestoreKeys2 = %v, cmds = %q", lo.RestoreKeys2, s.cmds)
				}
			})
			t.Run("a shell killed by a signal is the same unknown state", func(t *testing.T) {
				s, lo := run(t, r, rejected(), execResp{code: 129}, execResp{stdout: listed}, execResp{code: 0})
				if lo.RestoreKeys2 != nil || !moved(s, copyName) {
					t.Fatalf("RestoreKeys2 = %v, cmds = %q", lo.RestoreKeys2, s.cmds)
				}
			})
			t.Run("the listing is unavailable: unrestored", func(t *testing.T) {
				c := rejected()
				c.fullErrs = []error{kinded(fleet.ErrorKindAuth, "denied")}
				s, lo := run(t, r, c, drop, drop)
				if lo.RestoreKeys2 == nil || moved(s, copyName) || strings.Contains(lo.Error(), "lockout prevented") {
					t.Fatalf("lockout = %q (%+v), cmds = %q", lo, lo, s.cmds)
				}
			})
			t.Run("more than one copy cannot be told apart: unrestored", func(t *testing.T) {
				s, lo := run(t, r, rejected(), drop, execResp{stdout: listed + "sshepherd-keys2 " + copyName + ".20261108T010203Z\n"})
				if lo.RestoreKeys2 == nil || moved(s, copyName) || strings.Contains(lo.Error(), "lockout prevented") {
					t.Fatalf("lockout = %q, cmds = %q", lo, s.cmds)
				}
				if !strings.Contains(lo.RestoreKeys2.Error(), copyName+".20261108T010203Z") {
					t.Errorf("RestoreKeys2 = %v, want the copies named", lo.RestoreKeys2)
				}
			})
			t.Run("a hostile listing is refused: unrestored", func(t *testing.T) {
				s, lo := run(t, r, rejected(), drop, execResp{stdout: "sshepherd-keys2 ../../etc/passwd\n"})
				if lo.RestoreKeys2 == nil || moved(s, "../../etc/passwd") {
					t.Fatalf("lockout = %q, cmds = %q", lo, s.cmds)
				}
			})
			t.Run("a listing that exits nonzero: unrestored", func(t *testing.T) {
				_, lo := run(t, r, rejected(), drop, execResp{code: 1, stderr: "boom"})
				if lo.RestoreKeys2 == nil || strings.Contains(lo.Error(), "lockout prevented") {
					t.Fatalf("lockout = %q", lo)
				}
			})
			t.Run("a move-back that fails: unrestored", func(t *testing.T) {
				_, lo := run(t, r, rejected(), drop, execResp{stdout: listed}, execResp{code: changedExit})
				if lo.RestoreKeys2 == nil || strings.Contains(lo.Error(), "lockout prevented") {
					t.Fatalf("lockout = %q", lo)
				}
			})
			t.Run("the file is still in place: nothing to move", func(t *testing.T) {
				s, lo := run(t, r, rejected(), drop, execResp{stdout: "sshepherd-keys2-present\n"})
				if lo.RestoreKeys2 != nil || moved(s, copyName) || listings(s) != 1 {
					t.Fatalf("lockout = %+v, cmds = %q", lo, s.cmds)
				}
			})
			t.Run("no file and no copy: nothing to move", func(t *testing.T) {
				s, lo := run(t, r, rejected(), drop, execResp{})
				if lo.RestoreKeys2 != nil || moved(s, copyName) || listings(s) != 1 {
					t.Fatalf("lockout = %+v, cmds = %q", lo, s.cmds)
				}
			})
		})
	}
	t.Run("a keys2-only run that moved nothing says so", func(t *testing.T) {
		_, lo := run(t, keys2Only, rejected(), drop, execResp{stdout: "sshepherd-keys2-present\n"})
		if !lo.Keys2Untouched || strings.Contains(lo.Error(), "lockout prevented") || strings.Contains(lo.Error(), "moved authorized_keys2 back") {
			t.Errorf("lockout = %q", lo)
		}
	})
	t.Run("the listing retries over the one reconnect", func(t *testing.T) {
		c := rejected()
		s, lo := run(t, keys2Only, c, drop, drop, execResp{stdout: listed}, execResp{code: 0})
		if lo.RestoreKeys2 != nil || c.fullSeen != 2 || listings(s) != 2 {
			t.Fatalf("RestoreKeys2 = %v, full connects = %d, cmds = %q", lo.RestoreKeys2, c.fullSeen, s.cmds)
		}
	})
	t.Run("a session that never opened moved nothing: no listing", func(t *testing.T) {
		notOpened := execResp{err: fmt.Errorf("%w: gone", sshconn.ErrSessionNotOpened)}
		s, lo := run(t, keys2Only, rejected(), notOpened)
		if lo.RestoreKeys2 != nil || listings(s) != 0 || !lo.Keys2Untouched {
			t.Fatalf("lockout = %+v, cmds = %q", lo, s.cmds)
		}
	})
	t.Run("a refused move moved nothing: no listing", func(t *testing.T) {
		s, lo := run(t, keys2Only, rejected(), execResp{code: unsafePathExit})
		if lo.RestoreKeys2 != nil || listings(s) != 0 {
			t.Fatalf("lockout = %+v, cmds = %q", lo, s.cmds)
		}
	})
	// The script's own failures come before its mv (exit below 128): the
	// move did not happen, so nothing is listed and keys2 is untouched.
	t.Run("a script failure before the move moved nothing: no listing", func(t *testing.T) {
		s, lo := run(t, keys2Only, rejected(), execResp{code: 1, stderr: "mv: cannot move"})
		if lo.RestoreKeys2 != nil || listings(s) != 0 || !lo.Keys2Untouched {
			t.Fatalf("lockout = %+v, cmds = %q", lo, s.cmds)
		}
	})
	// F004: when the move-back state is unknown, a keys2-only run never says
	// keys2 was left alone; it says moving it back failed.
	for name, after := range map[string][]execResp{
		"the listing is unavailable": {drop, drop},
		"the listing exits nonzero":  {drop, {code: 1, stderr: "boom"}},
		"more than one copy":         {drop, {stdout: listed + "sshepherd-keys2 " + copyName + ".20261108T010203Z\n"}},
	} {
		t.Run("keys2-only, "+name+": never untouched", func(t *testing.T) {
			c := rejected()
			c.fullErrs = []error{kinded(fleet.ErrorKindAuth, "denied")}
			_, lo := run(t, keys2Only, c, after...)
			if lo.RestoreKeys2 == nil || lo.Keys2Untouched {
				t.Fatalf("lockout = %+v", lo)
			}
			if msg := lo.Error(); !strings.Contains(msg, "moving authorized_keys2 back failed") || strings.Contains(msg, "was not moved aside") {
				t.Errorf("err = %q, want the failed move-back", msg)
			}
		})
	}
	t.Run("a passing login never lists", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "x\n"}, drop}}
		err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, keys2Only)
		if err == nil || listings(s) != 0 {
			t.Fatalf("err = %v, cmds = %q", err, s.cmds)
		}
	})
	t.Run("a missing copy at the move-back is reported", func(t *testing.T) {
		_, lo := run(t, keys2Only, rejected(), drop, execResp{stdout: listed}, execResp{code: sshconn.FileAbsentExit})
		if lo.RestoreKeys2 == nil || !strings.Contains(lo.RestoreKeys2.Error(), "is gone") {
			t.Errorf("RestoreKeys2 = %v", lo.RestoreKeys2)
		}
	})
}
