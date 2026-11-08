package sshwrite

import (
	"context"
	"errors"
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
