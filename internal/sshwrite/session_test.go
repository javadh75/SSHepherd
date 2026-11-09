package sshwrite

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

const busyOwner = "sshepherd-lock 1192\nv1 ci-runner-3 4121 99 1000\n"

func rejected() *seamedConnect {
	return &seamedConnect{probeErr: kinded(fleet.ErrorKindAuth, "ssh: unable to authenticate")}
}

func lockoutOf(t *testing.T, err error) *LockoutError {
	t.Helper()
	var lo *LockoutError
	if !errors.As(err, &lo) {
		t.Fatalf("err = %v, want *LockoutError", err)
	}
	return lo
}

func TestApplyRestoreRetriesBusyLock(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	restoreCmd := restoreCmdFor(sshconn.DefaultAuthorizedKeysPath, false, SnapshotOf(false, []byte("x\n")))
	count := func(s *scriptedExec) int {
		n := 0
		for _, c := range s.cmds {
			if c == restoreCmd {
				n++
			}
		}
		return n
	}
	t.Run("a busy lock that frees is retried", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: lockedExit}, {code: lockedExit}, {code: 0}}}
		w, clk := seamedWriter(s, rejected()), newClock()
		w.now, w.sleep = clk.now, clk.sleep
		lo := lockoutOf(t, w.Apply(ctx, srv, req("x\n")))
		if lo.Restore != nil || count(s) != 3 {
			t.Errorf("Restore = %v, restores = %d", lo.Restore, count(s))
		}
		if want := []time.Duration{time.Second, 3 * time.Second}; !slices.Equal(clk.slept, want) {
			t.Errorf("waits = %v, want %v", clk.slept, want)
		}
	})
	t.Run("a lock that never frees names its owner", func(t *testing.T) {
		busy := execResp{code: lockedExit, stdout: busyOwner}
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, busy, busy, busy, busy}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, req("x\n")))
		want := "restore on web-1 refused: another apply holds the lock (held by ci-runner-3 pid 4121 for 3m12s) after 4 attempts"
		if lo.Restore == nil || lo.Restore.Error() != want {
			t.Errorf("Restore = %v, want %q", lo.Restore, want)
		}
		if count(s) != 4 {
			t.Errorf("restores = %d, want 4", count(s))
		}
		if fleet.IsRefusal(lo) {
			t.Error("an unrestored lockout must never read as a refusal")
		}
	})
	t.Run("any other restore exit is final", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: 1, stderr: "mv: denied"}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || count(s) != 1 {
			t.Errorf("Restore = %v, restores = %d", lo.Restore, count(s))
		}
	})
	t.Run("the budget stops the waits", func(t *testing.T) {
		clk := newClock()
		c := rejected()
		c.onlyHook = func(context.Context) { clk.t = clk.t.Add(119500 * time.Millisecond) }
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: lockedExit, stdout: busyOwner}}}
		w := seamedWriter(s, c)
		w.now, w.sleep = clk.now, clk.sleep
		lo := lockoutOf(t, w.Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || !strings.Contains(lo.Restore.Error(), "after 1 attempt") || len(clk.slept) != 0 {
			t.Errorf("Restore = %v, waits = %v", lo.Restore, clk.slept)
		}
	})
	t.Run("a wait the context ends stops the retries", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: lockedExit, stdout: busyOwner}}}
		w := seamedWriter(s, rejected())
		waits := 0
		w.sleep = func(context.Context, time.Duration) error {
			waits++
			return errors.New("context ended")
		}
		lo := lockoutOf(t, w.Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || !strings.Contains(lo.Restore.Error(), "after 1 attempt") || count(s) != 1 || waits != 1 {
			t.Errorf("Restore = %v, restores = %d, waits = %d", lo.Restore, count(s), waits)
		}
	})
	t.Run("a failed keys2 move-back is reported apart from the restored file", func(t *testing.T) {
		r := req("x\n")
		r.DisableKeys2 = true
		const moved = "sshepherd-keys2 authorized_keys2" + fleet.Keys2DisabledSuffix + "\n"
		s := &scriptedExec{responses: []execResp{{code: 0}, {code: 0, stdout: "x\n"}, {code: 0, stdout: moved}, {code: 0}, {code: changedExit}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, r))
		if lo.Restore != nil || lo.RestoreKeys2 == nil {
			t.Fatalf("Restore = %v, RestoreKeys2 = %v", lo.Restore, lo.RestoreKeys2)
		}
		if !strings.Contains(lo.Error(), "restored previous file") || !strings.Contains(lo.Error(), "restoring authorized_keys2 failed") {
			t.Errorf("err = %q", lo)
		}
	})
}

func TestLockedReadCmdThroughRealSh(t *testing.T) {
	forEachShell(t, func(t *testing.T, sh []string) {
		t.Run("reads under the lock and releases it", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "bytes\n")
			code, out := runShOut(t, sh, lockedReadCmdFor(target), home, nil)
			if code != 0 || out != "bytes\n" {
				t.Fatalf("exit = %d, out = %q", code, out)
			}
			assertNoResidue(t, target)
		})
		t.Run("a held lock exits 47", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			writeFile(t, target, "bytes\n")
			if err := os.Mkdir(target+lockSuffix, 0o700); err != nil {
				t.Fatal(err)
			}
			if code, _ := runShOut(t, sh, lockedReadCmdFor(target), home, nil); code != lockedExit {
				t.Fatalf("exit = %d, want %d", code, lockedExit)
			}
		})
		t.Run("an absent file in an existing directory is 44", func(t *testing.T) {
			home := t.TempDir()
			target := filepath.Join(home, "auth")
			if code, _ := runShOut(t, sh, lockedReadCmdFor(target), home, nil); code != sshconn.FileAbsentExit {
				t.Fatalf("exit = %d, want 44", code)
			}
			assertNoResidue(t, target)
		})
		t.Run("an absent directory is 44, not a lock failure", func(t *testing.T) {
			home := t.TempDir()
			if code, _ := runShOut(t, sh, lockedReadCmdFor(filepath.Join(home, "no", "auth")), home, nil); code != sshconn.FileAbsentExit {
				t.Fatalf("exit = %d, want 44", code)
			}
		})
	})
}

func TestApplyReconnectAfterDrop(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	const content = "rendered\n"
	drop := execResp{err: errors.New("EOF")}
	read := lockedReadCmdFor(sshconn.DefaultAuthorizedKeysPath)
	stages := []struct {
		name string
		head []execResp // what ran before the locked read
	}{
		{"write dropped", []execResp{drop}},
		{"verify dropped", []execResp{{code: 0}, drop}},
	}
	for _, st := range stages {
		t.Run(st.name, func(t *testing.T) {
			script := func(after ...execResp) *scriptedExec {
				return &scriptedExec{responses: append(append([]execResp{}, st.head...), after...)}
			}
			t.Run("the render is in place: the login check runs", func(t *testing.T) {
				s := script(execResp{stdout: content})
				c := &seamedConnect{}
				if err := seamedWriter(s, c).Apply(ctx, srv, req(content)); err != nil {
					t.Fatalf("Apply: %v", err)
				}
				if s.cmds[len(st.head)] != read || s.cmds[len(s.cmds)-1] != probeCmd || c.fullSeen != 2 {
					t.Errorf("cmds = %q, full connects = %d", s.cmds, c.fullSeen)
				}
				if c.opts[0].RequireOffer || !c.opts[1].RequireOffer {
					t.Errorf("RequireOffer on the write connect = %v, on the reconnect = %v; want false, true", c.opts[0].RequireOffer, c.opts[1].RequireOffer)
				}
			})
			t.Run("the snapshot still matches: original untouched", func(t *testing.T) {
				err := seamedWriter(script(execResp{stdout: "old\n"}), &seamedConnect{}).Apply(ctx, srv, req(content))
				want := "connection dropped before the rename; original untouched (re-checked under the lock)"
				if err == nil || err.Error() != want {
					t.Fatalf("err = %v, want %q", err, want)
				}
			})
			t.Run("other bytes are an unknown state", func(t *testing.T) {
				err := seamedWriter(script(execResp{stdout: "other\n"}), &seamedConnect{}).Apply(ctx, srv, req(content))
				want := "connection dropped; the file is in an unknown state (previous version at ~/.ssh/authorized_keys.sshepherd.bak) — run sshepherd audit"
				if err == nil || err.Error() != want {
					t.Fatalf("err = %v, want %q", err, want)
				}
			})
			t.Run("a busy lock is waited out", func(t *testing.T) {
				s := script(execResp{code: lockedExit}, execResp{code: lockedExit}, execResp{stdout: content})
				w, clk := seamedWriter(s, &seamedConnect{}), newClock()
				w.now, w.sleep = clk.now, clk.sleep
				if err := w.Apply(ctx, srv, req(content)); err != nil {
					t.Fatalf("Apply: %v", err)
				}
				if want := []time.Duration{time.Second, 3 * time.Second}; !slices.Equal(clk.slept, want) {
					t.Errorf("waits = %v, want %v", clk.slept, want)
				}
			})
			t.Run("a lock that never frees is an unknown state", func(t *testing.T) {
				busy := execResp{code: lockedExit}
				err := seamedWriter(script(busy, busy, busy, busy), &seamedConnect{}).Apply(ctx, srv, req(content))
				if err == nil || !strings.Contains(err.Error(), "unknown state") {
					t.Fatalf("err = %v", err)
				}
			})
			t.Run("a read that also drops is an unknown state", func(t *testing.T) {
				err := seamedWriter(script(drop), &seamedConnect{}).Apply(ctx, srv, req(content))
				if err == nil || !strings.Contains(err.Error(), "unknown state") {
					t.Fatalf("err = %v", err)
				}
			})
			t.Run("a refused reconnect is an unrestored lockout", func(t *testing.T) {
				c := &seamedConnect{fullErrs: []error{kinded(fleet.ErrorKindAuth, "unable to authenticate")}}
				err := seamedWriter(script(), c).Apply(ctx, srv, req(content))
				lo := lockoutOf(t, err)
				if !errors.Is(lo.Restore, fleet.ErrNoSession) {
					t.Fatalf("Restore = %v", lo.Restore)
				}
				if !strings.Contains(err.Error(), "a fresh login offering the keys you hold was refused") {
					t.Errorf("err = %q", err)
				}
			})
			t.Run("a reconnect that fails otherwise keeps its kind", func(t *testing.T) {
				c := &seamedConnect{fullErrs: []error{kinded(fleet.ErrorKindHostKeyChanged, "host key changed")}}
				err := seamedWriter(script(), c).Apply(ctx, srv, req(content))
				if err == nil || !strings.Contains(err.Error(), "unknown state") || fleet.ErrorKindOf(err) != fleet.ErrorKindHostKeyChanged {
					t.Fatalf("err = %v (kind %q)", err, fleet.ErrorKindOf(err))
				}
			})
			t.Run("a reconnect with nothing to offer proves nothing", func(t *testing.T) {
				c := &seamedConnect{fullErrs: []error{kinded(fleet.ErrorKindAgent, "no key to offer (agent locked, or keys removed since the plan)")}}
				err := seamedWriter(script(), c).Apply(ctx, srv, req(content))
				var lo *LockoutError
				if errors.As(err, &lo) || err == nil || !strings.Contains(err.Error(), "unknown state") || fleet.ErrorKindOf(err) != fleet.ErrorKindAgent {
					t.Fatalf("err = %v (kind %q), want an unknown state, never a lockout", err, fleet.ErrorKindOf(err))
				}
			})
		})
	}
	t.Run("a session that never opened did not start the upload", func(t *testing.T) {
		never := execResp{err: &sshconn.Error{Kind: fleet.ErrorKindRemote, Err: sshconn.ErrSessionNotOpened}}
		refused := []error{kinded(fleet.ErrorKindAuth, "unable to authenticate")}
		t.Run("in stage 1: a refused reconnect is not a lockout", func(t *testing.T) {
			err := seamedWriter(&scriptedExec{responses: []execResp{never}}, &seamedConnect{fullErrs: refused}).Apply(ctx, srv, req(content))
			var lo *LockoutError
			if errors.As(err, &lo) || err == nil || !strings.Contains(err.Error(), "unknown state") || fleet.ErrorKindOf(err) != fleet.ErrorKindAuth {
				t.Fatalf("err = %v (kind %q), want an unknown state keeping the kind", err, fleet.ErrorKindOf(err))
			}
		})
		t.Run("in verify: stage 1 had finished, so it is a lockout", func(t *testing.T) {
			err := seamedWriter(&scriptedExec{responses: []execResp{{code: 0}, never}}, &seamedConnect{fullErrs: refused}).Apply(ctx, srv, req(content))
			if lo := lockoutOf(t, err); !errors.Is(lo.Restore, fleet.ErrNoSession) {
				t.Fatalf("Restore = %v", lo.Restore)
			}
		})
	})
	t.Run("a verify that read different bytes never reconnects", func(t *testing.T) {
		c := &seamedConnect{}
		err := seamedWriter(&scriptedExec{responses: []execResp{{code: 0}, {stdout: "tampered\n"}}}, c).Apply(ctx, srv, req(content))
		if err == nil || !strings.Contains(err.Error(), "differ") || c.fullSeen != 1 {
			t.Fatalf("err = %v, full connects = %d", err, c.fullSeen)
		}
	})
}

func TestApplyRestoreOverDeadConnection(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	drop := execResp{err: errors.New("EOF")}
	t.Run("retried over the one reconnect", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {stdout: "x\n"}, drop, {code: 0}}}
		c := rejected()
		lo := lockoutOf(t, seamedWriter(s, c).Apply(ctx, srv, req("x\n")))
		if lo.Restore != nil || c.fullSeen != 2 {
			t.Errorf("Restore = %v, full connects = %d", lo.Restore, c.fullSeen)
		}
	})
	t.Run("a failed reconnect leaves the lockout unrestored", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 0}, {stdout: "x\n"}, drop}}
		c := rejected()
		c.fullErrs = []error{kinded(fleet.ErrorKindDial, "refused")}
		lo := lockoutOf(t, seamedWriter(s, c).Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil {
			t.Error("Restore = nil, want the failure")
		}
	})
	t.Run("only one reconnect per write", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{drop, {stdout: "x\n"}, drop}} // write dropped, render in place, restore dropped
		c := rejected()
		lo := lockoutOf(t, seamedWriter(s, c).Apply(ctx, srv, req("x\n")))
		if lo.Restore == nil || c.fullSeen != 2 {
			t.Errorf("Restore = %v, full connects = %d", lo.Restore, c.fullSeen)
		}
	})
}

func TestApplySkipWrite(t *testing.T) {
	ctx, srv := context.Background(), config.Server{Name: "web-1"}
	const moved = "sshepherd-keys2 authorized_keys2" + fleet.Keys2DisabledSuffix + "\n"
	r := req("x\n")
	r.DisableKeys2, r.SkipWrite = true, true
	t.Run("the first command is the read, and no write script runs", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "x\n"}, {stdout: moved}}}
		if err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if s.cmds[0] != unchangedReadCmdFor(sshconn.DefaultAuthorizedKeysPath) || s.cmds[1] != disableKeys2Cmd() || s.cmds[2] != probeCmd {
			t.Errorf("cmds = %q", s.cmds)
		}
	})
	t.Run("a mismatch is a refusal", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "changed\n"}}}
		err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r)
		var chg *ChangedError
		if !errors.As(err, &chg) || !fleet.IsRefusal(err) || len(s.cmds) != 1 {
			t.Fatalf("err = %v, cmds = %q", err, s.cmds)
		}
	})
	t.Run("an absent file is a refusal", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: sshconn.FileAbsentExit}}}
		if err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r); !fleet.IsRefusal(err) {
			t.Fatalf("err = %v, want a refusal", err)
		}
	})
	t.Run("a read that drops changes nothing and reports the failure", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{err: errors.New("EOF")}}}
		c := &seamedConnect{}
		err := seamedWriter(s, c).Apply(ctx, srv, r)
		if err == nil || fleet.IsRefusal(err) || c.fullSeen != 1 {
			t.Fatalf("err = %v, full connects = %d (no reconnect: nothing was written)", err, c.fullSeen)
		}
	})
	t.Run("a remote read error reports the failure", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{code: 1, stderr: "denied"}}}
		if err := seamedWriter(s, &seamedConnect{}).Apply(ctx, srv, r); err == nil || fleet.IsRefusal(err) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("a REJECTED login restores only keys2", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "x\n"}, {stdout: moved}, {code: 0}}}
		lo := lockoutOf(t, seamedWriter(s, rejected()).Apply(ctx, srv, r))
		if lo.Restore != nil || lo.RestoreKeys2 != nil {
			t.Fatalf("lockout = %+v", lo)
		}
		last := s.cmds[len(s.cmds)-1]
		if last != restoreKeys2Cmd("authorized_keys2"+fleet.Keys2DisabledSuffix) || strings.Contains(strings.Join(s.cmds, "\n"), bakSuffix) {
			t.Errorf("cmds = %q, want only the keys2 move-back and no .bak", s.cmds)
		}
	})
	t.Run("an UNPROVEN login keeps keys2 disabled", func(t *testing.T) {
		s := &scriptedExec{responses: []execResp{{stdout: "x\n"}, {stdout: moved}}}
		c := &seamedConnect{probeErr: kinded(fleet.ErrorKindDial, "refused")}
		err := seamedWriter(s, c).Apply(ctx, srv, r)
		unprovenFrom(t, err)
		if len(s.cmds) != 2 {
			t.Errorf("cmds = %q, want no move-back", s.cmds)
		}
	})
}
