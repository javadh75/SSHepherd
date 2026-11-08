package fleet

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// managed is a managed-header file (authkeys.ManagedHeader plus one line),
// spelled out so this stdlib-only package's tests import nothing else.
const managed = "# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'.\nkey-line\n"

// TestIsRefusal: only errors wrapped by Refused count, through any wrapper;
// the message is the wrapped error's, unchanged.
func TestIsRefusal(t *testing.T) {
	base := errors.New("/home/u/.ssh/authorized_keys changed since the plan was read")
	r := Refused(base)
	if !IsRefusal(r) || !IsRefusal(fmt.Errorf("srv: %w", r)) {
		t.Fatal("wrapped refusal not recognized")
	}
	if r.Error() != base.Error() || !errors.Is(r, base) {
		t.Fatalf("Refused changed the error: %q", r.Error())
	}
	if IsRefusal(base) || IsRefusal(nil) {
		t.Fatal("plain error counted as a refusal")
	}
}

func TestSnapshotOf(t *testing.T) {
	if got := SnapshotOf(true, []byte("ignored")); got != (Snapshot{Absent: true}) {
		t.Errorf("absent = %+v", got)
	}
	if got := SnapshotOf(false, []byte("x\n")); got.Size != 2 || got.Cksum != Cksum([]byte("x\n")) {
		t.Errorf("present = %+v", got)
	}
}

func TestHeldKeyLabel(t *testing.T) {
	if got := (HeldKey{Fingerprint: "SHA256:x", Source: SourceAgent}).Label(); got != "SHA256:x (agent)" {
		t.Errorf("Label = %q", got)
	}
}

func TestCksumMatchesPOSIXCksum(t *testing.T) {
	// Fixed vectors pin the algorithm even where no cksum binary exists.
	vectors := []struct {
		in   string
		want uint32
	}{
		{"", 4294967295},
		{"abc", 1219131554},
	}
	for _, v := range vectors {
		if got := Cksum([]byte(v.in)); got != v.want {
			t.Errorf("Cksum(%q) = %d, want %d", v.in, got, v.want)
		}
	}
	bin, err := exec.LookPath("cksum")
	if err != nil {
		t.Skip("no cksum binary to cross-check against")
	}
	inputs := [][]byte{[]byte(managed), bytes.Repeat([]byte("ssh-ed25519 AAAA x\n"), 4000), {0, 1, 2, 255}}
	for _, in := range inputs {
		c := exec.CommandContext(t.Context(), bin)
		c.Stdin = bytes.NewReader(in)
		out, err := c.Output()
		if err != nil {
			t.Fatalf("cksum: %v", err)
		}
		f := strings.Fields(string(out))
		snap := SnapshotOf(false, in)
		if len(f) < 2 || f[0] != strconv.FormatUint(uint64(snap.Cksum), 10) || f[1] != strconv.Itoa(snap.Size) {
			t.Errorf("cksum binary says %q, Go says %d %d", out, snap.Cksum, snap.Size)
		}
	}
}

type outcomeKind struct {
	kind ErrorKind
	msg  string
}

func (e outcomeKind) Error() string        { return e.msg }
func (e outcomeKind) ErrorKind() ErrorKind { return e.kind }

func TestUnprovenErrorMessages(t *testing.T) {
	const dial = "dial tcp 10.0.0.1:22: i/o timeout"
	for _, tt := range []struct {
		name string
		err  UnprovenError
		want string
	}{
		{"network", UnprovenError{Attempts: 4, Last: outcomeKind{ErrorKindDial, dial}},
			"written and verified, but the login check could not reach the server after 4 attempts (" + dial + ") — kept the new file; run sshepherd audit to confirm"},
		{"one attempt", UnprovenError{Attempts: 1, Last: outcomeKind{ErrorKindDial, dial}},
			"written and verified, but the login check could not reach the server after 1 attempt (" + dial + ") — kept the new file; run sshepherd audit to confirm"},
		{"agent", UnprovenError{Attempts: 2, Last: outcomeKind{ErrorKindAgent, "none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)"}},
			"written and verified, but the login check could not offer the surviving keys you hold after 2 attempts (none of the 1 surviving keys is offered (agent locked, or keys removed since the plan)) — kept the new file; unlock the agent or re-add the key, then run sshepherd audit to confirm"},
		{"host key", UnprovenError{Attempts: 1, HostKey: true, Last: outcomeKind{ErrorKindHostKeyChanged, "host key changed"}},
			"written and verified, but the login check stopped at a host-key alarm (host key changed) — kept the new file; check known_hosts, then run sshepherd audit"},
		{"budget", UnprovenError{Last: errors.New("session budget exhausted before the login check")},
			"written and verified, but the session budget ran out before the login check could start — kept the new file; run sshepherd audit to confirm"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
	e := &UnprovenError{Attempts: 1, Last: outcomeKind{ErrorKindHostKeyRevoked, "revoked"}}
	if got := ErrorKindOf(e); got != ErrorKindHostKeyRevoked {
		t.Errorf("ErrorKindOf = %q, want the last failure's kind through Unwrap", got)
	}
}

func TestLockoutErrorMessages(t *testing.T) {
	probe := errors.New("auth failed")
	restored := "lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: auth failed)"
	for _, tt := range []struct {
		name string
		err  LockoutError
		want string
	}{
		{"restored", LockoutError{Path: "~/k", Probe: probe}, restored},
		{"keys2 alone failed", LockoutError{Path: "~/k", Probe: probe, RestoreKeys2: errors.New("kept")},
			"restored previous file (post-write login offering only the surviving keys you hold failed: auth failed), but restoring authorized_keys2 failed (kept)"},
		{"keys2-only, moved back", LockoutError{Path: "~/k", Probe: probe, FileKept: true},
			"lockout prevented — moved authorized_keys2 back (post-write login offering only the surviving keys you hold failed: auth failed); authorized_keys was not changed"},
		{"keys2-only, move-back failed", LockoutError{Path: "~/k", Probe: probe, FileKept: true, RestoreKeys2: errors.New("kept")},
			"post-write login offering only the surviving keys you hold failed (auth failed) and moving authorized_keys2 back failed (kept); authorized_keys was not changed"},
		{"restore failed", LockoutError{Path: "~/k", Probe: probe, Restore: errors.New("denied")},
			"post-write login offering only the surviving keys you hold failed (auth failed) AND restoring the previous file failed (denied) — the previous version is at ~/k" + BackupSuffix + "; repair it over a session that is still open"},
		{"restore and keys2 both failed", LockoutError{Path: "~/k", Probe: probe, Restore: errors.New("denied"), RestoreKeys2: errors.New("kept")},
			"post-write login offering only the surviving keys you hold failed (auth failed) AND restoring the previous file failed (denied\nkept) — the previous version is at ~/k" + BackupSuffix + "; repair it over a session that is still open"},
		{"reconnect refused", LockoutError{Path: "~/k", Probe: probe, Restore: ErrNoSession},
			"connection dropped after the upload started and a fresh login offering the keys you hold was refused (auth failed) — the new file may lock you out; the previous version is at ~/k" + BackupSuffix},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
	wrapped := &LockoutError{Probe: outcomeKind{ErrorKindAuth, "x"}, RestoreKeys2: errors.New("y")}
	if got := ErrorKindOf(wrapped); got != ErrorKindAuth {
		t.Errorf("ErrorKindOf = %q, want the probe's kind", got)
	}
	bothKinded := &LockoutError{Probe: outcomeKind{ErrorKindAuth, "x"}, Restore: outcomeKind{ErrorKindTimeout, "y"}, RestoreKeys2: outcomeKind{ErrorKindDial, "z"}}
	if got := ErrorKindOf(bothKinded); got != ErrorKindAuth {
		t.Errorf("ErrorKindOf with kinded restore errors = %q, want the probe's kind", got)
	}
}
