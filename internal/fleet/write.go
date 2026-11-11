package fleet

import (
	"errors"
	"fmt"
)

// Keys2DisabledSuffix is appended to ~/.ssh/authorized_keys2 when a write
// disables it (WriteRequest.DisableKeys2).
const Keys2DisabledSuffix = ".sshepherd.disabled"

// BackupSuffix names the previous version the write protocol keeps next to
// the target: replaced by every write that changes the file, and removed by
// a write that creates it, so it only ever holds the bytes the latest write
// replaced.
const BackupSuffix = ".sshepherd.bak"

// Snapshot is the phase-1 state a write is conditional on: the file was
// absent, or it held Size bytes with POSIX cksum Cksum. The write script
// refuses (a changed-since-plan refusal) when the file no longer matches,
// so content that appeared after the plan was shown is never silently
// overwritten.
type Snapshot struct {
	Absent bool
	Size   int
	Cksum  uint32
	// Managed reports that the snapshot's first line is a managed header
	// (authkeys.ParseHeader's verdict, set by the caller — this package is
	// stdlib-only). The write script takes the one-time .orig backup only
	// when it is false, after the compare-and-swap proved the file is still
	// these bytes.
	Managed bool
}

// SnapshotOf builds the snapshot of phase-1 bytes read (or of an absent
// file).
func SnapshotOf(absent bool, content []byte) Snapshot {
	if absent {
		return Snapshot{Absent: true}
	}
	return Snapshot{Size: len(content), Cksum: Cksum(content)}
}

// WriteRequest is one server's write: the rendered bytes, the phase-1
// snapshot they replace, and the SHA256 fingerprints of the held keys (key
// files or agent) that must still log in afterwards (the post-write probe
// offers exactly these, in this order).
type WriteRequest struct {
	Content   []byte
	Expect    Snapshot
	Survivors []string
	// DisableKeys2 moves a non-empty ~/.ssh/authorized_keys2 aside (to
	// Keys2DisabledSuffix) after the write verifies and before the login
	// probe, so the probe proves the survivors log in without it.
	DisableKeys2 bool
	// SkipWrite: authorized_keys already holds Content (a plan that only
	// disables authorized_keys2), so no lock, backup, upload or rename runs:
	// the writer applies the write path's symlink and ownership refusals,
	// re-reads and compares the file (a mismatch is a refusal), disables
	// authorized_keys2 and proves the login. A rejected login check
	// restores only authorized_keys2.
	SkipWrite bool
	// HeadlessProof lists key-file fingerprints for one more login after a
	// passing probe (D9b: warn-only; it never restores); empty skips it.
	HeadlessProof []string
	// ProbeForward is set on a bastion another server's via names (spec S5):
	// every dependent's host:port. After the login probe runs its command,
	// the writer opens a direct-tcpip channel to each and closes it at once;
	// a prohibited channel is a rejected login check (restore). Empty skips
	// it.
	ProbeForward []string
	// OnWarning receives the sanitized cause when the headless proof fails.
	OnWarning func(cause string)
}

// cksumTable is the CRC-32 table for POSIX cksum's polynomial 0x04C11DB7,
// MSB-first (not hash/crc32's reflected IEEE variant).
var cksumTable = func() [256]uint32 {
	var t [256]uint32
	for i := range t {
		c := uint32(i) << 24 // #nosec G115 -- i < 256
		for range 8 {
			if c&0x80000000 != 0 {
				c = c<<1 ^ 0x04C11DB7
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return t
}()

// Cksum computes the POSIX cksum CRC of b — the value `cksum < file` prints
// first — so the write script can compare-and-swap with a POSIX-only tool
// (busybox, dash and macOS all ship cksum; sha256sum is not POSIX). The
// threat model is concurrent honest edits, not an adversary who already
// controls the file, so a CRC is sufficient.
func Cksum(b []byte) uint32 {
	var crc uint32
	for _, c := range b {
		crc = crc<<8 ^ cksumTable[byte(crc>>24)^c]
	}
	for n := len(b); n > 0; n >>= 8 {
		crc = crc<<8 ^ cksumTable[byte(crc>>24)^byte(n)] // #nosec G115 -- low byte of the length, by definition
	}
	return ^crc
}

// ErrWriteNotStarted marks a write interrupted (ctx canceled) before it
// began: nothing on the server changed.
var ErrWriteNotStarted = errors.New("interrupted before the write started")

// RefusalError marks a write the server declined before anything changed
// (symlink, unsafe path, changed since plan, locked). Error() and the
// chain are Err's, unchanged, so errors.As still reaches the concrete type.
type RefusalError struct{ Err error }

func (e *RefusalError) Error() string { return e.Err.Error() }
func (e *RefusalError) Unwrap() error { return e.Err }

// Refused marks err as a refusal.
func Refused(err error) error { return &RefusalError{Err: err} }

// IsRefusal reports whether a RefusalError is anywhere in err's chain.
func IsRefusal(err error) bool {
	var r *RefusalError
	return errors.As(err, &r)
}

// ErrNoSession is LockoutError.Restore when no session could be opened to
// restore over: the reconnect after a dropped write was refused.
var ErrNoSession = errors.New("no session left to restore over")

// LockoutError reports a write that verified but whose surviving held keys
// (key files or agent) could not log in on a fresh connection, or whose
// reconnect after a dropped connection was refused. Restore is nil when the
// previous authorized_keys was put back; RestoreKeys2 is the separate
// authorized_keys2 move-back. Either failure is an unrestored lockout (spec
// section 2), and the text never claims the lockout was prevented: a key
// whose authorized_keys line refuses this client (from=) may have logged in
// only through authorized_keys2.
type LockoutError struct {
	Path         string
	Probe        error // why the login failed
	Restore      error // nil when the previous file was put back, or FileKept
	RestoreKeys2 error // nil when authorized_keys2 went back, or was not moved
	FileKept     bool  // SkipWrite: authorized_keys was never written, so no file was restored
	// Created: the write created the file, so there is no previous version
	// and the undo is deleting it; the text never points at the backup.
	Created bool
	// Keys2Untouched: FileKept, and authorized_keys2 is known not to have been
	// moved (the move never ran, or a listing found it in place), so nothing
	// was restored and the text claims nothing was.
	Keys2Untouched bool
}

func (e *LockoutError) Error() string {
	const check = "post-write login offering only the surviving keys you hold failed"
	switch {
	case errors.Is(e.Restore, ErrNoSession):
		return fmt.Sprintf("connection dropped after the upload started and a fresh login offering the keys you hold was refused (%v) — the new file may lock you out; %s", e.Probe, e.undoText())
	case e.Restore != nil:
		verb := "restoring the previous file"
		if e.Created {
			verb = "removing the file this write created"
		}
		return fmt.Sprintf("%s (%v) AND %s failed (%v) — %s; repair it over a session that is still open", check, e.Probe, verb, errors.Join(e.Restore, e.RestoreKeys2), e.undoText())
	case e.FileKept && e.Keys2Untouched:
		return fmt.Sprintf("%s (%v); authorized_keys2 was not moved aside and authorized_keys was not changed", check, e.Probe)
	case e.FileKept && e.RestoreKeys2 != nil:
		return fmt.Sprintf("%s (%v) and moving authorized_keys2 back failed (%v); authorized_keys was not changed", check, e.Probe, e.RestoreKeys2)
	case e.FileKept:
		return fmt.Sprintf("lockout prevented — moved authorized_keys2 back (%s: %v); authorized_keys was not changed", check, e.Probe)
	case e.RestoreKeys2 != nil:
		return fmt.Sprintf("%s (%s: %v), but restoring authorized_keys2 failed (%v)", e.restoredText(), check, e.Probe, e.RestoreKeys2)
	}
	return fmt.Sprintf("lockout prevented — %s (%s: %v)", e.restoredText(), check, e.Probe)
}

// undoText says what undoes the write by hand.
func (e *LockoutError) undoText() string {
	if e.Created {
		return "there was no previous file; the undo is deleting " + e.Path
	}
	return "the previous version is at " + e.Path + BackupSuffix
}

// restoredText says what a successful restore did.
func (e *LockoutError) restoredText() string {
	if e.Created {
		return "removed the file this write created, there was no previous file"
	}
	return "restored previous file"
}

// Unwrap keeps the probe's kind first in the chain.
func (e *LockoutError) Unwrap() []error { return []error{e.Probe, e.Restore, e.RestoreKeys2} }

// UnprovenError reports a write that was written and verified but whose
// post-write login never got past authentication (dial, kex, agent, host
// key) after the retries. The
// file is kept because restoring could reinstall a key the manifest
// removed. Any failure after a successful login is a rejected probe, never
// an UnprovenError.
type UnprovenError struct {
	Path     string
	Attempts int
	HostKey  bool  // stopped by a host-key alarm (no retry)
	Last     error // sanitized; its kind is the last probe failure's
}

func (e *UnprovenError) Error() string {
	const kept = " — kept the new file; "
	switch {
	case e.Attempts == 0:
		return "written and verified, but the session budget ran out before the login check could start" + kept + "run sshepherd audit to confirm"
	case e.HostKey:
		return fmt.Sprintf("written and verified, but the login check stopped at a host-key alarm (%v)%scheck known_hosts, then run sshepherd audit", e.Last, kept)
	case ErrorKindOf(e.Last) == ErrorKindAgent:
		return fmt.Sprintf("written and verified, but the login check could not offer the surviving keys you hold after %s (%v)%sunlock the agent or re-add the key, then run sshepherd audit to confirm", attempts(e.Attempts), e.Last, kept)
	}
	return fmt.Sprintf("written and verified, but the login check could not reach the server after %s (%v)%srun sshepherd audit to confirm", attempts(e.Attempts), e.Last, kept)
}

// Unwrap exposes the last failure's kind and hint.
func (e *UnprovenError) Unwrap() error { return e.Last }

func attempts(n int) string {
	if n == 1 {
		return "1 attempt"
	}
	return fmt.Sprintf("%d attempts", n)
}
