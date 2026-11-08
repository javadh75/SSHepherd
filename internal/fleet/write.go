package fleet

import "errors"

// Keys2DisabledSuffix is appended to ~/.ssh/authorized_keys2 when a write
// disables it (WriteRequest.DisableKeys2).
const Keys2DisabledSuffix = ".sshepherd.disabled"

// Snapshot is the phase-1 state a write is conditional on: the file was
// absent, or it held Size bytes with POSIX cksum Cksum. The write script
// refuses (a changed-since-plan refusal) when the file no longer matches,
// so content that appeared after the plan was shown is never silently
// overwritten.
type Snapshot struct {
	Absent bool
	Size   int
	Cksum  uint32
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
