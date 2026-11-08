// Package sshwrite performs apply's remote write protocol over one SSH
// connection per server: a single guarded write script (symlink and
// ownership refusals, per-target lock, compare-and-swap against the phase-1
// snapshot, backups, length-checked atomic temp+rename), a read-back verify,
// and a post-write login probe that restores the previous file when the
// surviving keys cannot log in. Command builders are pure and share
// sshconn.PathAssign's quoting discipline (the path enters each script
// exactly once, fully quoted); only the network glue needs the integration
// suite, and even the protocol sequencing is unit-tested through seams.
package sshwrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sanitize"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// Sentinel exit statuses of the write and restore scripts (siblings of
// sshconn.FileAbsentExit, 44). Each maps to a typed error in Apply.
const (
	// symlinkExit: the target is a symlink — mv would replace the link with
	// a regular file, silently diverging what SSHepherd reads from what sshd
	// may read, and breaking config-management setups.
	symlinkExit = 45
	// changedExit: the file no longer matches the phase-1 snapshot the plan
	// was computed from (compare-and-swap failed).
	changedExit = 46
	// lockedExit: another apply holds the per-target lock directory.
	lockedExit = 47
	// unsafePathExit: the parent directory is a symlink, the file or its
	// directory is not owned by the login user, or an ancestor fails the
	// StrictModes-style ownership/mode walk (ancestorCheck).
	unsafePathExit = 48
	// shortWriteExit: the uploaded temp file is not exactly the rendered
	// length (the stream was cut) — the original was left untouched.
	shortWriteExit = 49
)

// Suffixes of the files the write protocol keeps next to the target.
const (
	tmpSuffix  = ".sshepherd.tmp"
	bakSuffix  = ".sshepherd.bak"
	origSuffix = ".sshepherd.orig"
	lockSuffix = ".sshepherd.lock"
	// casSuffix names the staging copy the compare-and-swap checks and
	// that then becomes the backup (writeCmdFor's casBackupBlock).
	casSuffix = ".sshepherd.cas"

	// Keys2DisabledSuffix is appended to ~/.ssh/authorized_keys2 when a
	// write disables it (Request.DisableKeys2).
	Keys2DisabledSuffix = ".sshepherd.disabled"
)

// defaultSessionBudget bounds a write connection's whole life once it is
// established: write, verify, the post-write login probe and a possible
// restore all run under it. It is deliberately independent of the caller's
// per-server deadline, which bounds only the dial and handshake — a write
// that has started must be able to finish, verify and, if need be, roll
// back.
const defaultSessionBudget = 2 * time.Minute

// Snapshot is the phase-1 state a write is conditional on: the file was
// absent, or it held Size bytes with POSIX cksum Cksum. The write script
// refuses (ChangedError) when the file no longer matches, so content that
// appeared after the plan was shown is never silently overwritten.
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

// Request is one server's write: the rendered bytes, the phase-1 snapshot
// they replace, and the SHA256 fingerprints of the held keys (key files or
// agent) that must still log in afterwards (the post-write probe offers
// exactly these, in this order).
type Request struct {
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

// lockPrologue takes the per-target lock (mkdir is atomic on every POSIX
// filesystem) and arranges its removal on every exit path, together with
// the temp file and the CAS staging copy only the lock holder may use (a
// successful run has already renamed both). A lost race or a stale lock exits 47; any other mkdir
// failure re-runs mkdir to surface its real error and exits 1. That re-run
// happens before the EXIT trap exists, so if it succeeds (the holder
// released the lock in between) it removes the directory it just made and
// exits 47 — a retryable lost race, never a stale lock. Signals route
// through exit so the EXIT trap runs.
const lockPrologue = `l="$p"` + lockSuffix + `; mkdir "$l" 2>/dev/null || { [ -d "$l" ] && exit 47; if mkdir "$l"; then rmdir "$l"; exit 47; fi; exit 1; }; trap 'rm -f "$p"` + tmpSuffix + ` "$p"` + casSuffix + `; rmdir "$l" 2>/dev/null' EXIT; trap 'exit 1' HUP INT TERM PIPE`

// ancestorCheck walks the target directory "$d" up to the login user's
// home (or /, for a path outside it) twice — as written, and resolved with
// cd -P — refusing (48) any component owned by someone other than the login
// user or root, and any directory that is group- or other-writable. This is
// sshd's StrictModes walk (which also stops at the home directory): whoever
// can write an ancestor, or owns a symlink along the path, can redirect the
// write, e.g. a link that turns root's write into /root/.ssh. Symlinks are
// judged by owner only (their mode bits are meaningless); the resolved walk
// covers the directories they lead to. ls -ldn reports a symlink itself,
// so the as-written walk sees each link, not its target. Needs u and d.
const ancestorCheck = `h=${HOME%/}; ph=$(cd -P "$h" 2>/dev/null && pwd -P)` +
	`; q="$d"; while :; do set -- $(ls -ldn "$q"); case $1 in l*) ;; ?????w*|????????w*) exit 48;; esac; if [ "$3" != "$u" ] && [ "$3" != 0 ]; then exit 48; fi; if [ "$q" = "$h" ] || [ "$q" = / ] || [ "$q" = . ]; then break; fi; q=$(dirname "$q"); done` +
	`; q=$(cd -P "$d" && pwd -P) || exit 1; while :; do set -- $(ls -ldn "$q"); case $1 in ?????w*|????????w*) exit 48;; esac; if [ "$3" != "$u" ] && [ "$3" != 0 ]; then exit 48; fi; if [ "$q" = "$ph" ] || [ "$q" = / ]; then break; fi; q=$(dirname "$q"); done`

// writeCmdFor builds the single write script. Order matters:
//
//  1. set -f (no globbing of ls output); umask 077 pins every file and
//     directory created below to owner-only before a byte is written.
//  2. Refuse a symlinked target (45) or a symlinked parent directory (48).
//     Walk the nearest existing ancestor of the target directory
//     (ancestorCheck) before creating anything, then create what is missing
//     with mkdir -p (first contact: ~/.ssh comes out 0700).
//  3. Walk the target directory as written and resolved: refuse it when it
//     is not owned by the login user (48) — like sshd's StrictModes,
//     running as root against another user's file must not write through
//     anything that user controls — and walk every ancestor up to the home
//     directory (ancestorCheck): each must be owned by the login user or
//     root and not group/other-writable (48). This second walk catches what
//     the textual pre-walk cannot see (a ".." component that mkdir -p
//     followed into a foreign symlink or a writable directory); a refusal
//     here removes, deepest first, the directories this run created.
//  4. Take the per-target lock (47), then re-check the target under it
//     (symlink 45, foreign-owned file 48) and, when the compare-and-swap
//     needs it, that cksum exists — all before the upload.
//  5. Upload to a fixed temp name created fresh with rm -f + set -C
//     (noclobber; stale temps from dropped connections are reclaimed),
//     check the byte count equals the render (a cut stream gives cat EOF
//     and exit 0; the length check turns that into 49 with the original
//     untouched), and flush the temp to disk (dd conv=fsync, per file —
//     never a global sync, which can hang on a dead NFS mount while the
//     lock is held).
//  6. In one tight step (casBackupBlock): copy the live file to a fresh
//     staging name, compare-and-swap that copy (46): the file must still be
//     absent, or still be exactly the phase-1 bytes (length + POSIX cksum)
//     — so a key another tool added during the upload refuses the write
//     instead of vanishing. .sshepherd.orig is derived from the copy once,
//     only while the file is not yet SSHepherd-managed, so a retry after a
//     failed apply never loses the hand-maintained original; the copy then
//     becomes .sshepherd.bak (the previous version, replaced every apply,
//     holding exactly the bytes the CAS validated) and is flushed too. Every
//     scratch name is created fresh with rm -f + set -C, so a symlink
//     planted at any of them is removed or refused, never written through.
//  7. mv the temp over the target — an atomic rename in the same directory,
//     so sshd never observes a partial file. The directory entry is not
//     flushed (best effort): after a crash the rename may be lost, which
//     leaves the old complete file, never an empty one.
//
// The script creates no file or directory before its last refusal point
// except the lock, the upload temp, the CAS staging copy and directories it
// removes again on refusal; its EXIT trap removes the lock, the temp and
// the staging copy.
//
// Content arrives on stdin — key material is never shell-encoded. The
// script is a single line (sshconn.Exec runs it under /bin/sh -c) and
// POSIX-only: it is exercised under dash, bash and busybox ash.
func writeCmdFor(path string, expect Snapshot, size int) string {
	return sshconn.PathAssign(path) +
		`; set -f; umask 077; u=$(id -u); d=$(dirname "$p"); b="$p"` + bakSuffix + `; o="$p"` + origSuffix + `; t="$p"` + tmpSuffix + `; c="$p"` + casSuffix +
		`; if [ -L "$p" ]; then exit 45; fi; if [ -L "$d" ]; then exit 48; fi` +
		// WP-9: walk the nearest EXISTING ancestor before creating anything,
		// so a refusal (48) leaves the tree exactly as it was.
		`; m=; e="$d"; while [ ! -e "$e" ] && [ ! -L "$e" ]; do m="$e"; e=$(dirname "$e"); done; D="$d"; d="$e"; ` + ancestorCheck + `; d="$D"` +
		`; if [ -n "$m" ]; then mkdir -p "$d" || exit 1; fi` +
		// The full walk of $d after mkdir: catches ".." and symlinks the
		// textual pre-walk could not see. On refusal, undo what mkdir created.
		`; ( set -- $(ls -ldn "$d"); if [ "$3" != "$u" ]; then exit 48; fi; ` + ancestorCheck + ` ) || { r=$?; if [ -n "$m" ]; then q="$d"; while :; do rmdir "$q" 2>/dev/null; if [ "$q" = "$m" ] || [ "$q" = / ] || [ "$q" = . ]; then break; fi; q=$(dirname "$q"); done; fi; exit $r; }` +
		`; ` + lockPrologue +
		`; if [ -L "$p" ]; then exit 45; fi; if [ -e "$p" ]; then set -- $(ls -ldn "$p"); if [ "$3" != "$u" ]; then exit 48; fi; fi` +
		cksumPresent(expect) +
		// Upload and length-check first (the slow part), then flush it.
		`; rm -f "$t"; (set -C; cat > "$t") || { rm -f "$t"; exit 1; }` +
		`; set -- $(wc -c < "$t"); if [ "$1" != ` + strconv.Itoa(size) + ` ]; then rm -f "$t"; exit 49; fi` +
		`; dd if=/dev/null of="$t" conv=notrunc,fsync 2>/dev/null || :` + // WP-4: the temp's data is on disk before the rename; never a global sync
		`; ` + casBackupBlock(expect) +
		`; if [ -e "$b" ]; then dd if=/dev/null of="$b" conv=notrunc,fsync 2>/dev/null || :; fi` +
		`; mv -f "$t" "$p" || { rm -f "$t"; exit 1; }`
}

// cksumPresent fails fast (before the upload) when the CAS needs cksum and
// the server has none.
func cksumPresent(expect Snapshot) string {
	if expect.Absent {
		return ""
	}
	return `; command -v cksum >/dev/null 2>&1 || { echo "sshepherd: cksum not found on the server" >&2; exit 1; }`
}

// casBackupBlock is the tight step between the completed upload and the mv
// (WP-3): copy the live file to a fresh staging name, compare-and-swap the
// COPY (46 on mismatch), derive .orig from it, and rename it to .bak — so
// .bak holds exactly the bytes the CAS validated, and a lock-less editor
// that changed the file during the upload refuses the write instead of
// losing its edit. rm -f + set -C keep the staging name from following a
// planted symlink; rm -f "$b" fails (exit 1) on a directory planted at .bak.
func casBackupBlock(expect Snapshot) string {
	if expect.Absent {
		return `if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi`
	}
	return `if [ -L "$p" ]; then exit 45; fi; if [ ! -f "$p" ]; then exit 46; fi` +
		`; rm -f "$c" || exit 1; (set -C; cat "$p" > "$c") || exit 1` +
		`; set -- $(cksum < "$c"); if [ "$1" != ` + strconv.FormatUint(uint64(expect.Cksum), 10) +
		` ] || [ "$2" != ` + strconv.Itoa(expect.Size) + ` ]; then rm -f "$c"; exit 46; fi` +
		`; if [ ! -e "$o" ] && [ ! -L "$o" ] && [ "$(head -n 1 "$c")" != ` + sshconn.ShQuote(authkeys.ManagedHeader) +
		` ]; then (set -C; cat "$c" > "$o") || exit 1; fi` +
		`; rm -f "$b" || exit 1; mv -f "$c" "$b" || exit 1`
}

// casCheck is the compare-and-swap test (exit 46): the file must be absent
// when expect.Absent, or hold exactly expect.Size bytes with POSIX cksum
// expect.Cksum.
func casCheck(expect Snapshot) string {
	if expect.Absent {
		return `if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi`
	}
	return `if [ ! -f "$p" ]; then exit 46; fi; command -v cksum >/dev/null 2>&1 || { echo "sshepherd: cksum not found on the server" >&2; exit 1; }; set -- $(cksum < "$p"); if [ "$1" != ` +
		strconv.FormatUint(uint64(expect.Cksum), 10) + ` ] || [ "$2" != ` + strconv.Itoa(expect.Size) + ` ]; then exit 46; fi`
}

// restoreCmdFor builds the rollback run after a failed post-write login
// probe, over the still-open write connection: put the previous version
// (.sshepherd.bak) back, or remove the file a first-contact write created.
// The write script's lock ended with stage 1, so restore takes the lock
// afresh (47 if another apply holds it) and compare-and-swaps against wrote
// — the bytes this apply installed — refusing (46) to replace a file a
// concurrent apply wrote in between.
func restoreCmdFor(path string, wasAbsent bool, wrote Snapshot) string {
	undo := `if [ -L "$b" ]; then exit 45; fi; mv -f "$b" "$p"`
	if wasAbsent {
		undo = `rm -f "$p"`
	}
	return sshconn.PathAssign(path) + `; set -f; u=$(id -u); d=$(dirname "$p"); b="$p"` + bakSuffix + `; ` + ancestorCheck + `; ` + lockPrologue +
		`; if [ -L "$p" ]; then exit 45; fi; ` + casCheck(wrote) + `; ` + undo
}

// disableKeys2Cmd moves ~/.ssh/authorized_keys2 aside to
// Keys2DisabledSuffix (replacing an older disabled copy). mv renames a
// symlink itself, never writing through it; the directory passes the same
// ancestor walk as the write, so only the login user (or root) can race the
// rename. An absent file is a no-op.
func disableKeys2Cmd() string {
	return sshconn.PathAssign(sshconn.SecondaryAuthorizedKeysPath) +
		`; set -f; u=$(id -u); d=$(dirname "$p"); s="$p"` + Keys2DisabledSuffix + `; ` + ancestorCheck +
		`; if [ -e "$p" ] || [ -L "$p" ]; then rm -f "$s" || exit 1; mv -f "$p" "$s" || exit 1; fi`
}

// restoreKeys2Cmd undoes disableKeys2Cmd after a failed login probe,
// refusing (46) to clobber an authorized_keys2 recreated meanwhile.
func restoreKeys2Cmd() string {
	return sshconn.PathAssign(sshconn.SecondaryAuthorizedKeysPath) +
		`; set -f; s="$p"` + Keys2DisabledSuffix +
		`; if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi; if [ -e "$s" ] || [ -L "$s" ]; then mv -f "$s" "$p" || exit 1; fi`
}

// SymlinkError reports a refused write: the target path is a symlink. The
// operator points authorized_keys_file at the real target if writing
// through was the intent.
type SymlinkError struct{ Path string }

func (e *SymlinkError) Error() string {
	return fmt.Sprintf("%s is a symlink — refusing to replace it with a regular file (point authorized_keys_file at the real target if intended)", e.Path)
}

// UnsafePathError reports a refused write: the target's directory is a
// symlink, the file or directory is owned by someone other than the login
// user, or an ancestor (as written or resolved, up to the home directory)
// is owned by someone other than the login user or root, or is group- or
// other-writable (writing there could follow links someone else controls).
type UnsafePathError struct{ Path string }

func (e *UnsafePathError) Error() string {
	return fmt.Sprintf("%s: its directory is a symlink, the file or directory is not owned by the login user, or an ancestor directory is writable by or owned by another user — refusing to write (log in as the owning user; fix ancestor ownership/modes as sshd's StrictModes requires)", e.Path)
}

// ChangedError reports a refused write: the file changed between the plan
// (phase 1) and the write, so overwriting it would destroy content the
// operator never reviewed.
type ChangedError struct{ Path string }

func (e *ChangedError) Error() string {
	return fmt.Sprintf("%s changed since the plan was read — refusing to overwrite unreviewed content; re-run apply", e.Path)
}

// LockedError reports a refused write: another apply holds the target's
// lock directory.
type LockedError struct{ Path string }

func (e *LockedError) Error() string {
	return fmt.Sprintf("another apply is in progress on %s (lock directory %s%s; remove it only if no apply is running)", e.Path, e.Path, lockSuffix)
}

// LockoutError reports a write that verified but whose surviving held keys
// (key files or agent) could not log in on a fresh connection; the
// previous file was restored unless Restore says otherwise.
type LockoutError struct {
	Path    string
	Probe   error // why the post-write login failed
	Restore error // nil when the previous file was put back
}

func (e *LockoutError) Error() string {
	if e.Restore == nil {
		return fmt.Sprintf("lockout prevented — restored previous file (post-write login offering only the surviving keys you hold failed: %v)", e.Probe)
	}
	return fmt.Sprintf("post-write login offering only the surviving keys you hold failed (%v) AND restoring the previous file failed (%v) — the previous version is at %s%s; repair it over a session that is still open", e.Probe, e.Restore, e.Path, bakSuffix)
}

func (e *LockoutError) Unwrap() []error { return []error{e.Probe, e.Restore} }

// IsRefusal reports whether err is a server-side refusal: the write was
// declined before anything changed (symlink, unsafe path, changed since
// plan, locked).
func IsRefusal(err error) bool {
	var (
		sym  *SymlinkError
		uns  *UnsafePathError
		chg  *ChangedError
		lock *LockedError
	)
	return errors.As(err, &sym) || errors.As(err, &uns) || errors.As(err, &chg) || errors.As(err, &lock)
}

// ErrNotStarted marks an Apply that was interrupted (ctx canceled) before
// the write began: nothing on the server changed.
var ErrNotStarted = errors.New("interrupted before the write started")

// FleetWriter applies rendered authorized_keys content to servers over SSH.
// It is apply's Writer seam implementation.
type FleetWriter struct {
	Dialer *sshconn.Dialer
	Log    *slog.Logger // optional stage-level telemetry; nil discards
	// SessionBudget bounds an established write connection (write, verify,
	// probe, restore); zero selects two minutes.
	SessionBudget time.Duration

	// Test seams; nil selects the real implementations.
	connect func(ctx context.Context, srv config.Server, opts sshconn.ConnectOptions) (*sshconn.Conn, error)
	exec    func(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error)
}

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (w *FleetWriter) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Apply makes srv's authorized_keys equal req.Content: the guarded write
// script (content on stdin), a read-back verify (byte-compare — trusting
// mv's exit status would leave silent-corruption blind spots for the cost
// of one extra cat), then a login probe on a fresh connection offering only
// req.Survivors that must run a probe command; if that login or command
// fails the previous file is restored over the still-open connection
// (*LockoutError).
//
// ctx bounds and may interrupt only the connect: canceled there, Apply
// returns an error wrapping ErrNotStarted and nothing changed. Once the
// write script starts, every stage runs to completion under the session
// budget — a started write always finishes, verifies and, if need be, rolls
// back. Refusals (IsRefusal) mean nothing changed. All errors pass the
// sanitized-error path: remote text never reaches a terminal raw.
func (w *FleetWriter) Apply(ctx context.Context, srv config.Server, req Request) error {
	if len(req.Survivors) == 0 {
		return fmt.Errorf("write on %s: no surviving key you hold to prove the post-write login with — refusing to write", srv.Name)
	}
	conn, err := w.connectForWrite(ctx, srv)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }() // errcheck: close error is uninteresting after the verdict
	execCtx := context.WithoutCancel(ctx)

	path := srv.AuthorizedKeysFile
	if path == "" {
		path = sshconn.DefaultAuthorizedKeysPath
	}
	log := w.log()

	// Stage 1: the guarded write, rendered bytes on stdin.
	code, _, stderr, err := w.execFn()(execCtx, conn.Client, writeCmdFor(path, req.Expect, len(req.Content)), bytes.NewReader(req.Content))
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("write on %s: %w (the server installs only a complete upload)", srv.Name, err)}
	}
	if err := writeExitError(code, path, srv.Name, stderr); err != nil {
		return err
	}
	log.Debug("write ok", "server", srv.Name, "bytes", len(req.Content))

	// Stage 2: verify — re-read through the existing read command and
	// byte-compare against the render.
	if err := w.verify(execCtx, conn, srv.Name, path, req.Content); err != nil {
		return err
	}
	log.Debug("verify ok", "server", srv.Name)

	// Stage 2b: disable a non-empty authorized_keys2 before the probe, so
	// the probe proves the survivors log in without it. A failure here
	// cannot lock anyone out (the file only ever adds keys), so the probe
	// still runs and the failure is reported after it.
	var keys2Err error
	if req.DisableKeys2 {
		keys2Err = w.disableKeys2(execCtx, conn, srv.Name)
		if keys2Err == nil {
			log.Debug("authorized_keys2 disabled", "server", srv.Name)
		}
	}

	// Stage 3: prove the lockout guard's prediction — a fresh login offering
	// only the surviving held keys (in req.Survivors order, which the caller
	// sets to the production offer order), running probeCmd. Every write is probed,
	// not only those that drop the session key: an options rewrite on the
	// survivor (from= fails the handshake, command= the probe command), or
	// sshd rejecting the survivor's algorithm, locks out just as surely, and
	// the cost is one handshake and one command per written server.
	if err := w.probeOrRestore(execCtx, conn, srv, path, req, req.DisableKeys2 && keys2Err == nil); err != nil {
		return err
	}
	return keys2Err
}

// disableKeys2 runs disableKeys2Cmd over conn.
func (w *FleetWriter) disableKeys2(ctx context.Context, conn *sshconn.Conn, server string) error {
	code, _, stderr, err := w.execFn()(ctx, conn.Client, disableKeys2Cmd(), nil)
	switch {
	case err != nil:
		return sshconn.SanitizedError{Err: fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s failed: %w", server, err)}
	case code == unsafePathExit:
		return fmt.Errorf("authorized_keys written and verified, but disabling authorized_keys2 on %s was refused: its directory fails the ownership/mode walk", server)
	case code != 0:
		return fmt.Errorf("authorized_keys written and verified, but %w", stageFailure("disabling authorized_keys2", server, code, stderr))
	}
	return nil
}

// connectFn and execFn resolve the test seams to the real implementations.
func (w *FleetWriter) connectFn() func(context.Context, config.Server, sshconn.ConnectOptions) (*sshconn.Conn, error) {
	if w.connect != nil {
		return w.connect
	}
	return w.Dialer.ConnectWith
}

func (w *FleetWriter) execFn() func(context.Context, *ssh.Client, string, io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
	if w.exec != nil {
		return w.exec
	}
	return sshconn.Exec
}

// connectForWrite opens the write connection. Its deadline (installed as
// the socket deadline) is the session budget, detached from ctx; ctx still
// aborts the dial and handshake through the AfterFunc until the connect
// returns. Canceled before or during the connect, it returns an error
// wrapping ErrNotStarted.
func (w *FleetWriter) connectForWrite(ctx context.Context, srv config.Server) (*sshconn.Conn, error) {
	notStarted := fmt.Errorf("%s: %w", srv.Name, ErrNotStarted)
	if ctx.Err() != nil {
		return nil, notStarted
	}
	budget := w.SessionBudget
	if budget <= 0 {
		budget = defaultSessionBudget
	}
	connCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), budget)
	stop := context.AfterFunc(ctx, cancel)
	conn, err := w.connectFn()(connCtx, srv, sshconn.ConnectOptions{})
	stop()
	// Releasing connCtx after a successful connect is safe: ConnectWith
	// stops watching it once the handshake completes, and the socket keeps
	// the budget deadline.
	cancel()
	interrupted := errors.Is(ctx.Err(), context.Canceled)
	switch {
	case err != nil && interrupted:
		return nil, notStarted
	case err != nil:
		return nil, sshconn.SanitizedError{Err: err}
	case interrupted:
		_ = conn.Close()
		return nil, notStarted
	}
	return conn, nil
}

// writeExitError maps the write script's exit status to its typed outcome;
// nil for success.
func writeExitError(code int, path, server string, stderr *sshconn.CappedBuffer) error {
	switch code {
	case 0:
		return nil
	case symlinkExit:
		return &SymlinkError{Path: path}
	case changedExit:
		return &ChangedError{Path: path}
	case lockedExit:
		return &LockedError{Path: path}
	case unsafePathExit:
		return &UnsafePathError{Path: path}
	case shortWriteExit:
		return fmt.Errorf("write on %s: upload incomplete (the server received fewer bytes than rendered) — original left untouched", server)
	default:
		return stageFailure("write", server, code, stderr)
	}
}

// verify re-reads path over conn and byte-compares it with content.
func (w *FleetWriter) verify(ctx context.Context, conn *sshconn.Conn, server, path string, content []byte) error {
	code, stdout, stderr, err := w.execFn()(ctx, conn.Client, sshconn.AuthorizedKeysCmdFor(path), nil)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("verify on %s: %w", server, err)}
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, server, w.log())
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("verify on %s: %w", server, err)}
	}
	if res.FileAbsent {
		return fmt.Errorf("verify on %s: file absent after write", server)
	}
	if !bytes.Equal(res.Content, content) {
		return fmt.Errorf("verify on %s: file bytes differ from the rendered desired state", server)
	}
	return nil
}

// probeCmd is what the post-write login probe runs; a session whose key
// line forces command= runs that instead and cannot print probeOutput.
const (
	probeCmd    = `echo sshepherd-probe-ok`
	probeOutput = "sshepherd-probe-ok\n"
)

// probeOrRestore logs in afresh offering only req.Survivors and runs
// probeCmd: a key that authenticates but whose line now forces a command
// (command=, or an options rewrite that adds one) would leave sshepherd
// unable to manage the server, so the probe requires the command to run
// and print probeOutput, not just a handshake. If either fails it restores
// the previous file over the still-open conn and returns a *LockoutError.
func (w *FleetWriter) probeOrRestore(ctx context.Context, conn *sshconn.Conn, srv config.Server, path string, req Request, keys2Disabled bool) error {
	log := w.log()
	perr := w.probe(ctx, srv, req.Survivors)
	if perr == nil {
		log.Debug("login probe ok", "server", srv.Name)
		return nil
	}
	log.Warn(fmt.Sprintf("%s: post-write login probe failed; restoring the previous file", srv.Name))
	lockout := &LockoutError{Path: path, Probe: sshconn.SanitizedError{Err: perr}}
	code, _, stderr, err := w.execFn()(ctx, conn.Client, restoreCmdFor(path, req.Expect.Absent, SnapshotOf(false, req.Content)), nil)
	switch {
	case err != nil:
		lockout.Restore = sshconn.SanitizedError{Err: err}
	case code != 0:
		lockout.Restore = restoreExitError(code, srv.Name, stderr)
	}
	if keys2Disabled {
		code, _, stderr, err := w.execFn()(ctx, conn.Client, restoreKeys2Cmd(), nil)
		var k2err error
		switch {
		case err != nil:
			k2err = sshconn.SanitizedError{Err: fmt.Errorf("restore authorized_keys2 on %s: %w", srv.Name, err)}
		case code == changedExit:
			k2err = fmt.Errorf("restore authorized_keys2 on %s refused: it was recreated meanwhile (the disabled copy is at authorized_keys2%s)", srv.Name, Keys2DisabledSuffix)
		case code != 0:
			k2err = stageFailure("restore authorized_keys2", srv.Name, code, stderr)
		}
		lockout.Restore = errors.Join(lockout.Restore, k2err)
	}
	return lockout
}

// restoreExitError explains a nonzero restore exit. It deliberately returns
// untyped errors: a LockoutError unwraps to its Restore error, and a typed
// refusal there would make IsRefusal call a written file "nothing changed".
func restoreExitError(code int, server string, stderr *sshconn.CappedBuffer) error {
	switch code {
	case symlinkExit:
		return fmt.Errorf("restore on %s refused: the file or its backup is now a symlink", server)
	case changedExit:
		return fmt.Errorf("restore on %s refused: the file changed since this apply wrote it (a concurrent apply?) — left as is", server)
	case lockedExit:
		return fmt.Errorf("restore on %s refused: another apply holds the lock", server)
	default:
		return stageFailure("restore", server, code, stderr)
	}
}

// probe logs in offering only survivors and runs probeCmd over that login.
func (w *FleetWriter) probe(ctx context.Context, srv config.Server, survivors []string) error {
	probe, err := w.connectFn()(ctx, srv, sshconn.ConnectOptions{Only: survivors})
	if err != nil {
		return err
	}
	defer func() { _ = probe.Close() }() // errcheck: the verdict is already decided
	code, stdout, _, err := w.execFn()(ctx, probe.Client, probeCmd, nil)
	switch {
	case err != nil:
		return fmt.Errorf("probe command: %w", err)
	case code != 0 || stdout.String() != probeOutput:
		return fmt.Errorf("probe command did not run as sent (exit %d) — a forced command= on the surviving key?", code)
	}
	return nil
}

// stageFailure wraps a nonzero remote exit with its stderr, bounded by
// sanitize.RemoteSnippet (SEC-8): one line, at most sanitize.MaxSnippet
// safe runes, so a hostile server can neither forge report rows with
// blank-looking padding nor flood the report.
func stageFailure(stage, server string, code int, stderr *sshconn.CappedBuffer) error {
	return fmt.Errorf("%s on %s failed (exit %d): %s",
		stage, server, code, sanitize.RemoteSnippet(stderr.String()))
}
