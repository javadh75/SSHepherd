// Package sshwrite performs apply's remote write protocol over one SSH
// connection per server: a single guarded write script (symlink and
// ownership refusals, per-target lock, compare-and-swap against the phase-1
// snapshot, backups, length-checked atomic temp+rename), a read-back verify,
// and a post-write login check that restores the previous file when the
// surviving keys are refused. Command builders are pure and share
// sshconn.PathAssign's quoting discipline (the path enters each script
// exactly once, fully quoted); only the network glue needs the integration
// suite, and even the protocol sequencing is unit-tested through seams.
package sshwrite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
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
	bakSuffix  = fleet.BackupSuffix
	origSuffix = ".sshepherd.orig"
	lockSuffix = ".sshepherd.lock"
	// casSuffix names the staging copy the compare-and-swap checks and
	// that then becomes the backup (writeCmdFor's casBackupBlock).
	casSuffix = ".sshepherd.cas"
)

// defaultSessionBudget bounds a write connection's whole life once it is
// established: write, verify, the post-write login probe and a possible
// restore all run under it. It is deliberately independent of the caller's
// per-server deadline, which bounds only the dial and handshake — a write
// that has started must be able to finish, verify and, if need be, roll
// back.
const defaultSessionBudget = 2 * time.Minute

// Snapshot is the phase-1 state a write is conditional on (fleet.Snapshot):
// the write script refuses (ChangedError) when the file no longer matches.
type Snapshot = fleet.Snapshot

// Request is one server's write (fleet.WriteRequest).
type Request = fleet.WriteRequest

// LockoutError is the typed rollback outcome (fleet.LockoutError).
type LockoutError = fleet.LockoutError

// SnapshotOf builds the snapshot of phase-1 bytes read (or of an absent
// file); see authkeys.ManagedSnapshot, the one definition of a managed file.
func SnapshotOf(absent bool, content []byte) Snapshot {
	return authkeys.ManagedSnapshot(absent, content)
}

const (
	lockBusy   = `{ echo "sshepherd-lock $(date +%s)"; head -n 1 "$l/owner" 2>/dev/null | cut -c1-200; exit 47; }`
	lockHead   = `l="$p"` + lockSuffix + `; mkdir "$l" 2>/dev/null || { [ -d "$l" ] && ` + lockBusy + `; if mkdir "$l"; then rmdir "$l"; exit 47; fi; exit 1; }; `
	lockTrap   = `trap 'x=$?; rm -f "$p"` + tmpSuffix + ` "$p"` + casSuffix + ` "$l/owner"; rmdir "$l" 2>/dev/null`
	signalTrap = `trap 'exit 1' HUP INT TERM PIPE`
)

// createDirs creates the missing directories of "$d" (the pre-walk left
// the shallowest missing spelling in "$m") one at a time, top-down along
// the textual dirname chain, and records each one it created by its depth
// below "$d" in C (deepest first; only digits, so safe to word-split). It
// never records a component that already resolves — with a ".." in the
// path, "home/new/../shared" names a directory that existed before the run
// once mkdir has created new — so U, which rmdirs exactly the recorded
// depths deepest first, never removes a directory this run did not create
// (WP-9). U runs from the EXIT trap on any nonzero exit; rmdir removes
// only empty directories. Needs d and m.
const createDirs = `; C=; U() { for k in $C; do j=0; q="$d"; while [ $j -lt $k ]; do q=$(dirname "$q"); j=$((j+1)); done; rmdir "$q" 2>/dev/null; done; }` +
	`; trap '[ $? = 0 ] || U' EXIT; ` + signalTrap +
	`; if [ -n "$m" ]; then k=0; q="$d"; while [ "$q" != "$m" ] && [ "$q" != / ] && [ "$q" != . ]; do k=$((k+1)); q=$(dirname "$q"); done` +
	`; while [ $k -ge 0 ]; do j=0; q="$d"; while [ $j -lt $k ]; do q=$(dirname "$q"); j=$((j+1)); done` +
	`; if [ ! -e "$q" ] && [ ! -L "$q" ]; then mkdir "$q" || exit 1; C="$k $C"; fi; k=$((k-1)); done; fi`

// ancestorCheck is the write path's StrictModes walk: the shared
// sshconn.AncestorWalk refusing (48) any component it objects to. Needs u
// and d. Every write-path script carries it, byte for byte.
var ancestorCheck = sshconn.AncestorWalk("exit "+strconv.Itoa(unsafePathExit), "exit "+strconv.Itoa(unsafePathExit))

// writeCmdFor builds the single write script. Order matters:
//
//  1. set -f (no globbing of ls output); umask 077 pins every file and
//     directory created below to owner-only before a byte is written.
//  2. Refuse a symlinked target (45) or a symlinked parent directory (48).
//     Walk the nearest existing ancestor of the target directory
//     (ancestorCheck) before creating anything, then create what is missing
//     one directory at a time, recording exactly which ones this run
//     created (createDirs; first contact: ~/.ssh comes out 0700).
//  3. Walk the target directory as written and resolved: refuse it when it
//     is not owned by the login user (48) — like sshd's StrictModes,
//     running as root against another user's file must not write through
//     anything that user controls — and walk every ancestor up to the home
//     directory (ancestorCheck): each must be owned by the login user or
//     root and not group/other-writable (48). This second walk catches what
//     the textual pre-walk cannot see (a ".." component that mkdir
//     followed into a foreign symlink or a writable directory). From here
//     on, every nonzero exit — this refusal, a held lock (47), the
//     compare-and-swap (46), a short upload (49) or a failure — removes,
//     deepest first, the directories this run created and nothing else
//     (the EXIT trap runs createDirs' U).
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
//     only while the snapshot is not SSHepherd-managed (Snapshot.Managed,
//     authkeys.ParseHeader's anchored verdict), so a retry after a
//     failed apply never loses the hand-maintained original, and flushed at
//     once (it is never rewritten, so a crash must not leave it empty —
//     WP-4); the copy then
//     becomes .sshepherd.bak (the previous version, replaced every apply,
//     holding exactly the bytes the CAS validated) and is flushed too; a
//     write that creates the file removes any older .bak instead, so that
//     name only ever holds the bytes the latest write replaced. Every
//     scratch name is created fresh with rm -f + set -C, so a symlink
//     planted at any of them is removed or refused, never written through.
//  7. mv the temp over the target — an atomic rename in the same directory,
//     so sshd never observes a partial file. The directory entry is not
//     flushed (best effort): after a crash the rename may be lost, which
//     leaves the old complete file, never an empty one.
//
// The script creates no file or directory before its last refusal point
// except the lock, the upload temp, the CAS staging copy and the missing
// directories it created; its EXIT trap removes the lock, the temp and the
// staging copy and, on any nonzero exit, those directories (never one that
// existed before the run).
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
		createDirs +
		// The full walk of $d after mkdir: catches ".." and symlinks the
		// textual pre-walk could not see. On refusal the EXIT trap (U)
		// removes what this run created.
		`; ( set -- $(ls -ldn "$d"); if [ "$3" != "$u" ]; then exit 48; fi; ` + ancestorCheck + ` ) || exit $?` +
		`; ` + lockPrologueUndo() +
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
// COPY (46 on mismatch), derive .orig from it — only when the snapshot is
// not managed (expect.Managed, decided in Go by authkeys.ParseHeader on the
// very bytes the CAS just proved) — and rename it to .bak, so .bak holds
// exactly the bytes the CAS validated, and a lock-less editor that changed
// the file during the upload refuses the write instead of losing its edit.
// rm -f + set -C keep the staging name from following a planted symlink;
// rm -f "$b" fails (exit 1) on a directory planted at .bak. A write over an
// absent file has nothing to back up, but an older .bak must go (F010): it
// is not this write's previous version. That removal comes after the absent
// check, so a refused write still changes nothing.
func casBackupBlock(expect Snapshot) string {
	if expect.Absent {
		return `if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi; rm -f "$b" || exit 1`
	}
	b := `if [ -L "$p" ]; then exit 45; fi; if [ ! -f "$p" ]; then exit 46; fi` +
		`; rm -f "$c" || exit 1; (set -C; cat "$p" > "$c") || exit 1` +
		`; set -- $(cksum < "$c"); if [ "$1" != ` + strconv.FormatUint(uint64(expect.Cksum), 10) +
		` ] || [ "$2" != ` + strconv.Itoa(expect.Size) + ` ]; then rm -f "$c"; exit 46; fi`
	if !expect.Managed {
		b += `; if [ ! -e "$o" ] && [ ! -L "$o" ]; then (set -C; cat "$c" > "$o") || exit 1; dd if=/dev/null of="$o" conv=notrunc,fsync 2>/dev/null || :; fi`
	}
	return b + `; rm -f "$b" || exit 1; mv -f "$c" "$b" || exit 1`
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
	return sshconn.PathAssign(path) + `; set -f; u=$(id -u); d=$(dirname "$p"); b="$p"` + bakSuffix + `; ` + ancestorCheck + `; ` + lockPrologue() +
		`; if [ -L "$p" ]; then exit 45; fi; ` + casCheck(wrote) + `; ` + undo
}

// lockedReadCmdFor re-reads path under the per-target lock, after a dropped
// connection: the dropped script may still be running and holding it (47).
// A missing directory reads as an absent file (44), since the lock could
// not be taken there.
func lockedReadCmdFor(path string) string {
	read := strings.TrimPrefix(sshconn.AuthorizedKeysCmdFor(path), sshconn.PathAssign(path))
	return sshconn.PathAssign(path) + `; set -f; if [ ! -d "$(dirname "$p")" ]; then exit 44; fi; ` + lockPrologue() + read
}

// unchangedReadCmdFor reads path for a keys2-only plan (SkipWrite), after
// the refusals the write script would have made: a symlinked target (45), a
// symlinked directory, a file or directory not owned by the login user, or
// an ancestor failing the walk (48). An absent file is 44. It takes no lock
// and creates nothing.
func unchangedReadCmdFor(path string) string {
	read := strings.TrimPrefix(sshconn.AuthorizedKeysCmdFor(path), sshconn.PathAssign(path))
	return sshconn.PathAssign(path) + `; set -f; u=$(id -u); d=$(dirname "$p"); if [ -L "$p" ]; then exit 45; fi; if [ ! -e "$p" ]; then exit 44; fi; if [ -L "$d" ]; then exit 48; fi` +
		`; ( set -- $(ls -ldn "$d"); if [ "$3" != "$u" ]; then exit 48; fi; ` + ancestorCheck + ` ) || exit $?` +
		`; set -- $(ls -ldn "$p"); if [ "$3" != "$u" ]; then exit 48; fi` + read
}

// disableKeys2Cmd moves ~/.ssh/authorized_keys2 aside and prints
// "sshepherd-keys2 <basename>". A copy is never overwritten: the name is
// fleet.Keys2DisabledSuffix when free, otherwise that plus a UTC timestamp,
// plus .$$ if that is taken too; copies accumulate and SSHepherd never
// deletes them. mv renames a symlink itself, never writing through it; the
// directory passes the same ancestor walk as the write, so only the login
// user (or root) can race the checks. An absent file is a no-op.
func disableKeys2Cmd() string {
	taken := func(v string) string { return `[ -e "` + v + `" ] || [ -L "` + v + `" ]` }
	return sshconn.PathAssign(sshconn.SecondaryAuthorizedKeysPath) +
		`; set -f; u=$(id -u); d=$(dirname "$p"); s="$p"` + fleet.Keys2DisabledSuffix + `; ` + ancestorCheck +
		`; if ` + taken("$p") + `; then` +
		` if ` + taken("$s") + `; then s="$s.$(date -u +%Y%m%dT%H%M%SZ)"; if ` + taken("$s") + `; then s="$s.$$"; fi; if ` + taken("$s") + `; then exit 1; fi; fi` +
		`; mv -f "$p" "$s" || exit 1; echo "sshepherd-keys2 ${s##*/}"; fi`
}

// restoreKeys2Cmd undoes disableKeys2Cmd after a failed login probe,
// moving back exactly the copy this run made (name passed parseKeys2Name),
// refusing (46) to clobber an authorized_keys2 recreated meanwhile. A copy
// that is not there is 44 (sshconn.FileAbsentExit): nothing was moved back,
// and exiting 0 would report that it was.
func restoreKeys2Cmd(name string) string {
	return sshconn.PathAssign(sshconn.SecondaryAuthorizedKeysPath) +
		`; set -f; s="$(dirname "$p")"/` + sshconn.ShQuote(name) +
		`; if [ -e "$p" ] || [ -L "$p" ]; then exit 46; fi; if [ ! -e "$s" ] && [ ! -L "$s" ]; then exit ` + strconv.Itoa(sshconn.FileAbsentExit) + `; fi; mv -f "$s" "$p" || exit 1`
}

// keys2NameRE is the only copy name the client passes back to a script.
var keys2NameRE = regexp.MustCompile(`^authorized_keys2\.sshepherd\.disabled(\.[0-9]{8}T[0-9]{6}Z(\.[0-9]+)?)?$`)

// parseKeys2Name reads disableKeys2Cmd's stdout: "" when nothing was
// there to move, the copy's basename otherwise; false for anything else.
func parseKeys2Name(stdout string) (string, bool) {
	line := strings.TrimSpace(stdout)
	if line == "" {
		return "", true
	}
	name, ok := strings.CutPrefix(line, "sshepherd-keys2 ")
	if !ok || !keys2NameRE.MatchString(name) {
		return "", false
	}
	return name, true
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
	forward func(ctx context.Context, client *ssh.Client, addr string) error
	now     func() time.Time
	sleep   func(ctx context.Context, d time.Duration) error
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
// script (content on stdin) or, for req.SkipWrite, a byte compare; a
// read-back verify; then a login check on a fresh connection offering only
// req.Survivors that must run a probe command. classifyProbe sorts a failed
// check by the stage it reached: a REJECTED login restores the previous
// file (*LockoutError, its Restore set when that failed too); one that
// never got past authentication keeps the file (*fleet.UnprovenError). A
// transport error during the write or verify opens one fresh connection and
// re-reads under the lock.
//
// ctx bounds and may interrupt only the connect: canceled there, Apply
// returns an error wrapping fleet.ErrWriteNotStarted and nothing changed.
// Once the write script starts, every stage runs to completion under the
// session budget — a started write always finishes, verifies and, if need
// be, rolls back. Refusals (fleet.IsRefusal: the typed refusal errors,
// wrapped by fleet.Refused) mean nothing changed. All errors pass the
// sanitized-error path: remote text never reaches a terminal raw.
func (w *FleetWriter) Apply(ctx context.Context, srv config.Server, req Request) error {
	if len(req.Survivors) == 0 {
		return fmt.Errorf("write on %s: no surviving key you hold to prove the post-write login with — refusing to write", srv.Name)
	}
	conn, deadline, err := w.connectForWrite(ctx, srv)
	if err != nil {
		return err
	}
	sessCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	defer cancel()
	path := srv.AuthorizedKeysFile
	if path == "" {
		path = sshconn.DefaultAuthorizedKeysPath
	}
	s := &writeSession{w: w, ctx: sessCtx, deadline: deadline, srv: srv, path: path, req: req, conn: conn}
	defer s.close()
	return s.run()
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

// forwardFn resolves the forward-probe seam to probeForward.
func (w *FleetWriter) forwardFn() func(context.Context, *ssh.Client, string) error {
	if w.forward != nil {
		return w.forward
	}
	return probeForward
}

// clock and sleepFn resolve the time seams to the real implementations.
func (w *FleetWriter) clock() time.Time {
	if w.now != nil {
		return w.now()
	}
	return time.Now()
}

func (w *FleetWriter) sleepFn() func(context.Context, time.Duration) error {
	if w.sleep != nil {
		return w.sleep
	}
	return sleepCtx
}

// routeOf lists srv's bastions, root first, as far as the Dialer resolves
// them: the route a lock-removal hint must print.
func (w *FleetWriter) routeOf(srv config.Server) []config.Server {
	if w.Dialer == nil {
		return nil
	}
	return w.Dialer.Route(srv)
}

// sleepCtx waits d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("wait: %w", ctx.Err())
	case <-t.C:
		return nil
	}
}

// connectForWrite opens the write connection and returns the budget
// deadline it installed (also the socket deadline), detached from ctx; ctx
// still aborts the dial and handshake through the AfterFunc until the
// connect returns. Canceled before or during the connect, it returns an
// error wrapping fleet.ErrWriteNotStarted.
func (w *FleetWriter) connectForWrite(ctx context.Context, srv config.Server) (*sshconn.Conn, time.Time, error) {
	notStarted := fmt.Errorf("%s: %w", srv.Name, fleet.ErrWriteNotStarted)
	if ctx.Err() != nil {
		return nil, time.Time{}, notStarted
	}
	budget := w.SessionBudget
	if budget <= 0 {
		budget = defaultSessionBudget
	}
	deadline := w.clock().Add(budget)
	connCtx, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
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
		return nil, time.Time{}, notStarted
	case err != nil:
		return nil, time.Time{}, sshconn.SanitizedError{Err: err}
	case interrupted:
		_ = conn.Close()
		return nil, time.Time{}, notStarted
	}
	return conn, deadline, nil
}

// writeExitError maps the write script's exit status to its typed outcome;
// nil for success.
func writeExitError(code int, path string, srv config.Server, route []config.Server, stdout, stderr *sshconn.CappedBuffer) error {
	switch code {
	case 0:
		return nil
	case symlinkExit:
		return fleet.Refused(&SymlinkError{Path: path}) //nolint:wrapcheck // Refused is the refusal marker itself; the message is the typed error's
	case changedExit:
		return fleet.Refused(&ChangedError{Path: path}) //nolint:wrapcheck // Refused is the refusal marker itself; the message is the typed error's
	case lockedExit:
		return fleet.Refused(lockedErrorFor(srv, route, path, stdout.String())) //nolint:wrapcheck // Refused is the refusal marker itself; the message is the typed error's
	case unsafePathExit:
		return fleet.Refused(&UnsafePathError{Path: path}) //nolint:wrapcheck // Refused is the refusal marker itself; the message is the typed error's
	case shortWriteExit:
		return fmt.Errorf("write on %s: upload incomplete (the server received fewer bytes than rendered) — original left untouched", srv.Name)
	default:
		return stageFailure("write", srv.Name, code, stderr)
	}
}

// restoreExitError explains a nonzero restore exit. It deliberately returns
// untyped errors: a LockoutError unwraps to its Restore error, and a typed
// refusal there would make fleet.IsRefusal call a written file "nothing
// changed". Exit 47 never arrives here: restoreFile retries a busy lock.
func restoreExitError(code int, server string, stderr *sshconn.CappedBuffer) error {
	switch code {
	case symlinkExit:
		return fmt.Errorf("restore on %s refused: the file or its backup is now a symlink", server)
	case changedExit:
		return fmt.Errorf("restore on %s refused: the file changed since this apply wrote it (a concurrent apply?) — left as is", server)
	default:
		return stageFailure("restore", server, code, stderr)
	}
}

// stageFailure wraps a nonzero remote exit with its stderr, bounded by
// sanitize.RemoteSnippet (SEC-8): one line, at most sanitize.MaxSnippet
// safe runes, so a hostile server can neither forge report rows with
// blank-looking padding nor flood the report.
func stageFailure(stage, server string, code int, stderr *sshconn.CappedBuffer) error {
	return fmt.Errorf("%s on %s failed (exit %d): %s",
		stage, server, code, sanitize.RemoteSnippet(stderr.String()))
}
