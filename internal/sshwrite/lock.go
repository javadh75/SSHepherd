package sshwrite

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// Owner descriptions of a busy lock with no usable record.
const (
	ownerUnknown      = "an unknown owner (older sshepherd or killed shell)"
	ownerUnrecognized = "an unrecognized owner record"
)

// ageUnknown is the age of a lock whose record gave no usable clock.
const ageUnknown time.Duration = -1

// maxLockAge caps a believable age (68 years): beyond it the record's
// numbers are garbage, and multiplying them would overflow a Duration.
const maxLockAge = 1 << 31

// lockOwnerRE is the only owner record the client believes:
// v1 <client-host> <client-pid> <remote-pid> <remote-epoch>. Remote bytes
// reach a report only through its digits and host alphabet.
var lockOwnerRE = regexp.MustCompile(`^v1 ([A-Za-z0-9._-]{1,64}) ([0-9]{1,10}) ([0-9]{1,10}) ([0-9]{1,12})$`)

// lockInfo is what a busy lock's stdout said about its holder.
type lockInfo struct {
	owner string
	age   time.Duration
	known bool
}

// parseLockOwner reads a busy script's stdout: "sshepherd-lock <remote-now>",
// then the first line of the owner record if there is one. The age uses
// only the server's clock, so client clock skew does not matter.
func parseLockOwner(stdout string) lockInfo {
	head, rest, _ := strings.Cut(stdout, "\n")
	now, ok := strings.CutPrefix(head, "sshepherd-lock ")
	line, _, _ := strings.Cut(rest, "\n")
	if !ok || line == "" {
		return lockInfo{owner: ownerUnknown, age: ageUnknown}
	}
	m := lockOwnerRE.FindStringSubmatch(line)
	if m == nil {
		return lockInfo{owner: ownerUnrecognized, age: ageUnknown}
	}
	info := lockInfo{owner: m[1] + " pid " + m[2], age: ageUnknown, known: true}
	nowSec, nowErr := strconv.ParseInt(now, 10, 64)
	epoch, epochErr := strconv.ParseInt(m[4], 10, 64)
	if nowErr == nil && epochErr == nil && nowSec >= epoch && nowSec-epoch < maxLockAge {
		info.age = time.Duration(nowSec-epoch) * time.Second
	}
	return info
}

// heldText is "<owner>" or "<owner> for <age>".
func heldText(owner string, age time.Duration) string {
	if age < 0 {
		return owner
	}
	return owner + " for " + age.Round(time.Second).String()
}

// LockedError reports a refused write: another apply holds the target's
// lock directory. Owner is a description; Known says it came from a valid
// record; Age is negative when the record gave no usable clock. RemoveCmd is
// the by-hand removal: SSHepherd never removes a lock itself.
type LockedError struct {
	Path      string
	Owner     string
	Age       time.Duration
	Known     bool
	RemoveCmd string
}

func (e *LockedError) Error() string {
	scope := ""
	if e.Known {
		host, pid, _ := strings.Cut(e.Owner, " pid ")
		scope = fmt.Sprintf(" on %s (pid %s)", host, pid)
	}
	return fmt.Sprintf("another apply is in progress on %s (lock held by %s); remove it only if no apply is running%s: %s (a killed write can also leave %s%s and %s%s; the next write reclaims both)",
		e.Path, heldText(e.Owner, e.Age), scope, e.RemoveCmd, e.Path, tmpSuffix, e.Path, casSuffix)
}

// lockedErrorFor builds the refusal for a script that exited 47.
func lockedErrorFor(srv config.Server, route []config.Server, path, stdout string) *LockedError {
	info := parseLockOwner(stdout)
	return &LockedError{Path: path, Owner: info.owner, Age: info.age, Known: info.known, RemoveCmd: lockRemoveCmd(srv, route, path)}
}

// lockRemovalScript removes a stale lock. rmdir, not rm -r: it refuses a
// lock directory holding anything unexpected.
func lockRemovalScript(path string) string {
	return sshconn.PathAssign(path) + `; rm -f -- "$p` + lockSuffix + `/owner"; rmdir -- "$p` + lockSuffix + `"`
}

// plainShellWord matches what a shell reads as one literal word.
var plainShellWord = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

// lockRemoveCmd is the paste-ready removal. A server behind bastions (route,
// root first) is reached through them (sshconn.RouteCmd), or the command is
// named as one to run on its bastion when a hop or the server is not a plain
// word (G017).
func lockRemoveCmd(srv config.Server, route []config.Server, path string) string {
	script := lockRemovalScript(path)
	direct := directRemoveCmd(srv, script)
	if len(route) == 0 {
		return direct
	}
	return sshconn.RouteCmd(route, srv, []string{script}, route[len(route)-1].Name, []string{direct})
}

// directRemoveCmd is the ssh command straight to srv: the remote script
// quoted once more for the local shell, and a manifest-controlled target
// that can become neither a local command nor an ssh option.
func directRemoveCmd(srv config.Server, script string) string {
	target := srv.User + "@" + srv.Host
	word := target
	if !plainShellWord.MatchString(target) {
		word = sshconn.ShQuote(target)
	}
	if strings.HasPrefix(target, "-") {
		word = "-- " + word
	}
	return fmt.Sprintf("ssh -p %d %s %s", srv.Port, word, sshconn.ShQuote(script))
}

// clientIdent is the "<host> <pid>" of the lock record: the host reduced to
// the record's alphabet and capped at 64 bytes.
func clientIdent(host string, pid int) string {
	clean := strings.Map(func(r rune) rune {
		if r < 0x80 && plainHostRune(byte(r)) { // #nosec G115 -- r < 0x80
			return r
		}
		return -1
	}, host)
	if len(clean) > 64 {
		clean = clean[:64]
	}
	if clean == "" {
		clean = "unknown"
	}
	return clean + " " + strconv.Itoa(pid)
}

func plainHostRune(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

// ownerIdent is this process's clientIdent. An os.Hostname failure yields
// "unknown": the record is diagnostics only.
var ownerIdent = sync.OnceValue(func() string {
	host, _ := os.Hostname()
	return clientIdent(host, os.Getpid())
})

// ownerRecord writes $l/owner. It runs after the EXIT trap exists: a kill
// in between must not leave a non-empty lock. A failed write is ignored:
// the lock is still valid.
func ownerRecord() string {
	return `printf 'v1 %s %s %s\n' ` + sshconn.ShQuote(ownerIdent()) + ` "$$" "$(date +%s)" > "$l/owner" 2>/dev/null || :`
}

// lockPrologue takes the per-target lock (mkdir is atomic on every POSIX
// filesystem), arranges its removal on every exit path together with the
// temp file, the CAS staging copy and the owner record, and then records
// who holds it. A held lock prints "sshepherd-lock <remote-now>" and the
// owner record's first line, cut to 200 bytes, and exits 47; a lost race
// also exits 47, with no record; any other mkdir failure re-runs mkdir to
// surface its real error and exits 1. That re-run happens before the EXIT
// trap exists, so if it succeeds (the holder released the lock in between)
// it removes the directory it just made and exits 47 — a retryable lost
// race, never a stale lock. Signals route through exit so the EXIT trap
// runs.
func lockPrologue() string {
	return lockHead + lockTrap + `' EXIT; ` + signalTrap + `; ` + ownerRecord()
}

// lockPrologueUndo is lockPrologue for the write script: its EXIT trap also
// runs U (createDirs) on a nonzero exit, after the lock and scratch files
// are gone, so a refusal or failure removes the directories this run
// created (WP-9). A lost lock race (47) exits before this trap exists;
// createDirs' own EXIT trap covers it.
func lockPrologueUndo() string {
	return lockHead + lockTrap + `; [ "$x" = 0 ] || U' EXIT; ` + signalTrap + `; ` + ownerRecord()
}
