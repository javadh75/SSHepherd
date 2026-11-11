package sshconn

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sanitize"
)

// AncestorWalk is sshd's StrictModes walk, shared by the write path (which
// refuses) and the posture probe (which reports). It walks the directory
// "$d" up to the login user's home (or /, for a path outside it) twice: as
// written, and resolved with cd -P. onMode runs for a component that is
// group- or other-writable, onOwner for one owned by neither the login user
// nor root; each action sees $1 (ls -ldn's mode), $3 (the owner uid) and $q
// (the path). Whoever can write an ancestor, or owns a symlink along the
// path, can redirect the file, e.g. a link that turns root's write into
// /root/.ssh. Symlinks are judged by owner only (their mode bits are
// meaningless); the resolved walk covers the directories they lead to.
// ls -ldn reports a symlink itself, so the as-written walk sees each link,
// not its target. Needs u and d.
func AncestorWalk(onMode, onOwner string) string {
	return `h=${HOME%/}; ` + resolvedTo("ph", `"$h"`, ` 2>/dev/null`) +
		`; q="$d"; while :; do set -- $(ls -ldn "$q"); case $1 in l*) ;; ?????w*|????????w*) ` + onMode +
		`;; esac; if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + onOwner +
		`; fi; if [ "$q" = "$h" ] || [ "$q" = / ] || [ "$q" = . ]; then break; fi; ` + DirnameTo("q", `"$q"`) + `; done` +
		`; q=$(cd -P "$d" && pwd -P && echo .) || exit 1; q=${q%??}` +
		`; while :; do set -- $(ls -ldn "$q"); case $1 in ?????w*|????????w*) ` + onMode +
		`;; esac; if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + onOwner +
		`; fi; if [ "$q" = "$ph" ] || [ "$q" = / ]; then break; fi; ` + DirnameTo("q", `"$q"`) + `; done`
}

// A bare "$(cmd)" drops every trailing newline, so a directory whose name
// ends in one would read as a sibling without it, and a walk would check
// that decoy (G018). These forms print a sentinel after the path and strip
// it with the one newline echo added before it, leaving the name intact.

// DirnameTo assigns the parent directory of the word from to the variable
// v (the write scripts' walks use it too).
func DirnameTo(v, from string) string {
	return v + `=$(dirname ` + from + ` && echo .); ` + v + `=${` + v + `%??}`
}

// resolvedTo assigns the physical path of the directory word dir to the
// variable v; a cd that fails leaves v empty. errs is cd's redirection.
func resolvedTo(v, dir, errs string) string {
	return v + `=$(cd -P ` + dir + errs + ` && pwd -P && echo .); ` + v + `=${` + v + `%??}`
}

// Records the posture probe prints, one per line.
const (
	postureKeys2Record = "SSHEPHERD-KEYS2 1"
	// maxPostureRecords bounds what a server can make audit print: a real
	// path has far fewer components than two walks times two findings.
	maxPostureRecords = 64
)

// postureRecord is the probe's one record shape. Issue names and the mode
// are closed sets; the path is the rest of the line, so a raw newline breaks
// the grammar and fails closed. The probe prints a path's newlines as '?'
// (R in PostureCmdFor), so a directory named with one is still graded.
var postureRecord = regexp.MustCompile(`^SSHEPHERD-POSTURE ([-dlbcps][-rwxsStT]{9}[.+@]?) ([0-9]+) (` +
	fleet.PostureSymlink + `|` + fleet.PostureForeignOwner + `|` + fleet.PostureGroupWritable + `|` + fleet.PostureWorldWritable + `) (.+)$`)

var errPostureMalformed = errors.New("posture probe output malformed")

// PostureCmdFor builds the read-only posture probe for the managed file at
// path: it prints one SSHEPHERD-POSTURE record per StrictModes problem on
// the file and its directories (group- or world-writable, owned by neither
// the login user nor root, a symlinked file), and SSHEPHERD-KEYS2 1 when a
// non-empty ~/.ssh/authorized_keys2 sits beside a default-equivalent managed
// path. It walks from the file's nearest existing directory, checking the
// owner of any dangling symlink it passes on the way up, never exits early
// on a finding, and exits non-zero only when a required tool fails. Absent
// components are not findings: the read already reports absence.
func PostureCmdFor(path string) string {
	const (
		rec        = `R() { printf 'SSHEPHERD-POSTURE %s %s %s %s\n' "$1" "$2" "$3" "$(printf '%s' "$q" | tr '\n' '?')"; }`
		modeFinds  = `case $1 in ?????w*) R "$1" "$3" ` + fleet.PostureGroupWritable + `;; esac; case $1 in ????????w*) R "$1" "$3" ` + fleet.PostureWorldWritable + `;; esac`
		ownerFinds = `R "$1" "$3" ` + fleet.PostureForeignOwner
	)
	return PathAssign(path) + `; set -f; u=$(id -u) || exit 1; ` + rec +
		`; q="$p"; if [ -L "$p" ]; then set -- $(ls -ldn "$p"); R "$1" "$3" ` + fleet.PostureSymlink +
		`; elif [ -e "$p" ]; then set -- $(ls -ldn "$p"); if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + ownerFinds + `; fi; ` + modeFinds + `; fi` +
		`; ` + DirnameTo("d", `"$p"`) + `; while [ ! -d "$d" ]; do if [ -L "$d" ]; then q="$d"; set -- $(ls -ldn "$q"); if [ "$3" != "$u" ] && [ "$3" != 0 ]; then ` + ownerFinds + `; fi; fi; ` + DirnameTo("d", `"$d"`) + `; done; ` + AncestorWalk(modeFinds, ownerFinds) +
		`; k="${HOME:?}"/.ssh; ` + keys2Check(path) + `; exit 0`
}

// keys2Check prints the keys2 record for a managed path that is the default
// spelling or resolves on the server to ~/.ssh/authorized_keys (cd -P for the
// directory; test -ef for a symlinked final component, degrading to the
// directory-only comparison on a shell without it). A directory that does
// not resolve never matches, so two missing directories cannot both collapse
// to "/authorized_keys". Needs p and k.
func keys2Check(path string) string {
	const report = `if [ -s "$k/authorized_keys2" ]; then printf '` + postureKeys2Record + `\n'; fi`
	if path == DefaultAuthorizedKeysPath {
		return report
	}
	return DirnameTo("m", `"$p"`) + `; ` + resolvedTo("a", `"$m"`, ` 2>/dev/null`) + `; ` + resolvedTo("s", `"$k"`, ` 2>/dev/null`) +
		`; [ -n "$a" ] && [ -n "$s" ]` +
		` && { [ "$a/${p##*/}" = "$s/authorized_keys" ] || [ "$p" -ef "$s/authorized_keys" ] 2>/dev/null; } && { ` + report + `; }`
}

// FinishPosture parses the probe's outcome, fail-closed: a non-zero exit,
// any line outside the grammar, more than maxPostureRecords records or
// output at the capture limit is ErrorKindRemote, never a clean result, so
// the server is unreachable rather than graded. The as-written and resolved
// walks visit the same directory when no symlink is involved, so identical
// (path, issue) records collapse to one, after the count check.
func FinishPosture(code int, stdout, stderr *CappedBuffer) ([]fleet.PostureIssue, bool, error) {
	if code != 0 {
		return nil, false, classify(fleet.ErrorKindRemote,
			fmt.Errorf("posture probe failed (exit %d): %s", code, sanitize.RemoteSnippet(stderr.String())))
	}
	if stdout.truncated || stdout.Len() >= MaxRemoteOutput {
		return nil, false, classify(fleet.ErrorKindRemote, errPostureMalformed)
	}
	out := stdout.String()
	if out == "" {
		return nil, false, nil
	}
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if !strings.HasSuffix(out, "\n") || len(lines) > maxPostureRecords {
		return nil, false, classify(fleet.ErrorKindRemote, errPostureMalformed)
	}
	var issues []fleet.PostureIssue
	keys2 := false
	for _, line := range lines {
		if line == postureKeys2Record {
			keys2 = true
			continue
		}
		m := postureRecord.FindStringSubmatch(line)
		if m == nil {
			return nil, false, classify(fleet.ErrorKindRemote, errPostureMalformed)
		}
		issue := fleet.PostureIssue{Mode: m[1], UID: m[2], Issue: m[3], Path: sanitize.Remote(m[4])}
		seen := slices.ContainsFunc(issues, func(i fleet.PostureIssue) bool { return i.Path == issue.Path && i.Issue == issue.Issue })
		if !seen {
			issues = append(issues, issue)
		}
	}
	return issues, keys2, nil
}
