package sshwrite

import (
	"fmt"
	"strings"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// signalExit is where a remote shell's exit status starts meaning a signal
// (ssh reports a signal as 128 plus its number).
const signalExit = 128

// keys2Present is listKeys2Cmd's whole output when authorized_keys2 exists.
const keys2Present = "sshepherd-keys2-present"

// keys2Move is what disableKeys2 learned: the copy's basename (empty when
// nothing was moved), or unknown when the script may have moved the file
// but its reply was lost or unparseable.
type keys2Move struct {
	name    string
	unknown bool
}

// listKeys2Cmd reports the state of authorized_keys2 after a lost reply: a
// single keys2Present line when it is in place (the move did not happen, or
// someone recreated it), otherwise one "sshepherd-keys2 <basename>" line per
// disabled copy. Globbing is on, for the copies. A name holding a newline
// splits into lines parseKeys2Listing refuses.
func listKeys2Cmd() string {
	return sshconn.PathAssign(sshconn.SecondaryAuthorizedKeysPath) +
		`; if [ -e "$p" ] || [ -L "$p" ]; then echo ` + keys2Present + `; exit 0; fi` +
		`; for f in "$p"` + fleet.Keys2DisabledSuffix + `*; do if [ -e "$f" ] || [ -L "$f" ]; then printf 'sshepherd-keys2 %s\n' "${f##*/}"; fi; done`
}

// parseKeys2Listing reads listKeys2Cmd's stdout into the disabled copies'
// names: none when authorized_keys2 is in place or nothing is there, the two
// cases that need no move. It fails closed: false for anything outside the
// grammar, or a name parseKeys2Name would not accept.
func parseKeys2Listing(stdout string) (names []string, ok bool) {
	out := strings.TrimSuffix(stdout, "\n")
	if out == "" || out == keys2Present {
		return nil, true
	}
	for line := range strings.SplitSeq(out, "\n") {
		name, valid := parseKeys2Name(line)
		if !valid || name == "" {
			return nil, false
		}
		names = append(names, name)
	}
	return names, true
}

// recoverKeys2 settles a move whose reply was lost, after a REJECTED login:
// it lists what is there and moves back the one copy it finds. It returns
// whether a copy was moved back. In place, or nothing there at all, needs
// no move. Any failure, and more than one copy (the older ones are not this
// run's, and a wrong copy would reinstall old keys), is an error, so the
// lockout reports an unrestored move-back.
func (s *writeSession) recoverKeys2() (bool, error) {
	const maybe = "authorized_keys2 on %s may have been moved aside, "
	code, stdout, stderr, err := s.listKeys2()
	if err != nil {
		return false, sshconn.SanitizedError{Err: fmt.Errorf(maybe+"and checking it failed: %w", s.srv.Name, err)}
	}
	if code != 0 {
		return false, fmt.Errorf(maybe+"and %w", s.srv.Name, stageFailure("listing its copies", s.srv.Name, code, stderr))
	}
	names, ok := parseKeys2Listing(stdout.String())
	switch {
	case !ok:
		return false, fmt.Errorf(maybe+"and the listing of its copies was not recognized", s.srv.Name)
	case len(names) == 0:
		return false, nil
	case len(names) > 1:
		return false, fmt.Errorf(maybe+"and %d copies exist, so this run's cannot be told apart (%s); move the right one back by hand", s.srv.Name, len(names), strings.Join(names, ", "))
	}
	return true, s.restoreKeys2(names[0])
}

// listKeys2 runs the listing, over the one reconnect if the connection is
// gone: the reply being lost usually means it is.
func (s *writeSession) listKeys2() (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
	code, stdout, stderr, err := s.exec(listKeys2Cmd(), nil)
	if err == nil {
		return code, stdout, stderr, nil
	}
	if rerr := s.reconnect(); rerr != nil {
		return 0, nil, nil, fmt.Errorf("%w (and no reconnect: %w)", err, rerr)
	}
	return s.exec(listKeys2Cmd(), nil)
}
