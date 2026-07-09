// Package authkeys parses OpenSSH authorized_keys entries into a structured,
// comparable form. It is the foundation for SSHepherd's source-of-truth model:
// reading what is currently installed on a host and diffing it against what
// should be there.
package authkeys

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Key is a single parsed authorized_keys entry.
type Key struct {
	Type        string   // key algorithm, e.g. "ssh-ed25519"
	Comment     string   // trailing comment, conventionally user@host
	Options     []string // leading options, e.g. ["no-port-forwarding"]
	Fingerprint string   // SHA256 fingerprint, e.g. "SHA256:abc..."
}

// ParseLine parses a single authorized_keys line. Blank lines and comment lines
// (those whose first non-space character is '#') are not entries and return
// (nil, nil). Anything else that is not a valid key returns an error.
func ParseLine(line string) (*Key, error) {
	if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, nil
	}

	pub, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse authorized_keys line: %w", err)
	}

	return &Key{
		Type:        pub.Type(),
		Comment:     comment,
		Options:     options,
		Fingerprint: ssh.FingerprintSHA256(pub),
	}, nil
}

// ParseError describes a single unparseable line in an authorized_keys file.
type ParseError struct {
	Line int // 1-based line number
	Err  error
}

func (e ParseError) Error() string {
	return fmt.Sprintf("line %d: %v", e.Line, e.Err)
}

func (e ParseError) Unwrap() error { return e.Err }

// ParseFile parses a whole authorized_keys file. Blank and comment lines are
// skipped. Every line that is neither is either a parsed Key or a ParseError
// carrying its 1-based line number, so a file can be partially usable while
// still reporting exactly what could not be read.
func ParseFile(data []byte) ([]Key, []ParseError) {
	var keys []Key
	var errs []ParseError
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		k, err := ParseLine(line)
		switch {
		case err != nil:
			errs = append(errs, ParseError{Line: i + 1, Err: err})
		case k != nil:
			keys = append(keys, *k)
		}
	}
	return keys, errs
}

// Result is the outcome of diffing a desired key set against an actual one.
type Result struct {
	OK           []Key // fingerprint present in both
	Missing      []Key // desired but not installed
	Unauthorized []Key // installed but not desired
}

// Diff compares key sets by SHA256 fingerprint. Order is deterministic without
// sorting: OK and Missing follow desired order, Unauthorized follows actual
// order. Duplicate fingerprints in actual are collapsed (first occurrence wins).
// desired is assumed unique by fingerprint — config validation guarantees this
// (duplicate keys are rejected at manifest load); Diff does not dedup it.
func Diff(desired, actual []Key) Result {
	actualByFP := make(map[string]Key, len(actual))
	var actualOrder []string
	for _, k := range actual {
		if _, dup := actualByFP[k.Fingerprint]; !dup {
			actualByFP[k.Fingerprint] = k
			actualOrder = append(actualOrder, k.Fingerprint)
		}
	}
	desiredFP := make(map[string]bool, len(desired))
	var r Result
	for _, k := range desired {
		desiredFP[k.Fingerprint] = true
		if _, ok := actualByFP[k.Fingerprint]; ok {
			r.OK = append(r.OK, k)
		} else {
			r.Missing = append(r.Missing, k)
		}
	}
	for _, fp := range actualOrder {
		if !desiredFP[fp] {
			r.Unauthorized = append(r.Unauthorized, actualByFP[fp])
		}
	}
	return r
}
