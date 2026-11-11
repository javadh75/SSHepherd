// Package authkeys parses OpenSSH authorized_keys entries into a structured,
// comparable form. It is the foundation for SSHepherd's source-of-truth model:
// reading what is currently installed on a host and diffing it against what
// should be there.
package authkeys

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"
)

// Key is a single parsed authorized_keys entry.
type Key struct {
	Type        string   // key algorithm, e.g. "ssh-ed25519"
	Comment     string   // trailing comment, conventionally user@host
	Options     []string // leading options, e.g. ["no-port-forwarding"]
	Fingerprint string   // SHA256 fingerprint, e.g. "SHA256:abc..."
	// Raw is the original line: options, key material, comment, and any
	// bytes sshd does not read (a tail after a NUL, whitespace inside the key
	// field), so it is never silently shortened. Only the spaces and tabs
	// sshd skips are trimmed at its start (a leading VT, FF or CR makes sshd
	// ignore the line and stays), and whitespace at its end.
	Raw string
	// Weak is StrengthIssue's verdict ("" for an acceptable key) and WeakBits
	// the RSA modulus size it found, set by ParseLine so the line is parsed once.
	Weak     string
	WeakBits int
}

// ParseLine parses a single authorized_keys line the way sshd reads it
// (readLine): a line sshd honors yields the key it logs in with, even where
// x/crypto's own line parser refuses it (review F002), and a line sshd skips
// is an error. Blank lines and comment lines (those whose first non-space
// character is '#') are not entries and return (nil, nil). Options are
// split, not judged: IgnoredBySSHD says whether sshd accepts them.
func ParseLine(line string) (*Key, error) {
	k, _, err := parseLine(line)
	return k, err
}

// parseLine is ParseLine, also returning the public key (RenderLine
// re-marshals it).
func parseLine(line string) (*Key, ssh.PublicKey, error) {
	text := cString(line)
	if t := strings.TrimSpace(text); t == "" || t[0] == '#' {
		return nil, nil, nil
	}
	f, err := readLine(text)
	if err != nil {
		return nil, nil, fmt.Errorf("parse authorized_keys line: %w", err)
	}
	weak, bits := StrengthIssue(f.pub)
	return &Key{
		Weak:        weak,
		WeakBits:    bits,
		Type:        f.pub.Type(),
		Comment:     strings.TrimSpace(f.comment),
		Options:     f.options,
		Fingerprint: ssh.FingerprintSHA256(f.pub),
		Raw:         strings.TrimRightFunc(strings.TrimLeft(line, fieldSeparators), unicode.IsSpace),
	}, f.pub, nil
}

// ParseError describes a single unparseable line in an authorized_keys file.
type ParseError struct {
	Line int // 1-based line number
	Err  error
}

func (e ParseError) Error() string {
	return stripControl(fmt.Sprintf("line %d: %v", e.Line, e.Err))
}

func (e ParseError) Unwrap() error { return e.Err }

// stripControl drops control characters (except newline and tab) so error
// text derived from remote file content cannot carry terminal escape
// sequences. unicode.IsControl covers C0, DEL, and C1 — C1 CSI (U+009B)
// acts like ESC [ in some terminals. Format (Cf) runes are dropped too:
// bidi overrides like U+202E can visually reorder the message.
func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if (unicode.IsControl(r) || unicode.Is(unicode.Cf, r)) && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// IsUnsafeRune reports whether r must never reach a rendered line or a
// terminal: control runes (C0, DEL, C1 — U+009B acts like ESC [), format
// runes (Cf: bidi overrides like U+202E visually reorder text), and the
// Unicode line/paragraph separators (Zl/Zp: U+2028/U+2029, which some
// editors, terminals and JSON consumers render as a line break).
func IsUnsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp)
}

// noSkip exempts no rune from unsafeText.
const noSkip rune = -1

// unsafeText reports whether s is not valid UTF-8 or holds a rune other than
// skip for which IsUnsafeRune holds. IsUnsafeRune sees an invalid byte
// only as U+FFFD, but a raw 0x9B is CSI to a terminal in an 8-bit locale
// (review F008), so invalid UTF-8 is unsafe too.
func unsafeText(s string, skip rune) bool {
	return !utf8.ValidString(s) || strings.ContainsFunc(s, func(r rune) bool { return r != skip && IsUnsafeRune(r) })
}

// LineTextIssue reports why a whole key line is unfit to keep in the
// manifest verbatim; empty means fit. A line passes when it is valid UTF-8
// with no unsafe rune but a tab (sshd's field separator). Parsing alone does
// not ensure this: sshd ends a line at a NUL and skips whitespace inside the
// key field, so a line that logs in may carry bytes a reviewer never sees.
func LineTextIssue(s string) string {
	if unsafeText(s, '\t') {
		return "contains control or format characters"
	}
	return ""
}

// RenderTextIssue reports why s is unsafe to render into an authorized_keys
// line and read back identically; empty means safe (and the empty string is
// safe — it means "unset"). Unsafe runes (IsUnsafeRune) and invalid UTF-8
// would split the one-entry-one-line invariant or smuggle terminal escapes;
// edge whitespace would not survive the key parser's comment trimming on
// re-read, making the written file permanently disagree with the manifest.
// config validation applies this to every rendered field (user names,
// comments) at manifest load, so hostile values die before the render path
// ever runs.
func RenderTextIssue(s string) string {
	if unsafeText(s, noSkip) {
		return "contains control or format characters"
	}
	if strings.TrimSpace(s) != s {
		return "has leading or trailing whitespace"
	}
	return ""
}

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

	// Actual indexes every installed key by fingerprint — first occurrence
	// per fingerprint, exactly the dedup Diff applies. It lets callers
	// inspect the on-server form (comment/options) of matched keys, whose
	// OK entries carry the desired form instead.
	Actual map[string]Key
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
	r := Result{Actual: actualByFP}
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
