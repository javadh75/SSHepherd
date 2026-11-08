// Package authkeys parses OpenSSH authorized_keys entries into a structured,
// comparable form. It is the foundation for SSHepherd's source-of-truth model:
// reading what is currently installed on a host and diffing it against what
// should be there.
package authkeys

import (
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/ssh"
)

// Key is a single parsed authorized_keys entry.
type Key struct {
	Type        string   // key algorithm, e.g. "ssh-ed25519"
	Comment     string   // trailing comment, conventionally user@host
	Options     []string // leading options, e.g. ["no-port-forwarding"]
	Fingerprint string   // SHA256 fingerprint, e.g. "SHA256:abc..."
	Raw         string   // the original line, whitespace-trimmed: options, key material, comment
	// Weak is StrengthIssue's verdict ("" for an acceptable key) and WeakBits
	// the RSA modulus size it found, set by ParseLine so the line is parsed once.
	Weak     string
	WeakBits int
}

// ParseLine parses a single authorized_keys line. Blank lines and comment lines
// (those whose first non-space character is '#') are not entries and return
// (nil, nil). Anything else that is not a valid key returns an error.
func ParseLine(line string) (*Key, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, nil
	}
	// An embedded CR is a hostile line break: x/crypto truncates the line
	// at the first CR, silently discarding whatever follows it, so the
	// hidden tail would vanish from every parsed view (Comment, and any
	// Raw-derived output) while still sitting in the file — and a terminal
	// or editor may show it as a second line. Reject it so the line hits
	// the strict/--partial gate and is never silently shortened. (A
	// trailing CR is trimmed above; ParseFile strips CRLF endings before
	// calling.)
	if strings.ContainsRune(trimmed, '\r') {
		return nil, fmt.Errorf("parse authorized_keys line: embedded carriage return")
	}

	pub, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse authorized_keys line: %w", err)
	}
	// OpenSSH's sshkey_read rejects a declared type token that disagrees
	// with the blob (KEY_TYPE_MISMATCH), so sshd skips such a line.
	// Accepting it would let audit/adopt report a key as installed that
	// cannot actually log in. x/crypto >= v0.56 rejects most mismatches
	// itself; this check is kept as defense in depth so the rule does not
	// depend on the dependency version.
	if declared := declaredType(trimmed, len(options) > 0); declared != pub.Type() {
		return nil, fmt.Errorf("parse authorized_keys line: key type mismatch: declared %q, key material %q",
			declared, pub.Type())
	}

	weak, bits := StrengthIssue(pub)
	return &Key{
		Weak:        weak,
		WeakBits:    bits,
		Type:        pub.Type(),
		Comment:     comment,
		Options:     options,
		Fingerprint: ssh.FingerprintSHA256(pub),
		Raw:         strings.TrimSpace(line),
	}, nil
}

// declaredType returns the key-type token of a trimmed line ParseLine has
// already parsed: the first token when the line has no options, else the
// token after the options field — scanned exactly like x/crypto's
// ParseAuthorizedKey (commas/whitespace split options outside double
// quotes; a backslash escapes a quote).
func declaredType(trimmed string, hasOptions bool) string {
	rest := trimmed
	if hasOptions {
		inQuote := false
		i := 0
		for ; i < len(rest); i++ {
			b := rest[i]
			if !inQuote && (b == ' ' || b == '\t') {
				break
			}
			if b == '"' && (i == 0 || rest[i-1] != '\\') {
				inQuote = !inQuote
			}
		}
		rest = strings.TrimLeft(rest[i:], " \t")
	}
	if i := strings.IndexAny(rest, " \t"); i >= 0 {
		return rest[:i]
	}
	return rest
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

// RenderTextIssue reports why s is unsafe to render into an authorized_keys
// line and read back identically; empty means safe (and the empty string is
// safe — it means "unset"). Unsafe runes (IsUnsafeRune) would split the
// one-entry-one-line invariant or smuggle terminal escapes; edge whitespace
// would not survive ssh.ParseAuthorizedKey's comment trimming on re-read,
// making the written file permanently disagree with the manifest. config
// validation applies this to every rendered field (user names, comments) at
// manifest load, so hostile values die before the render path ever runs.
func RenderTextIssue(s string) string {
	for _, r := range s {
		if IsUnsafeRune(r) {
			return "contains control or format characters"
		}
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
