package authkeys

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type effect int

const (
	neutral   effect = iota // environment=, tunnel=: neither narrows nor widens login access
	restricts               // narrows access: dropping it widens access
	loosens                 // widens access: adding it widens access
)

// optionSpec is sshd(8)'s meaning of one authorized_keys option
// (AUTHORIZED_KEYS FILE FORMAT). sshd rejects the whole line on any option
// missing from this table, a valued option without a double-quoted value,
// a bad expiry-time, or a second clause of a once-only option (command=,
// from=, principals=; auth-options.c "multiple … clauses").
type optionSpec struct {
	takesValue bool
	effect     effect
	// once: sshd rejects the line when the option appears twice.
	once bool
	// union: every clause adds to what the line allows (permitopen=,
	// permitlisten=): one more widens access, one fewer narrows it.
	union bool
	// underRestrict marks a re-enabler (pty, port-forwarding, …): it only
	// widens access on a line that also carries restrict; without restrict
	// the feature is already on.
	underRestrict bool
	// blocksLogin: can stop a non-interactive SSHepherd login outright.
	blocksLogin bool
	// certOnly: the line accepts only certificates the key signed, never the bare key.
	certOnly bool
	// value validates the unquoted value; nil accepts any.
	value func(string) error
}

var options = map[string]optionSpec{
	"agent-forwarding":    {effect: loosens, underRestrict: true},
	"cert-authority":      {effect: restricts, certOnly: true},
	"command":             {takesValue: true, effect: restricts, blocksLogin: true, once: true},
	"environment":         {takesValue: true},
	"expiry-time":         {takesValue: true, effect: restricts, blocksLogin: true, value: validExpiry},
	"from":                {takesValue: true, effect: restricts, blocksLogin: true, once: true},
	"no-agent-forwarding": {effect: restricts},
	"no-port-forwarding":  {effect: restricts},
	"no-pty":              {effect: restricts},
	"no-touch-required":   {effect: loosens}, // sk keys: no user-presence touch: a relaxation
	"no-user-rc":          {effect: restricts},
	"no-x11-forwarding":   {effect: restricts},
	"permitlisten":        {takesValue: true, effect: restricts, union: true},
	"permitopen":          {takesValue: true, effect: restricts, union: true},
	"port-forwarding":     {effect: loosens, underRestrict: true},
	"principals":          {takesValue: true, effect: restricts, certOnly: true, once: true},
	"pty":                 {effect: loosens, underRestrict: true},
	"restrict":            {effect: restricts, blocksLogin: true},
	"tunnel":              {takesValue: true},
	"user-rc":             {effect: loosens, underRestrict: true},
	"verify-required":     {effect: restricts}, // sk keys: PIN/biometric required
	"x11-forwarding":      {effect: loosens, underRestrict: true},
}

// nameOf is an option's lower-cased name (sshd matches names case-insensitively).
func nameOf(opt string) string {
	name, _, _ := strings.Cut(opt, "=")
	return strings.ToLower(name)
}

func lookup(opt string) (optionSpec, bool) {
	s, ok := options[nameOf(opt)]
	return s, ok
}

// IsOptionName reports whether name (no "=value") is an authorized_keys
// option sshd knows, case-insensitively.
func IsOptionName(name string) bool {
	_, ok := options[strings.ToLower(name)]
	return ok
}

// CheckOption reports why one key option is unfit for the manifest: an
// unsafe rune, or a reason sshd rejects the line; "" means acceptable.
// Unsafe runes are rejected first: option values are rendered verbatim into
// files and plan output.
func CheckOption(opt string) string {
	if strings.ContainsFunc(opt, IsUnsafeRune) {
		return "contains control or format characters"
	}
	return sshdIssue(opt)
}

// sshdIssue reports why one option makes sshd reject the line; "" means sshd
// accepts it. Unsafe runes are not sshd's concern: a quoted value may carry
// any byte, and an unknown name is caught by the table lookup.
//
// An accepted option is exactly one clause: its quoted value ends at its last
// byte, read as sshd's opt_dequote reads it. A value that closes earlier
// would carry further clauses, or a space and a whole second key, into a
// rendered line verbatim. The line parser never yields such a token for a
// line sshd honors (sshd rejects what follows an early close), but a raw
// grant option (spec S7) reaches here unsplit.
func sshdIssue(opt string) string {
	_, value, hasValue := strings.Cut(opt, "=")
	s, known := lookup(opt)
	switch {
	case !known:
		return "is not a recognized authorized_keys option"
	case !s.takesValue && hasValue:
		return "does not take a value"
	case !s.takesValue:
		return ""
	}
	end := quotedEnd(value)
	switch {
	case !hasValue || end < 0:
		return `requires a quoted value (name="...")`
	case end != len(value)-1:
		return `has an unescaped '"' inside its quoted value; sshd ends the value there (write \" for a literal quote)`
	case s.value != nil && s.value(value[1:end]) != nil:
		return "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])" // only expiry-time has a validator today
	}
	return ""
}

// quotedEnd returns the index of the '"' that closes value's leading quoted
// string, scanned like OpenSSH's opt_dequote (a backslash right before a '"'
// escapes it), or -1 when value does not start with '"' or never closes.
func quotedEnd(value string) int {
	if !strings.HasPrefix(value, `"`) {
		return -1
	}
	for i := 1; i < len(value); i++ {
		switch {
		case value[i] == '\\' && i+1 < len(value) && value[i+1] == '"':
			i++
		case value[i] == '"':
			return i
		}
	}
	return -1
}

// OptionIssue returns the first reason a line with these options is unfit
// for the manifest (CheckOption, or a repeated once-only clause), as
// `option "<opt>" <issue>`; nil when every option is acceptable.
func OptionIssue(opts []string) error { return linesIssue(opts, CheckOption) }

// IgnoredBySSHD returns the first reason sshd skips a line with these
// options (an unknown option, a bad value, a repeated once-only clause), in
// OptionIssue's wording; nil when sshd honors the line. Unlike OptionIssue
// it accepts control runes inside a quoted value, as sshd does.
func IgnoredBySSHD(opts []string) error { return linesIssue(opts, sshdIssue) }

func linesIssue(opts []string, check func(string) string) error {
	for i, o := range opts {
		if issue := check(o); issue != "" {
			return fmt.Errorf("option %q %s", o, issue)
		}
		if repeatOf(opts, i) {
			return fmt.Errorf("option %q repeats %s=, which sshd allows once per line", o, nameOf(o))
		}
	}
	return nil
}

// repeatOf reports whether opts[i] is a second (or later) clause of a
// once-only option.
func repeatOf(opts []string, i int) bool {
	s, ok := lookup(opts[i])
	return ok && s.once && slices.ContainsFunc(opts[:i], func(o string) bool { return nameOf(o) == nameOf(opts[i]) })
}

// Loosening reports how rewriting a line from actual to desired options
// widens access. dropped: restrictive options actual carries that desired
// does not carry verbatim (a changed from= value counts), and every option
// that makes sshd ignore the actual line (unknown, bad value, repeated
// once-only clause): a live rewrite of a dead line is the widest change. A
// permitopen=/permitlisten= clause is dropped only when desired carries
// none of that name (fewer clauses narrow the union). added: widening
// options desired adds — a loosening option (a re-enabler only when both
// lines carry restrict; otherwise it is a no-op, or dropping restrict is
// reported) or a new permitopen=/permitlisten= clause beside actual's.
func Loosening(actual, desired []string) (dropped, added []string) {
	for i := range actual {
		if droppedWidens(actual, i, desired) {
			dropped = append(dropped, actual[i])
		}
	}
	return dropped, addedWidening(actual, desired)
}

// droppedWidens reports whether losing actual[i] in the rewrite to desired
// widens access (see Loosening).
func droppedWidens(actual []string, i int, desired []string) bool {
	o := actual[i]
	if repeatOf(actual, i) {
		return countName(desired, nameOf(o)) < 2 // the repeat made sshd ignore the line
	}
	if slices.Contains(desired, o) {
		return false
	}
	if sshdIssue(o) != "" {
		return true // sshd ignores the line today
	}
	s, known := lookup(o)
	if !known || s.effect != restricts {
		return false
	}
	return !s.union || !hasName(desired, nameOf(o))
}

// addedWidening lists desired's options that widen access over actual (see Loosening).
func addedWidening(actual, desired []string) (added []string) {
	restrictBoth := hasName(actual, "restrict") && hasName(desired, "restrict")
	for _, o := range desired {
		s, ok := lookup(o)
		if !ok || slices.Contains(actual, o) {
			continue
		}
		if (s.union && hasName(actual, nameOf(o))) || (s.effect == loosens && (!s.underRestrict || restrictBoth)) {
			added = append(added, o)
		}
	}
	return added
}

func countName(opts []string, name string) int {
	n := 0
	for _, o := range opts {
		if nameOf(o) == name {
			n++
		}
	}
	return n
}

// BlocksLogin reports whether any option can stop a non-interactive login
// outright (from=, command=, restrict, expiry-time=).
func BlocksLogin(opts []string) bool {
	return anySpec(opts, func(s optionSpec) bool { return s.blocksLogin })
}

// CertOnly reports whether the line accepts only certificates (cert-authority, principals=).
func CertOnly(opts []string) bool {
	return anySpec(opts, func(s optionSpec) bool { return s.certOnly })
}

// FindOption returns the first option named name (case-insensitive), verbatim.
func FindOption(opts []string, name string) (string, bool) {
	for _, o := range opts {
		n, _, _ := strings.Cut(o, "=")
		if strings.EqualFold(n, name) {
			return o, true
		}
	}
	return "", false
}

// IsRestriction reports whether opt only narrows what a key line allows, so
// a per-grant restriction may add it (spec 2026-11-08 S7, OP5): an option the
// table marks restricts that does not make the line accept certificates only
// (cert-authority, principals=). The name matches case-insensitively;
// CheckOption judges the value.
func IsRestriction(opt string) bool {
	s, ok := lookup(opt)
	return ok && s.effect == restricts && !s.certOnly
}

// SameOptions reports whether a and b hold the same clauses, ignoring order,
// repeats and the case of option names (sshd matches names
// case-insensitively); values compare exactly. Every grant of one key on one
// server must agree by this test (spec S7).
func SameOptions(a, b []string) bool { return slices.Equal(optionSet(a), optionSet(b)) }

// optionSet is opts with each name lower-cased, sorted, repeats removed.
func optionSet(opts []string) []string {
	out := make([]string, 0, len(opts))
	for _, o := range opts {
		name, value, hasValue := strings.Cut(o, "=")
		clause := strings.ToLower(name)
		if hasValue {
			clause += "=" + value
		}
		out = append(out, clause)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

var errExpiry = errors.New("want YYYYMMDD[HHMM[SS]][Z]")

// ExpiryTime parses an expiry-time="…" option: sshd's YYYYMMDD[HHMM[SS]],
// in local unless suffixed Z (or z, as today's keyarg accepts) for UTC.
func ExpiryTime(opt string, local *time.Location) (time.Time, error) {
	_, v, _ := strings.Cut(opt, "=")
	return parseExpiry(strings.Trim(v, `"`), local)
}

// EarliestExpiry returns the earliest parseable expiry-time="…" clause of a
// line (sshd honours the earliest of a repeated clause), verbatim and as a
// time; ok is false when the line carries none. Malformed clauses are
// skipped: IgnoredBySSHD and manifest validation own that verdict.
func EarliestExpiry(opts []string, local *time.Location) (opt string, t time.Time, ok bool) {
	for _, o := range opts {
		if nameOf(o) != "expiry-time" {
			continue
		}
		when, err := ExpiryTime(o, local)
		if err == nil && (!ok || when.Before(t)) {
			opt, t, ok = o, when, true
		}
	}
	return opt, t, ok
}

// Expired reports whether a line's expiry-time has been reached: true when
// any clause is at or before now.
func Expired(opts []string, now time.Time, local *time.Location) bool {
	_, t, ok := EarliestExpiry(opts, local)
	return ok && !t.After(now)
}

func validExpiry(v string) error { _, err := parseExpiry(v, time.UTC); return err }

func parseExpiry(v string, loc *time.Location) (time.Time, error) {
	// OpenSSH's parse_absolute_time: a "Z" or "UTC" suffix (case-insensitive)
	// means UTC; otherwise the time is local to the reader.
	switch {
	case len(v) > 3 && strings.EqualFold(v[len(v)-3:], "UTC"):
		v, loc = v[:len(v)-3], time.UTC
	case len(v) > 1 && strings.EqualFold(v[len(v)-1:], "Z"):
		v, loc = v[:len(v)-1], time.UTC
	}
	layout, ok := map[int]string{8: "20060102", 12: "200601021504", 14: "20060102150405"}[len(v)]
	if !ok {
		return time.Time{}, errExpiry
	}
	t, err := time.ParseInLocation(layout, v, loc)
	if err != nil {
		return time.Time{}, errExpiry
	}
	return t, nil
}

func hasName(opts []string, name string) bool { _, ok := FindOption(opts, name); return ok }

func anySpec(opts []string, pred func(optionSpec) bool) bool {
	for _, o := range opts {
		if s, ok := lookup(o); ok && pred(s) {
			return true
		}
	}
	return false
}
