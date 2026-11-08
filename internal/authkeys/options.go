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
// or a bad expiry-time.
type optionSpec struct {
	takesValue bool
	effect     effect
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
	"command":             {takesValue: true, effect: restricts, blocksLogin: true},
	"environment":         {takesValue: true},
	"expiry-time":         {takesValue: true, effect: restricts, blocksLogin: true, value: validExpiry},
	"from":                {takesValue: true, effect: restricts, blocksLogin: true},
	"no-agent-forwarding": {effect: restricts},
	"no-port-forwarding":  {effect: restricts},
	"no-pty":              {effect: restricts},
	"no-touch-required":   {effect: loosens}, // sk keys: no user-presence touch: a relaxation
	"no-user-rc":          {effect: restricts},
	"no-x11-forwarding":   {effect: restricts},
	"permitlisten":        {takesValue: true, effect: restricts},
	"permitopen":          {takesValue: true, effect: restricts},
	"port-forwarding":     {effect: loosens, underRestrict: true},
	"principals":          {takesValue: true, effect: restricts, certOnly: true},
	"pty":                 {effect: loosens, underRestrict: true},
	"restrict":            {effect: restricts, blocksLogin: true},
	"tunnel":              {takesValue: true},
	"user-rc":             {effect: loosens, underRestrict: true},
	"verify-required":     {effect: restricts}, // sk keys: PIN/biometric required
	"x11-forwarding":      {effect: loosens, underRestrict: true},
}

func lookup(opt string) (optionSpec, bool) {
	name, _, _ := strings.Cut(opt, "=")
	s, ok := options[strings.ToLower(name)]
	return s, ok
}

// CheckOption reports why one key option would make sshd reject the line;
// "" means acceptable. Unsafe runes are rejected first: option values are
// rendered verbatim into files and plan output.
func CheckOption(opt string) string {
	if strings.ContainsFunc(opt, IsUnsafeRune) {
		return "contains control or format characters"
	}
	_, value, hasValue := strings.Cut(opt, "=")
	s, known := lookup(opt)
	switch {
	case !known:
		return "is not a recognized authorized_keys option"
	case s.takesValue && (!hasValue || len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"'):
		return `requires a quoted value (name="...")`
	case !s.takesValue && hasValue:
		return "does not take a value"
	case s.value != nil && s.value(value[1:len(value)-1]) != nil:
		return "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])" // only expiry-time has a validator today
	}
	return ""
}

// OptionIssue returns the first option sshd would reject, as
// `option "<opt>" <issue>`; nil when every option is acceptable.
func OptionIssue(opts []string) error {
	for _, o := range opts {
		if issue := CheckOption(o); issue != "" {
			return fmt.Errorf("option %q %s", o, issue)
		}
	}
	return nil
}

// Loosening reports how rewriting a line from actual to desired options
// widens access. dropped: restrictive options actual carries that desired
// does not carry verbatim (a changed from= value counts). added: widening
// options desired adds; a re-enabler counts only when both lines carry
// restrict (otherwise it is a no-op, or dropping restrict is reported).
func Loosening(actual, desired []string) (dropped, added []string) {
	for _, o := range actual {
		if s, ok := lookup(o); ok && s.effect == restricts && !slices.Contains(desired, o) {
			dropped = append(dropped, o)
		}
	}
	restrictBoth := hasName(actual, "restrict") && hasName(desired, "restrict")
	for _, o := range desired {
		s, ok := lookup(o)
		if !ok || s.effect != loosens || slices.Contains(actual, o) || (s.underRestrict && !restrictBoth) {
			continue
		}
		added = append(added, o)
	}
	return dropped, added
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

var errExpiry = errors.New("want YYYYMMDD[HHMM[SS]][Z]")

// ExpiryTime parses an expiry-time="…" option: sshd's YYYYMMDD[HHMM[SS]],
// in local unless suffixed Z (or z, as today's keyarg accepts) for UTC.
func ExpiryTime(opt string, local *time.Location) (time.Time, error) {
	_, v, _ := strings.Cut(opt, "=")
	return parseExpiry(strings.Trim(v, `"`), local)
}

func validExpiry(v string) error { _, err := parseExpiry(v, time.UTC); return err }

func parseExpiry(v string, loc *time.Location) (time.Time, error) {
	if strings.HasSuffix(v, "Z") || strings.HasSuffix(v, "z") {
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
