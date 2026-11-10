package authkeys

import (
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// quoteIssue is CheckOption's reason for an option that is more than one
// clause.
const quoteIssue = `has an unescaped '"' inside its quoted value; sshd ends the value there (write \" for a literal quote)`

func TestCheckOption(t *testing.T) {
	tests := []struct{ opt, want string }{
		{"no-pty", ""},
		{"No-PTY", ""}, // sshd matches names case-insensitively
		{`from="10.0.0.0/8,!10.0.0.1"`, ""},
		{"verify-required", ""},
		{"no-touch-required", ""},
		{"zzz", "is not a recognized authorized_keys option"},
		{"no-ptty", "is not a recognized authorized_keys option"}, // typo
		{"from=1.2.3.4", `requires a quoted value (name="...")`},
		{`no-pty="x"`, "does not take a value"},
		{"no-pty\x1b[31m", "contains control or format characters"},
		{`expiry-time="20270101"`, ""},
		{`expiry-time="202701011200Z"`, ""},
		// OpenSSH's parse_absolute_time accepts a "Z" or "UTC" suffix,
		// case-insensitively; sshd honors all of these lines.
		{`expiry-time="202701011200z"`, ""},
		{`expiry-time="20270101UTC"`, ""},
		{`expiry-time="20270101utc"`, ""},
		{`expiry-time="20270101120000UTC"`, ""},
		{`expiry-time="20270101XUTC"`, "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])"},
		{`expiry-time="UTC"`, "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])"},
		{`expiry-time="2027"`, "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])"},
		{`expiry-time="2027xx01"`, "has an invalid value (want YYYYMMDD[HHMM[SS]][Z])"},
		// One option is one clause: sshd's opt_dequote ends a value at its
		// first unescaped '"', so anything after it is another clause or,
		// past a space, the key itself. A raw grant option (spec S7) is the
		// first string that reaches here without the line parser's split.
		{`command="\"x\""`, ""},
		{`command="a\\b"`, ""},
		{`command="a,b c"`, ""},
		{`from="10.0.0.0/8",pty,port-forwarding,command="x"`, quoteIssue},
		{`from="10.0.0.0/8",cert-authority,principals="root"`, quoteIssue},
		{`from="10.0.0.0/8" ssh-ed25519 AAAA "`, quoteIssue},
		{`from="10.0.0.0/8" x="y"`, quoteIssue},
		{`from="a""b"`, quoteIssue},
		{`from="a\"`, `requires a quoted value (name="...")`},  // the last quote is escaped: no end quote
		{`from="a\\"`, `requires a quoted value (name="...")`}, // \ then \" (sshd's rule): no end quote
		{`from="`, `requires a quoted value (name="...")`},
	}
	for _, tt := range tests {
		if got := CheckOption(tt.opt); got != tt.want {
			t.Errorf("CheckOption(%q) = %q, want %q", tt.opt, got, tt.want)
		}
	}
}

func TestOptionIssue(t *testing.T) {
	if err := OptionIssue([]string{"restrict", `command="/bin/true"`}); err != nil {
		t.Errorf("clean options: err = %v", err)
	}
	err := OptionIssue([]string{"no-pty", "zzz", "no-ptty"})
	if err == nil || err.Error() != `option "zzz" is not a recognized authorized_keys option` {
		t.Errorf("err = %v, want the first bad option named", err)
	}
	// %q keeps remote control bytes out of the message.
	if err := OptionIssue([]string{"a\x1bb"}); err == nil || strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("err = %q, want an escaped option", err)
	}
}

// sshd (auth-options.c) rejects a line with a second command=, from= or
// principals= clause; repeated permitopen=/permitlisten=/environment= and
// expiry-time= are accepted (union, first-wins, earliest).
func TestOptionIssueRepeatedClause(t *testing.T) {
	for _, opts := range [][]string{
		{`command="echo A"`, `command="echo B"`},
		{`from="0.0.0.0/0"`, `from="0.0.0.0/0"`},
		{`principals="a"`, "cert-authority", `principals="b"`},
		{`command="a"`, `COMMAND="b"`},
	} {
		for name, check := range map[string]func([]string) error{"OptionIssue": OptionIssue, "IgnoredBySSHD": IgnoredBySSHD} {
			err := check(opts)
			if err == nil || !strings.Contains(err.Error(), "which sshd allows once per line") {
				t.Errorf("%s(%q) = %v, want a repeated-clause error", name, opts, err)
			}
		}
	}
	for _, opts := range [][]string{
		{`permitopen="a:1"`, `permitopen="b:2"`},
		{`permitlisten="1"`, `permitlisten="2"`},
		{`environment="A=1"`, `environment="B=2"`},
		{`expiry-time="20270101"`, `expiry-time="20280101"`},
	} {
		if err := OptionIssue(opts); err != nil {
			t.Errorf("OptionIssue(%q) = %v, want nil", opts, err)
		}
	}
}

// IgnoredBySSHD is sshd's view only: a quoted value may carry any byte
// (opt_dequote copies it), so control runes do not make sshd skip the line,
// though the manifest (OptionIssue) still refuses to store them.
func TestIgnoredBySSHD(t *testing.T) {
	tab := []string{"command=\"echo\ta\""}
	if err := IgnoredBySSHD(tab); err != nil {
		t.Errorf("IgnoredBySSHD(%q) = %v, want nil", tab, err)
	}
	if err := OptionIssue(tab); err == nil || !strings.Contains(err.Error(), "control or format characters") {
		t.Errorf("OptionIssue(%q) = %v, want the control-character refusal", tab, err)
	}
	for _, opts := range [][]string{{"zzz"}, {"no-ptty"}, {"from=1.2.3.4"}, {`no-pty="x"`}, {`expiry-time="2027"`}, {"no-pty\x1b"}, {`from="a"b"c"`}} {
		if err := IgnoredBySSHD(opts); err == nil {
			t.Errorf("IgnoredBySSHD(%q) = nil, want an error", opts)
		}
	}
	if err := IgnoredBySSHD([]string{"restrict", `from="10.0.0.1"`}); err != nil {
		t.Errorf("clean options: err = %v", err)
	}
}

func TestIsOptionName(t *testing.T) {
	for _, n := range []string{"restrict", "No-PTY", "from", "verify-required", "X11-Forwarding"} {
		if !IsOptionName(n) {
			t.Errorf("IsOptionName(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"", "no-ptty", "zzz", "from=x", "alice"} {
		if IsOptionName(n) {
			t.Errorf("IsOptionName(%q) = true, want false", n)
		}
	}
}

func TestLoosening(t *testing.T) {
	tests := []struct {
		name                    string
		actual, desired         []string
		wantDropped, wantWidens []string
	}{
		{"none on server", nil, []string{"no-pty"}, nil, nil},
		{"all dropped", []string{`from="10.0.0.5"`, `command="/x"`, "no-pty", "tty"}, nil,
			[]string{`from="10.0.0.5"`, `command="/x"`, "no-pty", "tty"}, nil}, // "tty" is unknown: sshd ignores the line
		{"kept verbatim", []string{"restrict", `expiry-time="20270101"`}, []string{"restrict", `expiry-time="20270101"`}, nil, nil},
		{"changed value counts", []string{`from="10.0.0.5"`}, []string{`from="0.0.0.0/0"`}, []string{`from="10.0.0.5"`}, nil},
		{"forwarding and ca", []string{`permitopen="h:1"`, `permitlisten="2"`, "cert-authority", `principals="a"`}, nil,
			[]string{`permitopen="h:1"`, `permitlisten="2"`, "cert-authority", `principals="a"`}, nil},
		// COR-4
		{"verify-required dropped loosens", []string{"verify-required"}, nil, []string{"verify-required"}, nil},
		{"no-touch-required dropped tightens", []string{"no-touch-required"}, nil, nil, nil},
		{"no-touch-required added loosens", nil, []string{"no-touch-required"}, nil, []string{"no-touch-required"}},
		{"re-enabler added under restrict", []string{"restrict"}, []string{"restrict", "port-forwarding"}, nil, []string{"port-forwarding"}},
		{"re-enabler without restrict is a no-op", nil, []string{"pty"}, nil, nil},
		{"restrict newly added with pty", nil, []string{"restrict", "pty"}, nil, nil},
		{"restrict dropped", []string{"restrict", "pty"}, []string{"pty"}, []string{"restrict"}, nil},
		// A server option sshd rejects makes the whole line dead: rewriting it
		// into a live line grants access the key does not have today.
		{"unknown server option dropped", []string{"no-ptty"}, nil, []string{"no-ptty"}, nil},
		{"unknown server option dropped beside kept ones", []string{"no-pty", "zzz"}, []string{"no-pty"}, []string{"zzz"}, nil},
		{"repeated command clause dropped", []string{`command="a"`, `command="a"`}, []string{`command="a"`}, []string{`command="a"`}, nil},
		// permitopen=/permitlisten= entries are a union: one more widens,
		// one fewer (others kept) narrows, the first one narrows.
		{"added permitopen widens", []string{`permitopen="db:5432"`}, []string{`permitopen="db:5432"`, `permitopen="*:*"`}, nil, []string{`permitopen="*:*"`}},
		{"added permitlisten widens", []string{`permitlisten="localhost:8080"`}, []string{`permitlisten="localhost:8080"`, `permitlisten="0.0.0.0:22"`}, nil, []string{`permitlisten="0.0.0.0:22"`}},
		{"changed permitopen widens", []string{`permitopen="a:1"`}, []string{`PermitOpen="b:2"`}, nil, []string{`PermitOpen="b:2"`}},
		{"first permitopen narrows", nil, []string{`permitopen="a:1"`}, nil, nil},
		{"one of several permitopen dropped narrows", []string{`permitopen="a:1"`, `permitopen="b:2"`}, []string{`permitopen="a:1"`}, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, w := Loosening(tt.actual, tt.desired)
			if strings.Join(d, "|") != strings.Join(tt.wantDropped, "|") || strings.Join(w, "|") != strings.Join(tt.wantWidens, "|") {
				t.Errorf("Loosening = (%q, %q), want (%q, %q)", d, w, tt.wantDropped, tt.wantWidens)
			}
		})
	}
}

func TestBlocksLoginAndCertOnly(t *testing.T) {
	for _, o := range []string{"restrict", `from="1.2.3.4"`, `command="/bin/true"`, `expiry-time="20270101"`, `FROM="10.0.0.1"`} {
		if !BlocksLogin([]string{o}) {
			t.Errorf("BlocksLogin(%q) = false, want true", o)
		}
	}
	for _, o := range []string{"no-pty", "no-agent-forwarding", "verify-required", "no-ptty"} {
		if BlocksLogin([]string{o}) {
			t.Errorf("BlocksLogin(%q) = true, want false", o)
		}
	}
	if !CertOnly([]string{"cert-authority"}) || !CertOnly([]string{`Principals="a"`}) || CertOnly([]string{"restrict"}) {
		t.Error("CertOnly: want true for cert-authority/principals= only")
	}
}

func TestExpiryTime(t *testing.T) {
	got, err := ExpiryTime(`expiry-time="202701021504Z"`, time.Local)
	if err != nil || !got.Equal(time.Date(2027, 1, 2, 15, 4, 0, 0, time.UTC)) {
		t.Errorf("ExpiryTime = %v, %v", got, err)
	}
	for _, v := range []string{`expiry-time="202701021504UTC"`, `expiry-time="202701021504utc"`, `expiry-time="202701021504z"`} {
		got, err := ExpiryTime(v, time.Local)
		if err != nil || !got.Equal(time.Date(2027, 1, 2, 15, 4, 0, 0, time.UTC)) {
			t.Errorf("ExpiryTime(%s) = %v, %v, want 2027-01-02 15:04 UTC", v, got, err)
		}
	}
	if opt, ok := FindOption([]string{"no-pty", `Expiry-Time="20270101"`}, "expiry-time"); !ok || opt != `Expiry-Time="20270101"` {
		t.Errorf("FindOption = %q, %v, want the option verbatim", opt, ok)
	}
}

func FuzzCheckOption(f *testing.F) {
	key := testkeys.Line(f, 1)
	for _, s := range []string{"no-pty", `from="x"`, "zzz", `expiry-time="2027"`, "a=b=c", `command="\"x\""`,
		`from="x",pty`, `from="x" ` + testkeys.Line(f, 2) + ` "`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, opt string) {
		if CheckOption(opt) == "" {
			name, _, _ := strings.Cut(opt, "=")
			if _, ok := options[strings.ToLower(name)]; !ok {
				t.Errorf("accepted unknown option %q", opt)
			}
			// An accepted option is exactly one clause: written in front of
			// a key, it parses back as itself and nothing else, and the key
			// stays the same (spec S7: a raw grant option reaches the file
			// verbatim).
			k, err := ParseLine(opt + " " + key)
			if err != nil || len(k.Options) != 1 || k.Options[0] != opt || k.Raw != opt+" "+key {
				t.Errorf("accepted option %q does not render as one clause: %+v, %v", opt, k, err)
			}
		}
		d, w := Loosening([]string{opt}, []string{opt})
		if len(d) != 0 || len(w) != 0 {
			t.Errorf("identical lines reported loosening for %q", opt)
		}
	})
}
