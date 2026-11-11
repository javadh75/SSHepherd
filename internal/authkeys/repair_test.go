package authkeys

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestClauseLimits: sshd skips a line past its per-line clause limits
// (measured against OpenSSH 10.5p1: 1025 distinct environment= names, a
// repeated name not counted; 4097 clauses of each of permitopen= and
// permitlisten=, repeats counted), so the manifest refuses it and audit
// reports it.
func TestClauseLimits(t *testing.T) {
	n := func(count int, f func(i int) string) []string {
		out := make([]string, count)
		for i := range out {
			out[i] = f(i)
		}
		return out
	}
	env := func(i int) string { return fmt.Sprintf(`environment="V%d=1"`, i) }
	open := func(int) string { return `permitopen="h:22"` }
	for _, tt := range []struct {
		name string
		opts []string
		want string // "" = accepted
	}{
		{"1025 environment names", n(1025, env), ""},
		{"1026 environment names", n(1026, env), `option "environment=\"V1025=1\"" goes past sshd's limit of 1025 environment= names per line`},
		{"a repeated name is not counted", n(2000, func(i int) string { return fmt.Sprintf(`environment="V=%d"`, i) }), ""},
		{"4097 permitopen", n(4097, open), ""},
		{"4098 permitopen", n(4098, open), `option "permitopen=\"h:22\"" goes past sshd's limit of 4097 permitopen= clauses per line`},
		{"4098 permitlisten", n(4098, func(i int) string { return fmt.Sprintf(`permitlisten="%d"`, 1000+i) }), `option "permitlisten=\"5097\"" goes past sshd's limit of 4097 permitlisten= clauses per line`},
		{"the kinds count apart", slices.Concat(n(3000, open), n(3000, func(int) string { return `permitlisten="80"` })), ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for name, err := range map[string]error{"IgnoredBySSHD": IgnoredBySSHD(tt.opts), "OptionIssue": OptionIssue(tt.opts)} {
				switch {
				case tt.want == "" && err != nil:
					t.Errorf("%s = %v, want nil", name, err)
				case tt.want != "" && (err == nil || err.Error() != tt.want):
					t.Errorf("%s = %v, want %q", name, err, tt.want)
				}
			}
		})
	}
}

// TestNoVerifyRequiredIsNeutral (F025): no-verify-required only lifts a
// requirement verify-required adds; on its own it neither restricts nor
// loosens, so adding or dropping it is never flagged.
func TestNoVerifyRequiredIsNeutral(t *testing.T) {
	if IsRestriction("no-verify-required") {
		t.Error("no-verify-required counted as a restriction")
	}
	for _, c := range []struct{ actual, desired []string }{
		{nil, []string{"no-verify-required"}},
		{[]string{"no-verify-required"}, nil},
		{[]string{"restrict"}, []string{"restrict", "no-verify-required"}},
	} {
		if dropped, added := Loosening(c.actual, c.desired); len(dropped) != 0 || len(added) != 0 {
			t.Errorf("Loosening(%q, %q) = (%q, %q), want nothing", c.actual, c.desired, dropped, added)
		}
	}
}

// TestIsOptionNameIsASCIIOnly: sshd's strcasecmp is ASCII-only, so U+0130
// (which Go lower-cases to i) does not make "restrİct" an option name.
func TestIsOptionNameIsASCIIOnly(t *testing.T) {
	if !IsOptionName("RESTRICT") {
		t.Error(`IsOptionName("RESTRICT") = false`)
	}
	if IsOptionName("restrİct") {
		t.Error(`IsOptionName("restrİct") = true, want false`)
	}
}

// TestLineTextIssueKeepsTabs: a tab is sshd's field separator, so a key
// line written with tabs is fit for the manifest; other control runes are
// not.
func TestLineTextIssueKeepsTabs(t *testing.T) {
	typ, blob, _ := strings.Cut(testkeys.Line(t, 9), " ")
	if issue := LineTextIssue(typ + "\t" + blob + "\talice"); issue != "" {
		t.Errorf("LineTextIssue(tab-separated line) = %q, want fit", issue)
	}
	if issue := LineTextIssue(typ + "\v" + blob); issue == "" {
		t.Error("LineTextIssue(a VT in the line) is fit, want refused")
	}
}

// TestParseLineTrimsTheComment: what follows the key field is the comment
// with its edge whitespace gone.
func TestParseLineTrimsTheComment(t *testing.T) {
	k := mustKey(t, testkeys.Line(t, 9)+"  alice laptop \t\v")
	if k.Comment != "alice laptop" {
		t.Errorf("Comment = %q, want %q", k.Comment, "alice laptop")
	}
}

// TestRawKeepsLeadingBytesSSHDDoesNotSkip: sshd skips only spaces and tabs
// before the first field, so a line starting with VT, FF or CR is one sshd
// ignores. Raw keeps those bytes, so rendering it again (a kept preserve:
// line) cannot turn that dead line into a live one.
func TestRawKeepsLeadingBytesSSHDDoesNotSkip(t *testing.T) {
	line := testkeys.Line(t, 9)
	for _, lead := range []string{"\v", "\f", "\r"} {
		raw := lead + "no-pty " + line + " gitea-x"
		k, err := ParseLine(" \t" + raw + " \t")
		if err != nil || k == nil {
			t.Fatalf("ParseLine(%q) = (%v, %v)", raw, k, err)
		}
		if IgnoredBySSHD(k.Options) == nil {
			t.Fatalf("%q: sshd ignores this line, IgnoredBySSHD says it honors it", raw)
		}
		if k.Raw != raw {
			t.Errorf("Raw = %q, want %q (only spaces and tabs trimmed at the start)", k.Raw, raw)
		}
		again, err := ParseLine(k.Raw)
		if err != nil || again == nil || IgnoredBySSHD(again.Options) == nil {
			t.Errorf("Raw re-read as a line sshd honors: %+v, %v", again, err)
		}
	}
}

// TestRenderLineRefusesANonKeyRaw: a Key whose Raw is blank or a comment
// was not produced by ParseLine; rendering it is an error, not a panic.
func TestRenderLineRefusesANonKeyRaw(t *testing.T) {
	for _, raw := range []string{"", "   ", "# a comment"} {
		_, err := RenderLine(RenderEntry{Key: Key{Raw: raw, Fingerprint: "SHA256:x"}})
		if !errors.Is(err, errNoKey) {
			t.Errorf("RenderLine(Raw %q) = %v, want errNoKey", raw, err)
		}
	}
}

// TestEscapedQuoteThenComma (F002): a \" inside a quoted value does not end
// it, so the comma after the closing quote splits the next option off.
func TestEscapedQuoteThenComma(t *testing.T) {
	k := mustKey(t, `command="a \" b",no-pty `+testkeys.Line(t, 9))
	want := []string{`command="a \" b"`, "no-pty"}
	if !slices.Equal(k.Options, want) {
		t.Errorf("Options = %q, want %q", k.Options, want)
	}
	if err := IgnoredBySSHD(k.Options); err != nil {
		t.Errorf("IgnoredBySSHD = %v, want nil", err)
	}
}
