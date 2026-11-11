package audit

import (
	"bytes"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRevokedKeyInAnSSHDOnlyLineIsCritical (review F002): a revoked key
// re-planted in a line sshd honors but Go's decoder refused (a NUL after the
// blob, VT, FF or CR inside it) logs in, so audit must name it REVOKED
// (critical, exit 2), not report an unparseable entry (exit 1).
func TestRevokedKeyInAnSSHDOnlyLineIsCritical(t *testing.T) {
	carol := testkeys.Line(t, 9)
	typ, blob := strings.Fields(carol)[0], strings.Fields(carol)[1]
	for name, line := range map[string]string{
		"plain": carol + " carol",
		"NUL":   typ + " " + blob + "\x00junk carol",
		"VT":    typ + " " + blob[:30] + "\v" + blob[30:] + " carol",
		"FF":    typ + " " + blob[:30] + "\f" + blob[30:] + " carol",
		"CR":    typ + " " + blob[:30] + "\r" + blob[30:] + " carol",
	} {
		t.Run(name, func(t *testing.T) {
			cfg := memoryConfig(t, "")
			web1 := authkeys.Header(7) + "\n" + testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n" +
				testkeys.Line(t, 3) + "\n" + line + "\n"
			r := &fakeReader{byName: map[string]fleet.ReadResult{
				"web-1": {Content: []byte(web1)},
				"web-2": {Content: []byte(authkeys.Header(7) + "\n" + testkeys.Line(t, 1) + "\n" + testkeys.Line(t, 2) + "\n")},
			}}
			res := memoryRun(t, cfg, r)
			if len(res[0].ParseErrs) != 0 {
				t.Errorf("ParseErrs = %v, want none (sshd honors the line)", res[0].ParseErrs)
			}
			if code := ExitCode(cfg, res); code != 2 {
				t.Errorf("ExitCode = %d, want 2", code)
			}
			var buf bytes.Buffer
			Render(&buf, cfg, res, RenderOptions{})
			if !strings.Contains(buf.String(), "installed but REVOKED") {
				t.Errorf("report lacks the REVOKED row:\n%s", buf.String())
			}
		})
	}
}

// TestOperatorLineWithABadValueCannotLogIn (review F003, F025): sshd skips
// a line whose option value it rejects, so an operator key held only there
// cannot log in (critical); touch-required and no-verify-required are
// options sshd accepts, so such a line logs in (drift only: options differ).
func TestOperatorLineWithABadValueCannotLogIn(t *testing.T) {
	op, alice := testkeys.Line(t, 1), testkeys.Line(t, 2)
	for _, tt := range []struct {
		opt    string
		reason string
		status serverStatus
	}{
		{`permitopen="db"`, "ignored", statusCritical},
		{`permitlisten="nope"`, "ignored", statusCritical},
		{`environment="FOO"`, "ignored", statusCritical},
		{`tunnel="abc"`, "ignored", statusCritical},
		{`permitopen="db:22"`, "", statusDrift},
		{"touch-required", "", statusDrift},
		{"no-verify-required", "", statusDrift},
	} {
		t.Run(tt.opt, func(t *testing.T) {
			cfg := trustConfig(t, op, "")
			r := runOne(t, cfg, fleet.ReadResult{Content: content(tt.opt+" "+op, alice)})
			if got := reasonOf(t, cfg, r); got != tt.reason {
				t.Errorf("cannotLogIn = %q, want %q", got, tt.reason)
			}
			if got := statusOf(cfg, r); got != tt.status {
				t.Errorf("status = %s, want %s", got, tt.status)
			}
		})
	}
}

// TestServerHeadNeverPrintsRawBytes (review F008): the head prints only
// text it checked; a field with control runes or invalid UTF-8 (a
// hand-built Server; config refuses both at load) loses those bytes.
func TestServerHeadNeverPrintsRawBytes(t *testing.T) {
	got := ServerHead(config.Server{Name: "web\x9b2J", User: "de\u202eploy", Host: "10.0.0.1\x1b[31m\xff", Port: 22, Via: "b\x9b"})
	if !utf8.ValidString(got) || strings.ContainsAny(got, "\x1b\u202e") {
		t.Errorf("ServerHead = %q, carries raw bytes", got)
	}
	if want := "web\ufffd2J (deploy@10.0.0.1[31m\ufffd:22 via b\ufffd)"; got != want {
		t.Errorf("ServerHead = %q, want %q", got, want)
	}
}
