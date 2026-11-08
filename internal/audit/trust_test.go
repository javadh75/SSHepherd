package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// trustConfig: op (k1) is an operator, alice (k2) is granted web-1; extra
// is appended to the manifest.
func trustConfig(t *testing.T, opLine, extra string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, comment: "op@sshepherd", keys: ["` + opLine + `"]}
  - {name: alice, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: alice, servers: [web-1]}
` + extra))
	if err != nil {
		t.Fatalf("trustConfig: %v", err)
	}
	return cfg
}

func pinNow(t *testing.T) {
	t.Helper()
	orig := now
	now = func() time.Time { return time.Date(2026, 6, 15, 12, 0, 0, 0, time.Local) }
	t.Cleanup(func() { now = orig })
}

func runOne(t *testing.T, cfg *config.Config, read fleet.ReadResult) ServerResult {
	t.Helper()
	r := &fakeReader{byName: map[string]fleet.ReadResult{"web-1": read}}
	return Run(context.Background(), cfg, r, Options{Parallel: 1})[0]
}

// content builds an authorized_keys body, one line per argument.
func content(lines ...string) []byte {
	return []byte(strings.Join(lines, "\n") + "\n")
}

func reasonOf(t *testing.T, cfg *config.Config, r ServerResult) string {
	t.Helper()
	for _, k := range r.Diff.OK {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			reason, _ := r.cannotLogIn(cfg, k)
			return reason
		}
	}
	t.Fatal("no present operator key")
	return ""
}

func TestCriticalOperatorCannotLogIn(t *testing.T) {
	pinNow(t)
	op, alice := testkeys.Line(t, 1), testkeys.Line(t, 2)
	expired := `expiry-time="20260101" ` + op
	tests := []struct {
		name     string
		manifest string // the operator's manifest line; "" = op
		lines    []string
		reason   string
		status   serverStatus
	}{
		{name: "plain", lines: []string{op, alice}, status: statusCompliant},
		{name: "TestCriticalOperatorCertOnly: cert-authority on the server", lines: []string{"cert-authority " + op, alice}, reason: "cert_only", status: statusCritical},
		{name: "TestCriticalOperatorCertOnly: principals= on the server", lines: []string{`principals="ops" ` + op, alice}, reason: "cert_only", status: statusCritical},
		{name: "declared cert-authority is not cert_only", manifest: "cert-authority " + op, lines: []string{"cert-authority " + op, alice}, status: statusCompliant},
		{name: "TestCriticalOperatorExpired: undeclared passed expiry", lines: []string{expired, alice}, reason: "expired", status: statusCritical},
		{name: "TestCriticalOperatorExpired: declared passed expiry is critical too", manifest: expired, lines: []string{expired, alice}, reason: "expired", status: statusCritical},
		{name: "future expiry", lines: []string{`expiry-time="20990101" ` + op, alice}, status: statusDrift},
		{name: "TestOperatorEveryLineIgnored: bad option", lines: []string{"bogus-option " + op, alice}, reason: "ignored", status: statusCritical},
		{name: "malformed expiry is a line sshd ignores", lines: []string{`expiry-time="2027" ` + op, alice}, reason: "ignored", status: statusCritical},
		{name: "TestOperatorLaterLineLogsIn: dead first, working second", lines: []string{"cert-authority " + op, op, alice}, status: statusDrift},
		{name: "TestOperatorIgnoredThenDeadLine: ignored first, dead second", lines: []string{"bogus-option " + op, "cert-authority " + op, alice}, reason: "cert_only", status: statusCritical},
		{name: "added from= still logs in (drift, not critical)", lines: []string{`from="10.0.0.1" ` + op, alice}, status: statusDrift},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifest := tt.manifest
			if manifest == "" {
				manifest = op
			}
			cfg := trustConfig(t, strings.ReplaceAll(manifest, `"`, `\"`), "")
			r := runOne(t, cfg, fleet.ReadResult{Content: content(tt.lines...)})
			if got := reasonOf(t, cfg, r); got != tt.reason {
				t.Errorf("cannotLogIn = %q, want %q", got, tt.reason)
			}
			if got := statusOf(cfg, r); got != tt.status {
				t.Errorf("status = %s, want %s", got, tt.status)
			}
		})
	}
}

// TestNonOperatorDeadLineIsDrift: only operator keys are graded critical.
func TestNonOperatorDeadLineIsDrift(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), "cert-authority "+testkeys.Line(t, 2))})
	if got := statusOf(cfg, r); got != statusDrift {
		t.Errorf("status = %s, want drift", got)
	}
}

func TestPostureGrading(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	clean := content(testkeys.Line(t, 1), testkeys.Line(t, 2))
	tests := []struct {
		name  string
		issue string
		want  serverStatus
		code  int
	}{
		{"world_writable is critical", fleet.PostureWorldWritable, statusCritical, 2},
		{"group_writable is drift", fleet.PostureGroupWritable, statusDrift, 1},
		{"foreign_owner is drift", fleet.PostureForeignOwner, statusDrift, 1},
		{"symlink is drift", fleet.PostureSymlink, statusDrift, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := runOne(t, cfg, fleet.ReadResult{Content: clean, Posture: []fleet.PostureIssue{{Path: "/home/d/.ssh", Issue: tt.issue, Mode: "drwxrwxrwx", UID: "1001"}}})
			if r.Compliant() {
				t.Error("a posture finding must not be compliant, even with matching keys")
			}
			if got := statusOf(cfg, r); got != tt.want {
				t.Errorf("status = %s, want %s", got, tt.want)
			}
			if got := ExitCode(cfg, []ServerResult{r}); got != tt.code {
				t.Errorf("ExitCode = %d, want %d", got, tt.code)
			}
		})
	}
}

func TestHostKeyTypeChangedIsAnAlert(t *testing.T) {
	cfg := reportConfig(t)
	r := &fakeReader{errs: map[string]error{
		"web-1": hintedErr{kindedErr{fleet.ErrorKindHostKeyTypeChanged, "ssh deploy@10.0.0.1:22: presented ecdsa-sha2-nistp256 key SHA256:abc: knownhosts: key mismatch"},
			"HOST KEY TYPE CHANGED for 10.0.0.1:22 — the server no longer presents any recorded key type (recorded: ssh-ed25519); possible impersonation"},
	}, byName: map[string]fleet.ReadResult{"web-2": {Content: content(testkeys.Line(t, 1))}}}
	results := Run(context.Background(), cfg, r, Options{Parallel: 2})
	if got := ExitCode(cfg, results); got != 2 {
		t.Errorf("ExitCode = %d, want 2", got)
	}
	if c := tallyResults(cfg, results); c.hostKeyAlerts != 1 {
		t.Errorf("hostKeyAlerts = %d, want 1", c.hostKeyAlerts)
	}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_host_key_type_changed.golden", buf.Bytes())
	checkGolden(t, "report_host_key_type_changed.golden.json", renderJSON(t, cfg, results))
}

func postureResults(t *testing.T, cfg *config.Config) []ServerResult {
	t.Helper()
	return []ServerResult{runOne(t, cfg, fleet.ReadResult{
		Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2)),
		Posture: []fleet.PostureIssue{
			{Path: "/home/deploy/.ssh", Issue: fleet.PostureWorldWritable, Mode: "drwxrwxrwx", UID: "1001"},
			{Path: "/home/deploy/.ssh/authorized_keys", Issue: fleet.PostureGroupWritable, Mode: "-rw-rw-r--", UID: "1001"},
			{Path: "/srv/keys", Issue: fleet.PostureForeignOwner, Mode: "drwxr-xr-x", UID: "1002"},
			{Path: "/home/deploy/.ssh/authorized_keys2", Issue: fleet.PostureSymlink, Mode: "lrwxrwxrwx", UID: "1001"},
		},
	})}
}

func TestReportPostureGolden(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	results := postureResults(t, cfg)
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_posture.golden", buf.Bytes())
	checkGolden(t, "report_posture.golden.json", renderJSON(t, cfg, results))
}

func TestReportOperatorCertOnlyGolden(t *testing.T) {
	pinNow(t)
	op := testkeys.Line(t, 1)
	cfg := trustConfig(t, op, "")
	var buf bytes.Buffer
	results := []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content(`expiry-time="20260101" `+op, testkeys.Line(t, 2))})}
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_operator_expired.golden", buf.Bytes())
	buf.Reset()
	results = []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content("cert-authority "+op, testkeys.Line(t, 2))})}
	Render(&buf, cfg, results, RenderOptions{})
	checkGolden(t, "report_operator_certonly.golden", buf.Bytes())
	checkGolden(t, "report_operator_certonly.golden.json", renderJSON(t, cfg, results))
}

func TestReportKeyIssuesGolden(t *testing.T) {
	pinNow(t)
	op := `expiry-time=\"20260101\" ` + testkeys.Line(t, 1)
	cfg := trustConfig(t, op, "  - {user: op, servers: [web-1]}\n")
	dsa := testkeys.DSALine(t, 7)
	results := []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content(
		`expiry-time="20260101" `+testkeys.Line(t, 1), testkeys.Line(t, 2), dsa, testkeys.RSALine(t, 8, 1024),
	)})}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	for _, want := range []string{" · WEAK (dsa)", " · WEAK (rsa 1024)", "CANNOT LOG IN"} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "report_key_issues.golden", buf.Bytes())
	checkGolden(t, "report_key_issues.golden.json", renderJSON(t, cfg, results))
}

func TestPresentExpiredAndWeakAnnotations(t *testing.T) {
	pinNow(t)
	dsa := testkeys.DSALine(t, 7)
	line := `expiry-time=\"20260101\" ` + dsa // a non-operator: annotations only
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: old, keys: ["` + line + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: old, servers: [web-1]}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), `expiry-time="20260101" `+dsa)})
	var buf bytes.Buffer
	Render(&buf, cfg, []ServerResult{r}, RenderOptions{})
	if !strings.Contains(buf.String(), " · WEAK (dsa) · EXPIRED") {
		t.Errorf("report lacks the annotations:\n%s", buf.String())
	}
}

// TestAnnotationsDoNotChangeExit (spec B1): EXPIRED and WEAK are
// informational. A non-operator's passed expiry on an otherwise compliant
// server exits 0, and an ungranted DSA key exits 1 as ordinary drift.
func TestAnnotationsDoNotChangeExit(t *testing.T) {
	pinNow(t)
	t.Run("non-operator with a passed desired expiry", func(t *testing.T) {
		line := testkeys.Line(t, 3)
		cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: old, keys: ["expiry-time=\"20260101\" ` + line + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: old, servers: [web-1]}
`))
		if err != nil {
			t.Fatal(err)
		}
		r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), `expiry-time="20260101" `+line)})
		var buf bytes.Buffer
		Render(&buf, cfg, []ServerResult{r}, RenderOptions{})
		if !strings.Contains(buf.String(), " · EXPIRED") {
			t.Errorf("report lacks the annotation:\n%s", buf.String())
		}
		if got := ExitCode(cfg, []ServerResult{r}); got != 0 {
			t.Errorf("ExitCode = %d, want 0", got)
		}
		if got := criticalReasons(cfg, r); got != nil {
			t.Errorf("critical reasons = %v, want none", got)
		}
	})
	t.Run("an ungranted DSA key on the server", func(t *testing.T) {
		cfg := trustConfig(t, testkeys.Line(t, 1), "")
		r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2), testkeys.DSALine(t, 7))})
		var buf bytes.Buffer
		Render(&buf, cfg, []ServerResult{r}, RenderOptions{})
		if !strings.Contains(buf.String(), "UNAUTHORIZED · WEAK (dsa)") {
			t.Errorf("report lacks the annotation:\n%s", buf.String())
		}
		if got := ExitCode(cfg, []ServerResult{r}); got != 1 {
			t.Errorf("ExitCode = %d, want 1", got)
		}
	})
}

// TestGrantedWeakKeyJSON (D29): the conflict's kind, the summary count and
// the critical reason, on the wire.
func TestGrantedWeakKeyJSON(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	cfg, err := config.Parse([]byte(`users:
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: old, keys: ["` + dsa + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: old, servers: [web-1]}
`))
	if err != nil {
		t.Fatal(err)
	}
	results := []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), dsa)})}
	var rep struct {
		PolicyConflicts []struct {
			Kind string `json:"kind"`
		} `json:"policy_conflicts"`
		Summary struct {
			PolicyConflicts int `json:"policy_conflicts"`
		} `json:"summary"`
		Servers []struct {
			CriticalReasons []string `json:"critical_reasons"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(renderJSON(t, cfg, results), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.PolicyConflicts) != 1 || rep.PolicyConflicts[0].Kind != "weak_key" || rep.Summary.PolicyConflicts != 1 {
		t.Errorf("report = %+v, want one weak_key conflict, counted in the summary", rep)
	}
	if got := rep.Servers[0].CriticalReasons; !slices.Equal(got, []string{"policy_conflict"}) {
		t.Errorf("critical_reasons = %v, want [policy_conflict]", got)
	}
}

func TestNoWeakAnnotationOnRevokedRow(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(dsa)
	if err != nil {
		t.Fatal(err)
	}
	cfg := trustConfig(t, testkeys.Line(t, 1), "revoked:\n  - {fingerprint: "+k.Fingerprint+", user: old, date: 2026-11-08}\n")
	results := []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2), dsa)})}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	if !strings.Contains(buf.String(), "REVOKED") || strings.Contains(buf.String(), "WEAK") {
		t.Errorf("a REVOKED row carries no WEAK note:\n%s", buf.String())
	}
	var rep struct {
		Servers []struct {
			Keys struct {
				Unauthorized []struct {
					KeyIssues []string `json:"key_issues"`
				} `json:"unauthorized"`
			} `json:"keys"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(renderJSON(t, cfg, results), &rep); err != nil {
		t.Fatal(err)
	}
	if got := rep.Servers[0].Keys.Unauthorized[0].KeyIssues; got != nil {
		t.Errorf("key_issues on a revoked key: %v", got)
	}
}

// TestCriticalReasonsAllSix: every reason at once, sorted, and absent on a
// server that is not critical.
func TestCriticalReasonsAllSix(t *testing.T) {
	dsa := testkeys.DSALine(t, 7)
	k, err := authkeys.ParseLine(testkeys.Line(t, 9))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(`users:
  - {name: gone, operator: true, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: dead, operator: true, keys: ["` + testkeys.Line(t, 4) + `"]}
  - {name: old, keys: ["` + dsa + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: old, servers: [web-1]}
revoked:
  - {fingerprint: ` + k.Fingerprint + `, user: carol, date: 2026-11-08}
`))
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"web-1": {
			Content: content(authkeys.Header(9999), "cert-authority "+testkeys.Line(t, 4), dsa, testkeys.Line(t, 9)),
			Posture: []fleet.PostureIssue{{Path: "/x", Issue: fleet.PostureWorldWritable, Mode: "drwxrwxrwx", UID: "0"}},
		},
		"web-2": {Content: content(authkeys.Header(0), testkeys.Line(t, 3), testkeys.Line(t, 4))},
	}}
	results := Run(context.Background(), cfg, r, Options{Parallel: 1})
	want := []string{"forged_serial", "operator_cannot_log_in", "operator_missing", "policy_conflict", "revoked_key", "world_writable"}
	if got := criticalReasons(cfg, results[0]); !slices.Equal(got, want) {
		t.Errorf("reasons = %v, want %v", got, want)
	}
	if got := criticalReasons(cfg, results[1]); got != nil {
		t.Errorf("web-2 reasons = %v, want none", got)
	}
	var rep struct {
		Servers []struct {
			Status          string   `json:"status"`
			CriticalReasons []string `json:"critical_reasons"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(renderJSON(t, cfg, results), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Servers[1].CriticalReasons != nil {
		t.Errorf("critical_reasons on %s: %v", rep.Servers[1].Status, rep.Servers[1].CriticalReasons)
	}
}

func TestLinesRecordedByAuditOne(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	op := testkeys.Line(t, 1)
	r := runOne(t, cfg, fleet.ReadResult{Content: content(op, "no-pty "+op)})
	if got := len(r.Lines[fpOf(t, 1)]); got != 2 {
		t.Errorf("Lines holds %d lines, want 2", got)
	}
}

// TestReportOperatorIgnoredText: the third CANNOT LOG IN wording, which no
// golden carries.
func TestReportOperatorIgnoredText(t *testing.T) {
	op := testkeys.Line(t, 1)
	cfg := trustConfig(t, op, "")
	r := runOne(t, cfg, fleet.ReadResult{Content: content("bogus-option "+op, testkeys.Line(t, 2))})
	var buf bytes.Buffer
	Render(&buf, cfg, []ServerResult{r}, RenderOptions{})
	if want := "present but CANNOT LOG IN (CRITICAL: operator key; sshd ignores every line holding it)"; !strings.Contains(buf.String(), want) {
		t.Errorf("report lacks %q:\n%s", want, buf.String())
	}
}

// TestCriticalReasonsNoneWhenUnreachable: nothing is knowable about an
// unreachable server, whatever else the result holds.
func TestCriticalReasonsNoneWhenUnreachable(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	r := ServerResult{
		Server:  cfg.Servers[0],
		Err:     errors.New("dial failed"),
		Posture: []fleet.PostureIssue{{Path: "/x", Issue: fleet.PostureWorldWritable, Mode: "drwxrwxrwx", UID: "0"}},
	}
	if got := criticalReasons(cfg, r); got != nil {
		t.Errorf("reasons = %v, want none", got)
	}
}

// TestCannotLogInNeedsLines: a result built without auditOne has no lines to
// grade, which must not read as "sshd ignores every line".
func TestCannotLogInNeedsLines(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2))})
	r.Lines = nil
	if got := reasonOf(t, cfg, r); got != "" {
		t.Errorf("cannotLogIn = %q, want none", got)
	}
}

// TestPostureSymlinkAndForeignOwnerAreNotCriticalReasons: only a
// world-writable path is a reason, however many other findings a server has.
func TestPostureSymlinkAndForeignOwnerAreNotCriticalReasons(t *testing.T) {
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	r := runOne(t, cfg, fleet.ReadResult{
		Content: content(testkeys.Line(t, 1), testkeys.Line(t, 2)),
		Posture: []fleet.PostureIssue{
			{Path: "/a", Issue: fleet.PostureGroupWritable, Mode: "drwxrwxr-x", UID: "1"},
			{Path: "/b", Issue: fleet.PostureForeignOwner, Mode: "drwxr-xr-x", UID: "2"},
			{Path: "/c", Issue: fleet.PostureSymlink, Mode: "lrwxrwxrwx", UID: "1"},
		},
	})
	if got := criticalReasons(cfg, r); got != nil {
		t.Errorf("reasons = %v, want none", got)
	}
}

// TestExpiredIssueOnlyOnDesiredKeys (plan decision 11): "expired" describes a
// present row's desired expiry-time. An unauthorized key's passed expiry is
// not an issue, in either report.
func TestExpiredIssueOnlyOnDesiredKeys(t *testing.T) {
	pinNow(t)
	cfg := trustConfig(t, testkeys.Line(t, 1), "")
	results := []ServerResult{runOne(t, cfg, fleet.ReadResult{Content: content(
		testkeys.Line(t, 1), testkeys.Line(t, 2), `expiry-time="20260101" `+testkeys.Line(t, 5),
	)})}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	if strings.Contains(buf.String(), "EXPIRED") {
		t.Errorf("an unauthorized row carries no EXPIRED note:\n%s", buf.String())
	}
	var rep struct {
		Servers []struct {
			Keys struct {
				Unauthorized []struct {
					KeyIssues []string `json:"key_issues"`
				} `json:"unauthorized"`
			} `json:"keys"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(renderJSON(t, cfg, results), &rep); err != nil {
		t.Fatal(err)
	}
	if got := rep.Servers[0].Keys.Unauthorized[0].KeyIssues; got != nil {
		t.Errorf("key_issues on an unauthorized key = %v, want none", got)
	}
}
