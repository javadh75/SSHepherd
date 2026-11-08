package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// kindedErr is a reader error that carries its own classification, the
// way sshconn.Error does.
type kindedErr struct {
	kind ErrorKind
	msg  string
}

func (e kindedErr) Error() string        { return e.msg }
func (e kindedErr) ErrorKind() ErrorKind { return e.kind }

func TestErrorKindOf(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ErrorKind
	}{
		{"nil", nil, ""},
		{"plain", errors.New("boom"), ErrorKindUnknown},
		{"kinded", kindedErr{ErrorKindAuth, "denied"}, ErrorKindAuth},
		{"kinded behind wrappers", fmt.Errorf("read: %w", kindedErr{ErrorKindHostKeyChanged, "x"}), ErrorKindHostKeyChanged},
		{"deadline", fmt.Errorf("x: %w", context.DeadlineExceeded), ErrorKindTimeout},
		{"canceled", fmt.Errorf("x: %w", context.Canceled), ErrorKindCanceled},
		{"net dial", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, ErrorKindDial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ErrorKindOf(tt.err); got != tt.want {
				t.Errorf("ErrorKindOf(%v) = %q, want %q", tt.err, got, tt.want)
			}
		})
	}
}

// errorKindResults: web-1 presents a changed host key, web-2 refuses auth.
func errorKindResults(t *testing.T, cfg *config.Config) []ServerResult {
	t.Helper()
	reader := &fakeReader{errs: map[string]error{
		"web-1": hintedErr{kindedErr{ErrorKindHostKeyChanged, "ssh deploy@10.0.0.1:22: presented ssh-ed25519 key SHA256:abc: knownhosts: key mismatch"},
			"HOST KEY CHANGED for 10.0.0.1:22 — possible impersonation; investigate and verify the new fingerprint out of band before touching ~/.ssh/known_hosts"},
		"web-2": kindedErr{ErrorKindAuth, "ssh deploy@10.0.0.2:22: ssh: unable to authenticate"},
	}}
	return Run(context.Background(), cfg, reader, Options{Parallel: 2})
}

// TestHostKeyChangedIsCritical pins the escalation: a changed host key is a
// possible impersonation, not a network blip — exit 2, the kind visible in
// the text head and the JSON error_kind, status still "unreachable"
// (nothing is knowable about the keys of a host we refused to trust).
func TestHostKeyChangedIsCritical(t *testing.T) {
	cfg := reportConfig(t)
	results := errorKindResults(t, cfg)
	if got := ExitCode(cfg, results); got != 2 {
		t.Errorf("ExitCode = %d, want 2 (host key changed)", got)
	}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	for _, want := range []string{"ERROR [host_key_changed]:", "ERROR [auth]:", "1 HOST KEY ALERT", "exit 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	checkGolden(t, "report_error_kinds.golden", buf.Bytes())
	checkGolden(t, "report_error_kinds.golden.json", renderJSON(t, cfg, results))

	var rep struct {
		Summary struct {
			HostKeyAlerts int `json:"host_key_alerts"`
			ExitCode      int `json:"exit_code"`
		} `json:"summary"`
		Servers []struct {
			Status    string `json:"status"`
			ErrorKind string `json:"error_kind"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(renderJSON(t, cfg, results), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Summary.HostKeyAlerts != 1 || rep.Summary.ExitCode != 2 {
		t.Errorf("summary = %+v, want 1 host-key alert, exit 2", rep.Summary)
	}
	if rep.Servers[0].Status != "unreachable" || rep.Servers[0].ErrorKind != "host_key_changed" {
		t.Errorf("web-1 = %+v, want unreachable/host_key_changed", rep.Servers[0])
	}
	if rep.Servers[1].ErrorKind != "auth" {
		t.Errorf("web-2 error_kind = %q, want auth", rep.Servers[1].ErrorKind)
	}
}

// hintedErr is a reader error carrying kind and hint, the way sshconn.Error does.
type hintedErr struct {
	kindedErr
	hint string
}

func (e hintedErr) ErrorHint() string { return e.hint }

func TestHintOf(t *testing.T) {
	h := hintedErr{kindedErr{ErrorKindDial, "dial tcp x: refused"}, "check the firewall"}
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"plain", errors.New("boom"), ""},
		{"hinted", h, "check the firewall"},
		{"hinted behind wrappers", fmt.Errorf("read: %w", h), "check the firewall"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := HintOf(tt.err); got != tt.want {
				t.Errorf("HintOf = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnknownErrorKindStaysPlain(t *testing.T) {
	cfg := reportConfig(t)
	var buf bytes.Buffer
	Render(&buf, cfg, []ServerResult{{Server: cfg.Servers[1], Err: errors.New("boom")}}, RenderOptions{})
	if !strings.Contains(buf.String(), "ERROR: boom") {
		t.Errorf("an unclassified error must render its plain ERROR: head:\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "ERROR [") {
		t.Errorf("an unclassified error must keep the plain ERROR: head:\n%s", buf.String())
	}
}

// optionsConfig: alice's key is granted with restrictions on both servers;
// bob (unrestricted) on web-2.
func optionsConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - name: alice
    keys: ['restrict,command="/usr/local/bin/backup",from="10.0.0.5" ` + testkeys.Line(t, 1) + `']
  - {name: bob, keys: ["` + testkeys.Line(t, 2) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: bob, servers: [web-2]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("optionsConfig: %v", err)
	}
	return cfg
}

// securityDriftResults: web-1 has alice's restrictions stripped; web-2 keeps
// the restricted line but carries an appended unrestricted duplicate of the
// same key, plus a non-empty ~/.ssh/authorized_keys2 sshd also consults.
func securityDriftResults(t *testing.T, cfg *config.Config) []ServerResult {
	t.Helper()
	restricted := `restrict,command="/usr/local/bin/backup",from="10.0.0.5" ` + testkeys.Line(t, 1)
	reader := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(testkeys.Line(t, 1) + "\n")},
		"web-2": {
			Content: []byte(restricted + "\n" +
				testkeys.Line(t, 2) + "\n" +
				testkeys.Line(t, 1) + " sneaky\n"),
			AuthorizedKeys2: true,
		},
	}}
	return Run(context.Background(), cfg, reader, Options{Parallel: 2})
}

// TestSecurityDriftClasses pins the three drift classes a fingerprint-only
// diff used to hide: loosened options on a matched key, a repeated
// fingerprint (sshd tries each line, so an unrestricted copy wins), and an
// unmanaged authorized_keys2. Each makes its server non-compliant (exit 1).
func TestSecurityDriftClasses(t *testing.T) {
	cfg := optionsConfig(t)
	results := securityDriftResults(t, cfg)
	for _, r := range results {
		if r.Compliant() {
			t.Errorf("%s: compliant, want drift", r.Server.Name)
		}
	}
	if got := ExitCode(cfg, results); got != 1 {
		t.Errorf("ExitCode = %d, want 1", got)
	}
	if d := results[1].Duplicates; len(d) != 1 || d[0].Count != 2 {
		t.Errorf("web-2 duplicates = %+v, want one fingerprint ×2", d)
	}

	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	for _, want := range []string{"OPTIONS DIFFER", "duplicate entry", "authorized_keys2"} {
		if !strings.Contains(out, want) {
			t.Errorf("report lacks %q:\n%s", want, out)
		}
	}
	checkGolden(t, "report_security_drift.golden", buf.Bytes())
	checkGolden(t, "report_security_drift.golden.json", renderJSON(t, cfg, results))

	var plain, colored bytes.Buffer
	Render(&plain, cfg, results, RenderOptions{})
	Render(&colored, cfg, results, RenderOptions{Color: true})
	if stripped := ansiRE.ReplaceAllString(colored.String(), ""); stripped != plain.String() {
		t.Errorf("stripped colored output differs from plain:\n%s\n---\n%s", stripped, plain.String())
	}
}

// TestOptionsMatchIsCompliant: identical options on the server are not drift.
func TestOptionsMatchIsCompliant(t *testing.T) {
	cfg := optionsConfig(t)
	restricted := `restrict,command="/usr/local/bin/backup",from="10.0.0.5" ` + testkeys.Line(t, 1)
	reader := &fakeReader{byName: map[string]ReadResult{
		"web-1": {Content: []byte(restricted + " any-comment\n")},
	}}
	res := auditOne(context.Background(), cfg, reader, cfg.Servers[0], 0, discardLogger)
	if !res.Compliant() {
		t.Errorf("matching options must be compliant: %+v", res)
	}
}

func TestGrantedFingerprints(t *testing.T) {
	cfg := operatorConfig(t)
	got := GrantedFingerprints(cfg, "web-1")
	want := []string{cfg.DesiredFor("web-1")[0].Fingerprint, cfg.DesiredFor("web-1")[1].Fingerprint}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("GrantedFingerprints = %v, want %v (operators first)", got, want)
	}
	if u, _ := cfg.OwnerOf(got[0]); !u.Operator {
		t.Errorf("first fingerprint must be the operator's, got %s", u.Name)
	}
}
