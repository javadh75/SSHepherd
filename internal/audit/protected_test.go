package audit

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// protectedConfig: alice (k1) holds web-1 and web-2; ci (k3) is protected and
// granted web-1 only.
func protectedConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: ci, protected: true, comment: "ci@sshepherd", keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: ci, servers: [web-1]}
`))
	if err != nil {
		t.Fatalf("protectedConfig: %v", err)
	}
	return cfg
}

// aliceOnly: both servers hold alice's key alone, so ci is missing on web-1,
// the one server it is granted.
func aliceOnly(t *testing.T) *fakeReader {
	t.Helper()
	body := fleet.ReadResult{Content: content(testkeys.Line(t, 1))}
	return &fakeReader{byName: map[string]fleet.ReadResult{"web-1": body, "web-2": body}}
}

func TestProtectedMissingIsCriticalOnlyWhereGranted(t *testing.T) {
	cfg := protectedConfig(t)
	results := Run(context.Background(), cfg, aliceOnly(t), Options{Parallel: 2})
	if s := statusOf(cfg, results[0]); s != statusCritical {
		t.Errorf("web-1 status = %s, want critical", s)
	}
	if s := statusOf(cfg, results[1]); s != statusCompliant {
		t.Errorf("web-2 status = %s, want compliant: a key not granted there is not missing", s)
	}
	if code := ExitCode(cfg, results); code != 2 {
		t.Errorf("ExitCode = %d, want 2", code)
	}
	if got, want := criticalReasons(cfg, results[0]), []string{"protected_missing"}; !reflect.DeepEqual(got, want) {
		t.Errorf("criticalReasons = %v, want %v", got, want)
	}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	out := buf.String()
	if strings.Count(out, "(CRITICAL: protected key)") != 1 || strings.Contains(out, "operator key") {
		t.Errorf("report:\n%s", out)
	}
	checkGolden(t, "report_protected.golden", buf.Bytes())
	got := renderJSON(t, cfg, results)
	if strings.Count(string(got), `"protected": true`) != 1 || strings.Contains(string(got), `"operator": true`) {
		t.Errorf("JSON:\n%s", got)
	}
	checkGolden(t, "report_protected.golden.json", got)
}

// TestProtectedPresentCannotLogIn: a present protected key sshd will not
// honour is the same emergency as a missing one.
func TestProtectedPresentCannotLogIn(t *testing.T) {
	cfg := protectedConfig(t)
	r := runOne(t, cfg, fleet.ReadResult{Content: content(testkeys.Line(t, 1), "cert-authority "+testkeys.Line(t, 3))})
	if got, want := criticalReasons(cfg, r), []string{"protected_cannot_log_in"}; !reflect.DeepEqual(got, want) {
		t.Errorf("criticalReasons = %v, want %v", got, want)
	}
	var buf bytes.Buffer
	Render(&buf, cfg, []ServerResult{r}, RenderOptions{})
	if !strings.Contains(buf.String(), "CANNOT LOG IN (CRITICAL: protected key; server line is cert-only)") {
		t.Errorf("report:\n%s", buf.String())
	}
	got := string(renderJSON(t, cfg, []ServerResult{r}))
	if !strings.Contains(got, `"cannot_log_in": "cert_only"`) || !strings.Contains(got, `"protected": true`) || strings.Contains(got, `"operator": true`) {
		t.Errorf("JSON:\n%s", got)
	}
}

// TestScopedOperatorKeepsOperatorWording: an operator is an operator however
// it is scoped, and its except: server is not critical.
func TestScopedOperatorKeepsOperatorWording(t *testing.T) {
	cfg, err := config.Parse([]byte(`
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: op, operator: true, keys: ["` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: op, servers: ["*"], except: [web-2]}
`))
	if err != nil {
		t.Fatal(err)
	}
	results := Run(context.Background(), cfg, aliceOnly(t), Options{Parallel: 2})
	if s := statusOf(cfg, results[1]); s != statusCompliant {
		t.Errorf("web-2 status = %s, want compliant (excepted)", s)
	}
	if got, want := criticalReasons(cfg, results[0]), []string{"operator_missing"}; !reflect.DeepEqual(got, want) {
		t.Errorf("criticalReasons = %v, want %v", got, want)
	}
	var buf bytes.Buffer
	Render(&buf, cfg, results, RenderOptions{})
	if strings.Count(buf.String(), "(CRITICAL: operator key)") != 1 || strings.Contains(buf.String(), "protected key") {
		t.Errorf("report:\n%s", buf.String())
	}
	got := string(renderJSON(t, cfg, results))
	if strings.Count(got, `"operator": true`) != 1 || strings.Contains(got, `"protected": true`) {
		t.Errorf("JSON:\n%s", got)
	}
}
