package audit

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// preserveConfig: alice (k1) on gitea and web-1; carol (k3) owns a key
// granted nowhere; dave (k4) owns a key whose access to gitea an access
// tombstone removed; k5 is revoked. gitea keeps gitea's command= lines and
// google-ssh comments; web-1 has no rules.
func preserveConfig(t *testing.T) *config.Config {
	t.Helper()
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: carol, keys: ["` + testkeys.Line(t, 3) + `"]}
  - {name: dave, keys: ["` + testkeys.Line(t, 4) + `"]}
servers:
  - {name: gitea, host: 10.0.4.1, user: git, preserve: [{command: '/usr/local/bin/gitea serv key-[0-9]+'}, {comment: 'google-ssh .*'}]}
  - {name: web-1, host: 10.0.1.5, user: deploy}
access:
  - {user: alice, servers: [gitea, web-1]}
revoked:
  - {fingerprint: ` + fpOf(t, 5) + `, date: 2026-11-10}
  - {user: dave, servers: [gitea], date: 2026-11-10}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("preserveConfig: %v", err)
	}
	return cfg
}

// giteaLine is a Gitea-style forced-command line for key seed.
func giteaLine(t *testing.T, seed byte, n int) string {
	t.Helper()
	return fmt.Sprintf(`command="/usr/local/bin/gitea serv key-%d",no-port-forwarding,no-pty %s git@laptop`, n, testkeys.Line(t, seed))
}

// preserveResult audits one server's content through the real pipeline.
func preserveResult(t *testing.T, cfg *config.Config, server, content string) ServerResult {
	t.Helper()
	r := &fakeReader{byName: map[string]fleet.ReadResult{server: {Content: []byte(content)}}}
	for _, res := range Run(context.Background(), cfg, r, Options{Parallel: 1}) {
		if res.Server.Name == server {
			return res
		}
	}
	t.Fatalf("no result for %s", server)
	return ServerResult{}
}

// TestExternalClassification (spec S6 "What a line is", "Lines that are
// never preserved", "Audit"): a fingerprint is kept only when every line
// holding it matches a rule; owned, revoked and cert-only keys never are;
// a kept key is in neither Diff.Unauthorized nor Duplicates, and is not
// drift.
func TestExternalClassification(t *testing.T) {
	cfg := preserveConfig(t)
	alice, k7 := testkeys.Line(t, 1), testkeys.Line(t, 7)
	type kept struct {
		seed  byte
		rule  string
		above int
	}
	for _, tc := range []struct {
		name, server, content string
		external              []kept
		unauthorized          []byte
		dups, exit            int
	}{
		{"command line kept", "gitea", alice + "\n# gitea public key\n" + giteaLine(t, 7, 1) + "\n",
			[]kept{{7, config.PreserveCommand, 1}}, nil, 0, 0},
		{"comment line kept", "gitea", alice + "\n" + testkeys.Line(t, 8) + ` google-ssh {"userName":"a@example.com"}` + "\n",
			[]kept{{8, config.PreserveComment, 0}}, nil, 0, 0},
		{"plain copy first", "gitea", alice + "\n" + k7 + "\n" + giteaLine(t, 7, 1) + "\n", nil, []byte{7}, 1, 1},
		{"plain copy after", "gitea", alice + "\n" + giteaLine(t, 7, 1) + "\n" + k7 + "\n", nil, []byte{7}, 1, 1},
		{"every line matches", "gitea", alice + "\n" + giteaLine(t, 7, 1) + "\n" + giteaLine(t, 7, 2) + "\n",
			[]kept{{7, config.PreserveCommand, 0}, {7, config.PreserveCommand, 0}}, nil, 0, 0},
		{"owned key", "gitea", alice + "\n" + giteaLine(t, 3, 1) + "\n", nil, []byte{3}, 0, 1},
		{"access tombstone", "gitea", alice + "\n" + giteaLine(t, 4, 1) + "\n", nil, []byte{4}, 0, 1}, // D1d drift, not kept
		{"revoked key", "gitea", alice + "\n" + giteaLine(t, 5, 1) + "\n", nil, []byte{5}, 0, 2},
		{"cert-authority", "gitea", alice + "\ncert-authority," + giteaLine(t, 9, 1) + "\n", nil, []byte{9}, 0, 1},
		{"no rules on web-1", "web-1", alice + "\n" + giteaLine(t, 7, 1) + "\n", nil, []byte{7}, 0, 1},
		{"desired key", "gitea", giteaLine(t, 1, 1) + "\n", nil, nil, 0, 1}, // the manifest wins: OK with options drift
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := preserveResult(t, cfg, tc.server, tc.content)
			if len(res.External) != len(tc.external) {
				t.Fatalf("External = %+v, want %d entries", res.External, len(tc.external))
			}
			for i, want := range tc.external {
				e := res.External[i]
				if e.Line.Key.Fingerprint != fpOf(t, want.seed) || e.Rule != want.rule || len(e.Line.Above) != want.above {
					t.Errorf("External[%d] = %s %s above %q, want k%d %s above %d", i, e.Line.Key.Fingerprint, e.Rule, e.Line.Above, want.seed, want.rule, want.above)
				}
				if !res.IsExternal(fpOf(t, want.seed)) {
					t.Errorf("IsExternal(k%d) = false", want.seed)
				}
			}
			var unauth []string
			for _, k := range res.Diff.Unauthorized {
				unauth = append(unauth, k.Fingerprint)
			}
			var wantUnauth []string
			for _, seed := range tc.unauthorized {
				wantUnauth = append(wantUnauth, fpOf(t, seed))
			}
			if !slices.Equal(unauth, wantUnauth) || len(res.Duplicates) != tc.dups {
				t.Errorf("Unauthorized = %v (want %v), %d duplicates (want %d)", unauth, wantUnauth, len(res.Duplicates), tc.dups)
			}
			if got := ExitCode(cfg, []ServerResult{res}); got != tc.exit {
				t.Errorf("ExitCode = %d, want %d", got, tc.exit)
			}
		})
	}
}

// TestKeptOnlyFileIsNotEmpty: a granted server whose file holds only kept
// lines is not the "empty yet login succeeded" paradox (spec S6).
func TestKeptOnlyFileIsNotEmpty(t *testing.T) {
	cfg := preserveConfig(t)
	res := preserveResult(t, cfg, "gitea", giteaLine(t, 7, 1)+"\n")
	var b bytes.Buffer
	Render(&b, cfg, []ServerResult{res}, RenderOptions{})
	if strings.Contains(b.String(), "is empty yet login succeeded") {
		t.Errorf("report calls a file with a kept line empty:\n%s", b.String())
	}
}

// TestAccessTombstoneDoesNotInteract (spec S6 "Tombstones"): an owned key
// is always managed, never kept, so dave's key on a rule-matching line,
// where an access tombstone removed his access, is the existing
// access-revoked drift (D1d, exit 1), labelled as such.
func TestAccessTombstoneDoesNotInteract(t *testing.T) {
	cfg := preserveConfig(t)
	res := preserveResult(t, cfg, "gitea", testkeys.Line(t, 1)+"\n"+giteaLine(t, 4, 1)+"\n")
	var b bytes.Buffer
	Render(&b, cfg, []ServerResult{res}, RenderOptions{})
	if len(res.External) != 0 || len(res.Diff.Unauthorized) != 1 || ExitCode(cfg, []ServerResult{res}) != 1 ||
		!strings.Contains(b.String(), "dave (access revoked 2026-11-10)") {
		t.Errorf("External = %d, Unauthorized = %d, exit %d; want 0, 1, 1 and the access-revoked label:\n%s",
			len(res.External), len(res.Diff.Unauthorized), ExitCode(cfg, []ServerResult{res}), b.String())
	}
}

// TestReportPreservedGoldens (spec S6 "Audit"): each kept line is listed by
// fingerprint with its rule, not drift; the counts line names them; JSON
// keys.external carries rule, and nothing else changes.
func TestReportPreservedGoldens(t *testing.T) {
	cfg := preserveConfig(t)
	alice := testkeys.Line(t, 1)
	r := &fakeReader{byName: map[string]fleet.ReadResult{
		"gitea": {Content: []byte(alice + "\n# gitea public key\n" + giteaLine(t, 7, 1) + "\n" +
			testkeys.Line(t, 8) + ` google-ssh {"userName":"a@example.com"}` + "\n")},
		"web-1": {Content: []byte(alice + "\n")},
	}}
	results := Run(context.Background(), cfg, r, Options{Parallel: 2})
	var text bytes.Buffer
	Render(&text, cfg, results, RenderOptions{})
	checkGolden(t, "report_preserved.golden", text.Bytes())
	checkGolden(t, "report_preserved.golden.json", renderJSON(t, cfg, results))
	if got := ExitCode(cfg, results); got != 0 {
		t.Errorf("ExitCode = %d, want 0 (a kept line is not drift)", got)
	}
}
