package apply

import (
	"bytes"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestPlural(t *testing.T) {
	for _, tt := range []struct {
		n    int
		want string
	}{{0, "0 keys"}, {1, "1 key"}, {2, "2 keys"}} {
		if got := Plural(tt.n, "key", "keys"); got != tt.want {
			t.Errorf("Plural(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}

// TestPluralizedCountStrings: every count string the plan and report print
// agrees with its number, singular and plural.
func TestPluralizedCountStrings(t *testing.T) {
	cfg := emptyDesiredCfg(t) // alice (k2) on web-1; bare has no grants
	web1 := renderedFor(t, cfg, "web-1")
	tests := []struct {
		name, server, content string
		want                  string
	}{
		{"one key wipe", "bare", testkeys.Line(t, 9) + "\n", "1 key installed but manifest grants none"},
		{"two keys wipe", "bare", testkeys.Line(t, 9) + "\n" + testkeys.Line(t, 8) + "\n", "2 keys installed but manifest grants none"},
		{"key and unparseable line wipe", "bare", testkeys.Line(t, 9) + "\ngarbage\n", "1 key and 1 unparseable line installed but manifest grants none"},
		{"keys and unparseable lines wipe", "bare", testkeys.Line(t, 9) + "\n" + testkeys.Line(t, 8) + "\ngarbage\nmore garbage\n", "2 keys and 2 unparseable lines installed"},
		{"one unparseable line", "web-1", testkeys.Line(t, 2) + "\ngarbage\n", "1 unparseable line — refusing to rewrite a file that could not be fully read (fix the line or"},
		{"two unparseable lines", "web-1", testkeys.Line(t, 2) + "\ngarbage\nmore\n", "2 unparseable lines — refusing to rewrite a file that could not be fully read (fix the lines or"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			read := map[string]audit.ReadResult{"web-1": {Content: web1}, "bare": {}}
			read[tt.server] = audit.ReadResult{Content: []byte(tt.content)}
			p := planFor(t, buildPlans(t, cfg, &fakeReader{byName: read}, []string{fp(t, 2)}), tt.server)
			if !strings.Contains(p.Refusal, tt.want) {
				t.Errorf("Refusal = %q, want it to contain %q", p.Refusal, tt.want)
			}
		})
	}

	t.Run("one key desired, plural non-key and duplicate lines", func(t *testing.T) {
		content := "# a\n\n" + testkeys.Line(t, 2) + " x\n" + testkeys.Line(t, 2) + " y\n" + testkeys.Line(t, 2) + " z\n"
		read := map[string]audit.ReadResult{"web-1": {Content: []byte(content)}}
		plans := buildPlans(t, cfg, &fakeReader{byName: read}, []string{fp(t, 2)})
		var buf bytes.Buffer
		Render(&buf, cfg, plans, RenderOptions{})
		for _, want := range []string{"→ 1 key desired", "removing 2 non-key lines (comments/blank)", "removing 2 duplicate key lines"} {
			if !strings.Contains(buf.String(), want) {
				t.Errorf("report lacks %q:\n%s", want, buf.String())
			}
		}
	})
}
