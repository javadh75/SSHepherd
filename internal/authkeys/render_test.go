package authkeys

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestRenderLine(t *testing.T) {
	base := testkeys.Line(t, 1)
	tests := []struct {
		name string
		line string // parsed into the entry's Key
		comm string
		want string
	}{
		{"plain with comment", base, "alice@work", base + " alice@work"},
		{"no comment", base, "", base},
		{"inline comment on source line is not the rendered comment",
			base + " old@host", "new@host", base + " new@host"},
		{"options preserved verbatim",
			"no-pty,no-agent-forwarding " + base, "a", "no-pty,no-agent-forwarding " + base + " a"},
		{"quoted option with comma and space survives the join",
			`command="echo a,b c",restrict ` + base, "x", `command="echo a,b c",restrict ` + base + " x"},
		{"odd whitespace in the source normalizes to canonical form",
			"   " + base + "   ", "c", base + " c"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RenderLine(RenderEntry{Key: mustKey(t, tt.line), Comment: tt.comm})
			if err != nil {
				t.Fatalf("RenderLine: %v", err)
			}
			if got != tt.want {
				t.Errorf("RenderLine = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRenderLineRejectsHandBuiltKey(t *testing.T) {
	// A Key not produced by ParseLine must surface as an error, never a
	// silently dropped (= lockout hazard) or garbage line.
	if _, err := RenderLine(RenderEntry{Key: Key{Raw: "not a key"}, Comment: "c"}); err == nil {
		t.Fatal("RenderLine(garbage Raw) = nil error, want error")
	}
}

func TestRenderGolden(t *testing.T) {
	entries := []RenderEntry{
		{Key: mustKey(t, testkeys.Line(t, 1)), Comment: "op@sshepherd"},
		{Key: mustKey(t, "no-pty "+testkeys.Line(t, 2)), Comment: "alice@work"},
		{Key: mustKey(t, testkeys.Line(t, 3)+" inline@host"), Comment: "bob"},
	}
	got, err := Render(entries)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := string(got)
	if !strings.HasPrefix(out, ManagedHeader+"\n") {
		t.Errorf("output must start with the managed header:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Error("output must end with a trailing newline")
	}
	// The renderer's output must satisfy our own parser (the project rule
	// behind FuzzRenderRoundTrip), reproducing keys in order.
	keys, parseErrs := ParseFile(got)
	if len(parseErrs) != 0 {
		t.Fatalf("rendered file has unparseable lines: %v", parseErrs)
	}
	if len(keys) != 3 {
		t.Fatalf("rendered file parses to %d keys, want 3", len(keys))
	}
	for i, e := range entries {
		if keys[i].Fingerprint != e.Key.Fingerprint {
			t.Errorf("key %d fingerprint = %s, want %s", i, keys[i].Fingerprint, e.Key.Fingerprint)
		}
		if keys[i].Comment != e.Comment {
			t.Errorf("key %d comment = %q, want %q", i, keys[i].Comment, e.Comment)
		}
		if !slices.Equal(keys[i].Options, e.Key.Options) {
			t.Errorf("key %d options = %v, want %v", i, keys[i].Options, e.Key.Options)
		}
	}
	// Byte-stable: rendering the same entries twice is identical (apply's
	// idempotency hangs on this).
	again, err := Render(entries)
	if err != nil || !bytes.Equal(got, again) {
		t.Errorf("Render is not deterministic (err %v)", err)
	}
	checkGolden(t, "render_basic.golden", got)
}

func TestRenderEmpty(t *testing.T) {
	// Never written in practice (empty desired is converged or refused),
	// but the function must still be total: header + trailing newline only.
	got, err := Render(nil)
	if err != nil || string(got) != ManagedHeader+"\n" {
		t.Fatalf("Render(nil) = (%q, %v), want header only", got, err)
	}
}
