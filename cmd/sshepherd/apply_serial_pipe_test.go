//go:build linux || darwin

package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestApplySerialBumpPipedConfig (spec §6, §9): a piped --config cannot be
// saved, so an apply that removes a key warns and proceeds — the write
// happens, exit 0; --dry-run warns the same way instead of promising a
// bump; --json reports serial_bump {from, to: null, saved: false, warning}.
func TestApplySerialBumpPipedConfig(t *testing.T) {
	stray := strings.Fields(testkeys.Line(t, 9))[1]
	setup := func(t *testing.T) (editHost, string, string) {
		hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
		h := hosts["web-1"]
		h.install(t, []byte{1, 9})
		return h, kh, pipeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
			"servers:\n"+h.line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
	}
	t.Run("text", func(t *testing.T) {
		h, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d, want 0\n%s\n%s", code, out.String(), errBuf.String())
		}
		if !strings.Contains(errBuf.String(), noBumpWarning) || strings.Contains(out.String(), "manifest serial:") {
			t.Errorf("stderr lacks the no-bump warning (or a bump was claimed):\n%s\n%s", errBuf.String(), out.String())
		}
		if strings.Contains(h.keys(t), stray) {
			t.Error("the write did not proceed: the stray key is still installed")
		}
	})
	t.Run("--dry-run", func(t *testing.T) {
		_, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		run([]string{"apply", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
		if !strings.Contains(errBuf.String(), noBumpWarning) || strings.Contains(out.String(), "would bump serial") {
			t.Errorf("dry run must warn, not promise a bump:\n%s\n%s", out.String(), errBuf.String())
		}
	})
	t.Run("--json", func(t *testing.T) {
		_, kh, cfg := setup(t)
		var out, errBuf bytes.Buffer
		if code := run([]string{"apply", "--yes", "--json", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
			t.Fatalf("exit = %d\n%s", code, errBuf.String())
		}
		var doc struct {
			SerialBump map[string]any `json:"serial_bump"`
		}
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("stdout is not one document: %v\n%s", err, out.String())
		}
		want := map[string]any{"from": float64(0), "to": nil, "saved": false, "warning": noBumpWarning}
		if !reflect.DeepEqual(doc.SerialBump, want) {
			t.Errorf("serial_bump = %v, want %v", doc.SerialBump, want)
		}
	})
}
