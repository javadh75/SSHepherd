package config

import (
	"strings"
	"testing"
)

// TestParseSurvivesDecoderPanic: yaml.v3 panics ("hash of unhashable type")
// when a merge key pulls a mapping whose key is a collection into a struct
// (found by FuzzRemoveAccess). The panic escaped Parse, so every command
// crashed with Go's exit 2, the code D28 keeps for "a human must act now on
// security". A manifest YAML cannot be decoded is a load error (exit 3).
func TestParseSurvivesDecoderPanic(t *testing.T) {
	inputs := map[string]string{
		"merge under a collection key": "users:\n  - {0, [0]}:\n    <<:",
		"fuzz crasher":                 "users:\n  - {000000000000000, [0000000000000000000000000000000000000000000000000000000000000000000000000000000000]}:\n    <<:",
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			c, err := Parse([]byte(in))
			if err == nil {
				t.Fatalf("Parse = %v, nil; want an error", c)
			}
			if !strings.HasPrefix(err.Error(), "parse manifest: ") || !strings.Contains(err.Error(), "YAML decoder failed") {
				t.Errorf("error = %q; want a parse manifest error naming the decoder failure", err)
			}
		})
	}
}

// TestSafeDecodeRecoversEveryPanic pins the helper on its own, since
// rejectNullSerial's decode only runs after Parse's strict decode passed.
func TestSafeDecodeRecoversEveryPanic(t *testing.T) {
	err := safeDecode(func() error { panic("boom") })
	if err == nil || err.Error() != "YAML decoder failed: boom" {
		t.Fatalf("safeDecode = %v; want the recovered panic as an error", err)
	}
	if err := safeDecode(func() error { return nil }); err != nil {
		t.Fatalf("safeDecode(nil) = %v", err)
	}
}
