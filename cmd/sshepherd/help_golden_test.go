package main

import (
	"cmp"
	"os"
	"path/filepath"
	"testing"
)

// TestHelpGolden snapshots the full --help of the root and every command,
// so a dependency bump that changes user-facing help text fails CI.
// Regenerate with: go test ./cmd/sshepherd -run TestHelpGolden -update
// and read the diff before accepting it.
func TestHelpGolden(t *testing.T) {
	if *update {
		if err := os.MkdirAll(filepath.Join("testdata", "help"), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range helpCommands {
		label := cmp.Or(name, "root")
		t.Run(label, func(t *testing.T) {
			checkGolden(t, filepath.Join("help", label+".golden"), []byte(helpOutput(t, name)))
		})
	}
}
