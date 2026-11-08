//go:build linux || darwin

package main

import (
	"errors"
	"testing"

	"github.com/javadh75/SSHepherd/internal/manifest"
)

// TestManifestTargetSeamFires pins the one contract the cmd adapter owns on
// top of manifest.Store (whose lock, compare-and-swap, mode and owner rules
// are tested in internal/manifest): beforeManifestSave fires on a regular
// file and never on a stream, and errManifestLocked is the store's
// ErrLocked.
func TestManifestTargetSeamFires(t *testing.T) {
	m, err := readManifest(writeConfig(t, "users: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	fired := false
	saved := beforeManifestSave
	beforeManifestSave = func(manifestTarget) { fired = true }
	t.Cleanup(func() { beforeManifestSave = saved })
	if err := m.Save([]byte("users: []\n# x\n")); err != nil || !fired {
		t.Fatalf("Save = %v, seam fired = %v; want nil, true", err, fired)
	}
	if !errors.Is(errManifestLocked, manifest.ErrLocked) {
		t.Error("errManifestLocked must be manifest.ErrLocked")
	}

	fired = false
	stream := manifestTarget{manifest.Store{Path: "/dev/stdin", Stream: true}}
	if err := stream.Save([]byte("users: []\n")); err == nil || fired {
		t.Fatalf("stream Save = %v, seam fired = %v; want the not-a-regular-file refusal and no seam", err, fired)
	}
}
