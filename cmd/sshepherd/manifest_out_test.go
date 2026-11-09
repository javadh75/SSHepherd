//go:build linux || darwin

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPublishManifestRoutes: -o is a new-file publish (manifest.WriteFile:
// 0600, never clobbered without --force) unless it names the very manifest
// the run read, which is an in-place update through Save (--force required,
// identical bytes write nothing, the file's mode kept).
func TestPublishManifestRoutes(t *testing.T) {
	const orig, next = "users: []\n", "users: []\n# next\n"
	tests := []struct {
		name    string
		out     func(t *testing.T, src string) string // -o path, given the manifest path
		data    string
		force   bool
		wantErr string
		check   func(t *testing.T, out string, before os.FileInfo)
	}{
		{
			name: "new path is created 0600",
			out:  func(t *testing.T, _ string) string { return filepath.Join(t.TempDir(), "new.yaml") },
			data: next,
			check: func(t *testing.T, out string, _ os.FileInfo) {
				fi, err := os.Stat(out)
				if err != nil || fi.Mode().Perm() != 0o600 {
					t.Errorf("new file = (%v, %v), want mode 0600", fi, err)
				}
			},
		},
		{
			name: "other existing path without force is refused",
			out: func(t *testing.T, _ string) string {
				p := filepath.Join(t.TempDir(), "other.yaml")
				if err := os.WriteFile(p, []byte("keep\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			data:    next,
			wantErr: "already exists; pass --force",
		},
		{
			name:    "same path without force is refused",
			out:     func(_ *testing.T, src string) string { return src },
			data:    next,
			wantErr: "is the manifest this run read; pass --force to update it in place",
			check: func(t *testing.T, out string, _ os.FileInfo) {
				if got, _ := os.ReadFile(out); string(got) != orig {
					t.Errorf("manifest = %q, want untouched", got)
				}
			},
		},
		{
			name:  "same path, force, identical bytes writes nothing",
			out:   func(_ *testing.T, src string) string { return src },
			data:  orig,
			force: true,
			check: func(t *testing.T, out string, before os.FileInfo) {
				now, err := os.Stat(out)
				if err != nil || !os.SameFile(before, now) || !now.ModTime().Equal(before.ModTime()) {
					t.Errorf("identical bytes rewrote the manifest (%v)", err)
				}
				if _, err := os.Lstat(filepath.Join(filepath.Dir(out), ".sshepherd.yaml.sshepherd-lock")); err == nil {
					t.Error("identical bytes took the manifest lock: nothing should have been saved")
				}
			},
		},
		{
			name:  "same path, force, new bytes is saved with its mode kept",
			out:   func(_ *testing.T, src string) string { return src },
			data:  next,
			force: true,
			check: func(t *testing.T, out string, _ os.FileInfo) {
				fi, err := os.Stat(out)
				if err != nil || fi.Mode().Perm() != 0o640 {
					t.Errorf("mode = (%v, %v), want 0640 kept", fi, err)
				}
				if got, _ := os.ReadFile(out); string(got) != next {
					t.Errorf("manifest = %q, want the new bytes", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := writeConfig(t, orig)
			if err := os.Chmod(src, 0o640); err != nil { // #nosec G302 -- a group-shared manifest under test
				t.Fatal(err)
			}
			m, err := readManifest(src)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(src)
			if err != nil {
				t.Fatal(err)
			}
			out := tt.out(t, src)
			_, err = publishManifest(m, out, []byte(tt.data), tt.force)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Fatalf("publishManifest = %v, want nil", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Fatalf("publishManifest = %v, want %q", err, tt.wantErr)
			}
			if tt.check != nil {
				tt.check(t, out, before)
			}
		})
	}
}

// TestPlaceManifest: no -o puts the bytes in the document; -o reports
// whether the file changed, which an identical in-place update did not.
func TestPlaceManifest(t *testing.T) {
	data := []byte("users: []\n")
	src := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := readManifest(src)
	if err != nil {
		t.Fatal(err)
	}
	got, err := placeManifest(m, "", data, false)
	if err != nil || got.Output != nil || got.Manifest == nil || *got.Manifest != string(data) {
		t.Errorf("no -o: placement = %+v, err = %v", got, err)
	}
	dst := filepath.Join(t.TempDir(), "new.yaml")
	got, err = placeManifest(m, dst, data, false)
	if err != nil || got.Manifest != nil || got.Output == nil || got.Output.Path != dst || !got.Output.Written {
		t.Errorf("new file: placement = %+v, err = %v", got, err)
	}
	got, err = placeManifest(m, src, data, true)
	if err != nil || got.Output == nil || got.Output.Written {
		t.Errorf("identical in-place update: placement = %+v, err = %v, want written false", got, err)
	}
	if _, err = placeManifest(m, dst, data, false); err == nil {
		t.Error("an existing -o without --force was accepted")
	}
	changed := []byte("users: []\nservers: []\naccess: []\n")
	got, err = placeManifest(m, src, changed, true)
	if err != nil || got.Output == nil || !got.Output.Written {
		t.Errorf("changing in-place update: placement = %+v, err = %v, want written true", got, err)
	}
	if onDisk, err := os.ReadFile(src); err != nil || !bytes.Equal(onDisk, changed) {
		t.Errorf("in-place update left %q (err %v), want %q", onDisk, err, changed)
	}
}

// TestPlaceManifestNonUTF8: json.Encoder would replace bytes that are not
// UTF-8, so the document refuses them rather than carry a different manifest;
// -o still gets them unchanged.
func TestPlaceManifestNonUTF8(t *testing.T) {
	data := utf16LE("users: []\n")
	got, err := placeManifest(manifestTarget{}, "", data, false)
	if err == nil || !strings.Contains(err.Error(), "-o FILE") {
		t.Errorf("err = %v, want a refusal naming -o FILE", err)
	}
	if got.Manifest != nil || got.Output != nil {
		t.Errorf("placement = %+v, want none", got)
	}
	dst := filepath.Join(t.TempDir(), "new.yaml")
	got, err = placeManifest(manifestTarget{}, dst, data, false)
	if err != nil || got.Output == nil || !got.Output.Written {
		t.Fatalf("-o: placement = %+v, err = %v", got, err)
	}
	if onDisk, err := os.ReadFile(dst); err != nil || !bytes.Equal(onDisk, data) {
		t.Errorf("-o wrote %x (err %v), want %x", onDisk, err, data)
	}
}
