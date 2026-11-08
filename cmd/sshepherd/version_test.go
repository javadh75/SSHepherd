package main

import (
	"runtime/debug"
	"testing"
)

func TestResolveVersion(t *testing.T) {
	info := func(v string) func() (*debug.BuildInfo, bool) {
		return func() (*debug.BuildInfo, bool) { return &debug.BuildInfo{Main: debug.Module{Version: v}}, true }
	}
	for _, tt := range []struct {
		name, ldflag string
		read         func() (*debug.BuildInfo, bool)
		want         string
	}{
		{"ldflags value wins", "v1.2.3", info("v9.9.9"), "v1.2.3"},
		{"go install module version", "dev", info("v1.2.0"), "v1.2.0"},
		{"VCS-stamped pseudo-version", "dev", info("v0.0.0-20261107120000-abcdef123456+dirty"), "v0.0.0-20261107120000-abcdef123456+dirty"},
		{"devel build stays dev", "dev", info("(devel)"), "dev"},
		{"empty main version", "dev", info(""), "dev"},
		{"empty ldflag falls back", "", info("v1.3.0"), "v1.3.0"},
		{"no build info", "dev", func() (*debug.BuildInfo, bool) { return nil, false }, "dev"},
		{"ok but nil build info", "dev", func() (*debug.BuildInfo, bool) { return nil, true }, "dev"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveVersion(tt.ldflag, tt.read); got != tt.want {
				t.Errorf("resolveVersion(%q) = %q, want %q", tt.ldflag, got, tt.want)
			}
		})
	}
}

// TestRootVersionUsesResolved: the root command's Version goes through
// resolveVersion, not the raw ldflags variable. An -X value wins as is; an
// empty one must still resolve (to the stamped module version, or "dev")
// — printing the raw "" would mean --version skipped resolveVersion.
func TestRootVersionUsesResolved(t *testing.T) {
	orig := version
	t.Cleanup(func() { version = orig })
	resolved := resolveVersion("", debug.ReadBuildInfo)
	if resolved == "" {
		t.Fatal("resolveVersion returned empty; it always falls back to dev")
	}
	for _, tt := range []struct{ ldflag, want string }{
		{"v7.7.7-test", "v7.7.7-test"},
		{"", resolved},
	} {
		version = tt.ldflag
		if got := newRootCmd(&app{}, nil, nil).Version; got != tt.want {
			t.Errorf("version %q: root Version = %q, want %q", tt.ldflag, got, tt.want)
		}
	}
}
