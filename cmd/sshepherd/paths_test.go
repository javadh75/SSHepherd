package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	tests := []struct{ in, want string }{
		{"~", home},
		{"~/x/y", filepath.Join(home, "x", "y")},
		{"/abs/path", "/abs/path"},
		{"relative", "relative"},
		{"~x", "~x"}, // not a home reference
	}
	for _, tt := range tests {
		got, err := expandHome(tt.in)
		if err != nil || got != tt.want {
			t.Errorf("expandHome(%q) = (%q, %v), want (%q, nil)", tt.in, got, err, tt.want)
		}
	}
}
