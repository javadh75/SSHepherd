package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// expandHome resolves "~" or a leading "~/" against the current user's home.
func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", path, err)
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}
