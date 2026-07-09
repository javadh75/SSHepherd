package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshcfg"
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

func TestGenerateManifestGolden(t *testing.T) {
	hosts := []sshcfg.Host{
		{Alias: "web-1", HostName: "10.0.0.1", Port: 2222, User: "deploy"},
		{Alias: "web-2", HostName: "10.0.0.2", Port: 22, User: "deploy"}, // port 22 omitted
		{Alias: "bastion", HostName: "bastion", User: "ops"},             // port 0 omitted
		{Alias: "nouser", HostName: "10.0.0.9"},                          // skipped
	}
	got, skipped, err := generateManifest(hosts, "~/.ssh/config")
	if err != nil {
		t.Fatalf("generateManifest: %v", err)
	}
	if len(skipped) != 1 || !strings.Contains(skipped[0], "nouser") {
		t.Errorf("skipped = %v, want one note about nouser", skipped)
	}
	if _, err := config.Parse(got); err != nil {
		t.Errorf("generated manifest rejected by config.Parse: %v", err)
	}
	checkGolden(t, "import_manifest.golden", got)
}

func TestGenerateManifestEmpty(t *testing.T) {
	got, skipped, err := generateManifest(nil, "x")
	if err != nil || len(skipped) != 0 {
		t.Fatalf("generateManifest(nil) = skipped %v, err %v", skipped, err)
	}
	if _, err := config.Parse(got); err != nil {
		t.Errorf("empty manifest rejected by config.Parse: %v", err)
	}
	if !strings.Contains(string(got), "servers: []") {
		t.Errorf("output %q missing explicit empty servers list", got)
	}
}
