//go:build linux || darwin

package main

import "testing"

// TestValidatePipedManifest: --config /dev/stdin or <(...) works, as on every
// command that reads the manifest once.
func TestValidatePipedManifest(t *testing.T) {
	code, out, stderr := validateCLI(t, "--config", pipeConfig(t, validateManifest(t)), "--known-hosts", recordedKnownHosts(t, "10.0.1.5"))
	if code != 0 || out != "manifest OK: 1 user, 1 server, 1 grant (0 warnings)\n" {
		t.Errorf("exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
}
