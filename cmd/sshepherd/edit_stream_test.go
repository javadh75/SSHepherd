//go:build linux || darwin

package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// pipeConfig serves content through a pipe and returns its /dev/fd path —
// what `--config /dev/stdin` or `--config <(...)` hands the tool. On Linux
// the path is a symlink into /proc whose target ("pipe:[N]") does not
// resolve; on macOS it does not, and a second read finds the pipe drained.
func pipeConfig(t *testing.T, content string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	if _, err := w.WriteString(content); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("/dev/fd/%d", r.Fd())
}

// TestReadManifestStream: a manifest read from a pipe loads; there is
// nothing to re-read (Unchanged passes) and nothing to save to.
func TestReadManifestStream(t *testing.T) {
	m, err := readManifest(pipeConfig(t, "users: []\n"))
	if err != nil {
		t.Fatalf("readManifest: %v", err)
	}
	if string(m.Loaded) != "users: []\n" || !m.Stream {
		t.Fatalf("target = %+v, want the piped bytes marked as a stream", m)
	}
	if err := m.Unchanged(); err != nil {
		t.Errorf("Unchanged on a stream: %v", err)
	}
	if err := m.Save([]byte("users: []\n")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("Save on a stream = %v, want a not-a-regular-file refusal", err)
	}
}

// TestApplyManifestFromPipe: plain apply still accepts a piped manifest
// (as audit does) and writes; the pre-write re-check has nothing to
// compare a drained pipe against, so it passes.
func TestApplyManifestFromPipe(t *testing.T) {
	hosts, kh, _ := editFleet(t, []byte{1}, "web-1")
	h := hosts["web-1"]
	h.install(t, []byte{1, 2})
	cfg := pipeConfig(t, "users:\n  - {name: alice, keys: ["+qk(t, 1)+"]}\n"+
		"servers:\n"+h.line("web-1")+"access:\n  - {user: alice, servers: [web-1]}\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if got := h.keys(t); strings.Contains(got, testkeys.Line(t, 2)) || !strings.Contains(got, testkeys.Line(t, 1)) {
		t.Errorf("authorized_keys = %q, want only alice's key", got)
	}
}

// TestApplyDryRunEmptyManifestFromPipe: the verifier's reproduction —
// `printf 'users: []\nservers: []\n' | sshepherd apply --dry-run --config
// /dev/stdin` exits 0.
func TestApplyDryRunEmptyManifestFromPipe(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--dry-run", "--config", pipeConfig(t, "users: []\nservers: []\n")}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d\n%s", code, errBuf.String())
	}
}

// TestEditRefusesStreamManifest: revoke and rotate save the manifest in
// place, so a piped one is refused before any edit — exit 3.
func TestEditRefusesStreamManifest(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	body := "users:\n  - {name: alice, keys: [" + qk(t, 1) + "]}\n  - {name: bob, keys: [" + qk(t, 2) + "]}\n"
	for _, args := range [][]string{
		{"revoke", "bob", "--dry-run"},
		{"rotate", "alice", "--old", fpOf(t, 1), "--new", testkeys.Line(t, 5), "--no-apply", "--yes"},
	} {
		t.Run(args[0], func(t *testing.T) {
			cfg := pipeConfig(t, body)
			var out, errBuf bytes.Buffer
			if code := run(append(args, "--config", cfg), &out, &errBuf); code != 3 {
				t.Fatalf("exit = %d, want 3\n%s", code, errBuf.String())
			}
			want := "cannot edit " + cfg + ": not a regular file — revoke and rotate save the manifest in place; pass the manifest file's path"
			if !strings.Contains(errBuf.String(), want) {
				t.Errorf("stderr = %q, want %q", errBuf.String(), want)
			}
		})
	}
}
