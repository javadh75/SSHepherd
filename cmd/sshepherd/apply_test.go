package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// applyFleetYAML: one user granted one server (host/port injected).
func applyFleetYAML(t *testing.T, hostPort string) string {
	t.Helper()
	return `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, ` + hostPort + `, user: deploy}
access:
  - {user: alice, servers: [web-1]}
`
}

func TestApplyMissingConfig(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", "no-such-file.yaml"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
}

func TestApplyInvalidParallel(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--parallel", "0"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
}

func TestApplyDryRunYesConflict(t *testing.T) {
	path := writeConfig(t, "")
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--dry-run", "--yes"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (mutually exclusive flags)", code)
	}
}

func TestApplyUnknownServer(t *testing.T) {
	// Checked before any preflight: a canary typo must fail fast, not
	// silently apply nothing — and must not require an agent.
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--server", "nope"}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), `unknown server "nope"`) {
		t.Errorf("stderr = %q, want the unknown-server error", errBuf.String())
	}
}

func TestApplyNoAgent(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, applyFleetYAML(t, "host: 10.0.0.1"))
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--known-hosts", emptyKnownHosts(t)}, &out, &errBuf); code != 3 {
		t.Fatalf("exit = %d, want 3", code)
	}
	if !strings.Contains(errBuf.String(), "SSH_AUTH_SOCK") {
		t.Errorf("stderr = %q, want agent guidance", errBuf.String())
	}
}

func TestApplyEmptyFleet(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "0 servers targeted — nothing to apply") {
		t.Errorf("stdout = %q, want the empty summary", out.String())
	}
}

func TestApplyLogsManifestWarnings(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeConfig(t, `
users:
  - name: alice
    comment: "alice — platform team"
    keys: ["`+testkeys.Line(t, 1)+`", "`+testkeys.Line(t, 2)+`"]
`)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "comment is set on a user with 2 keys") {
		t.Errorf("stderr = %q, want the multi-key comment warning", errBuf.String())
	}
}

// TestApplyDryRunUnreachable drives the full run() path against a fleet
// whose one server refuses connections: plan renders the ERROR head, the
// summary counts it, exit is 1, and nothing prompted.
func TestApplyDryRunUnreachable(t *testing.T) {
	path, kh := unreachableFleet(t) // fake agent + closed port, from adopt_test.go
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", path, "--known-hosts", kh, "--dry-run"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "ERROR [dial]:") {
		t.Errorf("stdout = %q, want the unreachable head", out.String())
	}
	if !strings.Contains(out.String(), "1 unreachable  → exit 1") {
		t.Errorf("stdout = %q, want the summary counting the unreachable server", out.String())
	}
}

// Without --dry-run the behavior is identical when no server needs a write:
// nothing to confirm, so no prompt and no TTY requirement.
func TestApplyUnreachableNoPromptNeeded(t *testing.T) {
	path, kh := unreachableFleet(t)
	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--config", path, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if strings.Contains(errBuf.String(), "[y/N]") {
		t.Errorf("stderr = %q, must not prompt when nothing needs a write", errBuf.String())
	}
}

func TestApplyServerFilterSkippedNote(t *testing.T) {
	fakeAgent(t)
	kh := writeEmptyKnownHosts(t)
	path := writeConfig(t, `
users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
servers:
  - {name: web-1, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
  - {name: web-2, host: 127.0.0.1, port: `+strconvItoa(closedPort(t))+`, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
`)
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", path, "--known-hosts", kh, "--dry-run", "--server", "web-1"}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "(1 server skipped by --server)") {
		t.Errorf("stdout = %q, want the skipped-by-server note", out.String())
	}
	if strings.Contains(out.String(), "web-2") {
		t.Errorf("stdout = %q, must not mention the skipped server", out.String())
	}
	if !strings.Contains(out.String(), "0/1 servers converged") {
		t.Errorf("stdout = %q, counts must be over the 1 targeted server only", out.String())
	}
}

// TestApplyHermetic drives the real apply wiring end to end against an
// in-process server running every command through the local /bin/sh:
// guarded write, verify, post-write login probe, backups, and a byte-stable
// re-run.
func TestApplyHermetic(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	target := filepath.Join(home, ".ssh", "authorized_keys")
	orig, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys2"), []byte("ssh-ed25519 AAAA planted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))

	var out, errBuf bytes.Buffer
	if code := run([]string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	for _, want := range []string{"web-1: applied · verified", "disable ~/.ssh/authorized_keys2"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, out.String())
		}
	}
	k2 := filepath.Join(home, ".ssh", "authorized_keys2")
	if _, err := os.Lstat(k2); !os.IsNotExist(err) {
		t.Error("authorized_keys2 still in place: a revoked key there keeps logging in")
	}
	if b, err := os.ReadFile(k2 + ".sshepherd.disabled"); err != nil || string(b) != "ssh-ed25519 AAAA planted\n" {
		t.Errorf("disabled copy = (%q, %v), want the moved authorized_keys2", b, err)
	}
	got, err := os.ReadFile(target)
	if err != nil || !strings.HasPrefix(string(got), authkeys.ManagedHeader+"\n") {
		t.Fatalf("file = (%q, %v), want the managed render", got, err)
	}
	for _, suffix := range []string{".sshepherd.bak", ".sshepherd.orig"} {
		if b, err := os.ReadFile(target + suffix); err != nil || !bytes.Equal(b, orig) {
			t.Errorf("%s = (%q, %v), want the pre-apply bytes", suffix, b, err)
		}
	}
	if _, err := os.Stat(target + ".sshepherd.lock"); !os.IsNotExist(err) {
		t.Error("lock directory left behind")
	}

	out.Reset()
	errBuf.Reset()
	if code := run([]string{"apply", "--dry-run", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 0 {
		t.Fatalf("re-run exit = %d, want 0 (converged)\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "converged (no changes)") {
		t.Errorf("re-run is not byte-stable:\n%s", out.String())
	}
}

func TestConfirm(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		tty     bool
		yes     bool
		wantOK  bool
		wantErr bool
	}{
		{"--yes bypasses the prompt", "", false, true, true, false},
		{"non-TTY without --yes errors", "", false, false, false, true},
		{"tty y", "y\n", true, false, true, false},
		{"tty Y", "Y\n", true, false, true, false},
		{"tty yes", "yes\n", true, false, true, false},
		{"tty n", "n\n", true, false, false, false},
		{"tty empty defaults to no", "\n", true, false, false, false},
		{"tty EOF declines", "", true, false, false, false},
		{"tty garbage declines", "sure why not\n", true, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var errBuf bytes.Buffer
			ok, err := confirm(context.Background(), strings.NewReader(tt.in), &errBuf, tt.tty, tt.yes, "apply 3 of 12 servers?")
			if ok != tt.wantOK || (err != nil) != tt.wantErr {
				t.Fatalf("confirm = (%v, %v), want (%v, err=%v)", ok, err, tt.wantOK, tt.wantErr)
			}
			if tt.tty && !tt.yes {
				if !strings.Contains(errBuf.String(), "apply 3 of 12 servers? [y/N]") {
					t.Errorf("prompt = %q, want the exact question on stderr", errBuf.String())
				}
			} else if errBuf.Len() != 0 {
				t.Errorf("wrote %q to stderr without a TTY prompt", errBuf.String())
			}
		})
	}
}

// TestConfirmInterrupted: Ctrl-C at the [y/N] prompt cancels ctx; the
// prompt must return at once (declining, with the cancellation) instead of
// swallowing the signal while still blocked on stdin.
func TestConfirmInterrupted(t *testing.T) {
	pr, pw := io.Pipe() // stdin that never answers
	t.Cleanup(func() { _ = pw.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	type res struct {
		ok  bool
		err error
	}
	done := make(chan res, 1)
	go func() {
		ok, err := confirm(ctx, pr, io.Discard, true, false, "apply 1 of 1 servers?")
		done <- res{ok, err}
	}()
	cancel()
	select {
	case r := <-done:
		if r.ok || !errors.Is(r.err, context.Canceled) {
			t.Fatalf("confirm = (%v, %v), want (false, context.Canceled)", r.ok, r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("confirm kept blocking on stdin after ctx was canceled")
	}
}

func TestStdioIsTTYOnBuffers(t *testing.T) {
	if stdioIsTTY(strings.NewReader(""), &bytes.Buffer{}) {
		t.Error("buffers must never count as a TTY")
	}
}

func TestSelectServers(t *testing.T) {
	y := `
users:
  - {name: alice, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: a, host: h1, user: u}
  - {name: b, host: h2, user: u}
  - {name: c, host: h3, user: u}
access:
  - {user: alice, servers: [a, b, c]}
`
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	t.Run("no names selects the fleet", func(t *testing.T) {
		got, err := selectServers(cfg, nil)
		if err != nil || len(got) != 3 {
			t.Fatalf("got %d servers, err %v; want 3", len(got), err)
		}
	})
	t.Run("subset keeps manifest order and dedupes", func(t *testing.T) {
		got, err := selectServers(cfg, []string{"c", "a", "c"})
		if err != nil {
			t.Fatalf("selectServers: %v", err)
		}
		if len(got) != 2 || got[0].Name != "a" || got[1].Name != "c" {
			t.Fatalf("got %v, want [a c] in manifest order", got)
		}
	})
	t.Run("unknown name errors", func(t *testing.T) {
		if _, err := selectServers(cfg, []string{"a", "nope"}); err == nil || !strings.Contains(err.Error(), `unknown server "nope"`) {
			t.Fatalf("err = %v, want the unknown-server error", err)
		}
	})
}

// writeEmptyKnownHosts creates an empty known_hosts for closed-port fleets.
func writeEmptyKnownHosts(t *testing.T) string {
	t.Helper()
	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	return kh
}

func strconvItoa(n int) string { return strconv.Itoa(n) }

// TestRelistPrefix pins the post-confirmation re-list error prefix: the
// pre---identity wording for an agent-only run, a key-neutral one with
// --identity.
func TestRelistPrefix(t *testing.T) {
	if got := relistPrefix(&sshconn.Credentials{AgentSock: "/s"}); got != "re-listing agent keys after confirmation" {
		t.Errorf("agent-only prefix = %q", got)
	}
	withFile := &sshconn.Credentials{Files: []keyfile.Identity{{Path: "/k"}}}
	if got := relistPrefix(withFile); got != "re-listing the keys you hold after confirmation" {
		t.Errorf("--identity prefix = %q", got)
	}
}

// usePromptStreams makes the confirmation prompt read in and write out as
// if both were a terminal.
func usePromptStreams(t *testing.T, in io.Reader, out io.Writer) {
	t.Helper()
	saved := promptStreams
	promptStreams = func(*cobra.Command) (io.Reader, io.Writer, bool) { return in, out, true }
	t.Cleanup(func() { promptStreams = saved })
}

// actionReader runs act once, on its first Read, then reads from r: a
// prompt answer that does something "while the prompt waits".
type actionReader struct {
	once sync.Once
	act  func()
	r    io.Reader
}

func (a *actionReader) Read(p []byte) (int, error) {
	a.once.Do(a.act)
	return a.r.Read(p)
}

// TestApplyRefusesChangedManifest: a manifest replaced while apply waited
// at its prompt (a concurrent revoke) is never planned-against-and-written:
// exit 3, the server untouched.
func TestApplyRefusesChangedManifest(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	target := filepath.Join(home, ".ssh", "authorized_keys")
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	var prompt bytes.Buffer
	usePromptStreams(t, &actionReader{
		act: func() {
			raw, err := os.ReadFile(cfg)
			if err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(cfg, append(raw, "# edited by a concurrent run\n"...), 0o600); err != nil {
				t.Error(err)
			}
		},
		r: strings.NewReader("y\n"),
	}, &prompt)
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 3 {
		t.Fatalf("exit = %d, want 3\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "manifest "+cfg+" changed since it was read; re-run") {
		t.Errorf("stderr = %q, want the changed-manifest refusal", errBuf.String())
	}
	if !strings.Contains(prompt.String(), "apply 1 of 1 servers? [y/N]") {
		t.Errorf("prompt = %q", prompt.String())
	}
	if after, _ := os.ReadFile(target); !bytes.Equal(after, before) {
		t.Errorf("authorized_keys written despite the refusal:\n%s", after)
	}
}

// TestApplyDeclinedPrompt: "n" at the prompt writes nothing, logs the
// abort and exits 1 (pending changes) — plain apply's long-standing
// behavior, now through the shared run body; no edit header or manifest
// save line ever appears for plain apply.
func TestApplyDeclinedPrompt(t *testing.T) {
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	usePromptStreams(t, strings.NewReader("n\n"), io.Discard)
	var out, errBuf bytes.Buffer
	code := run([]string{"apply", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
	if code != 1 {
		t.Fatalf("exit = %d, want 1\nstdout: %s\nstderr: %s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "aborted; no changes made") {
		t.Errorf("stderr = %q, want the abort line", errBuf.String())
	}
	if !strings.Contains(out.String(), "1 pending  → exit 1") {
		t.Errorf("stdout = %q, want the pending summary", out.String())
	}
	for _, never := range []string{"manifest edit:", "updated — commit and push"} {
		if strings.Contains(out.String(), never) {
			t.Errorf("plain apply printed %q:\n%s", never, out.String())
		}
	}
}
