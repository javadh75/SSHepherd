//go:build integration

package sshwrite

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// itDialer builds a Dialer from the environment exported by
// scripts/integration.sh; skips when not running under it.
func itDialer(t *testing.T) (*sshconn.Dialer, string, int) {
	t.Helper()
	host := os.Getenv("SSHEPHERD_IT_HOST")
	if host == "" {
		t.Skip("integration env not set; run via make integration")
	}
	port, err := strconv.Atoi(os.Getenv("SSHEPHERD_IT_PORT"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PORT: %v", err)
	}
	return &sshconn.Dialer{
		KnownHostsPath: os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS"),
		AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
		DialTimeout:    10 * time.Second,
	}, host, port
}

func itWriter(t *testing.T) (*FleetWriter, string, int) {
	t.Helper()
	d, host, port := itDialer(t)
	return &FleetWriter{Dialer: d}, host, port
}

func itCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// remoteOut runs cmd as srv's user and returns stdout, failing on transport
// errors or a nonzero exit — the assertion channel for on-server state.
func remoteOut(t *testing.T, d *sshconn.Dialer, srv config.Server, cmd string) string {
	t.Helper()
	conn, err := d.Connect(itCtx(t), srv)
	if err != nil {
		t.Fatalf("connect %s: %v", srv.User, err)
	}
	defer func() { _ = conn.Close() }()
	code, stdout, stderr, err := sshconn.Exec(itCtx(t), conn.Client, cmd, nil)
	if err != nil {
		t.Fatalf("exec %q: %v", cmd, err)
	}
	if code != 0 {
		t.Fatalf("exec %q: exit %d (stderr %q)", cmd, code, stderr.String())
	}
	return stdout.String()
}

// itPub returns the harness agent's public key line.
func itPub(t *testing.T) string {
	t.Helper()
	pub, err := os.ReadFile(os.Getenv("SSHEPHERD_IT_PUB"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PUB: %v", err)
	}
	return strings.TrimSpace(string(pub))
}

// itRendered builds a realistic managed-file payload from the agent's key.
func itRendered(t *testing.T) []byte {
	t.Helper()
	return []byte(authkeys.ManagedHeader + "\n" + itPub(t) + "\n")
}

// itSurvivors lists the agent key's fingerprint — the key the post-write
// login probe offers.
func itSurvivors(t *testing.T) []string {
	t.Helper()
	k, err := authkeys.ParseLine(itPub(t))
	if err != nil || k == nil {
		t.Fatalf("parse agent key: %v", err)
	}
	return []string{k.Fingerprint}
}

// itSnapshot reads srv's authorized_keys exactly as phase 1 does and returns
// its compare-and-swap snapshot.
func itSnapshot(t *testing.T, d *sshconn.Dialer, srv config.Server) Snapshot {
	t.Helper()
	conn, err := d.Connect(itCtx(t), srv)
	if err != nil {
		t.Fatalf("connect %s: %v", srv.User, err)
	}
	defer func() { _ = conn.Close() }()
	path := srv.AuthorizedKeysFile
	if path == "" {
		path = sshconn.DefaultAuthorizedKeysPath
	}
	code, stdout, stderr, err := sshconn.Exec(itCtx(t), conn.Client, sshconn.AuthorizedKeysCmdFor(path), nil)
	if err != nil {
		t.Fatalf("snapshot read: %v", err)
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, srv.Name, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("snapshot read: %v", err)
	}
	return SnapshotOf(res.FileAbsent, res.Content)
}

// itRequest builds a write of content conditional on srv's current file.
func itRequest(t *testing.T, d *sshconn.Dialer, srv config.Server, content []byte) Request {
	t.Helper()
	return Request{Content: content, Expect: itSnapshot(t, d, srv), Survivors: itSurvivors(t)}
}

// TestIntegrationApplyWriteBackupVerify covers the drifted-seed protocol on
// one user in one ordered flow: write → byte-equal → 0600 → backup and the
// sticky original hold the pre-apply bytes → no temp/lock residue →
// idempotent re-apply rolls the backup and keeps the original.
func TestIntegrationApplyWriteBackupVerify(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	rendered := itRendered(t)

	orig := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	if !strings.Contains(orig, "ssh-ed25519") || len(strings.Split(strings.TrimSpace(orig), "\n")) != 2 {
		t.Fatalf("pre-apply seed = %q, want the seeded 2-key drift", orig)
	}

	if err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, rendered)); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(rendered) {
		t.Errorf("file = %q, want byte-equal to the render", got)
	}
	if o := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys.sshepherd.orig"`); o != orig {
		t.Errorf(".orig = %q, want the pre-SSHepherd bytes %q", o, orig)
	}
	if mode := strings.TrimSpace(remoteOut(t, w.Dialer, srv, `stat -c %a "$HOME/.ssh/authorized_keys"`)); mode != "600" {
		t.Errorf("mode = %s, want 600", mode)
	}
	if bak := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys.sshepherd.bak"`); bak != orig {
		t.Errorf("backup = %q, want the pre-apply bytes %q", bak, orig)
	}
	if ls := remoteOut(t, w.Dialer, srv, `ls -a "$HOME/.ssh"`); strings.Contains(ls, ".sshepherd.tmp") || strings.Contains(ls, ".sshepherd.lock") {
		t.Errorf("temp/lock residue in ~/.ssh: %q", ls)
	}

	// Re-apply the identical render: succeeds, the backup now holds the
	// (identical) previous state, and the original stays sticky.
	if err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, rendered)); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if bak := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys.sshepherd.bak"`); bak != string(rendered) {
		t.Errorf("backup after re-apply = %q, want the rolled generation", bak)
	}
	if o := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys.sshepherd.orig"`); o != orig {
		t.Errorf(".orig after re-apply = %q, want it still the pre-SSHepherd bytes", o)
	}
}

// TestIntegrationOrphanedTempReclaimed: a temp file orphaned by a dropped
// connection (planted directly here) is reclaimed by the next apply's rm -f.
// The temp name is deliberately fixed — no $$ suffix — exactly so this
// reclamation works across connections (spec: orphaned-temp reclamation on
// re-apply; post-plan note 5).
func TestIntegrationOrphanedTempReclaimed(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	rendered := itRendered(t)

	remoteOut(t, w.Dialer, srv, `printf 'orphaned partial write' > "$HOME/.ssh/authorized_keys.sshepherd.tmp"`)

	if err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, rendered)); err != nil {
		t.Fatalf("Apply over an orphaned temp: %v", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(rendered) {
		t.Errorf("file = %q, want the render", got)
	}
	if ls := remoteOut(t, w.Dialer, srv, `ls "$HOME/.ssh"`); strings.Contains(ls, ".sshepherd.tmp") {
		t.Errorf("orphaned temp survived the re-apply: %q", ls)
	}
}

// TestIntegrationApplyFileAbsent: user virgin logs in via authorized_keys2,
// so the default file genuinely does not exist — apply creates it (0600)
// without touching how the user logs in.
func TestIntegrationApplyFileAbsent(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "virgin", Host: host, Port: port, User: "virgin"}
	rendered := itRendered(t)

	if err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, rendered)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(rendered) {
		t.Errorf("created file = %q, want the render", got)
	}
	if mode := strings.TrimSpace(remoteOut(t, w.Dialer, srv, `stat -c %a "$HOME/.ssh/authorized_keys"`)); mode != "600" {
		t.Errorf("mode = %s, want 600", mode)
	}
	// No backup: there was nothing to back up.
	if out := remoteOut(t, w.Dialer, srv, `ls "$HOME/.ssh"`); strings.Contains(out, "authorized_keys.sshepherd.bak") {
		t.Errorf("ls = %q, want no backup for a previously absent file", out)
	}
}

// TestIntegrationApplyCreatesOverrideDir: an authorized_keys_file override
// under a directory that does not exist yet — mkdir -p under umask 077 must
// yield 0700/0600.
func TestIntegrationApplyCreatesOverrideDir(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{
		Name: "virgin", Host: host, Port: port, User: "virgin",
		AuthorizedKeysFile: "~/keys.d/authorized_keys",
	}
	rendered := itRendered(t)

	if err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, rendered)); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/keys.d/authorized_keys"`); got != string(rendered) {
		t.Errorf("override file = %q, want the render", got)
	}
	// The fixture's busybox adduser gives /home/<u> the setgid bit, which
	// Linux mkdir inherits into new subdirectories — 2700 there is still the
	// umask-pinned 0700 permission bits, not a write-path defect.
	if mode := strings.TrimSpace(remoteOut(t, w.Dialer, srv, `stat -c %a "$HOME/keys.d"`)); mode != "700" && mode != "2700" {
		t.Errorf("created dir mode = %s, want 700 (or setgid-inherited 2700)", mode)
	}
	if mode := strings.TrimSpace(remoteOut(t, w.Dialer, srv, `stat -c %a "$HOME/keys.d/authorized_keys"`)); mode != "600" {
		t.Errorf("override file mode = %s, want 600", mode)
	}
}

// TestIntegrationSymlinkRefused: the seeded symlink trips the exit-45
// sentinel; the link, its target, and the absence of a backup prove the
// server was refused before any change.
func TestIntegrationSymlinkRefused(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "sym", Host: host, Port: port, User: "sym"}

	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t)))
	var symErr *SymlinkError
	if !errors.As(err, &symErr) {
		t.Fatalf("Apply = %v, want *SymlinkError", err)
	}

	if out := remoteOut(t, w.Dialer, srv, `if [ -L "$HOME/.ssh/authorized_keys" ]; then echo link; fi`); strings.TrimSpace(out) != "link" {
		t.Error("authorized_keys is no longer a symlink — the refusal must leave it untouched")
	}
	linkTarget := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys_real"`)
	if !strings.Contains(linkTarget, "ssh-ed25519") || bytes.Contains([]byte(linkTarget), []byte(authkeys.ManagedHeader)) {
		t.Errorf("symlink target = %q, want the untouched seed", linkTarget)
	}
	if out := remoteOut(t, w.Dialer, srv, `ls "$HOME/.ssh"`); strings.Contains(out, ".sshepherd.bak") {
		t.Errorf("ls = %q, a refused server must have no backup", out)
	}
}

// TestIntegrationChangedSincePlanRefused: a teammate edits the file between
// the phase-1 read and the write — the compare-and-swap refuses and the edit
// survives.
func TestIntegrationChangedSincePlanRefused(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "cas", Host: host, Port: port, User: "cas"}
	req := itRequest(t, w.Dialer, srv, itRendered(t)) // the plan's snapshot
	remoteOut(t, w.Dialer, srv, `printf '# emergency key added by a teammate\n' >> "$HOME/.ssh/authorized_keys"`)
	edited := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)

	err := w.Apply(itCtx(t), srv, req)
	var chg *ChangedError
	if !errors.As(err, &chg) {
		t.Fatalf("Apply = %v, want *ChangedError", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != edited {
		t.Errorf("file = %q, want the teammate's edit preserved", got)
	}
}

// TestIntegrationConcurrentApplyLocked: a held lock directory (another apply
// mid-write) refuses the write and is left in place.
func TestIntegrationConcurrentApplyLocked(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "locked", Host: host, Port: port, User: "locked"}
	before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	remoteOut(t, w.Dialer, srv, `mkdir "$HOME/.ssh/authorized_keys.sshepherd.lock"`)
	t.Cleanup(func() { remoteOut(t, w.Dialer, srv, `rmdir "$HOME/.ssh/authorized_keys.sshepherd.lock"`) })

	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t)))
	var locked *LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("Apply = %v, want *LockedError", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != before {
		t.Errorf("file = %q, want it untouched", got)
	}
	if out := remoteOut(t, w.Dialer, srv, `if [ -d "$HOME/.ssh/authorized_keys.sshepherd.lock" ]; then echo held; fi`); strings.TrimSpace(out) != "held" {
		t.Error("the other apply's lock must not be removed")
	}
}

// TestIntegrationVerifyFailure: the file changes between the rename and the
// read-back (injected through the exec seam over the real connection) — the
// verify stage reports the divergence instead of trusting mv.
func TestIntegrationVerifyFailure(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "verifyfail", Host: host, Port: port, User: "verifyfail"}
	w.exec = func(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
		code, out, errBuf, err := sshconn.Exec(ctx, client, cmd, stdin)
		if stdin != nil && err == nil && code == 0 { // the write just landed
			_, _, _, _ = sshconn.Exec(ctx, client, `printf 'tampered\n' >> "$HOME/.ssh/authorized_keys"`, nil)
		}
		return code, out, errBuf, err
	}
	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t)))
	if err == nil || !strings.Contains(err.Error(), "verify on verifyfail: file bytes differ") {
		t.Fatalf("Apply = %v, want the verify divergence", err)
	}
}

// TestIntegrationInterruptedWriteLeavesOriginal: the connection drops
// halfway through the upload. sshd hands cat an EOF, the length check
// rejects the partial temp, and the original stays byte-identical with no
// temp or lock residue.
func TestIntegrationInterruptedWriteLeavesOriginal(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "drop", Host: host, Port: port, User: "drop"}
	before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	// Large enough to span many channel packets.
	content := append(itRendered(t), bytes.Repeat([]byte("# padding padding padding padding\n"), 4000)...)
	w.exec = func(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
		if stdin != nil {
			stdin = &droppingReader{data: content[:len(content)/2], client: client}
		}
		return sshconn.Exec(ctx, client, cmd, stdin)
	}
	if err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content)); err == nil {
		t.Fatal("Apply over a dropped connection succeeded")
	}
	// The remote script finishes asynchronously after the drop.
	deadline := time.Now().Add(10 * time.Second)
	for {
		ls := remoteOut(t, w.Dialer, srv, `ls -a "$HOME/.ssh"`)
		if !strings.Contains(ls, ".sshepherd.lock") && !strings.Contains(ls, ".sshepherd.tmp") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("residue never cleaned up: %q", ls)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != before {
		t.Errorf("file = %q, want the original untouched after a cut upload", got)
	}
}

// droppingReader delivers data, then kills the SSH connection mid-stream.
type droppingReader struct {
	data   []byte
	client *ssh.Client
	sent   bool
}

func (r *droppingReader) Read(p []byte) (int, error) {
	if !r.sent {
		n := copy(p, r.data)
		r.data = r.data[n:]
		if len(r.data) == 0 {
			r.sent = true
		}
		return n, nil
	}
	_ = r.client.Close()
	return 0, io.ErrUnexpectedEOF
}

// TestIntegrationLoginProbeRestores: a write that keeps none of the agent's
// keys (the guard is bypassed here by claiming a survivor) is proven to be
// a lockout by the fresh-connection probe and rolled back over the still-open
// session.
func TestIntegrationLoginProbeRestores(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "lockout", Host: host, Port: port, User: "lockout"}
	before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	content := []byte(authkeys.ManagedHeader + "\n" + testkeys.Line(t, 42) + "\n")

	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content))
	var lo *LockoutError
	if !errors.As(err, &lo) || lo.Restore != nil {
		t.Fatalf("Apply = %v, want a restored *LockoutError", err)
	}
	// Still able to log in, and the file is what it was.
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != before {
		t.Errorf("file = %q, want the previous version restored", got)
	}
}

// TestIntegrationApplyDisablesAuthorizedKeys2: a revoked key planted in
// authorized_keys2 (which the fixture's sshd consults) is moved aside by a
// write that disables it, and the survivors still log in afterwards (the
// post-write probe ran without the file).
func TestIntegrationApplyDisablesAuthorizedKeys2(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	line := testkeys.Line(t, 9) + " revoked@example"
	planted := line + "\n"
	remoteOut(t, w.Dialer, srv, `printf '%s\n' '`+line+`' > "$HOME/.ssh/authorized_keys2"`)

	req := itRequest(t, w.Dialer, srv, itRendered(t))
	req.DisableKeys2 = true
	if err := w.Apply(itCtx(t), srv, req); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if out := remoteOut(t, w.Dialer, srv, `if [ -e "$HOME/.ssh/authorized_keys2" ]; then echo present; fi`); strings.TrimSpace(out) != "" {
		t.Error("authorized_keys2 still in place after a disabling write")
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys2`+Keys2DisabledSuffix+`"`); got != planted {
		t.Errorf("disabled copy = %q, want the planted file", got)
	}
}
