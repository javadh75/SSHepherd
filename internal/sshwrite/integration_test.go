//go:build integration

package sshwrite

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
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
	code, stdout, stderr, err := sshconn.Exec(conn.Client, cmd, nil)
	if err != nil {
		t.Fatalf("exec %q: %v", cmd, err)
	}
	if code != 0 {
		t.Fatalf("exec %q: exit %d (stderr %q)", cmd, code, stderr.String())
	}
	return stdout.String()
}

// itRendered builds a realistic managed-file payload from the agent's key.
func itRendered(t *testing.T) []byte {
	t.Helper()
	pub, err := os.ReadFile(os.Getenv("SSHEPHERD_IT_PUB"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PUB: %v", err)
	}
	return []byte(authkeys.ManagedHeader + "\n" + strings.TrimSpace(string(pub)) + "\n")
}

// TestIntegrationApplyWriteBackupVerify covers the drifted-seed protocol on
// one user in one ordered flow: write → byte-equal → 0600 → backup holds the
// pre-apply bytes → no temp residue → idempotent re-apply rolls the backup.
func TestIntegrationApplyWriteBackupVerify(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	rendered := itRendered(t)

	orig := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	if !strings.Contains(orig, "ssh-ed25519") || len(strings.Split(strings.TrimSpace(orig), "\n")) != 2 {
		t.Fatalf("pre-apply seed = %q, want the seeded 2-key drift", orig)
	}

	if err := w.Apply(itCtx(t), srv, rendered); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(rendered) {
		t.Errorf("file = %q, want byte-equal to the render", got)
	}
	if mode := strings.TrimSpace(remoteOut(t, w.Dialer, srv, `stat -c %a "$HOME/.ssh/authorized_keys"`)); mode != "600" {
		t.Errorf("mode = %s, want 600", mode)
	}
	if bak := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys.sshepherd.bak"`); bak != orig {
		t.Errorf("backup = %q, want the pre-apply bytes %q", bak, orig)
	}
	if ls := remoteOut(t, w.Dialer, srv, `ls "$HOME/.ssh"`); strings.Contains(ls, ".sshepherd.tmp") {
		t.Errorf("temp residue in ~/.ssh: %q", ls)
	}

	// Re-apply the identical render: succeeds, and the single-generation
	// backup now holds the (identical) previous state.
	if err := w.Apply(itCtx(t), srv, rendered); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if bak := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys.sshepherd.bak"`); bak != string(rendered) {
		t.Errorf("backup after re-apply = %q, want the rolled generation", bak)
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

	if err := w.Apply(itCtx(t), srv, rendered); err != nil {
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

	if err := w.Apply(itCtx(t), srv, rendered); err != nil {
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

	if err := w.Apply(itCtx(t), srv, rendered); err != nil {
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

	err := w.Apply(itCtx(t), srv, itRendered(t))
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
