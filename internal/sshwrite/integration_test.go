//go:build integration

package sshwrite

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
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
		Creds:          &sshconn.Credentials{AgentSock: os.Getenv("SSH_AUTH_SOCK")},
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

// itSurvivors lists the harness key's fingerprint — the key the post-write
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

// fixture is a user's starting state. A nil field leaves that file absent.
type fixture struct {
	keys, keys2 *string
	clear       []string // extra $HOME-relative paths to remove (e.g. "keys.d")
}

func strp(s string) *string { return &s }

// itDrifted is the writer/e2e seed: the harness key plus a stale key that
// apply must remove. testkeys keeps it hermetic.
func itDrifted(t *testing.T) string { return itPub(t) + "\n" + testkeys.Line(t, 7) + "\n" }

// shPrint returns a single-line sh command that prints content byte for
// byte. sshconn.Exec refuses a script holding a newline, so each line goes
// in as its own quoted printf argument instead of one quoted blob.
func shPrint(content string) string {
	lines := strings.Split(content, "\n")
	full, last := lines[:len(lines)-1], lines[len(lines)-1]
	var parts []string
	if len(full) > 0 {
		args := make([]string, len(full))
		for i, l := range full {
			args[i] = sshconn.ShQuote(l)
		}
		parts = append(parts, `printf '%s\n' `+strings.Join(args, " "))
	}
	if last != "" {
		parts = append(parts, `printf '%s' `+sshconn.ShQuote(last))
	}
	if len(parts) == 0 {
		return `{ :; }`
	}
	return `{ ` + strings.Join(parts, "; ") + `; }`
}

// reseed puts srv's user back to f over that user's own connection. It
// removes every artifact a previous test or run left behind (.bak, .orig,
// temp, lock, the disabled authorized_keys2), so no test depends on run
// order. The trailing marker catches a forced command= left on the login
// key, which would otherwise turn the reseed into a silent no-op.
func reseed(t *testing.T, d *sshconn.Dialer, srv config.Server, f fixture) {
	t.Helper()
	put := func(name string, content *string) string {
		if content == nil {
			return `rm -f ` + name
		}
		return shPrint(*content) + ` > ` + name + `.new && mv -f ` + name + `.new ` + name
	}
	var b strings.Builder
	b.WriteString(`set -e; umask 077; cd "$HOME/.ssh"`)
	b.WriteString(`; rm -f authorized_keys` + bakSuffix + ` authorized_keys` + origSuffix + ` authorized_keys` + tmpSuffix + ` authorized_keys2` + fleet.Keys2DisabledSuffix)
	b.WriteString(`; rmdir authorized_keys` + lockSuffix + ` 2>/dev/null || :`)
	b.WriteString(`; ` + put("authorized_keys", f.keys) + `; ` + put("authorized_keys2", f.keys2))
	for _, c := range f.clear {
		b.WriteString(`; rm -rf "$HOME"/` + sshconn.ShQuote(c))
	}
	b.WriteString(`; echo reseeded`)
	if out := remoteOut(t, d, srv, b.String()); out != "reseeded\n" {
		t.Fatalf("reseed %s: output %q — a forced command on the login key?", srv.User, out)
	}
}

// TestIntegrationApplyWriteBackupVerify covers the drifted-seed protocol on
// one user in one ordered flow: write → byte-equal → 0600 → backup and the
// sticky original hold the pre-apply bytes → no temp/lock residue →
// idempotent re-apply rolls the backup and keeps the original.
func TestIntegrationApplyWriteBackupVerify(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itDrifted(t))})
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
	// The success path also proves busybox dd's conv=fsync flushes (WP-4)
	// do not fail the script, and that the CAS staging copy became .bak.
	if ls := remoteOut(t, w.Dialer, srv, `ls -a "$HOME/.ssh"`); strings.Contains(ls, tmpSuffix) || strings.Contains(ls, lockSuffix) || strings.Contains(ls, casSuffix) {
		t.Errorf("temp/lock/CAS residue in ~/.ssh: %q", ls)
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

// TestIntegrationOrigFollowsHeaderSerial: on real sshd and every distro's
// shell, a "(serial 9)" file takes no .orig, while a "(serial 07)" lookalike
// — not a managed header by ParseHeader's anchored definition — does.
func TestIntegrationOrigFollowsHeaderSerial(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	for _, tc := range []struct {
		first string
		orig  bool
	}{
		{authkeys.Header(9), false},
		{"# Managed by SSHepherd (serial 07). Manual edits will be overwritten by 'sshepherd apply'.", true},
	} {
		seed := tc.first + "\n" + itPub(t) + "\n"
		reseed(t, w.Dialer, srv, fixture{keys: strp(seed)})
		if err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t))); err != nil {
			t.Fatalf("Apply over %q: %v", tc.first, err)
		}
		got := remoteOut(t, w.Dialer, srv, `if [ -e "$HOME/.ssh/authorized_keys.sshepherd.orig" ]; then cat "$HOME/.ssh/authorized_keys.sshepherd.orig"; else echo absent; fi`)
		switch {
		case tc.orig && got != seed:
			t.Errorf("first line %q: .orig = %q, want the seeded bytes", tc.first, got)
		case !tc.orig && got != "absent\n":
			t.Errorf("first line %q: .orig = %q, want none", tc.first, got)
		}
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
	reseed(t, w.Dialer, srv, fixture{keys: strp(itDrifted(t))})
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
	reseed(t, w.Dialer, srv, fixture{keys2: strp(itPub(t) + "\n")})
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
	reseed(t, w.Dialer, srv, fixture{keys2: strp(itPub(t) + "\n"), clear: []string{"keys.d"}})
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
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
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
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	remoteOut(t, w.Dialer, srv, `mkdir "$HOME/.ssh/authorized_keys.sshepherd.lock"`)
	t.Cleanup(func() { remoteOut(t, w.Dialer, srv, `rmdir "$HOME/.ssh/authorized_keys.sshepherd.lock"`) })

	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t)))
	var locked *LockedError
	if !errors.As(err, &locked) {
		t.Fatalf("Apply = %v, want *LockedError", err)
	}
	if locked.Known || locked.Owner != ownerUnknown {
		t.Errorf("bare lock = %+v, want the unknown owner", locked)
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
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
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
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	// Large enough to span many channel packets.
	content := append(itRendered(t), bytes.Repeat([]byte("# padding padding padding padding\n"), 4000)...)
	w.exec = func(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
		if stdin != nil {
			stdin = &droppingReader{data: content[:len(content)/2], client: client}
		}
		return sshconn.Exec(ctx, client, cmd, stdin)
	}
	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content))
	if err == nil || !strings.Contains(err.Error(), "connection dropped before the rename; original untouched") {
		t.Fatalf("Apply over a dropped connection = %v, want the re-check's verdict", err)
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
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
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
	reseed(t, w.Dialer, srv, fixture{keys: strp(itDrifted(t))})
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
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys2`+fleet.Keys2DisabledSuffix+`"`); got != planted {
		t.Errorf("disabled copy = %q, want the planted file", got)
	}
}

// TestIntegrationSkipWrite: a keys2-only write against real sshd moves
// authorized_keys2 aside without touching authorized_keys, and a symlinked
// authorized_keys is refused with authorized_keys2 left in place.
func TestIntegrationSkipWrite(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	rendered := string(itRendered(t))
	line := testkeys.Line(t, 9) + " revoked@example"
	skipReq := func(t *testing.T) Request {
		t.Helper()
		req := itRequest(t, w.Dialer, srv, itRendered(t))
		req.DisableKeys2, req.SkipWrite = true, true
		return req
	}
	const present = `if [ -e "$HOME/.ssh/authorized_keys2" ]; then echo present; fi`
	t.Run("a plain file: only authorized_keys2 moves", func(t *testing.T) {
		reseed(t, w.Dialer, srv, fixture{keys: &rendered, keys2: strp(line + "\n")})
		if err := w.Apply(itCtx(t), srv, skipReq(t)); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		if out := remoteOut(t, w.Dialer, srv, present); strings.TrimSpace(out) != "" {
			t.Error("authorized_keys2 still in place")
		}
		if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != rendered {
			t.Errorf("file = %q", got)
		}
		if out := remoteOut(t, w.Dialer, srv, `if [ -e "$HOME/.ssh/authorized_keys`+bakSuffix+`" ]; then echo present; fi`); strings.TrimSpace(out) != "" {
			t.Error("a keys2-only write rotated the backup")
		}
	})
	t.Run("a symlinked file is refused and authorized_keys2 stays", func(t *testing.T) {
		reseed(t, w.Dialer, srv, fixture{keys: &rendered, keys2: strp(line + "\n")})
		const realFile = `"$HOME/.ssh/authorized_keys.real"`
		remoteOut(t, w.Dialer, srv, `cd "$HOME/.ssh" && mv authorized_keys authorized_keys.real && ln -s authorized_keys.real authorized_keys`)
		t.Cleanup(func() { remoteOut(t, w.Dialer, srv, `mv -f `+realFile+` "$HOME/.ssh/authorized_keys"`) })
		err := w.Apply(itCtx(t), srv, skipReq(t))
		var sym *SymlinkError
		if !errors.As(err, &sym) || !fleet.IsRefusal(err) {
			t.Fatalf("err = %v, want a symlink refusal", err)
		}
		if out := remoteOut(t, w.Dialer, srv, present); strings.TrimSpace(out) != "present" {
			t.Error("authorized_keys2 moved on a refused server")
		}
	})
}

// TestIntegrationOwnershipRefusals runs the write script's StrictModes-style
// owner checks (ancestorCheck, and writeCmdFor's directory and file checks)
// against real sshd fixtures.
// Each must refuse with *UnsafePathError and leave the target byte-identical,
// with no backup.
func TestIntegrationOwnershipRefusals(t *testing.T) {
	w, host, port := itWriter(t)
	tests := []struct{ name, user, akf string }{
		{"~/.ssh owned by root (directory check)", "fdir", ""},
		{"authorized_keys owned by root (file check)", "ffile", ""},
		{"ancestor owned by nobody (ancestor walk)", "fanc", "~/shared/keys/authorized_keys"},
		{"root writing into a user's directory", "root", "/home/rootvictim/.ssh/authorized_keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := config.Server{Name: tt.user, Host: host, Port: port, User: tt.user, AuthorizedKeysFile: tt.akf}
			path := tt.akf
			if path == "" {
				path = sshconn.DefaultAuthorizedKeysPath
			}
			cat := sshconn.PathAssign(path) + `; cat "$p" 2>/dev/null || :`
			lsDir := sshconn.PathAssign(path) + `; ls -a "$(dirname "$p")" 2>/dev/null || :`
			before := remoteOut(t, w.Dialer, srv, cat)
			err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t)))
			var uns *UnsafePathError
			if !errors.As(err, &uns) {
				t.Fatalf("Apply = %v, want *UnsafePathError", err)
			}
			if got := remoteOut(t, w.Dialer, srv, cat); got != before {
				t.Errorf("target = %q, want it byte-identical to %q", got, before)
			}
			if ls := remoteOut(t, w.Dialer, srv, lsDir); strings.Contains(ls, ".sshepherd.") {
				t.Errorf("ls = %q, a refused write leaves no backup, temp or lock", ls)
			}
		})
	}
}

// TestIntegrationLoginProbeHonorsWrittenOptions: the post-write probe
// against real sshd. A survivor line that sshd will force to /bin/true, or
// refuse by source address, is a lockout. The probe restores the
// byte-identical pre-write file. A restrict-only survivor still runs
// the probe command (negative control).
func TestIntegrationLoginProbeHonorsWrittenOptions(t *testing.T) {
	w, host, port := itWriter(t)
	pub := itPub(t)
	tests := []struct {
		name, user, line string
		lockout          bool
	}{
		{"forced command= fails the probe and restores", "probecmd", `command="/bin/true" ` + pub, true},
		{"from= the client cannot match fails the login and restores", "probefrom", `from="10.255.255.1" ` + pub, true},
		{"restrict alone passes the probe (negative control)", "probeok", `restrict ` + pub, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := config.Server{Name: tt.user, Host: host, Port: port, User: tt.user}
			reseed(t, w.Dialer, srv, fixture{keys: strp(pub + "\n")})
			before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
			content := []byte(authkeys.ManagedHeader + "\n" + tt.line + "\n")
			err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content))
			if !tt.lockout {
				if err != nil {
					t.Fatalf("Apply = %v, want success: restrict permits exec", err)
				}
				return // the next run's reseed puts the plain line back
			}
			var lo *LockoutError
			if !errors.As(err, &lo) || lo.Restore != nil {
				t.Fatalf("Apply = %v, want a restored *LockoutError", err)
			}
			if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != before {
				t.Errorf("file = %q, want the pre-write bytes %q", got, before)
			}
		})
	}
}

// TestIntegrationRefusalCreatesNoDirectory (WP-9): a write under a
// world-writable ancestor is refused before mkdir runs, so the missing
// directory is never created — "refusals change nothing" on a real server.
func TestIntegrationRefusalCreatesNoDirectory(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "wp9", Host: host, Port: port, User: "cas", AuthorizedKeysFile: "~/wp9/dot-ssh/authorized_keys"}
	remoteOut(t, w.Dialer, srv, `mkdir -p "$HOME/wp9" && chmod 777 "$HOME/wp9"`)
	t.Cleanup(func() { remoteOut(t, w.Dialer, srv, `rm -rf "$HOME/wp9"`) })
	req := Request{Content: itRendered(t), Expect: Snapshot{Absent: true}, Survivors: itSurvivors(t)}
	var uns *UnsafePathError
	if err := w.Apply(itCtx(t), srv, req); !errors.As(err, &uns) {
		t.Fatalf("Apply = %v, want *UnsafePathError", err)
	}
	if out := remoteOut(t, w.Dialer, srv, `if [ -e "$HOME/wp9/dot-ssh" ]; then echo created; fi`); strings.TrimSpace(out) != "" {
		t.Error("a refused write created ~/wp9/dot-ssh")
	}
}

// remoteTry is remoteOut for goroutines other than the test's: it returns
// the error instead of failing the test.
func remoteTry(d *sshconn.Dialer, srv config.Server, cmd string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := d.Connect(ctx, srv)
	if err != nil {
		return "", fmt.Errorf("connect %s: %w", srv.User, err)
	}
	defer func() { _ = conn.Close() }()
	code, stdout, stderr, err := sshconn.Exec(ctx, conn.Client, cmd, nil)
	if err != nil {
		return "", fmt.Errorf("exec %q: %w", cmd, err)
	}
	if code != 0 {
		return "", fmt.Errorf("exec %q: exit %d (stderr %q)", cmd, code, stderr.String())
	}
	return stdout.String(), nil
}

// editMidUpload delivers data[:half], then — before handing out another
// byte — runs edit once (the concurrent editor), then delivers the rest.
type editMidUpload struct {
	data   []byte
	half   int
	off    int
	edited bool
	edit   func() error

	mu  sync.Mutex
	err error
}

func (r *editMidUpload) Read(p []byte) (int, error) {
	if r.off == len(r.data) {
		return 0, io.EOF
	}
	if r.off == r.half && !r.edited {
		r.edited = true
		err := r.edit()
		r.mu.Lock()
		r.err = err
		r.mu.Unlock()
	}
	end := len(r.data)
	if r.off < r.half {
		end = r.half
	}
	n := copy(p, r.data[r.off:end])
	r.off += n
	return n, nil
}

func (r *editMidUpload) editErr() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// TestIntegrationConcurrentEditDuringUploadRefused (WP-3): a lock-less
// editor (ssh-copy-id, Ansible, a human) appends a key while the upload is
// in flight. The compare-and-swap runs after the upload, so the write is
// refused, the edit survives and the backup does not rotate. Before the
// fix the CAS ran before the upload: the write succeeded and the appended
// key vanished from both the file and the backup.
func TestIntegrationConcurrentEditDuringUploadRefused(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "cas", Host: host, Port: port, User: "cas"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	t.Cleanup(func() { reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")}) })
	before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	bak := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys`+bakSuffix+`" 2>/dev/null || true`)
	// ~130 KB: many channel packets, yet inside OpenSSH's 2 MB window — so
	// the reader must wait for the temp to fill before it edits.
	content := append(itRendered(t), bytes.Repeat([]byte("# padding padding padding padding\n"), 3800)...)
	half := len(content) / 2
	r := &editMidUpload{data: content, half: half, edit: func() error {
		deadline := time.Now().Add(10 * time.Second)
		for {
			out, err := remoteTry(w.Dialer, srv, `wc -c < "$HOME/.ssh/authorized_keys`+tmpSuffix+`" 2>/dev/null || echo 0`)
			if err != nil {
				return err
			}
			if n, _ := strconv.Atoi(strings.TrimSpace(out)); n >= half {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("upload temp never reached %d bytes (last %q)", half, strings.TrimSpace(out))
			}
			time.Sleep(50 * time.Millisecond)
		}
		_, err := remoteTry(w.Dialer, srv, `printf '# concurrent edit\n' >> "$HOME/.ssh/authorized_keys"`)
		return err
	}}
	w.exec = func(ctx context.Context, client *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error) {
		if stdin != nil {
			stdin = r
		}
		return sshconn.Exec(ctx, client, cmd, stdin)
	}
	req := itRequest(t, w.Dialer, srv, content)
	err := w.Apply(itCtx(t), srv, req)
	if e := r.editErr(); e != nil {
		t.Fatalf("concurrent editor: %v", e)
	}
	var chg *ChangedError
	if !errors.As(err, &chg) {
		t.Fatalf("Apply = %v, want *ChangedError (a key added mid-upload must refuse, not vanish)", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != before+"# concurrent edit\n" {
		t.Errorf("file = %q, want the concurrent edit kept", got)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys`+bakSuffix+`" 2>/dev/null || true`); got != bak {
		t.Errorf(".bak = %q, want it unchanged (%q): a refused write takes no backup", got, bak)
	}
}

// itKeyFile loads one of the harness's unencrypted headless key files
// (scripts/integration.sh: ci_old) as a held --identity key.
func itKeyFile(t *testing.T, name string) keyfile.Identity {
	t.Helper()
	dir := os.Getenv("SSHEPHERD_IT_KEYS")
	if dir == "" {
		t.Skip("integration env not set; run via make integration")
	}
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- harness key dir (SSHEPHERD_IT_KEYS)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return keyfile.Identity{Path: path, Fingerprint: ssh.FingerprintSHA256(signer.PublicKey()), Signer: signer}
}

// TestIntegrationProbeOrderMatchesNextRun (WP-5): the render lists a
// forced-command line first (for the key file, which the default signer
// order offers first) and a plain line second (the agent key); both keys
// are held. The probe offers the survivors in authkeys.OfferOrder, so it
// proves the plain key — and the next run, offering the same order, reads
// the real file instead of running the forced command.
func TestIntegrationProbeOrderMatchesNextRun(t *testing.T) {
	plain, host, port := itDialer(t) // agent only: its key stays a plain line, so reseed works
	srv := config.Server{Name: "cas", Host: host, Port: port, User: "cas"}
	reseed(t, plain, srv, fixture{keys: strp(itPub(t) + "\n")})
	t.Cleanup(func() { reseed(t, plain, srv, fixture{keys: strp(itPub(t) + "\n")}) })

	ci := itKeyFile(t, "ci_old")
	forced := `command="echo forced" ` + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ci.Signer.PublicKey())))
	content := []byte(authkeys.ManagedHeader + "\n" + forced + "\n" + itPub(t) + "\n")
	var desired []authkeys.Key
	for _, line := range []string{forced, itPub(t)} {
		k, err := authkeys.ParseLine(line)
		if err != nil || k == nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		desired = append(desired, *k)
	}
	order := authkeys.OfferOrder(desired)
	if len(order) != 2 || order[0] != itSurvivors(t)[0] {
		t.Fatalf("OfferOrder = %v, want the plain agent key first", order)
	}

	creds := &sshconn.Credentials{Files: []keyfile.Identity{ci}, AgentSock: os.Getenv("SSH_AUTH_SOCK")}
	w := &FleetWriter{Dialer: &sshconn.Dialer{KnownHostsPath: plain.KnownHostsPath, Creds: creds, DialTimeout: plain.DialTimeout}}
	req := itRequest(t, plain, srv, content)
	req.Survivors = order
	if err := w.Apply(itCtx(t), srv, req); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	next := &sshconn.Dialer{KnownHostsPath: plain.KnownHostsPath, Creds: creds, DialTimeout: plain.DialTimeout,
		PreferKeys: func(config.Server) []string { return order }}
	if got := remoteOut(t, next, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(content) {
		t.Errorf("next run read %q, want the written file (a forced command captured the session)", got)
	}
	// Control: without the offer order the key file goes first and its
	// forced command captures the session — the hazard this order prevents.
	unordered := &sshconn.Dialer{KnownHostsPath: plain.KnownHostsPath, Creds: creds, DialTimeout: plain.DialTimeout}
	if got := remoteOut(t, unordered, srv, `cat "$HOME/.ssh/authorized_keys"`); got != "forced\n" {
		t.Errorf("default order read %q, want %q — the control no longer exercises the hazard", got, "forced\n")
	}
}

// closedPort returns a TCP port on 127.0.0.1 nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// TestIntegrationProbeTransientKeepsFile: the write lands, every login
// check dial is refused: UNPROVEN, and the new file stays.
func TestIntegrationProbeTransientKeepsFile(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "probeok", Host: host, Port: port, User: "probeok"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	closed := closedPort(t)
	w.sleep = func(context.Context, time.Duration) error { return nil } // no 17 s of real waits
	w.connect = func(ctx context.Context, s config.Server, o sshconn.ConnectOptions) (*sshconn.Conn, error) {
		if len(o.Only) > 0 {
			s.Port = closed
		}
		return w.Dialer.ConnectWith(ctx, s, o)
	}
	content := itRendered(t)
	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content))
	var un *fleet.UnprovenError
	if !errors.As(err, &un) || un.Attempts != 4 || fleet.ErrorKindOf(err) != fleet.ErrorKindDial {
		t.Fatalf("Apply = %v, want UNPROVEN after 4 dial attempts", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(content) {
		t.Errorf("file = %q, want the new file kept", got)
	}
}

// TestIntegrationStaleLockReportsOwnerAndAge: a held lock's record reaches
// the refusal; the printed removal script clears it; nothing else does.
func TestIntegrationStaleLockReportsOwnerAndAge(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "locked", Host: host, Port: port, User: "locked"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	lock := `"$HOME/.ssh/authorized_keys.sshepherd.lock"`
	remoteOut(t, w.Dialer, srv, `mkdir `+lock+` && printf 'v1 ci-runner-3 4121 99 %s\n' "$(($(date +%s) - 192))" > `+lock+`/owner`)
	t.Cleanup(func() { remoteOut(t, w.Dialer, srv, `rm -f `+lock+`/owner; rmdir `+lock+` 2>/dev/null || :`) })

	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, itRendered(t)))
	var locked *LockedError
	if !errors.As(err, &locked) || !locked.Known || locked.Owner != "ci-runner-3 pid 4121" {
		t.Fatalf("Apply = %v, want a known *LockedError", err)
	}
	if locked.Age < 190*time.Second || locked.Age > 5*time.Minute {
		t.Errorf("Age = %v, want about 192s", locked.Age)
	}
	if !strings.Contains(locked.RemoveCmd, srv.User+"@"+srv.Host) {
		t.Errorf("RemoveCmd = %q", locked.RemoveCmd)
	}
	if out := remoteOut(t, w.Dialer, srv, `if [ -d `+lock+` ]; then echo held; fi`); strings.TrimSpace(out) != "held" {
		t.Fatal("the lock must never be removed automatically")
	}
	remoteOut(t, w.Dialer, srv, lockRemovalScript(sshconn.DefaultAuthorizedKeysPath))
	if out := remoteOut(t, w.Dialer, srv, `if [ -d `+lock+` ]; then echo held; fi`); strings.TrimSpace(out) == "held" {
		t.Error("the printed removal script did not clear the lock")
	}
}

// TestIntegrationKeys2DisabledNeverOverwritten: an earlier disabled copy
// survives the next disable, and the new copy gets its own name.
func TestIntegrationKeys2DisabledNeverOverwritten(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "writer", Host: host, Port: port, User: "writer"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itDrifted(t))})
	disabled := `"$HOME/.ssh/authorized_keys2` + fleet.Keys2DisabledSuffix + `"`
	t.Cleanup(func() {
		remoteOut(t, w.Dialer, srv, `rm -f "$HOME"/.ssh/authorized_keys2`+fleet.Keys2DisabledSuffix+`*`)
	})
	line := testkeys.Line(t, 9) + " revoked@example"
	remoteOut(t, w.Dialer, srv, `printf 'earlier\n' > `+disabled+` && printf '%s\n' '`+line+`' > "$HOME/.ssh/authorized_keys2"`)

	req := itRequest(t, w.Dialer, srv, itRendered(t))
	req.DisableKeys2 = true
	if err := w.Apply(itCtx(t), srv, req); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat `+disabled); got != "earlier\n" {
		t.Errorf("earlier copy = %q, want it kept", got)
	}
	ls := remoteOut(t, w.Dialer, srv, `ls -a "$HOME/.ssh"`)
	var stamped string
	for f := range strings.FieldsSeq(ls) {
		if name, ok := parseKeys2Name("sshepherd-keys2 " + f); ok && name != "" && name != "authorized_keys2"+fleet.Keys2DisabledSuffix {
			stamped = name
		}
	}
	if stamped == "" {
		t.Fatalf("no timestamped copy in %q", ls)
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/`+stamped+`"`); got != line+"\n" {
		t.Errorf("new copy = %q", got)
	}
}

// TestIntegrationProbeHostKeyChangedKeepsFileExits2: the login check meets
// a changed host key (its known_hosts records another key): UNPROVEN, not
// retried, the file kept, and the kind is one the exit-2 rule reads.
func TestIntegrationProbeHostKeyChangedKeepsFileExits2(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "probefrom", Host: host, Port: port, User: "probefrom"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	swappedFile := sshtest.KnownHostsFile(t, fmt.Sprintf("[%s]:%d %s", host, port, testkeys.Line(t, 7)))
	swapped := &sshconn.Dialer{KnownHostsPath: swappedFile, Creds: w.Dialer.Creds, DialTimeout: w.Dialer.DialTimeout}
	onlyDials := 0
	w.connect = func(ctx context.Context, s config.Server, o sshconn.ConnectOptions) (*sshconn.Conn, error) {
		if len(o.Only) > 0 {
			onlyDials++
			return swapped.ConnectWith(ctx, s, o)
		}
		return w.Dialer.ConnectWith(ctx, s, o)
	}
	content := itRendered(t)
	err := w.Apply(itCtx(t), srv, itRequest(t, w.Dialer, srv, content))
	var un *fleet.UnprovenError
	if !errors.As(err, &un) || !un.HostKey || onlyDials != 1 {
		t.Fatalf("Apply = %v, only dials = %d; want a host-key UNPROVEN with no retry", err, onlyDials)
	}
	if !fleet.HostKeyAlert(fleet.ErrorKindOf(err)) {
		t.Errorf("kind = %q, want one apply.ExitCode maps to 2", fleet.ErrorKindOf(err))
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(content) {
		t.Errorf("file = %q, want the new file kept", got)
	}
}

// TestIntegrationProbeMaxAuthTriesRestores: more refused survivors than
// sshd's MaxAuthTries: the disconnect is REJECTED, with no retry, and the
// previous file comes back.
func TestIntegrationProbeMaxAuthTriesRestores(t *testing.T) {
	w, host, port := itWriter(t)
	srv := config.Server{Name: "maxauth", Host: host, Port: port, User: "maxauth"}
	reseed(t, w.Dialer, srv, fixture{keys: strp(itPub(t) + "\n")})
	before := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`)
	var files []keyfile.Identity
	var survivors []string
	for i := byte(0); i < 4; i++ {
		k := sshtest.Key(100 + i)
		files = append(files, sshtest.Identity(t, "/k/refused", k))
		survivors = append(survivors, sshtest.Fingerprint(t, k))
	}
	agentFP := itSurvivors(t)[0]
	w.Dialer.Creds = &sshconn.Credentials{Files: files, AgentSock: os.Getenv("SSH_AUTH_SOCK")}
	w.Dialer.PreferKeys = func(config.Server) []string { return []string{agentFP} } // the write login must not exhaust MaxAuthTries
	onlyDials := 0
	w.connect = func(ctx context.Context, s config.Server, o sshconn.ConnectOptions) (*sshconn.Conn, error) {
		if len(o.Only) > 0 {
			onlyDials++
		}
		return w.Dialer.ConnectWith(ctx, s, o)
	}
	req := Request{Content: itRendered(t), Expect: itSnapshot(t, w.Dialer, srv), Survivors: survivors}
	err := w.Apply(itCtx(t), srv, req)
	var lo *LockoutError
	if !errors.As(err, &lo) || lo.Restore != nil || onlyDials != 1 {
		t.Fatalf("Apply = %v, only dials = %d; want a restored *LockoutError with no retry", err, onlyDials)
	}
	if !sshconn.AuthExhausted(lo.Probe) || fleet.ErrorKindOf(lo.Probe) != fleet.ErrorKindHandshake {
		t.Errorf("probe = %v (kind %q), want the MaxAuthTries signal", lo.Probe, fleet.ErrorKindOf(lo.Probe))
	}
	if got := remoteOut(t, w.Dialer, srv, `cat "$HOME/.ssh/authorized_keys"`); got != before {
		t.Errorf("file = %q, want the previous version restored", got)
	}
}

// TestIntegrationWriteThroughBastion: apply's whole write protocol, the
// login probe included, through container A to container C.
func TestIntegrationWriteThroughBastion(t *testing.T) {
	d, host, port := itDialer(t)
	bastion := config.Server{Name: "bastion-it", Host: host, Port: port, User: "jump", JumpOnly: true}
	d.Server = func(name string) (config.Server, bool) { return bastion, name == bastion.Name }
	tp, err := strconv.Atoi(os.Getenv("SSHEPHERD_IT_TARGET_PORT"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_TARGET_PORT: %v", err)
	}
	srv := config.Server{Name: "hopw-it", Host: os.Getenv("SSHEPHERD_IT_TARGET_HOST"), Port: tp, User: "hopw", Via: bastion.Name}
	reseed(t, d, srv, fixture{keys: strp(itDrifted(t))})
	w := &FleetWriter{Dialer: d}
	if err := w.Apply(itCtx(t), srv, itRequest(t, d, srv, itRendered(t))); err != nil {
		t.Fatalf("Apply through the bastion: %v", err)
	}
	if got := remoteOut(t, d, srv, `cat "$HOME/.ssh/authorized_keys"`); got != string(itRendered(t)) {
		t.Errorf("file = %q, want the render", got)
	}
}

// TestIntegrationForwardProbeOnBastion: writing a bastion probes a forward
// to a dependent: allowed keeps the write, AllowTcpForwarding no restores.
func TestIntegrationForwardProbeOnBastion(t *testing.T) {
	forward := net.JoinHostPort(os.Getenv("SSHEPHERD_IT_TARGET_HOST"), os.Getenv("SSHEPHERD_IT_TARGET_PORT"))
	for _, tt := range []struct {
		user     string
		restored bool
	}{
		{"jumpw", false},
		{"jumpnofwd", true},
	} {
		t.Run(tt.user, func(t *testing.T) {
			d, host, port := itDialer(t)
			srv := config.Server{Name: tt.user + "-it", Host: host, Port: port, User: tt.user}
			reseed(t, d, srv, fixture{keys: strp(itDrifted(t))})
			req := itRequest(t, d, srv, itRendered(t))
			req.ProbeForward = []string{forward}
			err := (&FleetWriter{Dialer: d}).Apply(itCtx(t), srv, req)
			var lockout *fleet.LockoutError
			switch {
			case tt.restored && (!errors.As(err, &lockout) || lockout.Restore != nil):
				t.Fatalf("Apply = %v, want a restored lockout", err)
			case !tt.restored && err != nil:
				t.Fatalf("Apply = %v, want success", err)
			}
			want := string(itRendered(t))
			if tt.restored {
				want = itDrifted(t)
			}
			if got := remoteOut(t, d, srv, `cat "$HOME/.ssh/authorized_keys"`); got != want {
				t.Errorf("file = %q, want %q", got, want)
			}
		})
	}
}
