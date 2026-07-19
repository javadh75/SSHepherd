// Package sshwrite performs apply's remote write protocol: symlink pre-check
// + backup, atomic temp+rename write, and read-back verify — three sessions
// over one SSH connection per server. Command builders are pure and share
// sshconn.PathAssign's quoting discipline (the path enters each script
// exactly once, fully quoted); only the network glue needs the integration
// suite, and even the protocol sequencing is unit-tested through seams.
package sshwrite

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// symlinkExit is the sentinel exit status the pre-check emits for a
// symlinked target (sibling of sshconn.FileAbsentExit, 44): mv would replace
// the link with a regular file, silently diverging what SSHepherd reads from
// what sshd may read, and breaking config-management setups.
const symlinkExit = 45

// precheckCmdFor builds the remote pre-check: refuse a symlinked target
// (exit 45), then back up an existing file with cp -p — single generation,
// overwritten per apply; an absent file needs no backup.
func precheckCmdFor(path string) string {
	return sshconn.PathAssign(path) +
		`; if [ -L "$p" ]; then exit 45; fi; if [ -e "$p" ]; then cp -p "$p" "$p".sshepherd.bak; fi`
}

// writeCmdFor builds the atomic write (the exact script from the apply
// spec). umask 077 pins the temp file to 0600 before a byte is written;
// rm -f + set -C (noclobber) guarantee cat creates a fresh file — never
// truncating through a pre-existing file or symlink at the predictable temp
// name; mv in the same directory is an atomic rename, so sshd never
// observes a partial file; failure leaves the original untouched and
// removes the temp. mkdir -p covers first-contact servers (for the default
// path it creates ~/.ssh with 0700 thanks to the umask). Content arrives on
// stdin — key material is never shell-encoded.
func writeCmdFor(path string) string {
	return sshconn.PathAssign(path) +
		`; umask 077; d=$(dirname "$p"); mkdir -p "$d"; t="$p".sshepherd.tmp; rm -f "$t"; (set -C; cat > "$t") && mv "$t" "$p" || { rm -f "$t"; exit 1; }`
}

// SymlinkError reports a refused write: the target path is a symlink. The
// operator points authorized_keys_file at the real target if writing
// through was the intent.
type SymlinkError struct{ Path string }

func (e *SymlinkError) Error() string {
	return fmt.Sprintf("%s is a symlink — refusing to replace it with a regular file (point authorized_keys_file at the real target if intended)", e.Path)
}

// FleetWriter applies rendered authorized_keys content to servers over SSH.
// It is apply's Writer seam implementation.
type FleetWriter struct {
	Dialer *sshconn.Dialer
	Log    *slog.Logger // optional stage-level telemetry; nil discards

	// Test seams; nil selects the real implementations.
	connect func(ctx context.Context, srv config.Server) (*sshconn.Conn, error)
	exec    func(client *ssh.Client, cmd string, stdin io.Reader) (int, *sshconn.CappedBuffer, *sshconn.CappedBuffer, error)
}

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (w *FleetWriter) log() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.New(slog.DiscardHandler)
}

// Apply makes srv's authorized_keys equal content: pre-check + backup,
// atomic write (content on stdin), then read-back verify (byte-compare —
// trusting mv's exit status would leave silent-corruption blind spots for
// the cost of one extra cat). Any error means the server did not verifiably
// converge; a *SymlinkError specifically means the write was refused before
// any change. All errors pass the sanitized-error path: remote text never
// reaches a terminal raw.
func (w *FleetWriter) Apply(ctx context.Context, srv config.Server, content []byte) error {
	connect := w.connect
	if connect == nil {
		connect = w.Dialer.Connect
	}
	execCmd := w.exec
	if execCmd == nil {
		execCmd = sshconn.Exec
	}

	conn, err := connect(ctx, srv)
	if err != nil {
		return sshconn.SanitizedError{Err: err}
	}
	defer func() { _ = conn.Close() }() // errcheck: close error is uninteresting after the verify verdict

	path := srv.AuthorizedKeysFile
	if path == "" {
		path = sshconn.DefaultAuthorizedKeysPath
	}
	log := w.log()

	// Stage 1: symlink refusal + single-generation backup.
	code, _, stderr, err := execCmd(conn.Client, precheckCmdFor(path), nil)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("pre-check on %s: %w", srv.Name, err)}
	}
	if code == symlinkExit {
		return &SymlinkError{Path: path}
	}
	if code != 0 {
		return stageFailure("pre-check", srv.Name, code, stderr)
	}
	log.Debug("pre-check ok", "server", srv.Name)

	// Stage 2: atomic write, rendered bytes on stdin.
	code, _, stderr, err = execCmd(conn.Client, writeCmdFor(path), bytes.NewReader(content))
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("write on %s: %w", srv.Name, err)}
	}
	if code != 0 {
		return stageFailure("write", srv.Name, code, stderr)
	}
	log.Debug("write ok", "server", srv.Name, "bytes", len(content))

	// Stage 3: verify — re-read through the existing read command and
	// byte-compare against the render.
	code, stdout, stderr, err := execCmd(conn.Client, sshconn.AuthorizedKeysCmdFor(path), nil)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("verify on %s: %w", srv.Name, err)}
	}
	res, err := sshconn.FinishRead(code, stdout, stderr, srv.Name, log)
	if err != nil {
		return sshconn.SanitizedError{Err: fmt.Errorf("verify on %s: %w", srv.Name, err)}
	}
	if res.FileAbsent {
		return fmt.Errorf("verify on %s: file absent after write", srv.Name)
	}
	if !bytes.Equal(res.Content, content) {
		return fmt.Errorf("verify on %s: file bytes differ from the rendered desired state", srv.Name)
	}
	log.Debug("verify ok", "server", srv.Name)
	return nil
}

// stageFailure wraps a nonzero remote exit with its sanitized stderr.
func stageFailure(stage, server string, code int, stderr *sshconn.CappedBuffer) error {
	return fmt.Errorf("%s on %s failed (exit %d): %s",
		stage, server, code, strings.TrimSpace(sshconn.SanitizeRemote(stderr.String())))
}
