package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

type staticWriter struct{ err error }

func (w staticWriter) Apply(context.Context, config.Server, fleet.WriteRequest) error { return w.err }

// useWriter makes every write of the run return err.
func useWriter(t *testing.T, err error) {
	t.Helper()
	saved := newWriter
	newWriter = func(*sshconn.Dialer, *slog.Logger) apply.Writer { return staticWriter{err: err} }
	t.Cleanup(func() { newWriter = saved })
}

var (
	errRefusedLogin  = errors.New("ssh: unable to authenticate")
	lockoutError     = &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errRefusedLogin, Restore: errors.New("restore failed")}
	rolledBackError  = &fleet.LockoutError{Path: "~/.ssh/authorized_keys", Probe: errRefusedLogin}
	hostKeyChanged   = &fleet.UnprovenError{Path: "~/.ssh/authorized_keys", Attempts: 1, HostKey: true, Last: &sshconn.Error{Kind: fleet.ErrorKindHostKeyChanged, Err: errors.New("host key changed")}}
	unprovenDialFail = &fleet.UnprovenError{Path: "~/.ssh/authorized_keys", Attempts: 4, Last: &sshconn.Error{Kind: fleet.ErrorKindDial, Err: errors.New("dial timeout")}}
)

// applyDrift is a hermetic fleet with one unauthorized key installed (seed
// 9), and the manifest extended by extra; it returns the plain apply args.
func applyDrift(t *testing.T, extra string) []string {
	t.Helper()
	home := shortHome(t)
	srv, hostKey, cfg := hermeticFleet(t, home)
	kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))
	target := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(target, append(fileBytes(t, target), []byte(testkeys.Line(t, 9)+" stray\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, append(fileBytes(t, cfg), extra...), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"apply", "--yes", "--config", cfg, "--known-hosts", kh}
}

func revokedNine(t *testing.T) string {
	t.Helper()
	return "revoked:\n  - {fingerprint: \"" + fpOf(t, 9) + "\", date: \"2026-11-01\"}\n"
}

type failDoc struct {
	Summary struct {
		ExitCode int `json:"exit_code"`
	} `json:"summary"`
	Servers []struct {
		Outcome             string   `json:"outcome"`
		ErrorKind           string   `json:"error_kind"`
		RestoredRevokedKeys []string `json:"restored_revoked_keys"`
	} `json:"servers"`
}

// runApplyFailure runs a plain apply in text, then in JSON, and checks the
// exit and the document. One fleet serves both: the static writer changes
// nothing on the server, so the first run's serial bump (saved once) leaves
// the second run planning the same write.
func runApplyFailure(t *testing.T, args []string, want int) (string, failDoc) {
	t.Helper()
	var out, errBuf bytes.Buffer
	if code := run(args, &out, &errBuf); code != want {
		t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, want, out.String(), errBuf.String())
	}
	text := out.String()
	out.Reset()
	if code := run(append([]string{args[0], "--json"}, args[1:]...), &out, &errBuf); code != want {
		t.Fatalf("--json exit = %d, want %d\n%s", code, want, errBuf.String())
	}
	var doc failDoc
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	if doc.Summary.ExitCode != want {
		t.Errorf("summary.exit_code = %d, want %d", doc.Summary.ExitCode, want)
	}
	return text, doc
}

func TestApplyLockoutUnrestoredExits2(t *testing.T) {
	useWriter(t, lockoutError)
	text, doc := runApplyFailure(t, applyDrift(t, ""), 2)
	if !strings.Contains(text, "LOCKOUT — NOT RESTORED:") || doc.Servers[0].Outcome != "lockout_unrestored" {
		t.Errorf("text:\n%s\ndoc: %+v", text, doc)
	}
}

func TestApplyRollbackRestoresRevokedKeyExits2(t *testing.T) {
	useWriter(t, rolledBackError)
	text, doc := runApplyFailure(t, applyDrift(t, revokedNine(t)), 2)
	if !strings.Contains(text, "on the revoked: list") || len(doc.Servers[0].RestoredRevokedKeys) != 1 {
		t.Errorf("text:\n%s\ndoc: %+v", text, doc)
	}
}

func TestApplyRollbackOfOrdinaryKeyExits1(t *testing.T) {
	useWriter(t, rolledBackError)
	text, _ := runApplyFailure(t, applyDrift(t, ""), 1)
	if !strings.Contains(text, "it still grants") || strings.Contains(text, "on the revoked: list") {
		t.Errorf("text:\n%s", text)
	}
}

func TestApplyProbeHostKeyChangedExits2(t *testing.T) {
	useWriter(t, hostKeyChanged)
	_, doc := runApplyFailure(t, applyDrift(t, ""), 2)
	if doc.Servers[0].Outcome != "unproven" || doc.Servers[0].ErrorKind != "host_key_changed" {
		t.Errorf("doc: %+v", doc)
	}
}

func TestApplyUnprovenDialExits1(t *testing.T) {
	useWriter(t, unprovenDialFail)
	text, _ := runApplyFailure(t, applyDrift(t, ""), 1)
	if !strings.Contains(text, "UNPROVEN:") {
		t.Errorf("text:\n%s", text)
	}
}

// TestRevokeRotateFailureExits covers the shared run body: an edit that
// saves its manifest needs a fresh fleet per run.
func TestRevokeRotateFailureExits(t *testing.T) {
	cmds := map[string]func(t *testing.T) []string{
		"revoke": func(t *testing.T) []string {
			_, kh, cfg := twoUserFleet(t)
			return []string{"revoke", "bob", "--yes", "--config", cfg, "--known-hosts", kh}
		},
		"rotate": func(t *testing.T) []string {
			_, kh, cfg := twoUserFleet(t)
			return []string{"rotate", "bob", "--old", fpOf(t, 2), "--new", writePub(t, "n.pub", testkeys.Line(t, 5)), "--yes", "--config", cfg, "--known-hosts", kh}
		},
	}
	for cmdName, argsFor := range cmds {
		for _, tt := range []struct {
			name string
			err  error
			want int
		}{
			{"lockout not restored", lockoutError, 2},
			{"rollback put back a revoked key", rolledBackError, 2},
			{"host key changed at the login check", hostKeyChanged, 2},
			{"unproven", unprovenDialFail, 1},
		} {
			t.Run(cmdName+"/"+tt.name, func(t *testing.T) {
				useWriter(t, tt.err)
				var out, errBuf bytes.Buffer
				if code := run(argsFor(t), &out, &errBuf); code != tt.want {
					t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.want, out.String(), errBuf.String())
				}
				out.Reset()
				if code := run(append(argsFor(t), "--json"), &out, &errBuf); code != tt.want {
					t.Fatalf("--json exit = %d, want %d\n%s", code, tt.want, errBuf.String())
				}
				var doc failDoc
				if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Summary.ExitCode != tt.want {
					t.Errorf("doc = %+v (%v)\n%s", doc, err, out.String())
				}
			})
		}
	}
}
