package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
	"github.com/javadh75/SSHepherd/internal/workflow"
)

// TestClassifySweepUnprovable: a file with a line the parser refuses
// cannot prove the removal (sshd may read that line), a read a Ctrl-C cut
// short is not "unreachable" and not counted as checked, and a per-server
// timeout stays unreachable.
func TestClassifySweepUnprovable(t *testing.T) {
	bob := mustKey(t, 2)
	tombs := []config.Tombstone{{Fingerprint: bob.Fingerprint, User: "bob", Date: "2026-11-08"}}
	parse := []authkeys.ParseError{{Line: 2, Err: errors.New("embedded carriage return")}}
	results := []audit.ServerResult{
		{Server: config.Server{Name: "db-1"}, ParseErrs: parse},
		{Server: config.Server{Name: "db-2"}, ParseErrs: parse, Diff: authkeys.Result{Unauthorized: []authkeys.Key{bob}}},
		{Server: config.Server{Name: "db-3"}, Err: fmt.Errorf("not read: %w", context.Canceled)},
		{Server: config.Server{Name: "db-4"}, Err: fmt.Errorf("not read: %w", context.DeadlineExceeded)},
	}
	got := classifySweep(results, tombs)
	want := apply.SweepReport{
		Checked:        3,
		StillInstalled: []apply.SweepHit{{Server: "db-2", Fingerprint: bob.Fingerprint, User: "bob", File: "authorized_keys"}},
		Unreachable:    []string{"db-4"},
		Unprovable: []apply.SweepUnprovable{
			{Server: "db-1", Reason: sweepUnparsed},
			{Server: "db-2", Reason: sweepUnparsed},
			{Server: "db-3", Reason: sweepInterrupted},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("report = %+v\nwant   %+v", got, want)
	}
}

// TestRevokeSweepUnparseableLineExit1 (SEC-2): the revoked key on a line
// the parser refuses must not read as "no revoked key found".
func TestRevokeSweepUnparseableLineExit1(t *testing.T) {
	hosts, kh, cfg := sweepFleet(t)
	hosts["web-2"].install(t, []byte{1}, testkeys.Line(t, 2)+" bob\rlaptop")
	var out, errBuf bytes.Buffer
	if code := run([]string{"revoke", "bob", "--sweep", "--yes", "--config", cfg, "--known-hosts", kh}, &out, &errBuf); code != 1 {
		t.Fatalf("exit = %d, want 1\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !strings.Contains(out.String(), "cannot prove removal on web-2 ("+sweepUnparsed+")\n") {
		t.Errorf("stdout:\n%s", out.String())
	}
}

// interruptedRun is a confirmed, saved run whose sweep sees a canceled
// context: two servers neither written nor read.
func interruptedRun(t *testing.T) (*cobra.Command, editPlan, *fleetSession) {
	t.Helper()
	cfg, err := config.Parse([]byte("users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: web-1, host: h1, user: u}\n  - {name: web-2, host: h2, user: u}\n" +
		"access:\n  - {user: alice, servers: [web-1, web-2]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &cobra.Command{Use: "revoke"}
	cmd.SetContext(ctx)
	ep := editPlan{former: cfg, edited: cfg, summary: apply.EditSummary{
		Revoked: []config.Tombstone{{Fingerprint: mustKey(t, 2).Fingerprint, User: "bob", Date: "2026-11-08"}},
	}}
	return cmd, ep, &fleetSession{log: slog.New(slog.DiscardHandler), parallel: 2}
}

// TestEditFinishInterruptedSweepKeepsReport (SEC-2): a Ctrl-C reaching the
// sweep comes after the manifest was saved and servers written, so it is
// exit 1 with the report, never exit 3 with none.
func TestEditFinishInterruptedSweepKeepsReport(t *testing.T) {
	cmd, ep, sess := interruptedRun(t)
	out := workflow.Outcome{Stage: workflow.StageConfirmed, Saved: true}
	var stdout bytes.Buffer
	finish := editFinish(cmd, &stdout, sess.log, &editFlags{sweep: true}, ep, apply.AffectedSet{}, followUp{}, apply.RenderOptions{}, nil)
	if err := finish(out, sess); !errors.Is(err, errNonCompliant) {
		t.Fatalf("err = %v, want exit 1 (errNonCompliant)", err)
	}
	for _, want := range []string{"cannot prove removal on web-1 (sweep interrupted)\n", "cannot prove removal on web-2 (sweep interrupted)\n", "swept 0 of 2 servers"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("stdout lacks %q:\n%s", want, stdout.String())
		}
	}

	var got *apply.SweepReport
	doc := func(_ []apply.ServerPlan, _ bool, sweep *apply.SweepReport) error {
		got = sweep
		return nil
	}
	finish = editFinish(cmd, &stdout, sess.log, &editFlags{sweep: true}, ep, apply.AffectedSet{}, followUp{}, apply.RenderOptions{}, doc)
	if err := finish(out, sess); !errors.Is(err, errNonCompliant) {
		t.Fatalf("--json: err = %v, want exit 1 (a document is written)", err)
	}
	if got == nil || len(got.Unprovable) != 2 || got.Checked != 0 {
		t.Errorf("--json sweep = %+v, want two unprovable servers, none checked", got)
	}
}

// TestRepeatRevokeSweepStillSweeps (SEC-2): a repeated revoke --sweep that
// names an already-revoked key looks for it again; exit 0 here would be
// "all clear" while the key is installed. Without a finding it is the
// usual D1c exit 0, and --dry-run still contacts nothing.
func TestRepeatRevokeSweepStillSweeps(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"user", []string{"bob"}},
		{"key", []string{"--key", "FP"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hosts, kh, cfg := sweepFleet(t)
			args := make([]string, 0, len(tc.args))
			for _, a := range tc.args {
				if a == "FP" {
					a = fpOf(t, 2)
				}
				args = append(args, a)
			}
			revoke := append(append([]string{"revoke"}, args...), "--sweep", "--yes", "--config", cfg, "--known-hosts", kh)
			var out, errBuf bytes.Buffer
			if code := run(revoke, &out, &errBuf); code != 2 {
				t.Fatalf("first run: exit %d\n%s\n%s", code, out.String(), errBuf.String())
			}

			out.Reset()
			if code := run(revoke, &out, &errBuf); code != 2 {
				t.Fatalf("repeat: exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
			}
			for _, want := range []string{"was already revoked", "REVOKED KEY STILL INSTALLED: bob " + fpOf(t, 2) + " on web-2", "swept 2 of 2 servers: 1 still has a revoked key, 0 unreachable\n"} {
				if !strings.Contains(out.String(), want) {
					t.Errorf("repeat stdout lacks %q:\n%s", want, out.String())
				}
			}

			out.Reset()
			if code := run(append(revoke, "--json"), &out, &errBuf); code != 2 {
				t.Fatalf("--json repeat: exit = %d, want 2\n%s\n%s", code, out.String(), errBuf.String())
			}
			var doc struct {
				Sweep *apply.SweepReport `json:"sweep"`
			}
			if err := json.Unmarshal(out.Bytes(), &doc); err != nil || doc.Sweep == nil || len(doc.Sweep.StillInstalled) != 1 {
				t.Fatalf("--json document %s: %v", out.String(), err)
			}

			attempts := len(hosts["web-2"].srv.Attempts())
			out.Reset()
			dry := append(append([]string{"revoke"}, args...), "--sweep", "--dry-run", "--config", cfg, "--known-hosts", kh)
			if code := run(dry, &out, &errBuf); code != 0 {
				t.Fatalf("--dry-run repeat: exit %d\n%s\n%s", code, out.String(), errBuf.String())
			}
			if len(hosts["web-2"].srv.Attempts()) != attempts || strings.Contains(out.String(), "swept ") {
				t.Errorf("--dry-run repeat swept:\n%s", out.String())
			}

			hosts["web-2"].install(t, []byte{1})
			out.Reset()
			if code := run(revoke, &out, &errBuf); code != 0 || !strings.Contains(out.String(), "swept 2 of 2 servers: 0 still have a revoked key, 0 unreachable\n") {
				t.Errorf("clean repeat: exit %d\n%s\n%s", code, out.String(), errBuf.String())
			}
		})
	}
}

// TestRevokeSweepPreflightBeforeSave (SEC-2): on the save-only path a
// missing known_hosts is exit 3 with nothing saved; if the save came first,
// the retry would be a D1b no-op that never sweeps.
func TestRevokeSweepPreflightBeforeSave(t *testing.T) {
	_, _, cfg := sweepFleet(t)
	before := fileBytes(t, cfg)
	missing := filepath.Join(t.TempDir(), "absent")
	var out, errBuf bytes.Buffer
	code := run([]string{"revoke", "--key", fpOf(t, 7), "--sweep", "--yes", "--json", "--config", cfg, "--known-hosts", missing}, &out, &errBuf)
	if code != 3 || !strings.Contains(errBuf.String(), "known_hosts preflight") || out.Len() != 0 {
		t.Fatalf("exit = %d, want 3 with no document\n%s\n%s", code, out.String(), errBuf.String())
	}
	if !bytes.Equal(fileBytes(t, cfg), before) {
		t.Error("the manifest was saved before the sweep's preflight failed")
	}
}
