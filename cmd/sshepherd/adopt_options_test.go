package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// COR-1/TST-2: one server line sshd would ignore used to fail adopt's
// self-check ("bug: generated manifest fails validation", exit 3) even
// under --partial. It is now an unreadable-line issue: strict exit 1,
// --partial writes a valid manifest without that line.
func TestAdoptServerLineWithBadOption(t *testing.T) {
	for _, prefix := range []string{"no-ptty ", "from=1.2.3.4 "} {
		t.Run(strings.TrimSpace(prefix), func(t *testing.T) {
			home := shortHome(t)
			srv, hostKey, cfg := hermeticFleet(t, home)
			ak := filepath.Join(home, ".ssh", "authorized_keys")
			f, err := os.OpenFile(ak, os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString(prefix + testkeys.Line(t, 7) + " carol@laptop\n")
			_ = f.Close()
			kh := sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey))

			var out, errBuf bytes.Buffer
			code := run([]string{"adopt", "--config", cfg, "--known-hosts", kh}, &out, &errBuf)
			if code != 1 || strings.Contains(errBuf.String(), "bug:") {
				t.Fatalf("strict exit = %d, want 1 without 'bug:'\nstderr: %s", code, errBuf.String())
			}
			if !strings.Contains(errBuf.String(), "sshd ignores this line: option ") || out.Len() != 0 {
				t.Errorf("stderr = %q stdout = %q, want the issue and no manifest", errBuf.String(), out.String())
			}

			for _, extra := range [][]string{nil, {"--merge"}} {
				out.Reset()
				errBuf.Reset()
				args := append([]string{"adopt", "--config", cfg, "--known-hosts", kh, "--partial"}, extra...)
				if code := run(args, &out, &errBuf); code != 0 {
					t.Fatalf("%v exit = %d, want 0\nstderr: %s", args, code, errBuf.String())
				}
				if _, err := config.Parse(out.Bytes()); err != nil {
					t.Errorf("%v: stdout is not a valid manifest: %v", args, err)
				}
				if strings.Contains(out.String(), "carol") {
					t.Errorf("%v: the ignored line was adopted:\n%s", args, out.String())
				}
			}
		})
	}
}
