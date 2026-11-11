//go:build integration

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/authkeys/sshdmodel"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// grammarAccount is the fixture account whose authorized_keys this test
// rewrites: it holds only the stale key, and no E2E logs in to it. Root (the
// agent key) does the rewriting, so a line sshd skips cannot lock the test
// out, and writing through the existing file keeps its owner and mode.
const (
	grammarAccount = "rootvictim"
	grammarFile    = "/home/" + grammarAccount + "/.ssh/authorized_keys"
	grammarProof   = "LOGIN_OK"
)

// grammarRow is one authorized_keys line. accepted is what the review's
// real-sshd runs recorded for it, so a row that stops exercising its case
// (a typo that makes sshd skip it for another reason) still fails.
type grammarRow struct {
	name     string
	line     string
	accepted bool
}

// grammarRows is the ground-truth table for reviews F002, F003 and F025:
// lines x/crypto refuses but sshd reads, option values sshd refuses, and
// option names only one polarity of which used to be known.
func grammarRows(keyType, blob string) []grammarRow {
	key := keyType + " " + blob
	withOption := func(opt string) string { return opt + " " + key + " grammar" }
	inBlob := func(sep string) string { return keyType + " " + blob[:30] + sep + blob[30:] + " grammar" }
	return []grammarRow{
		// F002: how sshd reads the key field.
		{"plain", key + " grammar", true},
		{"nul after blob", key + "\x00junk attacker", true},
		{"vt inside blob", inBlob("\v"), true},
		{"ff inside blob", inBlob("\f"), true},
		{"cr inside blob", inBlob("\r"), true},
		{"truncated blob", keyType + " " + blob[:len(blob)-8] + " grammar", false},

		// F003: option values, bad and good.
		{"permitopen no port", withOption(`permitopen="db"`), false},
		{"permitopen port zero", withOption(`permitopen="db:0"`), false},
		{"permitopen host and port", withOption(`permitopen="db:5432"`), true},
		{"permitopen any port", withOption(`permitopen="db:*"`), true},
		{"permitlisten not a port", withOption(`permitlisten="nope"`), false},
		{"permitlisten bare port", withOption(`permitlisten="8080"`), true},
		{"permitlisten host and port", withOption(`permitlisten="localhost:8080"`), true},
		{"environment no equals", withOption(`environment="FOO"`), false},
		{"environment bad name", withOption(`environment="F-O=1"`), false},
		{"environment name and value", withOption(`environment="FOO=1"`), true},
		{"tunnel not a number", withOption(`tunnel="abc"`), false},
		{"tunnel number", withOption(`tunnel="1"`), true},
		{"tunnel any", withOption(`tunnel="any"`), true},
		{"nul inside quoted value", withOption("environment=\"FOO=1\x00\""), false},

		// F025: both polarities of the sk flags; unknown names stay refused.
		{"touch-required", withOption("touch-required"), true},
		{"no-touch-required", withOption("no-touch-required"), true},
		{"verify-required", withOption("verify-required"), true},
		{"no-verify-required", withOption("no-verify-required"), true},
		{"no-restrict", withOption("no-restrict"), false},
		{"unknown option", withOption("bogus-opt"), false},
	}
}

// TestE2ESSHDGrammar pins SSHepherd's reading of an authorized_keys line to
// the distro's real sshd: each line is installed as the account's only line
// and a real login with that key decides. sshd's verdict must equal the sshd
// model (the fuzz oracle) and what the production parser reports.
func TestE2ESSHDGrammar(t *testing.T) {
	keys := itKeys(t)
	host, kh := os.Getenv("SSHEPHERD_IT_HOST"), os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS")
	portText := os.Getenv("SSHEPHERD_IT_PORT")
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PORT: %v", err)
	}
	stale := strings.Fields(itPubLine(t, keys, "stale"))
	ids, err := keyfile.Load(t.Context(), []keyfile.Spec{{Path: filepath.Join(keys, "stale")}}, keyfile.Passphrases{}, nil, keyfile.OSFS{}, nil)
	if err != nil {
		t.Fatalf("load the stale key: %v", err)
	}
	want, err := authkeys.ParseLine(stale[0] + " " + stale[1])
	if err != nil || want == nil {
		t.Fatalf("stale key: %v", err)
	}
	remote := func(t *testing.T, script string) string { return e2eRemote(t, host, portText, kh, "root", script) }
	original := remote(t, "cat "+grammarFile)
	defer remote(t, grammarInstall(original))

	login := grammarDialer{host: host, port: port, knownHosts: kh, ids: ids}
	for _, row := range grammarRows(stale[0], stale[1]) {
		t.Run(row.name, func(t *testing.T) {
			content := row.line + "\n"
			remote(t, grammarInstall(content))
			if got := remote(t, "cat "+grammarFile); got != content {
				t.Fatalf("installed bytes differ:\ngot  %q\nwant %q", got, content)
			}
			sshd := login.accepts(t)
			if sshd != row.accepted {
				t.Errorf("real sshd accepted = %v, the table says %v for %q", sshd, row.accepted, row.line)
			}
			model := sshdmodel.Read(row.line)
			if model.Accepted != sshd {
				t.Errorf("sshd model accepted = %v (%s), real sshd %v for %q", model.Accepted, model.Reason, sshd, row.line)
			}
			if sshd && model.Fingerprint != want.Fingerprint {
				t.Errorf("sshd model fingerprint = %s, want %s", model.Fingerprint, want.Fingerprint)
			}
			if got, why := grammarParserAccepts(content, want.Fingerprint); got != sshd {
				t.Errorf("parser accepted = %v (%s), real sshd %v for %q", got, why, sshd, row.line)
			}
		})
	}
}

// grammarInstall is a one-line script writing content over the fixture file
// in place. Every byte is an octal escape: the script stays one line with no
// quoting to get wrong, and printf puts the NUL, VT, FF and CR on the file.
func grammarInstall(content string) string {
	var format strings.Builder
	for i := range len(content) {
		fmt.Fprintf(&format, `\%03o`, content[i])
	}
	return "printf '" + format.String() + "' > " + grammarFile
}

// grammarParserAccepts is the production verdict on an installed file: the
// parser audit and apply use yields exactly the expected key, on a line
// IgnoredBySSHD says sshd honors.
func grammarParserAccepts(content, fingerprint string) (bool, string) {
	got, errs := authkeys.ParseFile([]byte(content))
	if len(errs) > 0 {
		return false, errs[0].Error()
	}
	if len(got) != 1 {
		return false, fmt.Sprintf("%d keys", len(got))
	}
	if got[0].Fingerprint != fingerprint {
		return false, "fingerprint " + got[0].Fingerprint
	}
	if err := authkeys.IgnoredBySSHD(got[0].Options); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// grammarDialer logs in to the fixture account with the stale key alone.
type grammarDialer struct {
	host       string
	port       int
	knownHosts string
	ids        []keyfile.Identity
}

// accepts reports whether sshd let the key in and ran a command. sshd
// refusing the key is the "no" answer; any other failure says nothing about
// the line, so it fails the test.
func (d grammarDialer) accepts(t *testing.T) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	dialer := &sshconn.Dialer{KnownHostsPath: d.knownHosts, Creds: &sshconn.Credentials{Files: d.ids}, DialTimeout: 10 * time.Second}
	conn, err := dialer.Connect(ctx, config.Server{Name: grammarAccount, Host: d.host, Port: d.port, User: grammarAccount})
	if err != nil {
		if fleet.ErrorKindOf(err) == fleet.ErrorKindAuth {
			return false
		}
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	code, stdout, stderr, err := sshconn.Exec(ctx, conn.Client, "echo "+grammarProof, nil)
	if err != nil || code != 0 || strings.TrimSpace(stdout.String()) != grammarProof {
		t.Fatalf("login ran no command: code %d, err %v, stderr %q", code, err, execStderr(stderr))
	}
	return true
}
