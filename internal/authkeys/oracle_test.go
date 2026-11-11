package authkeys

import (
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys/sshdmodel"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// agreeWithSSHD fails t when ParseLine plus IgnoredBySSHD disagrees with the
// sshd model about line (review F009): whether sshd reads a key and valid
// options from it, and which key.
func agreeWithSSHD(t *testing.T, line string) {
	t.Helper()
	if strings.ContainsRune(line, '\n') {
		return // one line only: ParseFile splits at newlines
	}
	k, err := ParseLine(line)
	ours := err == nil && k != nil && IgnoredBySSHD(k.Options) == nil
	v := sshdmodel.Read(line)
	if ours != v.Accepted {
		t.Errorf("line %q: ParseLine = (%+v, %v), IgnoredBySSHD says %v; sshd model: accepted=%v (%s)",
			line, k, err, ours, v.Accepted, v.Reason)
		return
	}
	if ours && k.Fingerprint != v.Fingerprint {
		t.Errorf("line %q: fingerprint %s, sshd model %s", line, k.Fingerprint, v.Fingerprint)
	}
}

// oneClause reports whether opt, written in front of key, is exactly one
// option clause, by ParseLine's split.
func oneClause(opt, key string) bool {
	k, err := ParseLine(opt + " " + key)
	return err == nil && k != nil && len(k.Options) == 1 && k.Options[0] == opt
}

// optionAgreesWithSSHD fails t when CheckOption or IgnoredBySSHD disagrees
// with the sshd model about one option written in front of key: CheckOption's
// yes implies sshd's, and on one clause IgnoredBySSHD and sshd say the same.
func optionAgreesWithSSHD(t *testing.T, opt, key string) {
	t.Helper()
	line := opt + " " + key
	if strings.ContainsRune(line, '\n') {
		return
	}
	accepted := sshdmodel.Accepts(line)
	if CheckOption(opt) == "" && !accepted {
		t.Errorf("CheckOption accepts %q, sshd model skips the line: %s", opt, sshdmodel.Read(line).Reason)
	}
	if oneClause(opt, key) && (IgnoredBySSHD([]string{opt}) == nil) != accepted {
		t.Errorf("option %q: IgnoredBySSHD = %v, sshd model accepted = %v", opt, IgnoredBySSHD([]string{opt}), accepted)
	}
}

// sshdGrammarLines are the lines of findings F002, F003 and F025, plain and
// hostile: the oracle's seeds.
func sshdGrammarLines(tb testing.TB) []string {
	tb.Helper()
	line := testkeys.Line(tb, 9)
	typ, blob := strings.Fields(line)[0], strings.Fields(line)[1]
	rsa := testkeys.RSALine(tb, 3, 3072)
	rsaBlob := strings.Fields(rsa)[1]
	out := []string{
		line, line + " carol",
		typ + " " + blob + "\x00junk attacker",
		typ + " " + blob + " carol\x00junk",
		typ + " " + blob[:30] + "\v" + blob[30:] + " carol",
		typ + " " + blob[:30] + "\f" + blob[30:],
		typ + " " + blob[:30] + "\r" + blob[30:],
		typ + "\v" + blob, "\v" + line, "\u00a0" + line, line + "\u00a0",
		"ED25519 " + blob, "ed25519 " + blob, "RSA " + rsaBlob, "rsa-sha2-256 " + rsaBlob, "ECDSA " + blob,
		"ssh-rsa " + rsaBlob[:len(rsaBlob)-2] + "B=", // non-zero spare bits
		", " + line, "no-pty, " + line, ",,no-pty,, " + line,
		`command="a` + "\x00" + `" ` + line,
		"restr\u0130ct " + line,           // U+0130 is not i to strcasecmp
		`command="a \" b",no-pty ` + line, // an escaped quote, then a comma outside quotes
		"ed25519-s\u212a " + blob,
	}
	for _, opt := range sshdGrammarOptions() {
		out = append(out, opt+" "+line)
	}
	return out
}

// sshdGrammarOptions are the option values of F003 and F025, good and bad.
func sshdGrammarOptions() []string {
	return []string{
		`permitopen="db:22"`, `permitopen="db:*"`, `permitopen="db"`, `permitopen="db:0"`, `permitopen="db:65536"`,
		`permitopen="[::1]:22"`, `permitopen="[::1"`, `permitopen="db/22"`, `permitopen="db:ssh"`,
		`permitopen="` + strings.Repeat("h", 1024) + `:22"`, `permitopen="` + strings.Repeat("h", 1025) + `:22"`,
		`permitlisten="8080"`, `permitlisten="*"`, `permitlisten="nope"`, `permitlisten="host:80"`,
		`environment="FOO=1"`, `environment="FOO"`, `environment="=x"`, `environment="F-O=1"`,
		`tunnel="1"`, `tunnel="any"`, `tunnel="ANY"`, `tunnel="abc"`, `tunnel="2147483646"`,
		"touch-required", "no-touch-required", "verify-required", "no-verify-required",
		"no-restrict", "no-cert-authority", "bogus-opt", `expiry-time="20990101"`, `expiry-time="2027"`,
		`command="\"x\""`, `command="a"b`, `from="a",pty`, "no-pty,", "NO-PTY",
		// Repair round: service names, strtonum's whitespace and signs, the
		// env name's alphabet edges, a bracketed host with no port.
		`permitopen="db:https"`, `permitopen="db:nope"`, `permitopen="db:SSH"`, `permitopen="[::1]"`,
		`permitopen="db: 22"`, `tunnel=" 5"`, `tunnel="-0"`, `tunnel="++5"`, `tunnel="anyx"`,
		`environment="_A=1"`, `environment="Zz9=1"`, "environment=\"\x80=1\"",
	}
}

// TestSSHDModelAgreesOnGrammarLines runs the fuzz oracles over the findings'
// lines on every go test.
func TestSSHDModelAgreesOnGrammarLines(t *testing.T) {
	for _, line := range sshdGrammarLines(t) {
		agreeWithSSHD(t, line)
	}
	key := testkeys.Line(t, 9)
	for _, opt := range sshdGrammarOptions() {
		optionAgreesWithSSHD(t, opt, key)
	}
}
