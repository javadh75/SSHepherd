// Package sshdmodel is a small Go model of how OpenSSH's sshd reads one
// authorized_keys line (review F009): a line-by-line port of
// auth2-pubkeyfile.c's auth_check_authkey_line, sshkey.c's sshkey_read and
// sshkey_advance_past_options, b64_pton and auth-options.c's
// sshauthopt_parse. It is deliberately written apart from
// internal/authkeys, so it can be that package's differential oracle:
// FuzzParseLine and FuzzCheckOption must agree with it, and the real-sshd
// grammar test (cmd/sshepherd TestE2ESSHDGrammar) checks it against sshd.
// No production code imports it.
//
// The verdict is about the line's grammar: whether sshd reads a key and its
// options from it. What a line then permits at login is not judged here
// (cert-authority, principals=, from=, a passed expiry-time=, command=).
//
// Known limits, all deliberate:
//   - A port that is not a number is read only when it is one of the TCP
//     service names every services database carries (macOS, Alpine, Rocky,
//     Debian netbase): real sshd asks getservbyname, which only the server's
//     /etc/services can answer (a host with no such file refuses them all).
//   - expiry-time= uses Go's calendar check, like internal/authkeys; sshd's
//     strptime is laxer about impossible dates, and sshd also refuses a
//     time equal to the epoch.
//   - ssh-dss is read, as sshd before 10.0 does.
package sshdmodel

import (
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Verdict is sshd's reading of one line.
type Verdict struct {
	Accepted    bool
	Reason      string // why sshd skips the line ("" when accepted)
	Fingerprint string // SHA256 fingerprint of the line's key, when accepted
}

// Accepts reports whether sshd reads a key and valid options from line.
func Accepts(line string) bool { return Read(line).Accepted }

// Read is auth_check_authkey_line for one line, without its newline.
func Read(line string) Verdict {
	s := cstr(line)
	cp := skipSpace(s, 0)
	if cp == len(s) || s[cp] == '\n' || s[cp] == '#' {
		return Verdict{Reason: "blank or comment"}
	}
	pub, err := sshkeyRead(s[cp:])
	options := ""
	if err != "" {
		options = s[cp:]
		end, ok := advancePastOptions(options)
		if !ok {
			return Verdict{Reason: "invalid key option string"}
		}
		next := skipSpace(options, end)
		if pub, err = sshkeyRead(options[next:]); err != "" {
			return Verdict{Reason: err}
		}
	}
	if reason := ParseOptions(options); reason != "" {
		return Verdict{Reason: "bad key options: " + reason}
	}
	return Verdict{Accepted: true, Fingerprint: ssh.FingerprintSHA256(pub)}
}

// cstr is s up to its first NUL.
func cstr(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}

// skipSpace returns i advanced past spaces and tabs.
func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return i
}

// strcspn is the length of s's prefix with no space or tab.
func strcspn(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			return i
		}
	}
	return len(s)
}

// sshkeyRead is sshkey_read: "" on success.
func sshkeyRead(cp string) (ssh.PublicKey, string) {
	space := strcspn(cp)
	if space == len(cp) {
		return nil, "invalid format"
	}
	typ, curve := lookupName(cp[:space])
	if typ == keyUnspec {
		return nil, "invalid format"
	}
	rest := cp[skipSpace(cp, space):]
	if rest == "" {
		return nil, "invalid format"
	}
	blob, ok := b64pton(rest[:strcspn(rest)])
	if !ok {
		return nil, "invalid format"
	}
	pub, err := ssh.ParsePublicKey(blob)
	if err != nil {
		return nil, "invalid key blob"
	}
	if got, gotCurve := lookupName(pub.Type()); got != typ || gotCurve != curve {
		return nil, "key type mismatch"
	}
	return pub, ""
}

// advancePastOptions is sshkey_advance_past_options.
func advancePastOptions(s string) (end int, ok bool) {
	quoted := false
	i := 0
	for i < len(s) && (quoted || (s[i] != ' ' && s[i] != '\t')) {
		if s[i] == '\\' && i+1 < len(s) && s[i+1] == '"' {
			i++ // skip both
		} else if s[i] == '"' {
			quoted = !quoted
		}
		i++
	}
	return i, !quoted
}

const pad64 = '='

var base64Index = func() (t [256]int16) {
	for i := range t {
		t[i] = -1
	}
	for i, c := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/") {
		t[c] = int16(i) // #nosec G115 -- i is below 64
	}
	return t
}()

func isspace(c byte) bool {
	return c == ' ' || (c >= '\t' && c <= '\r')
}

// b64pton is OpenBSD's b64_pton: whitespace is skipped anywhere, padding
// must be correct, and the spare bits of a padded group must be zero.
func b64pton(src string) ([]byte, bool) {
	var out []byte
	state, i := 0, 0
	var ch byte
	for {
		if i >= len(src) {
			ch = 0
			break
		}
		ch = src[i]
		i++
		if isspace(ch) {
			continue
		}
		if ch == pad64 {
			break
		}
		pos := base64Index[ch]
		if pos < 0 {
			return nil, false
		}
		out, state = b64group(out, state, byte(pos)) // #nosec G115 -- pos is 0-63
	}
	if ch != pad64 {
		return out, state == 0
	}
	return b64padding(out, state, src, i)
}

// b64group adds one 6-bit value to out; a trailing partial byte is kept at
// the end of out until the next value completes it (as in the C target).
func b64group(out []byte, state int, v byte) ([]byte, int) {
	switch state {
	case 0:
		return append(out, v<<2), 1
	case 1:
		out[len(out)-1] |= v >> 4
		return append(out, v<<4), 2
	case 2:
		out[len(out)-1] |= v >> 2
		return append(out, v<<6), 3
	default:
		out[len(out)-1] |= v
		return out, 0
	}
}

// b64padding checks what follows the first pad character (src[i-1]).
func b64padding(out []byte, state int, src string, i int) ([]byte, bool) {
	if state < 2 {
		return nil, false
	}
	if state == 2 {
		for i < len(src) && isspace(src[i]) {
			i++
		}
		if i >= len(src) || src[i] != pad64 {
			return nil, false
		}
		i++
	}
	for ; i < len(src); i++ {
		if !isspace(src[i]) {
			return nil, false
		}
	}
	if out[len(out)-1] != 0 {
		return nil, false // non-zero spare bits
	}
	return out[:len(out)-1], true
}

// ParseOptions is sshauthopt_parse over an options string (it stops at the
// first space or tab outside a value): "" when sshd accepts it, else its
// error. A flag it does not name is "unknown key option" there too.
func ParseOptions(opts string) string {
	p := optParser{s: cstr(opts)}
	for !p.atEnd() {
		if !p.flag() {
			if reason := p.valued(); reason != "" {
				return reason
			}
		}
		if p.atEnd() {
			break
		}
		if p.s[p.i] != ',' {
			return "unknown key option"
		}
		p.i++
		if p.i >= len(p.s) {
			return "unexpected end-of-options"
		}
	}
	return ""
}

type optParser struct {
	s       string
	i       int
	seen    map[string]bool
	envs    map[string]bool // distinct environment= names
	permits map[string]int  // permitopen=/permitlisten= clauses
}

func (p *optParser) atEnd() bool {
	return p.i >= len(p.s) || p.s[p.i] == ' ' || p.s[p.i] == '\t'
}

// flag consumes one flag option; false when none matches.
func (p *optParser) flag() bool {
	// allow_negate as opt_flag's second argument, in sshauthopt_parse's order
	for _, f := range []struct {
		name   string
		negate bool
	}{
		{"restrict", false}, {"cert-authority", false}, {"port-forwarding", true}, {"agent-forwarding", true},
		{"x11-forwarding", true}, {"touch-required", true}, {"verify-required", true}, {"pty", true}, {"user-rc", true},
	} {
		if p.optFlag(f.name, f.negate) {
			return true
		}
	}
	return false
}

func hasPrefixFold(s, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if lower(s[i]) != lower(prefix[i]) {
			return false
		}
	}
	return true
}

func lower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}

// optFlag is opt_flag: an optional "no-" (when allowed), then name as a
// case-insensitive prefix. What follows is judged by the caller's loop.
func (p *optParser) optFlag(name string, allowNegate bool) bool {
	i := p.i
	if allowNegate && hasPrefixFold(p.s[i:], "no-") {
		i += 3
	}
	if hasPrefixFold(p.s[i:], name) {
		p.i = i + len(name)
		return true
	}
	return false
}

// optMatch is opt_match: name then '='.
func (p *optParser) optMatch(name string) bool {
	if !hasPrefixFold(p.s[p.i:], name) || p.i+len(name) >= len(p.s) || p.s[p.i+len(name)] != '=' {
		return false
	}
	p.i += len(name) + 1
	return true
}

// dequote is opt_dequote: the value, \" as ", ending at its first unescaped quote.
func (p *optParser) dequote() (string, string) {
	if p.i >= len(p.s) || p.s[p.i] != '"' {
		return "", "missing start quote"
	}
	i := p.i + 1
	var b strings.Builder
	for i < len(p.s) && p.s[i] != '"' {
		if p.s[i] == '\\' && i+1 < len(p.s) && p.s[i+1] == '"' {
			i++
		}
		b.WriteByte(p.s[i])
		i++
	}
	if i >= len(p.s) {
		return "", "missing end quote"
	}
	p.i = i + 1
	return b.String(), ""
}

// valued consumes one option of the name="value" form; it leaves p alone
// when none matches, and the caller's loop then judges the byte there (only
// a comma passes: an empty clause).
func (p *optParser) valued() string {
	for _, once := range []string{"command", "principals", "from"} {
		if p.optMatch(once) {
			if p.seen[once] {
				return `multiple "` + once + `" clauses`
			}
			if p.seen == nil {
				p.seen = map[string]bool{}
			}
			p.seen[once] = true
			_, reason := p.dequote()
			return reason
		}
	}
	for _, c := range []struct {
		name  string
		check func(string) string
	}{
		{"expiry-time", checkExpiry},
		{"environment", checkEnvironment},
		{"permitopen", func(v string) string { return checkPermit(v, false) }},
		{"permitlisten", func(v string) string { return checkPermit(v, true) }},
		{"tunnel", checkTunnel},
	} {
		if p.optMatch(c.name) {
			v, reason := p.dequote()
			if reason != "" {
				return reason
			}
			if reason := c.check(v); reason != "" {
				return reason
			}
			return p.count(c.name, v)
		}
	}
	return ""
}

// count applies sshd's per-line limits, as measured on OpenSSH 10.5p1:
// at most 1025 distinct environment= names (first match wins, so a repeat
// is not counted) and 4097 clauses of each of permitopen=/permitlisten=.
func (p *optParser) count(name, v string) string {
	switch name {
	case "environment":
		if p.envs == nil {
			p.envs = map[string]bool{}
		}
		p.envs[v[:strings.IndexByte(v, '=')]] = true
		if len(p.envs) > 1025 {
			return "too many environment strings"
		}
	case "permitopen", "permitlisten":
		if p.permits == nil {
			p.permits = map[string]int{}
		}
		p.permits[name]++
		if p.permits[name] > 4097 {
			return "too many permission directives"
		}
	}
	return ""
}

func isalnum(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// checkEnvironment: valid_env_name over the part before '='.
func checkEnvironment(v string) string {
	eq := strings.IndexByte(v, '=')
	if eq <= 0 {
		return "invalid environment string"
	}
	for i := 0; i < eq; i++ {
		if c := v[i]; !isalnum(c) && c != '_' {
			return "invalid environment string"
		}
	}
	return ""
}

// checkPermit is handle_permit; allowBarePort is permitlisten.
func checkPermit(v string, allowBarePort bool) string {
	if allowBarePort && !strings.Contains(v, ":") {
		v = "*:" + v
	}
	host, port, hasPort, ok := hpdelim2(v)
	if !ok || len(host) >= 1025 {
		return "invalid permission hostname"
	}
	if !hasPort || (port != "*" && a2port(port) <= 0) {
		return "invalid permission port"
	}
	return ""
}

// hpdelim2 splits host from port at a ':' or '/' after the host; a host in
// brackets is taken whole. ok is false for a malformed bracket form.
func hpdelim2(v string) (host, port string, hasPort, ok bool) {
	s := 0
	if strings.HasPrefix(v, "[") {
		end := strings.IndexByte(v, ']')
		if end < 0 {
			return "", "", false, false
		}
		s = end + 1
	} else if s = strings.IndexAny(v, ":/"); s < 0 {
		return v, "", false, true
	}
	if s == len(v) {
		return v, "", false, true
	}
	if v[s] != ':' && v[s] != '/' {
		return "", "", false, false
	}
	return v[:s], v[s+1:], true, true
}

// a2port is a2port: the number 0-65535, or the port of a known service
// name (getservbyname, matched case-sensitively), else -1.
func a2port(s string) int64 {
	n, ok := strtonum(s, 0, 65535)
	if ok {
		return n
	}
	if port, ok := services[s]; ok {
		return port
	}
	return -1
}

// services are the TCP names (and aliases) every services database carries.
var services = map[string]int64{
	"domain": 53, "ftp": 21, "ftp-data": 20, "ftps": 990, "git": 9418, "http": 80, "https": 443,
	"imap": 143, "imaps": 993, "kerberos": 88, "ldap": 389, "ldaps": 636, "mysql": 3306,
	"nntp": 119, "pop3": 110, "pop3s": 995, "postgresql": 5432, "rsync": 873, "smtp": 25,
	"socks": 1080, "ssh": 22, "submission": 587, "telnet": 23, "www": 80,
}

// checkTunnel is a2tun: "any" (any case) or a number up to SSH_TUNID_MAX.
func checkTunnel(v string) string {
	if len(v) == 3 && hasPrefixFold(v, "any") {
		return ""
	}
	if _, ok := strtonum(v, 0, 0x7ffffffd); !ok {
		return "invalid tun device"
	}
	return ""
}

// strtonum is OpenBSD's strtonum over base-10 strtoll.
func strtonum(s string, lo, hi int64) (int64, bool) {
	i := 0
	for i < len(s) && isspace(s[i]) {
		i++
	}
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start || i != len(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s[start:i], 10, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, n >= lo && n <= hi
}

// checkExpiry: see the package comment.
func checkExpiry(v string) string {
	t := v
	switch {
	case len(t) > 3 && hasPrefixFold(t[len(t)-3:], "utc"):
		t = t[:len(t)-3]
	case len(t) > 1 && (t[len(t)-1] == 'z' || t[len(t)-1] == 'Z'):
		t = t[:len(t)-1]
	}
	layout := map[int]string{8: "20060102", 12: "200601021504", 14: "20060102150405"}[len(t)]
	if layout == "" {
		return "invalid expires time"
	}
	if _, err := time.Parse(layout, t); err != nil {
		return "invalid expires time"
	}
	return ""
}

// keyType is OpenSSH's KEY_* enum.
type keyType int

const (
	keyUnspec keyType = iota
	keyRSA
	keyDSA
	keyECDSA
	keyED25519
	keyECDSASK
	keyED25519SK
	keyRSACert
	keyDSACert
	keyECDSACert
	keyED25519Cert
	keyECDSASKCert
	keyED25519SKCert
)

// impl is one row of sshkey.c's keyimpls table: a name sshkey_read accepts,
// its key type and curve. Short names (ED25519, RSA) are not listed: OpenSSH
// 10.5's sshkey_read refuses them as type tokens, though releases long
// before it matched them in any case.
type impl struct {
	name string
	typ  keyType
	nid  int
}

var keyimpls = []impl{
	{"ssh-ed25519", keyED25519, -1},
	{"ssh-ed25519-cert-v01@openssh.com", keyED25519Cert, -1},
	{"sk-ssh-ed25519@openssh.com", keyED25519SK, -1},
	{"sk-ssh-ed25519-cert-v01@openssh.com", keyED25519SKCert, -1},
	{"ecdsa-sha2-nistp256", keyECDSA, 256},
	{"ecdsa-sha2-nistp256-cert-v01@openssh.com", keyECDSACert, 256},
	{"ecdsa-sha2-nistp384", keyECDSA, 384},
	{"ecdsa-sha2-nistp384-cert-v01@openssh.com", keyECDSACert, 384},
	{"ecdsa-sha2-nistp521", keyECDSA, 521},
	{"ecdsa-sha2-nistp521-cert-v01@openssh.com", keyECDSACert, 521},
	{"sk-ecdsa-sha2-nistp256@openssh.com", keyECDSASK, -1},
	{"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com", keyECDSASKCert, -1},
	{"webauthn-sk-ecdsa-sha2-nistp256@openssh.com", keyECDSASK, -1},
	{"ssh-dss", keyDSA, -1},
	{"ssh-dss-cert-v01@openssh.com", keyDSACert, -1},
	{"ssh-rsa", keyRSA, -1},
	{"ssh-rsa-cert-v01@openssh.com", keyRSACert, -1},
	{"rsa-sha2-256", keyRSA, -1},
	{"rsa-sha2-256-cert-v01@openssh.com", keyRSACert, -1},
	{"rsa-sha2-512", keyRSA, -1},
	{"rsa-sha2-512-cert-v01@openssh.com", keyRSACert, -1},
}

// lookupName is sshkey_type_from_name, with the name's curve: a key's type
// on the line and in its blob both resolve here.
func lookupName(name string) (keyType, int) {
	for _, k := range keyimpls {
		if name == k.name {
			return k.typ, k.nid
		}
	}
	return keyUnspec, -1
}
