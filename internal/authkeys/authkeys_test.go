package authkeys

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// deterministicKeyLine builds a valid ssh-ed25519 authorized_keys entry from a
// fixed seed. Public keys are not secret, so a hard-coded seed is fine and keeps
// the test hermetic and reproducible.
func deterministicKeyLine() (string, error) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), nil
}

func testKeyLine(t *testing.T) string {
	t.Helper()
	line, err := deterministicKeyLine()
	if err != nil {
		t.Fatalf("deterministicKeyLine: %v", err)
	}
	return line
}

func TestParseLineValidKey(t *testing.T) {
	got, err := ParseLine(testKeyLine(t))
	if err != nil {
		t.Fatalf("ParseLine returned error: %v", err)
	}
	if got == nil {
		t.Fatal("ParseLine returned nil for a valid line")
	}
	if got.Type != "ssh-ed25519" {
		t.Errorf("Type = %q, want ssh-ed25519", got.Type)
	}
	if !strings.HasPrefix(got.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint = %q, want SHA256: prefix", got.Fingerprint)
	}
}

func TestParseLineComment(t *testing.T) {
	got, err := ParseLine(testKeyLine(t) + " alice@laptop")
	if err != nil {
		t.Fatalf("ParseLine returned error: %v", err)
	}
	if got.Comment != "alice@laptop" {
		t.Errorf("Comment = %q, want alice@laptop", got.Comment)
	}
}

func TestParseLineOptions(t *testing.T) {
	got, err := ParseLine("no-port-forwarding,no-agent-forwarding " + testKeyLine(t))
	if err != nil {
		t.Fatalf("ParseLine returned error: %v", err)
	}
	want := []string{"no-port-forwarding", "no-agent-forwarding"}
	if len(got.Options) != len(want) {
		t.Fatalf("Options = %v, want %v", got.Options, want)
	}
	for i := range want {
		if got.Options[i] != want[i] {
			t.Errorf("Options[%d] = %q, want %q", i, got.Options[i], want[i])
		}
	}
}

func TestParseLineBlankAndComment(t *testing.T) {
	for _, line := range []string{"", "   ", "\t", "# a comment", "   # indented comment"} {
		got, err := ParseLine(line)
		if err != nil {
			t.Errorf("ParseLine(%q) error = %v, want nil", line, err)
		}
		if got != nil {
			t.Errorf("ParseLine(%q) = %+v, want nil", line, got)
		}
	}
}

func TestParseLineGarbage(t *testing.T) {
	if _, err := ParseLine("this is not a key"); err == nil {
		t.Error("ParseLine(garbage) error = nil, want error")
	}
}

// TestParseLineDeclaredTypeMismatch pins the KEY_TYPE_MISMATCH rule: sshd
// skips a line whose type token disagrees with the blob, so ParseLine must
// reject it rather than report a key that cannot log in. The declared token
// is found after the options field, quotes (with embedded spaces and
// escaped quotes) included.
func TestParseLineDeclaredTypeMismatch(t *testing.T) {
	blob := strings.Fields(testKeyLine(t))[1]
	tests := []struct {
		name, line string
		wantErr    bool
	}{
		{"matching bare", "ssh-ed25519 " + blob, false},
		{"matching with options", `no-pty,command="a b" ssh-ed25519 ` + blob + " c", false},
		{"matching with escaped quote", `command="echo \"x y\"" ssh-ed25519 ` + blob, false},
		{"matching tab separated", "no-pty\tssh-ed25519\t" + blob, false},
		{"cert type over plain blob", "ssh-ed25519-cert-v01@openssh.com " + blob, true},
		{"rsa type over ed25519 blob", "ssh-rsa " + blob + " alice", true},
		{"mismatch after options", `from="10.0.0.0/8" ssh-rsa ` + blob, true},
		{"arbitrary type token", "garbage " + blob, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := ParseLine(tt.line)
			if tt.wantErr {
				// Either layer may reject (x/crypto >= v0.56 or our own
				// declared-type check); the contract is rejection.
				if err == nil || k != nil {
					t.Errorf("ParseLine(%q) = (%v, %v), want a rejection", tt.line, k, err)
				}
				return
			}
			if err != nil || k == nil || k.Type != "ssh-ed25519" {
				t.Errorf("ParseLine(%q) = (%v, %v), want an ssh-ed25519 key", tt.line, k, err)
			}
		})
	}
}

func TestParseFileMixed(t *testing.T) {
	line := testKeyLine(t)
	data := []byte("# header comment\n\n" + line + " alice@laptop\ngarbage line here\n" + line + "\n")
	keys, errs := ParseFile(data)
	if len(keys) != 2 {
		t.Fatalf("keys = %d, want 2", len(keys))
	}
	if keys[0].Comment != "alice@laptop" {
		t.Errorf("keys[0].Comment = %q, want alice@laptop", keys[0].Comment)
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly 1", errs)
	}
	if errs[0].Line != 4 {
		t.Errorf("errs[0].Line = %d, want 4 (1-based)", errs[0].Line)
	}
	if !strings.Contains(errs[0].Error(), "line 4") {
		t.Errorf("Error() = %q, want it to mention line 4", errs[0].Error())
	}
}

// A parse error's message reflects bytes from the remote file; Error() must
// strip control characters so a malicious host cannot inject terminal escape
// sequences into operator-facing output. The hostile line embeds its escape
// bytes in the wire blob's algorithm name — x/crypto formats that name
// verbatim into "ssh: unknown key algorithm: ...".
func TestParseErrorStripsControlBytes(t *testing.T) {
	algo := "ssh-\x1b[31mevil\x07"
	blob := make([]byte, 4+len(algo))
	binary.BigEndian.PutUint32(blob, uint32(len(algo)))
	copy(blob[4:], algo)
	line := "ssh-rsa " + base64.StdEncoding.EncodeToString(blob)
	_, errs := ParseFile([]byte(line + "\n"))
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly 1", errs)
	}
	msg := errs[0].Error()
	if strings.ContainsAny(msg, "\x1b\x07") {
		t.Errorf("Error() = %q, must not contain control bytes", msg)
	}
	if !strings.Contains(msg, "line 1") {
		t.Errorf("Error() = %q, want it to still mention line 1", msg)
	}
}

// stripControl must also drop DEL and C1 controls (not just C0): a
// UTF-8-encoded C1 CSI (U+009B) is honored like ESC [ by some terminals.
func TestStripControlDELAndC1(t *testing.T) {
	got := stripControl("a\x7fbc\nd\te")
	if got != "abc\nd\te" {
		t.Errorf("stripControl = %q, want %q", got, "abc\nd\te")
	}
	if got := stripControl("a\u009bb"); got != "ab" {
		t.Errorf("stripControl(C1 CSI) = %q, want %q", got, "ab")
	}
	// A raw (non-UTF-8) C1 byte is not valid UTF-8 on its own; strings.Map
	// decodes it as U+FFFD and passes it through, safely, but unpinned until
	// now.
	if got := stripControl("a\x9bb"); got != "a\ufffdb" {
		t.Errorf("stripControl(raw C1 byte) = %q, want %q", got, "a\ufffdb")
	}
	// Bidi/format (Cf) runes can visually reorder or hide error text in a
	// terminal; they carry no meaning in authorized_keys content, so drop them.
	if got := stripControl("user\u202eevil\u202c"); got != "userevil" {
		t.Errorf("stripControl(bidi override) = %q, want %q", got, "userevil")
	}
}

func TestParseFileEmpty(t *testing.T) {
	keys, errs := ParseFile(nil)
	if len(keys) != 0 || len(errs) != 0 {
		t.Errorf("ParseFile(nil) = %d keys, %d errs; want 0, 0", len(keys), len(errs))
	}
}

func TestParseFileCRLF(t *testing.T) {
	data := []byte(testKeyLine(t) + "\r\n")
	keys, errs := ParseFile(data)
	if len(errs) != 0 {
		t.Fatalf("CRLF input produced errors: %v", errs)
	}
	if len(keys) != 1 {
		t.Fatalf("keys = %d, want 1", len(keys))
	}
}

// An embedded carriage return is a hostile line break: written back out it
// would split into two lines, smuggling an extra key past review. It must be
// a parse error, not something that survives into Key.Raw or the comment.
func TestParseLineEmbeddedCR(t *testing.T) {
	line := testKeyLine(t) + " alice@laptop\r" + testKeyLine(t)
	k, err := ParseLine(line)
	if err == nil || !strings.Contains(err.Error(), "carriage return") {
		t.Errorf("ParseLine(embedded CR) = (%v, %v), want a carriage-return error", k, err)
	}
}

// In a file, the embedded CR must surface as a ParseError with the right
// line number, hitting the strict/--partial gate like any other bad line.
func TestParseFileEmbeddedCR(t *testing.T) {
	data := []byte(testKeyLine(t) + "\n" + testKeyLine(t) + " bob\rhidden\n")
	keys, errs := ParseFile(data)
	if len(keys) != 1 {
		t.Errorf("keys = %d, want 1 (only the clean line)", len(keys))
	}
	if len(errs) != 1 {
		t.Fatalf("errs = %v, want exactly one ParseError", errs)
	}
	if errs[0].Line != 2 {
		t.Errorf("ParseError.Line = %d, want 2", errs[0].Line)
	}
}

func mustKey(t *testing.T, line string) Key {
	t.Helper()
	k, err := ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("mustKey(%q): %v", line, err)
	}
	return *k
}

func TestDiff(t *testing.T) {
	a := mustKey(t, testKeyLine(t))      // in both
	b := mustKey(t, testkeys.Line(t, 2)) // desired only / actual only per case

	tests := []struct {
		name                       string
		desired, actual            []Key
		wantOK, wantMiss, wantUnau int
	}{
		{"all compliant", []Key{a}, []Key{a}, 1, 0, 0},
		{"missing", []Key{a, b}, []Key{a}, 1, 1, 0},
		{"unauthorized", []Key{a}, []Key{a, b}, 1, 0, 1},
		{"empty desired", nil, []Key{a}, 0, 0, 1},
		{"empty actual", []Key{a}, nil, 0, 1, 0},
		{"duplicate actual deduped", []Key{a}, []Key{a, a}, 1, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Diff(tt.desired, tt.actual)
			if len(r.OK) != tt.wantOK || len(r.Missing) != tt.wantMiss || len(r.Unauthorized) != tt.wantUnau {
				t.Errorf("Diff = OK:%d Missing:%d Unauthorized:%d, want %d/%d/%d",
					len(r.OK), len(r.Missing), len(r.Unauthorized),
					tt.wantOK, tt.wantMiss, tt.wantUnau)
			}
		})
	}
}

// TestDiffActual: Result.Actual exposes the on-server form (comment/options)
// of every installed key by fingerprint — first occurrence per fingerprint,
// exactly the dedup Diff already applies — so callers (audit --comments) can
// compare a matched key's actual comment against the desired one.
func TestDiffActual(t *testing.T) {
	desired := mustKey(t, testKeyLine(t))
	first := mustKey(t, testKeyLine(t)+" alice@laptop")
	dupe := mustKey(t, testKeyLine(t)+" alice@old-box")
	other := mustKey(t, testkeys.Line(t, 2)+" who@is-this")

	r := Diff([]Key{desired}, []Key{first, dupe, other})

	if len(r.Actual) != 2 {
		t.Fatalf("Actual has %d entries, want 2 (dupes collapsed)", len(r.Actual))
	}
	got, ok := r.Actual[desired.Fingerprint]
	if !ok {
		t.Fatalf("Actual lacks the matched fingerprint %s", desired.Fingerprint)
	}
	if got.Comment != "alice@laptop" {
		t.Errorf("Actual[matched].Comment = %q, want %q (first occurrence wins)", got.Comment, "alice@laptop")
	}
	if got, ok := r.Actual[other.Fingerprint]; !ok || got.Comment != "who@is-this" {
		t.Errorf("Actual[unauthorized] = (%+v, %v), want the installed key", got, ok)
	}

	// Empty actual: the map is empty, never nil-panicking lookups.
	if r := Diff([]Key{desired}, nil); len(r.Actual) != 0 {
		t.Errorf("Actual = %v for empty actual, want empty", r.Actual)
	}
}

// fingerprints projects keys to their fingerprint sequence for order checks.
func fingerprints(keys []Key) []string {
	fps := make([]string, len(keys))
	for i, k := range keys {
		fps[i] = k.Fingerprint
	}
	return fps
}

func assertFingerprintOrder(t *testing.T, label string, got []Key, want []Key) {
	t.Helper()
	gotFPs, wantFPs := fingerprints(got), fingerprints(want)
	if len(gotFPs) != len(wantFPs) {
		t.Fatalf("%s = %d keys %v, want %d %v", label, len(gotFPs), gotFPs, len(wantFPs), wantFPs)
	}
	for i := range wantFPs {
		if gotFPs[i] != wantFPs[i] {
			t.Errorf("%s[%d] = %s, want %s (full got %v, want %v)",
				label, i, gotFPs[i], wantFPs[i], gotFPs, wantFPs)
		}
	}
}

func TestDiffPreservesOrder(t *testing.T) {
	a := mustKey(t, testKeyLine(t))
	b := mustKey(t, testkeys.Line(t, 2))
	c := mustKey(t, testkeys.Line(t, 3))
	d := mustKey(t, testkeys.Line(t, 4))
	e := mustKey(t, testkeys.Line(t, 5))

	// desired: c, a, b (c missing; a, b installed)
	// actual:  e, b, d, a (e, d unauthorized; b before a)
	r := Diff([]Key{c, a, b}, []Key{e, b, d, a})

	// OK follows desired order (a before b), not actual order (b before a) —
	// a refactor to map iteration or actual-order emission must fail here.
	assertFingerprintOrder(t, "OK", r.OK, []Key{a, b})
	assertFingerprintOrder(t, "Missing", r.Missing, []Key{c})
	// Unauthorized follows actual order (e before d).
	assertFingerprintOrder(t, "Unauthorized", r.Unauthorized, []Key{e, d})

	// Multi-key Missing ordering: desired order must be preserved exactly.
	r2 := Diff([]Key{d, b, a}, nil)
	assertFingerprintOrder(t, "Missing(all)", r2.Missing, []Key{d, b, a})
}

func BenchmarkParseFile(b *testing.B) {
	// One deterministic key repeated: testkeys-style seeds are a single byte
	// (max 256 distinct keys), so for corpora beyond that we vary the comment,
	// not the key — ParseFile's cost is per-line and key-identity-blind.
	line, err := deterministicKeyLine()
	if err != nil {
		b.Fatal(err)
	}
	for _, lines := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("lines=%d", lines), func(b *testing.B) {
			var sb strings.Builder
			for i := 0; i < lines; i++ {
				fmt.Fprintf(&sb, "%s user%d@host\n# comment %d\n", line, i, i)
			}
			data := []byte(sb.String())
			b.SetBytes(int64(len(data)))
			for b.Loop() {
				ParseFile(data)
			}
		})
	}
}

func BenchmarkDiff(b *testing.B) {
	line, err := deterministicKeyLine()
	if err != nil {
		b.Fatal(err)
	}
	k, _ := ParseLine(line)
	for _, size := range []int{50, 500, 5000} {
		b.Run(fmt.Sprintf("keys=%d", size), func(b *testing.B) {
			// Fingerprints are synthesized (%06d) rather than derived from
			// real keys: single-byte seeds cap distinct real keys at 256, and
			// Diff compares by fingerprint string, so synthetic fingerprints
			// still measure the true map/lookup cost at this size.
			desired := make([]Key, 0, size)
			for i := 0; i < size; i++ {
				kk := *k
				kk.Fingerprint = fmt.Sprintf("SHA256:fake%06d", i)
				desired = append(desired, kk)
			}
			// actual = half of desired installed + an equal tranche of
			// unauthorized keys: exercises OK, Missing, and Unauthorized.
			actual := append([]Key{}, desired[:size/2]...)
			for i := 0; i < size/2; i++ {
				kk := *k
				kk.Fingerprint = fmt.Sprintf("SHA256:rogue%06d", i)
				actual = append(actual, kk)
			}
			for b.Loop() {
				Diff(desired, actual)
			}
		})
	}
}

func TestRenderTextIssue(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"empty is safe (means unset)", "", ""},
		{"plain", "alice@work", ""},
		{"internal spaces ok", "alice laptop key", ""},
		{"newline", "a\nb", "contains control or format characters"},
		{"carriage return", "a\rb", "contains control or format characters"},
		{"tab", "a\tb", "contains control or format characters"},
		{"escape byte", "a\x1b[31mb", "contains control or format characters"},
		{"C1 CSI", "a\u009bb", "contains control or format characters"},
		{"bidi override (Cf)", "user\u202eevil", "contains control or format characters"},
		{"line separator (Zl)", "a \u2028evil", "contains control or format characters"},
		{"paragraph separator (Zp)", "a\u2029evil", "contains control or format characters"},
		{"non-ASCII letters ok", "jos\u00e9@caf\u00e9", ""},
		{"leading space", " a", "has leading or trailing whitespace"},
		{"trailing space", "a ", "has leading or trailing whitespace"},
		{"all whitespace", "   ", "has leading or trailing whitespace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RenderTextIssue(tt.in); got != tt.want {
				t.Errorf("RenderTextIssue(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseLineRaw(t *testing.T) {
	base := testkeys.Line(t, 1)
	tests := []struct {
		name, line, want string
	}{
		{"bare key", base, base},
		{"options and comment",
			`no-port-forwarding,command="true" ` + base + " alice@laptop",
			`no-port-forwarding,command="true" ` + base + " alice@laptop"},
		{"surrounding whitespace trimmed",
			"  " + base + " alice@laptop\t",
			base + " alice@laptop"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k, err := ParseLine(tt.line)
			if err != nil || k == nil {
				t.Fatalf("ParseLine(%q) = %v, %v", tt.line, k, err)
			}
			if k.Raw != tt.want {
				t.Errorf("Raw = %q, want %q", k.Raw, tt.want)
			}
		})
	}
}

// TestDeclaredType pins the type-token scanner behind ParseLine's
// defense-in-depth mismatch check, independent of whether x/crypto already
// rejected the line upstream.
func TestDeclaredType(t *testing.T) {
	tests := []struct {
		line       string
		hasOptions bool
		want       string
	}{
		{"ssh-ed25519 AAAA c", false, "ssh-ed25519"},
		{"ssh-rsa", false, "ssh-rsa"},
		{`no-pty,command="a b" ssh-ed25519 AAAA`, true, "ssh-ed25519"},
		{`command="echo \"x y\"" ssh-rsa AAAA`, true, "ssh-rsa"},
		{"no-pty\tssh-ed25519\tAAAA", true, "ssh-ed25519"},
	}
	for _, tt := range tests {
		if got := declaredType(tt.line, tt.hasOptions); got != tt.want {
			t.Errorf("declaredType(%q, %v) = %q, want %q", tt.line, tt.hasOptions, got, tt.want)
		}
	}
}
