package authkeys

import (
	"reflect"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func parseOne(t *testing.T, line string) *Key {
	t.Helper()
	k, err := ParseLine(line)
	if err != nil || k == nil {
		t.Fatalf("ParseLine(%q) = %v, %v", line, k, err)
	}
	return k
}

func TestStrengthIssue(t *testing.T) {
	tests := []struct {
		name  string
		line  string
		issue string
		bits  int
	}{
		{"ed25519 is fine", testkeys.Line(t, 1), "", 0},
		{"rsa 2048 is fine", testkeys.RSALine(t, 1, 2048), "", 0},
		{"rsa 4096 is fine", testkeys.RSALine(t, 1, 4096), "", 0},
		{"rsa 2047 is weak", testkeys.RSALine(t, 1, 2047), WeakRSAUnder2K, 2047},
		{"rsa 1024 is weak", testkeys.RSALine(t, 1, 1024), WeakRSAUnder2K, 1024},
		{"dsa is weak", testkeys.DSALine(t, 1), WeakDSA, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(tt.line))
			if err != nil {
				t.Fatal(err)
			}
			if issue, bits := StrengthIssue(pub); issue != tt.issue || bits != tt.bits {
				t.Errorf("StrengthIssue = (%q, %d), want (%q, %d)", issue, bits, tt.issue, tt.bits)
			}
			k := parseOne(t, tt.line)
			if k.Weak != tt.issue || k.WeakBits != tt.bits {
				t.Errorf("ParseLine Weak = (%q, %d), want (%q, %d)", k.Weak, k.WeakBits, tt.issue, tt.bits)
			}
		})
	}
}

func TestLinesByFingerprint(t *testing.T) {
	a := parseOne(t, testkeys.Line(t, 1))
	aAgain := parseOne(t, `no-pty `+testkeys.Line(t, 1))
	b := parseOne(t, testkeys.Line(t, 2))
	got := LinesByFingerprint([]Key{*a, *b, *aAgain})
	want := map[string][]Key{a.Fingerprint: {*a, *aAgain}, b.Fingerprint: {*b}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LinesByFingerprint = %+v, want %+v", got, want)
	}
}

func TestExpired(t *testing.T) {
	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		opts []string
		want bool
	}{
		{"no clause", []string{"no-pty"}, false},
		{"8 digits, passed", []string{`expiry-time="20260101"`}, true},
		{"8 digits, future", []string{`expiry-time="20270101"`}, false},
		{"12 digits, passed", []string{`expiry-time="202606151159"`}, true},
		{"14 digits, passed", []string{`expiry-time="20260615115959"`}, true},
		{"exactly now counts", []string{`expiry-time="20260615120000"`}, true},
		{"Z suffix, future", []string{`expiry-time="20260615130000Z"`}, false},
		{"UTC suffix, passed", []string{`expiry-time="20260615110000UTC"`}, true},
		{"case-insensitive name", []string{`Expiry-Time="20260101"`}, true},
		{"only the earliest of a repeated clause has passed", []string{`expiry-time="20270101"`, `expiry-time="20260101"`}, true},
		{"malformed clause is skipped", []string{`expiry-time="garbage"`}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Expired(tt.opts, now, time.UTC); got != tt.want {
				t.Errorf("Expired = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEarliestExpiry(t *testing.T) {
	opt, when, ok := EarliestExpiry([]string{`expiry-time="20270101"`, "no-pty", `expiry-time="20260101"`}, time.UTC)
	if !ok || opt != `expiry-time="20260101"` || when.Year() != 2026 {
		t.Errorf("EarliestExpiry = %q, %v, %v", opt, when, ok)
	}
	if _, _, ok := EarliestExpiry([]string{"no-pty"}, time.UTC); ok {
		t.Error("EarliestExpiry found a clause in a line that has none")
	}
}
