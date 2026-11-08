package authkeys

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
)

const legacy = "# Managed by SSHepherd. Manual edits will be overwritten by 'sshepherd apply'."

func serialLine(digits string) string {
	return "# Managed by SSHepherd (serial " + digits + "). Manual edits will be overwritten by 'sshepherd apply'."
}

// parseHeaderCases is the spec §3 table of first lines. TestParseHeader
// and TestSnapshotManagedMatchesParseHeader (Task 12) both iterate it.
var parseHeaderCases = []struct {
	name    string
	line    string
	serial  uint64
	managed bool
}{
	{"legacy", legacy, 0, true},
	{"serial 7", serialLine("7"), 7, true},
	{"max serial", serialLine("9007199254740991"), MaxHeaderSerial, true},
	{"over max", serialLine("9007199254740992"), 0, false},
	{"17 digits", serialLine("12345678901234567"), 0, false},
	{"leading zero", serialLine("07"), 0, false},
	{"zero", serialLine("0"), 0, false},
	{"negative", serialLine("-1"), 0, false},
	{"trailing space", legacy + " ", 0, false},
	{"trailing CR", legacy + "\r", 0, false},
	{"prefix lookalike", "# Managed by SSHepherd-ish. Manual edits will be overwritten by 'sshepherd apply'.", 0, false},
	{"hand written", "ssh-ed25519 AAAA x", 0, false},
	{"empty", "", 0, false},
}

func TestParseHeader(t *testing.T) {
	for _, tt := range parseHeaderCases {
		t.Run(tt.name, func(t *testing.T) {
			s, m := ParseHeader(tt.line)
			if s != tt.serial || m != tt.managed {
				t.Errorf("ParseHeader(%q) = (%d, %v), want (%d, %v)", tt.line, s, m, tt.serial, tt.managed)
			}
		})
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	if Header(0) != ManagedHeader || ManagedHeader != legacy {
		t.Fatalf("Header(0) = %q, want the legacy bytes", Header(0))
	}
	for _, n := range []uint64{1, 7, 1000, MaxHeaderSerial} {
		if got := Header(n); got != serialLine(strconv.FormatUint(n, 10)) {
			t.Errorf("Header(%d) = %q", n, got)
		}
		if s, m := ParseHeader(Header(n)); s != n || !m {
			t.Errorf("ParseHeader(Header(%d)) = (%d, %v)", n, s, m)
		}
	}
}

func TestParseHeaderOf(t *testing.T) {
	for _, tt := range []struct {
		content string
		serial  uint64
		managed bool
	}{
		{Header(5) + "\nssh-ed25519 AAAA x\n", 5, true},
		{legacy + "\n", 0, true},
		{legacy, 0, true}, // no newline: the whole content is the first line
		{"ssh-ed25519 AAAA x\n" + Header(5) + "\n", 0, false},
		{"", 0, false},
	} {
		if s, m := ParseHeaderOf([]byte(tt.content)); s != tt.serial || m != tt.managed {
			t.Errorf("ParseHeaderOf(%q) = (%d, %v), want (%d, %v)", tt.content, s, m, tt.serial, tt.managed)
		}
	}
}

// TestSnapshotManagedMatchesParseHeader: ManagedSnapshot(…).Managed equals
// ParseHeader's managed over every TestParseHeader row and every file of
// the FuzzParseHeader seed corpus (Task 11), so the .orig decision can
// never drift from the header grammar.
func TestSnapshotManagedMatchesParseHeader(t *testing.T) {
	lines := map[string]string{}
	for _, tc := range parseHeaderCases {
		lines["table/"+tc.name] = tc.line
	}
	files, err := filepath.Glob(filepath.Join("testdata", "fuzz", "FuzzParseHeader", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("corpus: %v (%d files; Task 11 commits four)", err, len(files))
	}
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- committed corpus under testdata
		if err != nil {
			t.Fatal(err)
		}
		// "go test fuzz v1", then string("…"), then uint64(…).
		for _, l := range strings.Split(string(raw), "\n") {
			if q, ok := strings.CutPrefix(l, "string("); ok {
				v, err := strconv.Unquote(strings.TrimSuffix(q, ")"))
				if err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				lines["corpus/"+filepath.Base(f)] = v
			}
		}
	}
	for name, line := range lines {
		_, want := ParseHeader(line)
		if got := ManagedSnapshot(false, []byte(line+"\nkey-line\n")).Managed; got != want {
			t.Errorf("%s: ManagedSnapshot.Managed = %v, ParseHeader managed = %v (%q)", name, got, want, line)
		}
		if got := ManagedSnapshot(false, []byte(line)).Managed; got != want {
			t.Errorf("%s, no newline: ManagedSnapshot.Managed = %v, want %v", name, got, want)
		}
	}
	if s := ManagedSnapshot(true, nil); s.Managed || !s.Absent {
		t.Errorf("absent file = %+v, want Absent and not Managed", s)
	}
	if s, want := ManagedSnapshot(false, []byte(legacy+"\n")), fleet.SnapshotOf(false, []byte(legacy+"\n")); s.Size != want.Size || s.Cksum != want.Cksum {
		t.Errorf("ManagedSnapshot = %+v, want fleet.SnapshotOf's size and cksum %+v", s, want)
	}
}
