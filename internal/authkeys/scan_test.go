package authkeys

import (
	"reflect"
	"slices"
	"testing"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

type scanView struct {
	line  int
	raw   string
	above []string
}

func scanViews(lines []ScannedLine) []scanView {
	out := make([]scanView, 0, len(lines))
	for _, l := range lines {
		out = append(out, scanView{l.Line, l.Key.Raw, l.Above})
	}
	return out
}

// TestScanFile (spec S6 "What a line is", "Render"): ParseFile's key lines,
// in order, each with the comment lines directly above it. A blank line, a
// key line, an unparseable line, the managed header and the marker end a
// run; trailing CRs are trimmed (gap 8); other bytes are kept.
func TestScanFile(t *testing.T) {
	k1, k2 := testkeys.Line(t, 1), testkeys.Line(t, 2)
	gitea := `command="gitea serv key-1" ` + k2 + " g"
	in := ManagedHeader + "\n" + // 1
		"# above k1\n" + k1 + " a\n" + // 2, 3
		PreserveMarker + "\n" + // 4
		"# gitea public key\n  # indented\r\r\n" + gitea + "\n" + // 5, 6, 7
		"# orphan\n\n" + k1 + " again\n" + // 8, 9, 10
		"# before junk\nnot a key\n" + k2 + "\n" // 11, 12, 13
	got := ScanFile([]byte(in))
	want := []scanView{
		{3, k1 + " a", []string{"# above k1"}},
		{7, gitea, []string{"# gitea public key", "  # indented"}},
		{10, k1 + " again", nil},
		{13, k2, nil},
	}
	if !reflect.DeepEqual(scanViews(got), want) {
		t.Errorf("ScanFile =\n%+v\nwant\n%+v", scanViews(got), want)
	}
	keys, _ := ParseFile([]byte(in))
	if !slices.EqualFunc(keys, got, func(k Key, s ScannedLine) bool { return reflect.DeepEqual(k, s.Key) }) {
		t.Error("ScanFile's keys differ from ParseFile's")
	}
}

// TestScanFileNeverCapturesHeaderOrMarker: a managed header anywhere in the
// file, and the marker, end a run and are never captured.
func TestScanFileNeverCapturesHeaderOrMarker(t *testing.T) {
	k1 := testkeys.Line(t, 1)
	in := "# x\n" + Header(7) + "\n" + k1 + "\n# y\n" + PreserveMarker + "\n" + k1 + " b\n"
	for _, l := range ScanFile([]byte(in)) {
		if l.Above != nil {
			t.Errorf("line %d captured %q", l.Line, l.Above)
		}
	}
}

func TestCommandOf(t *testing.T) {
	for _, tc := range []struct {
		opts   []string
		want   string
		wantOK bool
	}{
		{nil, "", false},
		{[]string{"no-pty"}, "", false},
		{[]string{`command="gitea serv key-1"`}, "gitea serv key-1", true},
		{[]string{"restrict", `COMMAND="a \"b\" c"`}, `a "b" c`, true},
		{[]string{`command="first"`, `command="second"`}, "first", true},
		{[]string{"command=unquoted"}, "", false},
		{[]string{"command"}, "", false},
	} {
		got, ok := CommandOf(tc.opts)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("CommandOf(%q) = %q, %v; want %q, %v", tc.opts, got, ok, tc.want, tc.wantOK)
		}
	}
}
