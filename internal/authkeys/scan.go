package authkeys

import "strings"

// PreserveMarker opens the externally-managed section of a managed file
// (spec 2026-11-08 S6): it follows the desired keys and precedes the lines a
// preserve: rule keeps. It is never captured as a kept line's comment.
const PreserveMarker = "# Preserved by SSHepherd (externally managed):"

// ScannedLine is one parsed key line of a file with the comment lines
// directly above it (no blank line between), which some tools use to mark
// their own lines.
type ScannedLine struct {
	Key   Key
	Line  int      // 1-based line number of the key line
	Above []string // comment lines directly above, in file order, trailing CRs trimmed
}

// ScanFile returns ParseFile's key lines, in order, each with the comment
// lines directly above it. A blank line, a key line, an unparseable line,
// the managed header (on any line) and PreserveMarker end a run of
// comments, and the header and the marker are never captured. A key line is
// parsed exactly as ParseFile does; a comment line keeps every byte but its
// trailing carriage returns, so RenderKept then ScanFile is a fixed point.
func ScanFile(data []byte) []ScannedLine {
	var out []ScannedLine
	var run []string
	for i, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		_, header := ParseHeader(t)
		switch {
		case t == "" || header || t == PreserveMarker:
			run = nil
		case strings.HasPrefix(t, "#"):
			run = append(run, strings.TrimRight(line, "\r"))
		default:
			if k, err := ParseLine(strings.TrimSuffix(line, "\r")); err == nil && k != nil {
				out = append(out, ScannedLine{Key: *k, Line: i + 1, Above: run})
			}
			run = nil
		}
	}
	return out
}

// CommandOf returns the value of a line's first command="…" option, unquoted
// the way sshd reads it (\" is a quote); ok is false when the line has none
// or its value is not double-quoted.
func CommandOf(opts []string) (cmd string, ok bool) {
	opt, found := FindOption(opts, "command")
	if !found {
		return "", false
	}
	_, v, _ := strings.Cut(opt, "=")
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", false
	}
	return strings.ReplaceAll(v[1:len(v)-1], `\"`, `"`), true
}
