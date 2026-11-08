package authkeys

import (
	"bytes"
	"regexp"
	"strconv"

	"github.com/javadh75/SSHepherd/internal/fleet"
)

// MaxHeaderSerial is the largest serial a managed header may carry: 2^53-1,
// config.MaxSerial (internal/apply pins the two equal).
const MaxHeaderSerial = 1<<53 - 1

// ForgedMargin is the forgery threshold: a header serial more than this
// above the manifest's serial counts as forged (spec 2026-11-08 §3 row 1). audit reports it critical;
// apply treats it as no serial and rewrites the header.
const ForgedMargin = 1000

// headerTail is the fixed text after the optional serial.
const headerTail = ". Manual edits will be overwritten by 'sshepherd apply'."

// headerRE is the only managed first line: anchored, a serial of 1 to 16
// digits with no leading zero, nothing before or after. The first line is
// remote-controlled input, so it is matched, never evaluated.
var headerRE = regexp.MustCompile(`^# Managed by SSHepherd(?: \(serial ([1-9][0-9]{0,15})\))?\. Manual edits will be overwritten by 'sshepherd apply'\.$`)

// Header is the managed first line for serial: ManagedHeader (the legacy
// bytes) at 0, else "# Managed by SSHepherd (serial N). …".
func Header(serial uint64) string {
	if serial == 0 {
		return ManagedHeader
	}
	return "# Managed by SSHepherd (serial " + strconv.FormatUint(serial, 10) + ")" + headerTail
}

// ParseHeader reads a file's first line: (0, true) for the legacy header,
// (N, true) for a "(serial N)" header, (0, false) for anything else —
// including a serial over MaxHeaderSerial, a leading zero, "(serial 0)",
// or trailing whitespace or a carriage return.
func ParseHeader(firstLine string) (serial uint64, managed bool) {
	m := headerRE.FindStringSubmatch(firstLine)
	if m == nil {
		return 0, false
	}
	if m[1] == "" {
		return 0, true
	}
	v, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil || v > MaxHeaderSerial {
		return 0, false
	}
	return v, true
}

// ParseHeaderOf is ParseHeader on content's first line (the text before the
// first newline; all of content when it has none).
func ParseHeaderOf(content []byte) (serial uint64, managed bool) {
	first, _, _ := bytes.Cut(content, []byte("\n"))
	return ParseHeader(string(first))
}

// ManagedSnapshot is the write's compare-and-swap snapshot of phase-1
// bytes (fleet.SnapshotOf) plus the .orig decision input: Managed is
// ParseHeaderOf's verdict on those very bytes. It is the only producer of
// Snapshot.Managed — apply's planner and sshwrite.SnapshotOf both call it —
// so the write script never re-derives it with a shell pattern.
func ManagedSnapshot(absent bool, content []byte) fleet.Snapshot {
	s := fleet.SnapshotOf(absent, content)
	if !absent {
		_, s.Managed = ParseHeaderOf(content)
	}
	return s
}
