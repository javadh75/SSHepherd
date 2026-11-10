package authkeys

import (
	"bytes"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// ManagedHeader is the legacy first line of every rendered file — the
// header at serial 0 (see Header). Deliberately undated: output stays
// byte-stable and golden-testable, so a repeated apply is a byte-for-byte
// no-op (2026-07-19 apply spec, owner-approved; amended 2026-11-08).
const ManagedHeader = "# Managed by SSHepherd" + headerTail

// RenderEntry pairs a parsed key with the comment the write policy decided
// on (config.DesiredComment — resolved by the caller; authkeys cannot
// import config).
type RenderEntry struct {
	Key     Key
	Comment string
}

// RenderLine renders one authorized_keys line: options comma-joined
// verbatim (the parser preserves quoted values, so the join is faithful —
// pinned by FuzzRenderRoundTrip), key material re-marshaled to the one
// canonical base64 form regardless of odd whitespace in the source line,
// then the comment. Re-parsing Key.Raw is cheap and keeps Key small; a
// failure means the Key was not produced by ParseLine — a caller bug,
// surfaced as an error rather than a dropped line (a silently missing key
// is a lockout hazard).
func RenderLine(e RenderEntry) (string, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(e.Key.Raw))
	if err != nil {
		return "", fmt.Errorf("render key %s: raw line does not re-parse: %w", e.Key.Fingerprint, err)
	}
	var b strings.Builder
	if len(e.Key.Options) > 0 {
		b.WriteString(strings.Join(e.Key.Options, ","))
		b.WriteByte(' ')
	}
	b.WriteString(strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(pub)), "\n"))
	if e.Comment != "" {
		b.WriteByte(' ')
		b.WriteString(e.Comment)
	}
	return b.String(), nil
}

// Render renders the managed file at serial 0 (the legacy header); see
// RenderSerial.
func Render(entries []RenderEntry) ([]byte, error) { return RenderSerial(entries, 0) }

// RenderSerial renders the complete managed authorized_keys file: the
// managed header for serial (Header), one line per entry in order, trailing
// newline. Deterministic — equal input yields byte-identical output; apply's
// convergence test and its idempotency both hang on this.
func RenderSerial(entries []RenderEntry, serial uint64) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(Header(serial))
	b.WriteByte('\n')
	for _, e := range entries {
		line, err := RenderLine(e)
		if err != nil {
			return nil, err
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// RenderKept renders the managed file at serial with the lines a preserve:
// rule keeps (spec 2026-11-08 S6): RenderSerial's bytes, then, only when
// kept is not empty, PreserveMarker and each kept line in order, its comment
// lines first, every line verbatim (Key.Raw). Deterministic, so a file that
// already holds this section re-renders byte-identically.
func RenderKept(entries []RenderEntry, serial uint64, kept []ScannedLine) ([]byte, error) {
	out, err := RenderSerial(entries, serial)
	if err != nil || len(kept) == 0 {
		return out, err
	}
	b := bytes.NewBuffer(out)
	b.WriteString(PreserveMarker)
	b.WriteByte('\n')
	for _, l := range kept {
		for _, c := range l.Above {
			b.WriteString(c)
			b.WriteByte('\n')
		}
		b.WriteString(l.Key.Raw)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}
