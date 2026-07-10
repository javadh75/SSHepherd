// Package adopt turns audit results into manifest additions: unknown keys
// found on the fleet become new users with access to the servers where they
// were found; keys of known users found beyond their grants become access
// extensions. Pure logic — no I/O; the cmd layer owns SSH and rendering.
package adopt

import "strings"

// sanitizeName derives a manifest user name from a key comment: lowercase,
// every run of characters outside [a-z0-9] collapses to a single '-',
// leading and trailing '-' trimmed. Returns "" when nothing usable remains —
// the caller falls back to a numbered name.
func sanitizeName(comment string) string {
	var b strings.Builder
	pendingDash := false
	for _, r := range strings.ToLower(comment) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			if pendingDash && b.Len() > 0 {
				b.WriteByte('-')
			}
			pendingDash = false
			b.WriteRune(r)
		default:
			pendingDash = true
		}
	}
	return b.String()
}
