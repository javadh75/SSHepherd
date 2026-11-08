package audit

import "github.com/javadh75/SSHepherd/internal/fleet"

// hostKeyAlert reports whether kind is a host-key failure that may mean the
// server is being impersonated — exit 2, not a mere unreachable.
func hostKeyAlert(kind fleet.ErrorKind) bool {
	return kind == fleet.ErrorKindHostKeyChanged || kind == fleet.ErrorKindHostKeyRevoked
}
