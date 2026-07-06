// Package authkeys parses OpenSSH authorized_keys entries into a structured,
// comparable form. It is the foundation for SSHepherd's source-of-truth model:
// reading what is currently installed on a host and diffing it against what
// should be there.
package authkeys

import (
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Key is a single parsed authorized_keys entry.
type Key struct {
	Type        string   // key algorithm, e.g. "ssh-ed25519"
	Comment     string   // trailing comment, conventionally user@host
	Options     []string // leading options, e.g. ["no-port-forwarding"]
	Fingerprint string   // SHA256 fingerprint, e.g. "SHA256:abc..."
}

// ParseLine parses a single authorized_keys line. Blank lines and comment lines
// (those whose first non-space character is '#') are not entries and return
// (nil, nil). Anything else that is not a valid key returns an error.
func ParseLine(line string) (*Key, error) {
	if trimmed := strings.TrimSpace(line); trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return nil, nil
	}

	pub, comment, options, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("parse authorized_keys line: %w", err)
	}

	return &Key{
		Type:        pub.Type(),
		Comment:     comment,
		Options:     options,
		Fingerprint: ssh.FingerprintSHA256(pub),
	}, nil
}
