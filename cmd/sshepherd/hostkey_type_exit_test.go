package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// TestApplyProbeHostKeyTypeChangedExits2 (D10b, plan decision 13): a login
// check stopped by host_key_type_changed keeps the file, reports unproven
// and exits 2, in text and in JSON.
func TestApplyProbeHostKeyTypeChangedExits2(t *testing.T) {
	useWriter(t, &fleet.UnprovenError{Path: "~/.ssh/authorized_keys", Attempts: 1, HostKey: true,
		Last: &sshconn.Error{Kind: fleet.ErrorKindHostKeyTypeChanged, Err: errors.New("host key type changed")}})
	text, doc := runApplyFailure(t, applyDrift(t, ""), 2)
	if !strings.Contains(text, "UNPROVEN:") || doc.Servers[0].Outcome != "unproven" || doc.Servers[0].ErrorKind != "host_key_type_changed" {
		t.Errorf("text:\n%s\ndoc: %+v", text, doc)
	}
}
