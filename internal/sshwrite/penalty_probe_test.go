package sshwrite

import (
	"errors"
	"testing"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// TestProbePenaltyDropStaysTransient (G016): a PerSourcePenalties drop ends
// the login check's handshake before the banner. It says nothing about the
// file just written, so it is retried and then UNPROVEN, the file kept; it is
// never a rejection that restores the old file.
func TestProbePenaltyDropStaysTransient(t *testing.T) {
	err := &sshconn.Error{Kind: fleet.ErrorKindHandshake, Hint: sshconn.PenaltyHint, Err: errors.New("EOF")}
	if got := classifyProbe(stageDial, err); got != verdictTransient {
		t.Errorf("classifyProbe = %v, want verdictTransient", got)
	}
}
