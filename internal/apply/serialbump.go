package apply

import (
	"bytes"
	"fmt"
	"slices"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// NeedsSerialBump reports D4b (spec §6): some server this run writes loses
// a key (a remove row) while its header serial S is not below the
// manifest's serial m (m ≤ S; a forged header counts as no serial).
// Moving authorized_keys2 aside and collapsing duplicate lines do not count.
//
// A server a newer manifest wrote (rows 2-4) proves this manifest is stale:
// the run must never lift it past the serial that just refused or outranked
// it, or the next apply from this copy would re-grant what the newer
// manifest revoked (PRD-2). Staleness wins over any removal elsewhere.
func NeedsSerialBump(plans []ServerPlan, m uint64) bool {
	if slices.ContainsFunc(plans, func(p ServerPlan) bool { return p.Serial.Case.newer() }) {
		return false
	}
	for _, p := range plans {
		s := p.Serial.Header
		if p.Serial.Case == SerialForged {
			s = 0
		}
		if p.Class == ClassChange && len(p.Remove) > 0 && m <= s {
			return true
		}
	}
	return false
}

// Reserial re-renders the managed header of every change plan after apply
// saved a bumped serial to: each write carries to, or its own higher serial
// (a removal-only write on a newer server keeps S), so a serial on a server
// never goes down. Only line 1 changes.
func Reserial(plans []ServerPlan, to uint64) error {
	for i := range plans {
		p := &plans[i]
		if p.Class != ClassChange {
			continue
		}
		w := max(to, p.Serial.Writes)
		_, body, ok := bytes.Cut(p.Rendered, []byte("\n"))
		if !ok {
			return fmt.Errorf("bug: %s's rendered file has no header line", p.Server.Name)
		}
		p.Rendered = append([]byte(authkeys.Header(w)+"\n"), body...)
		p.Serial.Writes = w
	}
	return nil
}

// ReserialOversize reports every change plan the bumped header would push
// over maxRender (one message per server, nil when none). It mirrors
// Reserial's arithmetic and runs before the prompt: a file over the limit
// could be installed but never verified or read again, and Commit may
// re-render headers only, so the run is withheld here rather than one
// server refused after the plan was shown.
func ReserialOversize(plans []ServerPlan, to uint64) []string {
	var msgs []string
	for _, p := range plans {
		if p.Class != ClassChange {
			continue
		}
		_, body, ok := bytes.Cut(p.Rendered, []byte("\n"))
		if !ok {
			continue // Reserial reports this bug
		}
		w := max(to, p.Serial.Writes)
		if size := len(authkeys.Header(w)) + 1 + len(body); size > maxRender {
			msgs = append(msgs, fmt.Sprintf("%s: the serial bump to %d would make the rendered file %d bytes, over the %d-byte limit the read path accepts — nothing saved or written (split the grant across accounts)", p.Server.Name, w, size, maxRender))
		}
	}
	return msgs
}
