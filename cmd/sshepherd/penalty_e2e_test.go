//go:build integration

package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// penaltyAudit is the part of audit --json the penalty E2E reads.
type penaltyAudit struct {
	Servers []struct {
		Name      string `json:"name"`
		Status    string `json:"status"`
		ErrorKind string `json:"error_kind"`
		Hint      string `json:"hint"`
	} `json:"servers"`
}

// TestE2EPerSourcePenalties (G016) runs audit against container D, whose
// sshd keeps the distro's default PerSourcePenalties: bad1-4 refuse the
// agent key, good1-3 accept it. The first audit's failed logins make sshd
// penalize this address, so the next audit, run at once, is dropped before
// the server's banner on every account, healthy ones included. Each such
// drop is reported as handshake with sshconn.PenaltyHint, never as auth
// (a refused key, which apply's login check would read as REJECTED), and
// audit exits 1 (unreachable), not 2.
func TestE2EPerSourcePenalties(t *testing.T) {
	bin, host, _, kh, pub := itE2E(t)
	port := os.Getenv("SSHEPHERD_IT_PORT_PENALTY")
	if port == "" {
		t.Fatal("SSHEPHERD_IT_PORT_PENALTY not set: scripts/integration.sh must start the penalty container")
	}
	servers := ""
	for _, u := range []string{"bad1", "bad2", "bad3", "bad4", "good1", "good2", "good3"} {
		servers += "  - {name: " + u + ", host: " + host + ", port: " + port + ", user: " + u + "}\n"
	}
	m := writeE2EManifest(t, t.TempDir(), "penalty.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
servers:
`+servers)
	audit := func(stage string) penaltyAudit {
		t.Helper()
		code, out, stderr := runBin(t, bin, "audit", "--json", "--parallel", "1", "--config", m, "--known-hosts", kh)
		var rep penaltyAudit
		if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 1 || len(rep.Servers) != 7 {
			t.Fatalf("%s audit: exit = %d (want 1), servers = %d, json err = %v (stderr: %s)\n%s", stage, code, len(rep.Servers), err, stderr, out)
		}
		for _, s := range rep.Servers {
			if strings.HasPrefix(s.Name, "good") && s.ErrorKind == "auth" {
				t.Errorf("%s audit: %s error_kind auth: a penalty drop must never read as a refused key", stage, s.Name)
			}
			if s.ErrorKind == "handshake" && s.Hint != sshconn.PenaltyHint {
				t.Errorf("%s audit: %s dropped with hint %q, want the PerSourcePenalties hint", stage, s.Name, s.Hint)
			}
		}
		return rep
	}
	audit("first")
	rep := audit("second")
	for _, s := range rep.Servers {
		if s.Status != "unreachable" || s.ErrorKind != "handshake" || s.Hint != sshconn.PenaltyHint {
			t.Errorf("second audit: %s = %s/%s hint %q, want unreachable/handshake with the PerSourcePenalties hint (the address is penalized)",
				s.Name, s.Status, s.ErrorKind, s.Hint)
		}
	}
	code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh)
	if code != 1 || !strings.Contains(out+stderr, "PerSourcePenalties") || strings.Count(out+stderr, "PerSourcePenalties") != 1 {
		t.Errorf("text audit: exit = %d, want 1 with the hint printed once\nstdout:\n%s\nstderr:\n%s", code, out, stderr)
	}
}
