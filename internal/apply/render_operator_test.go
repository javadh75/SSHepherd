package apply

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// renderFleet renders every server of manifest y exactly as Build does, one
// block per server.
func renderFleet(t *testing.T, y string) []byte {
	t.Helper()
	cfg, err := config.Parse([]byte(y))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var b bytes.Buffer
	for _, s := range cfg.Servers {
		fmt.Fprintf(&b, "=== %s\n%s", s.Name, renderedFor(t, cfg, s.Name))
	}
	return b.Bytes()
}

// TestRenderTodaysOperatorManifestUnchanged: a manifest that could exist
// before S4 (an operator with no entry, one with a literal entry, one with
// its own "*" and no except:) renders byte-identically after it. The golden
// was generated from caea5ae, before any S4 code existed; never -update it.
func TestRenderTodaysOperatorManifestUnchanged(t *testing.T) {
	checkGolden(t, "render_operator_unchanged.golden", renderFleet(t, `users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: op-a, operator: true, keys: ["`+testkeys.Line(t, 2)+`"]}
  - {name: op-b, operator: true, keys: ["`+testkeys.Line(t, 3)+`"]}
  - {name: bob, keys: ["`+testkeys.Line(t, 4)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: bob, servers: [web-1]}
  - {user: op-a, servers: [web-2]}
  - {user: alice, servers: [web-1, web-2]}
  - {user: op-b, servers: ["*"]}
`))
}

// fleetBlock is one server's block of a renderFleet report.
func fleetBlock(t *testing.T, out []byte, server string) string {
	t.Helper()
	_, rest, ok := strings.Cut(string(out), "=== "+server+"\n")
	if !ok {
		t.Fatalf("no block for %s in:\n%s", server, out)
	}
	block, _, _ := strings.Cut(rest, "=== ")
	return block
}

// TestRenderOperatorOwnExcept: the operator's own "*" and except: replace the
// implicit grant, so the excepted server does not render its key.
func TestRenderOperatorOwnExcept(t *testing.T) {
	got := renderFleet(t, `users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: backup-root, operator: true, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: legacy-1, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, legacy-1]}
  - {user: backup-root, servers: ["*"], except: [legacy-1]}
`)
	if block := fleetBlock(t, got, "legacy-1"); strings.Contains(block, strings.Fields(testkeys.Line(t, 2))[1]) {
		t.Errorf("backup-root's key rendered on the excepted server:\n%s", block)
	}
	checkGolden(t, "render_operator_own_except.golden", got)
}

// TestRenderProtectedFirst: a protected user's key leads the file on a server
// it is granted, in users order, and is absent where it is not granted.
func TestRenderProtectedFirst(t *testing.T) {
	got := renderFleet(t, `users:
  - {name: alice, keys: ["`+testkeys.Line(t, 1)+`"]}
  - {name: ci, protected: true, keys: ["`+testkeys.Line(t, 2)+`"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
  - {name: web-2, host: 10.0.0.2, user: deploy}
access:
  - {user: alice, servers: [web-1, web-2]}
  - {user: ci, servers: [web-1]}
`)
	ci, alice := strings.Fields(testkeys.Line(t, 2))[1], strings.Fields(testkeys.Line(t, 1))[1]
	block := fleetBlock(t, got, "web-1")
	if i, j := strings.Index(block, ci), strings.Index(block, alice); i < 0 || j < 0 || i > j {
		t.Errorf("web-1: want ci's key before alice's:\n%s", block)
	}
	checkGolden(t, "render_protected_first.golden", got)
}
