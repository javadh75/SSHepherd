package sshwrite

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/sshconn"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestWriteScriptsUnchanged pins every remote script that carries the
// StrictModes walk, byte for byte: the walk moved to sshconn.AncestorWalk and
// these goldens are the proof the move changed nothing. The golden is
// taken before the move; a later rewrite of a script updates it knowingly.
// The lock owner record names this machine and process, so that one token is
// masked: it differs per run and the goldens are committed.
func TestWriteScriptsUnchanged(t *testing.T) {
	expect := Snapshot{Size: 7, Cksum: 4242, Managed: true}
	scripts := map[string]string{
		"write":         writeCmdFor("~/.ssh/authorized_keys", expect, 12),
		"write_absent":  writeCmdFor("/srv/keys/deploy", Snapshot{Absent: true}, 12),
		"restore":       restoreCmdFor("~/.ssh/authorized_keys", false, expect),
		"restore_empty": restoreCmdFor("~/.ssh/authorized_keys", true, expect),
		"disable_keys2": disableKeys2Cmd(),
	}
	for name, script := range scripts {
		t.Run(name, func(t *testing.T) {
			got := strings.ReplaceAll(script, sshconn.ShQuote(ownerIdent()), "'OWNER-IDENT'")
			path := filepath.Join("testdata", "script_"+name+".golden")
			if *update {
				if err := os.WriteFile(path, []byte(got+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path) // #nosec G304 -- a fixed test path
			if err != nil {
				t.Fatalf("read golden (run with -update first): %v", err)
			}
			if got+"\n" != string(want) {
				t.Errorf("script changed:\n got %s\nwant %s", got, want)
			}
		})
	}
}
