package apply

import (
	"reflect"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestProtectedRemovalsOncePerUser: a protected user with two keys that one
// except: removes is warned about once, not once per key.
func TestProtectedRemovalsOncePerUser(t *testing.T) {
	ci := `  - {name: ci, protected: true, keys: ["` + testkeys.Line(t, 2) + `", "` + testkeys.Line(t, 3) + `"]}` + "\n"
	cfg := exceptFleet(t, ci, `  - {user: ci, servers: ["*"], except: [web-2]}`+"\n", "")
	var remove []authkeys.Key
	for _, seed := range []byte{2, 3} {
		k, err := authkeys.ParseLine(testkeys.Line(t, seed))
		if err != nil {
			t.Fatal(err)
		}
		remove = append(remove, *k)
	}
	if got := protectedRemovals(cfg, "web-2", remove); !reflect.DeepEqual(got, []string{protectedRemovalText}) {
		t.Errorf("protectedRemovals = %q, want %q once", got, protectedRemovalText)
	}
}
