package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRegenerateWritesOptionsOnlyWhenSet (spec S7, Shared rules): a plain
// adopt carries a grant's options: verbatim and writes no options: key on an
// entry without them (DeepEqual cannot tell: an empty list loads as unset).
func TestRegenerateWritesOptionsOnlyWhenSet(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	cfg.Access = append(cfg.Access, config.Access{User: "bob", Servers: []string{"web-1"}})
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), "options:"); n != 1 {
		t.Errorf("options: written %d times, want once (the sampled entry only):\n%s", n, out)
	}
	got, err := config.Parse(out)
	if err != nil || !reflect.DeepEqual(got.Access, cfg.Access) {
		t.Errorf("access changed (err %v):\n%s", err, out)
	}
}

// TestAdoptRegenerateKeepsGroupGrantOptions: a group entry's options:
// survive a plain adopt (spec S7 with S3b).
func TestAdoptRegenerateKeepsGroupGrantOptions(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	cfg.Groups = []config.Group{{Name: "web-team", Members: []string{"op", "bob"}}}
	entry := config.Access{Group: "web-team", Servers: []string{"web-1"}, Options: []string{"no-x11-forwarding"}}
	cfg.Access = append(cfg.Access, entry)
	out, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := config.Parse(out)
	if err != nil || !reflect.DeepEqual(got.Access[len(got.Access)-1], entry) {
		t.Errorf("adopt lost the group entry's options (err %v):\n%s", err, out)
	}
}

// TestWideningGrantExitsThree (spec S7 Validation, D28): a grant option that
// widens access is a load error, exit 3 on every command.
func TestWideningGrantExitsThree(t *testing.T) {
	hermeticHome(t)
	cfg := writeConfig(t, "users:\n  - {name: alice, keys: [\""+testkeys.Line(t, 1)+"\"]}\n"+
		"servers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"+
		"access:\n  - {user: alice, servers: [web-1], options: [port-forwarding]}\n")
	const want = `access[0]: option "port-forwarding" does not restrict access; a grant can only add restrictions`
	for _, args := range [][]string{{"validate"}, {"audit"}, {"apply", "--dry-run"}, {"adopt"}} {
		var out, errBuf bytes.Buffer
		if code := run(append(args, "--config", cfg), &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), want) {
			t.Errorf("%v: exit = %d, stderr %s", args, code, errBuf.String())
		}
	}
}
