package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestRegeneratePreserveWritesOneField (spec S6 Go shape): adopt's
// regenerate and Append write each rule's one field. Without omitempty on
// PreserveRule, entryNode would write comment: "" beside command: (and
// command: "" beside comment:); that still loads, so checkRoundTrip's
// DeepEqual cannot see it.
func TestRegeneratePreserveWritesOneField(t *testing.T) {
	cfg, _, _, _ := roundTripConfig(t)
	adopted, err := generateAdoptManifest(cfg, adopt.Plan{}, "rt.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	mf, err := manifest.Load([]byte("users: []\nservers: []\naccess: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := mf.Append([]string{"rt"}, cfg.Users, cfg.Servers, cfg.Access); err != nil {
		t.Fatal(err)
	}
	appended, err := mf.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for how, out := range map[string][]byte{"adopt": adopted, "Append": appended} {
		s := string(out)
		if !strings.Contains(s, "preserve:") || strings.Contains(s, `command: ""`) || strings.Contains(s, `comment: ""`) {
			t.Errorf("%s wrote an empty preserve: field (or no preserve:):\n%s", how, s)
		}
	}
}

// TestPreserveBadRuleExitsThree (D28 "a bad preserve: rule → 3 on every
// command"): the load error stops every manifest-reading command before it
// dials or edits, with the rule's message on stderr. validate is
// TestValidatePreserve; import --merge loads the manifest the same way.
func TestPreserveBadRuleExitsThree(t *testing.T) {
	bad := writeConfig(t, preserveManifest(t, `[{comment: '.*'}]`))
	const want = `server "gitea": preserve[0]: pattern ".*" must start with at least 4 literal bytes`
	for name, args := range map[string][]string{
		"audit":  {"audit"},
		"apply":  {"apply", "--dry-run"},
		"adopt":  {"adopt"},
		"revoke": {"revoke", "alice"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, errBuf bytes.Buffer
			if code := run(append(args, "--config", bad), &out, &errBuf); code != 3 || !strings.Contains(errBuf.String(), want) {
				t.Errorf("exit = %d, stderr = %q; want 3 and %q", code, errBuf.String(), want)
			}
		})
	}
}

// preserveManifest: alice (k1) granted gitea, whose preserve: value is
// preserve verbatim.
func preserveManifest(t *testing.T, preserve string) string {
	t.Helper()
	return "users:\n  - {name: alice, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"servers:\n  - {name: gitea, host: 10.0.4.1, user: git, preserve: " + preserve + "}\n" +
		"access:\n  - {user: alice, servers: [gitea]}\n"
}

// TestValidatePreserve (spec S6 Validation, D28 "a bad preserve: rule"): a
// good rule is a valid manifest (exit 0); a bad one is a load error, exit 3
// in text and in --json, whose errors carries the message.
func TestValidatePreserve(t *testing.T) {
	kh := recordedKnownHosts(t, "10.0.4.1")
	good := writeConfig(t, preserveManifest(t, `[{command: '/usr/local/bin/gitea serv key-[0-9]+'}]`))
	if code, out, stderr := validateCLI(t, "--config", good, "--known-hosts", kh); code != 0 || out != "manifest OK: 1 user, 1 server, 1 grant (0 warnings)\n" {
		t.Fatalf("good rule: exit = %d, stdout = %q, stderr = %q", code, out, stderr)
	}
	bad := writeConfig(t, preserveManifest(t, `[{comment: '.*'}]`))
	const want = `server "gitea": preserve[0]: pattern ".*" must start with at least 4 literal bytes`
	code, _, stderr := validateCLI(t, "--config", bad, "--known-hosts", kh)
	if code != 3 || !strings.Contains(stderr, want) {
		t.Fatalf("bad rule: exit = %d, stderr = %q", code, stderr)
	}
	code, out, _ := validateCLI(t, "--json", "--config", bad, "--known-hosts", kh)
	errs, _ := oneJSONDoc(t, out)["errors"].([]any)
	first := ""
	if len(errs) == 1 {
		first, _ = errs[0].(string)
	}
	if code != 3 || !strings.Contains(first, want) {
		t.Errorf("--json: exit = %d, errors = %v", code, errs)
	}
}

// TestImportMergeKeepsPreserve: import --merge edits the manifest's YAML in
// place, so a server's preserve: rules come back unchanged beside the
// appended host.
func TestImportMergeKeepsPreserve(t *testing.T) {
	hermeticHome(t)
	m := writeConfig(t, preserveManifest(t, `[{command: '/usr/local/bin/gitea serv key-[0-9]+'}, {comment: 'google-ssh .*'}]`))
	src := writeSSHConfig(t, "Host app-1\n  HostName 10.0.0.5\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", src, "--merge", m, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	got, err := config.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("merged manifest does not load: %v\n%s", err, out.String())
	}
	want := []config.PreserveRule{{Command: "/usr/local/bin/gitea serv key-[0-9]+"}, {Comment: "google-ssh .*"}}
	if s, ok := got.ServerNamed("gitea"); !ok || !reflect.DeepEqual(s.Preserve, want) {
		t.Errorf("gitea's preserve: = %+v, want %+v\n%s", s.Preserve, want, out.String())
	}
	if _, ok := got.ServerNamed("app-1"); !ok {
		t.Errorf("app-1 was not appended:\n%s", out.String())
	}
}
