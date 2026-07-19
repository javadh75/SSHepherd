package manifest

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

var update = flag.Bool("update", false, "rewrite golden files")

func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update first): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("output differs from %s:\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

// commentedFixture is a hand-maintained-looking manifest: head comments,
// comments between entries, inline comments, a foot comment, and a blank
// line (which the fidelity contract allows to vanish — the golden shows it).
func commentedFixture(tb testing.TB) string {
	tb.Helper()
	return `# fleet manifest — hand-maintained, do not regenerate
# contact: ops@example.com
users:
  # op holds the break-glass key
  - name: op
    operator: true
    keys:
      - ` + testkeys.Line(tb, 1) + `
  - name: bob # bob predates sshepherd
    keys:
      - ` + testkeys.Line(tb, 4) + `

servers:
  - name: web-1
    host: 10.0.0.1
    user: deploy # inline: the deploy account
  - name: web-2
    host: 10.0.0.2
    user: deploy
access:
  - user: bob
    servers: [web-1]
# reviewed 2026-07-01
`
}

// carolEntry is the shape adopt appends: name + description + one raw line.
func carolEntry(tb testing.TB) UserEntry {
	tb.Helper()
	return UserEntry{
		Name:        "carol-laptop",
		Description: "adopted from web-1, web-2",
		Keys:        []string{testkeys.Line(tb, 7) + " carol@laptop"},
	}
}

var mergeComments = []string{
	"merged by sshepherd adopt on 2026-07-16",
	"WARNING: server db-9 unreadable — its access is NOT represented",
}

func TestLoadRejectsWhatConfigParseRejects(t *testing.T) {
	cases := map[string]string{
		"yaml syntax error": "users: [",
		"unknown field":     "userz: []",
		"duplicate user": `
users:
  - {name: a, keys: ["` + testkeys.Line(t, 1) + `"]}
  - {name: a, keys: ["` + testkeys.Line(t, 2) + `"]}
`,
		"root not a mapping": "- just\n- a\n- list\n",
		// Review-found: append rebuilds null sections without carrying
		// anchors, so an alias elsewhere would dangle after a merge — Load
		// rejects the whole anchor/alias class up front.
		"anchored section value": "users: &u\nservers:\naccess: *u\n",
		// Fuzz-found: config.Parse tolerates an anchored empty top-level key,
		// but the re-encode → re-parse self-check does not; Load must be the
		// stricter gate so anything it accepts is re-encodable.
		"anchored empty top-level key": "users:\nservers:\n&0000: ",
		"anchored empty nested key": `
users:
  - name: bob
    &a :
     x
`,
		// Fuzz-found: a null sequence item is silently skipped when decoding
		// into a slice but re-encodes into an empty string the reparse
		// rejects ("unknown server \"\"").
		"null sequence item": `
users:
  - {name: bob, keys: ["` + testkeys.Line(t, 1) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - user: bob
    servers: [&x]
`,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(in)); err == nil {
				t.Errorf("Load accepted input config.Parse rejects:\n%s", in)
			}
		})
	}
}

func TestLoadExposesConfig(t *testing.T) {
	f, err := Load([]byte(commentedFixture(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	cfg := f.Config()
	if cfg == nil || len(cfg.Users) != 2 || len(cfg.Servers) != 2 {
		t.Fatalf("Config() = %+v, want the validated fixture config", cfg)
	}
	if _, ok := cfg.OwnerOf("nope"); ok {
		t.Errorf("OwnerOf must behave like a validated config")
	}
}

// TestAppendGolden: comments survive the append + re-encode; the appended
// block carries the injected merge-marker comment lines; blank-line loss is
// visible in the golden (fidelity contract: comments yes, blank lines no).
func TestAppendGolden(t *testing.T) {
	f, err := Load([]byte(commentedFixture(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	users := []UserEntry{carolEntry(t)}
	access := []AccessEntry{
		{User: "bob", Servers: []string{"web-2"}},
		{User: "carol-laptop", Servers: []string{"web-1", "web-2"}},
	}
	if err := f.Append(mergeComments, users, nil, access); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for _, want := range []string{
		"# fleet manifest — hand-maintained, do not regenerate",
		"# contact: ops@example.com",
		"# op holds the break-glass key",
		"# bob predates sshepherd",
		"# inline: the deploy account",
		"# reviewed 2026-07-01",
		"# merged by sshepherd adopt on 2026-07-16",
		"# WARNING: server db-9 unreadable — its access is NOT represented",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	out, err := config.Parse(got)
	if err != nil {
		t.Fatalf("merged manifest rejected by config.Parse: %v", err)
	}
	// carol-laptop gets web-1+web-2, bob web-1 (existing) + web-2 (appended),
	// op is operator: 3 keys desired on web-2.
	if n := len(out.DesiredFor("web-2")); n != 3 {
		t.Errorf("DesiredFor(web-2) = %d keys, want 3", n)
	}
	checkGolden(t, "append.golden", got)
}

// TestAppendServers: servers append into the fixture's existing block
// section, in the generators' field order (name, host, port, user) with
// port omitted when 0 — the caller's spelling of the effective default 22.
func TestAppendServers(t *testing.T) {
	f, err := Load([]byte(commentedFixture(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	servers := []ServerEntry{
		{Name: "db-9", Host: "10.0.0.9", User: "deploy"},
		{Name: "db-8", Host: "10.0.0.8", Port: 2222, User: "root"},
	}
	if err := f.Append(mergeComments, nil, servers, nil); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for _, want := range []string{
		"- name: db-9\n    host: 10.0.0.9\n    user: deploy\n",
		"- name: db-8\n    host: 10.0.0.8\n    port: 2222\n    user: root\n",
	} {
		if !strings.Contains(string(got), want) {
			t.Errorf("output lacks block %q:\n%s", want, got)
		}
	}
	out, err := config.Parse(got)
	if err != nil {
		t.Fatalf("merged manifest rejected by config.Parse: %v", err)
	}
	ports := make(map[string]int, len(out.Servers))
	for _, s := range out.Servers {
		ports[s.Name] = s.Port
	}
	if ports["db-9"] != 22 || ports["db-8"] != 2222 {
		t.Errorf("ports = %v, want db-9 defaulted to 22 and db-8 at 2222", ports)
	}
}

// TestAppendServerSectionShapes: like the users/access shapes, the servers
// section may be flow-empty (`servers: []`), null, or missing; a
// servers-only append must produce a valid block-style section in all
// three, with the marker riding the first server.
func TestAppendServerSectionShapes(t *testing.T) {
	cases := map[string]string{
		"flow empty": "users: []\nservers: []\naccess: []\n",
		"null":       "users:\nservers:\naccess:\n",
		"missing":    "users: []\n",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := Load([]byte(in))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			servers := []ServerEntry{{Name: "db-9", Host: "10.0.0.9", User: "deploy"}}
			if err := f.Append(mergeComments, nil, servers, nil); err != nil {
				t.Fatalf("Append: %v", err)
			}
			got, err := f.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if strings.Contains(string(got), "servers: []") {
				t.Errorf("flow-style empty servers section survived an append:\n%s", got)
			}
			out, err := config.Parse(got)
			if err != nil {
				t.Fatalf("merged manifest rejected by config.Parse: %v", err)
			}
			if len(out.Servers) != 1 || out.Servers[0].Name != "db-9" {
				t.Errorf("Servers = %+v, want just db-9:\n%s", out.Servers, got)
			}
			if !strings.Contains(string(got), "# merged by sshepherd adopt on 2026-07-16") {
				t.Errorf("output lacks the merge marker:\n%s", got)
			}
		})
	}
}

// TestAppendCommentLandsOnFirstServer: with no new users, the merge marker
// must ride the first appended server — not the access entries appended
// after it (marker priority: first user, else first server, else first
// access).
func TestAppendCommentLandsOnFirstServer(t *testing.T) {
	f, err := Load([]byte(commentedFixture(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	servers := []ServerEntry{{Name: "db-9", Host: "10.0.0.9", User: "deploy"}}
	access := []AccessEntry{{User: "bob", Servers: []string{"db-9"}}}
	if err := f.Append(mergeComments, nil, servers, access); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	s := string(got)
	marker := strings.Index(s, "# merged by sshepherd adopt on 2026-07-16")
	serversAt := strings.Index(s, "servers:")
	accessAt := strings.Index(s, "access:")
	if marker < 0 || marker < serversAt || marker > accessAt {
		t.Errorf("merge marker must sit inside the servers section (marker@%d, servers@%d, access@%d):\n%s",
			marker, serversAt, accessAt, s)
	}
}

// TestEncodeWithoutAppend: a pure load/encode round-trip keeps every comment
// and stays semantically identical (the no-additions merge building block).
func TestEncodeWithoutAppend(t *testing.T) {
	f, err := Load([]byte(commentedFixture(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	for _, want := range []string{"# contact: ops@example.com", "# bob predates sshepherd", "# reviewed 2026-07-01"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("round-trip lost %q:\n%s", want, got)
		}
	}
	out, err := config.Parse(got)
	if err != nil {
		t.Fatalf("round-tripped manifest rejected: %v", err)
	}
	if len(out.Users) != 2 || len(out.Servers) != 2 || len(out.Access) != 1 {
		t.Errorf("round-trip changed the config: %+v", out)
	}
}

// TestAppendSectionShapes: the section value may be a flow-style empty list
// (`users: []`, our own generators' bootstrap output — the memo's known
// edge), a null (`users:`), or missing entirely; append must produce a valid
// block-style section in all three shapes.
func TestAppendSectionShapes(t *testing.T) {
	server := "\nservers:\n  - {name: web-1, host: 10.0.0.1, user: deploy}\n"
	cases := map[string]string{
		"flow empty": "users: []" + server + "access: []\n",
		"null":       "users:" + server + "access:\n",
		"missing":    server,
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			f, err := Load([]byte(in))
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			users := []UserEntry{carolEntry(t)}
			access := []AccessEntry{{User: "carol-laptop", Servers: []string{"web-1"}}}
			if err := f.Append(mergeComments, users, nil, access); err != nil {
				t.Fatalf("Append: %v", err)
			}
			got, err := f.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			if strings.Contains(string(got), "users: []") {
				t.Errorf("flow-style empty users section survived an append:\n%s", got)
			}
			out, err := config.Parse(got)
			if err != nil {
				t.Fatalf("merged manifest rejected by config.Parse: %v", err)
			}
			if n := len(out.DesiredFor("web-1")); n != 1 {
				t.Errorf("DesiredFor(web-1) = %d keys, want 1 (carol):\n%s", n, got)
			}
			if !strings.Contains(string(got), "# merged by sshepherd adopt on 2026-07-16") {
				t.Errorf("output lacks the merge marker:\n%s", got)
			}
		})
	}
}

// TestAppendCommentLandsOnFirstNode: with no new users, the merge marker
// must ride the first appended access entry instead.
func TestAppendCommentLandsOnFirstNode(t *testing.T) {
	f, err := Load([]byte(commentedFixture(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := f.Append(mergeComments, nil, nil, []AccessEntry{{User: "bob", Servers: []string{"web-2"}}}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	s := string(got)
	marker := strings.Index(s, "# merged by sshepherd adopt on 2026-07-16")
	access := strings.Index(s, "access:")
	if marker < 0 || access < 0 || marker < access {
		t.Errorf("merge marker must sit inside the access section (marker@%d, access@%d):\n%s", marker, access, s)
	}
}

// TestAppendNothingIsANoop: no entries means no marker and no text growth —
// the byte-identical empty-plan contract lives at the cmd layer, but the
// package must not invent content either.
func TestAppendNothingIsANoop(t *testing.T) {
	f, err := Load([]byte(commentedFixture(t)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := f.Append(mergeComments, nil, nil, nil); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got, err := f.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if strings.Contains(string(got), "merged by sshepherd") {
		t.Errorf("empty append still left a merge marker:\n%s", got)
	}
}
