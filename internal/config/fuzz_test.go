package config

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// FuzzLoad fuzzes the manifest trust gate every write passes through. Parse
// must never panic, and anything it accepts must satisfy the invariants
// apply's renderer relies on: every rendered field (server name/host/user,
// desired comments, key options) passes the same safety predicates, and
// each server's rendered authorized_keys re-parses cleanly and re-renders
// byte-exactly — fingerprints, options and comments intact.
func FuzzLoad(f *testing.F) {
	k1, k2 := testkeys.Line(f, 1), testkeys.Line(f, 2)
	seeds := []string{
		"",
		"users: [",
		manifest(k1, k2),
		// anchors and aliases
		"users: &u\n  - {name: a, keys: [\"" + k1 + "\"]}\nservers: []\naccess: *u\n",
		// huge and negative ports
		"servers:\n  - {name: s, host: h, user: u, port: 99999999999999999999}\n",
		"servers:\n  - {name: s, host: h, user: u, port: -1}\n",
		// escapes in every rendered field
		"users:\n  - {name: \"a\\e[31m\", comment: \"c\\u2028d\", keys: [\"" + k1 + "\"]}\n",
		"servers:\n  - {name: \"s\\e[1A\", host: \"h\\n\", user: \"u\\u202e\"}\n",
		"users:\n  - {name: a, keys: ['from=\"1.2.3.4\\e[2J\" " + k1 + "']}\n",
		// multi-document, wildcard, operator, overrides
		"users: []\n---\nusers: []\n",
		`
users:
  - {name: op, operator: true, keys: ['restrict,command="echo a,b" ` + k1 + ` op@x']}
  - {name: bob, comment: bob@work, keys: ["` + k2 + `"]}
servers:
  - {name: s1, host: h, user: u, authorized_keys_file: "~/.ssh/k"}
  - {name: s2, host: h, user: u, port: 2222, authorized_keys_file: "/etc/%u"}
access:
  - {user: bob, servers: ["*"], except: [s2]}
`,
		// revocation memory: serial, key and access tombstones, a conflict, D1e
		"serial: 7\n" + manifest(k1, k2) + "revoked:\n  - {fingerprint: " + fpFor(f, k1) + ", user: alice, date: 2026-11-08, reason: offboarded}\n  - {user: bob, servers: [web-1, db-9], date: 2026-11-08}\n",
		"serial: -1\nusers: []\n",
		"revoked:\n  - {fingerprint: 'SHA256:x', servers: ['*'], date: '2026-1-8', user: \"a\\e\"}\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	// The CLI goldens are real generated manifests (import/adopt output).
	goldens, _ := filepath.Glob(filepath.Join("..", "..", "cmd", "sshepherd", "testdata", "*.golden"))
	for _, g := range goldens {
		if data, err := os.ReadFile(g); err == nil { // #nosec G304 -- fixed test fixture glob
			f.Add(data)
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		cfg, err := Parse(data)
		if err != nil {
			return
		}
		for _, s := range cfg.Servers {
			for _, field := range []string{s.Name, s.Host, s.User} {
				if issue := ServerFieldIssue(field); issue != "" {
					t.Fatalf("accepted server field %q %s", field, issue)
				}
			}
			checkRenderRoundTrip(t, cfg, s.Name)
		}
		if cfg.Serial() > MaxSerial {
			t.Fatalf("accepted serial %d over %d", cfg.Serial(), MaxSerial)
		}
		names := make(map[string]bool, len(cfg.Servers))
		for _, s := range cfg.Servers {
			names[s.Name] = true
		}
		for _, tb := range cfg.Tombstones {
			for _, v := range []string{tb.User, tb.Reason} {
				if authkeys.RenderTextIssue(v) != "" || len(v) > maxTombstoneText {
					t.Fatalf("accepted tombstone text %q", v)
				}
			}
		}
		for _, c := range cfg.Conflicts() {
			for _, s := range c.Servers {
				if !names[s] {
					t.Fatalf("conflict %+v names unknown server %q", c, s)
				}
			}
		}
	})
}

func fpFor(tb testing.TB, line string) string {
	tb.Helper()
	k, err := authkeys.ParseLine(line)
	if err != nil || k == nil {
		tb.Fatalf("fpFor: %v", err)
	}
	return k.Fingerprint
}

// checkRenderRoundTrip renders server's desired file exactly as apply does
// and asserts it parses back without loss and re-renders byte-identically.
func checkRenderRoundTrip(t *testing.T, cfg *Config, server string) {
	t.Helper()
	desired := cfg.DesiredFor(server)
	entries := make([]authkeys.RenderEntry, 0, len(desired))
	for _, k := range desired {
		u, ok := cfg.OwnerOf(k.Fingerprint)
		if !ok {
			t.Fatalf("server %q: desired key %s has no owner", server, k.Fingerprint)
		}
		comment := DesiredComment(u, k)
		if issue := authkeys.RenderTextIssue(comment); issue != "" {
			t.Fatalf("server %q: accepted comment %q %s", server, comment, issue)
		}
		for _, opt := range k.Options {
			if issue := optionIssue(opt); issue != "" {
				t.Fatalf("server %q: accepted option %q %s", server, opt, issue)
			}
		}
		entries = append(entries, authkeys.RenderEntry{Key: k, Comment: comment})
	}
	out, err := authkeys.Render(entries)
	if err != nil {
		t.Fatalf("server %q: Render: %v", server, err)
	}
	back, perrs := authkeys.ParseFile(out)
	if len(perrs) > 0 || len(back) != len(entries) {
		t.Fatalf("server %q: rendered file does not re-parse (%d keys of %d, errs %v):\n%s",
			server, len(back), len(entries), perrs, out)
	}
	again := make([]authkeys.RenderEntry, len(back))
	for i, k := range back {
		want := entries[i]
		if k.Fingerprint != want.Key.Fingerprint || k.Comment != want.Comment ||
			!slices.Equal(k.Options, want.Key.Options) {
			t.Fatalf("server %q: line %d came back as %+v, want %+v", server, i+1, k, want)
		}
		again[i] = authkeys.RenderEntry{Key: k, Comment: k.Comment}
	}
	out2, err := authkeys.Render(again)
	if err != nil || !bytes.Equal(out, out2) {
		t.Fatalf("server %q: re-render differs (err %v):\n%s\n---\n%s", server, err, out, out2)
	}
}
