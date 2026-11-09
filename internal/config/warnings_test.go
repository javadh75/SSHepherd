package config

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// TestManifestWarningsMirrorWarnings: every load warning is recorded twice,
// as text for stderr and as a structured object for JSON, in the same order,
// each with its kind.
func TestManifestWarningsMirrorWarnings(t *testing.T) {
	pinNow(t, time.Date(2026, 6, 15, 0, 0, 0, 0, time.UTC))
	cfg, err := Parse([]byte(`users:
  - {name: multi, comment: "c", keys: ["` + testkeys.Line(t, 1) + `", "` + testkeys.Line(t, 2) + `"]}
  - {name: old, keys: ["` + testkeys.DSALine(t, 7) + `"]}
  - {name: gone, keys: ["expiry-time=\"20200101\" ` + testkeys.Line(t, 3) + `"]}
servers:
  - {name: web-1, host: 10.0.0.1, user: deploy}
access:
  - {user: gone, servers: [web-1]}
revoked:
  - {user: gone, servers: [db-9], date: 2026-11-08}
`))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	var kinds, messages []string
	for _, w := range cfg.ManifestWarnings {
		kinds = append(kinds, w.Kind)
		messages = append(messages, w.Message)
	}
	want := []string{WarnCommentOnMultiKey, WarnTombstoneUnknownServer, WarnWeakKeyUngranted, WarnKeyExpired}
	if !slices.Equal(kinds, want) {
		t.Errorf("kinds = %v, want %v", kinds, want)
	}
	if !slices.Equal(messages, cfg.Warnings) {
		t.Errorf("messages = %q\nWarnings = %q", messages, cfg.Warnings)
	}
	for _, w := range cfg.ManifestWarnings {
		if w.Kind == WarnTombstoneUnknownServer {
			if w.RevokedIndex == nil || *w.RevokedIndex != 0 || w.User != "gone" || w.Server != "db-9" {
				t.Errorf("tombstone warning = %+v", w)
			}
			continue
		}
		if w.RevokedIndex != nil || w.User != "" || w.Server != "" {
			t.Errorf("%s carries tombstone fields: %+v", w.Kind, w)
		}
	}
}

// TestManifestWarningWireShape: revoked[0] still prints its index, and the
// tombstone fields vanish for every other kind.
func TestManifestWarningWireShape(t *testing.T) {
	zero := 0
	for _, tc := range []struct {
		w    ManifestWarning
		want string
	}{
		{ManifestWarning{Kind: WarnTombstoneUnknownServer, RevokedIndex: &zero, User: "bob", Server: "db-9", Message: "m"},
			`{"kind":"tombstone_unknown_server","revoked_index":0,"user":"bob","server":"db-9","message":"m"}`},
		{ManifestWarning{Kind: WarnCommentOnMultiKey, Message: "m"}, `{"kind":"comment_on_multi_key","message":"m"}`},
	} {
		got, err := json.Marshal(tc.w)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != tc.want {
			t.Errorf("got %s\nwant %s", got, tc.want)
		}
	}
}
