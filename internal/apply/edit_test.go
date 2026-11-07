package apply

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestRenderEditHeaderGoldens(t *testing.T) {
	tests := []struct {
		golden string
		s      EditSummary
		color  bool
	}{
		{"edit_header_user.golden", EditSummary{
			Edits:    []Edit{{Kind: EditRemoveUser, User: "alice", Keys: 2, Grants: 3}},
			Affected: 3,
			Emptied:  []EmptiedServer{{Server: "db-1", Users: []string{"alice"}, Keys: 1}},
		}, false},
		{"edit_header_key.golden", EditSummary{
			Edits:    []Edit{{Kind: EditRemoveKey, User: "bob", Fingerprint: fp(t, 3), NoKeysLeft: true}},
			Affected: 2,
		}, false},
		{"edit_header_rotate.golden", EditSummary{
			Edits: []Edit{{Kind: EditRotate, User: "deploy", Fingerprint: fp(t, 4), NewFingerprint: fp(t, 5),
				KeepsExpiry: `expiry-time="20270101"`}},
			Affected: 5,
		}, false},
		{"edit_header_operator.golden", EditSummary{
			Edits: []Edit{
				{Kind: EditRemoveKey, User: "ops-bot", Fingerprint: fp(t, 1), NoKeysLeft: true, ClearsOperator: true},
				{Kind: EditRemoveUser, User: "alice", Keys: 1, Grants: 1},
			},
			Affected:  1,
			Operators: []string{"ops-bot"},
			Emptied:   []EmptiedServer{{Server: "db-1", Users: []string{"alice", "ops-bot"}, Keys: 2}},
		}, false},
		{"edit_header_operator_color.golden", EditSummary{
			Edits:     []Edit{{Kind: EditRemoveUser, User: "ops-bot", Keys: 2, Grants: 0}},
			Affected:  4,
			Operators: []string{"ops-bot"},
			Emptied:   []EmptiedServer{{Server: "db-1", Users: []string{"ops-bot"}, Keys: 2}},
		}, true},
		{"edit_header_none.golden", EditSummary{
			Edits:    []Edit{{Kind: EditRemoveUser, User: "dave", Keys: 1, Grants: 0}},
			Affected: 0,
		}, false},
	}
	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			var buf bytes.Buffer
			RenderEditHeader(&buf, tt.s, RenderOptions{Color: tt.color})
			checkGolden(t, tt.golden, buf.Bytes())
		})
	}
}

// TestRenderEditHeaderShapes pins the key phrases independent of goldens.
func TestRenderEditHeaderShapes(t *testing.T) {
	var buf bytes.Buffer
	RenderEditHeader(&buf, EditSummary{
		Edits:    []Edit{{Kind: EditRemoveUser, User: "alice", Keys: 1, Grants: 1}},
		Affected: 1,
		Emptied:  []EmptiedServer{{Server: "db-1", Users: []string{"alice"}, Keys: 1}},
	}, RenderOptions{})
	for _, want := range []string{
		"manifest edit: remove user alice (1 key, 1 access grant) — 1 server affected\n",
		"warning: db-1 would have no granted keys — apply never empties a server, so alice's key stays installed there; grant another user (or an operator) on db-1 first, or remove the key by hand\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("header lacks %q:\n%s", want, buf.String())
		}
	}
}

func TestRenderEditHeaderColorStrippedEqualsPlain(t *testing.T) {
	s := EditSummary{
		Edits:     []Edit{{Kind: EditRemoveUser, User: "ops-bot", Keys: 2}},
		Affected:  4,
		Operators: []string{"ops-bot"},
		Emptied:   []EmptiedServer{{Server: "db-1", Users: []string{"ops-bot"}, Keys: 2}},
	}
	var plain, color bytes.Buffer
	RenderEditHeader(&plain, s, RenderOptions{})
	RenderEditHeader(&color, s, RenderOptions{Color: true})
	stripped := color.String()
	for _, code := range []string{codeBoldRed, codeYellow} {
		stripped = strings.ReplaceAll(stripped, "\x1b["+code+"m", "")
	}
	if stripped = strings.ReplaceAll(stripped, "\x1b[0m", ""); stripped != plain.String() {
		t.Errorf("stripped color = %q, want plain %q", stripped, plain.String())
	}
}

// TestEditPromptGolden pins every prompt form, exactly as confirm prints
// it (question + " [y/N]").
func TestEditPromptGolden(t *testing.T) {
	var buf bytes.Buffer
	for _, q := range []string{
		EditPrompt(nil, 2, 3, false),
		EditPrompt(nil, 0, 3, false),
		EditPrompt(nil, 0, 0, false),
		EditPrompt(nil, 0, 3, true),
		EditPrompt([]string{"ops-bot"}, 1, 4, false),
		EditPrompt([]string{"ops-bot", "ci"}, 0, 2, true),
	} {
		fmt.Fprintln(&buf, q+" [y/N]")
	}
	want := "save manifest edit and write 2 of 3 affected servers? [y/N]\n"
	if !strings.HasPrefix(buf.String(), want) {
		t.Errorf("first prompt = %q, want %q", strings.SplitAfter(buf.String(), "\n")[0], want)
	}
	checkGolden(t, "edit_prompt.golden", buf.Bytes())
}

// TestRenderEditHeaderRemoveAccess: one line per user; count fragments
// pluralized and omitted when zero (the first present one names "access
// entry"); the wildcard-removed warning and the no-access-left note follow
// the edit lines; the affected tail obeys the lone-edit rule.
func TestRenderEditHeaderRemoveAccess(t *testing.T) {
	tests := []struct {
		golden string
		s      EditSummary
		color  bool
	}{
		{"edit_header_access.golden", EditSummary{
			Edits: []Edit{{Kind: EditRemoveAccess, User: "bob", AccessServers: []string{"web-1", "db-1"},
				EntriesChanged: 2, EntriesRemoved: 1, ServersExcepted: 1}},
			Affected: 2,
		}, false},
		{"edit_header_access_multi.golden", EditSummary{
			Edits: []Edit{
				{Kind: EditRemoveAccess, User: "alice", AccessServers: []string{"web-1"}, EntriesRemoved: 1, WildcardsRemoved: 1, NoGrantsLeft: true},
				{Kind: EditRemoveAccess, User: "bob", AccessServers: []string{"web-1"}, EntriesChanged: 1, ServersExcepted: 1},
			},
			Affected: 1,
			Emptied:  []EmptiedServer{{Server: "web-1", Users: []string{"alice", "bob"}, Keys: 2}},
		}, false},
		{"edit_header_access_color.golden", EditSummary{
			Edits:    []Edit{{Kind: EditRemoveAccess, User: "carol", AccessServers: []string{"db-1"}, EntriesRemoved: 1, WildcardsRemoved: 1, NoGrantsLeft: true}},
			Affected: 1,
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.golden, func(t *testing.T) {
			var buf bytes.Buffer
			RenderEditHeader(&buf, tt.s, RenderOptions{Color: tt.color})
			checkGolden(t, tt.golden, buf.Bytes())
		})
	}
}

// TestEditTextRemoveAccessCounts pins every fragment combination.
func TestEditTextRemoveAccessCounts(t *testing.T) {
	e := func(changed, removed, excepted int) Edit {
		return Edit{Kind: EditRemoveAccess, User: "bob", AccessServers: []string{"web-1"},
			EntriesChanged: changed, EntriesRemoved: removed, ServersExcepted: excepted}
	}
	for _, tt := range []struct {
		e    Edit
		want string
	}{
		{e(1, 0, 0), "remove bob's access to web-1 (1 access entry changed)"},
		{e(2, 1, 2), "remove bob's access to web-1 (2 access entries changed, 1 removed, 2 servers excepted)"},
		{e(0, 2, 0), "remove bob's access to web-1 (2 access entries removed)"},
		{e(1, 0, 1), "remove bob's access to web-1 (1 access entry changed, 1 server excepted)"},
		{e(0, 0, 0), "remove bob's access to web-1"},
	} {
		if got := editText(tt.e); got != tt.want {
			t.Errorf("editText(%+v) = %q, want %q", tt.e, got, tt.want)
		}
	}
}

// TestRenderEditHeaderKeepOld: rotate --keep-old adds "keeps the old key",
// joined to the expiry fragment with "; " when one carries over.
func TestRenderEditHeaderKeepOld(t *testing.T) {
	for _, tt := range []struct {
		golden string
		expiry string
	}{
		{"edit_header_keep_old.golden", ""},
		{"edit_header_keep_old_expiry.golden", `expiry-time="20270101"`},
	} {
		t.Run(tt.golden, func(t *testing.T) {
			var buf bytes.Buffer
			RenderEditHeader(&buf, EditSummary{
				Edits: []Edit{{Kind: EditRotate, User: "bob", Fingerprint: fp(t, 4), NewFingerprint: fp(t, 5),
					KeepsExpiry: tt.expiry, KeepOld: true}},
				Affected: 3,
			}, RenderOptions{})
			checkGolden(t, tt.golden, buf.Bytes())
		})
	}
	var buf bytes.Buffer
	RenderEditHeader(&buf, EditSummary{Edits: []Edit{{Kind: EditRotate, User: "bob", Fingerprint: "SHA256:old", NewFingerprint: "SHA256:new",
		KeepsExpiry: `expiry-time="20270101"`, KeepOld: true}}, Affected: 3}, RenderOptions{})
	if want := "manifest edit: rotate bob key SHA256:old → SHA256:new (keeps the old key; keeps expiry-time=\"20270101\") — 3 servers affected\n"; buf.String() != want {
		t.Errorf("header = %q, want %q", buf.String(), want)
	}
}
