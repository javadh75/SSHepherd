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
