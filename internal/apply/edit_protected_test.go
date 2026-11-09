package apply

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderEditHeaderProtected(t *testing.T) {
	s := EditSummary{
		Edits:     []Edit{{Kind: EditRemoveUser, User: "ci", Keys: 1, Grants: 1}, {Kind: EditRemoveUser, User: "ops-bot", Keys: 1}},
		Affected:  2,
		Operators: []string{"ops-bot"},
		Protected: []string{"ci"},
	}
	var buf bytes.Buffer
	RenderEditHeader(&buf, s, RenderOptions{})
	for _, want := range []string{
		"OPERATOR: ops-bot is an operator (fleet-wide, protected); --operator given\n",
		"PROTECTED: ci is protected; --operator given\n",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("header lacks %q:\n%s", want, buf.String())
		}
	}
	checkGolden(t, "edit_header_protected.golden", buf.Bytes())
	var color bytes.Buffer
	RenderEditHeader(&color, s, RenderOptions{Color: true})
	if !strings.Contains(color.String(), "\x1b[1;31mPROTECTED:\x1b[0m ci is protected") {
		t.Errorf("color header:\n%q", color.String())
	}
}

// TestRenderEditHeaderStillProtected: a user who stays protected after the
// edit needs --operator on the printed 'sshepherd revoke' too, or the hint
// itself exits 3. A user whose only protection the edit clears does not.
func TestRenderEditHeaderStillProtected(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit Edit
		want string
	}{
		{"no keys left", Edit{Kind: EditRemoveKey, User: "ci", NoKeysLeft: true, StillProtected: true},
			"note: ci has no keys left — 'sshepherd revoke ci --config m.yaml --operator' removes the user\n"},
		{"no access left", Edit{Kind: EditRemoveAccess, User: "ci", NoGrantsLeft: true, StillProtected: true},
			"note: ci has no access left — 'sshepherd revoke ci --config m.yaml --operator' removes the user\n"},
		{"operator flag cleared, protected: stays", Edit{Kind: EditRemoveKey, User: "both", NoKeysLeft: true, ClearsOperator: true, StillProtected: true},
			"note: both has no keys left, so its operator flag is cleared — 'sshepherd revoke both --config m.yaml --operator' removes the user\n"},
		{"operator flag cleared, nothing left to protect", Edit{Kind: EditRemoveKey, User: "op", NoKeysLeft: true, ClearsOperator: true},
			"note: op has no keys left, so its operator flag is cleared — 'sshepherd revoke op --config m.yaml' removes the user\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			RenderEditHeader(&buf, EditSummary{Edits: []Edit{tc.edit}, FollowUp: " --config m.yaml"}, RenderOptions{})
			if !strings.Contains(buf.String(), tc.want) {
				t.Errorf("header lacks %q:\n%s", tc.want, buf.String())
			}
		})
	}
}

// TestEditPromptProtected: any target that is not a fleet-wide operator makes
// the prefix the protected form, and a list mixing the two uses it too.
func TestEditPromptProtected(t *testing.T) {
	for _, tc := range []struct {
		name                string
		operators, protects []string
		want                string
	}{
		{"one protected", nil, []string{"ci"}, "PROTECTED ci: save manifest edit and write 1 of 2 affected servers?"},
		{"two protected", nil, []string{"ci", "scoped"}, "PROTECTED ci, scoped: save manifest edit and write 1 of 2 affected servers?"},
		{"mixed", []string{"ops"}, []string{"ci"}, "PROTECTED ops, ci: save manifest edit and write 1 of 2 affected servers?"},
		{"operators unchanged", []string{"ops", "bot"}, nil, "OPERATORS ops, bot: save manifest edit and write 1 of 2 affected servers?"},
		{"one operator unchanged", []string{"ops"}, nil, "OPERATOR ops: save manifest edit and write 1 of 2 affected servers?"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EditPrompt(tc.operators, tc.protects, 1, 2, false); got != tc.want {
				t.Errorf("prompt = %q, want %q", got, tc.want)
			}
		})
	}
}
