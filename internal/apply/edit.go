package apply

import (
	"fmt"
	"io"
	"strings"
)

// EditKind names one manifest edit revoke/rotate performs.
type EditKind string

// The three edits.
const (
	EditRemoveUser EditKind = "remove-user" // revoke USER
	EditRemoveKey  EditKind = "remove-key"  // revoke --key
	EditRotate     EditKind = "rotate"      // rotate USER --old --new
)

// Edit is one manifest edit, resolved against the as-loaded config.
type Edit struct {
	Kind EditKind
	// User is the removed user (EditRemoveUser), the removed key's owner
	// (EditRemoveKey), or the rotated user (EditRotate).
	User string
	// Keys and Grants count what EditRemoveUser deletes: the user's key
	// lines and the access: entries naming the user.
	Keys, Grants int
	// Fingerprint is the removed key (EditRemoveKey) or the old key
	// (EditRotate); NewFingerprint is the rotated-in key.
	Fingerprint, NewFingerprint string
	// KeepsExpiry is the old line's expiry-time= option, verbatim, that a
	// rotation carries over ("" when none).
	KeepsExpiry string
	// NoKeysLeft (EditRemoveKey) reports that the owner has no keys left
	// after the whole edit; ClearsOperator that the owner was an operator
	// whose flag the edit clears (operator: true needs a key).
	NoKeysLeft, ClearsOperator bool
}

// EmptiedServer is an affected server left with no granted keys: the
// removed keys stay installed there (apply never empties a server).
type EmptiedServer struct {
	Server string
	Users  []string // owners of the keys that stay installed, old-config order
	Keys   int      // how many removed keys were granted there
}

// EditSummary is everything the edit header shows.
type EditSummary struct {
	Edits     []Edit
	Affected  int      // servers whose rendered desired file changes
	Operators []string // operator targets, acknowledged with --operator
	Emptied   []EmptiedServer
}

// RenderEditHeader writes the manifest-edit header printed above the
// per-server plan (and alone under --no-apply): one line per edit (the
// affected-server count on the line of a lone edit, else on a closing
// line), a note per user left without keys, an OPERATOR line per operator
// target, and a warning per emptied server.
func RenderEditHeader(w io.Writer, s EditSummary, opts RenderOptions) {
	pal := palette{on: opts.Color}
	affected := Plural(s.Affected, "server", "servers") + " affected"
	if s.Affected == 0 {
		affected = "no servers affected"
	}
	for _, e := range s.Edits {
		line := "manifest edit: " + editText(e)
		if len(s.Edits) == 1 {
			line += " — " + affected
		}
		fmt.Fprintln(w, line)
	}
	if len(s.Edits) > 1 {
		fmt.Fprintf(w, "manifest edit: %d changes — %s\n", len(s.Edits), affected)
	}
	for _, e := range s.Edits {
		switch {
		case e.ClearsOperator:
			fmt.Fprintf(w, "note: %s has no keys left, so its operator flag is cleared — 'sshepherd revoke %s' removes the user\n", e.User, e.User)
		case e.NoKeysLeft:
			fmt.Fprintf(w, "note: %s has no keys left — 'sshepherd revoke %s' removes the user\n", e.User, e.User)
		}
	}
	for _, op := range s.Operators {
		fmt.Fprintf(w, "%s %s is an operator (fleet-wide, protected); --operator given\n", pal.paint(codeBoldRed, "OPERATOR:"), op)
	}
	for _, e := range s.Emptied {
		fmt.Fprintf(w, "%s %s would have no granted keys — apply never empties a server, so %s installed there; grant another user (or an operator) on %s first, or remove the key by hand\n",
			pal.paint(codeYellow, "warning:"), e.Server, stayText(e), e.Server)
	}
}

// editText describes one edit.
func editText(e Edit) string {
	switch e.Kind {
	case EditRemoveUser:
		return fmt.Sprintf("remove user %s (%s, %s)", e.User,
			Plural(e.Keys, "key", "keys"), Plural(e.Grants, "access grant", "access grants"))
	case EditRemoveKey:
		return fmt.Sprintf("remove key %s from %s", e.Fingerprint, e.User)
	default:
		t := fmt.Sprintf("rotate %s key %s → %s", e.User, e.Fingerprint, e.NewFingerprint)
		if e.KeepsExpiry != "" {
			t += fmt.Sprintf(" (keeps %s)", e.KeepsExpiry)
		}
		return t
	}
}

// stayText names what stays installed on an emptied server.
func stayText(e EmptiedServer) string {
	switch {
	case len(e.Users) > 1:
		return "the keys of " + strings.Join(e.Users, ", ") + " stay"
	case e.Keys > 1:
		return e.Users[0] + "'s keys stay"
	case len(e.Users) == 1:
		return e.Users[0] + "'s key stays"
	}
	return "the removed key stays"
}

// EditPrompt is revoke/rotate's confirmation question (confirm appends
// " [y/N] "): the save is always asked for, with the write count when
// servers will be written, prefixed "OPERATOR NAME: " per operator target.
func EditPrompt(operators []string, toWrite, affected int, noApply bool) string {
	var b strings.Builder
	for _, op := range operators {
		fmt.Fprintf(&b, "OPERATOR %s: ", op)
	}
	switch {
	case noApply:
		b.WriteString("save manifest edit?")
	case toWrite == 0:
		b.WriteString("save manifest edit (no servers need a write)?")
	default:
		fmt.Fprintf(&b, "save manifest edit and write %d of %d affected servers?", toWrite, affected)
	}
	return b.String()
}
