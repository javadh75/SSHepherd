package apply

import (
	"fmt"
	"io"
	"strings"

	"github.com/javadh75/SSHepherd/internal/config"
)

// EditKind names one manifest edit revoke/rotate performs.
type EditKind string

// The five edits.
const (
	EditRemoveUser   EditKind = "remove-user"   // revoke USER
	EditRemoveKey    EditKind = "remove-key"    // revoke --key
	EditRotate       EditKind = "rotate"        // rotate USER --old --new
	EditRemoveAccess EditKind = "remove-access" // revoke USER --server
	EditRecordKey    EditKind = "record-key"    // revoke --key of a key no user has (D1b): a tombstone, no server written
)

// Edit is one manifest edit, resolved against the as-loaded config.
type Edit struct {
	Kind EditKind
	// User is the removed user (EditRemoveUser), the removed key's owner
	// (EditRemoveKey), the rotated user (EditRotate), or the user losing
	// access (EditRemoveAccess).
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
	// KeepOld (EditRotate) is rotate --keep-old: the new key is added
	// after the old one, which stays (an overlap).
	KeepOld bool
	// NoKeysLeft (EditRemoveKey) reports that the owner has no keys left
	// after the whole edit; ClearsOperator that the owner was an operator
	// whose flag the edit clears (operator: true needs a key).
	NoKeysLeft, ClearsOperator bool
	// AccessServers (EditRemoveAccess) are the servers the user loses, as
	// named on the command line (de-duplicated, order kept).
	AccessServers []string
	// EntriesChanged, EntriesRemoved, ServersExcepted and WildcardsRemoved
	// (EditRemoveAccess) are manifest.AccessRemoval's counts.
	EntriesChanged, EntriesRemoved, ServersExcepted, WildcardsRemoved int
	// NoGrantsLeft (EditRemoveAccess) reports that the user has no access:
	// entry left after the whole edit.
	NoGrantsLeft bool
	// KeepsServers (EditRemoveAccess) counts the servers the user still
	// covers after the edit.
	KeepsServers int
}

// EmptiedServer is an affected server left with no granted keys: the
// removed keys stay installed there (apply never empties a server).
type EmptiedServer struct {
	Server string
	Users  []string // owners of the keys that stay installed, old-config order
	Keys   int      // how many removed keys were granted there
}

// AlreadyRevoked is a revoke target an earlier revoke already recorded
// (D1c: a user or a user's access; D1b: an unowned fingerprint): a no-op,
// exit 0. The json tags are edit.already_revoked's wire shape.
type AlreadyRevoked struct {
	User        string   `json:"user,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	Servers     []string `json:"servers,omitempty"`
	Date        string   `json:"date"`
}

// EditSummary is everything the edit header shows.
type EditSummary struct {
	Edits     []Edit
	Affected  int      // servers whose rendered desired file changes
	Operators []string // operator targets, acknowledged with --operator
	Emptied   []EmptiedServer
	// Serial is the manifest serial the edit saves (every saving revoke and
	// rotate bumps it once).
	Serial uint64
	// Revoked are the tombstones this edit adds to revoked:.
	Revoked []config.Tombstone
	// AlreadyRevoked are the targets an earlier revoke already recorded.
	AlreadyRevoked []AlreadyRevoked
	// CheckCommand is the printed follow-up audit ("" when no key was
	// removed, or when --sweep ran).
	CheckCommand string
	// FollowUp is the run's non-default flags appended to the header's
	// 'sshepherd revoke USER' hints (" --config fleet.yaml"); "" for none.
	// Not part of the JSON.
	FollowUp string
}

// RenderEditHeader writes the manifest-edit header printed above the
// per-server plan (and alone under --no-apply): one line per edit (the
// affected-server count on the line of a lone edit, else on a closing
// line), a note per user left without keys or without access, a warning
// per user whose wildcard grant is removed, an OPERATOR line per operator
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
		if e.WildcardsRemoved > 0 {
			fmt.Fprintf(w, "%s %s's wildcard grant is removed — it would cover no current server; servers added later are no longer granted to %s automatically\n",
				pal.paint(codeYellow, "warning:"), e.User, e.User)
		}
		switch {
		case e.NoGrantsLeft:
			fmt.Fprintf(w, "note: %s has no access left — 'sshepherd revoke %s%s' removes the user\n", e.User, e.User, s.FollowUp)
		case e.ClearsOperator:
			fmt.Fprintf(w, "note: %s has no keys left, so its operator flag is cleared — 'sshepherd revoke %s%s' removes the user\n", e.User, e.User, s.FollowUp)
		case e.NoKeysLeft:
			fmt.Fprintf(w, "note: %s has no keys left — 'sshepherd revoke %s%s' removes the user\n", e.User, e.User, s.FollowUp)
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
	case EditRecordKey:
		return fmt.Sprintf("record revoked key %s (no user has it; no server is written)", e.Fingerprint)
	case EditRemoveAccess:
		t := fmt.Sprintf("remove %s's access to %s", e.User, strings.Join(e.AccessServers, ", "))
		if c := accessCounts(e); c != "" {
			t += " (" + c + ")"
		}
		if e.KeepsServers > 0 {
			t += "; " + e.User + " keeps access to " + Plural(e.KeepsServers, "other server", "other servers")
		}
		return t
	default:
		t := fmt.Sprintf("rotate %s key %s → %s", e.User, e.Fingerprint, e.NewFingerprint)
		var keeps []string
		if e.KeepOld {
			keeps = append(keeps, "keeps the old key")
		}
		if e.KeepsExpiry != "" {
			keeps = append(keeps, "keeps "+e.KeepsExpiry)
		}
		if len(keeps) > 0 {
			t += " (" + strings.Join(keeps, "; ") + ")"
		}
		return t
	}
}

// accessCounts is a remove-access edit's count fragments, each omitted
// when zero; "access entry/entries" names the first one present.
func accessCounts(e Edit) string {
	var parts []string
	noun := func(n int) string {
		if len(parts) == 0 {
			return Plural(n, "access entry", "access entries")
		}
		return fmt.Sprint(n)
	}
	if e.EntriesChanged > 0 {
		parts = append(parts, noun(e.EntriesChanged)+" changed")
	}
	if e.EntriesRemoved > 0 {
		parts = append(parts, noun(e.EntriesRemoved)+" removed")
	}
	if e.ServersExcepted > 0 {
		parts = append(parts, Plural(e.ServersExcepted, "server", "servers")+" excepted")
	}
	return strings.Join(parts, ", ")
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
// servers will be written, prefixed "OPERATOR NAME: " for one operator
// target, or "OPERATORS A, B: " for several.
func EditPrompt(operators []string, toWrite, affected int, noApply bool) string {
	var b strings.Builder
	switch len(operators) {
	case 0:
	case 1:
		fmt.Fprintf(&b, "OPERATOR %s: ", operators[0])
	default:
		fmt.Fprintf(&b, "OPERATORS %s: ", strings.Join(operators, ", "))
	}
	switch {
	case noApply:
		b.WriteString("save manifest edit?")
	case toWrite == 0:
		b.WriteString("save manifest edit (no servers need a write)?")
	default:
		fmt.Fprintf(&b, "save manifest edit and write %d of %s?", toWrite, Plural(affected, "affected server", "affected servers"))
	}
	return b.String()
}
