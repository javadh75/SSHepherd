package manifest

import (
	"fmt"
	"slices"
	"strconv"

	"gopkg.in/yaml.v3"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// UserRemoval reports what RemoveUser deleted.
type UserRemoval struct {
	Keys   int // key lines the users: entry held
	Grants int // access: entries whose user: named the user
}

// RemoveUser deletes the users: entry named name and every access: entry
// whose user: is name. A removed entry's head comment moves to the next
// entry of its section, or to the section's footer when none follows; its
// line and foot comments go with it. Node tree only: nothing validates
// until Encode.
func (f *File) RemoveUser(name string) (UserRemoval, error) {
	m, err := f.rootMapping()
	if err != nil {
		return UserRemoval{}, err
	}
	usersKey, users := sectionOf(m, "users")
	item := userItem(users, name)
	if item == nil {
		return UserRemoval{}, fmt.Errorf("user %q is not in the manifest", name)
	}
	var r UserRemoval
	if keys := valueOf(item, "keys"); keys != nil && keys.Kind == yaml.SequenceNode {
		r.Keys = len(keys.Content)
	}
	removeItems(usersKey, users, func(n *yaml.Node) bool { return n == item }, true)
	if accessKey, access := sectionOf(m, "access"); access != nil {
		r.Grants = removeItems(accessKey, access, func(n *yaml.Node) bool {
			return scalarField(n, "user") == name
		}, true)
	}
	return r, nil
}

// RemoveKey deletes the keys: line whose parsed fingerprint is fp (options,
// comment and spacing are irrelevant) and reports its owner and whether
// the owner's keys: list is now empty. The line's head comment goes with
// it: it describes that key, and moving it would re-label a survivor.
func (f *File) RemoveKey(fp string) (owner string, lastKey bool, err error) {
	user, keys, idx, err := f.findKey(fp)
	if err != nil {
		return "", false, err
	}
	target := keys.Content[idx]
	removeItems(nil, keys, func(n *yaml.Node) bool { return n == target }, false)
	return scalarField(user, "name"), len(keys.Content) == 0, nil
}

// findKey locates the keys: item whose parsed fingerprint is fp: the
// owning users: entry, its keys: sequence, and the item's index.
func (f *File) findKey(fp string) (user, keys *yaml.Node, idx int, err error) {
	m, err := f.rootMapping()
	if err != nil {
		return nil, nil, 0, err
	}
	_, users := sectionOf(m, "users")
	if users != nil {
		for _, u := range users.Content {
			ks := valueOf(u, "keys")
			if u.Kind != yaml.MappingNode || ks == nil || ks.Kind != yaml.SequenceNode {
				continue
			}
			for i, k := range ks.Content {
				if k.Kind != yaml.ScalarNode {
					continue
				}
				parsed, perr := authkeys.ParseLine(k.Value)
				if perr == nil && parsed != nil && parsed.Fingerprint == fp {
					return u, ks, i, nil
				}
			}
		}
	}
	return nil, nil, 0, fmt.Errorf("key %s is not in the manifest", fp)
}

// sectionOf returns a top-level section's key node and its value when the
// value is a sequence (nil otherwise: missing, null, or another shape).
func sectionOf(m *yaml.Node, key string) (k, seq *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			if v := m.Content[i+1]; v.Kind == yaml.SequenceNode {
				return m.Content[i], v
			}
			return m.Content[i], nil
		}
	}
	return nil, nil
}

// userItem finds the users: entry whose name: is name.
func userItem(users *yaml.Node, name string) *yaml.Node {
	if users == nil {
		return nil
	}
	for _, u := range users.Content {
		if u.Kind == yaml.MappingNode && scalarField(u, "name") == name {
			return u
		}
	}
	return nil
}

// scalarField returns a mapping's scalar value for key ("" if absent or
// not a scalar).
func scalarField(n *yaml.Node, key string) string {
	if n.Kind != yaml.MappingNode {
		return ""
	}
	if v := valueOf(n, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return ""
}

// removeItems drops every item of seq that drop selects and returns how
// many it dropped. With rescue, a dropped item's head comment is prepended
// to the next surviving item's, or — when no item survives after it —
// inserted at the front of sectionKey's foot comment, which the encoder
// emits right after the section's remaining items (before any document
// footer already riding there, preserving the source order). The section
// key's head comment, which may hold the file header, is never touched.
// Without rescue, head comments go with their items. An emptied sequence
// is emitted in flow style (`[]`).
func removeItems(sectionKey, seq *yaml.Node, drop func(*yaml.Node) bool, rescue bool) int {
	var kept []*yaml.Node
	pending := ""
	removed := 0
	for _, it := range seq.Content {
		if drop(it) {
			removed++
			if rescue {
				pending = joinComments(pending, it.HeadComment)
			}
			continue
		}
		if pending != "" {
			it.HeadComment = joinComments(pending, it.HeadComment)
			pending = ""
		}
		kept = append(kept, it)
	}
	if pending != "" && sectionKey != nil {
		sectionKey.FootComment = joinComments(pending, sectionKey.FootComment)
	}
	seq.Content = kept
	if len(kept) == 0 {
		seq.Style = yaml.FlowStyle
	}
	return removed
}

// joinComments concatenates two comment blocks, either possibly empty.
func joinComments(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "\n" + b
}

// ReplaceKey replaces user's keys: line whose fingerprint is oldFP with
// newLine, at the same index, keeping the line's comments. The caller
// composes newLine (the old line's options, the new key, the chosen
// comment); nothing is validated until Encode.
func (f *File) ReplaceKey(user, oldFP, newLine string) error {
	owner, keys, idx, err := f.findKey(oldFP)
	if err != nil {
		return err
	}
	if name := scalarField(owner, "name"); name != user {
		return fmt.Errorf("key %s belongs to %q, not %q", oldFP, name, user)
	}
	n := keys.Content[idx]
	n.Value = newLine
	n.Tag = "!!str"
	if n.Style == yaml.LiteralStyle || n.Style == yaml.FoldedStyle {
		n.Style = 0 // a key line is one line; let the encoder pick the quoting
	}
	return nil
}

// SetOperator sets user's operator: flag (on) or removes the operator: key
// entirely (off). A removed operator: key's head comment moves to the next
// key of the entry; its line comment goes with it.
func (f *File) SetOperator(user string, on bool) error {
	m, err := f.rootMapping()
	if err != nil {
		return err
	}
	_, users := sectionOf(m, "users")
	item := userItem(users, user)
	if item == nil {
		return fmt.Errorf("user %q is not in the manifest", user)
	}
	for i := 0; i+1 < len(item.Content); i += 2 {
		if item.Content[i].Value != "operator" {
			continue
		}
		if on {
			v := item.Content[i+1]
			v.Kind, v.Tag, v.Value, v.Style = yaml.ScalarNode, "!!bool", "true", 0
			return nil
		}
		head := item.Content[i].HeadComment
		item.Content = append(item.Content[:i], item.Content[i+2:]...)
		if head != "" && i < len(item.Content) {
			item.Content[i].HeadComment = joinComments(head, item.Content[i].HeadComment)
		}
		return nil
	}
	if !on {
		return nil
	}
	pair := []*yaml.Node{strScalar("operator"), {Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"}}
	at := len(item.Content)
	for i := 0; i+1 < len(item.Content); i += 2 {
		if item.Content[i].Value == "keys" {
			at = i
			break
		}
	}
	item.Content = append(item.Content[:at], append(pair, item.Content[at:]...)...)
	return nil
}

// AccessRemoval reports what RemoveAccess changed.
type AccessRemoval struct {
	EntriesChanged   int // entries edited in place (list shortened or except: extended)
	EntriesRemoved   int // entries deleted: list emptied, or wildcard left covering nothing
	ServersExcepted  int // servers appended to except: lists
	WildcardsRemoved int // of EntriesRemoved: wildcard entries deleted (decision 1b)
}

// RemoveAccess takes servers away from user's access: entries, leaving the
// user, its keys and every other grant alone. An explicit servers: list
// loses every item naming one of servers; an entry left with no servers is
// deleted (its head comment rescued as RemoveUser does). A wildcard
// (servers: ["*"]) gets each covered server appended to except: — created
// right after servers:, in that list's flow/block style, when absent — and
// is deleted instead when it would then cover no server of the loaded
// config. A server already excepted is not covered, so it is never
// appended twice. Every name in servers must be a server of the loaded
// config; the wildcard is resolved against f.Config().Servers.
func (f *File) RemoveAccess(user string, servers []string) (AccessRemoval, error) {
	m, err := f.rootMapping()
	if err != nil {
		return AccessRemoval{}, err
	}
	fleet, err := f.accessTargets(m, user, servers)
	if err != nil {
		return AccessRemoval{}, err
	}
	var r AccessRemoval
	accessKey, access := sectionOf(m, "access")
	if access == nil {
		return r, nil
	}
	drop := map[*yaml.Node]bool{}
	for _, entry := range access.Content {
		if entry.Kind != yaml.MappingNode || scalarField(entry, "user") != user {
			continue
		}
		switch t := trimEntry(entry, servers, fleet); {
		case t.gone:
			drop[entry] = true
			r.EntriesRemoved++
			if t.wildcard {
				r.WildcardsRemoved++
			}
		case t.changed:
			r.EntriesChanged++
			r.ServersExcepted += t.excepted
		}
	}
	if len(drop) > 0 {
		removeItems(accessKey, access, func(n *yaml.Node) bool { return drop[n] }, true)
	}
	return r, nil
}

// accessTargets checks RemoveAccess's arguments against the loaded
// manifest (user has a users: entry, every server is a servers: entry) and
// returns the fleet's server names, manifest order.
func (f *File) accessTargets(m *yaml.Node, user string, servers []string) ([]string, error) {
	_, users := sectionOf(m, "users")
	if userItem(users, user) == nil {
		return nil, fmt.Errorf("user %q is not in the manifest", user)
	}
	fleet := make([]string, 0, len(f.cfg.Servers))
	for _, s := range f.cfg.Servers {
		fleet = append(fleet, s.Name)
	}
	for _, s := range servers {
		if !slices.Contains(fleet, s) {
			return nil, fmt.Errorf("server %q is not in the manifest", s)
		}
	}
	return fleet, nil
}

// entryTrim is what trimEntry did to one access: entry.
type entryTrim struct {
	changed  bool // servers: shortened or except: extended
	gone     bool // the entry must be deleted (list emptied, or wildcard left covering nothing)
	wildcard bool // the entry is a servers: ["*"] grant
	excepted int  // servers appended to except:
}

// trimEntry removes servers from one access: entry of the user: items of
// an explicit list (every occurrence; the removed item's comments go with
// it), or except: appends on a wildcard.
func trimEntry(entry *yaml.Node, servers, fleet []string) entryTrim {
	list := valueOf(entry, "servers")
	if list == nil || list.Kind != yaml.SequenceNode {
		return entryTrim{}
	}
	if seqHas(list, "*") {
		n, gone := exceptServers(entry, list, servers, fleet)
		return entryTrim{changed: n > 0, gone: gone, wildcard: true, excepted: n}
	}
	n := removeItems(nil, list, func(it *yaml.Node) bool {
		return it.Kind == yaml.ScalarNode && slices.Contains(servers, it.Value)
	}, false)
	return entryTrim{changed: n > 0, gone: n > 0 && len(list.Content) == 0}
}

// exceptServers appends to a wildcard entry's except: every server of
// servers the entry still covers, creating except: right after servers:
// (same sequence style) when absent or null. gone reports that the
// wildcard would then cover no server of fleet: the caller deletes the
// entry (decision 1b) and the appends do not matter.
func exceptServers(entry, list *yaml.Node, servers, fleet []string) (appended int, gone bool) {
	except := valueOf(entry, "except")
	if except != nil && except.Kind == yaml.ScalarNode && except.Tag == "!!null" {
		*except = yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: list.Style & yaml.FlowStyle,
			HeadComment: except.HeadComment, LineComment: except.LineComment, FootComment: except.FootComment}
	}
	for _, s := range servers {
		if except != nil && seqHas(except, s) {
			continue // already carved out: not covered
		}
		if except == nil {
			except = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Style: list.Style & yaml.FlowStyle}
			at := len(entry.Content)
			for i := 0; i+1 < len(entry.Content); i += 2 {
				if entry.Content[i].Value == "servers" {
					at = i + 2
					break
				}
			}
			entry.Content = append(entry.Content[:at], append([]*yaml.Node{strScalar("except"), except}, entry.Content[at:]...)...)
		}
		except.Content = append(except.Content, strScalar(s))
		appended++
	}
	for _, s := range fleet {
		if except == nil || !seqHas(except, s) {
			return appended, false
		}
	}
	return appended, true
}

// seqHas reports whether a sequence holds a scalar item equal to v.
func seqHas(seq *yaml.Node, v string) bool {
	return slices.ContainsFunc(seq.Content, func(it *yaml.Node) bool { return it.Kind == yaml.ScalarNode && it.Value == v })
}

// AddKeyAfter inserts newLine as a new keys: item of user immediately after
// the item whose fingerprint is oldFP (rotate --keep-old). It only inserts:
// the old item, its comments and the user's operator: flag are untouched;
// the caller composes newLine (rotatedLine), and nothing is validated until
// Encode.
func (f *File) AddKeyAfter(user, oldFP, newLine string) error {
	owner, keys, idx, err := f.findKey(oldFP)
	if err != nil {
		return err
	}
	if name := scalarField(owner, "name"); name != user {
		return fmt.Errorf("key %s belongs to %q, not %q", oldFP, name, user)
	}
	item := strScalar(newLine)
	keys.Content = append(keys.Content[:idx+1], append([]*yaml.Node{item}, keys.Content[idx+1:]...)...)
	return nil
}

// AddTombstones appends entries to revoked: — created as the last top-level
// key when absent — and returns the entries it added. A key entry whose
// fingerprint is already tombstoned (in the file, or earlier in entries) is
// skipped: the earliest entry wins, so a retried revoke never produces a
// duplicate-fingerprint load error. Entries render through the config
// types' encoder (Generate's). Node tree only.
func (f *File) AddTombstones(entries []config.Tombstone) ([]config.Tombstone, error) {
	m, err := f.rootMapping()
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	if seq := valueOf(m, "revoked"); seq != nil && seq.Kind == yaml.SequenceNode {
		for _, it := range seq.Content {
			if fp := scalarField(it, "fingerprint"); fp != "" {
				seen[fp] = true
			}
		}
	}
	var added []config.Tombstone
	for _, t := range entries {
		if t.IsKey() {
			if seen[t.Fingerprint] {
				continue
			}
			seen[t.Fingerprint] = true
		}
		added = append(added, t)
	}
	nodes, err := entryNodes(added)
	if err != nil {
		return nil, err
	}
	return added, f.appendToSection("revoked", nodes)
}

// BumpSerial raises serial: by one — inserting `serial: 1` as the first
// top-level key when absent, under the file's header comment — and returns
// the new value. At config.MaxSerial it fails and changes nothing. Node
// tree only (Load validated the current value).
func (f *File) BumpSerial() (uint64, error) {
	m, err := f.rootMapping()
	if err != nil {
		return 0, err
	}
	if v := valueOf(m, "serial"); v != nil {
		cur, err := strconv.ParseUint(v.Value, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("bug: serial %q passed validation but does not parse: %w", v.Value, err)
		}
		if cur >= config.MaxSerial {
			return 0, fmt.Errorf("serial %d is the largest serial a manifest may carry; it cannot be bumped", cur)
		}
		v.Value = strconv.FormatUint(cur+1, 10)
		return cur + 1, nil
	}
	m.Style = 0
	key := strScalar("serial")
	if len(m.Content) > 0 {
		// The file's header comment rides the first key; keep it on top.
		key.HeadComment, m.Content[0].HeadComment = m.Content[0].HeadComment, ""
	}
	m.Content = append([]*yaml.Node{key, {Kind: yaml.ScalarNode, Tag: "!!int", Value: "1"}}, m.Content...)
	return 1, nil
}
