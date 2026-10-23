package manifest

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/javadh75/SSHepherd/internal/authkeys"
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
