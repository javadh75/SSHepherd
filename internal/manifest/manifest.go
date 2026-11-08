// Package manifest owns how SSHepherd writes manifests: Generate renders a
// fresh manifest, Store/WriteFile publish one safely (lock, compare-and-swap,
// atomic rename), and File provides comment-preserving edits to an existing
// manifest: the file is decoded into a yaml.v3 node tree (comments intact)
// alongside the validated config, edited surgically, and the whole document
// is re-encoded. Generate and Append share one encoder driven by the
// config.User/Server/Access types. The edits are exactly these:
//
//   - Append adds users, servers and access entries (config types) at the
//     end of their sections (adopt --merge, import --merge);
//   - RemoveUser deletes a users: entry and every access: entry naming it;
//   - RemoveKey deletes one keys: line, found by fingerprint;
//   - ReplaceKey replaces one keys: line in place (same index);
//   - SetOperator sets or removes a user's operator: flag;
//   - RemoveAccess takes servers away from a user's access: entries
//     (explicit items removed, wildcards gain except:, emptied entries
//     deleted);
//   - AddKeyAfter inserts one keys: line right after another.
//
// Nothing else is reordered, rewritten, or removed. The edit methods change
// only the node tree — none validates, and Config stays the as-loaded
// config; Encode's config.Parse self-check is the one validation.
//
// Fidelity contract: comments are preserved (a removed users:/access:
// entry's head comment moves to the next entry or the section's footer; a
// removed key line's or servers: item's head comment goes with it); blank
// lines and quote styles may normalize.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/javadh75/SSHepherd/internal/config"
)

// File is a loaded manifest: the raw node tree for comment-preserving edits
// plus the validated config for lookups (OwnerOf, grants, …).
type File struct {
	root *yaml.Node // document node
	cfg  *config.Config
}

// UnsupportedError reports a manifest config.Parse accepts but this package
// cannot edit faithfully (anchors/aliases, null list entries, exotic keys).
// Callers tell it apart from a validation failure with errors.As: the
// manifest is valid, only the comment-preserving edit is impossible.
type UnsupportedError struct {
	Reason string
}

func (e *UnsupportedError) Error() string { return e.Reason }

// Load parses data twice: config.Parse for validation (Load rejects exactly
// what config.Parse rejects) and a yaml node decode for later
// comment-preserving edits.
func Load(data []byte) (*File, error) {
	cfg, err := config.Parse(data)
	if err != nil {
		//nolint:wrapcheck // Load's contract is config.Parse's verdict, verbatim; a wrapper prefix would only stutter.
		return nil, err
	}
	root := &yaml.Node{}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(root); err != nil {
		if !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("parse manifest: %w", err)
		}
		// Empty input parses as an empty config; synthesize an empty document
		// so Append/Encode still have a mapping to work with.
		root = &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{
			{Kind: yaml.MappingNode, Tag: "!!map"},
		}}
	} else if err := dec.Decode(&yaml.Node{}); !errors.Is(err, io.EOF) {
		// config.Parse already refuses this; kept so Encode can never
		// silently drop a second document even if that gate regressed.
		return nil, errors.New("parse manifest: manifest contains multiple YAML documents")
	}
	if err := checkTopLevelKeys(root); err != nil {
		return nil, err
	}
	if err := checkNodeShapes(root); err != nil {
		return nil, err
	}
	explicitFlowNulls(root, false)
	return &File{root: root, cfg: cfg}, nil
}

// explicitFlowNulls spells every implicit null inside a flow collection as
// `null` (fuzz-found): `{name: a, operator, keys: [...]}` decodes operator
// as an empty null, which the encoder writes back in flow context as an
// empty quoted string — which the reparse refuses for a bool (or a list,
// or a port). Block-context nulls re-encode faithfully and are left alone.
func explicitFlowNulls(n *yaml.Node, inFlow bool) {
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		inFlow = inFlow || n.Style&yaml.FlowStyle != 0
	}
	if inFlow && n.Kind == yaml.ScalarNode && n.Tag == "!!null" && n.Value == "" {
		n.Value = "null"
	}
	for _, c := range n.Content {
		explicitFlowNulls(c, inFlow)
	}
}

// checkTopLevelKeys rejects manifests whose top-level mapping keys are not
// plain users/servers/access scalars. config.Parse tolerates a few exotic
// key shapes (e.g. an anchored empty scalar, found by fuzzing) that break
// the re-encode → re-parse self-check; anything Load accepts must be
// structurally re-encodable, so the whole class dies here.
func checkTopLevelKeys(root *yaml.Node) error {
	if root.Kind != yaml.DocumentNode || len(root.Content) == 0 {
		return nil
	}
	m := root.Content[0]
	if m.Kind != yaml.MappingNode {
		return nil // null or non-mapping roots are handled elsewhere
	}
	for i := 0; i < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind != yaml.ScalarNode ||
			(k.Value != "users" && k.Value != "servers" && k.Value != "access") {
			return &UnsupportedError{Reason: fmt.Sprintf("manifest contains an unsupported top-level key %q", k.Value)}
		}
	}
	return nil
}

// checkNodeShapes walks the whole tree and rejects node shapes that
// config.Parse's struct decode tolerates but a re-encode → re-parse does
// not (all fuzz-found): a mapping key that is not a plain, non-empty scalar
// (an anchored empty key decodes as skippable but re-encodes into a key the
// reparse rejects), a null sequence item (silently skipped when decoding
// into a slice, materialized as an empty string by the re-encode), and any
// anchor or alias anywhere (append rebuilds null sections without carrying
// anchors, so an alias elsewhere would dangle; sharing structure across
// sections also makes "append to the anchored node" ambiguous — reject the
// whole class rather than half-support it). Only called on trees
// config.Parse already accepted, so nesting depth is schema-bounded.
func checkNodeShapes(n *yaml.Node) error {
	if n.Anchor != "" || n.Kind == yaml.AliasNode {
		return &UnsupportedError{Reason: fmt.Sprintf("manifest contains a YAML anchor or alias (line %d); comment-preserving edits do not support them", n.Line)}
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag == "!!null" || k.Value == "" {
				return &UnsupportedError{Reason: fmt.Sprintf("manifest contains an unsupported mapping key (line %d)", k.Line)}
			}
		}
	case yaml.SequenceNode:
		for _, item := range n.Content {
			if item.Kind == yaml.ScalarNode && item.Tag == "!!null" {
				return &UnsupportedError{Reason: fmt.Sprintf("manifest contains a null list entry (line %d)", item.Line)}
			}
		}
	}
	for _, c := range n.Content {
		if err := checkNodeShapes(c); err != nil {
			return err
		}
	}
	return nil
}

// Config returns the validated config parsed from the loaded bytes.
func (f *File) Config() *config.Config { return f.cfg }

// Append appends users, servers, and access entries to their sections,
// converting a flow-style empty (`[]`) or null section to block style and
// creating a missing section at the end of the document. comments (lines
// without the leading "#") become the head comment of the first appended
// node — first user, else first server, else first access entry — so the
// merge marker lands exactly where the additions live. Appending nothing is
// a no-op. Entries are the config types, rendered by the same encoder as
// Generate (required keys always, optional fields only when set, port 0/22
// omitted); Encode's config.Parse self-check validates the result.
func (f *File) Append(comments []string, users []config.User, servers []config.Server, access []config.Access) error {
	userNodes, err := entryNodes(users)
	if err != nil {
		return err
	}
	serverNodes, err := entryNodes(servers)
	if err != nil {
		return err
	}
	accessNodes, err := entryNodes(access)
	if err != nil {
		return err
	}
	switch {
	case len(userNodes) > 0:
		userNodes[0].HeadComment = strings.Join(comments, "\n")
	case len(serverNodes) > 0:
		serverNodes[0].HeadComment = strings.Join(comments, "\n")
	case len(accessNodes) > 0:
		accessNodes[0].HeadComment = strings.Join(comments, "\n")
	default:
		return nil
	}
	if err := f.appendToSection("users", userNodes); err != nil {
		return err
	}
	if err := f.appendToSection("servers", serverNodes); err != nil {
		return err
	}
	return f.appendToSection("access", accessNodes)
}

// Encode re-encodes the document (2-space indent, matching the generators)
// and self-checks the result through config.Parse: this package must never
// hand back a manifest our own loader would reject.
func (f *File) Encode() ([]byte, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(f.root); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	out := buf.Bytes()
	if _, err := config.Parse(out); err != nil {
		return nil, fmt.Errorf("bug: edited manifest fails validation: %w", err)
	}
	return out, nil
}

// appendToSection appends items to the sequence under key in the root
// mapping, normalizing the shapes a validated manifest can present: a
// missing key (created at the end), a null value (`users:`), or a
// flow-style empty list (`users: []` — our own generators' bootstrap
// output). Anchors and aliases were rejected at Load, so none appear here.
func (f *File) appendToSection(key string, items []*yaml.Node) error {
	if len(items) == 0 {
		return nil
	}
	m, err := f.rootMapping()
	if err != nil {
		return err
	}
	m.Style = 0 // a flow mapping cannot hold commented block entries
	seq := valueOf(m, key)
	if seq == nil {
		seq = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		m.Content = append(m.Content, strScalar(key), seq)
	}
	if seq.Kind == yaml.ScalarNode && seq.Tag == "!!null" {
		// `users:` with no value decodes to a null scalar; rebuild it as a
		// sequence in place, keeping any comments that rode the null.
		*seq = yaml.Node{
			Kind: yaml.SequenceNode, Tag: "!!seq",
			HeadComment: seq.HeadComment, LineComment: seq.LineComment, FootComment: seq.FootComment,
		}
	}
	if seq.Kind != yaml.SequenceNode {
		return fmt.Errorf("bug: manifest section %q is not a sequence", key)
	}
	seq.Style = 0 // flow (`[]`) cannot hold commented block entries
	seq.Content = append(seq.Content, items...)
	return nil
}

// rootMapping returns the document's root mapping, materializing one for
// the null-document shape (`null`, `---`) that still parses as an empty
// config.
func (f *File) rootMapping() (*yaml.Node, error) {
	if f.root.Kind != yaml.DocumentNode || len(f.root.Content) == 0 {
		return nil, fmt.Errorf("bug: manifest document has no root node")
	}
	m := f.root.Content[0]
	if m.Kind == yaml.ScalarNode && m.Tag == "!!null" {
		*m = yaml.Node{
			Kind: yaml.MappingNode, Tag: "!!map",
			HeadComment: m.HeadComment, FootComment: m.FootComment,
		}
		return m, nil
	}
	if m.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("bug: manifest root is not a mapping")
	}
	return m, nil
}

// valueOf finds the value node for key in a mapping (Content alternates
// key, value).
func valueOf(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func strScalar(v string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: v}
}

// requiredKeys are emitted even at their zero value (the loader requires
// them); every other field is omitempty. A new config field is therefore
// emitted by adopt, import and Append with no change here — and
// cmd/sshepherd/schema_roundtrip_test.go fails until it round-trips.
var requiredKeys = map[string]bool{"name": true, "host": true, "user": true, "keys": true, "servers": true}

// entryNode renders one config.User/Server/Access as a mapping in struct
// field order, from the yaml tags: required keys always, optional fields only
// when non-zero (an empty slice counts as zero), and port omitted at 0 or 22
// (validation defaults 0 to 22, so both spell the default).
func entryNode(v any) (*yaml.Node, error) {
	rv := reflect.ValueOf(v)
	rt := rv.Type()
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for i := range rt.NumField() {
		f := rt.Field(i)
		key, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if !f.IsExported() || key == "" || key == "-" {
			continue
		}
		fv := rv.Field(i)
		empty := fv.IsZero() || (fv.Kind() == reflect.Slice && fv.Len() == 0)
		if key == "port" && (fv.Int() == 0 || fv.Int() == 22) {
			empty = true
		}
		if empty && !requiredKeys[key] {
			continue
		}
		val := &yaml.Node{}
		if err := val.Encode(fv.Interface()); err != nil {
			return nil, fmt.Errorf("encode %s.%s: %w", rt.Name(), key, err)
		}
		n.Content = append(n.Content, strScalar(key), val)
	}
	return n, nil
}

func entryNodes[T any](items []T) ([]*yaml.Node, error) {
	out := make([]*yaml.Node, 0, len(items))
	for _, it := range items {
		n, err := entryNode(it)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

// Generate renders a fresh manifest — header (raw comment lines with their
// own "#" and trailing newline) then users, servers, access — with the same
// encoder settings as Encode (2-space indent). It is the one renderer for
// adopt's and import's generated drafts.
func Generate(header string, users []config.User, servers []config.Server, access []config.Access) ([]byte, error) {
	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, sec := range []struct {
		key   string
		items func() ([]*yaml.Node, error)
	}{
		{"users", func() ([]*yaml.Node, error) { return entryNodes(users) }},
		{"servers", func() ([]*yaml.Node, error) { return entryNodes(servers) }},
		{"access", func() ([]*yaml.Node, error) { return entryNodes(access) }},
	} {
		items, err := sec.items()
		if err != nil {
			return nil, err
		}
		root.Content = append(root.Content, strScalar(sec.key), &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: items})
	}
	var buf bytes.Buffer
	buf.WriteString(header)
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{root}}); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, fmt.Errorf("encode manifest: %w", err)
	}
	return buf.Bytes(), nil
}
