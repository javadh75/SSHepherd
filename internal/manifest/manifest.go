// Package manifest provides comment-preserving appends to an existing
// SSHepherd manifest: the file is decoded into a yaml.v3 node tree (comments
// intact) alongside the validated config, new user/access entries are
// appended surgically to their section sequences, and the whole document is
// re-encoded. Nothing existing is reordered, rewritten, or removed.
//
// Fidelity contract: comments are preserved; blank lines and quote styles
// may normalize.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
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

// UserEntry is one user to append to the users: section. Zero-valued
// optional fields (Description, Comment, Operator) are omitted from the
// output, mirroring the generators' omitempty rendering.
type UserEntry struct {
	Name        string
	Description string
	Comment     string
	Operator    bool
	Keys        []string
}

// AccessEntry is one grant to append to the access: section. Appends never
// carry except: — a merge only ever adds plain grants; carve-outs are a
// hand-written construct.
type AccessEntry struct {
	User    string
	Servers []string
}

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
	}
	if err := checkTopLevelKeys(root); err != nil {
		return nil, err
	}
	if err := checkNodeShapes(root); err != nil {
		return nil, err
	}
	return &File{root: root, cfg: cfg}, nil
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
			return fmt.Errorf("manifest contains an unsupported top-level key %q", k.Value)
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
		return fmt.Errorf("manifest contains a YAML anchor or alias (line %d); merge does not support them", n.Line)
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode || k.Tag == "!!null" || k.Value == "" {
				return fmt.Errorf("manifest contains an unsupported mapping key (line %d)", k.Line)
			}
		}
	case yaml.SequenceNode:
		for _, item := range n.Content {
			if item.Kind == yaml.ScalarNode && item.Tag == "!!null" {
				return fmt.Errorf("manifest contains a null list entry (line %d)", item.Line)
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

// Append appends users and access entries to their sections, converting a
// flow-style empty (`[]`) or null section to block style and creating a
// missing section at the end of the document. comments (lines without the
// leading "#") become the head comment of the first appended node, so the
// merge marker lands exactly where the additions live. Appending nothing is
// a no-op.
func (f *File) Append(comments []string, users []UserEntry, access []AccessEntry) error {
	userNodes := make([]*yaml.Node, 0, len(users))
	for _, u := range users {
		userNodes = append(userNodes, userNode(u))
	}
	accessNodes := make([]*yaml.Node, 0, len(access))
	for _, a := range access {
		accessNodes = append(accessNodes, accessNode(a))
	}
	switch {
	case len(userNodes) > 0:
		userNodes[0].HeadComment = strings.Join(comments, "\n")
	case len(accessNodes) > 0:
		accessNodes[0].HeadComment = strings.Join(comments, "\n")
	default:
		return nil
	}
	if err := f.appendToSection("users", userNodes); err != nil {
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
		return nil, fmt.Errorf("bug: merged manifest fails validation: %w", err)
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

func strSeq(vals []string) *yaml.Node {
	n := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, v := range vals {
		n.Content = append(n.Content, strScalar(v))
	}
	return n
}

// userNode renders one appended user in the generators' field order:
// name, description, comment, operator, keys — optional fields omitted.
func userNode(u UserEntry) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	pair := func(k string, v *yaml.Node) { n.Content = append(n.Content, strScalar(k), v) }
	pair("name", strScalar(u.Name))
	if u.Description != "" {
		pair("description", strScalar(u.Description))
	}
	if u.Comment != "" {
		pair("comment", strScalar(u.Comment))
	}
	if u.Operator {
		pair("operator", &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
	}
	pair("keys", strSeq(u.Keys))
	return n
}

func accessNode(a AccessEntry) *yaml.Node {
	n := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	n.Content = append(n.Content,
		strScalar("user"), strScalar(a.User),
		strScalar("servers"), strSeq(a.Servers))
	return n
}
