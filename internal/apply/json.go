package apply

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
)

// jsonSchemaVersion marks the write-path document shape. Bump only on
// breaking changes; additive optional fields keep 1.
const jsonSchemaVersion = 1

// JSONOptions selects the document kind and the revoke/rotate extras.
type JSONOptions struct {
	Command string         // "apply" | "revoke" | "rotate"
	DryRun  bool           // --dry-run was given
	Skipped int            // servers excluded by --server (apply only)
	Former  *config.Config // as-loaded config before the edit; nil for apply
	Edit    *EditSummary   // nil for apply
	Saved   bool           // the manifest was written (revoke/rotate)
}

// The json* types are the wire shape of --json on apply/revoke/rotate,
// pinned by docs/superpowers/specs/2026-11-07-apply-json-design.md and the
// json_*.golden.json fixtures. Field names are public contract — change
// them only with a schema bump.
type jsonDoc struct {
	Schema  int          `json:"schema"`
	Command string       `json:"command"`
	DryRun  bool         `json:"dry_run"`
	Edit    *jsonEdit    `json:"edit"`
	Summary jsonSummary  `json:"summary"`
	Servers []jsonServer `json:"servers"`
}

type jsonSummary struct {
	Servers     int `json:"servers"`
	Skipped     int `json:"skipped"`
	Converged   int `json:"converged"`
	Applied     int `json:"applied"`
	Pending     int `json:"pending"`
	Failed      int `json:"failed"`
	Refused     int `json:"refused"`
	Unreachable int `json:"unreachable"`
	ExitCode    int `json:"exit_code"`
}

type jsonEdit struct {
	Saved     bool            `json:"saved"`
	Edits     []jsonEditEntry `json:"edits"`
	Affected  int             `json:"affected"`
	Operators []string        `json:"operators"`
	Emptied   []jsonEmptied   `json:"emptied"`
}

// jsonEditEntry: pointer fields are present exactly for their kind, so a
// zero count or false flag is still emitted where it belongs.
type jsonEditEntry struct {
	Kind           string `json:"kind"`
	User           string `json:"user"`
	Keys           *int   `json:"keys,omitempty"`
	Grants         *int   `json:"grants,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	NewFingerprint string `json:"new_fingerprint,omitempty"`
	KeepsExpiry    string `json:"keeps_expiry,omitempty"`
	NoKeysLeft     *bool  `json:"no_keys_left,omitempty"`
	ClearsOperator *bool  `json:"clears_operator,omitempty"`
}

type jsonEmptied struct {
	Server string   `json:"server"`
	Users  []string `json:"users"`
	Keys   int      `json:"keys"`
}

type jsonServer struct {
	Name                    string      `json:"name"`
	Host                    string      `json:"host"`
	Port                    int         `json:"port"`
	User                    string      `json:"user"`
	AuthorizedKeysFile      string      `json:"authorized_keys_file,omitempty"`
	Class                   string      `json:"class"`
	Outcome                 *string     `json:"outcome"`
	Error                   *string     `json:"error"`
	ErrorKind               string      `json:"error_kind,omitempty"`
	Changes                 jsonChanges `json:"changes"`
	FileAbsent              bool        `json:"file_absent"`
	AuthorizedKeys2Present  bool        `json:"authorized_keys2_present"`
	DisablesAuthorizedKeys2 bool        `json:"disables_authorized_keys2"`
	Notes                   jsonNotes   `json:"notes"`
}

type jsonChanges struct {
	Add       []jsonKey     `json:"add"`
	Remove    []jsonKey     `json:"remove"`
	Rewrite   []jsonRewrite `json:"rewrite"`
	Normalize jsonNormalize `json:"normalize"`
}

// jsonKey: owner always present (null = the rendered manifest does not own
// it); former_owner only for a key only JSONOptions.Former owns.
type jsonKey struct {
	Owner       *string `json:"owner"`
	FormerOwner string  `json:"former_owner,omitempty"`
	Fingerprint string  `json:"fingerprint"`
	Type        string  `json:"type"`
	Comment     string  `json:"comment,omitempty"`
	Operator    bool    `json:"operator,omitempty"`
}

// jsonRewrite is not a key object: only what changes is present.
type jsonRewrite struct {
	Owner         *string            `json:"owner"`
	Fingerprint   string             `json:"fingerprint"`
	Type          string             `json:"type"`
	Operator      bool               `json:"operator,omitempty"`
	OptionsChange *jsonOptionsChange `json:"options_change,omitempty"`
	CommentChange *jsonCommentChange `json:"comment_change,omitempty"`
	Loosens       []string           `json:"loosens"`
}

type jsonOptionsChange struct {
	From []string `json:"from"`
	To   []string `json:"to"`
}

type jsonCommentChange struct {
	From string `json:"from"`
	To   string `json:"to"`
}

type jsonNormalize struct {
	Reorder                bool `json:"reorder"`
	NonKeyLines            int  `json:"non_key_lines"`
	Duplicates             int  `json:"duplicates"`
	DuplicateOptionsDiffer bool `json:"duplicate_options_differ"`
	Whitespace             bool `json:"whitespace"`
}

type jsonNotes struct {
	Guard              string `json:"guard,omitempty"`
	RestrictiveOptions string `json:"restrictive_options,omitempty"`
	AgentOnlySurvivors string `json:"agent_only_survivors,omitempty"`
}

// RenderJSON writes the write-path report as one indented JSON document
// with a trailing newline. plans may be nil (empty fleet, edit-only run).
func RenderJSON(w io.Writer, cfg *config.Config, plans []ServerPlan, opts JSONOptions) error {
	c := countSummary(plans)
	doc := jsonDoc{
		Schema:  jsonSchemaVersion,
		Command: opts.Command,
		DryRun:  opts.DryRun,
		Summary: jsonSummary{
			Servers: len(plans), Skipped: opts.Skipped,
			Converged: c.converged, Applied: c.applied, Pending: c.pending,
			Failed: c.failed, Refused: c.refused, Unreachable: c.unreachable,
			ExitCode: ExitCode(plans),
		},
		Servers: make([]jsonServer, 0, len(plans)),
	}
	if opts.Edit != nil {
		doc.Edit = jsonEditFor(*opts.Edit, opts.Saved)
	}
	for _, p := range plans {
		doc.Servers = append(doc.Servers, jsonServerFor(cfg, p, opts))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("render json: %w", err)
	}
	return nil
}

// clean strips terminal-hostile runes (C0/DEL/C1, Cf) that encoding/json
// would emit raw; idempotent on already-sanitized text.
func clean(s string) string { return sshconn.SanitizeRemote(s) }

// cleanLine is clean plus oneLine's whitespace collapse, for error text.
func cleanLine(s string) string { return clean(strings.Join(strings.Fields(s), " ")) }

// cleanAll sanitizes a list; never nil, so an empty list encodes as [].
func cleanAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, clean(s))
	}
	return out
}

// jsonEditFor maps the revoke/rotate edit section; every list encodes as
// [] when empty, and each entry carries exactly its kind's fields.
func jsonEditFor(s EditSummary, saved bool) *jsonEdit {
	e := &jsonEdit{
		Saved:     saved,
		Edits:     make([]jsonEditEntry, 0, len(s.Edits)),
		Affected:  s.Affected,
		Operators: append([]string{}, s.Operators...),
		Emptied:   make([]jsonEmptied, 0, len(s.Emptied)),
	}
	for _, ed := range s.Edits {
		je := jsonEditEntry{Kind: string(ed.Kind), User: ed.User}
		switch ed.Kind {
		case EditRemoveUser:
			keys, grants := ed.Keys, ed.Grants
			je.Keys, je.Grants = &keys, &grants
		case EditRemoveKey:
			noKeys, clears := ed.NoKeysLeft, ed.ClearsOperator
			je.Fingerprint = ed.Fingerprint
			je.NoKeysLeft, je.ClearsOperator = &noKeys, &clears
		case EditRotate:
			je.Fingerprint, je.NewFingerprint, je.KeepsExpiry = ed.Fingerprint, ed.NewFingerprint, ed.KeepsExpiry
		}
		e.Edits = append(e.Edits, je)
	}
	for _, em := range s.Emptied {
		e.Emptied = append(e.Emptied, jsonEmptied{Server: em.Server, Users: append([]string{}, em.Users...), Keys: em.Keys})
	}
	return e
}

// jsonServerFor maps one plan. changes is always fully present (arrays [],
// never null) so consumers read the same shape on every class.
func jsonServerFor(cfg *config.Config, p ServerPlan, opts JSONOptions) jsonServer {
	s := jsonServer{
		Name:               p.Server.Name,
		Host:               p.Server.Host,
		Port:               p.Server.Port,
		User:               p.Server.User,
		AuthorizedKeysFile: p.Server.AuthorizedKeysFile,
		Class:              string(p.Class),
		Changes: jsonChanges{
			Add:     []jsonKey{},
			Remove:  []jsonKey{},
			Rewrite: []jsonRewrite{},
			Normalize: jsonNormalize{
				Reorder:                p.Normalize.Reorder,
				NonKeyLines:            p.Normalize.NonKeyLines,
				Duplicates:             p.Normalize.Duplicates,
				DuplicateOptionsDiffer: p.Normalize.DuplicateOptionsDiffer,
				Whitespace:             p.Normalize.Whitespace,
			},
		},
		FileAbsent:              p.FileAbsent,
		AuthorizedKeys2Present:  p.AuthorizedKeys2,
		DisablesAuthorizedKeys2: p.DisableKeys2(),
		Notes: jsonNotes{
			Guard:              clean(p.Note),
			RestrictiveOptions: clean(p.Warning),
			AgentOnlySurvivors: clean(p.AgentOnly),
		},
	}
	if p.Class == ClassChange {
		// Mapped explicitly: planOne sets Pending on every plan, but an
		// outcome exists only for a server phase 2 could write.
		outcome := string(p.Outcome)
		s.Outcome = &outcome
	}
	s.Error, s.ErrorKind = jsonErrorFor(p)
	for _, k := range p.Add {
		jk := jsonKeyFor(cfg, opts.Former, k)
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
			jk.Comment = clean(config.DesiredComment(u, k)) // what the write installs
		}
		s.Changes.Add = append(s.Changes.Add, jk)
	}
	for _, k := range p.Remove {
		s.Changes.Remove = append(s.Changes.Remove, jsonKeyFor(cfg, opts.Former, k))
	}
	for _, rw := range p.Rewrites {
		s.Changes.Rewrite = append(s.Changes.Rewrite, jsonRewriteFor(cfg, rw))
	}
	return s
}

// jsonErrorFor picks the server's error text and kind: the unreachable
// error (kind from audit's classifier), the plan refusal (no kind), or the
// phase-2 outcome error — "canceled" only on a pending server phase 2 never
// started, so "not started" is detectable without parsing English.
func jsonErrorFor(p ServerPlan) (*string, string) {
	switch p.Class {
	case ClassUnreachable:
		if p.Err != nil {
			msg := cleanLine(p.Err.Error())
			return &msg, string(audit.ErrorKindOf(p.Err))
		}
	case ClassRefused:
		msg := cleanLine(p.Refusal)
		return &msg, ""
	case ClassChange:
		if p.OutcomeErr != nil {
			msg := cleanLine(p.OutcomeErr.Error())
			if p.Outcome == OutcomePending && errors.Is(p.OutcomeErr, errInterrupted) {
				return &msg, string(audit.ErrorKindCanceled)
			}
			return &msg, ""
		}
	}
	return nil, ""
}

// jsonKeyFor renders a key object: the comment is the key's own (on-server
// for remove; add overrides it with the decided comment). A key the
// rendered config does not own carries its former owner when the edit
// removed it.
func jsonKeyFor(cfg, former *config.Config, k authkeys.Key) jsonKey {
	jk := jsonKey{Fingerprint: k.Fingerprint, Type: k.Type, Comment: clean(k.Comment)}
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		name := u.Name
		jk.Owner = &name
		jk.Operator = u.Operator
		return jk
	}
	if former != nil {
		if fu, ok := former.OwnerOf(k.Fingerprint); ok {
			jk.FormerOwner = fu.Name
		}
	}
	return jk
}

// jsonRewriteFor renders a rewrite row: only what changes, plus loosens
// (the dropped restrictive options verbatim, [] when none).
func jsonRewriteFor(cfg *config.Config, rw RewriteRow) jsonRewrite {
	jr := jsonRewrite{Fingerprint: rw.Key.Fingerprint, Type: rw.Key.Type, Loosens: cleanAll(rw.Loosens)}
	if u, ok := cfg.OwnerOf(rw.Key.Fingerprint); ok {
		name := u.Name
		jr.Owner = &name
		jr.Operator = u.Operator
	}
	if rw.OptionsDiffer {
		jr.OptionsChange = &jsonOptionsChange{From: cleanAll(rw.ActualOptions), To: cleanAll(rw.Key.Options)}
	}
	if rw.CommentDiffers {
		jr.CommentChange = &jsonCommentChange{From: clean(rw.ActualComment), To: clean(rw.DesiredComment)}
	}
	return jr
}
