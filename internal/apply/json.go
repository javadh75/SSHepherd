package apply

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sanitize"
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
	// SerialBump is apply's D4b bump (apply only); nil unless the run would bump.
	SerialBump *SerialBump
	Sweep      *SweepReport // revoke/rotate --sweep; nil when no sweep ran
}

// SerialBump is apply's D4b serial bump (spec §6) for the JSON document:
// From → To, saved or not. To is nil and Warning set when the manifest
// cannot be saved (a piped --config) or when the bump would push a render
// over the read path's limit (ReserialOversize; the run is withheld).
type SerialBump struct {
	From    uint64  `json:"from"`
	To      *uint64 `json:"to"`
	Saved   bool    `json:"saved"`
	Warning string  `json:"warning,omitempty"`
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
	// PolicyConflicts, ManifestWarnings and SerialBump are additive-optional
	// (schema stays 1), each omitted when empty.
	PolicyConflicts  []config.Conflict        `json:"policy_conflicts,omitempty"`
	ManifestWarnings []config.ManifestWarning `json:"manifest_warnings,omitempty"`
	SerialBump       *SerialBump              `json:"serial_bump,omitempty"`
	// Sweep is additive-optional (schema stays 1): revoke/rotate --sweep
	// only; omitted when no sweep ran (--dry-run, --no-apply, or no flag).
	Sweep *SweepReport `json:"sweep,omitempty"`
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
	// Unproven and LockoutUnrestored are additive (schema stays 1).
	Unproven          int `json:"unproven"`
	LockoutUnrestored int `json:"lockout_unrestored"`
	ExitCode          int `json:"exit_code"`
}

type jsonEdit struct {
	Saved     bool            `json:"saved"`
	Edits     []jsonEditEntry `json:"edits"`
	Affected  int             `json:"affected"`
	Operators []string        `json:"operators"`
	Emptied   []jsonEmptied   `json:"emptied"`
	// Serial, Revoked, AlreadyRevoked and CheckCommand are additive (schema
	// stays 1). Serial is present only when the edit was saved; Revoked is
	// [] when none.
	Serial         *uint64          `json:"serial,omitempty"`
	Revoked        []jsonTombstone  `json:"revoked"`
	AlreadyRevoked []AlreadyRevoked `json:"already_revoked,omitempty"`
	CheckCommand   string           `json:"check_command,omitempty"`
}

// jsonTombstone is a revoked: entry in the manifest's own shape.
type jsonTombstone struct {
	Fingerprint string   `json:"fingerprint,omitempty"`
	User        string   `json:"user,omitempty"`
	Servers     []string `json:"servers,omitempty"`
	Date        string   `json:"date"`
	Reason      string   `json:"reason,omitempty"`
}

// jsonEditEntry: pointer fields are present exactly for their kind, so a
// zero count or false flag is still emitted where it belongs.
type jsonEditEntry struct {
	Kind           string   `json:"kind"`
	User           string   `json:"user"`
	Keys           *int     `json:"keys,omitempty"`
	Grants         *int     `json:"grants,omitempty"`
	Groups         []string `json:"groups,omitempty"`
	Fingerprint    string   `json:"fingerprint,omitempty"`
	NewFingerprint string   `json:"new_fingerprint,omitempty"`
	KeepsExpiry    string   `json:"keeps_expiry,omitempty"`
	KeepOld        *bool    `json:"keep_old,omitempty"` // always present on rotate entries
	NoKeysLeft     *bool    `json:"no_keys_left,omitempty"`
	ClearsOperator *bool    `json:"clears_operator,omitempty"`
	// remove-access: AccessServers is a pointer so an empty list still
	// encodes as [] (never null) while staying absent for other kinds.
	AccessServers    *[]string `json:"access_servers,omitempty"`
	EntriesChanged   *int      `json:"entries_changed,omitempty"`
	EntriesRemoved   *int      `json:"entries_removed,omitempty"`
	ServersExcepted  *int      `json:"servers_excepted,omitempty"`
	WildcardsRemoved *int      `json:"wildcards_removed,omitempty"`
	NoGrantsLeft     *bool     `json:"no_grants_left,omitempty"`
}

type jsonEmptied struct {
	Server string   `json:"server"`
	Users  []string `json:"users"`
	Keys   int      `json:"keys"`
}

type jsonServer struct {
	Name               string  `json:"name"`
	Host               string  `json:"host"`
	Port               int     `json:"port"`
	User               string  `json:"user"`
	AuthorizedKeysFile string  `json:"authorized_keys_file,omitempty"`
	Class              string  `json:"class"`
	Outcome            *string `json:"outcome"`
	Error              *string `json:"error"`
	ErrorKind          string  `json:"error_kind,omitempty"`
	// Hint is additive-optional (schema stays 1): operator remediation for
	// error (unreachable or phase-2 failure), sanitized; never part of error.
	Hint                    string      `json:"hint,omitempty"`
	Changes                 jsonChanges `json:"changes"`
	FileAbsent              bool        `json:"file_absent"`
	AuthorizedKeys2Present  bool        `json:"authorized_keys2_present"`
	DisablesAuthorizedKeys2 bool        `json:"disables_authorized_keys2"`
	Notes                   jsonNotes   `json:"notes"`
	Serial                  *jsonSerial `json:"serial,omitempty"`
	// RestoredRevokedKeys and Warnings are additive-optional (schema stays
	// 1): a rollback that reinstated keys on the revoked: list (D10a), and
	// the D9c headless-proof warning; each omitted when empty.
	RestoredRevokedKeys []string `json:"restored_revoked_keys,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
}

// jsonSerial is the §3 verdict: header is null for no serial, writes null
// when nothing is written.
type jsonSerial struct {
	Header   *uint64 `json:"header"`
	Manifest uint64  `json:"manifest"`
	Writes   *uint64 `json:"writes"`
	Case     string  `json:"case"`
}

func jsonSerialFor(p ServerPlan) *jsonSerial {
	sp := p.Serial
	if sp.Case == "" || (sp.Header == 0 && sp.Manifest == 0) {
		return nil
	}
	js := &jsonSerial{Manifest: sp.Manifest, Case: string(sp.Case)}
	if sp.Header > 0 {
		h := sp.Header
		js.Header = &h
	}
	if p.Class == ClassChange {
		w := sp.Writes
		js.Writes = &w
	}
	return js
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
	// Options is additive-optional (schema stays 1): remove keys neither
	// the rendered nor the former manifest owns, their on-server options,
	// sanitized.
	Options []string `json:"options,omitempty"`
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
	// Widens is additive (schema stays 1), always present like loosens:
	// the relaxing options the rewrite adds (no-touch-required, or
	// pty/port-forwarding/… under restrict), [] when none.
	Widens []string `json:"widens"`
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
	Serial             string `json:"serial,omitempty"`
}

// RenderJSON writes the write-path report as one indented JSON document
// with a trailing newline. plans may be nil (empty fleet, edit-only run); a
// document is written for exit 0, 1 or 2 (consumers must treat an unknown
// outcome as not converged).
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
			Unproven: c.unproven, LockoutUnrestored: c.lockout,
			ExitCode: max(ExitCode(plans), opts.Sweep.ExitCode()),
		},
		Servers: make([]jsonServer, 0, len(plans)),
	}
	if opts.Edit != nil {
		doc.Edit = jsonEditFor(*opts.Edit, opts.Saved)
	}
	doc.PolicyConflicts, doc.ManifestWarnings = cleanMemory(cfg)
	doc.SerialBump = opts.SerialBump
	doc.Sweep = opts.Sweep.wire()
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
func clean(s string) string { return sanitize.Remote(s) }

// cleanMemory is the manifest's policy conflicts and load warnings with
// every manifest-derived text passed through clean (spec §9: "sanitized
// like today's text fields"). A D1e warning's server can be any string —
// even one with control runes (plan decision 3) — so this is not
// cosmetic. Each list stays nil when empty (omitted).
func cleanMemory(cfg *config.Config) ([]config.Conflict, []config.ManifestWarning) {
	cs := cfg.Conflicts() // a copy
	for i := range cs {
		cs[i].Message, cs[i].User = clean(cs[i].Message), clean(cs[i].User)
	}
	ws := slices.Clone(cfg.ManifestWarnings)
	for i := range ws {
		ws[i].User, ws[i].Server, ws[i].Message = clean(ws[i].User), clean(ws[i].Server), clean(ws[i].Message)
	}
	return cs, ws
}

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

// jsonRemoveAccess fills a remove-access entry: every field present, the
// server list [] rather than null.
func jsonRemoveAccess(je *jsonEditEntry, ed Edit) {
	servers := append([]string{}, ed.AccessServers...)
	changed, removed, excepted, wildcards, noGrants := ed.EntriesChanged, ed.EntriesRemoved, ed.ServersExcepted, ed.WildcardsRemoved, ed.NoGrantsLeft
	je.AccessServers = &servers
	je.EntriesChanged, je.EntriesRemoved, je.ServersExcepted, je.WildcardsRemoved = &changed, &removed, &excepted, &wildcards
	je.NoGrantsLeft = &noGrants
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
			je.Groups = ed.Groups
		case EditRemoveKey:
			noKeys, clears := ed.NoKeysLeft, ed.ClearsOperator
			je.Fingerprint = ed.Fingerprint
			je.NoKeysLeft, je.ClearsOperator = &noKeys, &clears
		case EditRotate:
			keepOld := ed.KeepOld
			je.Fingerprint, je.NewFingerprint, je.KeepsExpiry, je.KeepOld = ed.Fingerprint, ed.NewFingerprint, ed.KeepsExpiry, &keepOld
		case EditRemoveAccess:
			jsonRemoveAccess(&je, ed)
		case EditRecordKey:
			je.Fingerprint = ed.Fingerprint
		}
		e.Edits = append(e.Edits, je)
	}
	for _, em := range s.Emptied {
		e.Emptied = append(e.Emptied, jsonEmptied{Server: em.Server, Users: append([]string{}, em.Users...), Keys: em.Keys})
	}
	e.Revoked = make([]jsonTombstone, 0, len(s.Revoked))
	for _, t := range s.Revoked {
		e.Revoked = append(e.Revoked, jsonTombstone{Fingerprint: t.Fingerprint, User: clean(t.User),
			Servers: t.Servers, Date: t.Date, Reason: clean(t.Reason)})
	}
	if saved && s.Serial > 0 {
		serial := s.Serial
		e.Serial = &serial
	}
	e.AlreadyRevoked, e.CheckCommand = s.AlreadyRevoked, clean(s.CheckCommand)
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
			Serial:             clean(p.SerialNote),
		},
		Serial:              jsonSerialFor(p),
		RestoredRevokedKeys: cleanAll(rolledBackRevoked(p)),
		Warnings:            cleanAll(p.Warnings),
	}
	if p.Class == ClassChange {
		// Mapped explicitly: planOne sets Pending on every plan, but an
		// outcome exists only for a server phase 2 could write.
		outcome := string(p.Outcome)
		s.Outcome = &outcome
	}
	s.Error, s.ErrorKind, s.Hint = jsonErrorFor(cfg, opts, p)
	for _, k := range p.Add {
		jk := jsonKeyFor(cfg, opts.Former, k)
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
			jk.Comment = clean(config.DesiredComment(u, k)) // what the write installs
		}
		s.Changes.Add = append(s.Changes.Add, jk)
	}
	for _, k := range p.Remove {
		jk := jsonKeyFor(cfg, opts.Former, k)
		if jk.Owner == nil && jk.FormerOwner == "" && len(k.Options) > 0 {
			jk.Options = cleanAll(k.Options)
		}
		s.Changes.Remove = append(s.Changes.Remove, jk)
	}
	for _, rw := range p.Rewrites {
		s.Changes.Rewrite = append(s.Changes.Rewrite, jsonRewriteFor(cfg, rw))
	}
	return s
}

// rolledBackRevoked is D10a's list: the removed keys on the revoked: list
// that a rollback put back.
func rolledBackRevoked(p ServerPlan) []string {
	if p.RolledBack {
		return p.RevokedRemovals
	}
	return nil
}

// jsonErrorFor picks the server's error text, kind and hint: the
// unreachable error (kind from audit's classifier), the plan refusal (no
// kind, no hint), or the phase-2 outcome error — "canceled" on a pending
// server phase 2 never started, so "not started" is detectable without
// parsing English; otherwise the kind the transport attached (ARC-3: e.g.
// host_key_changed when the host key changed between plan and write, auth,
// timeout — a started server's "canceled" is its per-server deadline, so it
// reads "timeout"), none for refusals and unclassified write/verify errors. A
// LockoutError unwraps to its probe error, so a refused probe reports
// "auth". The hint is the error's remediation (audit.CleanHint), never part
// of the message. A rollback's error names the keys it put back
// (rollbackDetail), the same text as the report line.
func jsonErrorFor(cfg *config.Config, opts JSONOptions, p ServerPlan) (msg *string, kind, hint string) {
	switch p.Class {
	case ClassUnreachable:
		if p.Err != nil {
			m := cleanLine(p.Err.Error())
			return &m, string(fleet.ErrorKindOf(p.Err)), audit.CleanHint(p.Err)
		}
	case ClassRefused:
		m := cleanLine(p.Refusal)
		return &m, "", ""
	case ClassChange:
		if p.OutcomeErr != nil {
			m := cleanLine(outcomeText(cfg, opts.Former, p))
			if p.Outcome == OutcomePending && errors.Is(p.OutcomeErr, errInterrupted) {
				return &m, string(fleet.ErrorKindCanceled), ""
			}
			// A transport-classified failure (host key changed at the
			// write connect, auth, timeout…) keeps its kind; refusals and
			// unclassified write/verify errors carry none, as before.
			hint := audit.CleanHint(p.OutcomeErr)
			switch k := fleet.ErrorKindOf(p.OutcomeErr); k {
			case fleet.ErrorKindUnknown:
				return &m, "", hint
			case fleet.ErrorKindCanceled:
				// "canceled" marks a pending server that never started. A
				// started server's write connect is canceled only by the
				// per-server deadline (Ctrl-C there leaves it pending, and
				// nothing after the connect is cancelable), which the
				// transport sees as a plain cancellation.
				return &m, string(fleet.ErrorKindTimeout), hint
			default:
				return &m, string(k), hint
			}
		}
	}
	return nil, "", ""
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
// (the dropped restrictive options verbatim, [] when none) and widens (the
// added relaxing options, [] when none).
func jsonRewriteFor(cfg *config.Config, rw RewriteRow) jsonRewrite {
	jr := jsonRewrite{Fingerprint: rw.Key.Fingerprint, Type: rw.Key.Type,
		Loosens: cleanAll(rw.Loosens), Widens: cleanAll(rw.Widens)}
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
