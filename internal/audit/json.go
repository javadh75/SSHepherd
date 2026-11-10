package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sanitize"
)

// schemaVersion marks the JSON report shape. Bump only on breaking changes
// so consumers can hard-fail instead of misparsing.
const schemaVersion = 1

// The json* types are the wire shape of --json output, pinned by the
// 2026-07-16 spec and the report_*.golden.json fixtures. Field names are
// part of the public contract — change them only with a schema bump.
type jsonReport struct {
	Schema int `json:"schema"`
	// ManifestSerial, PolicyConflicts and ManifestWarnings are
	// additive-optional (schema stays 1), each omitted when zero/empty.
	ManifestSerial   uint64                   `json:"manifest_serial,omitempty"`
	PolicyConflicts  []config.Conflict        `json:"policy_conflicts,omitempty"`
	ManifestWarnings []config.ManifestWarning `json:"manifest_warnings,omitempty"`
	Summary          jsonSummary              `json:"summary"`
	Servers          []jsonServer             `json:"servers"`
}

type jsonSummary struct {
	Servers int `json:"servers"`
	// Skipped is additive-optional (schema stays 1): servers --server left
	// out. Omitted when zero.
	Skipped     int `json:"skipped,omitempty"`
	Compliant   int `json:"compliant"`
	Drift       int `json:"drift"`
	Critical    int `json:"critical"`
	Unreachable int `json:"unreachable"`
	// JumpOnly is additive-optional (schema stays 1): jump_only servers,
	// listed and never read (spec S5). Omitted when zero.
	JumpOnly int `json:"jump_only,omitempty"`
	// HostKeyAlerts is additive-optional (schema stays 1): unreachable
	// servers whose host key changed or is @revoked — the reason exit_code
	// can be 2 with critical 0. Omitted when zero.
	HostKeyAlerts int `json:"host_key_alerts,omitempty"`
	// RevokedKeys and PolicyConflicts are additive-optional (schema stays
	// 1), omitted when zero: installed tombstoned keys across servers, and
	// the manifest's policy conflicts.
	RevokedKeys     int `json:"revoked_keys,omitempty"`
	PolicyConflicts int `json:"policy_conflicts,omitempty"`
	ExitCode        int `json:"exit_code"`
}

type jsonServer struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	// AuthorizedKeysFile is additive-optional (schema stays 1): present
	// exactly when the manifest sets the per-server override; omitempty
	// keeps override-free reports byte-identical to earlier releases.
	AuthorizedKeysFile string `json:"authorized_keys_file,omitempty"`
	// Via is additive-optional (schema stays 1): the bastion the manifest
	// reaches this server through (via:). Omitted for a direct server.
	Via    string  `json:"via,omitempty"`
	Status string  `json:"status"`
	Error  *string `json:"error"`
	// ErrorKind is additive-optional (schema stays 1): present exactly when
	// error is non-null; one of the fleet.ErrorKind values.
	ErrorKind string `json:"error_kind,omitempty"`
	// ViaFailed is additive-optional (schema stays 1): the bastion where an
	// unreachable server's connection failed (fleet.FailedHopOf). Omitted
	// when the failure is the server's own.
	ViaFailed string `json:"via_failed,omitempty"`
	// Hint is additive-optional (schema stays 1): operator remediation for
	// error, sanitized; never part of error.
	Hint           string           `json:"hint,omitempty"`
	Keys           jsonKeySets      `json:"keys"`
	ParseErrors    []jsonParseError `json:"parse_errors"`
	FileAbsent     bool             `json:"file_absent"`
	NoUsersGranted bool             `json:"no_users_granted"`
	// Duplicates and AuthorizedKeys2 are additive-optional (schema stays
	// 1), omitted when empty/false: fingerprints installed on several lines,
	// and a non-empty unmanaged ~/.ssh/authorized_keys2. Both are drift.
	Duplicates      []jsonDuplicate `json:"duplicates,omitempty"`
	AuthorizedKeys2 bool            `json:"authorized_keys2_present,omitempty"`
	// HeaderSerial, ManifestSerialAhead (D4a, drift) and ForgedHeaderSerial
	// (critical) are additive-optional (schema stays 1), omitted when 0.
	HeaderSerial        uint64 `json:"header_serial,omitempty"`
	ManifestSerialAhead uint64 `json:"manifest_serial_ahead,omitempty"`
	ForgedHeaderSerial  uint64 `json:"forged_header_serial,omitempty"`
	// Posture and CriticalReasons are additive-optional (schema stays 1):
	// the posture probe's findings, and exactly when status is critical why,
	// sorted and de-duplicated.
	Posture         []jsonPosture `json:"posture,omitempty"`
	CriticalReasons []string      `json:"critical_reasons,omitempty"`
}

type jsonPosture struct {
	Path  string `json:"path"`
	Issue string `json:"issue"`
	Mode  string `json:"mode"`
	UID   string `json:"uid"`
}

type jsonDuplicate struct {
	Owner       *string `json:"owner"`
	Fingerprint string  `json:"fingerprint"`
	Count       int     `json:"count"`
}

type jsonKeySets struct {
	Present      []jsonKey `json:"present"`
	Missing      []jsonKey `json:"missing"`
	Unauthorized []jsonKey `json:"unauthorized"`
	// External is additive-optional (schema stays 1): one object per line a
	// preserve: rule keeps (spec S6), each with its rule. Never drift.
	External []jsonKey `json:"external,omitempty"`
}

// jsonKey field presence is deliberately mixed: owner is always emitted
// (null = unknown key), while comment (identity hint, often empty) and
// operator, protected (exception marker: missing keys, and present keys that
// cannot log in) are omitted when unset.
type jsonKey struct {
	Owner       *string `json:"owner"`
	Comment     string  `json:"comment,omitempty"`
	Fingerprint string  `json:"fingerprint"`
	Type        string  `json:"type"`
	Operator    bool    `json:"operator,omitempty"`
	Protected   bool    `json:"protected,omitempty"`
	// CommentDrift is additive-optional (schema stays 1): present keys only,
	// and only when JSONOptions.Comments is on AND the on-server comment
	// differs from the decided write-time comment (config.DesiredComment).
	// Informational — never affects status or exit_code.
	CommentDrift *jsonCommentDrift `json:"comment_drift,omitempty"`
	// OptionsDrift is additive-optional (schema stays 1): present keys
	// whose on-server options differ from the manifest's. Unlike comment
	// drift it is real drift (status drift, exit 1) and is always reported.
	OptionsDrift *jsonOptionsDrift `json:"options_drift,omitempty"`
	// Options is additive-optional (schema stays 1): unauthorized keys the
	// manifest does not own, their on-server options, sanitized.
	Options []string `json:"options,omitempty"`
	// Revoked (a tombstoned unauthorized key, critical) and AccessRevoked
	// (an owner's key where an access tombstone removed it, D1d drift) are
	// additive-optional (schema stays 1).
	Revoked       *jsonRevoked       `json:"revoked,omitempty"`
	AccessRevoked *jsonAccessRevoked `json:"access_revoked,omitempty"`
	// CannotLogIn (a present protected key that is critical) and KeyIssues
	// (dsa, rsa_under_2048, expired; never on a revoked key) are
	// additive-optional (schema stays 1).
	CannotLogIn string   `json:"cannot_log_in,omitempty"`
	KeyIssues   []string `json:"key_issues,omitempty"`
	// Rule is additive-optional (schema stays 1): on keys.external entries
	// only, the kind of preserve: rule that kept the line (command or
	// comment), so comment-matched keys can be reviewed (D24a).
	Rule string `json:"rule,omitempty"`
}

type jsonRevoked struct {
	User   string `json:"user,omitempty"`
	Date   string `json:"date"`
	Reason string `json:"reason,omitempty"`
}

type jsonAccessRevoked struct {
	Date   string `json:"date"`
	Reason string `json:"reason,omitempty"`
}

type jsonOptionsDrift struct {
	Actual  []string `json:"actual"`
	Desired []string `json:"desired"`
}

type jsonCommentDrift struct {
	Actual  string `json:"actual"`
	Desired string `json:"desired"`
}

type jsonParseError struct {
	Line  int    `json:"line"`
	Error string `json:"error"`
}

// JSONOptions tunes the JSON report. Comments is the --comments twin of
// RenderOptions.Comments: opt-in comment_drift fields on present keys,
// informational only.
type JSONOptions struct {
	Comments bool
	// Skipped is the number of manifest servers --server left out.
	Skipped int
}

// RenderJSON writes the machine-readable audit report: one indented JSON
// document with a trailing newline. It is the --json twin of Render and
// takes the same inputs.
func RenderJSON(w io.Writer, cfg *config.Config, results []ServerResult, opts JSONOptions) error {
	rep := jsonReport{Schema: schemaVersion, ManifestSerial: cfg.Serial(), Servers: make([]jsonServer, 0, len(results))}
	rep.PolicyConflicts, rep.ManifestWarnings = ManifestFindings(cfg)
	for _, r := range results {
		rep.Servers = append(rep.Servers, jsonServerFor(cfg, r, opts))
	}
	c := tallyResults(cfg, results)
	rep.Summary = jsonSummary{
		Servers:         len(results),
		Skipped:         opts.Skipped,
		Compliant:       c.compliant,
		Drift:           c.drift,
		Critical:        c.critical,
		Unreachable:     c.unreachable,
		JumpOnly:        c.jumpOnly,
		HostKeyAlerts:   c.hostKeyAlerts,
		RevokedKeys:     c.revokedKeys,
		PolicyConflicts: len(rep.PolicyConflicts),
		ExitCode:        ExitCode(cfg, results),
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		return fmt.Errorf("encode audit report: %w", err)
	}
	return nil
}

func jsonServerFor(cfg *config.Config, r ServerResult, opts JSONOptions) jsonServer {
	s := jsonServer{
		Name:               r.Server.Name,
		Host:               r.Server.Host,
		Port:               r.Server.Port,
		User:               r.Server.User,
		AuthorizedKeysFile: r.Server.AuthorizedKeysFile,
		Via:                r.Server.Via,
		Status:             string(statusOf(cfg, r)),
		Keys: jsonKeySets{
			Present:      []jsonKey{},
			Missing:      []jsonKey{},
			Unauthorized: []jsonKey{},
		},
		ParseErrors:    []jsonParseError{},
		FileAbsent:     r.FileAbsent,
		NoUsersGranted: r.NoUsersGranted,
	}
	if r.Err != nil {
		// oneLine collapses newlines (same defense as the human head line);
		// sanitize.Remote strips C0/C1/Cf, which encoding/json leaves raw
		// (C1, Cf) or merely escapes (C0) for the consumer to decode.
		msg := sanitize.Remote(oneLine(r.Err))
		s.Error = &msg
		s.ErrorKind = string(fleet.ErrorKindOf(r.Err))
		// Not deduplicated: each server object stays self-contained.
		s.Hint = CleanHint(r.Err)
		s.ViaFailed = fleet.FailedHopOf(r.Err)
		return s
	}
	if r.Server.JumpOnly {
		return s // status jump_only, empty key lists: nothing was read
	}
	s.AuthorizedKeys2 = r.AuthorizedKeys2
	s.Posture, s.CriticalReasons = postureJSON(r), criticalReasons(cfg, r)
	serialFields(&s, cfg, r)
	for _, d := range r.Duplicates {
		jd := jsonDuplicate{Fingerprint: d.Key.Fingerprint, Count: d.Count}
		if u, ok := cfg.OwnerOf(d.Key.Fingerprint); ok {
			name := u.Name
			jd.Owner = &name
		}
		s.Duplicates = append(s.Duplicates, jd)
	}
	for _, k := range r.Diff.OK {
		s.Keys.Present = append(s.Keys.Present, jsonPresentKey(cfg, r, k, opts))
	}
	for _, k := range r.Diff.Missing {
		s.Keys.Missing = append(s.Keys.Missing, jsonKeyFor(cfg, k, true))
	}
	for _, k := range r.Diff.Unauthorized {
		jk := jsonKeyFor(cfg, k, false)
		if len(k.Options) > 0 && jk.Owner == nil {
			jk.Options = sanitizeAll(k.Options)
		}
		memoryKey(&jk, cfg, r.Server.Name, k)
		if jk.Revoked == nil {
			jk.KeyIssues = keyIssues(k, false)
		}
		s.Keys.Unauthorized = append(s.Keys.Unauthorized, jk)
	}
	for _, e := range r.External {
		s.Keys.External = append(s.Keys.External, jsonExternalKey(e))
	}
	for _, pe := range r.ParseErrs {
		// pe.Error() is the control-stripped rendering; the line prefix is
		// redundant with Line but keeps the string self-contained.
		s.ParseErrors = append(s.ParseErrors, jsonParseError{Line: pe.Line, Error: sanitize.Remote(pe.Error())})
	}
	return s
}

// jsonPresentKey is one matched key, with its drift, cannot_log_in and
// key_issues findings.
func jsonPresentKey(cfg *config.Config, r ServerResult, k authkeys.Key, opts JSONOptions) jsonKey {
	jk := jsonKeyFor(cfg, k, false)
	if actual, desired, drifted := r.optionsDrift(k); drifted {
		jk.OptionsDrift = &jsonOptionsDrift{Actual: sanitizeAll(actual), Desired: sanitizeAll(desired)}
	}
	if actual, desired, drifted := commentDrift(cfg, r, k); opts.Comments && drifted {
		jk.CommentDrift = &jsonCommentDrift{Actual: sanitize.Remote(actual), Desired: sanitize.Remote(desired)}
	}
	if reason, _ := r.cannotLogIn(cfg, k); reason != "" {
		jk.CannotLogIn = reason
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
			jk.markTier(u)
		}
	}
	jk.KeyIssues = keyIssues(k, true)
	return jk
}

// jsonExternalKey is one kept line in the unowned-key shape (owner null,
// sanitized comment and options, key_issues) plus the rule that kept it.
func jsonExternalKey(e External) jsonKey {
	k := e.Line.Key
	jk := jsonKey{Comment: sanitize.Remote(k.Comment), Fingerprint: k.Fingerprint, Type: k.Type, Rule: e.Rule}
	if len(k.Options) > 0 {
		jk.Options = sanitizeAll(k.Options)
	}
	jk.KeyIssues = keyIssues(k, false)
	return jk
}

// keyIssues lists a key's strength finding and, for a desired key, whether
// its expiry-time has passed; nil when there are none (omitted).
func keyIssues(k authkeys.Key, desired bool) []string {
	var out []string
	if k.Weak != "" {
		out = append(out, k.Weak)
	}
	if desired && authkeys.Expired(k.Options, now(), time.Local) {
		out = append(out, cannotLogInExpired)
	}
	return out
}

// postureJSON is the server's posture findings; nil when clean (omitted).
func postureJSON(r ServerResult) []jsonPosture {
	var out []jsonPosture
	for _, p := range r.Posture {
		out = append(out, jsonPosture{Path: sanitize.Remote(p.Path), Issue: p.Issue, Mode: p.Mode, UID: p.UID})
	}
	return out
}

// serialFields sets the server's header-serial fields (spec §9): the
// header's serial, and the D4a (drift) or forged (critical) verdict.
func serialFields(s *jsonServer, cfg *config.Config, r ServerResult) {
	m := cfg.Serial()
	if r.HeaderManaged {
		s.HeaderSerial = r.HeaderSerial
	}
	switch {
	case r.forged(m):
		s.ForgedHeaderSerial = r.HeaderSerial
	case r.serialAhead(m):
		s.ManifestSerialAhead = r.HeaderSerial
	}
}

// memoryKey marks an unauthorized key the manifest remembers: a key
// tombstone (revoked, critical) or, for a known owner, an access tombstone
// on this server (access_revoked, D1d drift). Tombstone text is printed,
// so it passes sanitize.Remote like every text field (spec §9).
func memoryKey(jk *jsonKey, cfg *config.Config, server string, k authkeys.Key) {
	if t, revoked := cfg.Revoked(k.Fingerprint); revoked {
		jk.Revoked = &jsonRevoked{User: sanitize.Remote(t.User), Date: t.Date, Reason: sanitize.Remote(t.Reason)}
		return
	}
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		if t, gone := cfg.AccessRevoked(u.Name, server); gone {
			jk.AccessRevoked = &jsonAccessRevoked{Date: t.Date, Reason: sanitize.Remote(t.Reason)}
		}
	}
}

// ManifestFindings is the manifest's policy conflicts and load warnings with
// every manifest-derived text through sanitize.Remote (spec §9). A D1e
// warning's server may hold control runes. Each list stays nil when empty
// (omitted). validate's document uses it too.
func ManifestFindings(cfg *config.Config) ([]config.Conflict, []config.ManifestWarning) {
	cs := cfg.Conflicts() // a copy
	for i := range cs {
		cs[i].Message, cs[i].User = sanitize.Remote(cs[i].Message), sanitize.Remote(cs[i].User)
	}
	ws := slices.Clone(cfg.ManifestWarnings)
	for i := range ws {
		ws[i].User, ws[i].Server, ws[i].Message = sanitize.Remote(ws[i].User), sanitize.Remote(ws[i].Server), sanitize.Remote(ws[i].Message)
	}
	return cs, ws
}

// jsonKeyFor renders one key. markOperator is true only for missing keys:
// the exception marker (markTier) is the JSON twin of the CRITICAL rendering,
// and appears otherwise only on a present key that cannot log in (set in
// jsonPresentKey).
func jsonKeyFor(cfg *config.Config, k authkeys.Key, markOperator bool) jsonKey {
	jk := jsonKey{Comment: sanitize.Remote(k.Comment), Fingerprint: k.Fingerprint, Type: k.Type}
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		name := u.Name
		jk.Owner = &name
		if markOperator && u.IsProtected() {
			jk.markTier(u)
		}
	}
	return jk
}

// markTier sets the exception marker: operator on an operator's key,
// protected on any other protected user's, never both, so a document with no
// protected user is byte-identical to before.
func (jk *jsonKey) markTier(u config.User) {
	jk.Operator, jk.Protected = u.Operator, !u.Operator
}

// sanitizeAll renders an options list with each entry through
// sanitize.Remote (on-server options are remote-controlled text), and an
// absent list as [] rather than null.
func sanitizeAll(s []string) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		out = append(out, sanitize.Remote(v))
	}
	return out
}
