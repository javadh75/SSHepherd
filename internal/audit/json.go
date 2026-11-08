package audit

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sanitize"
)

// schemaVersion marks the JSON report shape. Bump only on breaking changes
// so consumers can hard-fail instead of misparsing.
const schemaVersion = 1

// The json* types are the wire shape of --json output, pinned by the
// 2026-07-16 spec and the report_*.golden.json fixtures. Field names are
// part of the public contract — change them only with a schema bump.
type jsonReport struct {
	Schema  int          `json:"schema"`
	Summary jsonSummary  `json:"summary"`
	Servers []jsonServer `json:"servers"`
}

type jsonSummary struct {
	Servers     int `json:"servers"`
	Compliant   int `json:"compliant"`
	Drift       int `json:"drift"`
	Critical    int `json:"critical"`
	Unreachable int `json:"unreachable"`
	// HostKeyAlerts is additive-optional (schema stays 1): unreachable
	// servers whose host key changed or is @revoked — the reason exit_code
	// can be 2 with critical 0. Omitted when zero.
	HostKeyAlerts int `json:"host_key_alerts,omitempty"`
	ExitCode      int `json:"exit_code"`
}

type jsonServer struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	// AuthorizedKeysFile is additive-optional (schema stays 1): present
	// exactly when the manifest sets the per-server override; omitempty
	// keeps override-free reports byte-identical to earlier releases.
	AuthorizedKeysFile string  `json:"authorized_keys_file,omitempty"`
	Status             string  `json:"status"`
	Error              *string `json:"error"`
	// ErrorKind is additive-optional (schema stays 1): present exactly when
	// error is non-null; one of the audit.ErrorKind values.
	ErrorKind string `json:"error_kind,omitempty"`
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
}

// jsonKey field presence is deliberately mixed: owner is always emitted
// (null = unknown key), while comment (identity hint, often empty) and
// operator (exception marker, missing keys only) are omitted when unset.
type jsonKey struct {
	Owner       *string `json:"owner"`
	Comment     string  `json:"comment,omitempty"`
	Fingerprint string  `json:"fingerprint"`
	Type        string  `json:"type"`
	Operator    bool    `json:"operator,omitempty"`
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
}

// RenderJSON writes the machine-readable audit report: one indented JSON
// document with a trailing newline. It is the --json twin of Render and
// takes the same inputs.
func RenderJSON(w io.Writer, cfg *config.Config, results []ServerResult, opts JSONOptions) error {
	rep := jsonReport{Schema: schemaVersion, Servers: make([]jsonServer, 0, len(results))}
	for _, r := range results {
		rep.Servers = append(rep.Servers, jsonServerFor(cfg, r, opts))
	}
	c := tallyResults(cfg, results)
	rep.Summary = jsonSummary{
		Servers:       len(results),
		Compliant:     c.compliant,
		Drift:         c.drift,
		Critical:      c.critical,
		Unreachable:   c.unreachable,
		HostKeyAlerts: c.hostKeyAlerts,
		ExitCode:      ExitCode(cfg, results),
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
		s.ErrorKind = string(ErrorKindOf(r.Err))
		// Not deduplicated: each server object stays self-contained.
		s.Hint = CleanHint(r.Err)
		return s
	}
	s.AuthorizedKeys2 = r.AuthorizedKeys2
	for _, d := range r.Duplicates {
		jd := jsonDuplicate{Fingerprint: d.Key.Fingerprint, Count: d.Count}
		if u, ok := cfg.OwnerOf(d.Key.Fingerprint); ok {
			name := u.Name
			jd.Owner = &name
		}
		s.Duplicates = append(s.Duplicates, jd)
	}
	for _, k := range r.Diff.OK {
		jk := jsonKeyFor(cfg, k, false)
		if actual, desired, drifted := r.optionsDrift(k); drifted {
			jk.OptionsDrift = &jsonOptionsDrift{Actual: sanitizeAll(actual), Desired: sanitizeAll(desired)}
		}
		if actual, desired, drifted := commentDrift(cfg, r, k); opts.Comments && drifted {
			jk.CommentDrift = &jsonCommentDrift{Actual: sanitize.Remote(actual), Desired: sanitize.Remote(desired)}
		}
		s.Keys.Present = append(s.Keys.Present, jk)
	}
	for _, k := range r.Diff.Missing {
		s.Keys.Missing = append(s.Keys.Missing, jsonKeyFor(cfg, k, true))
	}
	for _, k := range r.Diff.Unauthorized {
		jk := jsonKeyFor(cfg, k, false)
		if len(k.Options) > 0 && jk.Owner == nil {
			jk.Options = sanitizeAll(k.Options)
		}
		s.Keys.Unauthorized = append(s.Keys.Unauthorized, jk)
	}
	for _, pe := range r.ParseErrs {
		// pe.Error() is the control-stripped rendering; the line prefix is
		// redundant with Line but keeps the string self-contained.
		s.ParseErrors = append(s.ParseErrors, jsonParseError{Line: pe.Line, Error: sanitize.Remote(pe.Error())})
	}
	return s
}

// jsonKeyFor renders one key. markOperator is true only for missing keys:
// operator: true is the JSON twin of the CRITICAL rendering and appears
// nowhere else.
func jsonKeyFor(cfg *config.Config, k authkeys.Key, markOperator bool) jsonKey {
	jk := jsonKey{Comment: sanitize.Remote(k.Comment), Fingerprint: k.Fingerprint, Type: k.Type}
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		name := u.Name
		jk.Owner = &name
		if markOperator && u.Operator {
			jk.Operator = true
		}
	}
	return jk
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
