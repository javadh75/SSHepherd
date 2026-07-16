package audit

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
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
	ExitCode    int `json:"exit_code"`
}

type jsonServer struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	// AuthorizedKeysFile is additive-optional (schema stays 1): present
	// exactly when the manifest sets the per-server override; omitempty
	// keeps override-free reports byte-identical to earlier releases.
	AuthorizedKeysFile string           `json:"authorized_keys_file,omitempty"`
	Status             string           `json:"status"`
	Error              *string          `json:"error"`
	Keys               jsonKeySets      `json:"keys"`
	ParseErrors        []jsonParseError `json:"parse_errors"`
	FileAbsent         bool             `json:"file_absent"`
	NoUsersGranted     bool             `json:"no_users_granted"`
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
		Servers:     len(results),
		Compliant:   c.compliant,
		Drift:       c.drift,
		Critical:    c.critical,
		Unreachable: c.unreachable,
		ExitCode:    ExitCode(cfg, results),
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
		// encoding/json escapes any remaining control bytes.
		msg := oneLine(r.Err)
		s.Error = &msg
		return s
	}
	for _, k := range r.Diff.OK {
		jk := jsonKeyFor(cfg, k, false)
		if actual, desired, drifted := commentDrift(cfg, r, k); opts.Comments && drifted {
			jk.CommentDrift = &jsonCommentDrift{Actual: actual, Desired: desired}
		}
		s.Keys.Present = append(s.Keys.Present, jk)
	}
	for _, k := range r.Diff.Missing {
		s.Keys.Missing = append(s.Keys.Missing, jsonKeyFor(cfg, k, true))
	}
	for _, k := range r.Diff.Unauthorized {
		s.Keys.Unauthorized = append(s.Keys.Unauthorized, jsonKeyFor(cfg, k, false))
	}
	for _, pe := range r.ParseErrs {
		// pe.Error() is the control-stripped rendering; the line prefix is
		// redundant with Line but keeps the string self-contained.
		s.ParseErrors = append(s.ParseErrors, jsonParseError{Line: pe.Line, Error: pe.Error()})
	}
	return s
}

// jsonKeyFor renders one key. markOperator is true only for missing keys:
// operator: true is the JSON twin of the CRITICAL rendering and appears
// nowhere else.
func jsonKeyFor(cfg *config.Config, k authkeys.Key, markOperator bool) jsonKey {
	jk := jsonKey{Comment: k.Comment, Fingerprint: k.Fingerprint, Type: k.Type}
	if u, ok := cfg.OwnerOf(k.Fingerprint); ok {
		name := u.Name
		jk.Owner = &name
		if markOperator && u.Operator {
			jk.Operator = true
		}
	}
	return jk
}
