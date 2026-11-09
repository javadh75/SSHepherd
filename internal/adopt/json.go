package adopt

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/javadh75/SSHepherd/internal/sanitize"
)

// The Report.Mode values.
const (
	ModeGenerate = "generate"
	ModeMerge    = "merge"
)

// jsonSchema marks the document's shape; it stays 1, with additive fields.
const jsonSchema = 1

// Output says where -o put the manifest. Written is false only for an
// in-place update whose bytes were identical.
type Output struct {
	Path    string `json:"path"`
	Written bool   `json:"written"`
}

// Placement is where a --json run's manifest went: Output with -o, the bytes
// in Manifest without it, neither when nothing was emitted. Manifest is a
// pointer because an emitted empty manifest (a no-op --merge of a 0-byte
// file) must still appear in the document.
type Placement struct {
	Output   *Output
	Manifest *string
}

// Report is what the document carries beyond the Plan.
type Report struct {
	Mode       string // ModeGenerate or ModeMerge
	Emitted    bool   // a manifest was produced
	Placement  Placement
	Servers    int
	Read       int
	PartlyRead int
	ExitCode   int
}

type jsonSummary struct {
	Servers    int `json:"servers"`
	Read       int `json:"read"`
	PartlyRead int `json:"partly_read"`
	NewUsers   int `json:"new_users"`
	Extensions int `json:"extensions"`
	Warnings   int `json:"warnings"`
	ExitCode   int `json:"exit_code"`
}

type jsonNewUser struct {
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint"`
	Type        string   `json:"type"`
	FoundOn     []string `json:"found_on"`
}

type jsonExtension struct {
	User    string   `json:"user"`
	Servers []string `json:"servers"`
}

// jsonUnreadable is a server the run could not read: it always carries
// error_kind.
type jsonUnreadable struct {
	Server    string `json:"server"`
	ErrorKind string `json:"error_kind"`
	Detail    string `json:"detail"`
	Hint      string `json:"hint,omitempty"`
}

// jsonLineIssue is a line adopt could not use on a server it did read.
type jsonLineIssue struct {
	Server string `json:"server"`
	Detail string `json:"detail"`
}

// jsonDoc is adopt's --json document. The lists are always present; Output
// and Manifest are mutually exclusive and absent when Emitted is false.
type jsonDoc struct {
	Schema     int              `json:"schema"`
	Command    string           `json:"command"`
	Mode       string           `json:"mode"`
	Emitted    bool             `json:"emitted"`
	Output     *Output          `json:"output,omitempty"`
	Manifest   *string          `json:"manifest,omitempty"`
	Summary    jsonSummary      `json:"summary"`
	NewUsers   []jsonNewUser    `json:"new_users"`
	Extensions []jsonExtension  `json:"extensions"`
	Unreadable []jsonUnreadable `json:"unreadable"`
	LineIssues []jsonLineIssue  `json:"line_issues"`
	Warnings   []Warning        `json:"warnings"`
}

// WriteJSON writes the discovery and warnings report for plan. The manifest
// bytes are not sanitized: they must equal a plain run's. Remote text in the
// rest is, because encoding/json does not escape C1 or Cf runes.
func WriteJSON(w io.Writer, p Plan, r Report) error {
	doc := jsonDoc{
		Schema: jsonSchema, Command: "adopt", Mode: r.Mode, Emitted: r.Emitted,
		Output: r.Placement.Output, Manifest: r.Placement.Manifest,
		Summary: jsonSummary{
			Servers: r.Servers, Read: r.Read, PartlyRead: r.PartlyRead,
			NewUsers: len(p.NewUsers), Extensions: len(p.Extensions), Warnings: len(p.Warnings), ExitCode: r.ExitCode,
		},
		NewUsers:   make([]jsonNewUser, 0, len(p.NewUsers)),
		Extensions: make([]jsonExtension, 0, len(p.Extensions)),
		Unreadable: make([]jsonUnreadable, 0, len(p.Issues)),
		LineIssues: make([]jsonLineIssue, 0, len(p.Issues)),
		Warnings:   make([]Warning, 0, len(p.Warnings)),
	}
	for _, u := range p.NewUsers {
		doc.NewUsers = append(doc.NewUsers, jsonNewUser{Name: u.Name, Fingerprint: u.Fingerprint, Type: u.Type, FoundOn: u.FoundOn})
	}
	for _, e := range p.Extensions {
		doc.Extensions = append(doc.Extensions, jsonExtension(e))
	}
	for _, is := range p.Issues {
		if is.Kind == "" {
			doc.LineIssues = append(doc.LineIssues, jsonLineIssue{Server: sanitize.Remote(is.Server), Detail: sanitize.Remote(is.Detail)})
			continue
		}
		doc.Unreadable = append(doc.Unreadable, jsonUnreadable{
			Server: sanitize.Remote(is.Server), ErrorKind: string(is.Kind),
			Detail: sanitize.Remote(is.Detail), Hint: sanitize.Remote(is.Hint),
		})
	}
	for _, x := range p.Warnings {
		x.Server, x.User, x.Date, x.Message = sanitize.Remote(x.Server), sanitize.Remote(x.User), sanitize.Remote(x.Date), sanitize.Remote(x.Message)
		doc.Warnings = append(doc.Warnings, x)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode adopt report: %w", err)
	}
	return nil
}
