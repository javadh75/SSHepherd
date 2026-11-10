package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/identity"
	"github.com/javadh75/SSHepherd/internal/reconcile"
	"github.com/javadh75/SSHepherd/internal/sanitize"
)

// The warning kinds import assigns itself; reconcile assigns the rest.
// Consumers ignore kinds they do not know.
const (
	importWarnSSHConfig       = "ssh_config"
	importWarnIdentity        = "identity"
	importWarnUnsafeHost      = "unsafe_host"
	importWarnCollapsed       = "collapsed_target"
	importWarnProxy           = "proxy_not_mapped"
	importWarnMemoryDropped   = "revocation_memory_dropped"
	importWarnSettingsDropped = "manifest_settings_dropped"
)

// importWarnings is the one collector for import's warnings: each is logged
// as it is found, exactly as the plain run prints it, and kept for --json.
type importWarnings struct {
	log  *slog.Logger
	list []reconcile.Warning
}

func (c *importWarnings) add(w reconcile.Warning) {
	c.log.Warn(w.Message)
	c.list = append(c.list, w)
}

func (c *importWarnings) addAll(kind string, msgs ...string) {
	for _, m := range msgs {
		c.add(reconcile.Warning{Kind: kind, Message: m})
	}
}

// importSchema marks the document's shape; it stays 1, with additive fields.
const importSchema = 1

type importSummary struct {
	Hosts     int `json:"hosts"`
	Users     int `json:"users"`
	Grants    int `json:"grants"`
	Conflicts int `json:"conflicts"`
	Warnings  int `json:"warnings"`
	ExitCode  int `json:"exit_code"`
}

type importServerJSON struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
	User string `json:"user"`
	Via  string `json:"via,omitempty"` // the mapped ProxyJump's bastion (spec S5); additive, schema 1
}

type importUserJSON struct {
	Name        string   `json:"name"`
	Fingerprint string   `json:"fingerprint"`
	Type        string   `json:"type"`
	Operator    bool     `json:"operator,omitempty"`
	Servers     []string `json:"servers"`
}

// importDoc is import's --json document, written only on exit 0. The lists
// are always present; Output and Manifest are mutually exclusive. Notes are
// steady-state findings and are not counted in summary.warnings.
type importDoc struct {
	Schema     int                   `json:"schema"`
	Command    string                `json:"command"`
	Mode       string                `json:"mode"`
	Output     *adopt.Output         `json:"output,omitempty"`
	Manifest   *string               `json:"manifest,omitempty"`
	Summary    importSummary         `json:"summary"`
	NewServers []importServerJSON    `json:"new_servers"`
	NewUsers   []importUserJSON      `json:"new_users"`
	Extensions []reconcile.Extension `json:"extensions"`
	Warnings   []reconcile.Warning   `json:"warnings"`
	Notes      []string              `json:"notes"`
}

// importStats is what the ssh config yielded (hosts as parsed, users after
// target collapse, their server grants without operators).
type importStats struct {
	hosts, users, grants int
}

func importStatsOf(parsed int, users []identity.User) importStats {
	grants := 0
	for _, u := range users {
		if !u.Operator {
			grants += len(u.Servers)
		}
	}
	return importStats{hosts: parsed, users: len(users), grants: grants}
}

// importOutcome is what the output adds: a merge's plan, or a fresh
// manifest, where every entry is new.
type importOutcome struct {
	servers    []importServerJSON
	users      []importUserJSON
	extensions []reconcile.Extension
	conflicts  int
	notes      []string
}

// newImportUser names a key for the report. The line has already passed
// config.Parse or identity resolution, so a failed parse leaves the facts
// empty rather than failing a finished run.
func newImportUser(name, line string, operator bool, servers []string) importUserJSON {
	if servers == nil {
		servers = []string{}
	}
	u := importUserJSON{Name: name, Operator: operator, Servers: servers}
	if k, err := authkeys.ParseLine(line); err == nil && k != nil {
		u.Fingerprint, u.Type = k.Fingerprint, k.Type
	}
	return u
}

func planOutcome(plan reconcile.Plan) importOutcome {
	grants := make(map[string][]string, len(plan.NewGrants))
	for _, g := range plan.NewGrants {
		grants[g.User] = g.Servers
	}
	out := importOutcome{
		servers:    make([]importServerJSON, 0, len(plan.NewServers)),
		users:      make([]importUserJSON, 0, len(plan.NewUsers)),
		extensions: append([]reconcile.Extension{}, plan.Extensions...),
		conflicts:  plan.ConflictsSkipped(),
		notes:      plan.Notes,
	}
	for _, s := range plan.NewServers {
		port := s.Port
		if port == 0 {
			port = 22
		}
		out.servers = append(out.servers, importServerJSON{Name: s.Name, Host: s.Host, Port: port, User: s.User, Via: s.Via})
	}
	for _, u := range plan.NewUsers {
		out.users = append(out.users, newImportUser(u.Name, u.Keys[0], u.Operator, grants[u.Name]))
	}
	return out
}

func freshOutcome(cfg *config.Config) importOutcome {
	grants := make(map[string][]string, len(cfg.Access))
	for _, a := range cfg.Access {
		grants[a.User] = append(grants[a.User], a.Servers...)
	}
	out := importOutcome{
		servers:    make([]importServerJSON, 0, len(cfg.Servers)),
		users:      make([]importUserJSON, 0, len(cfg.Users)),
		extensions: []reconcile.Extension{},
	}
	for _, s := range cfg.Servers {
		out.servers = append(out.servers, importServerJSON{Name: s.Name, Host: s.Host, Port: s.Port, User: s.User, Via: s.Via})
	}
	for _, u := range cfg.Users {
		out.users = append(out.users, newImportUser(u.Name, u.Keys[0], u.Operator, grants[u.Name]))
	}
	return out
}

// buildImportDoc assembles the document. The manifest bytes are not
// sanitized (they must equal a plain run's); the warnings and notes are.
func buildImportDoc(mode string, place adopt.Placement, stats importStats, out importOutcome, warnings []reconcile.Warning) importDoc {
	doc := importDoc{
		Schema: importSchema, Command: "import", Mode: mode,
		Output: place.Output, Manifest: place.Manifest,
		Summary: importSummary{Hosts: stats.hosts, Users: stats.users, Grants: stats.grants,
			Conflicts: out.conflicts, Warnings: len(warnings)},
		NewServers: out.servers, NewUsers: out.users, Extensions: out.extensions,
		Warnings: make([]reconcile.Warning, 0, len(warnings)),
		Notes:    make([]string, 0, len(out.notes)),
	}
	if doc.NewServers == nil {
		doc.NewServers = []importServerJSON{}
	}
	if doc.NewUsers == nil {
		doc.NewUsers = []importUserJSON{}
	}
	if doc.Extensions == nil {
		doc.Extensions = []reconcile.Extension{}
	}
	for _, w := range warnings {
		w.Server, w.Identity, w.User = sanitize.Remote(w.Server), sanitize.Remote(w.Identity), sanitize.Remote(w.User)
		w.Date, w.Message = sanitize.Remote(w.Date), sanitize.Remote(w.Message)
		doc.Warnings = append(doc.Warnings, w)
	}
	for _, n := range out.notes {
		doc.Notes = append(doc.Notes, sanitize.Remote(n))
	}
	return doc
}

// finishJSON emits the manifest and then the document, so a refused -o
// (exit 3) leaves stdout empty. A nil plan means a fresh manifest.
func (r *importRun) finishJSON(m manifestTarget, rendered []byte, saved *config.Config, plan *reconcile.Plan, stats importStats, warnings []reconcile.Warning) error {
	place, err := placeManifest(m, r.opts.outPath, rendered, r.opts.force)
	if err != nil {
		return err
	}
	mode, outcome := adopt.ModeGenerate, freshOutcome(saved)
	if plan != nil {
		mode, outcome = adopt.ModeMerge, planOutcome(*plan)
	}
	return writeImportDoc(r.stdout, buildImportDoc(mode, place, stats, outcome, warnings))
}

func writeImportDoc(w io.Writer, doc importDoc) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode import report: %w", err)
	}
	return nil
}
