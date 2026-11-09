package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/manifest"
	"github.com/javadh75/SSHepherd/internal/sanitize"
	"github.com/javadh75/SSHepherd/internal/sshread"
)

// The manifest_warnings kinds validate adds. Consumers ignore kinds they do
// not know.
const (
	warnManifestNotEditable = "manifest_not_editable"
	warnKnownHostsMissing   = "known_hosts_missing"
	warnHostKeyNotRecorded  = "host_key_not_recorded"
)

// validateSchema marks the JSON document's shape; it stays 1, with additive
// fields.
const validateSchema = 1

type validateSummary struct {
	Users    int `json:"users"`
	Servers  int `json:"servers"`
	Grants   int `json:"grants"`
	Warnings int `json:"warnings"`
	ExitCode int `json:"exit_code"`
}

// validateDoc is the --json document. Errors is always present;
// PolicyConflicts and ManifestWarnings follow audit's shapes and are omitted
// when empty.
type validateDoc struct {
	Schema           int                      `json:"schema"`
	Valid            bool                     `json:"valid"`
	Summary          validateSummary          `json:"summary"`
	HostKeysChecked  bool                     `json:"host_keys_checked"`
	Errors           []string                 `json:"errors"`
	PolicyConflicts  []config.Conflict        `json:"policy_conflicts,omitempty"`
	ManifestWarnings []config.ManifestWarning `json:"manifest_warnings,omitempty"`
}

type validateOpts struct {
	cfgPath    string
	knownHosts string
	strict     bool
	json       bool
}

func newValidateCmd(a *app, stdout io.Writer) *cobra.Command {
	var o validateOpts
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check the manifest offline: schema, policy conflicts and host-key coverage (never connects)",
		Long: "Checks the manifest offline: parses and validates it, reports policy\n" +
			"conflicts, says whether revoke, rotate and --merge can edit it and, when a\n" +
			"known_hosts file loads, which servers have no recorded host key. Never\n" +
			"opens a socket or reads a key.\n\n" + exitCodesValidate,
		Example: "  # Check the default manifest\n" +
			"  sshepherd validate\n\n" +
			"  # GitOps PR check: any warning fails the job\n" +
			"  sshepherd validate --strict --json --known-hosts ci/known_hosts --config fleet.yaml",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v := &validation{log: a.logger, stdout: stdout, opts: o, explicitKnownHosts: cmd.Flags().Changed("known-hosts")}
			return v.run()
		},
	}
	cmd.Flags().StringVar(&o.cfgPath, "config", defaultConfigPath, "path to the manifest")
	cmd.Flags().StringVar(&o.knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (checks that every server has a recorded host key)")
	cmd.Flags().BoolVar(&o.strict, "strict", false, "exit 1 when the manifest is valid but has warnings")
	cmd.Flags().BoolVar(&o.json, "json", false, "emit the result as machine-readable JSON on stdout")
	return cmd
}

// validation is one validate run.
type validation struct {
	log                *slog.Logger
	stdout             io.Writer
	opts               validateOpts
	explicitKnownHosts bool
	hostKeysChecked    bool // a known_hosts file loaded
}

func (v *validation) run() error {
	m, err := readManifest(v.opts.cfgPath)
	if err != nil {
		return manifestError("--config", v.opts.cfgPath, err)
	}
	cfg, err := config.Parse(m.Loaded)
	if err != nil {
		return v.invalid(err)
	}
	logManifest(v.log, cfg)
	own, err := notEditable(m.Loaded)
	if err != nil {
		return err
	}
	known, knownErr := v.knownHostsWarnings(cfg)
	if knownErr != nil && v.explicitKnownHosts {
		return knownErr // design: a bad explicit --known-hosts writes no document
	}
	own = append(own, known...)
	for _, w := range own {
		v.log.Warn(w.Message)
	}
	return v.finish(cfg, own, knownErr)
}

// knownHostsWarnings is step 5: a missing default file is a warning (OP1), a
// bad file is a tool error, and each server with no recorded host key is a
// warning. A host matched only by @cert-authority counts as recorded.
func (v *validation) knownHostsWarnings(cfg *config.Config) ([]config.ManifestWarning, error) {
	path := v.opts.knownHosts
	resolved, err := expandHome(path)
	if err != nil {
		return nil, fmt.Errorf("known_hosts preflight: %w", err)
	}
	kh, err := sshread.LoadKnownHosts(resolved)
	if errors.Is(err, fs.ErrNotExist) && !v.explicitKnownHosts {
		return []config.ManifestWarning{{Kind: warnKnownHostsMissing,
			Message: "no known_hosts at " + path + "; host keys were not checked"}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("known_hosts preflight: %w", err)
	}
	v.hostKeysChecked = true
	var out []config.ManifestWarning
	for _, s := range cfg.Servers {
		addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
		if kh.HostKeyAlgorithms(addr) == nil {
			out = append(out, config.ManifestWarning{Kind: warnHostKeyNotRecorded, Server: s.Name,
				Message: fmt.Sprintf("server %q: no host key recorded for %s in %s", s.Name, addr, path)})
		}
	}
	return out, nil
}

// notEditable reports a valid manifest the comment-preserving editor refuses.
func notEditable(data []byte) ([]config.ManifestWarning, error) {
	_, err := manifest.Load(data)
	var ue *manifest.UnsupportedError
	if errors.As(err, &ue) {
		return []config.ManifestWarning{{Kind: warnManifestNotEditable,
			Message: "revoke, rotate and --merge cannot edit this manifest: " + ue.Reason}}, nil
	}
	return nil, err //nolint:wrapcheck // nil, or config.Parse's verdict on bytes it already accepted
}

// finish reports the verdict: own is what validate found beyond the
// manifest's load warnings, and knownErr a default known_hosts file that
// exists but could not be loaded (exit 3; the document still says why). Under
// --json the document is written on every exit here, 3 included (a conflict is
// validate's finding, not a tool failure).
func (v *validation) finish(cfg *config.Config, own []config.ManifestWarning, knownErr error) error {
	conflicts, warnings := audit.ManifestFindings(cfg)
	for _, w := range own {
		w.Server, w.Message = sanitize.Remote(w.Server), sanitize.Remote(w.Message)
		warnings = append(warnings, w)
	}
	code := validateExit(len(conflicts), len(warnings), v.opts.strict)
	if knownErr != nil {
		code = 3
	}
	if v.opts.json {
		errs := []string{}
		if knownErr != nil {
			errs = splitErrors(knownErr)
		}
		err := v.writeDoc(validateDoc{
			Schema: validateSchema, Valid: len(conflicts) == 0,
			Summary: validateSummary{Users: len(cfg.Users), Servers: len(cfg.Servers), Grants: cfg.GrantCount(),
				Warnings: len(warnings), ExitCode: code},
			HostKeysChecked: v.hostKeysChecked, Errors: errs,
			PolicyConflicts: conflicts, ManifestWarnings: warnings,
		})
		if err != nil {
			return err
		}
	} else if code != 3 {
		fmt.Fprintf(v.stdout, "manifest OK: %s, %s, %s (%s)\n",
			apply.Plural(len(cfg.Users), "user", "users"), apply.Plural(len(cfg.Servers), "server", "servers"),
			apply.Plural(cfg.GrantCount(), "grant", "grants"), apply.Plural(len(warnings), "warning", "warnings"))
	}
	switch {
	case len(conflicts) > 0:
		return errors.Join(conflictsError(conflicts), knownErr) // Join drops a nil knownErr
	case knownErr != nil:
		return knownErr
	default:
		return exitFor(code)
	}
}

// invalid reports a manifest config.Parse refused: exit 3, and under --json
// a document whose counts are 0.
func (v *validation) invalid(err error) error {
	verdict := manifestError("--config", v.opts.cfgPath, err)
	if v.opts.json {
		if werr := v.writeDoc(validateDoc{Schema: validateSchema, Summary: validateSummary{ExitCode: 3}, Errors: splitErrors(err)}); werr != nil {
			return werr
		}
	}
	return verdict
}

func (v *validation) writeDoc(doc validateDoc) error {
	enc := json.NewEncoder(v.stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("encode validate report: %w", err)
	}
	return nil
}

// splitErrors lists each validation error of errors.Join, sanitized; a parse
// failure is one entry. Never nil.
func splitErrors(err error) []string {
	list := []error{err}
	var joined interface{ Unwrap() []error }
	if errors.As(err, &joined) {
		list = joined.Unwrap()
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		out = append(out, sanitize.Remote(e.Error()))
	}
	return out
}

// validateExit is the command's exit code once the manifest has parsed.
func validateExit(conflicts, warnings int, strict bool) int {
	switch {
	case conflicts > 0:
		return 3
	case strict && warnings > 0:
		return 1
	default:
		return 0
	}
}

// conflictsError is validate's own wording: conflictRefusal talks about
// writing, and validate writes nothing.
func conflictsError(cs []config.Conflict) error {
	msgs := make([]string, 0, len(cs))
	for _, c := range cs {
		msgs = append(msgs, c.Message)
	}
	return fmt.Errorf("manifest has %s: %s", apply.Plural(len(cs), "policy conflict", "policy conflicts"), strings.Join(msgs, "; "))
}
