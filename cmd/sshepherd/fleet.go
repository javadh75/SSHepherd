package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshread"
)

// connFlags are the connection flags audit, adopt, apply, revoke and rotate
// share: one registration, one set of defaults and help strings.
type connFlags struct {
	cfgPath    string
	knownHosts string
	parallel   int
	idf        identityFlags
}

// register declares the flags; parallelUsage keeps each command's own
// --parallel wording (server audits / reads / connections).
func (f *connFlags) register(cmd *cobra.Command, parallelUsage string) {
	cmd.Flags().StringVar(&f.cfgPath, "config", defaultConfigPath, "path to the manifest")
	cmd.Flags().StringVar(&f.knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&f.parallel, "parallel", defaultParallel, parallelUsage)
	f.idf.register(cmd)
}

// validate is step 1 of every connecting command: --parallel and the
// identity flags, before the manifest is read.
func (f *connFlags) validate() (identities, error) { return validateFlags(f.parallel, &f.idf) }

// followUp builds copy-paste follow-up commands carrying the run's own
// non-default flags, so a pasted hint reads the same manifest with the same
// known_hosts and keys. Values are paths, never file contents; --parallel
// is tuning, not correctness, and is left out.
type followUp struct {
	config string   // "--config X", or "" for the default
	conn   []string // "--known-hosts X", "--identity Y", … in flag order
}

func (f *connFlags) followUp() followUp {
	var h followUp
	if f.cfgPath != defaultConfigPath {
		h.config = "--config " + hintArg(f.cfgPath)
	}
	if f.knownHosts != defaultKnownHosts {
		h.conn = append(h.conn, "--known-hosts "+hintArg(f.knownHosts))
	}
	for _, p := range f.idf.paths {
		h.conn = append(h.conn, "--identity "+hintArg(p))
	}
	if f.idf.defaultFile != "" {
		h.conn = append(h.conn, "--identity-passphrase-file "+hintArg(f.idf.defaultFile))
	}
	for _, kv := range f.idf.perKey {
		h.conn = append(h.conn, "--identity-passphrase "+hintArg(kv))
	}
	return h
}

// command renders "sshepherd SUB LEAD… [--config] [connection flags] TAIL…"
// (lead: e.g. --key FP; tail: e.g. --server NAME, --operator).
func (h followUp) command(sub string, lead []string, tail ...string) string {
	parts := append([]string{"sshepherd", sub}, lead...)
	if h.config != "" {
		parts = append(parts, h.config)
	}
	parts = append(append(parts, h.conn...), tail...)
	return strings.Join(parts, " ")
}

// suffix is the flags part of command, with a leading space ("" for none).
func (h followUp) suffix() string {
	parts := h.conn
	if h.config != "" {
		parts = append([]string{h.config}, parts...)
	}
	if len(parts) == 0 {
		return ""
	}
	return " " + strings.Join(parts, " ")
}

// manifestError words a manifest that cannot be loaded, once. config's own
// "read manifest:"/"parse manifest:" prefix is kept and cmd adds none; a
// missing file gets the bootstrap hint; a validation error (config's joined
// list has no prefix) names the file. flag names path: "--config", or
// import's "--merge".
func manifestError(flag, path string, err error) error {
	if errors.Is(err, fs.ErrNotExist) {
		return &missingManifestError{flag: flag, path: path, err: err}
	}
	if m := err.Error(); strings.HasPrefix(m, "read manifest:") || strings.HasPrefix(m, "parse manifest:") {
		return err //nolint:wrapcheck // config's verdict already says what failed; a prefix would only stutter
	}
	return fmt.Errorf("invalid manifest %s: %w", path, err)
}

// missingManifestError is a manifest path that does not exist: the default
// path points at the bootstrap command, an explicit one says to check the
// flag first.
type missingManifestError struct {
	flag, path string
	err        error
}

func (e *missingManifestError) Error() string {
	create := "'sshepherd import --servers-only -o " + hintArg(e.path) + "'"
	if e.flag == "--config" && e.path == defaultConfigPath {
		return "no manifest at " + e.path + " — create one with " + create + ", or pass --config PATH"
	}
	return "no manifest at " + e.path + " — check " + e.flag + ", or create one with " + create
}

func (e *missingManifestError) Unwrap() error { return e.err }

// logManifest is every command's loaded-manifest phase line, then the
// manifest's warnings.
func logManifest(log *slog.Logger, cfg *config.Config) {
	log.Info("loaded manifest: " + apply.Plural(len(cfg.Users), "user", "users") + ", " + apply.Plural(len(cfg.Servers), "server", "servers"))
	for _, w := range cfg.Warnings {
		log.Warn(w)
	}
}

// fleetSession is one run's connection setup, built once: known_hosts parsed
// once, the key files loaded (may prompt), the credentials checked. Every
// reader, writer and probe of the run shares the snapshot and credentials.
type fleetSession struct {
	log      *slog.Logger
	khPath   string
	kh       *sshconn.KnownHosts
	creds    *sshconn.Credentials
	parallel int
}

// openFleet runs the pre-dial checks in the documented order: known_hosts
// (a bad path fails with one clear error instead of N identical per-server
// errors, before any key file is read), key files, credentials (needHeld:
// apply's guard needs plain held keys).
func openFleet(ctx context.Context, log *slog.Logger, f *connFlags, ids identities, needHeld bool) (*fleetSession, error) {
	khPath, err := expandHome(f.knownHosts)
	if err != nil {
		return nil, err
	}
	kh, err := sshread.LoadKnownHosts(khPath)
	if err != nil {
		return nil, fmt.Errorf("known_hosts preflight: %w", err)
	}
	creds, err := ids.credentials(ctx, log)
	if err != nil {
		return nil, err
	}
	if err := checkCredentials(ctx, creds, needHeld); err != nil {
		return nil, err
	}
	return &fleetSession{log: log, khPath: khPath, kh: kh, creds: creds, parallel: f.parallel}, nil
}

// Read is phase 1 of every command: audit's pipeline over servers, offering
// preferKeys first on each dial, with the phase and done lines, and a
// canceled run reported as a tool error (nothing rendered or written).
func (s *fleetSession) Read(ctx context.Context, verb string, cfg *config.Config, servers []config.Server,
	preferKeys func(config.Server) []string,
) ([]audit.ServerResult, error) {
	reader := s.reader(preferKeys)
	s.log.Info(fmt.Sprintf("%s %s (parallelism %d)…", verb, apply.Plural(len(servers), "server", "servers"), s.parallel))
	start := time.Now()
	results := audit.Run(ctx, cfg, reader, audit.Options{Parallel: s.parallel, PerServerTimeout: perServerTimeout,
		Servers: servers, Logger: s.log})
	logFleetReadDone(s.log, cfg, results, start)
	if err := interrupted(ctx); err != nil {
		return nil, err
	}
	return results, nil
}

// reader is phase 1's reader: the run's known_hosts snapshot and
// credentials, offering preferKeys first on each dial.
func (s *fleetSession) reader(preferKeys func(config.Server) []string) *sshread.Client {
	return &sshread.Client{KnownHostsPath: s.khPath, KnownHosts: s.kh, Creds: s.creds,
		DialTimeout: dialTimeout, PreferKeys: preferKeys, Log: s.log}
}

// dialer is phase 2's dialer: the same known_hosts snapshot and credentials.
func (s *fleetSession) dialer(preferKeys func(config.Server) []string) *sshconn.Dialer {
	return &sshconn.Dialer{KnownHostsPath: s.khPath, KnownHosts: s.kh, Creds: s.creds,
		DialTimeout: dialTimeout, PreferKeys: preferKeys, Log: s.log}
}

// readFleet is audit's and adopt's whole read: an empty fleet needs no
// credentials (never reads a key, never prompts) and returns nil.
func readFleet(ctx context.Context, log *slog.Logger, cfg *config.Config, f *connFlags, ids identities, verb string) ([]audit.ServerResult, error) {
	if len(cfg.Servers) == 0 {
		return nil, nil
	}
	s, err := openFleet(ctx, log, f, ids, false)
	if err != nil {
		return nil, err
	}
	// Granted keys (operators first) go first, so many held keys cannot trip MaxAuthTries.
	return s.Read(ctx, verb, cfg, cfg.Servers, func(srv config.Server) []string { return audit.GrantedFingerprints(cfg, srv.Name) })
}

// interrupted reports a canceled run (Ctrl-C/SIGTERM) as a tool error.
// Read-only commands check it after their fan-out: servers the interrupt
// cut short come back as read errors, and treating them as unreachable
// would render a report (or, under adopt --partial, write a manifest)
// that misdescribes the fleet.
func interrupted(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("interrupted: %w — no report or manifest produced", err)
	}
	return nil
}
