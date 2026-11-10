package main

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	offerAll   bool
	idf        identityFlags
}

// register declares the flags; parallelUsage keeps each command's own
// --parallel wording (server audits / reads / connections).
func (f *connFlags) register(cmd *cobra.Command, parallelUsage string) {
	cmd.Flags().StringVar(&f.cfgPath, "config", defaultConfigPath, "path to the manifest")
	cmd.Flags().StringVar(&f.knownHosts, "known-hosts", defaultKnownHosts, "path to known_hosts (strict host-key checking)")
	cmd.Flags().IntVar(&f.parallel, "parallel", defaultParallel, parallelUsage)
	cmd.Flags().BoolVar(&f.offerAll, "offer-all-keys", false,
		"offer every loaded key to every server (default: only the keys the manifest grants there)")
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
	if f.offerAll {
		h.conn = append(h.conn, "--offer-all-keys")
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
	offerAll bool // --offer-all-keys
	// quietFallback: a preflight already warned once for the whole run, so
	// the per-server fallback lines drop to debug level.
	quietFallback bool
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
	return &fleetSession{log: log, khPath: khPath, kh: kh, creds: creds, parallel: f.parallel, offerAll: f.offerAll}, nil
}

// Read is phase 1 of every command: audit's pipeline over servers, offering
// preferKeys on each dial, with the phase and done lines, and a
// canceled run reported as a tool error (nothing rendered or written).
func (s *fleetSession) Read(ctx context.Context, verb string, cfg *config.Config, servers []config.Server,
	preferKeys func(config.Server) []string,
) ([]audit.ServerResult, error) {
	reader := s.reader(cfg, preferKeys)
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
// credentials, offering preferKeys on each dial, resolving via: through
// cfg.
func (s *fleetSession) reader(cfg *config.Config, preferKeys func(config.Server) []string) *sshread.Client {
	return &sshread.Client{KnownHostsPath: s.khPath, KnownHosts: s.kh, Creds: s.creds, DialTimeout: dialTimeout,
		PreferKeys: preferKeys, Server: cfg.ServerNamed, OfferAll: s.offerAll, QuietFallback: s.quietFallback, Log: s.log}
}

// dialer is phase 2's dialer: the same known_hosts snapshot and
// credentials, resolving via: through cfg.
func (s *fleetSession) dialer(cfg *config.Config, preferKeys func(config.Server) []string) *sshconn.Dialer {
	return &sshconn.Dialer{KnownHostsPath: s.khPath, KnownHosts: s.kh, Creds: s.creds, DialTimeout: dialTimeout,
		PreferKeys: preferKeys, Server: cfg.ServerNamed, OfferAll: s.offerAll, QuietFallback: s.quietFallback, Log: s.log}
}

// readFleet is audit's and adopt's whole read over targets: an empty list
// needs no credentials (never reads a key, never prompts) and returns nil.
func readFleet(ctx context.Context, log *slog.Logger, cfg *config.Config, targets []config.Server, f *connFlags, ids identities, verb string) ([]audit.ServerResult, error) {
	if len(targets) == 0 {
		return nil, nil
	}
	s, err := openFleet(ctx, log, f, ids, false)
	if err != nil {
		return nil, err
	}
	s.warnNoGrantedKeys(ctx, targets, grantedOn(cfg))
	return s.Read(ctx, verb, cfg, targets, grantedOn(cfg))
}

// selectServers resolves --server names to manifest servers, preserving
// manifest order and deduplicating; no names selects the whole fleet. An
// unknown name is a usage error: a canary typo must not silently apply or
// audit nothing.
func selectServers(cfg *config.Config, names []string) ([]config.Server, error) {
	if len(names) == 0 {
		return cfg.Servers, nil
	}
	known := make(map[string]bool, len(cfg.Servers))
	for _, s := range cfg.Servers {
		known[s.Name] = true
	}
	wanted := make(map[string]bool, len(names))
	for _, n := range names {
		if !known[n] {
			return nil, fmt.Errorf("--server: unknown server %q", n)
		}
		wanted[n] = true
	}
	var targets []config.Server
	for _, s := range cfg.Servers {
		if wanted[s.Name] {
			targets = append(targets, s)
		}
	}
	return targets, nil
}

// printSkipped is the report's closing line when --server left servers out.
func printSkipped(w io.Writer, skipped int) {
	if skipped > 0 {
		fmt.Fprintf(w, "(%s skipped by --server)\n", apply.Plural(skipped, "server", "servers"))
	}
}

// grantedOn is every command's PreferKeys for cfg: the keys it grants on srv.
func grantedOn(cfg *config.Config) func(config.Server) []string {
	return func(srv config.Server) []string { return audit.GrantedFingerprints(cfg, srv.Name) }
}

// warnNoGrantedKeys warns, before the first read of a run, when no
// held key is granted on any target server: normal right after import
// --servers-only, and then one line is enough, so the per-server fallback
// warnings drop to debug level. Warn only: first contact is what the
// fallback exists for. Skipped under --offer-all-keys; a credential error is
// left for the first connection to report.
func (s *fleetSession) warnNoGrantedKeys(ctx context.Context, servers []config.Server, preferKeys func(config.Server) []string) {
	if s.offerAll {
		return
	}
	signers, release, err := s.creds.Signers(ctx)
	if err != nil {
		return
	}
	defer release()
	for _, srv := range servers {
		granted := preferKeys(srv)
		for _, signer := range signers {
			if sshconn.GrantIndex(signer.PublicKey(), granted) >= 0 {
				return
			}
		}
	}
	s.quietFallback = true
	s.log.Warn("none of the loaded keys is granted on any target server; each server will be offered all " +
		apply.Plural(len(signers), "held key", "held keys"))
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
