// Package audit orchestrates the drift audit: it fans out over the fleet,
// fetches each server's actual authorized_keys through the KeyReader seam,
// diffs against the manifest's desired state, and renders a report.
package audit

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
)

// KeyReader fetches a server's current authorized_keys. Implementations must
// honor ctx cancellation/deadlines.
type KeyReader interface {
	ReadAuthorizedKeys(ctx context.Context, srv config.Server) (fleet.ReadResult, error)
}

// ServerResult is the audit outcome for one server.
type ServerResult struct {
	Server         config.Server
	Err            error // connection/auth/host-key/read failure: server unauditable
	FileAbsent     bool
	Content        []byte // raw file bytes as read; apply's byte-exact convergence input
	SessionKeyFP   string // key (file or agent) that completed the phase-1 handshake
	NoUsersGranted bool
	ParseErrs      []authkeys.ParseError
	Diff           authkeys.Result
	// Duplicates lists fingerprints installed on more than one line, in
	// first-occurrence order. Diff collapses them (first wins), but sshd
	// keeps scanning after a line whose options refuse a login, so an
	// unrestricted second copy defeats a restricted first one.
	Duplicates      []Duplicate
	AuthorizedKeys2 bool // unmanaged non-empty ~/.ssh/authorized_keys2 (see fleet.ReadResult)
	// HeaderSerial and HeaderManaged are authkeys.ParseHeaderOf's verdict on
	// Content's first line: the serial of the manifest that last wrote the
	// file (0 for the legacy header), and whether it is a managed header at
	// all. Zero for an absent file.
	HeaderSerial  uint64
	HeaderManaged bool
	// Keys2 and Keys2Err carry fleet.ReadResult's authorized_keys2 read;
	// only the post-revoke sweep's reader asks for it.
	Keys2    []byte
	Keys2Err error
}

// Duplicate is one fingerprint installed on Count (>= 2) lines; Key is its
// first occurrence.
type Duplicate struct {
	Key   authkeys.Key
	Count int
}

// Compliant reports whether this server fully matches the source of truth.
// An unreadable (Err != nil) or partially-parsed (ParseErrs) server is never
// compliant, and neither is one whose matched keys carry options other than
// the manifest's, whose file repeats a fingerprint, or which has an
// unmanaged authorized_keys2. A file-absent server with no desired keys is
// treated as compliant: nothing should be there and nothing is. Comment
// drift is cosmetic and never counts.
func (r ServerResult) Compliant() bool {
	return r.Err == nil &&
		len(r.ParseErrs) == 0 &&
		len(r.Diff.Missing) == 0 &&
		len(r.Diff.Unauthorized) == 0 &&
		len(r.Duplicates) == 0 &&
		!r.AuthorizedKeys2 &&
		!r.anyOptionsDrift()
}

// optionsDrift compares a matched key's on-server options (Diff.Actual)
// with the manifest's (the OK entry carries the desired form) — the same
// comparison apply's rewrite rows make. Options are security-relevant
// (from=, command=, restrict), so unlike comment drift this is real drift.
func (r ServerResult) optionsDrift(k authkeys.Key) (actual, desired []string, drifted bool) {
	actual = r.Diff.Actual[k.Fingerprint].Options
	return actual, k.Options, !slices.Equal(actual, k.Options)
}

func (r ServerResult) anyOptionsDrift() bool {
	for _, k := range r.Diff.OK {
		if _, _, drifted := r.optionsDrift(k); drifted {
			return true
		}
	}
	return false
}

// duplicatesOf lists fingerprints occurring more than once in actual, in
// first-occurrence order.
func duplicatesOf(actual []authkeys.Key) []Duplicate {
	counts := make(map[string]int, len(actual))
	for _, k := range actual {
		counts[k.Fingerprint]++
	}
	var dups []Duplicate
	for _, k := range actual {
		if n := counts[k.Fingerprint]; n > 1 {
			dups = append(dups, Duplicate{Key: k, Count: n})
			counts[k.Fingerprint] = 0 // report each fingerprint once
		}
	}
	return dups
}

// GrantedFingerprints lists the fingerprints the manifest grants on server,
// in authkeys.OfferOrder. Connection layers offer these keys (from --identity files
// or the agent) first, so a run holding many keys does not exhaust sshd's
// MaxAuthTries on keys the server was never meant to accept, and a session
// authenticates with an unrestricted key whenever one is held.
func GrantedFingerprints(cfg *config.Config, server string) []string {
	return authkeys.OfferOrder(cfg.DesiredFor(server))
}

// auditOne audits a single server. It is self-contained and shares no mutable
// state, so Run can execute many of these concurrently.
func auditOne(ctx context.Context, cfg *config.Config, reader KeyReader, srv config.Server, timeout time.Duration, log *slog.Logger) ServerResult {
	res := ServerResult{Server: srv}
	desired := cfg.DesiredFor(srv.Name)
	res.NoUsersGranted = len(desired) == 0

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	start := time.Now()
	read, err := reader.ReadAuthorizedKeys(ctx, srv)
	if err != nil {
		// Live telemetry: the report will also show this, but during a slow
		// fan-out the operator sees which server failed as it happens. A
		// canceled read is the operator's own Ctrl-C: the command exits 3
		// with one "interrupted" line, so a warning per queued server would
		// only bury it.
		if fleet.ErrorKindOf(err) != fleet.ErrorKindCanceled {
			log.Warn(fmt.Sprintf("%s: %v", srv.Name, err))
		}
		res.Err = err
		return res
	}
	res.FileAbsent = read.FileAbsent
	res.Content = read.Content
	res.SessionKeyFP = read.SessionKeyFP
	res.AuthorizedKeys2 = read.AuthorizedKeys2
	res.Keys2, res.Keys2Err = read.Keys2, read.Keys2Err
	if !read.FileAbsent {
		res.HeaderSerial, res.HeaderManaged = authkeys.ParseHeaderOf(read.Content)
	}

	actual, parseErrs := authkeys.ParseFile(read.Content)
	res.ParseErrs = parseErrs
	res.Diff = authkeys.Diff(desired, actual)
	res.Duplicates = duplicatesOf(actual)
	log.Debug("audited", "server", srv.Name, "dur", time.Since(start).Round(time.Millisecond))
	return res
}

// Options tunes the fleet fan-out.
type Options struct {
	Parallel int // max concurrent server audits (>= 1)
	// Servers restricts the fan-out to a subset of cfg's servers (apply's
	// --server canary flag); nil or empty audits the whole fleet.
	Servers          []config.Server
	PerServerTimeout time.Duration // overall deadline per server; 0 = none
	Logger           *slog.Logger  // optional per-server telemetry; nil discards
}

// logger returns the configured logger or a discard logger, so auditOne
// never nil-checks.
func (o Options) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// Run audits every server concurrently through a bounded worker pool and
// returns results sorted by server name, so output is deterministic no matter
// the completion order.
func Run(ctx context.Context, cfg *config.Config, reader KeyReader, opts Options) []ServerResult {
	if opts.Parallel < 1 {
		opts.Parallel = 1
	}
	log := opts.logger()
	servers := opts.Servers
	if len(servers) == 0 {
		servers = cfg.Servers
	}
	results := make([]ServerResult, len(servers))
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	for i, srv := range servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Ctrl-C stops the queue: a server still waiting for a slot is
			// never dialed (the same select apply.Execute uses).
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				results[i] = canceledResult(ctx, cfg, srv)
				return
			}
			defer func() { <-sem }()
			if ctx.Err() != nil { // both select cases were ready
				results[i] = canceledResult(ctx, cfg, srv)
				return
			}
			results[i] = auditOne(ctx, cfg, reader, srv, opts.PerServerTimeout, log)
		}()
	}
	wg.Wait()
	sort.Slice(results, func(a, b int) bool {
		return results[a].Server.Name < results[b].Server.Name
	})
	return results
}

// canceledResult is a server the run never read because ctx ended first.
// fleet.ErrorKindOf classifies the wrapped context error (canceled or timeout),
// so callers (cmd's interrupted(), apply's plan) see the same kind a read
// cut short would have produced.
func canceledResult(ctx context.Context, cfg *config.Config, srv config.Server) ServerResult {
	return ServerResult{
		Server:         srv,
		NoUsersGranted: len(cfg.DesiredFor(srv.Name)) == 0,
		Err:            fmt.Errorf("not read: %w", ctx.Err()),
	}
}
