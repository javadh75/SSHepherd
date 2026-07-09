// Package audit orchestrates the drift audit: it fans out over the fleet,
// fetches each server's actual authorized_keys through the KeyReader seam,
// diffs against the manifest's desired state, and renders a report.
package audit

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// ReadResult is the outcome of reading a server's authorized_keys.
// FileAbsent means login succeeded but the audited file does not exist —
// a strong signal sshd consults a different key source on that host.
type ReadResult struct {
	Content    []byte
	FileAbsent bool
}

// KeyReader fetches a server's current authorized_keys. Implementations must
// honor ctx cancellation/deadlines.
type KeyReader interface {
	ReadAuthorizedKeys(ctx context.Context, srv config.Server) (ReadResult, error)
}

// ServerResult is the audit outcome for one server.
type ServerResult struct {
	Server         config.Server
	Err            error // connection/auth/host-key/read failure: server unauditable
	FileAbsent     bool
	NoUsersGranted bool
	ParseErrs      []authkeys.ParseError
	Diff           authkeys.Result
}

// Compliant reports whether this server fully matches the source of truth.
// An unauditable or partially-unreadable server is never compliant.
func (r ServerResult) Compliant() bool {
	return r.Err == nil &&
		len(r.ParseErrs) == 0 &&
		len(r.Diff.Missing) == 0 &&
		len(r.Diff.Unauthorized) == 0
}

// auditOne audits a single server. It is self-contained and shares no mutable
// state, so Run can execute many of these concurrently.
func auditOne(ctx context.Context, cfg *config.Config, reader KeyReader, srv config.Server, timeout time.Duration) ServerResult {
	res := ServerResult{Server: srv}
	desired := cfg.DesiredFor(srv.Name)
	res.NoUsersGranted = len(desired) == 0

	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}

	read, err := reader.ReadAuthorizedKeys(ctx, srv)
	if err != nil {
		res.Err = err
		return res
	}
	res.FileAbsent = read.FileAbsent

	actual, parseErrs := authkeys.ParseFile(read.Content)
	res.ParseErrs = parseErrs
	res.Diff = authkeys.Diff(desired, actual)
	return res
}

// Options tunes the fleet fan-out.
type Options struct {
	Parallel         int           // max concurrent server audits (>= 1)
	PerServerTimeout time.Duration // overall deadline per server; 0 = none
}

// Run audits every server concurrently through a bounded worker pool and
// returns results sorted by server name, so output is deterministic no matter
// the completion order.
func Run(ctx context.Context, cfg *config.Config, reader KeyReader, opts Options) []ServerResult {
	if opts.Parallel < 1 {
		opts.Parallel = 1
	}
	results := make([]ServerResult, len(cfg.Servers))
	sem := make(chan struct{}, opts.Parallel)
	var wg sync.WaitGroup
	for i, srv := range cfg.Servers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = auditOne(ctx, cfg, reader, srv, opts.PerServerTimeout)
		}()
	}
	wg.Wait()
	sort.Slice(results, func(a, b int) bool {
		return results[a].Server.Name < results[b].Server.Name
	})
	return results
}
