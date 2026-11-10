package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
)

// sweepTargets is every server of cfg except the affected ones this run
// applied-and-verified or found converged (spec §7): those already prove
// the key is gone.
func sweepTargets(cfg *config.Config, plans []apply.ServerPlan) []config.Server {
	done := make(map[string]bool, len(plans))
	for _, p := range plans {
		if p.Class == apply.ClassConverged || (p.Class == apply.ClassChange && p.Outcome == apply.OutcomeApplied) {
			done[p.Server.Name] = true
		}
	}
	var out []config.Server
	for _, s := range cfg.Servers {
		if !done[s.Name] {
			out = append(out, s)
		}
	}
	return out
}

// keyTombstones filters this run's new tombstones to key entries: an access
// tombstone only names servers the run already wrote, so it adds nothing
// to look for.
func keyTombstones(ts []config.Tombstone) []config.Tombstone {
	var out []config.Tombstone
	for _, t := range ts {
		if t.IsKey() {
			out = append(out, t)
		}
	}
	return out
}

// runSweep reads targets with the run's session (known_hosts, credentials,
// --parallel), offering offer's keys on each dial, asking for
// authorized_keys2 too, and classifies the reads. The servers it reads were
// not written, so they still hold the old keys: offer must include them, or
// a server only the old key opens reads as unreachable instead of exit 2.
// A Ctrl-C reaching the sweep is no tool error: the manifest is saved and
// servers are written, so the run keeps its report and the unread servers
// count as unprovable (exit 1 at most), never exit 3.
func runSweep(ctx context.Context, sess *fleetSession, cfg *config.Config, offer func(config.Server) []string, targets []config.Server, tombs []config.Tombstone) apply.SweepReport {
	if len(targets) == 0 {
		return classifySweep(nil, tombs) // audit.Run would read the whole fleet
	}
	reader := sess.reader(cfg, offer)
	reader.ReadKeys2 = true
	sess.log.Info(fmt.Sprintf("sweeping %s for revoked keys (parallelism %d)…", apply.Plural(len(targets), "server", "servers"), sess.parallel))
	results := audit.Run(ctx, cfg, reader, audit.Options{Parallel: sess.parallel, PerServerTimeout: perServerTimeout, Servers: targets, Logger: sess.log})
	logSweepHints(sess.log, results)
	return classifySweep(results, tombs)
}

// logSweepHints logs each distinct remediation hint once: the sweep's report
// only names an unreachable server, so the fix (--offer-all-keys, a
// known_hosts entry) would otherwise reach nobody.
func logSweepHints(log *slog.Logger, results []audit.ServerResult) {
	seen := make(map[string]bool)
	for _, r := range results {
		hint := audit.CleanHint(r.Err)
		if hint == "" || seen[hint] {
			continue
		}
		seen[hint] = true
		log.Warn("hint: " + hint)
	}
}

// sweepUnparsed and sweepInterrupted are SweepUnprovable reasons.
const (
	sweepUnparsed    = "authorized_keys has unparseable lines"
	sweepInterrupted = "sweep interrupted"
)

// classifySweep keeps only this run's key tombstones found in
// authorized_keys (audit's Unauthorized keys) or in a non-empty
// authorized_keys2. A file that cannot be read or fully parsed cannot prove
// the removal (exit 1, never 0): sshd may read a line this parser refuses.
// A server the sweep never read because of a Ctrl-C is not unreachable and
// is not counted as checked.
func classifySweep(results []audit.ServerResult, tombs []config.Tombstone) apply.SweepReport {
	label := make(map[string]string, len(tombs))
	for _, t := range tombs {
		if t.IsKey() {
			label[t.Fingerprint] = t.User
		}
	}
	var rep apply.SweepReport
	for _, r := range results {
		if r.Server.JumpOnly {
			rep.JumpOnly = append(rep.JumpOnly, r.Server.Name) // audit.Run listed it without a read
			continue
		}
		if r.Err != nil && fleet.ErrorKindOf(r.Err) == fleet.ErrorKindCanceled {
			rep.Unprovable = append(rep.Unprovable, apply.SweepUnprovable{Server: r.Server.Name, Reason: sweepInterrupted})
			continue
		}
		rep.Checked++
		if r.Err != nil {
			rep.Unreachable = append(rep.Unreachable, r.Server.Name)
			continue
		}
		if len(r.ParseErrs) > 0 {
			rep.Unprovable = append(rep.Unprovable, apply.SweepUnprovable{Server: r.Server.Name, Reason: sweepUnparsed})
		}
		for _, k := range r.Diff.Unauthorized {
			if user, ok := label[k.Fingerprint]; ok {
				rep.StillInstalled = append(rep.StillInstalled, apply.SweepHit{Server: r.Server.Name, Fingerprint: k.Fingerprint, User: user, File: "authorized_keys"})
			}
		}
		rep = keys2Hits(rep, r, label)
	}
	return rep
}

// keys2Hits adds a server's authorized_keys2 findings.
func keys2Hits(rep apply.SweepReport, r audit.ServerResult, label map[string]string) apply.SweepReport {
	if !r.AuthorizedKeys2 {
		return rep
	}
	keys, perrs := authkeys.ParseFile(r.Keys2)
	if r.Keys2Err != nil || r.Keys2 == nil || len(perrs) > 0 {
		rep.Unprovable = append(rep.Unprovable, apply.SweepUnprovable{Server: r.Server.Name, Reason: "authorized_keys2 unreadable"})
		return rep
	}
	seen := map[string]bool{}
	for _, k := range keys {
		if user, ok := label[k.Fingerprint]; ok && !seen[k.Fingerprint] {
			seen[k.Fingerprint] = true
			rep.StillInstalled = append(rep.StillInstalled, apply.SweepHit{Server: r.Server.Name, Fingerprint: k.Fingerprint, User: user, File: "authorized_keys2"})
		}
	}
	return rep
}

// sweepGroup is one revoked key in one file, with the servers holding it:
// fixable by apply, or by hand (the manifest grants nothing there and apply
// never empties a server).
type sweepGroup struct {
	fp, user, file  string
	fixable, byHand []string
}

func groupHits(rep apply.SweepReport, cfg *config.Config) []*sweepGroup {
	var groups []*sweepGroup
	idx := map[string]*sweepGroup{}
	for _, hit := range rep.StillInstalled {
		key := hit.Fingerprint + "\x00" + hit.File
		g := idx[key]
		if g == nil {
			g = &sweepGroup{fp: hit.Fingerprint, user: hit.User, file: hit.File}
			idx[key] = g
			groups = append(groups, g)
		}
		if len(cfg.DesiredFor(hit.Server)) == 0 {
			g.byHand = append(g.byHand, hit.Server)
		} else {
			g.fixable = append(g.fixable, hit.Server)
		}
	}
	return groups
}

// renderSweep prints the sweep: one line per revoked key and file with its
// servers and the fix (the apply hint carries the run's flags), then the
// servers that could not prove the removal, then the tally.
func renderSweep(w io.Writer, rep apply.SweepReport, cfg *config.Config, h followUp, fleetSize int) {
	for _, g := range groupHits(rep, cfg) {
		head := "REVOKED KEY STILL INSTALLED"
		if g.file == "authorized_keys2" {
			head += " (authorized_keys2)"
		}
		who := strings.TrimSpace(g.user + " " + g.fp)
		if len(g.fixable) > 0 {
			fmt.Fprintf(w, "%s: %s on %s — run '%s'\n", head, who, strings.Join(g.fixable, ", "), applyHint(h, g.fixable))
		}
		if len(g.byHand) > 0 {
			fmt.Fprintf(w, "%s: %s on %s — remove it by hand or grant another user there first\n", head, who, strings.Join(g.byHand, ", "))
		}
	}
	for _, s := range rep.Unreachable {
		fmt.Fprintf(w, "cannot prove removal on %s (unreachable)\n", s)
	}
	for _, u := range rep.Unprovable {
		fmt.Fprintf(w, "cannot prove removal on %s (%s)\n", u.Server, u.Reason)
	}
	for _, s := range rep.JumpOnly {
		fmt.Fprintf(w, "not swept: %s (jump only)\n", s)
	}
	holding := map[string]bool{}
	for _, hit := range rep.StillInstalled {
		holding[hit.Server] = true
	}
	fmt.Fprintf(w, "swept %d of %s: %d still %s a revoked key, %d unreachable\n",
		rep.Checked, apply.Plural(fleetSize, "server", "servers"), len(holding), pluralWord(len(holding), "has", "have"), len(rep.Unreachable))
}
