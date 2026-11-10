package audit

import (
	"slices"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
)

// External is one line a preserve: rule keeps (spec 2026-11-08 S6): the
// line, with the comment lines directly above it, and the kind of rule it
// matched (config.PreserveCommand or config.PreserveComment).
type External struct {
	Line authkeys.ScannedLine
	Rule string
}

// externalLines returns the lines of scanned that a preserve: rule of server
// keeps, in file order. A fingerprint is kept only when every line holding
// it matches a rule: an unrestricted copy beside a restricted one would
// otherwise be kept (see ServerResult.Duplicates). An owned, revoked or
// cert-only key never is: the manifest and revocation memory win, and a
// cert-authority line would admit every certificate its CA signs.
func externalLines(cfg *config.Config, server string, scanned []authkeys.ScannedLine) []External {
	rules := make([]string, len(scanned))
	refused := make(map[string]bool)
	for i, l := range scanned {
		rules[i] = cfg.PreserveRuleFor(server, l.Key)
		if rules[i] == "" || neverKept(cfg, l.Key) {
			refused[l.Key.Fingerprint] = true
		}
	}
	var out []External
	for i, l := range scanned {
		if !refused[l.Key.Fingerprint] {
			out = append(out, External{Line: l, Rule: rules[i]})
		}
	}
	return out
}

// neverKept: a key the manifest owns, one a key tombstone names, or a line
// that accepts only certificates (spec S6 "Lines that are never preserved").
func neverKept(cfg *config.Config, k authkeys.Key) bool {
	_, owned := cfg.OwnerOf(k.Fingerprint)
	_, revoked := cfg.Revoked(k.Fingerprint)
	return owned || revoked || authkeys.CertOnly(k.Options)
}

// withoutExternal drops the kept fingerprints from the unauthorized keys and
// the duplicate findings: a kept line is neither drift nor apply's to
// remove.
func withoutExternal(unauthorized []authkeys.Key, dups []Duplicate, ext []External) ([]authkeys.Key, []Duplicate) {
	if len(ext) == 0 {
		return unauthorized, dups
	}
	kept := make(map[string]bool, len(ext))
	for _, e := range ext {
		kept[e.Line.Key.Fingerprint] = true
	}
	unauthorized = slices.DeleteFunc(unauthorized, func(k authkeys.Key) bool { return kept[k.Fingerprint] })
	dups = slices.DeleteFunc(dups, func(d Duplicate) bool { return kept[d.Key.Fingerprint] })
	return unauthorized, dups
}

// IsExternal reports whether a preserve: rule keeps fp on this server.
func (r ServerResult) IsExternal(fp string) bool {
	return slices.ContainsFunc(r.External, func(e External) bool { return e.Line.Key.Fingerprint == fp })
}
