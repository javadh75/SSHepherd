package authkeys

import (
	"cmp"
	"slices"
)

// OfferRank groups a granted key line for the connection layers, read from
// the option table only: 0 lets any command run; 1 may reject the
// login or narrow the session (from=, expiry-time=, restrict); 2 forces a
// command (authenticating with it runs that command instead of sshepherd's
// script); 3 never accepts the bare key (cert-authority, principals=).
func OfferRank(options []string) int {
	if CertOnly(options) {
		return 3
	}
	if _, forced := FindOption(options, "command"); forced {
		return 2
	}
	if BlocksLogin(options) {
		return 1
	}
	return 0
}

// OfferOrder is the one order in which every connection offers a server's
// granted keys — audit and adopt reads, apply's read and write, and the
// post-write probe: desired (DesiredFor order: operators, then grant order)
// stably partitioned by OfferRank, so a forced-command line is never the
// first key a session authenticates with while a plain one is held.
func OfferOrder(desired []Key) []string {
	keys := slices.Clone(desired)
	slices.SortStableFunc(keys, func(a, b Key) int {
		return cmp.Compare(OfferRank(a.Options), OfferRank(b.Options))
	})
	fps := make([]string, 0, len(keys))
	for _, k := range keys {
		fps = append(fps, k.Fingerprint)
	}
	return fps
}
