// Package naming allocates collision-free manifest user names. import,
// import --merge and adopt all generate user names into a namespace that may
// already hold earlier runs' output; sharing one allocator keeps their
// suffixing identical, so a re-run continues the existing numbering instead
// of stacking suffixes.
package naming

import (
	"strconv"
	"strings"
)

// Claim reserves want in taken, suffixing -2, -3, … on collision, and
// reports whether a suffix was needed. The suffix continues any existing
// -<n> numbering (n >= 2) instead of stacking: with x and x-2 taken, a
// second claim of x-2 yields x-3, not x-2-2. A trailing -1 is not treated
// as numbering (x-1 is usually a real name, e.g. web-1), so it suffixes to
// x-1-2.
func Claim(taken map[string]bool, want string) (string, bool) {
	if !taken[want] {
		taken[want] = true
		return want, false
	}
	stem, n := want, 2
	if i := strings.LastIndex(want, "-"); i > 0 {
		if v, err := strconv.Atoi(want[i+1:]); err == nil && v >= 2 {
			stem, n = want[:i], v+1
		}
	}
	for ; ; n++ {
		cand := stem + "-" + strconv.Itoa(n)
		if !taken[cand] {
			taken[cand] = true
			return cand, true
		}
	}
}

// ClaimNumbered reserves the first free <prefix><n> for n = 1, 2, …: names
// that carry no other identity (e.g. adopted-key-<n>) continue numbering
// across runs instead of restarting at 1 and colliding into suffixes.
func ClaimNumbered(taken map[string]bool, prefix string) string {
	for n := 1; ; n++ {
		cand := prefix + strconv.Itoa(n)
		if !taken[cand] {
			taken[cand] = true
			return cand
		}
	}
}
