package apply

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
)

// TestOfferRankAgreesWithGuard: every option P05's table classifies is read
// the same way by the offer order and by the lockout guard's warning.
func TestOfferRankAgreesWithGuard(t *testing.T) {
	for _, tt := range []struct {
		opts        []string
		rank        int
		restrictive bool
	}{
		{nil, 0, false},
		{[]string{"no-pty"}, 0, false},
		{[]string{`from="10.0.0.0/8"`}, 1, true},
		{[]string{`expiry-time="20990101"`}, 1, true},
		{[]string{"restrict"}, 1, true},
		{[]string{`command="/bin/true"`}, 2, true},
		{[]string{"restrict", `command="/bin/true"`}, 2, true},
		{[]string{"cert-authority"}, 3, false},
		{[]string{`principals="a"`}, 3, false},
	} {
		if got := authkeys.OfferRank(tt.opts); got != tt.rank {
			t.Errorf("OfferRank(%q) = %d, want %d", tt.opts, got, tt.rank)
		}
		if got := hasRestrictiveOption(tt.opts); got != tt.restrictive {
			t.Errorf("hasRestrictiveOption(%q) = %v, want %v", tt.opts, got, tt.restrictive)
		}
		if tt.rank == 2 && !tt.restrictive {
			t.Errorf("%q: a forced command must count as restrictive for the guard", tt.opts)
		}
	}
}
