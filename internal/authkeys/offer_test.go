package authkeys

import (
	"slices"
	"testing"
)

func TestOfferRank(t *testing.T) {
	for _, tt := range []struct {
		opts []string
		want int
	}{
		{nil, 0},
		{[]string{"no-pty"}, 0},
		{[]string{`from="10.0.0.0/8"`}, 1},
		{[]string{`expiry-time="20990101"`}, 1},
		{[]string{"restrict"}, 1},
		{[]string{`command="/bin/true"`}, 2},
		{[]string{"restrict", `command="/bin/true"`}, 2},
		{[]string{"cert-authority"}, 3},
		{[]string{`principals="a"`}, 3},
	} {
		if got := OfferRank(tt.opts); got != tt.want {
			t.Errorf("OfferRank(%q) = %d, want %d", tt.opts, got, tt.want)
		}
	}
}

// TestOfferOrder: a stable partition by OfferRank — plain keys first in
// their given order, then from=/restrict, then command=, then cert-only —
// and the input slice is left untouched.
func TestOfferOrder(t *testing.T) {
	k := func(fp string, opts ...string) Key { return Key{Fingerprint: fp, Options: opts} }
	in := []Key{
		k("forced", `command="/bin/true"`),
		k("ca", "cert-authority"),
		k("plainB"),
		k("from", `from="10.0.0.1"`),
		k("plainA", "no-pty"),
	}
	before := slices.Clone(in)
	want := []string{"plainB", "plainA", "from", "forced", "ca"}
	if got := OfferOrder(in); !slices.Equal(got, want) {
		t.Errorf("OfferOrder = %v, want %v", got, want)
	}
	for i := range in {
		if in[i].Fingerprint != before[i].Fingerprint {
			t.Fatalf("OfferOrder reordered its input: %v", in)
		}
	}
	if got := OfferOrder(nil); len(got) != 0 {
		t.Errorf("OfferOrder(nil) = %v, want empty", got)
	}
}
