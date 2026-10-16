package naming

import "testing"

func TestClaim(t *testing.T) {
	tests := []struct {
		name        string
		taken       []string
		want        string
		got         string
		wantRenamed bool
	}{
		{name: "free", want: "x", got: "x"},
		{name: "collision suffixes -2", taken: []string{"x"}, want: "x", got: "x-2", wantRenamed: true},
		{name: "skips taken suffixes", taken: []string{"x", "x-2"}, want: "x", got: "x-3", wantRenamed: true},
		{name: "continues numbering", taken: []string{"x", "x-2"}, want: "x-2", got: "x-3", wantRenamed: true},
		{name: "-1 is a name, not numbering", taken: []string{"web-1"}, want: "web-1", got: "web-1-2", wantRenamed: true},
		{name: "non-numeric tail", taken: []string{"a-b"}, want: "a-b", got: "a-b-2", wantRenamed: true},
		{name: "leading dash is not a stem", taken: []string{"-5"}, want: "-5", got: "-5-2", wantRenamed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			taken := map[string]bool{}
			for _, n := range tt.taken {
				taken[n] = true
			}
			got, renamed := Claim(taken, tt.want)
			if got != tt.got || renamed != tt.wantRenamed {
				t.Errorf("Claim(%v, %q) = %q, %v; want %q, %v", tt.taken, tt.want, got, renamed, tt.got, tt.wantRenamed)
			}
			if !taken[got] {
				t.Errorf("Claim did not reserve %q", got)
			}
		})
	}
}

func TestClaimNumbered(t *testing.T) {
	tests := []struct {
		name  string
		taken []string
		want  []string // successive claims
	}{
		{name: "fresh namespace starts at 1", want: []string{"k-1", "k-2"}},
		{name: "continues after an earlier run", taken: []string{"k-1"}, want: []string{"k-2", "k-3"}},
		{name: "fills gaps first", taken: []string{"k-1", "k-3"}, want: []string{"k-2", "k-4"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			taken := map[string]bool{}
			for _, n := range tt.taken {
				taken[n] = true
			}
			for i, w := range tt.want {
				if got := ClaimNumbered(taken, "k-"); got != w {
					t.Errorf("claim %d = %q, want %q", i+1, got, w)
				}
			}
		})
	}
}
