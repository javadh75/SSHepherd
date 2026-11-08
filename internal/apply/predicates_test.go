package apply

import (
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestNothingCanLand(t *testing.T) {
	p := func(c Class) ServerPlan { return ServerPlan{Class: c} }
	for _, tt := range []struct {
		name  string
		plans []ServerPlan
		want  bool
	}{
		{"all refused", []ServerPlan{p(ClassRefused), p(ClassRefused)}, true},
		{"refused + unreachable", []ServerPlan{p(ClassRefused), p(ClassUnreachable)}, true},
		{"all unreachable can converge later", []ServerPlan{p(ClassUnreachable)}, false},
		{"one change lands", []ServerPlan{p(ClassRefused), p(ClassChange)}, false},
		{"one converged lands", []ServerPlan{p(ClassRefused), p(ClassConverged)}, false},
	} {
		if got := NothingCanLand(tt.plans); got != tt.want {
			t.Errorf("%s: NothingCanLand = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestAnySurvivor(t *testing.T) {
	k1, err := authkeys.ParseLine(testkeys.Line(t, 1))
	if err != nil || k1 == nil {
		t.Fatal(err)
	}
	desired := []ServerPlan{{Class: ClassChange, Desired: []authkeys.Key{*k1}}}
	if AnySurvivor(desired, nil) {
		t.Error("no held keys cannot survive")
	}
	if !AnySurvivor(desired, []fleet.HeldKey{{Fingerprint: fp(t, 1), Source: fleet.SourceAgent}}) {
		t.Error("a held desired key survives")
	}
	if AnySurvivor([]ServerPlan{{Class: ClassRefused, Desired: desired[0].Desired}},
		[]fleet.HeldKey{{Fingerprint: fp(t, 1)}}) {
		t.Error("only change plans count")
	}
}

func TestAnyConverged(t *testing.T) {
	for _, tt := range []struct {
		name  string
		plans []ServerPlan
		want  bool
	}{
		{"none", nil, false},
		{"change and refused", []ServerPlan{{Class: ClassChange}, {Class: ClassRefused}}, false},
		{"one converged", []ServerPlan{{Class: ClassChange}, {Class: ClassConverged}}, true},
	} {
		if got := AnyConverged(tt.plans); got != tt.want {
			t.Errorf("%s: AnyConverged = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestCountChanges(t *testing.T) {
	plans := []ServerPlan{{Class: ClassChange}, {Class: ClassConverged}, {Class: ClassChange}, {Class: ClassRefused}}
	if got := CountChanges(plans); got != 2 {
		t.Errorf("CountChanges = %d, want 2", got)
	}
	if got := CountChanges(nil); got != 0 {
		t.Errorf("CountChanges(nil) = %d, want 0", got)
	}
}
