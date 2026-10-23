package main

import (
	"slices"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/apply"
	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestApplyHint(t *testing.T) {
	for _, tt := range []struct {
		cfg     string
		servers []string
		want    string
	}{
		{"sshepherd.yaml", []string{"web-1"}, "sshepherd apply --server web-1"},
		{"/etc/fleet.yaml", []string{"web-1", "db-1"}, "sshepherd apply --config /etc/fleet.yaml --server web-1 --server db-1"},
		{"my fleet.yaml", []string{"web-1"}, "sshepherd apply --config 'my fleet.yaml' --server web-1"},
	} {
		if got := applyHint(tt.cfg, tt.servers); got != tt.want {
			t.Errorf("applyHint(%q, %v) = %q, want %q", tt.cfg, tt.servers, got, tt.want)
		}
	}
}

func TestNothingCanLand(t *testing.T) {
	p := func(c apply.Class) apply.ServerPlan { return apply.ServerPlan{Class: c} }
	for _, tt := range []struct {
		name  string
		plans []apply.ServerPlan
		want  bool
	}{
		{"all refused", []apply.ServerPlan{p(apply.ClassRefused), p(apply.ClassRefused)}, true},
		{"refused + unreachable", []apply.ServerPlan{p(apply.ClassRefused), p(apply.ClassUnreachable)}, true},
		{"all unreachable can converge later", []apply.ServerPlan{p(apply.ClassUnreachable)}, false},
		{"one change lands", []apply.ServerPlan{p(apply.ClassRefused), p(apply.ClassChange)}, false},
		{"one converged lands", []apply.ServerPlan{p(apply.ClassRefused), p(apply.ClassConverged)}, false},
	} {
		if got := nothingCanLand(tt.plans); got != tt.want {
			t.Errorf("%s: nothingCanLand = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestAnySurvivor(t *testing.T) {
	k1, err := authkeys.ParseLine(testkeys.Line(t, 1))
	if err != nil || k1 == nil {
		t.Fatal(err)
	}
	desired := []apply.ServerPlan{{Class: apply.ClassChange, Desired: []authkeys.Key{*k1}}}
	if anySurvivor(desired, nil) {
		t.Error("no held keys cannot survive")
	}
	if !anySurvivor(desired, []sshconn.HeldKey{{Fingerprint: fpOf(t, 1), Source: sshconn.SourceAgent}}) {
		t.Error("a held desired key survives")
	}
	if anySurvivor([]apply.ServerPlan{{Class: apply.ClassRefused, Desired: desired[0].Desired}},
		[]sshconn.HeldKey{{Fingerprint: fpOf(t, 1)}}) {
		t.Error("only change plans count")
	}
}

func TestOperatorGate(t *testing.T) {
	cfg, err := config.Parse([]byte("users:\n" +
		"  - {name: ops, operator: true, keys: [\"" + testkeys.Line(t, 1) + "\"]}\n" +
		"  - {name: ci, operator: true, keys: [\"" + testkeys.Line(t, 2) + "\"]}\n" +
		"  - {name: alice, keys: [\"" + testkeys.Line(t, 3) + "\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := operatorGate(cfg, []string{"alice", "ops", "ci"}, false); err == nil ||
		err.Error() != "ops, ci are operators (fleet-wide, protected); pass --operator to confirm" {
		t.Errorf("err = %v", err)
	}
	if _, err := operatorGate(cfg, []string{"alice"}, true); err == nil || !strings.Contains(err.Error(), "drop the flag") {
		t.Errorf("err = %v", err)
	}
	ops, err := operatorGate(cfg, []string{"ops", "alice", "ops"}, true)
	if err != nil || !slices.Equal(ops, []string{"ops"}) {
		t.Errorf("operatorGate = (%v, %v), want [ops]", ops, err)
	}
	if ops, err := operatorGate(cfg, []string{"alice"}, false); err != nil || len(ops) != 0 {
		t.Errorf("operatorGate = (%v, %v), want no operators", ops, err)
	}
}

func TestUnionFPs(t *testing.T) {
	if got := unionFPs([]string{"a", "b"}, []string{"b", "c"}); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("unionFPs = %v", got)
	}
}
