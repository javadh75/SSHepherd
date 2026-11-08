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
		cfg, kh string
		servers []string
		want    string
	}{
		{"sshepherd.yaml", defaultKnownHosts, []string{"web-1"}, "sshepherd apply --server web-1"},
		{"/etc/fleet.yaml", defaultKnownHosts, []string{"web-1", "db-1"}, "sshepherd apply --config /etc/fleet.yaml --server web-1 --server db-1"},
		{"my fleet.yaml", defaultKnownHosts, []string{"web-1"}, "sshepherd apply --config \"my fleet.yaml\" --server web-1"},
		{"/etc/fleet.yaml", "/kh", []string{"web-1", "db-1"}, "sshepherd apply --config /etc/fleet.yaml --known-hosts /kh --server web-1 --server db-1"},
	} {
		cf := connFlags{cfgPath: tt.cfg, knownHosts: tt.kh}
		if got := applyHint(cf.followUp(), tt.servers); got != tt.want {
			t.Errorf("applyHint(%q, %q, %v) = %q, want %q", tt.cfg, tt.kh, tt.servers, got, tt.want)
		}
	}
}

// TestHintArg: hints are printed inside '…', so an argument that needs
// quoting gets double quotes whenever they are safe (nothing the shell
// expands inside them), which keeps the hint's own end unambiguous; only
// the rest falls back to POSIX single quotes.
func TestHintArg(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"/etc/fleet.yaml", "/etc/fleet.yaml"},
		{"my fleet.yaml", `"my fleet.yaml"`},
		{"~/.ssh/ci", `"~/.ssh/ci"`},
		{"don't.yaml", `"don't.yaml"`},
		{"$HOME/f.yaml", `'$HOME/f.yaml'`},
		{"a`b`", "'a`b`'"},
		{`a"b`, `'a"b'`},
		{`a\b`, `'a\b'`},
		{"wow!.yaml", "'wow!.yaml'"},
		{"a\tb", "'a\tb'"},
		{"it's $x", `'it'\''s $x'`},
	} {
		if got := hintArg(tt.in); got != tt.want {
			t.Errorf("hintArg(%q) = %s, want %s", tt.in, got, tt.want)
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

// TestOverlapHint pins every finish-hint row, the --config/--operator
// parts of CMD (quoted like applyHint), and the operator's second line.
func TestOverlapHint(t *testing.T) {
	bob := overlapFinish{user: "bob", oldFP: "SHA256:old+/="}
	ops := overlapFinish{user: "ops", oldFP: "SHA256:old", operator: true}
	const opLine = "if the old key is how this machine logs in, run the finish with --identity pointing at the new key's private key, or the lockout guard will refuse it\n"
	for _, tt := range []struct {
		name                   string
		o                      overlapFinish
		cfg, kh                string
		affected, notConverged int
		noApply                bool
		want                   string
	}{
		{"started", bob, "sshepherd.yaml", defaultKnownHosts, 3, 0, false,
			"overlap started — every affected server accepts both keys; once every client uses the new key, finish with: sshepherd revoke --key SHA256:old+/=\n"},
		{"incomplete, one", bob, "sshepherd.yaml", defaultKnownHosts, 3, 1, false,
			"overlap incomplete — 1 server does not have the new key yet; push it first (see the apply hint above), then finish with: sshepherd revoke --key SHA256:old+/=\n"},
		{"incomplete, many", bob, "/etc/fleet.yaml", defaultKnownHosts, 3, 2, false,
			"overlap incomplete — 2 servers do not have the new key yet; push it first (see the apply hint above), then finish with: sshepherd revoke --key SHA256:old+/= --config /etc/fleet.yaml\n"},
		{"not pushed", bob, "my fleet.yaml", defaultKnownHosts, 3, 0, true,
			"overlap recorded, not pushed — run the apply hint above, then, once every client uses the new key, finish with: sshepherd revoke --key SHA256:old+/= --config \"my fleet.yaml\"\n"},
		{"no grants", bob, "sshepherd.yaml", defaultKnownHosts, 0, 0, true,
			"new key recorded — bob has no grants yet, so no server was contacted; finish the overlap with: sshepherd revoke --key SHA256:old+/=\n"},
		{"operator", ops, "sshepherd.yaml", defaultKnownHosts, 2, 0, false,
			"overlap started — every affected server accepts both keys; once every client uses the new key, finish with: sshepherd revoke --key SHA256:old --operator\n" + opLine},
		{"operator, run flags", ops, "/etc/fleet.yaml", "/kh", 2, 0, false,
			"overlap started — every affected server accepts both keys; once every client uses the new key, finish with: sshepherd revoke --key SHA256:old --config /etc/fleet.yaml --known-hosts /kh --operator\n" + opLine},
	} {
		h := (&connFlags{cfgPath: tt.cfg, knownHosts: tt.kh}).followUp()
		if got := overlapHint(tt.o, h, tt.affected, tt.noApply, tt.notConverged); got != tt.want {
			t.Errorf("%s:\n got %q\nwant %q", tt.name, got, tt.want)
		}
	}
}
