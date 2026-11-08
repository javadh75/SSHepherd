package apply

import (
	"fmt"
	"strings"
	"testing"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

func TestNeedsSerialBump(t *testing.T) {
	cfg := serialCfg(t) // M = 7
	removal := authkeys.Header(7) + "\n" + web1Body(t, cfg) + testkeys.Line(t, 9) + "\n"
	for _, tc := range []struct {
		name    string
		content string
		want    bool
	}{
		{"equal serial, a removal", removal, true},
		{"newer serial, removal-only: this manifest is stale", authkeys.Header(9) + "\n" + web1Body(t, cfg) + testkeys.Line(t, 9) + "\n", false},
		{"older serial, a removal (M > S)", authkeys.Header(6) + "\n" + web1Body(t, cfg) + testkeys.Line(t, 9) + "\n", false},
		{"forged counts as no serial", authkeys.Header(5000) + "\n" + web1Body(t, cfg) + testkeys.Line(t, 9) + "\n", false},
		{"no removal", authkeys.Header(7) + "\n" + testkeys.Line(t, 1) + " op\n", false},
	} {
		p := planWeb1(t, cfg, tc.content, false, false)
		if got := NeedsSerialBump([]ServerPlan{p}, cfg.Serial()); got != tc.want {
			t.Errorf("%s: NeedsSerialBump = %v, want %v (plan %+v)", tc.name, got, tc.want, p)
		}
	}
}

// TestNeedsSerialBumpStaleEvidence (PRD-2): a server in the run that a
// newer manifest wrote proves this copy is stale, so a removal elsewhere
// must not lift it past the serial that just refused it. A forged header
// is no evidence.
func TestNeedsSerialBumpStaleEvidence(t *testing.T) {
	cfg := serialCfg(t) // M = 7
	body := web1Body(t, cfg)
	stray := testkeys.Line(t, 9) + "\n"
	removal := planWeb1(t, cfg, authkeys.Header(7)+"\n"+body+stray, false, false)
	for _, tc := range []struct {
		name    string
		content string
		want    SerialCase
		bump    bool
	}{
		{"refused sibling", authkeys.Header(9) + "\n" + testkeys.Line(t, 1) + " op\n", SerialNewerRefused, false},
		{"newer converged sibling", authkeys.Header(9) + "\n" + body, SerialNewerConverged, false},
		{"newer removal-only sibling", authkeys.Header(9) + "\n" + body + stray, SerialNewerRemovalOnly, false},
		{"forged sibling is no evidence", authkeys.Header(5000) + "\n" + body, SerialForged, true},
		{"older sibling", authkeys.Header(6) + "\n" + body, SerialOlder, true},
	} {
		sibling := planWeb1(t, cfg, tc.content, false, false)
		if sibling.Serial.Case != tc.want {
			t.Fatalf("%s: case = %q, want %q", tc.name, sibling.Serial.Case, tc.want)
		}
		if got := NeedsSerialBump([]ServerPlan{removal, sibling}, cfg.Serial()); got != tc.bump {
			t.Errorf("%s: NeedsSerialBump = %v, want %v", tc.name, got, tc.bump)
		}
	}
}

func TestReserial(t *testing.T) {
	cfg := serialCfg(t)
	plain := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	higher := planWeb1(t, cfg, authkeys.Header(20)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	plans := []ServerPlan{plain, higher}
	if err := Reserial(plans, 8); err != nil {
		t.Fatal(err)
	}
	if want := authkeys.Header(8) + "\n" + web1Body(t, cfg); string(plans[0].Rendered) != want || plans[0].Serial.Writes != 8 {
		t.Errorf("plain = %q (writes %d)", plans[0].Rendered, plans[0].Serial.Writes)
	}
	if want := authkeys.Header(20) + "\n" + web1Body(t, cfg); string(plans[1].Rendered) != want {
		t.Errorf("a removal-only write keeps its higher S: %q", plans[1].Rendered)
	}
}

func TestReserialOversize(t *testing.T) {
	cfg := serialCfg(t)
	plain := planWeb1(t, cfg, authkeys.Header(7)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	higher := planWeb1(t, cfg, authkeys.Header(20)+"\n"+web1Body(t, cfg)+testkeys.Line(t, 9)+"\n", false, false)
	size := func(serial uint64) int { return len(authkeys.Header(serial)) + 1 + len(web1Body(t, cfg)) }
	saved := maxRender
	t.Cleanup(func() { maxRender = saved })

	t.Run("exactly at the limit passes", func(t *testing.T) {
		maxRender = size(100)
		if got := ReserialOversize([]ServerPlan{plain}, 100); got != nil {
			t.Errorf("got %q, want nil", got)
		}
	})
	t.Run("over the limit names the server and the numbers", func(t *testing.T) {
		maxRender = size(100) - 1
		got := ReserialOversize([]ServerPlan{plain}, 100)
		want := fmt.Sprintf("web-1: the serial bump to 100 would make the rendered file %d bytes, over the %d-byte limit the read path accepts — nothing saved or written (split the grant across accounts)", size(100), maxRender)
		if len(got) != 1 || got[0] != want {
			t.Errorf("got %q\nwant %q", got, want)
		}
	})
	t.Run("a removal-only write is measured at its higher serial", func(t *testing.T) {
		maxRender = size(20) - 1 // serial 8 would fit; the 20 it writes does not
		got := ReserialOversize([]ServerPlan{higher}, 8)
		if len(got) != 1 || !strings.Contains(got[0], "the serial bump to 20 ") {
			t.Errorf("got %q, want one message at max(to, Writes) = 20", got)
		}
	})
	t.Run("other classes are ignored", func(t *testing.T) {
		maxRender = 1
		refused := plain
		refused.Class = ClassRefused
		if got := ReserialOversize([]ServerPlan{refused}, 100); got != nil {
			t.Errorf("got %q, want nil", got)
		}
	})
	t.Run("a render with no header line is left to Reserial", func(t *testing.T) {
		maxRender = 1
		bad := plain
		bad.Rendered = []byte("no newline")
		if got := ReserialOversize([]ServerPlan{bad}, 100); got != nil {
			t.Errorf("got %q, want nil", got)
		}
	})
}
