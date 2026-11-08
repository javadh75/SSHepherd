package apply

import (
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
		{"newer serial, removal-only", authkeys.Header(9) + "\n" + web1Body(t, cfg) + testkeys.Line(t, 9) + "\n", true},
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
