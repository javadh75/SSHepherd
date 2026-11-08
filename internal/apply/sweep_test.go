package apply

import (
	"bytes"
	"testing"
)

func TestSweepReportExitCode(t *testing.T) {
	var none *SweepReport
	for _, tc := range []struct {
		r    *SweepReport
		want int
	}{
		{none, 0},
		{&SweepReport{Checked: 3}, 0},
		{&SweepReport{Unreachable: []string{"db-3"}}, 1},
		{&SweepReport{Unprovable: []SweepUnprovable{{Server: "db-2", Reason: "authorized_keys2 unreadable"}}}, 1},
		{&SweepReport{Unreachable: []string{"db-3"}, StillInstalled: []SweepHit{{Server: "db-2"}}}, 2},
	} {
		if got := tc.r.ExitCode(); got != tc.want {
			t.Errorf("%+v: ExitCode = %d, want %d", tc.r, got, tc.want)
		}
	}
}

func TestRenderJSONSweepGolden(t *testing.T) {
	cfg := planCfg(t)
	rep := &SweepReport{Checked: 2,
		StillInstalled: []SweepHit{{Server: "db-2", Fingerprint: fp(t, 3), User: "bob", File: "authorized_keys2"}},
		Unreachable:    []string{"db-3"},
	}
	got := renderJSONCfg(t, cfg, nil, JSONOptions{Command: "revoke", Edit: &EditSummary{}, Saved: true, Sweep: rep})
	checkGolden(t, "json_sweep.golden.json", got)
	for _, want := range []string{`"sweep": {`, `"still_installed": [`, `"file": "authorized_keys2"`, `"unprovable": []`, `"exit_code": 2`} {
		if !bytes.Contains(got, []byte(want)) {
			t.Errorf("document lacks %s", want)
		}
	}
	if bytes.Contains(renderJSONCfg(t, cfg, nil, JSONOptions{Command: "revoke", Edit: &EditSummary{}}), []byte(`"sweep"`)) {
		t.Error("a run without a sweep has no sweep object")
	}
}
