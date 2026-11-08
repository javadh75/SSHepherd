package apply

// SweepReport is the opt-in post-revoke sweep (spec 2026-11-08 §7):
// read-only, over every manifest server the run did not just write or find
// converged, looking for this run's revoked keys. The json tags are the
// wire shape of the document's sweep object.
type SweepReport struct {
	Checked        int               `json:"checked"`
	StillInstalled []SweepHit        `json:"still_installed"`
	Unreachable    []string          `json:"unreachable"`
	Unprovable     []SweepUnprovable `json:"unprovable"`
}

// SweepHit is a revoked key still installed on Server, in File
// ("authorized_keys" or "authorized_keys2"); User is the tombstone's label.
type SweepHit struct {
	Server      string `json:"server"`
	Fingerprint string `json:"fingerprint"`
	User        string `json:"user,omitempty"`
	File        string `json:"file"`
}

// SweepUnprovable is a server read whose removal the sweep cannot prove.
type SweepUnprovable struct {
	Server string `json:"server"`
	Reason string `json:"reason"`
}

// ExitCode is the sweep's share of the run's exit (spec §8): 2 when a
// revoked key is still installed, 1 when a server could not be read or
// could not prove the removal, else 0 (also for a nil report: no sweep).
func (r *SweepReport) ExitCode() int {
	switch {
	case r == nil:
		return 0
	case len(r.StillInstalled) > 0:
		return 2
	case len(r.Unreachable)+len(r.Unprovable) > 0:
		return 1
	}
	return 0
}

// wire returns r with every list non-nil, so each encodes as [].
func (r *SweepReport) wire() *SweepReport {
	if r == nil {
		return nil
	}
	w := *r
	if w.StillInstalled == nil {
		w.StillInstalled = []SweepHit{}
	}
	if w.Unreachable == nil {
		w.Unreachable = []string{}
	}
	if w.Unprovable == nil {
		w.Unprovable = []SweepUnprovable{}
	}
	return &w
}
