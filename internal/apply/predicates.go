package apply

import (
	"slices"

	"github.com/javadh75/SSHepherd/internal/fleet"
)

// The predicates below answer the write workflow's questions over a plan
// set, next to ExitCode and Interrupted.

// CountChanges tallies the servers phase 2 would write.
func CountChanges(plans []ServerPlan) int {
	n := 0
	for _, p := range plans {
		if p.Class == ClassChange {
			n++
		}
	}
	return n
}

// NothingCanLand reports that no affected server is change-planned or
// converged, and at least one is refused for a reason other than a weak-key
// conflict. Unreachable servers can converge later, and a weak-key refusal
// must not withhold the save that remediates it (OP4).
func NothingCanLand(plans []ServerPlan) bool {
	refused := false
	for _, p := range plans {
		switch p.Class {
		case ClassChange, ClassConverged:
			return false
		case ClassRefused:
			refused = refused || !p.WeakRefused
		}
	}
	return refused
}

// AnySurvivor reports that some change-planned server keeps a key held
// under the post-prompt listing (fresh).
func AnySurvivor(plans []ServerPlan, fresh []fleet.HeldKey) bool {
	held := heldSet(fresh)
	for _, p := range plans {
		if p.Class == ClassChange && len(Survivors(p.Desired, held)) > 0 {
			return true
		}
	}
	return false
}

// AnyConverged reports that some server already holds exactly its desired file.
func AnyConverged(plans []ServerPlan) bool {
	return slices.ContainsFunc(plans, func(p ServerPlan) bool { return p.Class == ClassConverged })
}
