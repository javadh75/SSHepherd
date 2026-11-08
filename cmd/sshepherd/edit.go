package main

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/manifest"
)

// runFlags are the flags apply, revoke and rotate share, registered with
// apply's defaults and help text (apply adds --server on top): the
// connection flags plus the run modes.
type runFlags struct {
	connFlags
	dryRun bool
	yes    bool
	json   bool
}

// register declares the shared flags on cmd.
func (f *runFlags) register(cmd *cobra.Command) {
	f.connFlags.register(cmd, "max concurrent server connections")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "plan and report only; never write")
	cmd.Flags().BoolVar(&f.yes, "yes", false, "skip the confirmation prompt (automation)")
	cmd.Flags().BoolVar(&f.json, "json", false,
		"emit the plan and outcome as machine-readable JSON on stdout (needs --dry-run or --yes)")
}

// errJSONNeedsMode: a script cannot answer the [y/N] prompt, so --json
// must say up front whether this run previews or writes.
var errJSONNeedsMode = usageError{errors.New("--json needs --dry-run or --yes (a script cannot answer the confirmation prompt)")}

// errDryRunYes: the two modes contradict each other; said in our own words
// rather than cobra's flag-group wording.
var errDryRunYes = usageError{errors.New("--dry-run and --yes cannot be combined: --dry-run previews without writing, --yes writes without asking")}

// checkModes: --dry-run and --yes exclude each other, and --json needs one
// of them (errJSONNeedsMode — even when nothing would change, so the rule
// is predictable). It runs with the other flag checks, before the manifest
// is read or anything is printed.
func (f *runFlags) checkModes() error {
	switch {
	case f.dryRun && f.yes:
		return errDryRunYes
	case f.json && !f.dryRun && !f.yes:
		return errJSONNeedsMode
	}
	return nil
}

// manifestTarget is the manifest as a run read it (manifest.Store: path,
// resolved file, exact bytes, stream flag) plus this package's test seam.
// apply, revoke, rotate, and adopt/import in-place output all save through it.
type manifestTarget struct{ manifest.Store }

// readManifest reads the manifest once through the store (see manifest.Read).
func readManifest(path string) (manifestTarget, error) {
	s, err := manifest.Read(path)
	if err != nil {
		return manifestTarget{}, err //nolint:wrapcheck // Store errors already read "read manifest: …"; a prefix would stutter
	}
	return manifestTarget{s}, nil
}

// beforeManifestSave is a test seam: it runs at the start of Save on a
// regular file, before the lock and the compare-and-swap.
var beforeManifestSave = func(manifestTarget) {}

// Save replaces the manifest with data through manifest.Store.Save: under
// the manifest lock, after the changed-since-read compare-and-swap, keeping
// the file's mode and owner.
func (m manifestTarget) Save(data []byte) error {
	if !m.Stream {
		beforeManifestSave(m)
	}
	return m.Store.Save(data) //nolint:wrapcheck // "save manifest PATH: …" / "changed since it was read" are the user-facing text
}

// errManifestLocked is returned when another run holds the manifest lock.
var errManifestLocked = manifest.ErrLocked
