package main

import (
	"bytes"
	"fmt"
	"io"

	"github.com/javadh75/SSHepherd/internal/manifest"
)

// emitManifest sends a generated manifest to stdout, or to -o through
// publishManifest when out is set.
func emitManifest(stdout io.Writer, src manifestTarget, out string, data []byte, force bool) error {
	if out != "" {
		return publishManifest(src, out, data, force)
	}
	if _, err := stdout.Write(data); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}

// publishManifest writes a generated manifest to -o. When out is the very
// file this run read (adopt's --config, adopt/import --merge; symlinks
// followed) it is an in-place update: --force is still required, identical
// bytes write nothing, and the write goes through Save — the manifest lock,
// the changed-since-read refusal, the file's own mode and owner — so it can
// never undo a concurrent revoke. Any other path is a new file
// (manifest.WriteFile: mode 0600, never clobbered without --force).
func publishManifest(src manifestTarget, out string, data []byte, force bool) error {
	same, err := src.SameAs(out)
	if err != nil {
		return err //nolint:wrapcheck // SameAs names both paths
	}
	if !same {
		return manifest.WriteFile(out, data, force) //nolint:wrapcheck // "write PATH: …" / "--force" hints are the user-facing text
	}
	if !force {
		return fmt.Errorf("%s is the manifest this run read; pass --force to update it in place", out)
	}
	if bytes.Equal(data, src.Loaded) {
		return nil
	}
	return src.Save(data)
}
