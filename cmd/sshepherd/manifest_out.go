package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/javadh75/SSHepherd/internal/adopt"
	"github.com/javadh75/SSHepherd/internal/manifest"
)

// emitManifest sends a generated manifest to stdout, or to -o through
// publishManifest when out is set.
func emitManifest(stdout io.Writer, src manifestTarget, out string, data []byte, force bool) error {
	if out != "" {
		_, err := publishManifest(src, out, data, force)
		return err
	}
	if _, err := stdout.Write(data); err != nil {
		return fmt.Errorf("write stdout: %w", err)
	}
	return nil
}

// placeManifest is emitManifest under --json: stdout belongs to the
// document, so with no -o the bytes go into it (OP3). A JSON string holds
// only UTF-8 and the encoder would silently replace anything else, so a
// manifest in another encoding (a no-op merge returns a UTF-16 file's raw
// bytes) is refused here rather than emitted changed; -o still takes it.
func placeManifest(src manifestTarget, out string, data []byte, force bool) (adopt.Placement, error) {
	if out == "" {
		if !utf8.Valid(data) {
			return adopt.Placement{}, errors.New("the manifest is not UTF-8, so a JSON report cannot hold its bytes; pass -o FILE to write it to a file")
		}
		s := string(data)
		return adopt.Placement{Manifest: &s}, nil
	}
	written, err := publishManifest(src, out, data, force)
	if err != nil {
		return adopt.Placement{}, err
	}
	return adopt.Placement{Output: &adopt.Output{Path: out, Written: written}}, nil
}

// publishManifest writes a generated manifest to -o and reports whether the
// file changed. When out is the very file this run read (adopt's --config,
// adopt/import --merge; symlinks followed) it is an in-place update: --force
// is still required, identical bytes write nothing, and the write goes
// through Save — the manifest lock, the changed-since-read refusal, the
// file's own mode and owner — so it can never undo a concurrent revoke. Any
// other path is a new file (manifest.WriteFile: mode 0600, never clobbered
// without --force).
func publishManifest(src manifestTarget, out string, data []byte, force bool) (bool, error) {
	same, err := src.SameAs(out)
	if err != nil {
		return false, err //nolint:wrapcheck // SameAs names both paths
	}
	if !same {
		if err := manifest.WriteFile(out, data, force); err != nil {
			return false, err //nolint:wrapcheck // "write PATH: …" / "--force" hints are the user-facing text
		}
		return true, nil
	}
	if !force {
		return false, fmt.Errorf("%s is the manifest this run read; pass --force to update it in place", out)
	}
	if bytes.Equal(data, src.Loaded) {
		return false, nil
	}
	if err := src.Save(data); err != nil {
		return false, err
	}
	return true, nil
}
