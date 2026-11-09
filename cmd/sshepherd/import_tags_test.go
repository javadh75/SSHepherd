package main

import (
	"bytes"
	"strings"
	"testing"
)

// TestImportSkipsTagSelectorAlias: an alias starting with @ cannot be a
// server name, so it is skipped with a warning; the sibling alias of the same
// Host line is kept and import exits 0.
func TestImportSkipsTagSelectorAlias(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host @web web1\n  HostName 10.0.0.1\n  User deploy\n")
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", path, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, errBuf.String())
	}
	if want := `host "@web": alias "@web" is reserved for tag selectors, skipped (not valid in a manifest)`; !strings.Contains(errBuf.String(), want) {
		t.Errorf("stderr = %q, want %q", errBuf.String(), want)
	}
	if !strings.Contains(out.String(), "name: web1") || strings.Contains(out.String(), "@web") {
		t.Errorf("manifest = %q, want web1 kept and @web left out", out.String())
	}
}

func TestImportJSONTagSelectorAliasKind(t *testing.T) {
	hermeticHome(t)
	path := writeSSHConfig(t, "Host @web\n  HostName 10.0.0.1\n  User deploy\nHost web1\n  HostName 10.0.0.2\n  User deploy\n")
	code, doc, stderr := importJSONCLI(t, path, "--servers-only")
	if code != 0 {
		t.Fatalf("exit = %d (stderr: %s)", code, stderr)
	}
	if len(doc.Warnings) != 1 || doc.Warnings[0].Kind != importWarnUnsafeHost || !strings.Contains(doc.Warnings[0].Message, "reserved for tag selectors") {
		t.Errorf("warnings = %+v", doc.Warnings)
	}
}
