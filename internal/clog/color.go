// Package clog renders sshepherd's leveled, color-aware CLI logging: a
// slog.Handler that writes human-friendly lines (calm at normal verbosity,
// timestamped at debug) plus the per-stream color decision honoring
// --color, TTY detection, NO_COLOR (https://no-color.org), and TERM=dumb.
package clog

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ColorMode is the user's --color choice.
type ColorMode int

// The three --color values: auto detects a terminal; always and never
// override detection in both directions.
const (
	ColorAuto ColorMode = iota
	ColorAlways
	ColorNever
)

// ParseColorMode maps a --color flag value to a ColorMode.
func ParseColorMode(s string) (ColorMode, error) {
	switch s {
	case "auto":
		return ColorAuto, nil
	case "always":
		return ColorAlways, nil
	case "never":
		return ColorNever, nil
	default:
		return ColorAuto, fmt.Errorf("invalid color mode %q (want auto, always, or never)", s)
	}
}

// Enabled decides whether w should receive ANSI color. The decision is made
// per stream: stderr logs and the stdout report can differ (one piped, one a
// terminal). Non-file writers (test buffers) are never terminals.
func Enabled(w io.Writer, mode ColorMode) bool {
	isTTY := false
	if f, ok := w.(*os.File); ok {
		isTTY = term.IsTerminal(int(f.Fd()))
	}
	return enabled(mode, isTTY, os.Getenv("NO_COLOR"), os.Getenv("TERM"))
}

// enabled is the pure decision: explicit modes win; auto needs a real TTY,
// an unset/empty NO_COLOR, and a TERM that is not "dumb".
func enabled(mode ColorMode, isTTY bool, noColor, termEnv string) bool {
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	}
	return isTTY && noColor == "" && termEnv != "dumb"
}
