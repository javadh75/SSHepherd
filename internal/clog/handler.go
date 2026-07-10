package clog

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

// Options configures a Handler.
type Options struct {
	Level   slog.Level // minimum record level to emit
	Color   bool       // apply ANSI color (decide via Enabled)
	Verbose bool       // debug format: timestamp + level word on every line
}

// Handler renders slog records as human-friendly CLI lines: calm prefixes at
// normal verbosity ("• ", "warn: ", "error: "), timestamped level-tagged
// lines in verbose mode. All rendered text passes through sanitize, and a
// shared mutex serializes writes so lines from concurrent server workers
// never interleave mid-line. Groups are unused in this CLI and pass through.
type Handler struct {
	mu    *sync.Mutex // pointer: WithAttrs children share the serialization
	w     io.Writer
	opts  Options
	attrs []slog.Attr
}

var _ slog.Handler = (*Handler)(nil)

// NewHandler returns a Handler writing rendered lines to w.
func NewHandler(w io.Writer, opts Options) *Handler {
	return &Handler{mu: &sync.Mutex{}, w: w, opts: opts}
}

// Enabled implements slog.Handler.
func (h *Handler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.opts.Level
}

// WithAttrs implements slog.Handler.
func (h *Handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	h2 := *h
	//nolint:gocritic // three-index slice deliberately caps capacity so sibling WithAttrs branches never share a backing array
	h2.attrs = append(h.attrs[:len(h.attrs):len(h.attrs)], attrs...)
	return &h2
}

// WithGroup implements slog.Handler; groups are unused and pass through.
func (h *Handler) WithGroup(string) slog.Handler { return h }

// ANSI SGR fragments used by the handler.
const (
	sgrReset  = "\x1b[0m"
	sgrDim    = "\x1b[2m"
	sgrRed    = "\x1b[31m"
	sgrYellow = "\x1b[33m"
	sgrBlue   = "\x1b[34m"
	sgrCyan   = "\x1b[36m"
)

// paint wraps s in an SGR sequence only when color is on, so degraded output
// is genuinely plain text rather than stripped text.
func (h *Handler) paint(sgr, s string) string {
	if !h.opts.Color {
		return s
	}
	return sgr + s + sgrReset
}

// Handle implements slog.Handler.
func (h *Handler) Handle(_ context.Context, r slog.Record) error {
	var b bytes.Buffer
	if h.opts.Verbose {
		b.WriteString(h.paint(sgrDim, r.Time.Format("15:04:05.000")))
		b.WriteByte(' ')
		b.WriteString(h.levelWord(r.Level))
		b.WriteByte(' ')
	} else {
		b.WriteString(h.prefix(r.Level))
	}
	b.WriteString(sanitize(r.Message))
	for _, a := range h.attrs {
		h.appendAttr(&b, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		h.appendAttr(&b, a)
		return true
	})
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	if _, err := h.w.Write(b.Bytes()); err != nil {
		return fmt.Errorf("write log line: %w", err)
	}
	return nil
}

// levelWord renders the fixed-width verbose-mode level tag; equal widths
// keep verbose lines visually columnar.
func (h *Handler) levelWord(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return h.paint(sgrRed, "ERROR")
	case l >= slog.LevelWarn:
		return h.paint(sgrYellow, "WARN ")
	case l >= slog.LevelInfo:
		return h.paint(sgrCyan, "INFO ")
	default:
		return h.paint(sgrBlue, "DEBUG")
	}
}

// prefix renders the calm normal-mode line prefix.
func (h *Handler) prefix(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return h.paint(sgrRed, "error:") + " "
	case l >= slog.LevelWarn:
		return h.paint(sgrYellow, "warn:") + " "
	case l >= slog.LevelInfo:
		return h.paint(sgrDim, "•") + " "
	default:
		return h.paint(sgrBlue, "debug:") + " "
	}
}

// appendAttr renders " key=value" with both halves sanitized; the key is
// dimmed so values stand out.
func (h *Handler) appendAttr(b *bytes.Buffer, a slog.Attr) {
	b.WriteByte(' ')
	b.WriteString(h.paint(sgrDim, sanitize(a.Key)+"="))
	b.WriteString(sanitize(a.Value.Resolve().String()))
}
