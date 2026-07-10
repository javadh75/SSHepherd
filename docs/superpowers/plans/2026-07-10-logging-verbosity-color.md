# Leveled Color-Aware Logging (quiet/normal/debug) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Three verbosity modes (`-q` quiet / normal / `-v` debug) with colored, gracefully-degrading logs on stderr and a colorized audit report on stdout.

**Architecture:** New package `internal/clog` provides a custom `slog.Handler` (human-friendly lines, ANSI color, injection-sanitized, mutex-serialized) and the per-stream color decision (`--color auto|always|never` × TTY × `NO_COLOR` × `TERM=dumb`). The root command builds a `*slog.Logger` in `PersistentPreRunE` and stores it in an `app` struct threaded to subcommands; `internal/sshread` and `internal/audit` accept an optional `*slog.Logger` for per-server DEBUG/WARN. `audit.Render` gains `RenderOptions{Color}` with equal-byte-length SGR codes so `text/tabwriter` alignment survives coloring.

**Tech Stack:** Go 1.26, stdlib `log/slog`, `golang.org/x/term` (new dep, first-party), Cobra persistent flags, native fuzzing, golden files.

**Spec:** `docs/superpowers/specs/2026-07-10-logging-verbosity-color-design.md`

**Conventions that apply to every task** (from CLAUDE.md / repo):
- TDD: write the failing test, see it fail, implement, see it pass, commit to `master` (solo trunk-based — no branches).
- Import grouping (goimports, local prefix `github.com/javadh75/SSHepherd`): stdlib / blank / third-party / blank / local.
- Exported identifiers need doc comments (revive). Errors crossing package boundaries get wrapped (`wrapcheck`).
- Run `gofmt -l .` before each commit; the pre-commit hook enforces it.

---

### Task 1: `internal/clog` — color decision (`ColorMode`, `ParseColorMode`, `Enabled`)

**Files:**
- Create: `internal/clog/color.go`
- Create: `internal/clog/color_test.go`
- Create: `internal/clog/leak_test.go`
- Modify: `go.mod` / `go.sum` (add `golang.org/x/term`)

- [ ] **Step 1: Add the `golang.org/x/term` dependency**

```bash
cd /Users/javad/w/personal/SSHepherd
go get golang.org/x/term
go mod tidy
```

Expected: `go.mod` gains `golang.org/x/term` in the require block (`x/sys` is already there, indirect via `x/crypto`).

- [ ] **Step 2: Write the failing tests**

Create `internal/clog/leak_test.go`:

```go
package clog

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
```

Create `internal/clog/color_test.go`:

```go
package clog

import (
	"bytes"
	"os"
	"testing"
)

func TestParseColorMode(t *testing.T) {
	tests := []struct {
		in      string
		want    ColorMode
		wantErr bool
	}{
		{in: "auto", want: ColorAuto},
		{in: "always", want: ColorAlways},
		{in: "never", want: ColorNever},
		{in: "sometimes", wantErr: true},
		{in: "", wantErr: true},
		{in: "AUTO", wantErr: true}, // exact match only, like most CLIs
	}
	for _, tt := range tests {
		got, err := ParseColorMode(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseColorMode(%q): want error, got %v", tt.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseColorMode(%q): unexpected error %v", tt.in, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseColorMode(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// TestEnabledDecision exercises the pure decision table: explicit modes win;
// auto requires TTY + no NO_COLOR + TERM != dumb.
func TestEnabledDecision(t *testing.T) {
	tests := []struct {
		name    string
		mode    ColorMode
		isTTY   bool
		noColor string
		termEnv string
		want    bool
	}{
		{name: "always wins without tty", mode: ColorAlways, isTTY: false, want: true},
		{name: "always wins over NO_COLOR", mode: ColorAlways, isTTY: true, noColor: "1", want: true},
		{name: "never wins on tty", mode: ColorNever, isTTY: true, want: false},
		{name: "auto tty clean env", mode: ColorAuto, isTTY: true, termEnv: "xterm-256color", want: true},
		{name: "auto no tty", mode: ColorAuto, isTTY: false, termEnv: "xterm", want: false},
		{name: "auto NO_COLOR set", mode: ColorAuto, isTTY: true, noColor: "1", termEnv: "xterm", want: false},
		{name: "auto NO_COLOR empty is unset", mode: ColorAuto, isTTY: true, noColor: "", termEnv: "xterm", want: true},
		{name: "auto TERM dumb", mode: ColorAuto, isTTY: true, termEnv: "dumb", want: false},
	}
	for _, tt := range tests {
		if got := enabled(tt.mode, tt.isTTY, tt.noColor, tt.termEnv); got != tt.want {
			t.Errorf("%s: enabled(%v, %v, %q, %q) = %v, want %v",
				tt.name, tt.mode, tt.isTTY, tt.noColor, tt.termEnv, got, tt.want)
		}
	}
}

// TestEnabledWriterKinds pins the io.Writer plumbing: buffers and pipes are
// never TTYs, so auto degrades to plain; always still overrides.
func TestEnabledWriterKinds(t *testing.T) {
	var buf bytes.Buffer
	if Enabled(&buf, ColorAuto) {
		t.Error("Enabled(buffer, auto) = true, want false (not a file)")
	}
	if !Enabled(&buf, ColorAlways) {
		t.Error("Enabled(buffer, always) = false, want true (explicit override)")
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer func() { _ = r.Close(); _ = w.Close() }()
	if Enabled(w, ColorAuto) {
		t.Error("Enabled(pipe, auto) = true, want false (file but not a terminal)")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/clog/ -v 2>&1 | head -20`
Expected: compile FAIL — `undefined: ColorMode`, `undefined: ParseColorMode`, etc.

- [ ] **Step 4: Write the implementation**

Create `internal/clog/color.go`:

```go
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/clog/ -v`
Expected: PASS (all three tests).

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/clog/
git commit -m "feat(clog): color-mode parsing and per-stream color detection"
```

---

### Task 2: `internal/clog` — log-injection sanitizer + fuzz

**Files:**
- Create: `internal/clog/sanitize.go`
- Create: `internal/clog/sanitize_test.go`
- Create: `internal/clog/fuzz_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/clog/sanitize_test.go`:

```go
package clog

import "testing"

func TestSanitize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "plain passes through", in: "dial web-1 ok", want: "dial web-1 ok"},
		{name: "newline becomes space", in: "line1\nline2", want: "line1 line2"},
		{name: "tab becomes space", in: "a\tb", want: "a b"},
		{name: "CR stripped", in: "a\rb", want: "ab"},
		{name: "ESC stripped", in: "evil\x1b[31mred", want: "evil[31mred"},
		{name: "C1 CSI stripped", in: "evil\u009b31mred", want: "evil31mred"},
		{name: "DEL stripped", in: "a\x7fb", want: "ab"},
		{name: "NUL stripped", in: "a\x00b", want: "ab"},
		{name: "raw C1 byte becomes replacement rune", in: "a\x9bb", want: "a\ufffdb"},
		{name: "unicode preserved", in: "clé ✓ 键", want: "clé ✓ 键"},
		{name: "multi-line hint collapses", in: "bad key\n  hint: run ssh-keyscan", want: "bad key   hint: run ssh-keyscan"},
	}
	for _, tt := range tests {
		if got := sanitize(tt.in); got != tt.want {
			t.Errorf("%s: sanitize(%q) = %q, want %q", tt.name, tt.in, got, tt.want)
		}
	}
}
```

Create `internal/clog/fuzz_test.go`:

```go
package clog

import (
	"testing"
	"unicode"
	"unicode/utf8"
)

// FuzzSanitize pins the security property: no control rune ever survives
// sanitization (terminal-escape / log-forging injection), and the function
// is idempotent.
func FuzzSanitize(f *testing.F) {
	f.Add("plain text")
	f.Add("evil\x1b[31mred")
	f.Add("line1\nline2\tend")
	f.Add("\u009b31m csi")
	f.Add("a\x00\x7f\rb")
	f.Add("evil\x9b31mred")
	f.Fuzz(func(t *testing.T, s string) {
		out := sanitize(s)
		for _, r := range out {
			if unicode.IsControl(r) {
				t.Fatalf("control rune %U survived: %q -> %q", r, s, out)
			}
		}
		if !utf8.ValidString(out) {
			t.Fatalf("invalid UTF-8 survived: %q -> %q", s, out)
		}
		if again := sanitize(out); again != out {
			t.Fatalf("not idempotent: %q -> %q -> %q", s, out, again)
		}
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/clog/ -run TestSanitize -v 2>&1 | head -5`
Expected: compile FAIL — `undefined: sanitize`.

- [ ] **Step 3: Write the implementation**

Create `internal/clog/sanitize.go`:

```go
package clog

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// sanitize strips control characters from operator-facing log text so
// hostile input (server names, remote-supplied error text) cannot forge log
// lines or inject terminal escape sequences. Each newline or tab becomes a
// single space; every other control rune is dropped — unicode.IsControl
// covers C0, DEL, and C1, whose CSI (U+009B) acts like ESC [ in some
// terminals. Defense-in-depth behind sshread's sanitizeRemote: it also
// protects future log call sites that forget to sanitize. Invalid UTF-8
// never takes the fast path: strings.Map rewrites each invalid byte to
// U+FFFD, so a raw 0x9B (8-bit CSI on non-UTF-8 terminals) cannot pass
// through verbatim.
func sanitize(s string) string {
	if utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl) {
		return s // fast path: log lines are almost always already clean
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return ' '
		case unicode.IsControl(r):
			return -1
		default:
			return r
		}
	}, s)
}
```

- [ ] **Step 4: Run tests + a short fuzz to verify**

Run: `go test ./internal/clog/ -run 'TestSanitize|FuzzSanitize' -v`
Expected: PASS.
Run: `go test -run='^$' -fuzz=FuzzSanitize -fuzztime=10s ./internal/clog`
Expected: `ok` with no crashers.

- [ ] **Step 5: Commit**

```bash
git add internal/clog/sanitize.go internal/clog/sanitize_test.go internal/clog/fuzz_test.go
git commit -m "feat(clog): control-character sanitizer with fuzz coverage"
```

---

### Task 3: `internal/clog` — the slog Handler

**Files:**
- Create: `internal/clog/handler.go`
- Create: `internal/clog/handler_test.go`

- [ ] **Step 1: Write the failing tests (normal + verbose formats, sanitization, attrs)**

Create `internal/clog/handler_test.go`:

```go
package clog

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixedTime keeps verbose-mode timestamps deterministic.
var fixedTime = time.Date(2026, 7, 10, 12, 4, 1, 234_000_000, time.UTC)

func record(level slog.Level, msg string, args ...any) slog.Record {
	r := slog.NewRecord(fixedTime, level, msg, 0)
	r.Add(args...)
	return r
}

func TestHandlerFormats(t *testing.T) {
	tests := []struct {
		name string
		opts Options
		rec  slog.Record
		want string
	}{
		{
			name: "normal info plain",
			opts: Options{Level: slog.LevelInfo},
			rec:  record(slog.LevelInfo, "loaded manifest: 4 users, 12 servers"),
			want: "• loaded manifest: 4 users, 12 servers\n",
		},
		{
			name: "normal warn plain",
			opts: Options{Level: slog.LevelInfo},
			rec:  record(slog.LevelWarn, "db-1: connection refused"),
			want: "warn: db-1: connection refused\n",
		},
		{
			name: "normal error plain",
			opts: Options{Level: slog.LevelInfo},
			rec:  record(slog.LevelError, "load manifest: no such file"),
			want: "error: load manifest: no such file\n",
		},
		{
			name: "normal info color",
			opts: Options{Level: slog.LevelInfo, Color: true},
			rec:  record(slog.LevelInfo, "auditing 12 servers (parallelism 10)…"),
			want: "\x1b[2m•\x1b[0m auditing 12 servers (parallelism 10)…\n",
		},
		{
			name: "normal warn color",
			opts: Options{Level: slog.LevelInfo, Color: true},
			rec:  record(slog.LevelWarn, "db-1: connection refused"),
			want: "\x1b[33mwarn:\x1b[0m db-1: connection refused\n",
		},
		{
			name: "normal error color",
			opts: Options{Level: slog.LevelInfo, Color: true},
			rec:  record(slog.LevelError, "boom"),
			want: "\x1b[31merror:\x1b[0m boom\n",
		},
		{
			name: "verbose debug plain with attrs",
			opts: Options{Level: slog.LevelDebug, Verbose: true},
			rec:  record(slog.LevelDebug, "dial ok", "server", "web-1", "dur", 34*time.Millisecond),
			want: "12:04:01.234 DEBUG dial ok server=web-1 dur=34ms\n",
		},
		{
			name: "verbose info plain",
			opts: Options{Level: slog.LevelDebug, Verbose: true},
			rec:  record(slog.LevelInfo, "done in 2.3s — 11 read, 1 unreachable"),
			want: "12:04:01.234 INFO  done in 2.3s — 11 read, 1 unreachable\n",
		},
		{
			name: "verbose warn color",
			opts: Options{Level: slog.LevelDebug, Verbose: true, Color: true},
			rec:  record(slog.LevelWarn, "slow"),
			want: "\x1b[2m12:04:01.234\x1b[0m \x1b[33mWARN \x1b[0m slow\n",
		},
		{
			name: "verbose debug color with attr",
			opts: Options{Level: slog.LevelDebug, Verbose: true, Color: true},
			rec:  record(slog.LevelDebug, "dial ok", "server", "web-1"),
			want: "\x1b[2m12:04:01.234\x1b[0m \x1b[34mDEBUG\x1b[0m dial ok \x1b[2mserver=\x1b[0mweb-1\n",
		},
		{
			name: "message sanitized",
			opts: Options{Level: slog.LevelInfo},
			rec:  record(slog.LevelWarn, "evil\x1b[31m\nname"),
			want: "warn: evil[31m name\n",
		},
		{
			name: "attr key and value sanitized",
			opts: Options{Level: slog.LevelInfo},
			rec:  record(slog.LevelInfo, "m", "k\x1bey", "v\nal"),
			want: "• m key=v al\n",
		},
	}
	for _, tt := range tests {
		var buf bytes.Buffer
		h := NewHandler(&buf, tt.opts)
		if err := h.Handle(context.Background(), tt.rec); err != nil {
			t.Errorf("%s: Handle: %v", tt.name, err)
			continue
		}
		if got := buf.String(); got != tt.want {
			t.Errorf("%s:\n got %q\nwant %q", tt.name, got, tt.want)
		}
	}
}

func TestHandlerLevelGate(t *testing.T) {
	tests := []struct {
		level slog.Level
		emit  slog.Level
		want  bool
	}{
		{level: slog.LevelError, emit: slog.LevelWarn, want: false},  // quiet hides warn
		{level: slog.LevelError, emit: slog.LevelError, want: true},  // quiet shows error
		{level: slog.LevelInfo, emit: slog.LevelDebug, want: false},  // normal hides debug
		{level: slog.LevelInfo, emit: slog.LevelInfo, want: true},    // normal shows info
		{level: slog.LevelDebug, emit: slog.LevelDebug, want: true},  // debug shows debug
	}
	for _, tt := range tests {
		h := NewHandler(&bytes.Buffer{}, Options{Level: tt.level})
		if got := h.Enabled(context.Background(), tt.emit); got != tt.want {
			t.Errorf("Enabled(min %v, emit %v) = %v, want %v", tt.level, tt.emit, got, tt.want)
		}
	}
}

// TestHandlerThroughLogger exercises the real slog front door, including a
// WithAttrs child; the parent must not inherit the child's attrs.
func TestHandlerThroughLogger(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(&buf, Options{Level: slog.LevelInfo}))
	child := log.With("server", "web-1")
	child.Info("read done", "bytes", 512)
	log.Info("plain")
	want := "• read done server=web-1 bytes=512\n• plain\n"
	if got := buf.String(); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestHandlerWithGroupPassesThrough(t *testing.T) {
	h := NewHandler(&bytes.Buffer{}, Options{})
	if h.WithGroup("g") != slog.Handler(h) {
		t.Error("WithGroup should return the same handler (groups unused)")
	}
}

// TestHandlerConcurrent pins line-atomicity: many goroutines share one
// handler and every emitted line must be complete. Run under -race by the
// suite, this also proves write serialization.
func TestHandlerConcurrent(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(NewHandler(&buf, Options{Level: slog.LevelInfo}))
	const workers, lines = 8, 50
	var wg sync.WaitGroup
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range lines {
				log.Info(fmt.Sprintf("worker %d line %d", w, i))
			}
		}()
	}
	wg.Wait()
	got := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(got) != workers*lines {
		t.Fatalf("line count = %d, want %d", len(got), workers*lines)
	}
	for _, line := range got {
		if !strings.HasPrefix(line, "• worker ") {
			t.Fatalf("malformed line %q", line)
		}
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/clog/ -run TestHandler -v 2>&1 | head -5`
Expected: compile FAIL — `undefined: NewHandler`, `undefined: Options`.

- [ ] **Step 3: Write the implementation**

Create `internal/clog/handler.go`:

```go
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/clog/ -race -v`
Expected: PASS (formats, level gate, logger integration, group pass-through, concurrency).

- [ ] **Step 5: Commit**

```bash
git add internal/clog/handler.go internal/clog/handler_test.go
git commit -m "feat(clog): human-friendly color slog handler (normal + verbose formats)"
```

---

### Task 4: Root command wiring — `-v`/`-q`/`--color` flags, `app` state, fatal-error line

**Files:**
- Modify: `cmd/sshepherd/run.go`
- Modify: `cmd/sshepherd/run_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `cmd/sshepherd/run_test.go`:

```go
func TestRunFatalErrorPrefix(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run(nil, &out, &errBuf); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.HasPrefix(errBuf.String(), "error: ") {
		t.Errorf("stderr = %q, want an %q prefix", errBuf.String(), "error: ")
	}
}

func TestRunVerboseQuietConflict(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"-v", "-q"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	got := errBuf.String()
	if !strings.Contains(got, "verbose") || !strings.Contains(got, "quiet") {
		t.Errorf("stderr = %q, want the mutual-exclusion message naming both flags", got)
	}
}

func TestRunInvalidColor(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--color", "sometimes"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "invalid color mode") {
		t.Errorf("stderr = %q, want the invalid-color message", errBuf.String())
	}
}

// TestRunColorAlwaysFatal proves the --color flag reaches the logger: with
// always, the fatal line carries ANSI even though stderr is a buffer.
func TestRunColorAlwaysFatal(t *testing.T) {
	var out, errBuf bytes.Buffer
	if code := run([]string{"--color", "always"}, &out, &errBuf); code != 2 {
		t.Fatalf("exit code = %d, want 2", code)
	}
	if !strings.Contains(errBuf.String(), "\x1b[31merror:\x1b[0m") {
		t.Errorf("stderr = %q, want a red error: prefix", errBuf.String())
	}
}

func TestFmtDur(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{in: 34 * time.Millisecond, want: "34ms"},
		{in: 999 * time.Millisecond, want: "999ms"},
		{in: 2340 * time.Millisecond, want: "2.3s"},
		{in: 61 * time.Second, want: "1m1s"},
	}
	for _, tt := range tests {
		if got := fmtDur(tt.in); got != tt.want {
			t.Errorf("fmtDur(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
```

Add `"time"` to the test file's imports.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./cmd/sshepherd/ -run 'TestRunFatal|TestRunVerbose|TestRunInvalidColor|TestRunColorAlways|TestFmtDur' -v 2>&1 | head -10`
Expected: compile FAIL (`undefined: fmtDur`) — and after that's stubbed, assertion failures (`sshepherd: ` prefix instead of `error: `, unknown flags `-v`/`-q`/`--color`).

- [ ] **Step 3: Rewrite `cmd/sshepherd/run.go`**

Replace the whole file with:

```go
package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"github.com/javadh75/SSHepherd/internal/clog"
)

// version is the binary version, overridden at build time via
// -ldflags "-X main.version=<v>". Defaults to "dev" for local builds.
var version = "dev"

// errNonCompliant signals exit code 1: the audit ran but the fleet is not
// (provably) compliant. Everything else non-nil maps to usage/config exit 2.
var errNonCompliant = errors.New("fleet not compliant")

// errFleetUnreadable signals exit code 1 for adopt's strict gate: some
// servers could not be read and --partial was not given. Per-server details
// are already on stderr.
var errFleetUnreadable = errors.New("fleet not fully readable")

// app carries the per-invocation logging state from flag parsing
// (PersistentPreRunE) to the subcommands and to run()'s fatal-error path.
type app struct {
	logger      *slog.Logger // stderr logger; nil until flags are parsed
	reportColor bool         // whether stdout renderers may color
}

// log returns the flag-configured logger, or a safe default for failures
// that happen before flags parse (usage errors, unknown flags).
func (a *app) log(stderr io.Writer) *slog.Logger {
	if a.logger != nil {
		return a.logger
	}
	return slog.New(clog.NewHandler(stderr, clog.Options{
		Level: slog.LevelInfo,
		Color: clog.Enabled(stderr, clog.ColorAuto),
	}))
}

// fmtDur renders durations at operator resolution: whole milliseconds under
// a second, tenths of a second above.
func fmtDur(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

// run is the testable entrypoint: it builds the Cobra tree, executes it
// against the provided streams, and maps errors to process exit codes.
func run(args []string, stdout, stderr io.Writer) int {
	a := &app{}
	root := newRootCmd(a, stdout, stderr)
	if args == nil {
		args = []string{} // SetArgs(nil) would fall back to os.Args[1:]
	}
	root.SetArgs(args)
	err := root.Execute()
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errNonCompliant), errors.Is(err, errFleetUnreadable):
		return 1 // report already rendered; nothing more to say
	default:
		a.log(stderr).Error(err.Error())
		return 2
	}
}

func newRootCmd(a *app, stdout, stderr io.Writer) *cobra.Command {
	var (
		verbose   bool
		quiet     bool
		colorFlag string
	)
	root := &cobra.Command{
		Use:           "sshepherd",
		Short:         "Manage SSH authorized_keys across a fleet of servers",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true, // run() prints errors with consistent formatting
		PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
			mode, err := clog.ParseColorMode(colorFlag)
			if err != nil {
				return fmt.Errorf("--color: %w", err)
			}
			level := slog.LevelInfo
			switch {
			case quiet:
				level = slog.LevelError
			case verbose:
				level = slog.LevelDebug
			}
			a.logger = slog.New(clog.NewHandler(stderr, clog.Options{
				Level:   level,
				Color:   clog.Enabled(stderr, mode),
				Verbose: verbose,
			}))
			a.reportColor = clog.Enabled(stdout, mode)
			return nil
		},
		RunE: func(_ *cobra.Command, _ []string) error {
			return errors.New("no command given (try --help)")
		},
	}
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetVersionTemplate("sshepherd {{.Version}}\n")
	pf := root.PersistentFlags()
	pf.BoolVarP(&verbose, "verbose", "v", false, "enable debug logging")
	pf.BoolVarP(&quiet, "quiet", "q", false, "log errors only")
	pf.StringVar(&colorFlag, "color", "auto", "colorize output: auto, always, or never")
	root.MarkFlagsMutuallyExclusive("verbose", "quiet")
	root.AddCommand(newAuditCmd(stdout))
	root.AddCommand(newImportCmd(stdout))
	root.AddCommand(newAdoptCmd(stdout))
	return root
}
```

Note: subcommand constructors are untouched in this task; they adopt the
logger in Tasks 6–8. The fatal line changes from `sshepherd: <err>` to
`error: <err>` — existing tests only assert substrings, which survive.

- [ ] **Step 4: Run the full cmd test suite**

Run: `go test ./cmd/sshepherd/ -race`
Expected: PASS (new tests pass; all existing tests still pass — they assert substrings/exit codes, not the `sshepherd:` prefix).

- [ ] **Step 5: Commit**

```bash
git add cmd/sshepherd/run.go cmd/sshepherd/run_test.go
git commit -m "feat(cmd): -v/-q/--color flags; logger built at flag parse; fatal errors through the handler"
```

---

### Task 5: Colorized audit report — `RenderOptions` + tabwriter-safe palette

**Files:**
- Modify: `internal/audit/report.go`
- Modify: `internal/audit/report_test.go`
- Create: `internal/audit/testdata/report_drift_color.golden`
- Create: `internal/audit/testdata/report_critical_color.golden`

- [ ] **Step 1: Update existing call sites to the new signature (mechanical)**

In `internal/audit/report_test.go`, every `Render(&buf, cfg, results)` becomes `Render(&buf, cfg, results, RenderOptions{})`. In `cmd/sshepherd/audit.go`, both `audit.Render(stdout, cfg, nil)` and `audit.Render(stdout, cfg, results)` become `audit.Render(stdout, cfg, nil, audit.RenderOptions{})` / `audit.Render(stdout, cfg, results, audit.RenderOptions{})` for now (the real color flag is wired in Task 6).

- [ ] **Step 2: Write the failing tests**

Append to `internal/audit/report_test.go`:

```go
// ansiRE strips SGR sequences; see TestRenderColorStrippedEqualsPlain.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// TestRenderColorStrippedEqualsPlain pins the two load-bearing invariants at
// once: color adds nothing but SGR codes (content identical), and because
// every glyph-column SGR prefix has equal byte length, tabwriter computes
// the same column widths — so stripping color must reproduce the plain
// output byte-for-byte, alignment included.
func TestRenderColorStrippedEqualsPlain(t *testing.T) {
	cfg := reportConfig(t)
	results := driftResults(t, cfg) // extracted in Step 3 below

	var plain, colored bytes.Buffer
	Render(&plain, cfg, results, RenderOptions{})
	Render(&colored, cfg, results, RenderOptions{Color: true})

	if plain.String() == colored.String() {
		t.Fatal("colored output is identical to plain — no color was applied")
	}
	stripped := ansiRE.ReplaceAllString(colored.String(), "")
	if stripped != plain.String() {
		t.Errorf("stripped colored output differs from plain:\n--- stripped ---\n%s\n--- plain ---\n%s",
			stripped, plain.String())
	}
}

func TestRenderDriftColorGolden(t *testing.T) {
	cfg := reportConfig(t)
	var buf bytes.Buffer
	Render(&buf, cfg, driftResults(t, cfg), RenderOptions{Color: true})
	checkGolden(t, "report_drift_color.golden", buf.Bytes())
}
```

Add `"regexp"` to the test file's imports.

- [ ] **Step 3: Extract the drift fixture**

`TestRenderDrift` currently builds its `[]ServerResult` inline. Extract that construction into a helper so the color tests reuse the exact same fixture:

```go
// driftResults builds the standard drift scenario: web-1 with alice ok, bob
// missing, one unauthorized key and one parse error; web-2 unreachable.
func driftResults(t *testing.T, cfg *config.Config) []ServerResult {
	t.Helper()
	// … move the existing []ServerResult construction from TestRenderDrift
	// here verbatim and return it …
}
```

`TestRenderDrift` then calls `driftResults(t, cfg)`. Do the same only if the
critical-scenario test's fixture is needed; otherwise mirror this pattern
with a `criticalResults` helper for a `report_critical_color.golden` test:

```go
func TestRenderCriticalColorGolden(t *testing.T) {
	// reuse the fixture that produced report_critical.golden, with
	// RenderOptions{Color: true}, checked against report_critical_color.golden
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `go test ./internal/audit/ -run TestRender -v 2>&1 | head -10`
Expected: compile FAIL — `undefined: RenderOptions`.

- [ ] **Step 5: Implement the palette and color paths in `internal/audit/report.go`**

Add near the top of the file:

```go
// RenderOptions tunes report presentation.
type RenderOptions struct {
	Color bool // ANSI-color drift glyphs and key words; off = byte-identical to plain
}

// SGR codes used by the report. Every code is exactly four bytes ("0;32"),
// so each painted glyph cell carries identically-sized invisible bytes:
// text/tabwriter sizes columns by byte count, and equal-length prefixes are
// what keep the columns aligned when color is on.
const (
	codeGreen   = "0;32"
	codeRed     = "0;31"
	codeBoldRed = "1;31"
	codeYellow  = "0;33"
)

// palette paints report fragments when color is on.
type palette struct{ on bool }

func (p palette) paint(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}
```

Change signatures and bodies:

```go
// Render writes the human-readable audit report. The report is the command's
// stdout product; diagnostics beyond the report belong on stderr (caller's
// concern).
func Render(w io.Writer, cfg *config.Config, results []ServerResult, opts RenderOptions) {
	if len(results) == 0 {
		fmt.Fprintln(w, "Summary: 0 servers configured — nothing to audit")
		return
	}
	pal := palette{on: opts.Color}
	for _, r := range results {
		renderServer(w, cfg, r, pal)
		fmt.Fprintln(w)
	}
	renderSummary(w, cfg, results)
}

func renderServer(w io.Writer, cfg *config.Config, r ServerResult, pal palette) {
	head := fmt.Sprintf("%s (%s@%s:%d)", r.Server.Name, r.Server.User, r.Server.Host, r.Server.Port)
	if r.Err != nil {
		fmt.Fprintf(w, "%s  %s %v\n", head, pal.paint(codeRed, "ERROR:"), r.Err)
		return
	}
	fmt.Fprintln(w, head)

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, k := range r.Diff.OK {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tpresent & authorized\n",
			pal.paint(codeGreen, "✓"), label(cfg, k), k.Fingerprint, k.Type)
	}
	for _, k := range r.Diff.Missing {
		if u, ok := cfg.OwnerOf(k.Fingerprint); ok && u.Operator {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tauthorized but %s (%s: operator key)\n",
				pal.paint(codeBoldRed, "‼"), label(cfg, k), k.Fingerprint, k.Type,
				pal.paint(codeRed, "MISSING"), pal.paint(codeBoldRed, "CRITICAL"))
			continue
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tauthorized but %s\n",
			pal.paint(codeRed, "✗"), label(cfg, k), k.Fingerprint, k.Type,
			pal.paint(codeRed, "MISSING"))
	}
	for _, k := range r.Diff.Unauthorized {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\tinstalled but %s\n",
			pal.paint(codeYellow, "⚠"), label(cfg, k), k.Fingerprint, k.Type,
			pal.paint(codeYellow, "UNAUTHORIZED"))
	}
	_ = tw.Flush()
	// … the ParseErrs / FileAbsent / emptyFile / NoUsersGranted / totals
	// block is unchanged from the current file …
}
```

Everything else (`renderSummary`, `label`, `criticalDrift`, notes) stays
untouched. Key detail: the head `ERROR:` moved inside a `%s` painted cell —
with color off `pal.paint` returns the string unchanged, so plain output
stays byte-identical (`head  ERROR: err`). Colored key words (`MISSING`,
`CRITICAL`, `UNAUTHORIZED`) live only in the **last** tabwriter column,
where unequal byte lengths cannot affect alignment.

- [ ] **Step 6: Generate the color goldens, then verify everything**

Run: `go test ./internal/audit/ -run 'Golden' -update`
Then inspect the new files — `testdata/report_drift_color.golden` must show
`\x1b[0;32m✓\x1b[0m` style glyphs with intact column alignment.
Run: `go test ./internal/audit/ ./cmd/sshepherd/ -race`
Expected: PASS — including the three pre-existing plain goldens **unmodified** (`git status` must show no changes to `report_compliant.golden`, `report_drift.golden`, `report_critical.golden`).

- [ ] **Step 7: Commit**

```bash
git add internal/audit/report.go internal/audit/report_test.go internal/audit/testdata/ cmd/sshepherd/audit.go
git commit -m "feat(audit): colorized report behind RenderOptions; tabwriter-safe equal-width SGR codes"
```

---

### Task 6: Audit command — phase logs + per-server WARN/DEBUG via `audit.Options.Logger`

**Files:**
- Modify: `internal/audit/audit.go`
- Modify: `internal/audit/audit_test.go`
- Modify: `cmd/sshepherd/audit.go`
- Modify: `cmd/sshepherd/run.go` (pass `a` to `newAuditCmd`)
- Modify: `cmd/sshepherd/audit_test.go`

- [ ] **Step 1: Write the failing package test (audit fan-out logging)**

Append to `internal/audit/audit_test.go` (it already has a fake `KeyReader`; reuse the existing fake, shown here as `fakeReader` — adapt the name to the file's actual fake):

```go
// TestRunLogsPerServer pins the live per-server telemetry: failures WARN as
// they happen, successes leave a DEBUG breadcrumb with a duration.
func TestRunLogsPerServer(t *testing.T) {
	cfg := reportConfig(t)
	reader := readerFunc(func(_ context.Context, srv config.Server) (ReadResult, error) {
		if srv.Name == "web-2" {
			return ReadResult{}, errors.New("dial tcp: connection refused")
		}
		return ReadResult{Content: nil}, nil
	})
	var buf bytes.Buffer
	log := slog.New(clog.NewHandler(&buf, clog.Options{Level: slog.LevelDebug}))
	Run(context.Background(), cfg, reader, Options{Parallel: 2, Logger: log})

	got := buf.String()
	if !strings.Contains(got, "warn: web-2: dial tcp: connection refused") {
		t.Errorf("log = %q, want a live warn line for web-2", got)
	}
	if !strings.Contains(got, "audited") || !strings.Contains(got, "server=web-1") {
		t.Errorf("log = %q, want a debug audited line for web-1", got)
	}
}

// TestRunNilLoggerSafe: Options.Logger is optional.
func TestRunNilLoggerSafe(t *testing.T) {
	cfg := reportConfig(t)
	reader := readerFunc(func(_ context.Context, _ config.Server) (ReadResult, error) {
		return ReadResult{}, nil
	})
	Run(context.Background(), cfg, reader, Options{Parallel: 1}) // must not panic
}
```

If the file has no function-adapter fake, add one:

```go
// readerFunc adapts a function to KeyReader for tests.
type readerFunc func(context.Context, config.Server) (ReadResult, error)

func (f readerFunc) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (ReadResult, error) {
	return f(ctx, srv)
}
```

Imports to add: `bytes`, `errors`, `log/slog`, `strings`, and `github.com/javadh75/SSHepherd/internal/clog`.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/audit/ -run TestRunLogs -v 2>&1 | head -5`
Expected: compile FAIL — `unknown field Logger in struct literal`.

- [ ] **Step 3: Implement logging in `internal/audit/audit.go`**

Add `"fmt"` and `"log/slog"` to imports. Extend `Options` and thread the logger:

```go
// Options tunes the fleet fan-out.
type Options struct {
	Parallel         int           // max concurrent server audits (>= 1)
	PerServerTimeout time.Duration // overall deadline per server; 0 = none
	Logger           *slog.Logger  // optional per-server telemetry; nil discards
}

// logger returns the configured logger or a discard logger, so auditOne
// never nil-checks.
func (o Options) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.New(slog.DiscardHandler)
}
```

In `Run`, resolve once before the loop and pass down:

```go
log := opts.logger()
…
results[i] = auditOne(ctx, cfg, reader, srv, opts.PerServerTimeout, log)
```

In `auditOne` (new `log *slog.Logger` parameter):

```go
start := time.Now()
read, err := reader.ReadAuthorizedKeys(ctx, srv)
if err != nil {
	// Live telemetry: the report will also show this, but during a slow
	// fan-out the operator sees which server failed as it happens.
	log.Warn(fmt.Sprintf("%s: %v", srv.Name, err))
	res.Err = err
	return res
}
…existing diff logic…
log.Debug("audited", "server", srv.Name, "dur", time.Since(start).Round(time.Millisecond))
return res
```

- [ ] **Step 4: Run package tests**

Run: `go test ./internal/audit/ -race`
Expected: PASS.

- [ ] **Step 5: Write the failing cmd tests**

Append to `cmd/sshepherd/audit_test.go` (there is a `writeManifest`-style helper already in the cmd test files for creating temp manifests — reuse whatever helper `TestAuditEmptyFleet` uses; shown here inline):

```go
// TestAuditPhaseLogs: normal mode narrates phases on stderr.
func TestAuditPhaseLogs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, []byte("users: []\nservers: []\naccess: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "loaded manifest: 0 users, 0 servers") {
		t.Errorf("stderr = %q, want the loaded-manifest phase line", errBuf.String())
	}
}

// TestAuditQuietSilencesPhases: -q leaves stderr empty on a clean run.
func TestAuditQuietSilencesPhases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, []byte("users: []\nservers: []\naccess: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "-q", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty under -q", errBuf.String())
	}
	if !strings.Contains(out.String(), "0 servers configured") {
		t.Errorf("stdout = %q, the product must survive -q", out.String())
	}
}

// TestAuditVerboseFormat: -v switches stderr to the timestamped format.
func TestAuditVerboseFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.yaml")
	if err := os.WriteFile(path, []byte("users: []\nservers: []\naccess: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errBuf bytes.Buffer
	if code := run([]string{"audit", "-v", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "INFO") {
		t.Errorf("stderr = %q, want verbose INFO tags", errBuf.String())
	}
}
```

(Imports: these files already use `bytes`/`strings`; add `os`/`filepath` if missing.)

- [ ] **Step 6: Run to verify failure**

Run: `go test ./cmd/sshepherd/ -run TestAuditPhase -v 2>&1 | head -5`
Expected: FAIL — no phase line on stderr yet.

- [ ] **Step 7: Wire the audit command**

In `cmd/sshepherd/run.go`, change `root.AddCommand(newAuditCmd(stdout))` to `root.AddCommand(newAuditCmd(a, stdout))`.

In `cmd/sshepherd/audit.go`, change the signature to `func newAuditCmd(a *app, stdout io.Writer) *cobra.Command` and update `RunE`:

```go
RunE: func(cmd *cobra.Command, _ []string) error {
	if parallel < 1 {
		return fmt.Errorf("--parallel must be >= 1 (got %d)", parallel)
	}
	log := a.logger
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return fmt.Errorf("load manifest: %w", err) // wrapcheck: wrap at package boundary
	}
	log.Info(fmt.Sprintf("loaded manifest: %d users, %d servers", len(cfg.Users), len(cfg.Servers)))
	if len(cfg.Servers) == 0 {
		audit.Render(stdout, cfg, nil, audit.RenderOptions{Color: a.reportColor})
		return nil
	}
	if err := sshread.CheckAgent(os.Getenv("SSH_AUTH_SOCK")); err != nil {
		return fmt.Errorf("agent preflight: %w", err)
	}
	khPath, err := expandHome(knownHosts)
	if err != nil {
		return err
	}
	// Preflight known_hosts once: a bad path fails with a single
	// clear error instead of N identical per-server errors.
	if err := sshread.PreflightKnownHosts(khPath); err != nil {
		return fmt.Errorf("known_hosts preflight: %w", err)
	}
	reader := &sshread.Client{
		KnownHostsPath: khPath,
		AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
		DialTimeout:    dialTimeout,
	}
	log.Info(fmt.Sprintf("auditing %d servers (parallelism %d)…", len(cfg.Servers), parallel))
	start := time.Now()
	results := audit.Run(cmd.Context(), cfg, reader, audit.Options{
		Parallel:         parallel,
		PerServerTimeout: perServerTimeout,
		Logger:           log,
	})
	var unreachable int
	for _, r := range results {
		if r.Err != nil {
			unreachable++
		}
	}
	log.Info(fmt.Sprintf("done in %s — %d read, %d unreachable",
		fmtDur(time.Since(start)), len(results)-unreachable, unreachable))
	audit.Render(stdout, cfg, results, audit.RenderOptions{Color: a.reportColor})
	if audit.ExitCode(results) != 0 {
		return errNonCompliant
	}
	return nil
},
```

- [ ] **Step 8: Run the suites**

Run: `go test ./cmd/sshepherd/ ./internal/audit/ -race`
Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add cmd/sshepherd/run.go cmd/sshepherd/audit.go cmd/sshepherd/audit_test.go internal/audit/
git commit -m "feat(audit): phase-level progress at INFO, live per-server WARN/DEBUG telemetry"
```

---

### Task 7: `sshread` — SSH-stage DEBUG logs + stderr-truncation WARN

**Files:**
- Modify: `internal/sshread/sshread.go`
- Modify: `internal/sshread/sshread_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/sshread/sshread_test.go`:

```go
// TestClientLogNilSafe: an unset Log field must yield a usable logger.
func TestClientLogNilSafe(t *testing.T) {
	c := &Client{}
	c.log().Debug("must not panic")
}

func TestFinishRead(t *testing.T) {
	discard := slog.New(slog.DiscardHandler)
	content := &cappedBuffer{limit: 10}
	_, _ = content.Write([]byte("key-line\n"))

	t.Run("content returned", func(t *testing.T) {
		res, err := finishRead(0, content, &cappedBuffer{limit: 10}, "h:22", discard)
		if err != nil || string(res.Content) != "key-line\n" || res.FileAbsent {
			t.Fatalf("got (%q, absent=%v, %v)", res.Content, res.FileAbsent, err)
		}
	})
	t.Run("absent sentinel", func(t *testing.T) {
		res, err := finishRead(fileAbsentExit, &cappedBuffer{limit: 10}, &cappedBuffer{limit: 10}, "h:22", discard)
		if err != nil || !res.FileAbsent {
			t.Fatalf("got (absent=%v, %v), want (true, nil)", res.FileAbsent, err)
		}
	})
	t.Run("stdout truncation is an error", func(t *testing.T) {
		trunc := &cappedBuffer{limit: 2}
		_, _ = trunc.Write([]byte("too long"))
		_, err := finishRead(0, trunc, &cappedBuffer{limit: 10}, "h:22", discard)
		if err == nil || !strings.Contains(err.Error(), "refusing to audit") {
			t.Fatalf("err = %v, want the truncation refusal", err)
		}
	})
	t.Run("stderr truncation warns but succeeds", func(t *testing.T) {
		var logBuf bytes.Buffer
		log := slog.New(clog.NewHandler(&logBuf, clog.Options{Level: slog.LevelInfo}))
		errTrunc := &cappedBuffer{limit: 2}
		_, _ = errTrunc.Write([]byte("noisy remote stderr"))
		res, err := finishRead(0, content, errTrunc, "h:22", log)
		if err != nil || string(res.Content) != "key-line\n" {
			t.Fatalf("got (%q, %v), want content and nil error", res.Content, err)
		}
		if !strings.Contains(logBuf.String(), "warn: h:22: remote stderr exceeded") {
			t.Errorf("log = %q, want the stderr-truncation warn", logBuf.String())
		}
	})
	t.Run("nonzero exit is an error", func(t *testing.T) {
		errOut := &cappedBuffer{limit: 100}
		_, _ = errOut.Write([]byte("cat: permission denied"))
		_, err := finishRead(1, &cappedBuffer{limit: 10}, errOut, "h:22", discard)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("err = %v, want the remote stderr embedded", err)
		}
	})
}
```

Imports to add in the test file: `bytes`, `log/slog`, `strings` (if missing), and `github.com/javadh75/SSHepherd/internal/clog`.

- [ ] **Step 2: Run to verify failure**

Run: `go test ./internal/sshread/ -run 'TestClientLogNil|TestFinishRead' -v 2>&1 | head -5`
Expected: compile FAIL — `c.log undefined`, `undefined: finishRead`.

- [ ] **Step 3: Implement in `internal/sshread/sshread.go`**

Add `"log/slog"` to imports. Extend `Client`:

```go
// Client reads remote authorized_keys over SSH. It implements audit.KeyReader.
type Client struct {
	KnownHostsPath string
	AgentSock      string
	DialTimeout    time.Duration
	Log            *slog.Logger // optional stage-level telemetry; nil discards
}

// log returns the configured logger or a discard logger, so call sites never
// nil-check.
func (c *Client) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.DiscardHandler)
}
```

In `readAuthorizedKeys`, add stage breadcrumbs (each is one line; the whole
point is seeing where a hung server is stuck under `-v`):

```go
log := c.log()
```
after the deadline setup; then before the TCP dial:
```go
log.Debug("dialing", "server", srv.Name, "addr", addr)
dialStart := time.Now()
```
after a successful dial:
```go
log.Debug("dial ok", "server", srv.Name, "addr", addr,
	"dur", time.Since(dialStart).Round(time.Millisecond))
```
inside the host-key callback's success path (`cb`), after `hostKeys(...)` returns nil:
```go
log.Debug("host key verified", "server", srv.Name)
```
after `ssh.NewClientConn` succeeds:
```go
log.Debug("auth ok", "server", srv.Name, "user", srv.User)
```
and change the final call to `return readRemote(client, addr, log)`.

Refactor `readRemote`: it keeps the session mechanics and delegates outcome
mapping to a pure, unit-testable `finishRead`:

```go
// readRemote runs the read command over an established SSH connection and
// maps its output and exit status to a ReadResult.
func readRemote(client *ssh.Client, addr string, log *slog.Logger) (audit.ReadResult, error) {
	var zero audit.ReadResult

	sess, err := client.NewSession()
	if err != nil {
		return zero, fmt.Errorf("open session on %s: %w", addr, err)
	}
	defer func() { _ = sess.Close() }()

	stdout := &cappedBuffer{limit: maxRemoteOutput}
	stderr := &cappedBuffer{limit: maxRemoteOutput}
	sess.Stdout = stdout
	sess.Stderr = stderr

	code := 0
	if runErr := sess.Run(authorizedKeysCmd); runErr != nil {
		var exitErr *ssh.ExitError
		if !errors.As(runErr, &exitErr) {
			return zero, fmt.Errorf("remote read on %s: %w", addr, runErr)
		}
		code = exitErr.ExitStatus()
	}
	log.Debug("remote read done", "addr", addr, "exit", code)
	return finishRead(code, stdout, stderr, addr, log)
}

// finishRead maps the remote command outcome (exit code + captured output)
// to a ReadResult. Pure — unit-testable without a connection. Truncated
// stdout is an error (a partial authorized_keys must never be diffed as
// truth: missing tail keys would be misreported as drift); truncated stderr
// is diagnostics only and is worth a WARN, not a failure.
func finishRead(code int, stdout, stderr *cappedBuffer, addr string, log *slog.Logger) (audit.ReadResult, error) {
	var zero audit.ReadResult
	if stderr.truncated {
		log.Warn(fmt.Sprintf("%s: remote stderr exceeded %d bytes; diagnostics truncated", addr, maxRemoteOutput))
	}
	absent, err := interpretExit(code, stderr.String())
	if err != nil {
		return zero, fmt.Errorf("remote read on %s: %w", addr, err)
	}
	if stdout.truncated {
		return zero, fmt.Errorf("remote read on %s: remote output exceeded 1MiB — refusing to audit a truncated authorized_keys", addr)
	}
	if absent {
		return audit.ReadResult{FileAbsent: true}, nil
	}
	log.Debug("read authorized_keys", "addr", addr, "bytes", stdout.buf.Len())
	return audit.ReadResult{Content: stdout.Bytes()}, nil
}
```

Then set the field at the two construction sites: in `cmd/sshepherd/audit.go`
add `Log: log,` to the `sshread.Client{…}` literal (Task 6 already put `log`
in scope); `readFleet` in adopt.go is handled in Task 8.

- [ ] **Step 4: Run the suites**

Run: `go test ./internal/sshread/ ./cmd/sshepherd/ -race`
Expected: PASS. Also run `go vet ./...` — clean.

- [ ] **Step 5: Commit**

```bash
git add internal/sshread/ cmd/sshepherd/audit.go
git commit -m "feat(sshread): per-stage debug telemetry; stderr truncation warns instead of vanishing"
```

---

### Task 8: `adopt` — logger migration, phase logs, `readFleet` telemetry

**Files:**
- Modify: `cmd/sshepherd/adopt.go`
- Modify: `cmd/sshepherd/adopt_test.go`
- Modify: `cmd/sshepherd/run.go` (pass `a` to `newAdoptCmd`)

- [ ] **Step 1: Write the failing tests**

Append to `cmd/sshepherd/adopt_test.go` (reuse its existing empty-fleet manifest helper):

```go
// TestAdoptQuietKeepsProduct: -q silences the nothing-to-adopt note but the
// manifest still lands on stdout.
func TestAdoptQuietKeepsProduct(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	path := writeEmptyFleetManifest(t) // reuse however TestAdoptEmptyFleet builds its manifest
	var out, errBuf bytes.Buffer
	if code := run([]string{"adopt", "-q", "--config", path}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr = %q, want empty under -q", errBuf.String())
	}
	if !strings.Contains(out.String(), "generated by sshepherd adopt") {
		t.Errorf("stdout = %q, the manifest must survive -q", out.String())
	}
}
```

Note for the implementer: `TestAdoptEmptyFleet` constructs an empty-fleet
manifest inline — extract that into a small helper (`writeEmptyFleetManifest`)
or repeat its 3 lines; either is fine.

Existing assertions that must keep passing after migration (verify, don't delete):
- `adopt_test.go:216` — "nothing to adopt" (now rendered `• nothing to adopt…`).
- `adopt_test.go:322` — strict-gate stderr contains `web-1` and `--partial` (now `error: server web-1: …` / `error: 1 server(s) could not be fully read — nothing written; fix the errors above or re-run with --partial`).
- `adopt_test.go:340` — "on the readable servers".

- [ ] **Step 2: Run to verify failure**

Run: `go test ./cmd/sshepherd/ -run TestAdoptQuiet -v 2>&1 | head -5`
Expected: FAIL — stderr not empty (the note prints regardless of -q today).

- [ ] **Step 3: Migrate `cmd/sshepherd/adopt.go` to the logger**

Change signatures: `func newAdoptCmd(a *app, stdout io.Writer) *cobra.Command`; in run.go `root.AddCommand(newAdoptCmd(a, stdout))`.

`readFleet` gains the logger and passes it down both seams:

```go
// readFleet runs the agent/known_hosts preflights and reads every server's
// authorized_keys via the same SSH path as audit. An empty fleet needs no
// agent and returns nil results.
func readFleet(ctx context.Context, log *slog.Logger, cfg *config.Config, knownHosts string, parallel int) ([]audit.ServerResult, error) {
	if len(cfg.Servers) == 0 {
		return nil, nil
	}
	…preflights unchanged…
	reader := &sshread.Client{
		KnownHostsPath: khPath,
		AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
		DialTimeout:    dialTimeout,
		Log:            log,
	}
	return audit.Run(ctx, cfg, reader, audit.Options{
		Parallel:         parallel,
		PerServerTimeout: perServerTimeout,
		Logger:           log,
	}), nil
}
```

`reportPlan` speaks slog instead of a raw writer, and gains the
positive-outcome line:

```go
// reportPlan logs the plan's operator-facing notes: attribution warnings,
// the adoption outcome, and a nothing-to-adopt note qualified when part of
// the fleet went unread.
func reportPlan(log *slog.Logger, plan adopt.Plan, unreadable []string) {
	for _, w := range plan.Warnings {
		log.Warn(w)
	}
	if len(plan.NewUsers) == 0 && len(plan.Extensions) == 0 {
		note := "nothing to adopt: the manifest already accounts for every key found"
		if len(unreadable) > 0 {
			// Unreadable servers may hold keys we never saw; don't let the
			// note read as "the whole fleet is clean".
			note += " on the readable servers"
		}
		log.Info(note)
		return
	}
	log.Info(fmt.Sprintf("adopting %d new users, %d access extensions",
		len(plan.NewUsers), len(plan.Extensions)))
}
```

In `RunE`: delete `stderr := cmd.ErrOrStderr()`; use `log := a.logger`.
After `config.Load`:

```go
log.Info(fmt.Sprintf("loaded manifest: %d users, %d servers", len(cfg.Users), len(cfg.Servers)))
if len(cfg.Servers) > 0 {
	log.Info(fmt.Sprintf("reading %d servers (parallelism %d)…", len(cfg.Servers), parallel))
}
start := time.Now()
results, err := readFleet(cmd.Context(), log, cfg, knownHosts, parallel)
if err != nil {
	return err
}
if len(cfg.Servers) > 0 {
	var unreachable int
	for _, r := range results {
		if r.Err != nil {
			unreachable++
		}
	}
	log.Info(fmt.Sprintf("done in %s — %d read, %d unreachable",
		fmtDur(time.Since(start)), len(results)-unreachable, unreachable))
}
```

The unreadable-servers block replaces its Fprintfs:

```go
if len(unreadable) > 0 {
	for _, is := range plan.Issues {
		msg := fmt.Sprintf("server %s: %s", is.Server, is.Detail)
		if partial {
			log.Warn(msg)
		} else {
			log.Error(msg)
		}
	}
	if !partial {
		// A draft generated from a partial read under-represents
		// reality; a later apply would revoke the unseen keys.
		log.Error(fmt.Sprintf(
			"%d server(s) could not be fully read — nothing written; fix the errors above or re-run with --partial",
			len(unreadable)))
		return errFleetUnreadable
	}
}
```

And `reportPlan(stderr, plan, unreadable)` becomes `reportPlan(log, plan, unreadable)`.
Add `"log/slog"` and `"time"` to imports; drop `"io"` if now unused.

- [ ] **Step 4: Run the suite**

Run: `go test ./cmd/sshepherd/ -race`
Expected: PASS — including the pre-existing strict-gate and note tests listed in Step 1.

- [ ] **Step 5: Commit**

```bash
git add cmd/sshepherd/run.go cmd/sshepherd/adopt.go cmd/sshepherd/adopt_test.go
git commit -m "feat(adopt): diagnostics through the leveled logger; fleet-read phase telemetry"
```

---

### Task 9: `import` — logger migration + phase logs

**Files:**
- Modify: `cmd/sshepherd/import.go`
- Modify: `cmd/sshepherd/import_test.go`
- Modify: `cmd/sshepherd/run.go` (pass `a` to `newImportCmd`)

- [ ] **Step 1: Update the three empty-stderr assertions (they now see INFO lines)**

In `cmd/sshepherd/import_test.go`:
- The clean-import test at ~line 200 (`errBuf.Len() != 0 … "want empty for a clean import"`): add `"-q"` to the `run` args and keep the empty assertion — it becomes the quiet-mode e2e proof for import.
- The two remaining `errBuf.Len() != 0` assertions (~lines 291, 306): replace with warn-free assertions so they still pin "no complaints" without forbidding phase INFO lines:

```go
if strings.Contains(errBuf.String(), "warn:") || strings.Contains(errBuf.String(), "error:") {
	t.Errorf("stderr = %q, want no warnings for a clean import", errBuf.String())
}
```

- [ ] **Step 2: Write the failing phase-log test**

Append to `cmd/sshepherd/import_test.go` (reuse the file's existing ssh-config fixture helper, the one used by the clean-import test):

```go
// TestImportPhaseLogs: normal mode narrates parsing on stderr.
func TestImportPhaseLogs(t *testing.T) {
	cfg := writeBasicSSHConfig(t) // reuse the fixture helper the clean-import test uses
	var out, errBuf bytes.Buffer
	if code := run([]string{"import", cfg, "--servers-only"}, &out, &errBuf); code != 0 {
		t.Fatalf("exit = %d, want 0 (stderr: %s)", code, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "parsed") || !strings.Contains(errBuf.String(), "hosts") {
		t.Errorf("stderr = %q, want a parsed-hosts phase line", errBuf.String())
	}
}
```

- [ ] **Step 3: Run to verify failure**

Run: `go test ./cmd/sshepherd/ -run TestImport -v 2>&1 | head -20`
Expected: FAIL — the `-q` test fails (INFO would…) actually at this point `-q` passes vacuously (no INFO yet) but `TestImportPhaseLogs` FAILS (no phase line yet). That failing test drives the change.

- [ ] **Step 4: Migrate `cmd/sshepherd/import.go`**

Signature `func newImportCmd(a *app, stdout io.Writer) *cobra.Command`; in run.go `root.AddCommand(newImportCmd(a, stdout))`. In `RunE`, delete `stderr := cmd.ErrOrStderr()` and use the logger:

```go
log := a.logger
hosts, warnings, err := sshcfg.Load(srcPath)
if err != nil {
	return fmt.Errorf("load ssh config: %w", err) // wrapcheck: wrap at package boundary
}
log.Info(fmt.Sprintf("parsed %s: %d hosts", src, len(hosts)))
for _, w := range warnings {
	log.Warn(w)
}
var users []identity.User
if !serversOnly {
	var idWarnings []string
	users, idWarnings, err = resolveUsers(hosts, operators)
	if err != nil {
		return err
	}
	for _, w := range idWarnings {
		log.Warn(w)
	}
	log.Info(fmt.Sprintf("derived %d users from identity files", len(users)))
}
manifest, notes, err := generateManifest(hosts, users, src)
if err != nil {
	return err
}
for _, n := range notes {
	log.Warn(n)
}
```

Rest of `RunE` unchanged. Drop unused imports if any.

- [ ] **Step 5: Run the full cmd suite**

Run: `go test ./cmd/sshepherd/ -race`
Expected: PASS — including the updated warn-substring tests (`nouser`, `no access derived` still appear, now behind `warn: `).

- [ ] **Step 6: Commit**

```bash
git add cmd/sshepherd/run.go cmd/sshepherd/import.go cmd/sshepherd/import_test.go
git commit -m "feat(import): diagnostics through the leveled logger; parse/derive phase telemetry"
```

---

### Task 10: Gate, fuzz target, docs

**Files:**
- Modify: `Makefile`
- Modify: `CLAUDE.md`
- Modify: `docs/superpowers/specs/2026-07-10-logging-verbosity-color-design.md`

- [ ] **Step 1: Add the clog fuzzer to `make fuzz`**

In the `fuzz:` target, append:

```make
	$(GO) test -run='^$$' -fuzz=FuzzSanitize -fuzztime=15s ./internal/clog
```

Run: `make fuzz`
Expected: all six fuzzers pass 15s runs (watch the new FuzzSanitize line).

- [ ] **Step 2: Run the full gate**

```bash
make check && make coverage
```

Expected: tidy/fmt/vet/lint/deadcode/security/test all green; coverage ≥ 80%.
Likely trip points and fixes:
- `deadcode`: every new exported clog identifier is reached from `main` via `newRootCmd` — if it flags something, delete the unused identifier rather than exporting it "for later".
- `golangci-lint` `wrapcheck` on new cross-package error returns: wrap with `fmt.Errorf("…: %w", err)` at the cmd boundary (already done for `--color`).
- `gitleaks`: nothing new should trip; goldens contain only test keys already in-repo.

- [ ] **Step 3: Update docs**

- Spec: flip `- **Status:** Approved` to `- **Status:** Implemented (2026-07-10) — see docs/superpowers/plans/2026-07-10-logging-verbosity-color.md`.
- `CLAUDE.md` Status section: append one sentence to the existing paragraph:

```
CLI-wide leveled logging is in place: `-v/--verbose`, `-q/--quiet`, and
`--color auto|always|never` on the root command, phase-level progress at
normal verbosity, per-SSH-stage detail at debug, and a colorized audit
report — all degrading to plain text on non-TTY/`NO_COLOR`/`TERM=dumb`
(specced in `docs/superpowers/specs/2026-07-10-logging-verbosity-color-design.md`).
```

- [ ] **Step 4: Manual smoke (eyes on the real thing)**

```bash
go build -o bin/sshepherd ./cmd/sshepherd
./bin/sshepherd audit --config /nonexistent.yaml            # error: load manifest: … (red on a TTY)
./bin/sshepherd audit --config /nonexistent.yaml -q          # same error (quiet never hides errors)
./bin/sshepherd --color=always 2>&1 | cat -v                 # ^[[31merror:^[[0m … (forced color visible through the pipe)
NO_COLOR=1 ./bin/sshepherd --color=auto; echo                # plain error line, no escapes
```

- [ ] **Step 5: Final commit**

```bash
git add Makefile CLAUDE.md docs/superpowers/specs/2026-07-10-logging-verbosity-color-design.md
git commit -m "chore: wire clog fuzzing into make fuzz; mark logging slice implemented"
```

---

## Self-Review Notes (already applied)

- **Spec coverage:** flags/mode mapping (Task 4), per-stream color decision (Task 1), handler formats + sanitization + fuzz + race (Tasks 2–3), report color + tabwriter safety + goldens (Task 5), audit phases + live WARN (Task 6), sshread stages + stderr-truncation WARN (Task 7), adopt/import migration incl. quiet semantics (Tasks 8–9), Makefile/docs (Task 10). Fatal-line-in-quiet is pinned by `TestRunFatalErrorPrefix` plus adopt/audit `-q` tests asserting errors still surface via exit-code paths.
- **Known wording change:** ad-hoc `warning:` prefixes become the handler's `warn:`; the fatal prefix `sshepherd:` becomes `error:`. All existing tests assert message substrings, which survive; no test asserts the old prefixes.
- **Type consistency check:** `clog.Options{Level, Color, Verbose}`, `clog.NewHandler(w, opts)`, `clog.Enabled(w, mode)`, `clog.ParseColorMode(s)`, `audit.Options.Logger`, `audit.RenderOptions{Color}`, `sshread.Client.Log`, `app{logger, reportColor}`, `fmtDur` — used with these exact names in every task.
