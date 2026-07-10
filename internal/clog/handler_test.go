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
		{level: slog.LevelError, emit: slog.LevelWarn, want: false}, // quiet hides warn
		{level: slog.LevelError, emit: slog.LevelError, want: true}, // quiet shows error
		{level: slog.LevelInfo, emit: slog.LevelDebug, want: false}, // normal hides debug
		{level: slog.LevelInfo, emit: slog.LevelInfo, want: true},   // normal shows info
		{level: slog.LevelDebug, emit: slog.LevelDebug, want: true}, // debug shows debug
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
