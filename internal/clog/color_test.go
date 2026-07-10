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
