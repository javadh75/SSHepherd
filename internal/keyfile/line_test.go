package keyfile

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestReadLine(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"secret\n", "secret", false},
		{"secret\r\n", "secret", false},
		{"secret", "secret", false},
		{"\n", "", false},
		{"first\nsecond\n", "first", false},
		{strings.Repeat("x", 9), "", true},
	}
	for _, tt := range tests {
		got, err := readLine(strings.NewReader(tt.in), 8)
		if (err != nil) != tt.wantErr || string(got) != tt.want {
			t.Errorf("readLine(%q) = (%q, %v), want (%q, err=%v)", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestReadLineReadError(t *testing.T) {
	if _, err := readLine(io.MultiReader(bytes.NewReader([]byte("ab")), failingReader{}), 8); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want the read error", err)
	}
}

// TestReadLineNoRegrowth pins that a typed passphrase is read into one
// buffer that never grows: append-growth would leave earlier, unzeroed
// copies of the secret behind on the heap.
func TestReadLineNoRegrowth(t *testing.T) {
	in := []byte(strings.Repeat("p", 200) + "\n")
	r := bytes.NewReader(in)
	var line []byte
	allocs := testing.AllocsPerRun(20, func() {
		r.Reset(in)
		var err error
		line, err = readLine(r, 4096)
		if err != nil {
			t.Fatal(err)
		}
	})
	if string(line) != strings.Repeat("p", 200) {
		t.Fatalf("line = %q", line)
	}
	if allocs > 2 { // the line buffer and the one-byte read buffer
		t.Fatalf("readLine allocated %v times for a 200-byte line, want <= 2 (no regrowth)", allocs)
	}
}

func TestReadLineExactlyLimit(t *testing.T) {
	if got, err := readLine(strings.NewReader("12345678\n"), 8); err != nil || string(got) != "12345678" {
		t.Fatalf("readLine(limit bytes) = (%q, %v)", got, err)
	}
}

// TestReadBoundedNoRegrowth pins the same for passphrase and key files.
func TestReadBoundedNoRegrowth(t *testing.T) {
	in := []byte(strings.Repeat("s", 3000))
	r := bytes.NewReader(in)
	var got []byte
	allocs := testing.AllocsPerRun(20, func() {
		r.Reset(in)
		var err error
		got, err = readBounded(r, 4096)
		if err != nil {
			t.Fatal(err)
		}
	})
	if !bytes.Equal(got, in) {
		t.Fatalf("readBounded returned %d bytes, want %d", len(got), len(in))
	}
	if allocs > 1 {
		t.Fatalf("readBounded allocated %v times, want 1 (no regrowth)", allocs)
	}
}

func TestReadBoundedLimit(t *testing.T) {
	if got, err := readBounded(strings.NewReader("12345678"), 8); err != nil || string(got) != "12345678" {
		t.Fatalf("readBounded(limit bytes) = (%q, %v)", got, err)
	}
	if _, err := readBounded(strings.NewReader("123456789"), 8); !errors.Is(err, errTooLarge) {
		t.Fatalf("readBounded(limit+1) err = %v, want errTooLarge", err)
	}
	if _, err := readBounded(io.MultiReader(strings.NewReader("ab"), failingReader{}), 8); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("readBounded read error = %v, want boom", err)
	}
}
