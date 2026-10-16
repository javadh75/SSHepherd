package keyfile

import (
	"errors"
	"fmt"
	"io"
)

// readLine reads one line byte by byte (a terminal in canonical mode hands
// over whole lines; byte reads never consume past the newline), dropping
// the newline and one trailing \r. More than limit bytes is an error, with
// what was read wiped. The line buffer is allocated once at its full
// capacity and never regrows, so no stale copy of the passphrase is left
// for the caller's clear() to miss.
func readLine(r io.Reader, limit int) ([]byte, error) {
	line := make([]byte, 0, limit)
	b := make([]byte, 1)
	for {
		n, err := r.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			if len(line) >= limit {
				clear(line[:cap(line)])
				return nil, fmt.Errorf("passphrase longer than %d bytes", limit)
			}
			line = append(line, b[0])
			continue
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			clear(line[:cap(line)])
			return nil, fmt.Errorf("read passphrase: %w", err)
		}
	}
	if n := len(line); n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line, nil
}
