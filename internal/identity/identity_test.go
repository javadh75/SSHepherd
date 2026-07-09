package identity

import (
	"strings"
	"testing"
)

func TestExpand(t *testing.T) {
	r := Resolver{Home: "/home/j", LocalUser: "javad"}
	tests := []struct {
		in, want, wantErr string
	}{
		{in: "~", want: "/home/j"},
		{in: "~/.ssh/id_ed25519", want: "/home/j/.ssh/id_ed25519"},
		{in: "%d/.ssh/key", want: "/home/j/.ssh/key"},
		{in: "/keys/%u/id", want: "/keys/javad/id"},
		{in: "/k/100%%", want: "/k/100%"},
		{in: "/abs/plain", want: "/abs/plain"},
		{in: "%h/key", wantErr: "unsupported token %h"},
		{in: "/key%", wantErr: "dangling %"},
	}
	for _, tt := range tests {
		got, err := r.expand(tt.in)
		if tt.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expand(%q) err = %v, want containing %q", tt.in, err, tt.wantErr)
			}
			continue
		}
		if err != nil || got != tt.want {
			t.Errorf("expand(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}
