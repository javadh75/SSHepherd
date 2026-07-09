package sshcfg

import (
	"reflect"
	"testing"
)

func TestParseLine(t *testing.T) {
	tests := []struct {
		in   string
		key  string
		args []string
		ok   bool
	}{
		{"", "", nil, false},
		{"   \t ", "", nil, false},
		{"# a comment", "", nil, false},
		{"Host web-1", "host", []string{"web-1"}, true},
		{"HOST web-1 web-2", "host", []string{"web-1", "web-2"}, true},
		{"  HostName 10.0.0.1", "hostname", []string{"10.0.0.1"}, true},
		{"HostName=example.com", "hostname", []string{"example.com"}, true},
		{"Port = 2222", "port", []string{"2222"}, true},
		{"User \"deploy user\"", "user", []string{"deploy user"}, true},
		{"Host \"web 1\" web-2", "host", []string{"web 1", "web-2"}, true},
		{"IdentityFile ~/.ssh/id_ed25519", "identityfile", []string{"~/.ssh/id_ed25519"}, true},
		{"Host", "host", nil, true},                       // keyword with no args: caller warns
		{"Host web-1\r", "host", []string{"web-1"}, true}, // CRLF input
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			key, args, ok := parseLine(tt.in)
			if key != tt.key || ok != tt.ok || !reflect.DeepEqual(args, tt.args) {
				t.Errorf("parseLine(%q) = (%q, %v, %v), want (%q, %v, %v)",
					tt.in, key, args, ok, tt.key, tt.args, tt.ok)
			}
		})
	}
}
