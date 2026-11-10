package authkeys

import "testing"

// TestForwards: may a key line open a direct-tcpip channel to host:port
// (the forwarding a via: dependent needs through its bastion).
func TestForwards(t *testing.T) {
	for _, tt := range []struct {
		name string
		opts []string
		host string
		want bool
	}{
		{"a plain line", nil, "10.0.1.5", true},
		{"no-port-forwarding", []string{"no-port-forwarding"}, "10.0.1.5", false},
		{"restrict", []string{"restrict"}, "10.0.1.5", false},
		{"restrict re-enabled", []string{"restrict", "port-forwarding"}, "10.0.1.5", true},
		{"permitopen names the dependent", []string{`permitopen="10.0.1.5:22"`}, "10.0.1.5", true},
		{"permitopen names another host", []string{`permitopen="10.0.1.6:22"`}, "10.0.1.5", false},
		{"permitopen names another port", []string{`permitopen="10.0.1.5:2222"`}, "10.0.1.5", false},
		{"permitopen any port", []string{`permitopen="10.0.1.5:*"`}, "10.0.1.5", true},
		{"permitopen any host", []string{`permitopen="*:22"`}, "10.0.1.5", true},
		{"one of two permitopen clauses", []string{`permitopen="10.0.1.6:22"`, `permitopen="10.0.1.5:22"`}, "10.0.1.5", true},
		{"a bracketed IPv6 permitopen", []string{`permitopen="[2001:db8::5]:22"`}, "2001:db8::5", true},
		{"hosts compare literally", []string{`permitopen="WEB.example.com:22"`}, "web.example.com", false},
		{"other restrictions do not matter", []string{"no-pty", "no-agent-forwarding", `from="10.0.0.0/8"`}, "10.0.1.5", true},
		{"option names fold case", []string{"No-Port-Forwarding"}, "10.0.1.5", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := Forwards(tt.opts, tt.host, 22); got != tt.want {
				t.Errorf("Forwards(%q, %s:22) = %v, want %v", tt.opts, tt.host, got, tt.want)
			}
		})
	}
}
