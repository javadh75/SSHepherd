package sshcfg

import (
	"slices"
	"testing"
)

func TestParseJump(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want []JumpHop
		ok   bool
	}{
		{"ProxyJump bastion", []JumpHop{{Host: "bastion"}}, true},
		{"ProxyJump jump@bastion.example.com:2200,inner", []JumpHop{{User: "jump", Host: "bastion.example.com", Port: 2200}, {Host: "inner"}}, true},
		{"ProxyJump [2001:db8::1]:22", []JumpHop{{Host: "2001:db8::1", Port: 22}}, true},
		{"ProxyJump 2001:db8::1", []JumpHop{{Host: "2001:db8::1"}}, true},
		{"ProxyJump a@b@c", []JumpHop{{User: "a@b", Host: "c"}}, true},
		{"ProxyCommand nc %h %p", nil, false},
		{"ProxyJump ssh://jump@bastion:22", nil, false},
		{"ProxyJump a,,b", nil, false},
		{"ProxyJump @bastion", nil, false},
		{"ProxyJump bastion:", nil, false},
		{"ProxyJump bastion:99999", nil, false},
		{"ProxyJump [::1]", nil, false},
		{"ProxyJump ", nil, false},
		{"", nil, false},
	} {
		got, ok := ParseJump(tt.in)
		if ok != tt.ok || !slices.Equal(got, tt.want) {
			t.Errorf("ParseJump(%q) = %+v, %v; want %+v, %v", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}

func TestJumpHopString(t *testing.T) {
	for _, tt := range []struct {
		hop  JumpHop
		want string
	}{
		{JumpHop{Host: "a"}, "a"},
		{JumpHop{User: "u", Host: "a", Port: 2200}, "u@a:2200"},
		{JumpHop{Host: "::1", Port: 22}, "[::1]:22"},
	} {
		if got := tt.hop.String(); got != tt.want {
			t.Errorf("%+v.String() = %q, want %q", tt.hop, got, tt.want)
		}
	}
}
