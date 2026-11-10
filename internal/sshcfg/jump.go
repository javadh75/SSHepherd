package sshcfg

import (
	"net"
	"strconv"
	"strings"
)

// JumpHop is one hop of a ProxyJump value, [user@]host[:port]. User is ""
// and Port 0 when the hop names none.
type JumpHop struct {
	User string
	Host string
	Port int
}

// String renders the hop as ProxyJump spells it.
func (h JumpHop) String() string {
	s := h.Host
	if h.Port != 0 {
		s = net.JoinHostPort(h.Host, strconv.Itoa(h.Port))
	}
	if h.User != "" {
		s = h.User + "@" + s
	}
	return s
}

// ParseJump splits a Host.Proxy of "ProxyJump a,b" into its hops in the
// order ssh connects to them, a first. ok is false for a ProxyCommand, an
// empty hop, an ssh:// URI, a bad port or a bracketed address without one,
// or whitespace: import leaves those unmapped and warns (spec S5 Import).
func ParseJump(proxy string) ([]JumpHop, bool) {
	spec, isJump := strings.CutPrefix(proxy, "ProxyJump ")
	if !isJump || spec == "" || strings.ContainsAny(spec, " \t") {
		return nil, false
	}
	var hops []JumpHop
	for _, part := range strings.Split(spec, ",") {
		h, ok := parseHop(part)
		if !ok {
			return nil, false
		}
		hops = append(hops, h)
	}
	return hops, true
}

// parseHop reads one [user@]host[:port]; the user ends at the last '@', as
// ssh reads it.
func parseHop(s string) (JumpHop, bool) {
	if s == "" || strings.Contains(s, "://") {
		return JumpHop{}, false
	}
	var h JumpHop
	if at := strings.LastIndex(s, "@"); at >= 0 {
		h.User, s = s[:at], s[at+1:]
		if h.User == "" {
			return JumpHop{}, false
		}
	}
	h.Host = s
	if host, port, err := net.SplitHostPort(s); err == nil {
		p, perr := strconv.Atoi(port)
		if perr != nil || p < 1 || p > 65535 {
			return JumpHop{}, false
		}
		h.Host, h.Port = host, p
	} else if strings.HasPrefix(s, "[") || strings.Count(s, ":") == 1 {
		return JumpHop{}, false // "[v6]" with no port, "host:", "host:x"
	}
	if h.Host == "" || strings.ContainsAny(h.Host, "/[]") {
		return JumpHop{}, false
	}
	return h, true
}
