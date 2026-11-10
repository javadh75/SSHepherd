package authkeys

import (
	"strconv"
	"strings"
)

// Forwards reports whether a key line with these options lets its session
// open a direct-tcpip channel to host:port, the ssh -J that a via: server
// relies on (spec S5): no no-port-forwarding, no restrict unless
// port-forwarding re-enables it, and, when the line carries permitopen=
// clauses, one names that host (or "*") and that port (or "*"). Hosts
// compare as sshd compares them: literally, with no patterns and no name
// lookup.
func Forwards(opts []string, host string, port int) bool {
	restricted, reenabled := false, false
	var permits []string
	for _, o := range opts {
		switch nameOf(o) {
		case "no-port-forwarding":
			return false
		case "restrict":
			restricted = true
		case "port-forwarding":
			reenabled = true
		case "permitopen":
			_, v, _ := strings.Cut(o, "=")
			permits = append(permits, strings.Trim(v, `"`))
		}
	}
	if restricted && !reenabled {
		return false
	}
	if len(permits) == 0 {
		return true
	}
	for _, p := range permits {
		if permitMatches(p, host, port) {
			return true
		}
	}
	return false
}

// permitMatches reports whether one permitopen="host:port" admits
// host:port; an IPv6 host is bracketed.
func permitMatches(spec, host string, port int) bool {
	h, p, ok := cutPermit(spec)
	return ok && (h == "*" || h == host) && (p == "*" || p == strconv.Itoa(port))
}

// cutPermit splits a permitopen= value into host and port: "[v6]:port" or
// "host:port".
func cutPermit(spec string) (host, port string, ok bool) {
	if rest, bracketed := strings.CutPrefix(spec, "["); bracketed {
		return strings.Cut(rest, "]:")
	}
	i := strings.LastIndex(spec, ":")
	if i < 0 {
		return "", "", false
	}
	return spec[:i], spec[i+1:], true
}
