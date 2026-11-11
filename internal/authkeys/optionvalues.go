package authkeys

import (
	"errors"
	"strconv"
	"strings"
)

// The value checks sshd's auth-options.c applies (review F003): a line whose
// value fails one is skipped ("bad key options"), so the manifest refuses
// it and IgnoredBySSHD reports it. Each check takes the dequoted value.

var (
	errPermitOpen   = errors.New("want host:port or host:*, port 1-65535")
	errPermitListen = errors.New("want [host:]port or *, port 1-65535")
	errEnvironment  = errors.New("want NAME=value, NAME of letters, digits and _")
	errTunnel       = errors.New("want a number up to 2147483645 or any")
)

const (
	maxHost   = 1025       // NI_MAXHOST: sshd refuses a host this long or longer
	maxTunnel = 0x7ffffffd // SSH_TUNID_MAX
)

// validPermitOpen is handle_permit for permitopen: host:port or host:*.
func validPermitOpen(v string) error { return permit(v, errPermitOpen) }

// validPermitListen is handle_permit for permitlisten: a value with no ':'
// is a bare port (or *) on any host.
func validPermitListen(v string) error {
	if !strings.Contains(v, ":") {
		v = "*:" + v
	}
	return permit(v, errPermitListen)
}

// permit checks host[:/]port as hpdelim2 splits it (a host in brackets may
// hold ':'), then the port as a2port reads it, or "*".
func permit(v string, want error) error {
	host, port, ok := hostPort(v)
	switch {
	case !ok || len(host) >= maxHost:
		return want
	case port == "*":
		return nil
	}
	return portValue(port, want)
}

// hostPort is hpdelim2: the host ends at the ']' of a bracketed host, else
// at the first ':' or '/'; that delimiter must follow the host, and a value
// with none has no port. ok is false when either part is missing.
func hostPort(v string) (host, port string, ok bool) {
	end := strings.IndexAny(v, ":/")
	if strings.HasPrefix(v, "[") {
		end = strings.IndexByte(v, ']') + 1
		if end == 0 {
			return "", "", false
		}
	}
	if end < 0 || end >= len(v) || (v[end] != ':' && v[end] != '/') {
		return "", "", false
	}
	return v[:end], v[end+1:], true
}

// portValue is a2port's number: 1-65535 as strtonum reads it. a2port then
// tries the name as a service (getservbyname), which only the server's
// /etc/services can answer and sshd's manual does not offer; SSHepherd
// counts a service name as a port sshd cannot read.
func portValue(p string, want error) error {
	if _, ok := strtonum(p, 1, 65535); ok {
		return nil
	}
	return want
}

// validEnvironment is sshd's environment= check: NAME=value, NAME
// non-empty and only ASCII letters, digits and '_' (valid_env_name).
func validEnvironment(v string) error {
	name, _, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return errEnvironment
	}
	for i := 0; i < len(name); i++ {
		if b := name[i]; !isASCIILetter(b) && !isDigit(b) && b != '_' {
			return errEnvironment
		}
	}
	return nil
}

// validTunnel is a2tun: "any" (any case) or a number 0-SSH_TUNID_MAX.
func validTunnel(v string) error {
	if strings.EqualFold(v, "any") {
		return nil
	}
	if _, ok := strtonum(v, 0, maxTunnel); ok {
		return nil
	}
	return errTunnel
}

// strtonum is OpenBSD's strtonum over strtoll in base 10: optional leading
// C whitespace and sign, then digits only; ok when the value fits [lo, hi].
func strtonum(s string, lo, hi int64) (int64, bool) {
	t := strings.TrimLeft(s, " \t\n\v\f\r")
	neg := strings.HasPrefix(t, "-")
	if neg || strings.HasPrefix(t, "+") {
		t = t[1:]
	}
	if t == "" || strings.Trim(t, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, n >= lo && n <= hi
}

func isASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
