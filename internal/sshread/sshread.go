// Package sshread is the real KeyReader: it connects to a server over SSH
// (agent auth, strict known_hosts) and reads the remote authorized_keys.
// It is deliberately thin — decision logic lives in small pure helpers so the
// unit-test path stays hermetic; only the network glue needs the integration
// suite.
package sshread

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
)

// authorizedKeysCmd reads the default authorized_keys, using a distinctive
// exit code to signal "file does not exist" (vs. cat failing for other
// reasons). The path is fixed — no user input reaches the remote command.
const authorizedKeysCmd = `if [ -e ~/.ssh/authorized_keys ]; then cat ~/.ssh/authorized_keys; else exit 44; fi`

// fileAbsentExit is the sentinel exit status in authorizedKeysCmd.
const fileAbsentExit = 44

// interpretExit maps the remote command's exit status to read semantics.
func interpretExit(code int, stderr string) (fileAbsent bool, err error) {
	switch code {
	case 0:
		return false, nil
	case fileAbsentExit:
		return true, nil
	default:
		return false, fmt.Errorf("remote read failed (exit %d): %s", code, strings.TrimSpace(stderr))
	}
}

// CheckAgent verifies a usable SSH agent before any server is dialed, so a
// missing agent fails once with a clear message instead of once per server.
func CheckAgent(sock string) error {
	if sock == "" {
		return errors.New("no SSH agent: SSH_AUTH_SOCK is not set (start ssh-agent and ssh-add a key)")
	}
	conn, err := net.DialTimeout("unix", sock, 3*time.Second)
	if err != nil {
		return fmt.Errorf("SSH agent unreachable at %s: %w", sock, err)
	}
	_ = conn.Close()
	return nil
}

// hostKeyHint augments knownhosts verification failures with actionable
// remediation. known_hosts entries are keyed by the exact host form used, so
// the hint names the configured host:port verbatim.
func hostKeyHint(err error, srv config.Server, knownHostsPath string) error {
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		return err
	}
	if len(ke.Want) == 0 {
		return fmt.Errorf(
			"%w\n  hint: host is not in %s; if you trust it, run: ssh-keyscan -p %d %s >> %s",
			err, knownHostsPath, srv.Port, srv.Host, knownHostsPath)
	}
	return fmt.Errorf("%w\n  hint: HOST KEY CHANGED for %s:%d — investigate before trusting this host",
		err, srv.Host, srv.Port)
}
