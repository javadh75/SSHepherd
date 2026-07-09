// Package sshread is the real KeyReader: it connects to a server over SSH
// (agent auth, strict known_hosts) and reads the remote authorized_keys.
// It is deliberately thin — decision logic lives in small pure helpers so the
// unit-test path stays hermetic; only the network glue needs the integration
// suite.
package sshread

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/audit"
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

// Client reads remote authorized_keys over SSH. It implements audit.KeyReader.
type Client struct {
	KnownHostsPath string
	AgentSock      string
	DialTimeout    time.Duration
}

var _ audit.KeyReader = (*Client)(nil)

// ReadAuthorizedKeys connects to srv (agent auth, strict known_hosts) and
// reads ~/.ssh/authorized_keys via a one-shot session. The ctx deadline (set
// by the audit orchestrator) bounds the whole exchange, not just the dial.
func (c *Client) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (audit.ReadResult, error) {
	var zero audit.ReadResult

	agentConn, err := net.Dial("unix", c.AgentSock)
	if err != nil {
		return zero, fmt.Errorf("connect ssh-agent: %w", err)
	}
	defer func() { _ = agentConn.Close() }() // errcheck: close error is uninteresting on a read path
	ag := agent.NewClient(agentConn)

	hostKeys, err := knownhosts.New(c.KnownHostsPath)
	if err != nil {
		return zero, fmt.Errorf("load known_hosts %s: %w", c.KnownHostsPath, err)
	}

	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	dialer := net.Dialer{Timeout: c.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return zero, fmt.Errorf("dial %s: %w", addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl) // bounds handshake + session I/O, not just dial
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            srv.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)},
		HostKeyCallback: hostKeys,
		Timeout:         c.DialTimeout,
	})
	if err != nil {
		_ = conn.Close()
		return zero, fmt.Errorf("ssh %s@%s: %w", srv.User, addr, hostKeyHint(err, srv, c.KnownHostsPath))
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() { _ = client.Close() }()

	sess, err := client.NewSession()
	if err != nil {
		return zero, fmt.Errorf("open session on %s: %w", addr, err)
	}
	defer func() { _ = sess.Close() }()

	var stdout, stderr bytes.Buffer
	sess.Stdout = &stdout
	sess.Stderr = &stderr

	code := 0
	if runErr := sess.Run(authorizedKeysCmd); runErr != nil {
		var exitErr *ssh.ExitError
		if !errors.As(runErr, &exitErr) {
			return zero, fmt.Errorf("remote read on %s: %w", addr, runErr)
		}
		code = exitErr.ExitStatus()
	}
	absent, err := interpretExit(code, stderr.String())
	if err != nil {
		return zero, fmt.Errorf("remote read on %s: %w", addr, err)
	}
	if absent {
		return audit.ReadResult{FileAbsent: true}, nil
	}
	return audit.ReadResult{Content: stdout.Bytes()}, nil
}
