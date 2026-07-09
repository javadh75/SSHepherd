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

// maxRemoteOutput caps how much remote stdout/stderr is buffered (1 MiB).
// authorized_keys files are tiny; anything larger is hostile or broken.
const maxRemoteOutput = 1 << 20

// interpretExit maps the remote command's exit status to read semantics.
// Remote stderr is sanitized before it is embedded in an error message.
func interpretExit(code int, stderr string) (fileAbsent bool, err error) {
	switch code {
	case 0:
		return false, nil
	case fileAbsentExit:
		return true, nil
	default:
		return false, fmt.Errorf("remote read failed (exit %d): %s", code, strings.TrimSpace(sanitizeRemote(stderr)))
	}
}

// sanitizeRemote strips control bytes (except newline and tab) from
// remote-controlled text so a malicious host cannot inject terminal escape
// sequences into operator-facing error messages.
func sanitizeRemote(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' {
			return -1
		}
		return r
	}, s)
}

// cappedBuffer buffers writes up to limit bytes, silently discards the rest,
// and flags that truncation happened. Write never fails: the remote session
// should still finish and report its exit status even when output is
// oversized; the caller decides what truncation means.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.limit - b.buf.Len(); room > 0 {
		if n > room {
			p = p[:room]
			b.truncated = true
		}
		b.buf.Write(p)
	} else if n > 0 {
		b.truncated = true
	}
	return n, nil
}

func (b *cappedBuffer) String() string { return b.buf.String() }
func (b *cappedBuffer) Bytes() []byte  { return b.buf.Bytes() }

// CheckAgent verifies a usable SSH agent before any server is dialed, so a
// missing agent fails once with a clear message instead of once per server.
func CheckAgent(sock string) error {
	if sock == "" {
		return errors.New("no SSH agent: SSH_AUTH_SOCK is not set (start ssh-agent and ssh-add a key)")
	}
	dialer := net.Dialer{Timeout: 3 * time.Second}
	conn, err := dialer.DialContext(context.Background(), "unix", sock)
	if err != nil {
		return fmt.Errorf("SSH agent unreachable at %s: %w", sock, err)
	}
	_ = conn.Close()
	return nil
}

// hostKeyHint augments knownhosts verification failures with actionable
// remediation, using the key the server actually presented to tell a
// genuinely changed key apart from a merely unrecorded key type. known_hosts
// entries are keyed by the exact host form used, so hints name the configured
// host:port verbatim. Unrelated errors pass through untouched.
func hostKeyHint(err error, presented ssh.PublicKey, srv config.Server, knownHostsPath string) error {
	var ke *knownhosts.KeyError
	if !errors.As(err, &ke) {
		return err
	}
	if presented != nil {
		err = fmt.Errorf("presented %s key %s: %w", presented.Type(), ssh.FingerprintSHA256(presented), err)
	}
	if len(ke.Want) == 0 {
		return fmt.Errorf(
			"%w\n  hint: host is not in %s; if you trust it, run: ssh-keyscan -p %d %s >> %s",
			err, knownHostsPath, srv.Port, srv.Host, knownHostsPath)
	}
	if presented != nil && !typeRecorded(ke, presented.Type()) {
		return fmt.Errorf(
			"%w\n  hint: host key type %s is not recorded in known_hosts for this host (recorded: %s); if the host is healthy, re-run ssh-keyscan to record all key types",
			err, presented.Type(), strings.Join(recordedTypes(ke), ", "))
	}
	return fmt.Errorf("%w\n  hint: HOST KEY CHANGED for %s:%d — investigate before trusting this host",
		err, srv.Host, srv.Port)
}

// typeRecorded reports whether known_hosts already records a key of the
// presented type for this host.
func typeRecorded(ke *knownhosts.KeyError, keyType string) bool {
	for _, k := range ke.Want {
		if k.Key != nil && k.Key.Type() == keyType {
			return true
		}
	}
	return false
}

// recordedTypes lists the distinct key types known_hosts records for the host.
func recordedTypes(ke *knownhosts.KeyError) []string {
	var types []string
	seen := make(map[string]bool)
	for _, k := range ke.Want {
		if k.Key == nil || seen[k.Key.Type()] {
			continue
		}
		seen[k.Key.Type()] = true
		types = append(types, k.Key.Type())
	}
	return types
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
// by the audit orchestrator) bounds the whole exchange — agent I/O, dial,
// handshake, and session — not just the dial. Callers without a ctx deadline
// still get a hard bound: 3×DialTimeout (30s when DialTimeout is zero).
func (c *Client) ReadAuthorizedKeys(ctx context.Context, srv config.Server) (audit.ReadResult, error) {
	var zero audit.ReadResult

	if _, ok := ctx.Deadline(); !ok {
		fallback := 3 * c.DialTimeout
		if fallback <= 0 {
			fallback = 30 * time.Second
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, fallback)
		defer cancel()
	}
	dl, _ := ctx.Deadline() // always present: the floor above guarantees it

	agentDialer := net.Dialer{}
	agentConn, err := agentDialer.DialContext(ctx, "unix", c.AgentSock)
	if err != nil {
		return zero, fmt.Errorf("connect ssh-agent: %w", err)
	}
	defer func() { _ = agentConn.Close() }() // errcheck: close error is uninteresting on a read path
	_ = agentConn.SetDeadline(dl)            // ag.Signers does I/O mid-handshake; a wedged agent must not hang a worker
	ag := agent.NewClient(agentConn)

	hostKeys, err := knownhosts.New(c.KnownHostsPath)
	if err != nil {
		return zero, fmt.Errorf("load known_hosts %s: %w", c.KnownHostsPath, err)
	}
	// Wrap the strict callback so verification failures carry the key the
	// server actually presented — hostKeyHint needs it to tell a changed key
	// apart from an unrecorded key type.
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if khErr := hostKeys(hostname, remote, key); khErr != nil {
			return hostKeyHint(khErr, key, srv, c.KnownHostsPath)
		}
		return nil
	}

	addr := net.JoinHostPort(srv.Host, strconv.Itoa(srv.Port))
	dialer := net.Dialer{Timeout: c.DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return zero, fmt.Errorf("dial %s: %w", addr, err)
	}
	_ = conn.SetDeadline(dl) // bounds handshake + session I/O, not just dial

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:            srv.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeysCallback(ag.Signers)},
		HostKeyCallback: cb,
	})
	if err != nil {
		_ = conn.Close()
		return zero, fmt.Errorf("ssh %s@%s: %w", srv.User, addr, err)
	}
	client := ssh.NewClient(sshConn, chans, reqs)
	defer func() { _ = client.Close() }()

	return readRemote(client, addr)
}

// readRemote runs the read command over an established SSH connection and
// maps its output and exit status to a ReadResult.
func readRemote(client *ssh.Client, addr string) (audit.ReadResult, error) {
	var zero audit.ReadResult

	sess, err := client.NewSession()
	if err != nil {
		return zero, fmt.Errorf("open session on %s: %w", addr, err)
	}
	defer func() { _ = sess.Close() }()

	stdout := &cappedBuffer{limit: maxRemoteOutput}
	stderr := &cappedBuffer{limit: maxRemoteOutput}
	sess.Stdout = stdout
	sess.Stderr = stderr

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
	if stdout.truncated {
		// A truncated authorized_keys must never be diffed as truth: missing
		// tail keys would be misreported as drift.
		return zero, fmt.Errorf("remote read on %s: remote output exceeded 1MiB — refusing to audit a truncated authorized_keys", addr)
	}
	if absent {
		return audit.ReadResult{FileAbsent: true}, nil
	}
	return audit.ReadResult{Content: stdout.Bytes()}, nil
}
