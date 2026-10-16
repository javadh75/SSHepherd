package sshconn

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/audit"
	"github.com/javadh75/SSHepherd/internal/keyfile"
)

// SourceAgent is HeldKey.Source for a key the ssh-agent holds.
const SourceAgent = "agent"

// agentTimeout bounds agent I/O when the caller's ctx has no deadline.
const agentTimeout = 3 * time.Second

// HeldKey is one plain key the run can authenticate with: its SHA256
// fingerprint and where it comes from — the --identity path, or
// SourceAgent.
type HeldKey struct {
	Fingerprint string
	Source      string
}

// Label renders the key with its source, as refusals list it:
// "SHA256:… (/home/op/.ssh/ci)" or "SHA256:… (agent)".
func (k HeldKey) Label() string { return k.Fingerprint + " (" + k.Source + ")" }

// Credentials is the run's one credential source, shared by the read
// client, the writer and the login probe: --identity key files (in flag
// order) in union with the ssh-agent at AgentSock ("" = no agent), like
// ssh -i. Use it by pointer: the degraded-agent warning is logged once per
// run across Signers and Held.
type Credentials struct {
	Files     []keyfile.Identity
	AgentSock string
	Log       *slog.Logger // optional; nil discards

	warnOnce sync.Once
}

func (c *Credentials) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.DiscardHandler)
}

// warnAgent logs the one-time "agent unusable, continuing with key files"
// warning. Only called when key files are present.
func (c *Credentials) warnAgent(err error) {
	c.warnOnce.Do(func() {
		c.log().Warn(fmt.Sprintf("ssh-agent unusable (%v) — continuing with the --identity keys only", err))
	})
}

// dialAgent connects to the agent with ctx's deadline (or agentTimeout)
// applied to the socket, so a wedged agent cannot hang a worker. A dial
// error is returned unwrapped; callers phrase it (Signers and Held keep
// their pre---identity wordings).
func (c *Credentials) dialAgent(ctx context.Context) (agent.ExtendedAgent, net.Conn, error) {
	if c.AgentSock == "" {
		return nil, nil, errors.New("no SSH agent: SSH_AUTH_SOCK is not set")
	}
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(agentTimeout)
	}
	d := net.Dialer{Deadline: dl}
	conn, err := d.DialContext(ctx, "unix", c.AgentSock)
	if err != nil {
		return nil, nil, err //nolint:wrapcheck // wrapped by the caller with its own wording
	}
	_ = conn.SetDeadline(dl)
	return agent.NewClient(conn), conn, nil
}

// fileSigners returns the key-file signers in flag order, de-duplicated by
// fingerprint, and the set of their fingerprints.
func (c *Credentials) fileSigners() ([]ssh.Signer, map[string]bool) {
	out := make([]ssh.Signer, 0, len(c.Files))
	seen := make(map[string]bool, len(c.Files))
	for _, id := range c.Files {
		fp := ssh.FingerprintSHA256(id.Signer.PublicKey())
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, id.Signer)
	}
	return out, seen
}

// Signers returns every signer to offer, in order: key files (flag order),
// then agent signers in the agent's own order (certificates included, where
// the agent lists them — exactly the pre---identity offer), de-duplicated by fingerprint (the file signer wins). The closer releases
// the agent connection, which agent signers sign through: keep it open
// until the handshake is over. Agent failure with key files present is
// logged once and the file signers are returned; with no key files it is
// an ErrorKindAgent error, as before this slice.
func (c *Credentials) Signers(ctx context.Context) ([]ssh.Signer, func(), error) {
	noop := func() {}
	out, seen := c.fileSigners()
	if c.AgentSock == "" && len(out) > 0 {
		return out, noop, nil // no agent configured: nothing to warn about
	}
	ag, conn, err := c.dialAgent(ctx)
	if err != nil && c.AgentSock != "" {
		err = fmt.Errorf("connect ssh-agent: %w", err) // ConnectWith's wording before this slice
	}
	if err == nil {
		var signers []ssh.Signer
		signers, err = ag.Signers()
		if err != nil {
			_ = conn.Close()
			err = fmt.Errorf("agent signers: %w", err)
		} else {
			closer := func() { _ = conn.Close() }
			return appendAgentSigners(out, seen, signers), closer, nil
		}
	}
	if len(out) == 0 {
		return nil, noop, classify(audit.ErrorKindAgent, err)
	}
	c.warnAgent(err)
	return out, noop, nil
}

// appendAgentSigners appends the agent's signers in agent order,
// skipping fingerprints already offered (a key file wins).
func appendAgentSigners(out []ssh.Signer, seen map[string]bool, signers []ssh.Signer) []ssh.Signer {
	for _, s := range signers {
		fp := ssh.FingerprintSHA256(s.PublicKey())
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, s)
	}
	return out
}

// isCert reports whether pub is a certificate. Agent keys arrive as
// *agent.Key whatever their type, so the wire form is re-parsed.
func isCert(pub ssh.PublicKey) bool {
	parsed, err := ssh.ParsePublicKey(pub.Marshal())
	if err != nil {
		return false
	}
	_, ok := parsed.(*ssh.Certificate)
	return ok
}

// Held lists the plain keys of the current union with their sources — the
// self-lockout guard's and the login probe's ground truth. Agent
// certificates are excluded: they log in through cert-authority lines,
// which the guard cannot prove survive. The agent is re-listed on every
// call, so the post-prompt re-check sees keys that expired meanwhile.
// Agent failure with key files present returns the file keys with a nil
// error (agent keys simply stop counting — fail-safe) and the one-time
// warning; with no key files it is returned.
func (c *Credentials) Held(ctx context.Context) ([]HeldKey, error) {
	var held []HeldKey
	seen := make(map[string]bool, len(c.Files))
	for _, id := range c.Files {
		fp := ssh.FingerprintSHA256(id.Signer.PublicKey())
		if !seen[fp] {
			seen[fp] = true
			held = append(held, HeldKey{Fingerprint: fp, Source: id.Path})
		}
	}
	if c.AgentSock == "" && len(held) > 0 {
		return held, nil
	}
	keys, err := c.listAgent(ctx)
	if err != nil {
		if len(held) == 0 {
			return nil, err
		}
		c.warnAgent(err)
		return held, nil
	}
	for _, k := range keys {
		if isCert(k) {
			continue
		}
		fp := ssh.FingerprintSHA256(k)
		if !seen[fp] {
			seen[fp] = true
			held = append(held, HeldKey{Fingerprint: fp, Source: SourceAgent})
		}
	}
	return held, nil
}

// listAgent lists the agent's keys over one short-lived connection.
func (c *Credentials) listAgent(ctx context.Context) ([]*agent.Key, error) {
	ag, conn, err := c.dialAgent(ctx)
	if err != nil {
		if c.AgentSock != "" {
			err = fmt.Errorf("SSH agent unreachable at %s: %w", c.AgentSock, err) // AgentFingerprints' wording before this slice
		}
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	keys, err := ag.List()
	if err != nil {
		return nil, fmt.Errorf("list SSH agent keys at %s: %w", c.AgentSock, err)
	}
	return keys, nil
}
