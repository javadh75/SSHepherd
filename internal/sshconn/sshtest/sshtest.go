// Package sshtest runs hermetic, in-process SSH peers for unit tests: an
// x/crypto/ssh server on 127.0.0.1, an agent.NewKeyring served on a unix
// socket, and file-key helpers (Identity, WriteKeyFile) for auth with no
// agent at all. Every goroutine they start is torn down by tb.Cleanup, so the
// goleak TestMain in each consuming package stays green.
package sshtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"os/exec" //nolint:depguard // test-support package, never linked into the binary: ShellHandler stands in for sshd running the command
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/keyfile"
)

// Key returns a deterministic ed25519 private key derived from seed.
func Key(seed byte) ed25519.PrivateKey {
	raw := make([]byte, ed25519.SeedSize)
	for i := range raw {
		raw[i] = seed
	}
	return ed25519.NewKeyFromSeed(raw)
}

// Signer wraps priv as an ssh.Signer, failing tb on error.
func Signer(tb testing.TB, priv any) ssh.Signer {
	tb.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		tb.Fatalf("sshtest: signer: %v", err)
	}
	return s
}

// Fingerprint returns the SHA256 fingerprint of priv's public key.
func Fingerprint(tb testing.TB, priv any) string {
	tb.Helper()
	return ssh.FingerprintSHA256(Signer(tb, priv).PublicKey())
}

// shortDir returns a temp dir with a short absolute path: unix socket paths
// are capped (~104 bytes on macOS) and t.TempDir() embeds the test name.
func shortDir(tb testing.TB) string {
	tb.Helper()
	dir, err := os.MkdirTemp("", "st")
	if err != nil {
		tb.Fatalf("sshtest: mkdtemp: %v", err)
	}
	tb.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// tracker owns a listener's accepted connections and the goroutines serving
// them, so Cleanup can close everything and wait for it.
type tracker struct {
	l     net.Listener
	wg    sync.WaitGroup
	mu    sync.Mutex
	conns []net.Conn
}

func (t *tracker) add(c net.Conn) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.conns = append(t.conns, c)
}

func (t *tracker) close() {
	_ = t.l.Close()
	t.mu.Lock()
	for _, c := range t.conns {
		_ = c.Close()
	}
	t.mu.Unlock()
	t.wg.Wait()
}

// serve accepts until the listener closes, handing each connection to fn on
// a tracked goroutine.
func (t *tracker) serve(fn func(net.Conn)) {
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		for {
			c, err := t.l.Accept()
			if err != nil {
				return
			}
			t.add(c)
			t.wg.Add(1)
			go func() {
				defer t.wg.Done()
				fn(c)
			}()
		}
	}()
}

// Agent serves an in-memory keyring holding keys and returns its socket.
func Agent(tb testing.TB, keys ...any) string {
	tb.Helper()
	added := make([]agent.AddedKey, 0, len(keys))
	for _, k := range keys {
		added = append(added, agent.AddedKey{PrivateKey: k})
	}
	return AgentKeys(tb, added...)
}

// AgentKeys serves an in-memory keyring holding exactly keys (certificates
// included, via AddedKey.Certificate) and returns its socket.
func AgentKeys(tb testing.TB, keys ...agent.AddedKey) string {
	tb.Helper()
	keyring := agent.NewKeyring()
	for _, k := range keys {
		if err := keyring.Add(k); err != nil {
			tb.Fatalf("sshtest: keyring add: %v", err)
		}
	}
	sock := filepath.Join(shortDir(tb), "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		tb.Fatalf("sshtest: listen agent: %v", err)
	}
	tr := &tracker{l: l}
	tb.Cleanup(tr.close)
	tr.serve(func(c net.Conn) {
		_ = agent.ServeAgent(keyring, c) // returns on client close (EOF)
		_ = c.Close()
	})
	return sock
}

// UserCert returns a user certificate for priv's public key, signed by ca,
// valid for principal — an agent-held certificate for tests (servers
// accept it by listing the certificate itself in ServerConfig.Authorized).
func UserCert(tb testing.TB, priv, ca any, principal string) *ssh.Certificate {
	tb.Helper()
	cert := &ssh.Certificate{
		Key:             Signer(tb, priv).PublicKey(),
		CertType:        ssh.UserCert,
		KeyId:           "sshtest",
		ValidPrincipals: []string{principal},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, Signer(tb, ca)); err != nil {
		tb.Fatalf("sshtest: sign cert: %v", err)
	}
	return cert
}

// Identity returns priv as a loaded --identity key named path — file-key
// auth with no agent and no disk.
func Identity(tb testing.TB, path string, priv any) keyfile.Identity {
	tb.Helper()
	s := Signer(tb, priv)
	return keyfile.Identity{Path: path, Fingerprint: ssh.FingerprintSHA256(s.PublicKey()), Signer: s}
}

// WriteKeyFile writes priv as an OpenSSH private key file (mode 0600)
// named name in dir — encrypted with passphrase unless it is nil — plus its
// .pub, and returns the key's path.
func WriteKeyFile(tb testing.TB, dir, name string, priv any, passphrase []byte) string {
	tb.Helper()
	var (
		block *pem.Block
		err   error
	)
	if passphrase == nil {
		block, err = ssh.MarshalPrivateKey(priv, "sshtest")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "sshtest", passphrase)
	}
	if err != nil {
		tb.Fatalf("sshtest: marshal key: %v", err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		tb.Fatalf("sshtest: write key: %v", err)
	}
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(Signer(tb, priv).PublicKey()), 0o600); err != nil {
		tb.Fatalf("sshtest: write pub: %v", err)
	}
	return path
}

// Handler runs one exec request: cmd is the raw command string the client
// sent; the return value is the exit status. ctx is canceled when the
// client closes the channel.
type Handler func(ctx context.Context, cmd string, stdin io.Reader, stdout, stderr io.Writer) int

// ShellHandler runs each command through the local /bin/sh -c with HOME set
// to home — a faithful stand-in for sshd running the command under a POSIX
// login shell, confined to a temp directory.
func ShellHandler(home string) Handler {
	return func(ctx context.Context, cmd string, stdin io.Reader, stdout, stderr io.Writer) int {
		c := exec.CommandContext(ctx, "/bin/sh", "-c", cmd) // #nosec G204 -- test peer runs the client's command by design
		c.Env = []string{"HOME=" + home, "PATH=/usr/bin:/bin"}
		c.Stdin, c.Stdout, c.Stderr = stdin, stdout, stderr
		if err := c.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode()
			}
			return 127
		}
		return 0
	}
}

// ServerConfig shapes a test server.
type ServerConfig struct {
	HostKeys   []ssh.Signer    // presented host keys (certificate signers included)
	Authorized []ssh.PublicKey // keys accepted for login; others are refused
	Handle     Handler         // exec handler; nil exits 0 with no output
	Stall      bool            // accept TCP but never speak SSH

	// AuthorizedKeysFile, when set, replaces Authorized. Every login
	// re-reads this file, as sshd does, so tests see exactly what a write
	// left there. It honors the options the login probe depends on:
	// command= forces the command, and from= must match the client address
	// (comma-separated globs, "!" negates). restrict and every other option
	// are accepted and ignored.
	AuthorizedKeysFile string

	// Forward, when set, handles a direct-tcpip channel (a client tunnelling
	// through this server, ssh -J): it returns the connection to splice the
	// channel to, or nil and the rejection reason. Nil keeps the "session
	// only" rejection.
	Forward func(host string, port uint32) (net.Conn, ssh.RejectionReason)
}

// Server is a running in-process SSH server.
type Server struct {
	Host string
	Port int

	forward func(string, uint32) (net.Conn, ssh.RejectionReason)

	mu       sync.Mutex
	attempts []string
	commands []string
	forwards []string
}

// Addr is the host:port the server listens on.
func (s *Server) Addr() string { return net.JoinHostPort(s.Host, strconv.Itoa(s.Port)) }

// Attempts lists the fingerprints of the public keys clients offered, in
// order.
func (s *Server) Attempts() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.attempts...)
}

// Commands lists the raw exec command strings received, in order.
func (s *Server) Commands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.commands...)
}

// Forwards lists the host:port of every direct-tcpip channel clients asked
// for, in order, as they sent it (unresolved).
func (s *Server) Forwards() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.forwards...)
}

// NewServer starts a server on 127.0.0.1:0 and stops it at tb.Cleanup.
func NewServer(tb testing.TB, cfg ServerConfig) *Server {
	tb.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("sshtest: listen: %v", err)
	}
	s := &Server{Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port, forward: cfg.Forward}
	tr := &tracker{l: l}
	tb.Cleanup(tr.close)

	sc := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) { // #nosec G408 -- test server: the attempt log only observes; the verdict depends on the key and, with AuthorizedKeysFile set, on that file's current lines and the client address (from=)
			fp := ssh.FingerprintSHA256(key)
			s.mu.Lock()
			s.attempts = append(s.attempts, fp)
			s.mu.Unlock()
			if cfg.AuthorizedKeysFile != "" {
				return authorizeFromFile(cfg.AuthorizedKeysFile, meta.RemoteAddr(), key)
			}
			for _, k := range cfg.Authorized {
				if ssh.FingerprintSHA256(k) == fp {
					return &ssh.Permissions{}, nil
				}
			}
			return nil, errRefused
		},
	}
	for _, hk := range cfg.HostKeys {
		sc.AddHostKey(hk)
	}
	tr.serve(func(c net.Conn) {
		if cfg.Stall {
			_, _ = io.Copy(io.Discard, c) // silent peer: returns once Cleanup closes c
			return
		}
		s.serveConn(c, sc, cfg.Handle, &tr.wg)
	})
	return s
}

type refusedError struct{}

func (refusedError) Error() string { return "sshtest: key refused" }

var errRefused = refusedError{}

// authorizeFromFile returns the permissions of the first line in file that
// holds key and whose from= admits remote. Forced commands travel in
// CriticalOptions["force-command"].
func authorizeFromFile(file string, remote net.Addr, key ssh.PublicKey) (*ssh.Permissions, error) {
	data, err := os.ReadFile(file) // #nosec G304 -- test server reads the file the test configured
	if err != nil {
		return nil, errRefused
	}
	host, _, _ := net.SplitHostPort(remote.String())
	want := key.Marshal()
	for len(data) > 0 {
		pub, _, opts, rest, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			break // no further key lines
		}
		data = rest
		if !bytes.Equal(pub.Marshal(), want) {
			continue
		}
		perms, ok := &ssh.Permissions{CriticalOptions: map[string]string{}}, true
		for _, o := range opts {
			name, val, _ := strings.Cut(o, "=")
			if u, err := strconv.Unquote(val); err == nil {
				val = u
			}
			switch strings.ToLower(name) {
			case "command":
				perms.CriticalOptions["force-command"] = val
			case "from":
				ok = ok && fromMatches(val, host)
			}
		}
		if ok {
			return perms, nil
		}
	}
	return nil, errRefused
}

// fromMatches applies an OpenSSH from= pattern list to host: any negated
// match refuses, otherwise at least one plain pattern must match.
func fromMatches(list, host string) bool {
	matched := false
	for _, p := range strings.Split(list, ",") {
		neg := strings.HasPrefix(p, "!")
		if ok, _ := path.Match(strings.TrimPrefix(p, "!"), host); ok {
			if neg {
				return false
			}
			matched = true
		}
	}
	return matched
}

func (s *Server) serveConn(c net.Conn, sc *ssh.ServerConfig, h Handler, wg *sync.WaitGroup) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, sc)
	if err != nil {
		_ = c.Close()
		return
	}
	defer func() { _ = sconn.Close() }()
	forced := ""
	if sconn.Permissions != nil {
		forced = sconn.Permissions.CriticalOptions["force-command"]
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		ssh.DiscardRequests(reqs)
	}()
	for nc := range chans {
		switch {
		case nc.ChannelType() == "direct-tcpip" && s.forward != nil:
			s.serveForward(nc, wg)
			continue
		case nc.ChannelType() != "session":
			_ = nc.Reject(ssh.UnknownChannelType, "session only")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.serveSession(ch, creqs, h, forced, wg)
		}()
	}
}

// forwardMsg is the direct-tcpip open payload (RFC 4254 7.2).
type forwardMsg struct {
	Host     string
	Port     uint32
	OrigHost string
	OrigPort uint32
}

// serveForward records the requested address, asks Forward, and splices
// the channel to the connection it returns until either side ends.
func (s *Server) serveForward(nc ssh.NewChannel, wg *sync.WaitGroup) {
	var m forwardMsg
	if err := ssh.Unmarshal(nc.ExtraData(), &m); err != nil {
		_ = nc.Reject(ssh.ConnectionFailed, "sshtest: bad direct-tcpip payload")
		return
	}
	s.mu.Lock()
	s.forwards = append(s.forwards, net.JoinHostPort(m.Host, strconv.FormatUint(uint64(m.Port), 10)))
	s.mu.Unlock()
	conn, reason := s.forward(m.Host, m.Port)
	if conn == nil {
		_ = nc.Reject(reason, "sshtest: forward refused")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		_ = conn.Close()
		return
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		ssh.DiscardRequests(reqs)
	}()
	go func() {
		defer wg.Done()
		splice(ch, conn)
	}()
}

// splice copies both ways until either side ends, then closes both and
// waits for the other copy.
func splice(ch ssh.Channel, conn net.Conn) {
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(ch, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, ch); done <- struct{}{} }()
	<-done
	_ = ch.Close()
	_ = conn.Close()
	<-done
}

func (s *Server) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, h Handler, forced string, wg *sync.WaitGroup) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		if req.Type != "exec" {
			_ = req.Reply(false, nil)
			continue
		}
		if len(req.Payload) < 4 {
			_ = req.Reply(false, nil)
			continue
		}
		n := binary.BigEndian.Uint32(req.Payload)
		cmd := string(req.Payload[4 : 4+n])
		s.mu.Lock()
		s.commands = append(s.commands, cmd)
		s.mu.Unlock()
		_ = req.Reply(true, nil)
		run := cmd // sshd runs a forced command in place of the client's
		if forced != "" {
			run = forced
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			code := 0
			if h != nil {
				code = h(ctx, run, ch, ch, ch.Stderr())
			}
			status := make([]byte, 4)
			binary.BigEndian.PutUint32(status, uint32(code)) // #nosec G115 -- exit codes are 0..255
			_, _ = ch.SendRequest("exit-status", false, status)
			_ = ch.Close()
		}()
	}
	// reqs closes when the client closes the channel; the deferred cancel
	// then releases a handler still blocked on ctx.
}

// DialForward is a Forward that dials host:port from the test process: a
// bastion that reaches every other test server. The host is resolved here,
// on the "bastion", never by the client.
func DialForward(host string, port uint32) (net.Conn, ssh.RejectionReason) {
	d := net.Dialer{Timeout: 5 * time.Second}
	c, err := d.DialContext(context.Background(), "tcp", net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10)))
	if err != nil {
		return nil, ssh.ConnectionFailed
	}
	return c, 0
}

// ProhibitForward is a Forward that refuses every channel, as sshd does
// with AllowTcpForwarding no or a no-port-forwarding key line.
func ProhibitForward(string, uint32) (net.Conn, ssh.RejectionReason) { return nil, ssh.Prohibited }

// KnownHostsFile writes lines into a fresh known_hosts file and returns its
// path.
func KnownHostsFile(tb testing.TB, lines ...string) string {
	tb.Helper()
	path := filepath.Join(tb.TempDir(), "known_hosts")
	var data []byte
	for _, l := range lines {
		data = append(data, l...)
		data = append(data, '\n')
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		tb.Fatalf("sshtest: write known_hosts: %v", err)
	}
	return path
}

// KnownHostsLine renders the known_hosts line recording key for s.
func (s *Server) KnownHostsLine(key ssh.PublicKey) string {
	return knownhosts.Line([]string{s.Addr()}, key)
}
