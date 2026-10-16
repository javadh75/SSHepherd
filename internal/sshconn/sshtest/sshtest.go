// Package sshtest runs hermetic, in-process SSH peers for unit tests: an
// x/crypto/ssh server on 127.0.0.1, an agent.NewKeyring served on a unix
// socket, and file-key helpers (Identity, WriteKeyFile) for auth with no
// agent at all. Every goroutine they start is torn down by tb.Cleanup, so the
// goleak TestMain in each consuming package stays green.
package sshtest

import (
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
	"path/filepath"
	"strconv"
	"sync"
	"testing"

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
}

// Server is a running in-process SSH server.
type Server struct {
	Host string
	Port int

	mu       sync.Mutex
	attempts []string
	commands []string
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

// NewServer starts a server on 127.0.0.1:0 and stops it at tb.Cleanup.
func NewServer(tb testing.TB, cfg ServerConfig) *Server {
	tb.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("sshtest: listen: %v", err)
	}
	s := &Server{Host: "127.0.0.1", Port: l.Addr().(*net.TCPAddr).Port}
	tr := &tracker{l: l}
	tb.Cleanup(tr.close)

	sc := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) { // #nosec G408 -- test server: the attempt log only observes; the verdict depends on the key alone
			fp := ssh.FingerprintSHA256(key)
			s.mu.Lock()
			s.attempts = append(s.attempts, fp)
			s.mu.Unlock()
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

func (s *Server) serveConn(c net.Conn, sc *ssh.ServerConfig, h Handler, wg *sync.WaitGroup) {
	sconn, chans, reqs, err := ssh.NewServerConn(c, sc)
	if err != nil {
		_ = c.Close()
		return
	}
	defer func() { _ = sconn.Close() }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		ssh.DiscardRequests(reqs)
	}()
	for nc := range chans {
		if nc.ChannelType() != "session" {
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
			s.serveSession(ch, creqs, h, wg)
		}()
	}
}

func (s *Server) serveSession(ch ssh.Channel, reqs <-chan *ssh.Request, h Handler, wg *sync.WaitGroup) {
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
		wg.Add(1)
		go func() {
			defer wg.Done()
			code := 0
			if h != nil {
				code = h(ctx, cmd, ch, ch, ch.Stderr())
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
