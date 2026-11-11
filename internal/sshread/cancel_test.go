package sshread

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// silentProxy forwards TCP both ways until silence() is called; from then
// on it drops every byte and leaves both sockets open: a peer that stopped
// answering (a firewall DROP rule, a wedged host).
type silentProxy struct {
	l      net.Listener
	port   int
	quiet  chan struct{}
	once   sync.Once
	wg     sync.WaitGroup
	mu     sync.Mutex
	conns  []net.Conn
	target string
}

func newSilentProxy(t *testing.T, target string) *silentProxy {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &silentProxy{l: l, port: l.Addr().(*net.TCPAddr).Port, quiet: make(chan struct{}), target: target}
	t.Cleanup(func() {
		_ = l.Close()
		p.mu.Lock()
		for _, c := range p.conns {
			_ = c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	p.wg.Add(1)
	go p.accept()
	return p
}

func (p *silentProxy) silence() { p.once.Do(func() { close(p.quiet) }) }

func (p *silentProxy) addr() string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(p.port)) }

func (p *silentProxy) accept() {
	defer p.wg.Done()
	for {
		c, err := p.l.Accept()
		if err != nil {
			return
		}
		up, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", p.target)
		if err != nil {
			_ = c.Close()
			continue
		}
		p.mu.Lock()
		p.conns = append(p.conns, c, up)
		p.mu.Unlock()
		p.wg.Add(2)
		go func() { defer p.wg.Done(); p.pipe(up, c) }()
		go func() { defer p.wg.Done(); p.pipe(c, up) }()
	}
}

// pipe copies src to dst until either ends; once silenced it keeps reading
// and drops everything, so the far side sees no error, only silence.
func (p *silentProxy) pipe(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			select {
			case <-p.quiet:
			default:
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

// blockingHandler signals started on the first command and then blocks
// until its session ends: a read in flight.
func blockingHandler(started chan<- struct{}) sshtest.Handler {
	var once sync.Once
	return func(ctx context.Context, _ string, _ io.Reader, _, _ io.Writer) int {
		once.Do(func() { close(started) })
		<-ctx.Done()
		return 1
	}
}

// TestCancelEndsAReadOnASilentPeer (F011): Ctrl-C ends an in-flight read at
// once even when the peer (or the bastion carrying it) stopped answering.
// Closing the session alone sends a CHANNEL_CLOSE and waits for a reply
// that never comes, so the read used to run on to the socket deadline.
func TestCancelEndsAReadOnASilentPeer(t *testing.T) {
	user := sshtest.Key(1)
	pub := sshtest.Signer(t, user).PublicKey()
	host := sshtest.Signer(t, sshtest.Key(40))
	hopHost := sshtest.Signer(t, sshtest.Key(41))
	for _, tt := range []struct {
		name string
		via  bool
	}{
		{"direct", false},
		{"through a bastion", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			started := make(chan struct{})
			target := sshtest.NewServer(t, sshtest.ServerConfig{
				HostKeys: []ssh.Signer{host}, Authorized: []ssh.PublicKey{pub}, Handle: blockingHandler(started),
			})
			srv := config.Server{Name: "web-1", Host: target.Host, Port: target.Port, User: "deploy"}
			var hopSrv config.Server
			var lines []string
			var proxy *silentProxy
			if tt.via {
				hop := sshtest.NewServer(t, sshtest.ServerConfig{
					HostKeys: []ssh.Signer{hopHost}, Authorized: []ssh.PublicKey{pub}, Forward: sshtest.DialForward,
				})
				proxy = newSilentProxy(t, hop.Addr())
				hopSrv = config.Server{Name: "bastion", Host: "127.0.0.1", Port: proxy.port, User: "jump"}
				srv.Via = "bastion"
				lines = []string{knownhosts.Line([]string{proxy.addr()}, hopHost.PublicKey()), target.KnownHostsLine(host.PublicKey())}
			} else {
				proxy = newSilentProxy(t, target.Addr())
				srv.Port = proxy.port
				lines = []string{knownhosts.Line([]string{proxy.addr()}, host.PublicKey())}
			}
			c := &Client{
				KnownHostsPath: sshtest.KnownHostsFile(t, lines...),
				Creds:          &sshconn.Credentials{AgentSock: sshtest.Agent(t, user)},
				DialTimeout:    5 * time.Second,
				Server: func(name string) (config.Server, bool) {
					return hopSrv, tt.via && name == hopSrv.Name
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			go func() {
				select {
				case <-started:
					proxy.silence()
					time.Sleep(50 * time.Millisecond) // the peer is silent before the interrupt
					cancel()
				case <-ctx.Done():
				}
			}()
			start := time.Now()
			_, err := c.ReadAuthorizedKeys(ctx, srv)
			took := time.Since(start)
			if err == nil {
				t.Fatal("ReadAuthorizedKeys succeeded, want it canceled")
			}
			if got := fleet.ErrorKindOf(err); got != fleet.ErrorKindCanceled {
				t.Errorf("kind = %q, want %q (err: %v)", got, fleet.ErrorKindCanceled, err)
			}
			if took > 2*time.Second {
				t.Errorf("ReadAuthorizedKeys returned %v after start, want within a second of the interrupt", took)
			}
		})
	}
}
