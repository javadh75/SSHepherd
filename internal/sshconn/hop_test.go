package sshconn

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// hopFixture: a bastion that forwards (DialForward) and a target, both
// accepting key 1 from the agent; known_hosts records both; the Dialer
// resolves "bastion".
type hopFixture struct {
	hop, target       *sshtest.Server
	hopSrv, targetSrv config.Server
	hopKey, targetKey ssh.Signer
	agent, kh         string
}

func newHopFixture(t *testing.T, hopCfg, targetCfg sshtest.ServerConfig) hopFixture {
	t.Helper()
	pub := sshtest.Signer(t, sshtest.Key(1)).PublicKey()
	f := hopFixture{hopKey: sshtest.Signer(t, sshtest.Key(40)), targetKey: sshtest.Signer(t, sshtest.Key(41))}
	if hopCfg.HostKeys == nil {
		hopCfg.HostKeys = []ssh.Signer{f.hopKey}
	}
	if hopCfg.Authorized == nil {
		hopCfg.Authorized = []ssh.PublicKey{pub}
	}
	if hopCfg.Forward == nil {
		hopCfg.Forward = sshtest.DialForward
	}
	if targetCfg.HostKeys == nil {
		targetCfg.HostKeys = []ssh.Signer{f.targetKey}
	}
	if targetCfg.Authorized == nil {
		targetCfg.Authorized = []ssh.PublicKey{pub}
	}
	f.hop, f.target = sshtest.NewServer(t, hopCfg), sshtest.NewServer(t, targetCfg)
	f.hopSrv = config.Server{Name: "bastion", Host: f.hop.Host, Port: f.hop.Port, User: "jump"}
	f.targetSrv = config.Server{Name: "web-1", Host: f.target.Host, Port: f.target.Port, User: "deploy", Via: "bastion"}
	f.agent = sshtest.Agent(t, sshtest.Key(1))
	f.kh = sshtest.KnownHostsFile(t, f.hop.KnownHostsLine(f.hopKey.PublicKey()), f.target.KnownHostsLine(f.targetKey.PublicKey()))
	return f
}

func (f hopFixture) dialer() *Dialer {
	return &Dialer{KnownHostsPath: f.kh, Creds: &Credentials{AgentSock: f.agent}, DialTimeout: 5 * time.Second,
		Server: func(name string) (config.Server, bool) {
			if name == f.hopSrv.Name {
				return f.hopSrv, true
			}
			return config.Server{}, false
		}}
}

// TestConnectThroughHop: the target is reached over a direct-tcpip channel
// the bastion opened; the bastion runs nothing; Close tears both down.
func TestConnectThroughHop(t *testing.T) {
	f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{Handle: sshtest.ShellHandler(t.TempDir())})
	conn, err := f.dialer().Connect(ctxTimeout(t, 10*time.Second), f.targetSrv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	code, stdout, _, err := Exec(context.Background(), conn.Client, `echo through`, nil)
	if err != nil {
		t.Fatalf("Exec: %v", err) // stdout is nil on error
	}
	if code != 0 || stdout.String() != "through\n" {
		t.Fatalf("Exec = (%d, %q)", code, stdout.String())
	}
	if err := conn.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if got := f.hop.Forwards(); !slices.Equal(got, []string{f.target.Addr()}) {
		t.Errorf("bastion forwards = %v, want [%s]", got, f.target.Addr())
	}
	if cmds := f.hop.Commands(); len(cmds) != 0 {
		t.Errorf("the bastion ran %q; a hop runs nothing", cmds)
	}
}

// chainFixture puts an outer bastion "edge" in front of the hopFixture's
// bastion (bastion via: edge), so web-1 is two bastions deep.
type chainFixture struct {
	hopFixture
	edge    *sshtest.Server
	edgeSrv config.Server
	edgeKey ssh.Signer
}

func newChainFixture(t *testing.T, edgeCfg sshtest.ServerConfig) chainFixture {
	t.Helper()
	c := chainFixture{hopFixture: newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{Handle: sshtest.ShellHandler(t.TempDir())}),
		edgeKey: sshtest.Signer(t, sshtest.Key(43))}
	if edgeCfg.HostKeys == nil {
		edgeCfg.HostKeys = []ssh.Signer{c.edgeKey}
	}
	edgeCfg.Authorized = []ssh.PublicKey{sshtest.Signer(t, sshtest.Key(1)).PublicKey()}
	edgeCfg.Forward = sshtest.DialForward
	c.edge = sshtest.NewServer(t, edgeCfg)
	c.edgeSrv = config.Server{Name: "edge", Host: c.edge.Host, Port: c.edge.Port, User: "ops"}
	c.hopSrv.Via = "edge"
	c.kh = sshtest.KnownHostsFile(t, c.edge.KnownHostsLine(c.edgeKey.PublicKey()),
		c.hop.KnownHostsLine(c.hopKey.PublicKey()), c.target.KnownHostsLine(c.targetKey.PublicKey()))
	return c
}

func (c chainFixture) dialer() *Dialer {
	d := c.hopFixture.dialer()
	d.Server = func(name string) (config.Server, bool) {
		switch name {
		case c.hopSrv.Name:
			return c.hopSrv, true
		case c.edgeSrv.Name:
			return c.edgeSrv, true
		}
		return config.Server{}, false
	}
	return d
}

// TestConnectThroughTwoBastions: a chain is walked hop by hop: the outer
// bastion forwards only to the inner one, the inner one only to the target,
// and neither runs anything.
func TestConnectThroughTwoBastions(t *testing.T) {
	c := newChainFixture(t, sshtest.ServerConfig{})
	conn, err := c.dialer().Connect(ctxTimeout(t, 10*time.Second), c.targetSrv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	code, stdout, _, err := Exec(context.Background(), conn.Client, `echo deep`, nil)
	if err != nil {
		t.Fatalf("Exec: %v", err)
	}
	if code != 0 || stdout.String() != "deep\n" {
		t.Fatalf("Exec = (%d, %q)", code, stdout.String())
	}
	if err := conn.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if got := c.edge.Forwards(); !slices.Equal(got, []string{c.hop.Addr()}) {
		t.Errorf("edge forwards = %v, want only the inner bastion [%s]", got, c.hop.Addr())
	}
	if got := c.hop.Forwards(); !slices.Equal(got, []string{c.target.Addr()}) {
		t.Errorf("bastion forwards = %v, want [%s]", got, c.target.Addr())
	}
	if cmds := append(c.edge.Commands(), c.hop.Commands()...); len(cmds) != 0 {
		t.Errorf("a bastion ran %q; a hop runs nothing", cmds)
	}
}

// TestConnectChainOuterFailure: a failure at the outer bastion names it as
// the failed hop, keeps its kind, and reaches neither the inner bastion nor
// the target.
func TestConnectChainOuterFailure(t *testing.T) {
	c := newChainFixture(t, sshtest.ServerConfig{})
	c.kh = sshtest.KnownHostsFile(t, c.edge.KnownHostsLine(sshtest.Signer(t, sshtest.Key(42)).PublicKey()),
		c.hop.KnownHostsLine(c.hopKey.PublicKey()), c.target.KnownHostsLine(c.targetKey.PublicKey()))
	_, err := c.dialer().Connect(ctxTimeout(t, 5*time.Second), c.targetSrv)
	if kindOf(t, err) != fleet.ErrorKindHostKeyChanged || fleet.FailedHopOf(err) != "edge" {
		t.Fatalf("err = %v (kind %q, hop %q), want host_key_changed at edge", err, kindOf(t, err), fleet.FailedHopOf(err))
	}
	if !strings.HasPrefix(err.Error(), "via bastion: via edge: ") {
		t.Errorf("error = %q, want both hops named outermost last", err)
	}
	if len(c.hop.Attempts())+len(c.target.Attempts()) != 0 {
		t.Error("the chain went past a failed outer bastion")
	}
}

// TestConnectThroughHopPassesHostnameToBastion: DNS for the target is the
// bastion's: the client sends the hostname unresolved (spec S5, fact 3).
func TestConnectThroughHopPassesHostnameToBastion(t *testing.T) {
	f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
	f.targetSrv.Host = "localhost"
	addr := net.JoinHostPort("localhost", strconv.Itoa(f.target.Port))
	f.kh = sshtest.KnownHostsFile(t, f.hop.KnownHostsLine(f.hopKey.PublicKey()), knownhosts.Line([]string{addr}, f.targetKey.PublicKey()))
	conn, err := f.dialer().Connect(ctxTimeout(t, 10*time.Second), f.targetSrv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	_ = conn.Close()
	if got := f.hop.Forwards(); !slices.Equal(got, []string{addr}) {
		t.Errorf("bastion was asked for %v, want the unresolved %s", got, addr)
	}
}

// TestConnectViaWithoutLookupFailsClosed: a via server on a Dialer that
// cannot resolve its bastion is never dialed directly.
func TestConnectViaWithoutLookupFailsClosed(t *testing.T) {
	f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
	d := f.dialer()
	d.Server = nil
	_, err := d.Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
	if err == nil || !strings.Contains(err.Error(), "refusing to dial") {
		t.Fatalf("Connect = %v, want the fail-closed refusal", err)
	}
	if len(f.target.Attempts())+len(f.hop.Attempts()) != 0 {
		t.Error("a via server was dialed without its bastion")
	}
}

// TestConnectHopFailures: a failure at the bastion keeps its kind and hint,
// names the bastion, and never reaches the target.
func TestConnectHopFailures(t *testing.T) {
	t.Run("unreachable bastion", func(t *testing.T) {
		f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		f.hopSrv.Port = l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		_, err = f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
		assertHopErr(t, err, fleet.ErrorKindDial, "bastion", DialHint)
		if !strings.HasPrefix(err.Error(), "via bastion: ") {
			t.Errorf("error = %q, want the via prefix", err)
		}
	})
	t.Run("changed bastion host key", func(t *testing.T) {
		f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
		f.kh = sshtest.KnownHostsFile(t, f.hop.KnownHostsLine(sshtest.Signer(t, sshtest.Key(42)).PublicKey()),
			f.target.KnownHostsLine(f.targetKey.PublicKey()))
		_, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
		if kindOf(t, err) != fleet.ErrorKindHostKeyChanged || fleet.FailedHopOf(err) != "bastion" {
			t.Fatalf("err = %v (kind %q, hop %q), want host_key_changed at bastion", err, kindOf(t, err), fleet.FailedHopOf(err))
		}
		if len(f.target.Attempts()) != 0 || len(f.hop.Attempts()) != 0 {
			t.Error("credentials were offered past a changed bastion key")
		}
	})
	t.Run("forward prohibited", func(t *testing.T) {
		f := newHopFixture(t, sshtest.ServerConfig{Forward: sshtest.ProhibitForward}, sshtest.ServerConfig{})
		idle := goleak.IgnoreCurrent() // the hop must close before the servers' cleanup would
		_, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
		assertHopErr(t, err, fleet.ErrorKindDial, "bastion", ForwardHint)
		goleak.VerifyNone(t, idle)
	})
	t.Run("target the bastion cannot reach", func(t *testing.T) {
		down := func(string, uint32) (net.Conn, ssh.RejectionReason) { return nil, ssh.ConnectionFailed }
		f := newHopFixture(t, sshtest.ServerConfig{Forward: down}, sshtest.ServerConfig{})
		idle := goleak.IgnoreCurrent()
		_, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
		assertHopErr(t, err, fleet.ErrorKindDial, "", HopDialHint)
		goleak.VerifyNone(t, idle)
	})
	// A jump_only bastion's host key is still strict (spec S5): unrecorded,
	// @revoked or of another type, it stops the tunnel before any key is
	// offered, and the failure names the bastion.
	t.Run("unrecorded jump_only bastion key", func(t *testing.T) {
		f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
		f.hopSrv.JumpOnly = true
		f.kh = sshtest.KnownHostsFile(t, f.target.KnownHostsLine(f.targetKey.PublicKey()))
		_, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
		if kindOf(t, err) != fleet.ErrorKindHostKeyUnknown || fleet.FailedHopOf(err) != "bastion" {
			t.Fatalf("err = %v (kind %q, hop %q), want host_key_unknown at bastion", err, kindOf(t, err), fleet.FailedHopOf(err))
		}
		if len(f.target.Attempts()) != 0 || len(f.hop.Attempts()) != 0 {
			t.Error("credentials were offered past an unrecorded bastion key")
		}
		// The bastion itself has no route, so its scan is the direct form.
		hint := fleet.HintOf(err)
		if want := "ssh-keyscan -t ed25519 -p " + strconv.Itoa(f.hop.Port) + " '127.0.0.1' | ssh-keygen -lf -"; !strings.Contains(hint, want) ||
			strings.Contains(hint, "as seen by the bastion") {
			t.Errorf("hint = %q, want the direct scan %q", hint, want)
		}
	})
	t.Run("revoked jump_only bastion key", func(t *testing.T) {
		f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
		f.hopSrv.JumpOnly = true
		f.kh = sshtest.KnownHostsFile(t, f.hop.KnownHostsLine(f.hopKey.PublicKey()),
			"@revoked * "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(f.hopKey.PublicKey()))),
			f.target.KnownHostsLine(f.targetKey.PublicKey()))
		_, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
		if kindOf(t, err) != fleet.ErrorKindHostKeyRevoked || fleet.FailedHopOf(err) != "bastion" {
			t.Fatalf("err = %v (kind %q, hop %q), want host_key_revoked at bastion", err, kindOf(t, err), fleet.FailedHopOf(err))
		}
	})
	t.Run("jump_only bastion key of another type", func(t *testing.T) {
		// known_hosts records the ed25519 hopKey; the bastion presents ECDSA.
		f := newHopFixture(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{ecdsaSigner(t)}}, sshtest.ServerConfig{})
		f.hopSrv.JumpOnly = true
		_, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
		if kindOf(t, err) != fleet.ErrorKindHostKeyTypeChanged || fleet.FailedHopOf(err) != "bastion" {
			t.Fatalf("err = %v (kind %q, hop %q), want host_key_type_changed at bastion", err, kindOf(t, err), fleet.FailedHopOf(err))
		}
		if len(f.target.Attempts()) != 0 {
			t.Error("the target was reached past a changed bastion key type")
		}
	})
	t.Run("target refuses the key", func(t *testing.T) {
		f := newHopFixture(t, sshtest.ServerConfig{},
			sshtest.ServerConfig{Authorized: []ssh.PublicKey{sshtest.Signer(t, sshtest.Key(9)).PublicKey()}})
		// The servers' cleanup would close a leaked hop before TestMain's
		// goleak runs, so check right after Connect returns: every goroutine
		// the connect started (the hop's client and its server side
		// included) must end while both servers are still up.
		idle := goleak.IgnoreCurrent()
		_, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.targetSrv)
		assertHopErr(t, err, fleet.ErrorKindAuth, "", "")
		goleak.VerifyNone(t, idle)
	})
}

// TestForwardFailurePastDeadlineIsTimeout (F012): the hop's socket deadline
// is ctx's instant, so the bastion's mux can fail a pending channel open
// before ctx's timer sets Err. That failure is the deadline's: timeout,
// never the target's dial with HopDialHint and x/crypto's internal text.
func TestForwardFailurePastDeadlineIsTimeout(t *testing.T) {
	openErr := errors.New("ssh: unexpected packet in response to channel open: <nil>")
	err := forwardFailure(pastDeadlineCtx{context.Background()}, "bastion", "10.0.0.5:22", openErr)
	if got := kindOf(t, err); got != fleet.ErrorKindTimeout {
		t.Errorf("kind past the deadline = %q, want %q (err: %v)", got, fleet.ErrorKindTimeout, err)
	}
	if hint := fleet.HintOf(err); hint != "" {
		t.Errorf("hint past the deadline = %q, want none", hint)
	}
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "%!") || strings.Contains(err.Error(), "unexpected packet") {
		t.Errorf("error = %q, want the deadline named, not x/crypto's text", err)
	}
	future, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	err = forwardFailure(future, "bastion", "10.0.0.5:22", openErr)
	if kindOf(t, err) != fleet.ErrorKindDial || fleet.HintOf(err) != HopDialHint {
		t.Errorf("before the deadline: kind %q hint %q, want dial with HopDialHint", kindOf(t, err), fleet.HintOf(err))
	}
}

// TestConnectForwardNeverAnswersIsTimeout (F012): a bastion whose forward
// never answers holds the channel open until the deadline; the result is a
// timeout every time (run with -race -count=50: it used to come back as the
// target's dial failure about one run in eight).
func TestConnectForwardNeverAnswersIsTimeout(t *testing.T) {
	release := make(chan struct{})
	wedged := func(string, uint32) (net.Conn, ssh.RejectionReason) {
		<-release
		return nil, ssh.ConnectionFailed
	}
	f := newHopFixture(t, sshtest.ServerConfig{Forward: wedged}, sshtest.ServerConfig{})
	t.Cleanup(func() { close(release) }) // runs before the servers' cleanup
	start := time.Now()
	_, err := f.dialer().Connect(ctxTimeout(t, 400*time.Millisecond), f.targetSrv)
	if err == nil {
		t.Fatal("Connect succeeded through a forward that never answers")
	}
	if got := kindOf(t, err); got != fleet.ErrorKindTimeout {
		t.Fatalf("kind = %q, want %q (err: %v, hint %q)", got, fleet.ErrorKindTimeout, err, fleet.HintOf(err))
	}
	if hint := fleet.HintOf(err); hint == HopDialHint {
		t.Errorf("hint = %q, a timeout must not blame the target", hint)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("Connect took %v, want about the 400ms deadline", d)
	}
}

func assertHopErr(t *testing.T, err error, kind fleet.ErrorKind, hop, hint string) {
	t.Helper()
	if err == nil {
		t.Fatal("Connect succeeded")
	}
	if got := kindOf(t, err); got != kind {
		t.Errorf("kind = %q, want %q (err: %v)", got, kind, err)
	}
	if got := fleet.FailedHopOf(err); got != hop {
		t.Errorf("FailedHopOf = %q, want %q", got, hop)
	}
	if got := fleet.HintOf(err); got != hint {
		t.Errorf("hint = %q, want %q", got, hint)
	}
}

// TestConnectThroughHopDeadlineAndCancel: the hop's socket bounds a
// stalled target; Ctrl-C returns at once, even with the tunnel wedged.
func TestConnectThroughHopDeadlineAndCancel(t *testing.T) {
	t.Run("stalled target times out", func(t *testing.T) {
		f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{Stall: true})
		start := time.Now()
		_, err := f.dialer().Connect(ctxTimeout(t, 300*time.Millisecond), f.targetSrv)
		if kindOf(t, err) != fleet.ErrorKindTimeout || time.Since(start) > 2*time.Second {
			t.Fatalf("err = %v after %v, want timeout within ~300ms", err, time.Since(start))
		}
	})
	t.Run("cancel with a wedged tunnel", func(t *testing.T) {
		// The freeze must land after the tunnel is open: the target reads the
		// client's first byte (its SSH version line, sent only once
		// CHANNEL_OPEN_CONFIRMATION arrived), then the proxy in front of the
		// bastion freezes and ctx is canceled. Closing the channel alone now
		// waits for a close reply the frozen proxy never delivers; only
		// closing the hop returns.
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		proxy, freeze := frozenProxy(t)
		f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
		f.targetSrv.Port = stallAfterHello(t, func() { freeze(); cancel() })
		proxy.to(f.hop.Addr())
		f.hopSrv.Port = proxy.port
		f.kh = sshtest.KnownHostsFile(t, knownhosts.Line([]string{proxy.addr()}, f.hopKey.PublicKey()),
			f.target.KnownHostsLine(f.targetKey.PublicKey()))
		start := time.Now()
		_, err := f.dialer().Connect(ctx, f.targetSrv)
		if kindOf(t, err) != fleet.ErrorKindCanceled || time.Since(start) > 2*time.Second {
			t.Fatalf("err = %v after %v, want canceled at once (closing the channel alone waits for a reply that never comes)", err, time.Since(start))
		}
	})
	t.Run("cancel with a wedged bastion", func(t *testing.T) {
		f := newHopFixture(t, sshtest.ServerConfig{Stall: true}, sshtest.ServerConfig{})
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)
		start := time.Now()
		_, err := f.dialer().Connect(ctx, f.targetSrv)
		if kindOf(t, err) != fleet.ErrorKindCanceled || fleet.FailedHopOf(err) != "bastion" || time.Since(start) > 2*time.Second {
			t.Fatalf("err = %v after %v, want canceled at the bastion at once", err, time.Since(start))
		}
	})
}

// TestConnectThroughHopOutlivesItsConnectContext: the connectForWrite
// pattern — the connect ctx is released at once and its deadline passes,
// and SessionTimeout moved the hop's socket deadline, so the tunnelled
// session still runs (gap item 1).
func TestConnectThroughHopOutlivesItsConnectContext(t *testing.T) {
	f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{Handle: sshtest.ShellHandler(t.TempDir())})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	conn, err := f.dialer().ConnectWith(ctx, f.targetSrv, ConnectOptions{SessionTimeout: 20 * time.Second})
	cancel()
	if err != nil {
		t.Fatalf("ConnectWith: %v", err)
	}
	defer func() { _ = conn.Close() }()
	time.Sleep(1500 * time.Millisecond) // past the connect deadline the hop's socket started with
	code, stdout, _, err := Exec(context.Background(), conn.Client, `echo alive`, nil)
	if err != nil {
		t.Fatalf("Exec after the connect deadline: %v, want the session alive", err) // stdout is nil on error
	}
	if code != 0 || stdout.String() != "alive\n" {
		t.Fatalf("Exec after the connect deadline = (%d, %q), want the session alive", code, stdout.String())
	}
}

// TestConnCloseClosesHopWithNilClient: Close always closes the hop.
func TestConnCloseClosesHopWithNilClient(t *testing.T) {
	f := newHopFixture(t, sshtest.ServerConfig{}, sshtest.ServerConfig{})
	hop, err := f.dialer().Connect(ctxTimeout(t, 5*time.Second), f.hopSrv)
	if err != nil {
		t.Fatal(err)
	}
	if err := (&Conn{hop: hop}).Close(); err != nil {
		t.Errorf("Close = %v", err)
	}
	if _, err := hop.Client.NewSession(); err == nil {
		t.Error("the hop is still open after Close")
	}
}

// TestHopOffering: a jump_only bastion is offered every held key in
// Signers order with no fallback warning; a managed one only its granted
// keys (D17).
func TestHopOffering(t *testing.T) {
	k1, k2 := sshtest.Key(1), sshtest.Key(2)
	fp2 := sshtest.Fingerprint(t, k2)
	for _, tt := range []struct {
		name     string
		jumpOnly bool
		want     func(fp1 string) []string
	}{
		{"jump_only", true, func(fp1 string) []string { return []string{fp1, fp2} }},
		{"managed", false, func(string) []string { return []string{fp2} }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newHopFixture(t, sshtest.ServerConfig{Authorized: []ssh.PublicKey{sshtest.Signer(t, k2).PublicKey()}},
				sshtest.ServerConfig{Authorized: []ssh.PublicKey{sshtest.Signer(t, k2).PublicKey()}})
			f.agent = sshtest.Agent(t, k1, k2)
			f.hopSrv.JumpOnly = tt.jumpOnly
			d := f.dialer()
			buf, log := logBuffer()
			d.Log = log
			d.PreferKeys = func(s config.Server) []string {
				if s.JumpOnly {
					return nil
				}
				return []string{fp2}
			}
			conn, err := d.Connect(ctxTimeout(t, 10*time.Second), f.targetSrv)
			if err != nil {
				t.Fatalf("Connect: %v", err)
			}
			_ = conn.Close()
			if got, want := f.hop.Attempts(), tt.want(sshtest.Fingerprint(t, k1)); !slices.Equal(got, want) {
				t.Errorf("bastion was offered %v, want %v", got, want)
			}
			if strings.Contains(buf.String(), "none of the keys granted here") {
				t.Errorf("the hop warned about a fallback:\n%s", buf.String())
			}
		})
	}
}

// TestHopOfferingFallsBack (D17): a managed bastion none of whose granted
// keys the run holds is offered every held key with the fallback warning;
// QuietFallback (after the preflight warned once) drops it to debug.
func TestHopOfferingFallsBack(t *testing.T) {
	k1, k2 := sshtest.Key(1), sshtest.Key(2)
	fp1, fp2 := sshtest.Fingerprint(t, k1), sshtest.Fingerprint(t, k2)
	unheld := sshtest.Fingerprint(t, sshtest.Key(9))
	for _, quiet := range []bool{false, true} {
		t.Run(fmt.Sprintf("quiet=%v", quiet), func(t *testing.T) {
			f := newHopFixture(t, sshtest.ServerConfig{Authorized: []ssh.PublicKey{sshtest.Signer(t, k2).PublicKey()}},
				sshtest.ServerConfig{Authorized: []ssh.PublicKey{sshtest.Signer(t, k2).PublicKey()}})
			f.agent = sshtest.Agent(t, k1, k2)
			d := f.dialer()
			buf, log := logBuffer()
			d.Log, d.QuietFallback = log, quiet
			d.PreferKeys = func(s config.Server) []string {
				if s.Name == f.hopSrv.Name {
					return []string{unheld}
				}
				return []string{fp2}
			}
			conn, err := d.Connect(ctxTimeout(t, 10*time.Second), f.targetSrv)
			if err != nil {
				t.Fatalf("Connect: %v", err)
			}
			_ = conn.Close()
			if got := f.hop.Attempts(); !slices.Equal(got, []string{fp1, fp2}) {
				t.Errorf("bastion was offered %v, want every held key %v", got, []string{fp1, fp2})
			}
			warned := strings.Contains(buf.String(), "bastion: none of the keys granted here are loaded")
			if warned == quiet {
				t.Errorf("fallback warning at info = %v with QuietFallback %v:\n%s", warned, quiet, buf.String())
			}
		})
	}
}

// TestHopIgnoresTargetOnly (spec S5 Transport): the hop never inherits the
// target's Only or Prefer: the login probe's IdentitiesOnly offer is the
// target's, and the hop still offers as any connection to it does.
func TestHopIgnoresTargetOnly(t *testing.T) {
	k1, k2 := sshtest.Key(1), sshtest.Key(2)
	fp1, fp2 := sshtest.Fingerprint(t, k1), sshtest.Fingerprint(t, k2)
	f := newHopFixture(t, sshtest.ServerConfig{Authorized: []ssh.PublicKey{sshtest.Signer(t, k2).PublicKey()}},
		sshtest.ServerConfig{Authorized: []ssh.PublicKey{sshtest.Signer(t, k1).PublicKey()}})
	f.agent = sshtest.Agent(t, k1, k2)
	conn, err := f.dialer().ConnectWith(ctxTimeout(t, 10*time.Second), f.targetSrv, ConnectOptions{Only: []string{fp1}, Prefer: []string{fp1}})
	if err != nil {
		t.Fatalf("ConnectWith(Only: key 1): %v (the hop must not be limited to the target's keys)", err)
	}
	_ = conn.Close()
	if got := f.hop.Attempts(); !slices.Contains(got, fp2) {
		t.Errorf("bastion was offered %v, want key 2 among them", got)
	}
}

// stallAfterHello is a raw TCP target: on each connection it reads one
// byte, calls hello, and then stalls (reads to EOF) until the test ends. It
// returns the port. Cleanup closes the listener and every connection and
// waits for its goroutines (goleak).
func stallAfterHello(t *testing.T, hello func()) int {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		conns  []net.Conn
		closed bool
	)
	t.Cleanup(func() {
		_ = l.Close()
		mu.Lock()
		closed = true
		for _, c := range conns {
			_ = c.Close()
		}
		mu.Unlock()
		wg.Wait()
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			if closed {
				mu.Unlock()
				_ = c.Close()
				return
			}
			conns = append(conns, c)
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				if _, err := c.Read(make([]byte, 1)); err == nil {
					hello()
				}
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// frozenTCP is a TCP proxy in front of the bastion that stops forwarding,
// both ways, once frozen: a bastion wedged mid-tunnel.
type frozenTCP struct {
	l      net.Listener
	port   int
	frozen chan struct{}
	once   sync.Once
	mu     sync.Mutex
	conns  []net.Conn
	wg     sync.WaitGroup
	target string
}

func frozenProxy(t *testing.T) (*frozenTCP, func()) {
	t.Helper()
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &frozenTCP{l: l, port: l.Addr().(*net.TCPAddr).Port, frozen: make(chan struct{})}
	t.Cleanup(func() {
		_ = l.Close()
		p.mu.Lock()
		for _, c := range p.conns {
			_ = c.Close()
		}
		p.mu.Unlock()
		p.wg.Wait()
	})
	return p, func() { p.once.Do(func() { close(p.frozen) }) }
}

func (p *frozenTCP) addr() string { return net.JoinHostPort("127.0.0.1", strconv.Itoa(p.port)) }

// to starts proxying every accepted connection to target.
func (p *frozenTCP) to(target string) {
	p.target = target
	p.wg.Add(1)
	go func() {
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
	}()
}

// pipe copies src to dst until either ends or the proxy freezes; once
// frozen it drops what it read and stops, leaving both sockets open.
func (p *frozenTCP) pipe(dst, src net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			select {
			case <-p.frozen:
				return
			default:
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
