package sshconn

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// kindOf extracts the *Error kind, failing when err carries none.
func kindOf(t *testing.T, err error) fleet.ErrorKind {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error %v carries no *sshconn.Error", err)
	}
	return e.Kind
}

func ecdsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}
	return sshtest.Signer(t, priv)
}

// fixture is one hermetic server + agent + known_hosts trio.
type fixture struct {
	srv    *sshtest.Server
	cfgSrv config.Server
	agent  string
}

func newFixture(t *testing.T, sc sshtest.ServerConfig, agentKeys ...any) fixture {
	t.Helper()
	s := sshtest.NewServer(t, sc)
	return fixture{
		srv:    s,
		cfgSrv: config.Server{Name: "web-1", Host: s.Host, Port: s.Port, User: "deploy"},
		agent:  sshtest.Agent(t, agentKeys...),
	}
}

func (f fixture) dialer(kh string) *Dialer {
	return &Dialer{KnownHostsPath: kh, Creds: &Credentials{AgentSock: f.agent}, DialTimeout: 5 * time.Second}
}

func ctxTimeout(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestConnectMatchingKeyRunsUnderSh(t *testing.T) {
	host := sshtest.Signer(t, sshtest.Key(40))
	user := sshtest.Key(1)
	f := newFixture(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		Handle:     sshtest.ShellHandler(t.TempDir()),
	}, user)
	kh := sshtest.KnownHostsFile(t, f.srv.KnownHostsLine(host.PublicKey()))

	conn, err := f.dialer(kh).Connect(ctxTimeout(t, 10*time.Second), f.cfgSrv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if got, want := conn.SessionKeyFP(), sshtest.Fingerprint(t, user); got != want {
		t.Errorf("SessionKeyFP = %s, want %s", got, want)
	}
	code, stdout, _, err := Exec(context.Background(), conn.Client, `printf '%s' "it's \ok"`, nil)
	if err != nil || code != 0 {
		t.Fatalf("Exec = (%d, %v)", code, err)
	}
	if stdout.String() != `it's \ok` {
		t.Errorf("stdout = %q, want %q", stdout.String(), `it's \ok`)
	}
	if cmds := f.srv.Commands(); len(cmds) != 1 || !strings.HasPrefix(cmds[0], "exec /bin/sh -c '") {
		t.Errorf("server received %q, want an exec /bin/sh -c wrapper", cmds)
	}
}

func TestConnectHostKeyFailures(t *testing.T) {
	user := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	tests := []struct {
		name     string
		hostKeys []ssh.Signer
		khLines  func(f fixture) []string
		kind     fleet.ErrorKind
		want     []string
		notWant  []string
	}{
		{
			name:     "changed key is refused with the alarm",
			hostKeys: []ssh.Signer{host},
			khLines: func(f fixture) []string {
				return []string{f.srv.KnownHostsLine(sshtest.Signer(t, sshtest.Key(41)).PublicKey())}
			},
			kind: fleet.ErrorKindHostKeyChanged,
			want: []string{"HOST KEY CHANGED", "presented ssh-ed25519 key " + ssh.FingerprintSHA256(host.PublicKey())},
		},
		{
			name:     "unknown host gets an out-of-band hint, never a blind append",
			hostKeys: []ssh.Signer{host},
			khLines:  func(fixture) []string { return nil },
			kind:     fleet.ErrorKindHostKeyUnknown,
			want:     []string{"out of band", "| ssh-keygen -lf -", "'127.0.0.1'"},
			notWant:  []string{">>"},
		},
		{
			name:     "unrecorded key type is flagged, not alarmed",
			hostKeys: []ssh.Signer{ecdsaSigner(t)},
			khLines: func(f fixture) []string {
				return []string{f.srv.KnownHostsLine(host.PublicKey())}
			},
			kind:    fleet.ErrorKindHostKeyTypeUnrecorded,
			want:    []string{"not recorded", "recorded: ssh-ed25519"},
			notWant: []string{"HOST KEY CHANGED", ">>"},
		},
		{
			name:     "revoked key is refused",
			hostKeys: []ssh.Signer{host},
			khLines: func(f fixture) []string {
				return []string{
					f.srv.KnownHostsLine(host.PublicKey()),
					"@revoked * " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(host.PublicKey()))),
				}
			},
			kind: fleet.ErrorKindHostKeyRevoked,
			want: []string{"@revoked"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, sshtest.ServerConfig{
				HostKeys:   tt.hostKeys,
				Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
			}, user)
			kh := sshtest.KnownHostsFile(t, tt.khLines(f)...)
			conn, err := f.dialer(kh).Connect(ctxTimeout(t, 10*time.Second), f.cfgSrv)
			if err == nil {
				_ = conn.Close()
				t.Fatal("Connect succeeded, want a host-key refusal")
			}
			if got := kindOf(t, err); got != tt.kind {
				t.Errorf("kind = %q, want %q (err: %v)", got, tt.kind, err)
			}
			if strings.Contains(err.Error(), "hint:") || strings.ContainsAny(err.Error(), "\n") {
				t.Errorf("message %q must not embed the hint", err)
			}
			full := err.Error() + "\n" + fleet.HintOf(err)
			for _, w := range tt.want {
				if !strings.Contains(full, w) {
					t.Errorf("error + hint lacks %q:\n%s", w, full)
				}
			}
			for _, w := range tt.notWant {
				if strings.Contains(full, w) {
					t.Errorf("error + hint must not contain %q:\n%s", w, full)
				}
			}
			if n := len(f.srv.Attempts()); n != 0 {
				t.Errorf("%d auth attempts reached an untrusted host, want 0", n)
			}
		})
	}
}

// TestConnectNegotiatesRecordedHostKey pins the known_hosts-ordered
// HostKeyAlgorithms: x/crypto's default order would pick the server's
// certificate (no CA line: "no authorities") or its ECDSA key (only
// ed25519 recorded: an unrecorded-type refusal) — both hosts are pinned
// and must connect.
func TestConnectNegotiatesRecordedHostKey(t *testing.T) {
	user := sshtest.Key(1)
	plain := sshtest.Signer(t, sshtest.Key(40))
	ca := sshtest.Signer(t, sshtest.Key(50))
	cert := &ssh.Certificate{
		Key: plain.PublicKey(), CertType: ssh.HostCert, KeyId: "web-1",
		ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatalf("sign host cert: %v", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, plain)
	if err != nil {
		t.Fatalf("cert signer: %v", err)
	}
	caLine := func(f fixture) string {
		return "@cert-authority " + knownhosts.Normalize(f.srv.Addr()) + " " +
			strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
	}
	tests := []struct {
		name     string
		hostKeys []ssh.Signer
		khLines  func(f fixture) []string
	}{
		{"ed25519 recorded, ecdsa also served", []ssh.Signer{ecdsaSigner(t), plain},
			func(f fixture) []string { return []string{f.srv.KnownHostsLine(plain.PublicKey())} }},
		{"plain key recorded, certificate also served", []ssh.Signer{certSigner, plain},
			func(f fixture) []string { return []string{f.srv.KnownHostsLine(plain.PublicKey())} }},
		{"only the CA recorded", []ssh.Signer{certSigner},
			func(f fixture) []string { return []string{caLine(f)} }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t, sshtest.ServerConfig{
				HostKeys:   tt.hostKeys,
				Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
			}, user)
			kh := sshtest.KnownHostsFile(t, tt.khLines(f)...)
			conn, err := f.dialer(kh).Connect(ctxTimeout(t, 10*time.Second), f.cfgSrv)
			if err != nil {
				t.Fatalf("Connect: %v", err)
			}
			_ = conn.Close()
		})
	}
}

func TestConnectDeadlineAndCancel(t *testing.T) {
	user := sshtest.Key(1)
	f := newFixture(t, sshtest.ServerConfig{Stall: true}, user)
	kh := sshtest.KnownHostsFile(t)

	t.Run("handshake stall hits the deadline", func(t *testing.T) {
		start := time.Now()
		_, err := f.dialer(kh).Connect(ctxTimeout(t, 200*time.Millisecond), f.cfgSrv)
		if err == nil {
			t.Fatal("stalled server produced no error")
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("returned after %v, want ~200ms", elapsed)
		}
		if got := kindOf(t, err); got != fleet.ErrorKindTimeout {
			t.Errorf("kind = %q, want timeout (err: %v)", got, err)
		}
	})
	t.Run("cancellation aborts the handshake before the deadline", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background()) // floor deadline: 15s
		time.AfterFunc(100*time.Millisecond, cancel)
		start := time.Now()
		_, err := f.dialer(kh).Connect(ctx, f.cfgSrv)
		if err == nil {
			t.Fatal("canceled handshake produced no error")
		}
		if elapsed := time.Since(start); elapsed > 2*time.Second {
			t.Errorf("returned after %v, want ~100ms", elapsed)
		}
		if got := kindOf(t, err); got != fleet.ErrorKindCanceled {
			t.Errorf("kind = %q, want canceled (err: %v)", got, err)
		}
	})
}

// TestConnectDialRefusedHintIsSeparate: a refused dial names the address
// once, says "dial" once, carries no hint text in its message, and exposes
// the bastion hint through fleet.HintOf.
func TestConnectDialRefusedHintIsSeparate(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close() // nothing listens there now
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: time.Second}
	_, err = d.Connect(ctxTimeout(t, 5*time.Second), config.Server{Name: "x", Host: "127.0.0.1", Port: port, User: "u"})
	if err == nil {
		t.Fatal("dial to a closed port succeeded")
	}
	if got := kindOf(t, err); got != fleet.ErrorKindDial {
		t.Errorf("kind = %q, want dial", got)
	}
	msg := err.Error()
	addr := "127.0.0.1:" + strconv.Itoa(port)
	if strings.Count(msg, "dial") != 1 || strings.Count(msg, addr) != 1 {
		t.Errorf("message %q: want exactly one \"dial\" and one %q", msg, addr)
	}
	if strings.Contains(msg, "hint") || strings.ContainsAny(msg, "\n") {
		t.Errorf("message %q must not embed the hint", msg)
	}
	if h := fleet.HintOf(err); h != DialHint {
		t.Errorf("HintOf = %q, want DialHint", h)
	}
}

// TestConnectDialEndedByCtxHint: a dial the operator interrupted is kind
// canceled and carries no hint (there is nothing to fix); a dial whose
// deadline passed is kind timeout and keeps DialHint. Key-file credentials
// only, so no agent I/O stands between the ctx and the dial.
func TestConnectDialEndedByCtxHint(t *testing.T) {
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t),
		Creds:       &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/ci", sshtest.Key(1))}},
		DialTimeout: time.Second}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	for _, tt := range []struct {
		name     string
		ctx      context.Context
		kind     fleet.ErrorKind
		wantHint string
	}{
		{"canceled", canceled, fleet.ErrorKindCanceled, ""},
		{"deadline passed", expired, fleet.ErrorKindTimeout, DialHint},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := d.Connect(tt.ctx, config.Server{Name: "x", Host: "127.0.0.1", Port: 1, User: "u"})
			if err == nil {
				t.Fatal("dial under an ended ctx succeeded")
			}
			if got := kindOf(t, err); got != tt.kind {
				t.Errorf("kind = %q, want %q (err: %v)", got, tt.kind, err)
			}
			if h := fleet.HintOf(err); h != tt.wantHint {
				t.Errorf("HintOf = %q, want %q", h, tt.wantHint)
			}
		})
	}
}

// TestAuditGoldenCarriesDialHint: audit's goldens (and the README samples
// copied from them) use a mirror of DialHint; this keeps the mirror honest.
func TestAuditGoldenCarriesDialHint(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "audit", "testdata", "report_drift.golden"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("  hint: "+DialHint+"\n")) {
		t.Error("internal/audit/testdata/report_drift.golden does not carry sshconn.DialHint verbatim; update testDialHint in internal/audit/report_test.go")
	}
}

// TestDialErr: the address is added only when the net error does not
// already name it (a DNS failure names the host, not host:port).
func TestDialErr(t *testing.T) {
	refused := &net.OpError{Op: "dial", Net: "tcp", Addr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22},
		Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}
	lookup := &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "web-1.invalid"}}
	for _, tt := range []struct {
		name, addr string
		in         error
		want       string
	}{
		{"refused names addr", "10.0.0.1:22", refused, "dial tcp 10.0.0.1:22: connect: connection refused"},
		{"lookup gets addr", "web-1.invalid:22", lookup, "dial web-1.invalid:22: dial tcp: lookup web-1.invalid: no such host"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := dialErr(tt.addr, tt.in).Error(); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestConnectKeyOffering pins MaxAuthTries hygiene: the granted key is
// offered first, and Only offers nothing else.
func TestConnectKeyOffering(t *testing.T) {
	a, b, c := sshtest.Key(1), sshtest.Key(2), sshtest.Key(3)
	fpA, fpB, fpC := sshtest.Fingerprint(t, a), sshtest.Fingerprint(t, b), sshtest.Fingerprint(t, c)
	host := sshtest.Signer(t, sshtest.Key(40))
	f := newFixture(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, c).PublicKey()},
	}, a, b, c)
	kh := sshtest.KnownHostsFile(t, f.srv.KnownHostsLine(host.PublicKey()))

	connect := func(t *testing.T, d *Dialer, opts ConnectOptions) ([]string, error) {
		t.Helper()
		before := len(f.srv.Attempts())
		conn, err := d.ConnectWith(ctxTimeout(t, 10*time.Second), f.cfgSrv, opts)
		if err == nil {
			_ = conn.Close()
		}
		return f.srv.Attempts()[before:], err
	}

	t.Run("agent order without preference", func(t *testing.T) {
		got, err := connect(t, f.dialer(kh), ConnectOptions{})
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		if !slices.Equal(got, []string{fpA, fpB, fpC}) {
			t.Errorf("attempts = %v, want agent order", got)
		}
	})
	t.Run("granted key first via Dialer.PreferKeys", func(t *testing.T) {
		d := f.dialer(kh)
		d.PreferKeys = func(config.Server) []string { return []string{fpC} }
		got, err := connect(t, d, ConnectOptions{})
		if err != nil {
			t.Fatalf("Connect: %v", err)
		}
		if !slices.Equal(got, []string{fpC}) {
			t.Errorf("attempts = %v, want only the preferred key tried", got)
		}
	})
	t.Run("Only offers exactly that set", func(t *testing.T) {
		got, err := connect(t, f.dialer(kh), ConnectOptions{Only: []string{fpB}})
		if err == nil {
			t.Fatal("login with a refused-only key set succeeded")
		}
		if k := kindOf(t, err); k != fleet.ErrorKindAuth {
			t.Errorf("kind = %q, want auth (err: %v)", k, err)
		}
		if !slices.Equal(got, []string{fpB}) {
			t.Errorf("attempts = %v, want exactly [%s]", got, fpB)
		}
	})
}

func TestOrderSigners(t *testing.T) {
	keys := []ssh.Signer{
		sshtest.Signer(t, sshtest.Key(1)), sshtest.Signer(t, sshtest.Key(2)), sshtest.Signer(t, sshtest.Key(3)),
	}
	fp := func(i int) string { return ssh.FingerprintSHA256(keys[i].PublicKey()) }
	tests := []struct {
		name         string
		prefer, only []string
		want         []int
	}{
		{"no preference keeps agent order", nil, nil, []int{0, 1, 2}},
		{"preferred first, rest in agent order", []string{fp(2)}, nil, []int{2, 0, 1}},
		{"preference order wins", []string{fp(2), fp(1)}, nil, []int{2, 1, 0}},
		{"unknown preferred fingerprints are skipped", []string{"SHA256:nope", fp(1)}, nil, []int{1, 0, 2}},
		{"only restricts and orders", []string{fp(0)}, []string{fp(2), fp(1)}, []int{2, 1}},
		{"only with nothing held offers nothing", nil, []string{"SHA256:nope"}, nil},
		{"duplicates offered once", []string{fp(1), fp(1)}, nil, []int{1, 0, 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := orderSigners(keys, tt.prefer, tt.only)
			var idx []int
			for _, s := range got {
				for i, k := range keys {
					if s == k {
						idx = append(idx, i)
					}
				}
			}
			if !slices.Equal(idx, tt.want) {
				t.Errorf("order = %v, want %v", idx, tt.want)
			}
		})
	}
}

// TestDialerParsesKnownHostsOnce: one snapshot per Dialer — a file removed
// (or rewritten) mid-run does not change later verdicts.
func TestDialerParsesKnownHostsOnce(t *testing.T) {
	user := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	f := newFixture(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
	}, user)
	kh := sshtest.KnownHostsFile(t, f.srv.KnownHostsLine(host.PublicKey()))
	d := f.dialer(kh)
	for i := range 2 {
		conn, err := d.Connect(ctxTimeout(t, 10*time.Second), f.cfgSrv)
		if err != nil {
			t.Fatalf("Connect #%d: %v", i+1, err)
		}
		_ = conn.Close()
		if err := os.Remove(kh); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
	}
	t.Run("preloaded snapshot is used as given", func(t *testing.T) {
		snap, err := LoadKnownHosts(sshtest.KnownHostsFile(t, f.srv.KnownHostsLine(host.PublicKey())))
		if err != nil {
			t.Fatal(err)
		}
		d := &Dialer{KnownHostsPath: "/nonexistent", KnownHosts: snap, Creds: &Credentials{AgentSock: f.agent}, DialTimeout: time.Second}
		conn, err := d.Connect(ctxTimeout(t, 10*time.Second), f.cfgSrv)
		if err != nil {
			t.Fatalf("Connect with preloaded snapshot: %v", err)
		}
		_ = conn.Close()
	})
}

func TestExecCancellationClosesSession(t *testing.T) {
	user := sshtest.Key(1)
	host := sshtest.Signer(t, sshtest.Key(40))
	f := newFixture(t, sshtest.ServerConfig{
		HostKeys:   []ssh.Signer{host},
		Authorized: []ssh.PublicKey{sshtest.Signer(t, user).PublicKey()},
		Handle: func(ctx context.Context, _ string, _ io.Reader, _, _ io.Writer) int {
			<-ctx.Done() // hangs until the client closes the session
			return 0
		},
	}, user)
	kh := sshtest.KnownHostsFile(t, f.srv.KnownHostsLine(host.PublicKey()))
	conn, err := f.dialer(kh).Connect(ctxTimeout(t, 10*time.Second), f.cfgSrv)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	_, _, _, err = Exec(ctx, conn.Client, "sleep 60", nil)
	if err == nil {
		t.Fatal("canceled Exec returned no error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Exec returned after %v, want ~100ms", elapsed)
	}
	if got := kindOf(t, err); got != fleet.ErrorKindCanceled {
		t.Errorf("kind = %q, want canceled", got)
	}

	t.Run("pre-canceled ctx never opens a session", func(t *testing.T) {
		before := len(f.srv.Commands())
		_, _, _, err := Exec(ctx, conn.Client, "true", nil)
		if !errors.Is(err, context.Canceled) {
			t.Errorf("err = %v, want context.Canceled", err)
		}
		if len(f.srv.Commands()) != before {
			t.Error("a session was opened under a canceled ctx")
		}
	})
}

func TestExecRejectsMultiLineScripts(t *testing.T) {
	_, _, _, err := Exec(context.Background(), nil, "true\nfalse", nil)
	if err == nil || !strings.Contains(err.Error(), "single line") {
		t.Errorf("err = %v, want single-line refusal", err)
	}
}

// TestRemoteCommandUnderLoginShells runs the wrapper through every login
// shell present on this machine: each must hand /bin/sh exactly the
// original script, whatever its quoting.
func TestRemoteCommandUnderLoginShells(t *testing.T) {
	scripts := []string{
		`printf '%s|' plain`,
		`printf '%s|' "it's" 'back\slash' "dq\"q" '$HOME' "a  b"`,
		AuthorizedKeysCmdFor("/tmp/o'brien/x;$(id)") + "; echo rc=$?",
		`printf '%s' '\\'`,
	}
	shells := []string{"sh", "bash", "zsh", "fish", "csh", "tcsh"}
	run := func(t *testing.T, shell, cmd string) string {
		t.Helper()
		c := exec.CommandContext(t.Context(), shell, "-c", cmd)
		c.Env = []string{"HOME=" + t.TempDir(), "PATH=/usr/bin:/bin"}
		out, _ := c.CombinedOutput() // the exit code is part of the compared output via rc=
		return string(out)
	}
	for _, shell := range shells {
		path, err := exec.LookPath(shell)
		if err != nil {
			continue
		}
		t.Run(shell, func(t *testing.T) {
			for _, s := range scripts {
				want := run(t, "/bin/sh", s)
				if got := run(t, path, remoteCommand(s)); got != want {
					t.Errorf("%s -c remoteCommand(%q):\n got %q\nwant %q", shell, s, got, want)
				}
			}
		})
	}
}

// TestHandshakeDisconnectTextIsBounded (SEC-8): a server that sends
// SSH_MSG_DISCONNECT during kex controls the error text; it must come back
// bounded and without blank-looking runes, still classified as a handshake
// failure.
func TestHandshakeDisconnectTextIsBounded(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	t.Cleanup(func() { <-done })         // runs last: the peer goroutine has exited
	t.Cleanup(func() { _ = ln.Close() }) // runs first: unblocks a pending Accept
	desc := strings.Repeat("\u2800", 1<<14) + "\n\u2713 present & authorized"
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(c, "SSH-2.0-evil\r\n")
		// payload: byte 1 (disconnect), uint32 reason 2, string desc, string lang ""
		payload := []byte{1, 0, 0, 0, 2}
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(desc))) // #nosec G115 -- small test constant
		payload = append(payload, desc...)
		payload = binary.BigEndian.AppendUint32(payload, 0)
		pad := 8 - (5+len(payload))%8
		if pad < 4 {
			pad += 8
		}
		pkt := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad)) // #nosec G115 -- small test constant
		pkt = append(pkt, byte(pad))
		pkt = append(pkt, payload...)
		pkt = append(pkt, make([]byte, pad)...)
		_, _ = c.Write(pkt)
		_, _ = io.Copy(io.Discard, c) // keep reading the client's KEXINIT until it hangs up
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	d := &Dialer{KnownHostsPath: sshtest.KnownHostsFile(t), Creds: &Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: time.Second}
	_, err = d.Connect(ctxTimeout(t, 5*time.Second), config.Server{Name: "evil", Host: "127.0.0.1", Port: port, User: "u"})
	if err == nil {
		t.Fatal("dial succeeded against a disconnecting server")
	}
	msg := err.Error()
	if len(msg) > 512 || strings.ContainsRune(msg, '\u2800') || strings.Contains(msg, "\n") {
		t.Errorf("handshake error not bounded: %d bytes, %q…", len(msg), msg[:min(len(msg), 120)])
	}
	if !strings.Contains(msg, "ssh u@127.0.0.1:"+strconv.Itoa(port)) || !strings.Contains(msg, "disconnect") {
		t.Errorf("message %q lost its prefix or the disconnect reason", msg)
	}
	if got := kindOf(t, err); got != fleet.ErrorKindHandshake {
		t.Errorf("kind = %q, want handshake", got)
	}
}

// TestExecOpenSessionRejectTextIsBounded (SEC-8): an authenticated server
// that rejects the session channel chooses the rejection message; Exec's
// error must come back bounded and without blank-looking runes or newlines,
// still classified as a remote failure.
func TestExecOpenSessionRejectTextIsBounded(t *testing.T) {
	// A real loopback socket: over net.Pipe both sides' version lines
	// would block each other.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	host := ecdsaSigner(t)
	sc := &ssh.ServerConfig{NoClientAuth: true}
	sc.AddHostKey(host)
	msg := strings.Repeat("⠀", 1<<14) + "\nweb-3  ✓ present & authorized"
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = srv.Close() }()
		_, chans, reqs, err := ssh.NewServerConn(srv, sc)
		if err != nil {
			return
		}
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			_ = nc.Reject(ssh.Prohibited, msg)
		}
	}()
	t.Cleanup(func() { <-done })
	cli, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cb, err := knownhosts.New(sshtest.KnownHostsFile(t, knownhosts.Line([]string{ln.Addr().String()}, host.PublicKey())))
	if err != nil {
		t.Fatal(err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(cli, ln.Addr().String(), &ssh.ClientConfig{
		User:            "u",
		HostKeyCallback: cb,
	})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer func() { _ = client.Close() }()

	_, _, _, err = Exec(ctxTimeout(t, 5*time.Second), client, "true", nil)
	if err == nil {
		t.Fatal("Exec succeeded against a server rejecting every session")
	}
	got := err.Error()
	if len(got) > 512 || strings.ContainsRune(got, '⠀') || strings.Contains(got, "\n") {
		t.Errorf("open-session error not bounded: %d bytes, %q…", len(got), got[:min(len(got), 120)])
	}
	if !strings.Contains(got, "open session") {
		t.Errorf("message %q lost its prefix", got)
	}
	var oce *ssh.OpenChannelError
	if !errors.As(err, &oce) || oce.Reason != ssh.Prohibited {
		t.Errorf("err = %v, want the *ssh.OpenChannelError kept for errors.As", err)
	}
	if got := kindOf(t, err); got != fleet.ErrorKindRemote {
		t.Errorf("kind = %q, want remote", got)
	}
}
