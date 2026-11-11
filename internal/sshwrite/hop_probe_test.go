package sshwrite

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/javadh75/SSHepherd/internal/authkeys"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// TestClassifyProbeHopStage: a failure at a bastion is "could not check"
// whatever its kind (spec S5): never a rejection, so never a restore.
func TestClassifyProbeHopStage(t *testing.T) {
	for _, tt := range []struct {
		name  string
		stage probeStage
		err   error
		want  verdict
	}{
		{"hop refused the key", stageDial, &sshconn.Error{Kind: fleet.ErrorKindAuth, HopStage: "b", Err: errors.New("x")}, verdictTransient},
		{"hop MaxAuthTries", stageDial, &sshconn.Error{Kind: fleet.ErrorKindHandshake, HopStage: "b", AuthExhausted: true, Err: errors.New("x")}, verdictTransient},
		{"hop host key changed", stageDial, &sshconn.Error{Kind: fleet.ErrorKindHostKeyChanged, HopStage: "b", Err: errors.New("x")}, verdictHostKey},
		{"forward prohibited at the hop", stageDial, &sshconn.Error{Kind: fleet.ErrorKindDial, HopStage: "b", Err: errors.New("x")}, verdictTransient},
		{"the server refused the key", stageDial, &sshconn.Error{Kind: fleet.ErrorKindAuth, Err: errors.New("x")}, verdictRejected},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyProbe(tt.stage, tt.err); got != tt.want {
				t.Errorf("classifyProbe = %v, want %v", got, tt.want)
			}
		})
	}
}

// probeHome seeds a temp HOME whose authorized_keys holds line.
func probeHome(t *testing.T, line string) string {
	t.Helper()
	home, err := os.MkdirTemp("", "home")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// bastionWrite writes a fresh render to a server that is a bastion, with
// the given Forward, and returns Apply's error and the file afterwards.
func bastionWrite(t *testing.T, forward func(string, uint32) (net.Conn, ssh.RejectionReason)) (before, after string, err error) {
	t.Helper()
	user := sshtest.Signer(t, sshtest.Key(1))
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(user.PublicKey())))
	home := probeHome(t, line+"\n"+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshtest.Signer(t, sshtest.Key(7)).PublicKey()))))
	file := filepath.Join(home, ".ssh", "authorized_keys")
	orig, rerr := os.ReadFile(file)
	if rerr != nil {
		t.Fatal(rerr)
	}
	hostKey := sshtest.Signer(t, sshtest.Key(40))
	srv := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{hostKey}, AuthorizedKeysFile: file,
		Handle: sshtest.ShellHandler(home), Forward: forward})
	d := &sshconn.Dialer{KnownHostsPath: sshtest.KnownHostsFile(t, srv.KnownHostsLine(hostKey.PublicKey())),
		Creds: &sshconn.Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: 5 * time.Second}
	w := &FleetWriter{Dialer: d, sleep: func(context.Context, time.Duration) error { return nil }}
	k, _ := authkeys.ParseLine(line)
	content := authkeys.ManagedHeader + "\n" + line + "\n"
	err = w.Apply(context.Background(), config.Server{Name: "bastion", Host: srv.Host, Port: srv.Port, User: "jump"}, Request{
		Content: []byte(content), Expect: SnapshotOf(false, orig), Survivors: []string{k.Fingerprint},
		ProbeForward: []string{"10.0.1.5:22", "10.0.1.6:22"},
	})
	now, rerr := os.ReadFile(file)
	if rerr != nil {
		t.Fatal(rerr)
	}
	return string(orig), string(now), err
}

// TestForwardProbeProhibitedRestores: a bastion whose new file may not
// forward fails the login check after a successful login: restore.
func TestForwardProbeProhibitedRestores(t *testing.T) {
	before, after, err := bastionWrite(t, sshtest.ProhibitForward)
	var lockout *fleet.LockoutError
	if !errors.As(err, &lockout) || lockout.Restore != nil {
		t.Fatalf("Apply = %v, want a restored lockout", err)
	}
	if after != before {
		t.Errorf("file after the rejected forward = %q, want the original back", after)
	}
}

// TestForwardProbeChecksEveryDependent (F007): the probe covers every
// dependent, so a key that may forward to the first one only is caught at the
// second: restore.
func TestForwardProbeChecksEveryDependent(t *testing.T) {
	onlyFirst := func(host string, _ uint32) (net.Conn, ssh.RejectionReason) {
		if host == "10.0.1.6" {
			return nil, ssh.Prohibited
		}
		return nil, ssh.ConnectionFailed
	}
	before, after, err := bastionWrite(t, onlyFirst)
	var lockout *fleet.LockoutError
	if !errors.As(err, &lockout) || lockout.Restore != nil {
		t.Fatalf("Apply = %v, want a restored lockout", err)
	}
	if !strings.Contains(err.Error(), "10.0.1.6:22") {
		t.Errorf("err = %v, want the prohibited dependent named", err)
	}
	if after != before {
		t.Errorf("file after the rejected forward = %q, want the original back", after)
	}
}

// TestProbeForwardsAHungDependentHidesNothing (F007): a dependent the bastion
// is still connecting to must not use up the deadline before a later one is
// asked, or a prohibited forward would read as a pass. The hung dependent is
// released only once the later one has been probed.
func TestProbeForwardsAHungDependentHidesNothing(t *testing.T) {
	prohibited := errors.New("prohibited")
	asked := make(chan struct{})
	w := &FleetWriter{forward: func(ctx context.Context, _ *ssh.Client, addr string) error {
		if addr == "10.0.1.5:22" {
			select {
			case <-asked:
			case <-ctx.Done():
			}
			return nil
		}
		close(asked)
		select {
		case <-ctx.Done(): // what the real probe reads as "not prohibited"
			return nil
		default:
			return prohibited
		}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := w.probeForwards(ctx, nil, []string{"10.0.1.5:22", "10.0.1.6:22"}); !errors.Is(err, prohibited) {
		t.Fatalf("probeForwards = %v, want the later dependent's refusal", err)
	}
}

// TestProbeForwardsReportsTheFirstDependentInOrder: which failure is reported
// does not depend on which reply arrived first.
func TestProbeForwardsReportsTheFirstDependentInOrder(t *testing.T) {
	first, second := errors.New("first"), errors.New("second")
	secondDone := make(chan struct{})
	w := &FleetWriter{forward: func(ctx context.Context, _ *ssh.Client, addr string) error {
		if addr == "a:22" {
			select {
			case <-secondDone:
			case <-ctx.Done():
			}
			return first
		}
		close(secondDone)
		return second
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := w.probeForwards(ctx, nil, []string{"a:22", "b:22"})
	select {
	case <-secondDone:
	default:
		t.Fatal("the second dependent was never probed")
	}
	if !errors.Is(err, first) || errors.Is(err, second) {
		t.Fatalf("probeForwards = %v, want the first dependent's error alone", err)
	}
	if err := w.probeForwards(ctx, nil, nil); err != nil {
		t.Fatalf("probeForwards with no dependents = %v", err)
	}
}

// TestForwardProbeTargetDownKeepsTheFile: a dependent the bastion cannot
// reach is the dependent's problem; the write stands.
func TestForwardProbeTargetDownKeepsTheFile(t *testing.T) {
	down := func(string, uint32) (net.Conn, ssh.RejectionReason) { return nil, ssh.ConnectionFailed }
	before, after, err := bastionWrite(t, down)
	if err != nil {
		t.Fatalf("Apply = %v, want success", err)
	}
	if after == before {
		t.Error("the write did not land")
	}
}

// TestProbeHopDeathIsUnproven: after the write's own connection the
// bastion stops accepting the key, so every login check fails at the hop
// with kind auth. That proves nothing about this server's file: UNPROVEN,
// kept, never a restore or a lockout (spec S5, P08). Without classifyProbe's
// hop branch the auth kind reads as verdictRejected and the file is
// restored, so this test fails before Step 3.
func TestProbeHopDeathIsUnproven(t *testing.T) {
	user := sshtest.Signer(t, sshtest.Key(1))
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(user.PublicKey())))
	home := probeHome(t, line)
	file := filepath.Join(home, ".ssh", "authorized_keys")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	hopFile := filepath.Join(t.TempDir(), "hop_authorized_keys")
	if err := os.WriteFile(hopFile, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hopKey, targetKey := sshtest.Signer(t, sshtest.Key(40)), sshtest.Signer(t, sshtest.Key(41))
	hop := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{hopKey}, AuthorizedKeysFile: hopFile, Forward: sshtest.DialForward})
	target := sshtest.NewServer(t, sshtest.ServerConfig{HostKeys: []ssh.Signer{targetKey}, AuthorizedKeysFile: file, Handle: sshtest.ShellHandler(home)})
	bastion := config.Server{Name: "bastion", Host: hop.Host, Port: hop.Port, User: "jump", JumpOnly: true}
	d := &sshconn.Dialer{KnownHostsPath: sshtest.KnownHostsFile(t, hop.KnownHostsLine(hopKey.PublicKey()), target.KnownHostsLine(targetKey.PublicKey())),
		Creds: &sshconn.Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(1))}, DialTimeout: 5 * time.Second,
		Server: func(name string) (config.Server, bool) { return bastion, name == bastion.Name }}
	// The first connect is the write's own; from the second (the first
	// login check) on, the bastion's file is empty, so the hop refuses the
	// key (sshtest re-reads AuthorizedKeysFile on every login).
	calls := 0
	connect := func(ctx context.Context, srv config.Server, opts sshconn.ConnectOptions) (*sshconn.Conn, error) {
		calls++
		if calls == 2 {
			if err := os.WriteFile(hopFile, nil, 0o600); err != nil {
				t.Error(err)
			}
		}
		return d.ConnectWith(ctx, srv, opts)
	}
	w := &FleetWriter{Dialer: d, connect: connect, sleep: func(context.Context, time.Duration) error { return nil }}
	k, _ := authkeys.ParseLine(line)
	content := authkeys.ManagedHeader + "\n" + line + "\n"
	err = w.Apply(context.Background(), config.Server{Name: "web-1", Host: target.Host, Port: target.Port, User: "deploy", Via: "bastion"},
		Request{Content: []byte(content), Expect: SnapshotOf(false, before), Survivors: []string{k.Fingerprint}})
	var unproven *fleet.UnprovenError
	var lockout *fleet.LockoutError
	if !errors.As(err, &unproven) || errors.As(err, &lockout) || fleet.FailedHopOf(err) != "bastion" {
		t.Fatalf("Apply = %v, want UNPROVEN at the bastion and no lockout", err)
	}
	if after, _ := os.ReadFile(file); string(after) != content {
		t.Errorf("file = %q, want the new file kept", after)
	}
}

// TestProbeForwardsShareTheExecDeadline (F007): every concurrent forward
// runs under the probe's one exec deadline, however long the caller's ctx
// lives.
func TestProbeForwardsShareTheExecDeadline(t *testing.T) {
	type seen struct {
		addr     string
		deadline time.Time
		ok       bool
	}
	got := make(chan seen, 4)
	w := seamedWriter(&scriptedExec{}, &seamedConnect{})
	w.forward = func(ctx context.Context, _ *ssh.Client, addr string) error {
		dl, ok := ctx.Deadline()
		got <- seen{addr, dl, ok}
		return nil
	}
	start := time.Now()
	if _, err := w.probeOnce(context.Background(), config.Server{Name: "bastion"}, nil, []string{"a:22", "b:22"}, time.Second); err != nil {
		t.Fatalf("probeOnce: %v", err)
	}
	close(got)
	n := 0
	for s := range got {
		n++
		if !s.ok || s.deadline.After(start.Add(probeExecDeadline+time.Second)) {
			t.Errorf("forward to %s: deadline = %v, %v; want within %v of the connect", s.addr, s.deadline, s.ok, probeExecDeadline)
		}
	}
	if n != 2 {
		t.Errorf("%d forwards, want 2", n)
	}
}

// TestHeadlessProofOpensNoForwards (D9b, F007): the warn-only headless
// proof only logs in; the bastion's forwards are proven once, by the login
// check.
func TestHeadlessProofOpensNoForwards(t *testing.T) {
	r := req("x\n", "SHA256:agent")
	r.HeadlessProof = []string{"SHA256:file"}
	r.ProbeForward = []string{"10.0.1.5:22", "10.0.1.6:22"}
	var warnings []string
	r.OnWarning = func(cause string) { warnings = append(warnings, cause) }
	c := &seamedConnect{}
	w := seamedWriter(&scriptedExec{responses: goodWrite}, c)
	var forwards atomic.Int32
	w.forward = func(context.Context, *ssh.Client, string) error {
		forwards.Add(1)
		return nil
	}
	if err := w.Apply(context.Background(), config.Server{Name: "bastion-eu"}, r); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if len(c.opts) != 3 || !slices.Equal(c.opts[2].Only, r.HeadlessProof) {
		t.Fatalf("connects = %+v, want the write, the login check and the headless proof", c.opts)
	}
	if n := int(forwards.Load()); n != len(r.ProbeForward) || len(warnings) != 0 {
		t.Errorf("forwards = %d, warnings = %q; want only the login check's %d", n, warnings, len(r.ProbeForward))
	}
}
