package sshwrite

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
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
		ProbeForward: "10.0.1.5:22",
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
