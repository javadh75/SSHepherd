package sshconn

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

// deadSock is an agent socket path nothing listens on.
func deadSock(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "dead.sock")
}

// warnLog captures warnings.
func warnLog() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), &buf
}

func signerFPs(signers []ssh.Signer) []string {
	out := make([]string, 0, len(signers))
	for _, s := range signers {
		out = append(out, ssh.FingerprintSHA256(s.PublicKey()))
	}
	return out
}

func TestSignersUnionOrderAndDedup(t *testing.T) {
	a, b, c, ca := sshtest.Key(1), sshtest.Key(2), sshtest.Key(3), sshtest.Key(9)
	cert := sshtest.UserCert(t, c, ca, "deploy")
	sock := sshtest.AgentKeys(t,
		agent.AddedKey{PrivateKey: c, Certificate: cert}, // a certificate listed first by the agent
		agent.AddedKey{PrivateKey: b},
		agent.AddedKey{PrivateKey: a}, // also a key file: offered once, as the file
	)
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/a", a), sshtest.Identity(t, "/k/a-again", a)}, AgentSock: sock}
	signers, release, err := creds.Signers(context.Background())
	if err != nil {
		t.Fatalf("Signers: %v", err)
	}
	defer release()
	want := []string{sshtest.Fingerprint(t, a), ssh.FingerprintSHA256(cert), sshtest.Fingerprint(t, b)}
	if got := signerFPs(signers); !slices.Equal(got, want) {
		t.Errorf("Signers = %v, want file keys, then agent keys in raw agent order (certificate included where the agent lists it): %v", got, want)
	}
	if !isCert(signers[1].PublicKey()) {
		t.Error("the agent certificate must still be offered for login")
	}

	held, err := creds.Held(context.Background())
	if err != nil {
		t.Fatalf("Held: %v", err)
	}
	wantHeld := []HeldKey{{sshtest.Fingerprint(t, a), "/k/a"}, {sshtest.Fingerprint(t, b), SourceAgent}}
	if !slices.Equal(held, wantHeld) {
		t.Errorf("Held = %v, want %v (no certificate, file source wins)", held, wantHeld)
	}
}

// TestSignersAgentOnlyKeepsAgentOrder pins decision 1: with no --identity
// the offer is exactly the agent's own order — a certificate the agent
// lists first is offered first, as before the --identity slice.
func TestSignersAgentOnlyKeepsAgentOrder(t *testing.T) {
	b, c, ca := sshtest.Key(2), sshtest.Key(3), sshtest.Key(9)
	cert := sshtest.UserCert(t, c, ca, "deploy")
	sock := sshtest.AgentKeys(t,
		agent.AddedKey{PrivateKey: c, Certificate: cert},
		agent.AddedKey{PrivateKey: b},
	)
	signers, release, err := (&Credentials{AgentSock: sock}).Signers(context.Background())
	if err != nil {
		t.Fatalf("Signers: %v", err)
	}
	defer release()
	want := []string{ssh.FingerprintSHA256(cert), sshtest.Fingerprint(t, b)}
	if got := signerFPs(signers); !slices.Equal(got, want) {
		t.Errorf("Signers = %v, want the raw agent order %v", got, want)
	}
}

func TestHeldExcludesAgentCertificates(t *testing.T) {
	c, ca := sshtest.Key(3), sshtest.Key(9)
	cert := sshtest.UserCert(t, c, ca, "deploy")
	creds := &Credentials{AgentSock: sshtest.AgentKeys(t, agent.AddedKey{PrivateKey: c, Certificate: cert})}
	signers, release, err := creds.Signers(context.Background())
	if err != nil || len(signers) != 1 {
		t.Fatalf("Signers = (%d, %v), want the certificate offered", len(signers), err)
	}
	release()
	held, err := creds.Held(context.Background())
	if err != nil || len(held) != 0 {
		t.Errorf("Held = (%v, %v), want empty: certificates never count", held, err)
	}
}

func TestBrokenAgentDegradesOnce(t *testing.T) {
	log, buf := warnLog()
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/ci", sshtest.Key(1))}, AgentSock: deadSock(t), Log: log}
	for range 2 {
		signers, release, err := creds.Signers(context.Background())
		if err != nil || len(signers) != 1 {
			t.Fatalf("Signers = (%d, %v), want the file key alone", len(signers), err)
		}
		release()
		held, err := creds.Held(context.Background())
		if err != nil || len(held) != 1 || held[0].Source != "/k/ci" {
			t.Fatalf("Held = (%v, %v), want the file key alone and a nil error (fail-safe)", held, err)
		}
	}
	if n := strings.Count(buf.String(), "ssh-agent unusable"); n != 1 {
		t.Errorf("warnings = %d, want exactly one per run:\n%s", n, buf.String())
	}
}

func TestUnsetAgentWithFileKeyIsSilent(t *testing.T) {
	log, buf := warnLog()
	creds := &Credentials{Files: []keyfile.Identity{sshtest.Identity(t, "/k/ci", sshtest.Key(1))}, Log: log}
	signers, release, err := creds.Signers(context.Background())
	if err != nil || len(signers) != 1 {
		t.Fatalf("Signers = (%d, %v), want the file key", len(signers), err)
	}
	release()
	if held, err := creds.Held(context.Background()); err != nil || len(held) != 1 {
		t.Fatalf("Held = (%v, %v)", held, err)
	}
	if buf.Len() != 0 {
		t.Errorf("an unset SSH_AUTH_SOCK must not warn: %q", buf.String())
	}
}

func TestNoKeysAtAllIsAnAgentError(t *testing.T) {
	for name, sock := range map[string]string{"dead socket": deadSock(t), "unset": ""} {
		t.Run(name, func(t *testing.T) {
			creds := &Credentials{AgentSock: sock}
			_, _, err := creds.Signers(context.Background())
			if err == nil || kindOf(t, err) != fleet.ErrorKindAgent {
				t.Fatalf("Signers err = %v, want ErrorKindAgent", err)
			}
			if _, err := creds.Held(context.Background()); err == nil {
				t.Fatal("Held with no keys at all returned no error")
			}
		})
	}
}

func TestHeldKeyLabel(t *testing.T) {
	if got := (HeldKey{Fingerprint: "SHA256:x", Source: SourceAgent}).Label(); got != "SHA256:x (agent)" {
		t.Errorf("Label = %q", got)
	}
}

// TestHeldAgentOnlyErrorText pins the pre---identity wording of a failed
// agent re-list (old AgentFingerprints): an unreachable agent reads
// "SSH agent unreachable at SOCK: …".
func TestHeldAgentOnlyErrorText(t *testing.T) {
	sock := deadSock(t)
	_, err := (&Credentials{AgentSock: sock}).Held(context.Background())
	if err == nil || !strings.HasPrefix(err.Error(), "SSH agent unreachable at "+sock+": ") {
		t.Fatalf("Held err = %v, want %q prefix", err, "SSH agent unreachable at "+sock+": ")
	}
}

// TestSignersAgentOnlyErrorText pins ConnectWith's pre-slice wording for an
// unreachable agent: "connect ssh-agent: …".
func TestSignersAgentOnlyErrorText(t *testing.T) {
	_, _, err := (&Credentials{AgentSock: deadSock(t)}).Signers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "connect ssh-agent: ") {
		t.Fatalf("Signers err = %v, want the connect ssh-agent wording", err)
	}
}
