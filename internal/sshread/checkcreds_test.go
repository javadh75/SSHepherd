package sshread

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/agent"

	"github.com/javadh75/SSHepherd/internal/keyfile"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/sshconn/sshtest"
)

func TestCheckCredentials(t *testing.T) {
	file := []keyfile.Identity{sshtest.Identity(t, "/k/ci", sshtest.Key(1))}
	dead := filepath.Join(t.TempDir(), "dead.sock")
	c, ca := sshtest.Key(3), sshtest.Key(9)
	certOnly := sshtest.AgentKeys(t, agent.AddedKey{PrivateKey: c, Certificate: sshtest.UserCert(t, c, ca, "deploy")})
	tests := []struct {
		name     string
		creds    *sshconn.Credentials
		needHeld bool
		wantErr  string // "" = ok
	}{
		{"no identity, no agent: today's message", &sshconn.Credentials{}, false, "no SSH agent: SSH_AUTH_SOCK is not set (start ssh-agent and ssh-add a key)"},
		{"no identity, dead agent: today's message", &sshconn.Credentials{AgentSock: dead}, true, "SSH agent unreachable at " + dead},
		{"no identity, empty agent: today's message", &sshconn.Credentials{AgentSock: sshtest.Agent(t)}, false, "has no keys loaded (run ssh-add to load your key)"},
		{"no identity, agent with a key", &sshconn.Credentials{AgentSock: sshtest.Agent(t, sshtest.Key(2))}, true, ""},
		{"cert-only agent is enough to read", &sshconn.Credentials{AgentSock: certOnly}, false, ""},
		{"cert-only agent is refused for apply", &sshconn.Credentials{AgentSock: certOnly}, true, "are all certificates"},
		{"file key, no agent: read", &sshconn.Credentials{Files: file}, false, ""},
		{"file key, no agent: apply", &sshconn.Credentials{Files: file}, true, ""},
		{"file key, dead agent: read degrades", &sshconn.Credentials{Files: file, AgentSock: dead}, false, ""},
		{"file key, dead agent: apply degrades", &sshconn.Credentials{Files: file, AgentSock: dead}, true, ""},
		{"file key, cert-only agent: apply holds the file key", &sshconn.Credentials{Files: file, AgentSock: certOnly}, true, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckCredentials(context.Background(), tt.creds, tt.needHeld)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("CheckCredentials = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("CheckCredentials = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
