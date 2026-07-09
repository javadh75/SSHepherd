//go:build integration

package sshread

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
)

// itClient builds a Client from the environment exported by
// scripts/integration.sh; skips when not running under it.
func itClient(t *testing.T) (*Client, string, int) {
	t.Helper()
	host := os.Getenv("SSHEPHERD_IT_HOST")
	if host == "" {
		t.Skip("integration env not set; run via make integration")
	}
	port, err := strconv.Atoi(os.Getenv("SSHEPHERD_IT_PORT"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PORT: %v", err)
	}
	return &Client{
		KnownHostsPath: os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS"),
		AgentSock:      os.Getenv("SSH_AUTH_SOCK"),
		DialTimeout:    10 * time.Second,
	}, host, port
}

func TestIntegrationReadPresent(t *testing.T) {
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{
		Name: "it", Host: host, Port: port, User: "present",
	})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if res.FileAbsent {
		t.Fatal("FileAbsent = true for a seeded file")
	}
	if !strings.Contains(string(res.Content), "ssh-ed25519") {
		t.Errorf("content = %q, want the seeded key", res.Content)
	}
}

func TestIntegrationFileAbsent(t *testing.T) {
	// User "absent" logs in via authorized_keys2 (custom AuthorizedKeysFile),
	// so the default file genuinely does not exist: the paradox case.
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{
		Name: "it", Host: host, Port: port, User: "absent",
	})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if !res.FileAbsent {
		t.Error("FileAbsent = false, want true")
	}
	if len(res.Content) != 0 {
		t.Errorf("content = %q, want empty", res.Content)
	}
}

func TestIntegrationUnknownHostKey(t *testing.T) {
	c, host, port := itClient(t)
	empty := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c.KnownHostsPath = empty
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := c.ReadAuthorizedKeys(ctx, config.Server{
		Name: "it", Host: host, Port: port, User: "present",
	})
	if err == nil || !strings.Contains(err.Error(), "ssh-keyscan") {
		t.Errorf("err = %v, want strict-host-key failure with keyscan hint", err)
	}
}
