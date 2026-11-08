//go:build integration

package sshread

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/fleet"
	"github.com/javadh75/SSHepherd/internal/sshconn"
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
		Creds:          &sshconn.Credentials{AgentSock: os.Getenv("SSH_AUTH_SOCK")},
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
	if res.SessionKeyFP == "" {
		t.Error("SessionKeyFP empty after a real agent-authenticated read")
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
	if err == nil || !strings.Contains(fleet.HintOf(err), "| ssh-keygen -lf -") {
		t.Errorf("err = %v, want strict-host-key failure with a compare-first keyscan hint", err)
	}
	if fleet.ErrorKindOf(err) != fleet.ErrorKindHostKeyUnknown {
		t.Errorf("kind = %q, want host_key_unknown", fleet.ErrorKindOf(err))
	}
}

// TestIntegrationKeys2OnAbsoluteDefaultPath (WP-10): the absolute spelling
// of the default file still probes authorized_keys2 on a real sshd. User
// "absent" has a non-empty authorized_keys2 and no default file.
func TestIntegrationKeys2OnAbsoluteDefaultPath(t *testing.T) {
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{
		Name: "it", Host: host, Port: port, User: "absent", AuthorizedKeysFile: "/home/absent/.ssh/authorized_keys",
	})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if !res.FileAbsent || !res.AuthorizedKeys2 {
		t.Errorf("FileAbsent=%v AuthorizedKeys2=%v, want both true (the absolute spelling of the default file)", res.FileAbsent, res.AuthorizedKeys2)
	}
}

// TestIntegrationReadKeys2Content: on a real sshd and every distro's shell,
// ReadKeys2 returns authorized_keys2's bytes. Container A's user "absent"
// has no default file and the seed key (SSHEPHERD_IT_PUB) in
// authorized_keys2 (scripts/integration.sh).
func TestIntegrationReadKeys2Content(t *testing.T) {
	c, host, port := itClient(t)
	want, err := os.ReadFile(os.Getenv("SSHEPHERD_IT_PUB")) // #nosec G703 -- harness key path (SSHEPHERD_IT_PUB)
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PUB: %v", err)
	}
	c.ReadKeys2 = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "it", Host: host, Port: port, User: "absent"})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if !res.AuthorizedKeys2 || res.Keys2Err != nil || !bytes.Equal(bytes.TrimSpace(res.Keys2), bytes.TrimSpace(want)) {
		t.Errorf("Keys2 = %q (err %v, present %v), want the seed key %q", res.Keys2, res.Keys2Err, res.AuthorizedKeys2, want)
	}
}

// TestIntegrationPostureGroupWritable: on a real sshd and every distro's
// shell, a 0775 directory reports group_writable. User "loose" logs in via
// its 0700 ~/.ssh; the managed file is an override below a 0775 ~/loose, so
// sshd's StrictModes (on in the container) still lets the login through.
func TestIntegrationPostureGroupWritable(t *testing.T) {
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "it", Host: host, Port: port, User: "loose", AuthorizedKeysFile: "~/loose/keys"})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if len(res.Posture) != 1 || res.Posture[0].Issue != fleet.PostureGroupWritable || res.Posture[0].Path != "/home/loose/loose" {
		t.Fatalf("posture = %+v, want one group_writable finding on /home/loose/loose", res.Posture)
	}
	if !strings.HasPrefix(res.Posture[0].Mode, "drwxrwx") {
		t.Errorf("mode = %q", res.Posture[0].Mode)
	}
}

// TestIntegrationPostureRootOwnedClean (D14a): sshd accepts root as owner of
// the file and of its directory, so audit does too, although apply refuses
// both (TestIntegrationOwnershipRefusals). The fixtures are read-only here.
func TestIntegrationPostureRootOwnedClean(t *testing.T) {
	c, host, port := itClient(t)
	for _, user := range []string{"ffile", "fdir"} { // root-owned authorized_keys; root-owned ~/.ssh
		t.Run(user, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			res, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: user, Host: host, Port: port, User: user})
			if err != nil {
				t.Fatalf("ReadAuthorizedKeys: %v", err)
			}
			if len(res.Posture) != 0 {
				t.Errorf("posture = %+v, want clean: root is an accepted owner", res.Posture)
			}
		})
	}
}

// TestIntegrationPostureClean: a stock fixture user has no findings.
func TestIntegrationPostureClean(t *testing.T) {
	c, host, port := itClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ReadAuthorizedKeys(ctx, config.Server{Name: "it", Host: host, Port: port, User: "present"})
	if err != nil {
		t.Fatalf("ReadAuthorizedKeys: %v", err)
	}
	if len(res.Posture) != 0 {
		t.Errorf("posture = %+v, want clean", res.Posture)
	}
}
