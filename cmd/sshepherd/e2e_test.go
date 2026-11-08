//go:build integration

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/sshconn"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// itE2E reads the integration env (scripts/integration.sh) or skips, and
// builds the real binary once per test.
func itE2E(t *testing.T) (bin, host, port, kh, pubLine string) {
	t.Helper()
	host = os.Getenv("SSHEPHERD_IT_HOST")
	if host == "" {
		t.Skip("integration env not set; run via make integration")
	}
	port = os.Getenv("SSHEPHERD_IT_PORT")
	kh = os.Getenv("SSHEPHERD_IT_KNOWN_HOSTS")
	pub, err := os.ReadFile(os.Getenv("SSHEPHERD_IT_PUB"))
	if err != nil {
		t.Fatalf("SSHEPHERD_IT_PUB: %v", err)
	}
	bin = filepath.Join(t.TempDir(), "sshepherd")
	out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin, host, port, kh, strings.TrimSpace(string(pub))
}

// runBin executes the built binary with the inherited environment (the
// harness's SSH_AUTH_SOCK) and returns exit code, stdout, stderr.
func runBin(t *testing.T, bin string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), bin, args...)
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = exitErr.ExitCode()
	}
	return code, out.String(), errBuf.String()
}

func writeE2EManifest(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil { // #nosec G703 -- t.TempDir path
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestE2EApplyLoop drives the built binary through the testing policy's
// distribute → audit → revoke → rotate flow against the docker fleet:
// adopt → apply --json --yes (first write, normalizes everything; the
// parsed document says applied) → apply --dry-run (no-op, byte-stable) →
// revoke --key --dry-run (plan, manifest untouched) → revoke --key --json
// --yes (edit saved, server applied) → audit exits 0 → the lockout guard trips
// on a manifest holding none of the agent's keys (file untouched) → rotate
// the operator's agent key to a key-file key → audit exits 0. Ordered
// subtests: each stage's on-server state is the next stage's input.
func TestE2EApplyLoop(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	keys := itKeys(t)
	dir := t.TempDir()

	// m0: the operator's key (held by the harness agent) on server e2e.
	m0Body := `
users:
  - {name: op, operator: true, keys: ["` + pub + `"]}
servers:
  - {name: e2e, host: ` + host + `, port: ` + port + `, user: e2e}
`
	m0 := writeE2EManifest(t, dir, "m0.yaml", m0Body)
	adopted := filepath.Join(dir, "adopted.yaml")

	t.Run("adopt discovers the stale key", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "adopt", "--config", m0, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("adopt exit = %d (stderr: %s)", code, stderr)
		}
		if !strings.Contains(out, "adopted from") {
			t.Fatalf("adopt output lacks an adopted user:\n%s", out)
		}
		if err := os.WriteFile(adopted, []byte(out), 0o600); err != nil {
			t.Fatalf("write adopted manifest: %v", err)
		}
	})

	t.Run("first apply normalizes and verifies (--json)", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "apply", "--json", "--yes", "--config", adopted, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		var doc struct {
			Summary struct {
				Applied  int `json:"applied"`
				ExitCode int `json:"exit_code"`
			} `json:"summary"`
			Servers []struct {
				Outcome *string `json:"outcome"`
			} `json:"servers"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
		}
		if doc.Summary.Applied != 1 || doc.Summary.ExitCode != 0 || len(doc.Servers) != 1 ||
			doc.Servers[0].Outcome == nil || *doc.Servers[0].Outcome != "applied" {
			t.Errorf("apply document = %+v\n%s", doc, out)
		}
	})

	t.Run("re-apply is a byte-stable no-op", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "apply", "--dry-run", "--config", adopted, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("dry-run exit = %d, want 0 (converged) (stderr: %s)\n%s", code, stderr, out)
		}
		if !strings.Contains(out, "converged (no changes)") {
			t.Errorf("dry-run output lacks convergence:\n%s", out)
		}
	})

	stalePub := filepath.Join(keys, "stale.pub")

	t.Run("revoke --key --dry-run plans the remove and saves nothing", func(t *testing.T) {
		before, err := os.ReadFile(adopted)
		if err != nil {
			t.Fatal(err)
		}
		code, out, stderr := runBin(t, bin, "revoke", "--key", stalePub, "--dry-run", "--config", adopted, "--known-hosts", kh)
		if code != 1 {
			t.Fatalf("dry-run exit = %d, want 1 (pending change) (stderr: %s)\n%s", code, stderr, out)
		}
		for _, want := range []string{"manifest edit: remove key ", "(revoked)", "remove (unauthorized)"} {
			if !strings.Contains(out, want) {
				t.Errorf("plan lacks %q:\n%s", want, out)
			}
		}
		if after, _ := os.ReadFile(adopted); string(after) != string(before) {
			t.Error("--dry-run changed the manifest")
		}
	})

	t.Run("revoke --key --json saves the manifest and converges", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "revoke", "--key", stalePub, "--json", "--yes", "--config", adopted, "--known-hosts", kh)
		if code != 0 {
			t.Fatalf("revoke exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		var doc struct {
			Command string `json:"command"`
			Edit    struct {
				Saved bool `json:"saved"`
				Edits []struct {
					Kind       string `json:"kind"`
					NoKeysLeft *bool  `json:"no_keys_left"`
				} `json:"edits"`
			} `json:"edit"`
			Summary struct {
				ExitCode int `json:"exit_code"`
			} `json:"summary"`
			Servers []struct {
				Name    string  `json:"name"`
				Outcome *string `json:"outcome"`
			} `json:"servers"`
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("stdout is not one JSON document: %v\n%s", err, out)
		}
		if doc.Command != "revoke" || !doc.Edit.Saved || len(doc.Edit.Edits) != 1 || doc.Edit.Edits[0].Kind != "remove-key" ||
			doc.Edit.Edits[0].NoKeysLeft == nil || !*doc.Edit.Edits[0].NoKeysLeft || doc.Summary.ExitCode != 0 || len(doc.Servers) == 0 {
			t.Errorf("revoke document = %+v\n%s", doc, out)
		}
		for _, s := range doc.Servers {
			if s.Outcome == nil || *s.Outcome != "applied" {
				t.Errorf("server %s outcome = %v, want applied\n%s", s.Name, s.Outcome, out)
			}
		}
	})

	// The revoke saved serial 1 and wrote it to the server: the hand-written
	// m0 must say so too, or audit reports the newer header as drift (D4a).
	m1 := writeE2EManifest(t, dir, "m1.yaml", "serial: 1\n"+m0Body)

	t.Run("audit is clean after the revoke", func(t *testing.T) {
		if code, out, stderr := runBin(t, bin, "audit", "--config", adopted, "--known-hosts", kh); code != 0 {
			t.Fatalf("audit exit = %d, want 0 — the revoke loop must close (stderr: %s)\n%s", code, stderr, out)
		}
		if code, out, stderr := runBin(t, bin, "audit", "--config", m1, "--known-hosts", kh); code != 0 {
			t.Fatalf("audit (m1) exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
		}
	})

	t.Run("lockout guard refuses and leaves the file alone", func(t *testing.T) {
		ghost := writeE2EManifest(t, dir, "ghost.yaml", `serial: 1
users:
  - {name: ghost, keys: ["`+testkeys.Line(t, 42)+`"]}
servers:
  - {name: e2e, host: `+host+`, port: `+port+`, user: e2e}
access:
  - {user: ghost, servers: [e2e]}
`)
		code, out, _ := runBin(t, bin, "apply", "--yes", "--config", ghost, "--known-hosts", kh)
		if code != 1 {
			t.Fatalf("lockout apply exit = %d, want 1\n%s", code, out)
		}
		if !strings.Contains(out, "REFUSED:") || !strings.Contains(out, "lock this session out") {
			t.Errorf("output lacks the guard refusal:\n%s", out)
		}
		// The file is untouched: the m1 audit still passes byte-for-byte.
		if code, out, stderr := runBin(t, bin, "audit", "--config", m1, "--known-hosts", kh); code != 0 {
			t.Fatalf("post-refusal audit exit = %d, want 0 (the refused write must not have touched the file) (stderr: %s)\n%s", code, stderr, out)
		}
	})

	ciOld := filepath.Join(keys, "ci_old")

	t.Run("rotate swaps the operator key for a key-file key", func(t *testing.T) {
		code, out, stderr := runBin(t, bin, "rotate", "op", "--old", os.Getenv("SSHEPHERD_IT_PUB"), "--new", ciOld+".pub",
			"--operator", "--yes", "--config", adopted, "--known-hosts", kh, "--identity", ciOld)
		if code != 0 {
			t.Fatalf("rotate exit = %d (stderr: %s)\n%s", code, stderr, out)
		}
		for _, want := range []string{"OPERATOR: op is an operator", "op (rotated out)", "removes the key this session logged in with", "applied · verified"} {
			if !strings.Contains(out, want) {
				t.Errorf("rotate output lacks %q:\n%s", want, out)
			}
		}
		b, err := os.ReadFile(adopted)
		if err != nil || !strings.Contains(string(b), strings.Fields(itPubLine(t, keys, "ci_old"))[1]) ||
			strings.Contains(string(b), strings.Fields(pub)[1]) {
			t.Errorf("manifest after rotate must hold ci_old and not the agent key (%v):\n%s", err, b)
		}
	})

	t.Run("audit is clean after the rotation", func(t *testing.T) {
		if code, out, stderr := runBin(t, bin, "audit", "--config", adopted, "--known-hosts", kh, "--identity", ciOld); code != 0 {
			t.Fatalf("audit exit = %d, want 0 — the rotate loop must close (stderr: %s)\n%s", code, stderr, out)
		}
	})
}

// e2eRemoteCat reads user's ~/.ssh/authorized_keys over a real connection —
// the assertion channel for "the file was left untouched".
func e2eRemoteCat(t *testing.T, host, port, kh, user string) string {
	t.Helper()
	p, err := strconv.Atoi(port)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	d := &sshconn.Dialer{KnownHostsPath: kh, Creds: &sshconn.Credentials{AgentSock: os.Getenv("SSH_AUTH_SOCK")}, DialTimeout: 10 * time.Second}
	conn, err := d.Connect(ctx, config.Server{Name: user, Host: host, Port: p, User: user})
	if err != nil {
		t.Fatalf("connect %s: %v", user, err)
	}
	defer func() { _ = conn.Close() }()
	code, stdout, stderr, err := sshconn.Exec(ctx, conn.Client, `cat "$HOME/.ssh/authorized_keys"`, nil)
	if err != nil || code != 0 {
		t.Fatalf("cat: code %d, err %v, stderr %q", code, err, stderr.String())
	}
	return stdout.String()
}

// TestE2EApplyRefusesUnparseable: a server whose file holds a line apply
// cannot parse is refused (a full-file rewrite would destroy it), exit 1,
// and the file is byte-identical afterwards.
func TestE2EApplyRefusesUnparseable(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	before := e2eRemoteCat(t, host, port, kh, "unparse")
	m := writeE2EManifest(t, t.TempDir(), "m.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
servers:
  - {name: unparse, host: `+host+`, port: `+port+`, user: unparse}
`)
	code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh)
	if code != 1 {
		t.Fatalf("apply exit = %d, want 1 (stderr: %s)\n%s", code, stderr, out)
	}
	if !strings.Contains(out, "REFUSED:") || !strings.Contains(out, "unparseable line") {
		t.Errorf("output lacks the unparseable refusal:\n%s", out)
	}
	if after := e2eRemoteCat(t, host, port, kh, "unparse"); after != before {
		t.Errorf("file = %q, want it untouched (%q)", after, before)
	}
}

// TestE2ERevokeServer: tmp is granted trim-a and trim-b; revoke tmp
// --server trim-a removes the key from trim-a only (trim-b is never
// contacted), the manifest keeps tmp with trim-b, and audit is clean.
func TestE2ERevokeServer(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	stale := itPubLine(t, itKeys(t), "stale")
	m := writeE2EManifest(t, t.TempDir(), "trim.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
  - {name: tmp, keys: ["`+stale+`"]}
servers:
  - {name: trim-a, host: `+host+`, port: `+port+`, user: trima}
  - {name: trim-b, host: `+host+`, port: `+port+`, user: trimb}
access:
  - {user: tmp, servers: [trim-a, trim-b]}
`)
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	code, out, stderr := runBin(t, bin, "revoke", "tmp", "--server", "trim-a", "--yes", "--config", m, "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("revoke --server exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	for _, want := range []string{"manifest edit: remove tmp's access to trim-a (1 access entry changed); tmp keeps access to 1 other server — 1 server affected", "trim-a: applied · verified"} {
		if !strings.Contains(out, want) {
			t.Errorf("revoke output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "trim-b:") {
		t.Errorf("trim-b was contacted:\n%s", out)
	}
	blob := strings.Fields(stale)[1]
	if got := e2eRemoteCat(t, host, port, kh, "trima"); strings.Contains(got, blob) {
		t.Errorf("trim-a still holds tmp's key:\n%s", got)
	}
	if got := e2eRemoteCat(t, host, port, kh, "trimb"); !strings.Contains(got, blob) {
		t.Errorf("trim-b lost tmp's key:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
}

// TestE2ERotateKeepOld: rotate --keep-old installs the new key beside the
// old one (audit clean with both), and the printed finish — revoke --key
// OLD — leaves only the new key (audit clean again).
func TestE2ERotateKeepOld(t *testing.T) {
	bin, host, port, kh, pub := itE2E(t)
	keys := itKeys(t)
	stale, ciOld := itPubLine(t, keys, "stale"), itPubLine(t, keys, "ci_old")
	m := writeE2EManifest(t, t.TempDir(), "overlap.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
  - {name: deploy, keys: ["`+stale+`"]}
servers:
  - {name: ov, host: `+host+`, port: `+port+`, user: overlap}
access:
  - {user: deploy, servers: [ov]}
`)
	if code, out, stderr := runBin(t, bin, "apply", "--yes", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("apply exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	code, out, stderr := runBin(t, bin, "rotate", "deploy", "--old", filepath.Join(keys, "stale.pub"), "--new", filepath.Join(keys, "ci_old.pub"),
		"--keep-old", "--yes", "--config", m, "--known-hosts", kh)
	if code != 0 {
		t.Fatalf("rotate --keep-old exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	const lead = "overlap started — every affected server accepts both keys; once every client uses the new key, finish with: "
	_, finish, ok := strings.Cut(out, lead)
	if !ok || !strings.Contains(out, "(keeps the old key)") {
		t.Fatalf("rotate output lacks the keep-old header or the finish hint:\n%s", out)
	}
	finish, _, _ = strings.Cut(finish, "\n")
	got := e2eRemoteCat(t, host, port, kh, "overlap")
	if !strings.Contains(got, strings.Fields(stale)[1]) || !strings.Contains(got, strings.Fields(ciOld)[1]) {
		t.Errorf("overlap must hold both keys:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit during the overlap exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
	args := strings.Fields(finish)
	if len(args) < 4 || args[0] != "sshepherd" || args[1] != "revoke" || args[2] != "--key" {
		t.Fatalf("finish = %q, want a sshepherd revoke --key command", finish)
	}
	if code, out, stderr := runBin(t, bin, append(args[1:], "--yes", "--known-hosts", kh)...); code != 0 {
		t.Fatalf("finish exit = %d (stderr: %s)\n%s", code, stderr, out)
	}
	got = e2eRemoteCat(t, host, port, kh, "overlap")
	if strings.Contains(got, strings.Fields(stale)[1]) || !strings.Contains(got, strings.Fields(ciOld)[1]) {
		t.Errorf("after the finish, overlap must hold only the new key:\n%s", got)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("audit after the finish exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
}

// TestE2EFleetFanOut drives two sshd containers: fleet-a (default path) and
// fleet-b (sshd reads ~/.ssh/fleet_keys; the manifest says so). One apply
// converges both in parallel; audit closes the loop. known_hosts is checked
// per host:port in two steps: B's entry recording A's keys must raise a
// host-key alarm (exit 2) for B alone, with A still compliant; and a cross
// swap (each entry recording the other's keys, so both real keys are still
// in the file under 127.0.0.1) must alarm on both, which a lookup that pools
// keys across ports would miss.
func TestE2EFleetFanOut(t *testing.T) {
	bin, host, portA, kh, pub := itE2E(t)
	portB := os.Getenv("SSHEPHERD_IT_PORT_B")
	if portB == "" {
		t.Fatal("SSHEPHERD_IT_PORT_B not set: scripts/integration.sh must start the second container")
	}
	dir := t.TempDir()
	m := writeE2EManifest(t, dir, "fleet.yaml", `
users:
  - {name: op, operator: true, keys: ["`+pub+`"]}
servers:
  - {name: fleet-a, host: `+host+`, port: `+portA+`, user: fleet}
  - {name: fleet-b, host: `+host+`, port: `+portB+`, user: fleet, authorized_keys_file: ~/.ssh/fleet_keys}
`)
	if a, b := hostKeyBlob(t, kh, portA), hostKeyBlob(t, kh, portB); a == b {
		t.Fatalf("both containers present the same ed25519 host key; per-host known_hosts would be untested")
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 1 ||
		!strings.Contains(out, "fleet-a") || !strings.Contains(out, "fleet-b") {
		t.Fatalf("pre-apply audit exit = %d, want 1 (stale key on both) (stderr: %s)\n%s", code, stderr, out)
	}
	code, out, stderr := runBin(t, bin, "apply", "--json", "--yes", "--config", m, "--known-hosts", kh)
	var doc struct {
		Summary struct {
			Applied int `json:"applied"`
		} `json:"summary"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &doc) != nil || doc.Summary.Applied != 2 {
		t.Fatalf("apply exit = %d applied = %d, want 0 and 2 (stderr: %s)\n%s", code, doc.Summary.Applied, stderr, out)
	}
	if code, out, stderr := runBin(t, bin, "audit", "--config", m, "--known-hosts", kh); code != 0 {
		t.Fatalf("post-apply audit exit = %d, want 0 (stderr: %s)\n%s", code, stderr, out)
	}
	// apply wrote B's override path, not the default one sshd ignores there.
	wrong := writeE2EManifest(t, dir, "wrong.yaml", strings.Replace(readFile(t, m), ", authorized_keys_file: ~/.ssh/fleet_keys", "", 1))
	if code, _, _ := runBin(t, bin, "audit", "--config", wrong, "--known-hosts", kh); code == 0 {
		t.Errorf("audit of B's default path exit 0: apply must not have written ~/.ssh/authorized_keys on fleet-b")
	}
	blobsA, blobsB := knownHostsBlobs(t, kh, portA), knownHostsBlobs(t, kh, portB)
	for _, tc := range []struct {
		name  string
		blobs map[string]map[string]string // port -> key type -> recorded blob
		want  map[string]string            // server -> error_kind ("" = verified and compliant)
	}{
		{"b-impersonated", map[string]map[string]string{portB: blobsA},
			map[string]string{"fleet-a": "", "fleet-b": "host_key_changed"}},
		{"cross-swap", map[string]map[string]string{portA: blobsB, portB: blobsA},
			map[string]string{"fleet-a": "host_key_changed", "fleet-b": "host_key_changed"}},
	} {
		swapped := filepath.Join(dir, "known_hosts."+tc.name)
		writeSwappedKnownHosts(t, kh, swapped, tc.blobs)
		code, out, stderr := runBin(t, bin, "audit", "--json", "--config", m, "--known-hosts", swapped)
		var rep struct {
			Servers []struct {
				Name      string `json:"name"`
				Status    string `json:"status"`
				ErrorKind string `json:"error_kind"`
			} `json:"servers"`
		}
		if err := json.Unmarshal([]byte(out), &rep); err != nil || code != 2 {
			t.Fatalf("%s known_hosts: exit = %d (want 2), json err = %v (stderr: %s)\n%s", tc.name, code, err, stderr, out)
		}
		got := map[string]string{}
		for _, s := range rep.Servers {
			got[s.Name] = s.ErrorKind
			if s.ErrorKind == "" && s.Status != "compliant" {
				t.Errorf("%s known_hosts: %s status = %q, want compliant", tc.name, s.Name, s.Status)
			}
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s known_hosts: servers = %v, want %v", tc.name, got, tc.want)
		}
		for name, kind := range tc.want {
			if g, ok := got[name]; !ok || g != kind {
				t.Errorf("%s known_hosts: %s error_kind = %q, want %q\n%s", tc.name, name, g, kind, out)
			}
		}
	}
}

// readFile is os.ReadFile that fails the test on error.
func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) // #nosec G304 -- harness known_hosts (SSHEPHERD_IT_KNOWN_HOSTS) or a t.TempDir path
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// knownHostsBlobs maps key type to base64 blob for the [127.0.0.1]:port
// lines of the known_hosts file kh.
func knownHostsBlobs(t *testing.T, kh, port string) map[string]string {
	t.Helper()
	blobs := map[string]string{}
	for line := range strings.Lines(readFile(t, kh)) {
		if f := strings.Fields(line); len(f) >= 3 && f[0] == "[127.0.0.1]:"+port {
			blobs[f[1]] = f[2]
		}
	}
	return blobs
}

// hostKeyBlob returns the ssh-ed25519 host key blob recorded for port.
func hostKeyBlob(t *testing.T, kh, port string) string {
	t.Helper()
	blob := knownHostsBlobs(t, kh, port)["ssh-ed25519"]
	if blob == "" {
		t.Fatalf("%s has no [127.0.0.1]:%s ssh-ed25519 line", kh, port)
	}
	return blob
}

// writeSwappedKnownHosts copies kh to dst, recording on every
// [127.0.0.1]:port line of a port in blobs the blob blobs[port] holds for
// that line's key type (that host now looks impersonated). A line whose type
// has no replacement fails the test: left genuine, it would still verify.
func writeSwappedKnownHosts(t *testing.T, kh, dst string, blobs map[string]map[string]string) {
	t.Helper()
	var b strings.Builder
	for line := range strings.Lines(readFile(t, kh)) {
		f := strings.Fields(line)
		for port, repl := range blobs {
			if len(f) < 3 || f[0] != "[127.0.0.1]:"+port {
				continue
			}
			if repl[f[1]] == "" {
				t.Fatalf("%s: no %s key to record on the [127.0.0.1]:%s line", kh, f[1], port)
			}
			line = f[0] + " " + f[1] + " " + repl[f[1]] + "\n"
		}
		b.WriteString(line)
	}
	if err := os.WriteFile(dst, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write %s: %v", dst, err)
	}
}
