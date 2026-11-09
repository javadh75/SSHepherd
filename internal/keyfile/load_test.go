package keyfile

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakePrompter answers prompts from a script.
type fakePrompter struct {
	avail    bool
	answers  []string
	prompts  []string
	onPrompt func() // runs before answering (e.g. cancel the ctx)
}

func (p *fakePrompter) Available() bool { return p.avail }

func (p *fakePrompter) ReadPassphrase(ctx context.Context, prompt string) ([]byte, error) {
	p.prompts = append(p.prompts, prompt)
	if p.onPrompt != nil {
		p.onPrompt()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(p.answers) == 0 {
		return nil, errors.New("fake prompter: no answer scripted")
	}
	a := p.answers[0]
	p.answers = p.answers[1:]
	return []byte(a), nil
}

// logBuffer captures log output at debug level.
func logBuffer() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// fpOf is the SHA256 fingerprint of priv's public key.
func fpOf(t testing.TB, priv any) string {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return ssh.FingerprintSHA256(s.PublicKey())
}

// pubLine is priv's authorized_keys line (a sibling .pub file's content).
func pubLine(t testing.TB, priv any) []byte {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return ssh.MarshalAuthorizedKey(s.PublicKey())
}

// paddingFooler finds a wrong passphrase under which data's legacy PEM
// still decrypts with valid padding (about 1 in 256 do), yielding garbage —
// the case x509.DecryptPEMBlock cannot detect.
func paddingFooler(t testing.TB, data []byte, right string) string {
	t.Helper()
	block, _ := pem.Decode(data)
	for i := range 100000 {
		cand := "wrong-" + big.NewInt(int64(i)).String()
		if cand == right {
			continue
		}
		//nolint:staticcheck // SA1019: probing the legacy format's undetectable wrong passwords
		if _, err := x509.DecryptPEMBlock(block, []byte(cand)); err == nil {
			return cand
		}
	}
	t.Fatal("no padding-fooling passphrase found")
	return ""
}

// pubWire is priv's public key in wire format (an OpenSSH header's PubKey).
func pubWire(t testing.TB, priv any) []byte {
	t.Helper()
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return s.PublicKey().Marshal()
}

// load runs Load over fsys with the given passphrases and prompter.
func load(t *testing.T, fsys *fakeFS, pp Passphrases, p Prompter, paths ...string) ([]Identity, string, error) {
	t.Helper()
	specs := make([]Spec, 0, len(paths))
	for _, p := range paths {
		specs = append(specs, Spec{Path: p})
	}
	log, buf := logBuffer()
	ids, err := Load(context.Background(), specs, pp, p, fsys, log)
	return ids, buf.String(), err
}

func TestLoadUnencrypted(t *testing.T) {
	ed := edKey(1)
	f := newFS().key("/k", opensshPEM(t, ed, nil))
	p := &fakePrompter{avail: true}
	ids, logs, err := load(t, f, Passphrases{}, p, "/k")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(ids) != 1 || ids[0].Path != "/k" || ids[0].Fingerprint != fpOf(t, ed) {
		t.Fatalf("ids = %+v, want /k with the decrypted fingerprint", ids)
	}
	if len(p.prompts) != 0 {
		t.Errorf("prompted %d times for an unencrypted key", len(p.prompts))
	}
	if !strings.Contains(logs, "identity loaded") || !strings.Contains(logs, fpOf(t, ed)) {
		t.Errorf("logs = %q, want the identity-loaded line with its fingerprint", logs)
	}
}

func TestLoadNoSpecs(t *testing.T) {
	ids, err := Load(context.Background(), nil, Passphrases{}, nil, newFS(), nil)
	if ids != nil || err != nil {
		t.Fatalf("Load(nil) = (%v, %v), want (nil, nil)", ids, err)
	}
}

func TestLoadPassphraseResolution(t *testing.T) {
	// The resolution order is container-independent, so the table runs on
	// legacy PEM (cheap KDF); the OpenSSH-specific wrong-passphrase signal
	// is pinned by TestLoadOpenSSHPassphrase.
	k := ecKey(t)
	enc := legacyPEM(t, k, []byte("right"))
	tests := []struct {
		name        string
		files       map[string]string // passphrase files
		pp          Passphrases
		prompter    *fakePrompter
		wantErr     []string
		wantPrompts int
	}{
		{name: "per-key ok", files: map[string]string{"/pk": "right\n"}, pp: Passphrases{PerKey: map[string]string{"/k": "/pk"}}, prompter: &fakePrompter{avail: true}},
		{name: "per-key wrong is exit 3 with no fallback", files: map[string]string{"/pk": "wrong\n", "/def": "right\n"},
			pp: Passphrases{Default: "/def", PerKey: map[string]string{"/k": "/pk"}}, prompter: &fakePrompter{avail: true, answers: []string{"right"}},
			wantErr: []string{"/k: the passphrase in /pk (--identity-passphrase) does not unlock it"}},
		{name: "default ok", files: map[string]string{"/def": "right"}, pp: Passphrases{Default: "/def"}, prompter: &fakePrompter{}},
		{name: "default wrong falls through to the prompt", files: map[string]string{"/def": "wrong"}, pp: Passphrases{Default: "/def"},
			prompter: &fakePrompter{avail: true, answers: []string{"right"}}, wantPrompts: 1},
		{name: "default wrong and headless names the default", files: map[string]string{"/def": "wrong"}, pp: Passphrases{Default: "/def"},
			prompter: &fakePrompter{}, wantErr: []string{"/k is encrypted and no passphrase source is available (use --identity-passphrase-file or --identity-passphrase PATH=FILE)", "the default passphrase file /def did not unlock it"}},
		{name: "prompt ok", prompter: &fakePrompter{avail: true, answers: []string{"right"}}, wantPrompts: 1},
		{name: "prompt wrong then right", prompter: &fakePrompter{avail: true, answers: []string{"no", "right"}}, wantPrompts: 2},
		{name: "prompt wrong three times", prompter: &fakePrompter{avail: true, answers: []string{"a", "b", "c", "right"}}, wantPrompts: 3,
			wantErr: []string{"/k: 3 incorrect passphrase attempts"}},
		{name: "headless, no source", prompter: &fakePrompter{}, wantErr: []string{"/k is encrypted and no passphrase source is available"}},
		{name: "nil prompter is headless", prompter: nil, wantErr: []string{"no passphrase source is available"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFS().key("/k", enc)
			for path, content := range tt.files {
				f.key(path, []byte(content))
			}
			var p Prompter
			if tt.prompter != nil {
				p = tt.prompter
			}
			ids, _, err := load(t, f, tt.pp, p, "/k")
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("Load succeeded, want %q", tt.wantErr)
				}
				for _, w := range tt.wantErr {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("err = %q, want it to contain %q", err, w)
					}
				}
			} else if err != nil || len(ids) != 1 || ids[0].Fingerprint != fpOf(t, k) {
				t.Fatalf("Load = (%+v, %v), want the decrypted key", ids, err)
			}
			if tt.prompter != nil && len(tt.prompter.prompts) != tt.wantPrompts {
				t.Errorf("prompts = %d, want %d", len(tt.prompter.prompts), tt.wantPrompts)
			}
		})
	}
}

func TestLoadOpenSSHPassphrase(t *testing.T) {
	enc := sharedEncrypted(t)
	t.Run("x509.IncorrectPasswordError is a wrong passphrase", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/pk", []byte("wrong"))
		_, _, err := load(t, f, Passphrases{PerKey: map[string]string{"/k": "/pk"}}, nil, "/k")
		if err == nil || !strings.Contains(err.Error(), "does not unlock it") {
			t.Fatalf("err = %v, want the wrong-passphrase verdict", err)
		}
	})
	t.Run("prompt unlocks, labelled with the embedded public key", func(t *testing.T) {
		p := &fakePrompter{avail: true, answers: []string{sharedPass}}
		ids, _, err := load(t, newFS().key("/k", enc), Passphrases{}, p, "/k")
		if err != nil || len(ids) != 1 || ids[0].Fingerprint != fpOf(t, edKey(2)) {
			t.Fatalf("Load = (%+v, %v)", ids, err)
		}
		want := "waiting for passphrase for /k on the terminal\nEnter passphrase for /k (" + fpOf(t, edKey(2)) + "): "
		if len(p.prompts) != 1 || p.prompts[0] != want {
			t.Errorf("prompts = %q, want [%q]", p.prompts, want)
		}
	})
	t.Run("the embedded public key is only a label: a mismatch is refused after decryption", func(t *testing.T) {
		// x/crypto never compares the header's public key with the
		// decrypted one; Load does, and the fingerprint is the decrypted
		// key's, never the label's.
		bad := editOpenSSH(t, enc, func(h *opensshHeader) { h.PubKey = pubWire(t, edKey(13)) })
		p := &fakePrompter{avail: true, answers: []string{sharedPass}}
		ids, _, err := load(t, newFS().key("/k", bad), Passphrases{}, p, "/k")
		if err == nil || ids != nil || !strings.Contains(err.Error(), "/k: embedded public key does not match the private key") {
			t.Fatalf("Load = (%+v, %v), want the mismatch refusal", ids, err)
		}
		if len(p.prompts) != 1 || !strings.Contains(p.prompts[0], "("+fpOf(t, edKey(13))+")") {
			t.Errorf("prompts = %q, want one prompt labelled with the embedded (pre-decryption) key", p.prompts)
		}
	})
}

func TestLoadPromptText(t *testing.T) {
	k := ecKey(t)
	f := newFS().key("/k", legacyPEM(t, k, []byte("right")))
	p := &fakePrompter{avail: true, answers: []string{"no", "right"}}
	if _, _, err := load(t, f, Passphrases{}, p, "/k"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	// No .pub sibling: no label.
	if want := "waiting for passphrase for /k on the terminal\nEnter passphrase for /k: "; p.prompts[0] != want {
		t.Errorf("first prompt = %q, want %q", p.prompts[0], want)
	}
	if p.prompts[1] != "Bad passphrase, try again for /k: " {
		t.Errorf("retry prompt = %q", p.prompts[1])
	}
}

func TestLoadPromptCanceled(t *testing.T) {
	f := newFS().key("/k", sharedEncrypted(t))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p := &fakePrompter{avail: true, onPrompt: cancel}
	_, err := Load(ctx, []Spec{{"/k"}}, Passphrases{}, p, f, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled (the interrupted path)", err)
	}
}

func TestLoadPipeDefaultForTwoKeys(t *testing.T) {
	a, b := ecKey(t), ecKey(t)
	f := newFS().key("/a", legacyPEM(t, a, []byte("shared"))).key("/b", legacyPEM(t, b, []byte("shared"))).
		fifo("/dev/fd/63", []byte("shared\n"))
	ids, _, err := load(t, f, Passphrases{Default: "/dev/fd/63"}, &fakePrompter{}, "/a", "/b")
	if err != nil || len(ids) != 2 {
		t.Fatalf("Load = (%d ids, %v), want both keys unlocked by the one pipe", len(ids), err)
	}
	if n := f.opens["/dev/fd/63"]; n != 1 {
		t.Errorf("pipe opened %d times, want 1", n)
	}
}

func TestLoadEmptyPassphraseFileNeverTried(t *testing.T) {
	f := newFS().key("/k", sharedEncrypted(t)).key("/empty", []byte("\r\n"))
	_, _, err := load(t, f, Passphrases{Default: "/empty"}, &fakePrompter{avail: true, answers: []string{""}}, "/k")
	if err == nil || !strings.Contains(err.Error(), "passphrase file /empty is empty") {
		t.Fatalf("err = %v, want the empty-file exit (never tried as an empty passphrase)", err)
	}
}

func TestLoadJoinsEveryKeyError(t *testing.T) {
	f := newFS().
		regular("/loose", opensshPEM(t, edKey(8), nil), 0o644).
		key("/ppk", []byte("PuTTY-User-Key-File-3: ssh-ed25519\n")).
		key("/enc", sharedEncrypted(t))
	p := &fakePrompter{avail: true, answers: []string{sharedPass}}
	_, _, err := load(t, f, Passphrases{}, p, "/loose", "/missing", "/ppk", "/enc")
	if err == nil {
		t.Fatal("Load succeeded")
	}
	for _, w := range []string{"permissions 0644 for /loose", "key file /missing", "/ppk is a PuTTY key"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("err = %q, want it to contain %q", err, w)
		}
	}
	if len(p.prompts) != 0 {
		t.Errorf("prompted %d times although the run was already failing", len(p.prompts))
	}
}

func TestLoadRefusesBeforePrompt(t *testing.T) {
	// An encrypted key in a refused container: the operator is never asked.
	enc := withRounds(t, sharedEncrypted(t), 4096)
	p := &fakePrompter{avail: true, answers: []string{sharedPass}}
	_, _, err := load(t, newFS().key("/k", enc), Passphrases{}, p, "/k")
	if err == nil || !strings.Contains(err.Error(), "exceed the supported maximum") || len(p.prompts) != 0 {
		t.Fatalf("err = %v, prompts = %d; want the rounds refusal and no prompt", err, len(p.prompts))
	}
}

func TestLoadLegacyPEM(t *testing.T) {
	k := ecKey(t)
	enc := legacyPEM(t, k, []byte("right"))
	fooler := paddingFooler(t, enc, "right")
	t.Run("unencrypted", func(t *testing.T) {
		ids, _, err := load(t, newFS().key("/k", legacyPEM(t, k, nil)), Passphrases{}, nil, "/k")
		if err != nil || len(ids) != 1 || ids[0].Fingerprint != fpOf(t, k) {
			t.Fatalf("Load = (%+v, %v)", ids, err)
		}
	})
	t.Run("valid-padding wrong default falls through like any wrong passphrase", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/def", []byte(fooler))
		p := &fakePrompter{avail: true, answers: []string{"right"}}
		ids, _, err := load(t, f, Passphrases{Default: "/def"}, p, "/k")
		if err != nil || len(ids) != 1 || len(p.prompts) != 1 {
			t.Fatalf("Load = (%d ids, %v), prompts %d; want fall-through to one prompt", len(ids), err, len(p.prompts))
		}
	})
	t.Run("valid-padding wrong per-key is a wrong passphrase, not a hard error", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/pk", []byte(fooler))
		_, _, err := load(t, f, Passphrases{PerKey: map[string]string{"/k": "/pk"}}, nil, "/k")
		if err == nil || !strings.Contains(err.Error(), "does not unlock it") {
			t.Fatalf("err = %v, want the wrong-passphrase verdict", err)
		}
	})
	t.Run("stale sibling .pub refused", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/pk", []byte("right")).key("/k.pub", pubLine(t, edKey(11)))
		_, _, err := load(t, f, Passphrases{PerKey: map[string]string{"/k": "/pk"}}, nil, "/k")
		if err == nil || !strings.Contains(err.Error(), "/k: /k.pub does not match the private key") {
			t.Fatalf("err = %v, want the stale .pub refusal", err)
		}
	})
	t.Run("matching sibling .pub labels the prompt", func(t *testing.T) {
		f := newFS().key("/k", enc).key("/k.pub", pubLine(t, k))
		p := &fakePrompter{avail: true, answers: []string{"right"}}
		if _, _, err := load(t, f, Passphrases{}, p, "/k"); err != nil {
			t.Fatalf("Load: %v", err)
		}
		if !strings.Contains(p.prompts[0], "("+fpOf(t, k)+")") {
			t.Errorf("prompt = %q, want the .pub fingerprint as a label", p.prompts[0])
		}
	})
}

func TestLoadMismatchedOpenSSHPublicSection(t *testing.T) {
	bad := editOpenSSH(t, opensshPEM(t, edKey(12), nil), func(h *opensshHeader) {
		h.PubKey = pubWire(t, edKey(13))
	})
	_, _, err := load(t, newFS().key("/k", bad), Passphrases{}, nil, "/k")
	if err == nil || !strings.Contains(err.Error(), "/k: embedded public key does not match the private key") {
		t.Fatalf("err = %v, want the mismatch refusal", err)
	}
}

func TestLoadDedupByDecryptedFingerprint(t *testing.T) {
	// One key, two containers (plain and encrypted): the second path is
	// the same key once decrypted.
	k := ecKey(t)
	f := newFS().key("/a", legacyPEM(t, k, nil)).key("/b", legacyPEM(t, k, []byte("pw"))).key("/pw", []byte("pw"))
	ids, logs, err := load(t, f, Passphrases{PerKey: map[string]string{"/b": "/pw"}}, nil, "/a", "/b")
	if err != nil || len(ids) != 1 || ids[0].Path != "/a" {
		t.Fatalf("Load = (%+v, %v), want only the first path", ids, err)
	}
	if !strings.Contains(logs, "identity /b is the same key as /a") {
		t.Errorf("logs = %q, want the dropped-path info line", logs)
	}
}

func TestLoadCertificateNote(t *testing.T) {
	f := newFS().key("/k", opensshPEM(t, edKey(15), nil)).key("/k-cert.pub", []byte("ssh-ed25519-cert-v01@openssh.com AAAA"))
	_, logs, err := load(t, f, Passphrases{}, nil, "/k")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !strings.Contains(logs, "certificate /k-cert.pub not used; authenticating with the plain key") {
		t.Errorf("logs = %q, want the certificate note", logs)
	}
}

func TestLoadNeverLeaksPassphrases(t *testing.T) {
	const marker = "Zq8vL2pX9mR4kT7w" // 16 high-entropy bytes
	for name, data := range map[string][]byte{"openssh": sharedEncrypted(t), "legacy pem": legacyPEM(t, ecKey(t), []byte("other"))} {
		t.Run(name, func(t *testing.T) {
			f := newFS().key("/k", data).key("/pk", []byte(marker+"\n"))
			_, logs, err := load(t, f, Passphrases{PerKey: map[string]string{"/k": "/pk"}}, nil, "/k")
			if err == nil {
				t.Fatal("wrong passphrase accepted")
			}
			if strings.Contains(err.Error(), marker) || strings.Contains(logs, marker) {
				t.Fatalf("passphrase leaked: err %q, logs %q", err, logs)
			}
		})
	}
}

// TestLoadWipesPassphraseCache captures the passphrase cache Load built and
// checks every cached byte is zero once Load has returned — on success and
// on a refusal alike.
func TestLoadWipesPassphraseCache(t *testing.T) {
	enc := sharedEncrypted(t)
	tests := []struct {
		name    string
		fsys    *fakeFS
		paths   []string
		wantErr bool
	}{
		{"success", newFS().key("/k", enc).key("/pw", []byte(sharedPass+"\n")), []string{"/k"}, false},
		{"refused (another key missing)", newFS().key("/k", enc).key("/pw", []byte(sharedPass+"\n")), []string{"/k", "/missing"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var captured map[string][]byte
			orig := wipeCache
			wipeCache = func(c map[string][]byte) { captured = c; orig(c) }
			t.Cleanup(func() { wipeCache = orig })

			_, _, err := load(t, tt.fsys, Passphrases{Default: "/pw"}, nil, tt.paths...)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Load err = %v, wantErr %v", err, tt.wantErr)
			}
			b, ok := captured["/pw"]
			if !ok || len(b) != len(sharedPass) {
				t.Fatalf("cache = %v, want /pw cached (%d bytes) and handed to the wipe", captured, len(sharedPass))
			}
			for i, c := range b[:cap(b)] {
				if c != 0 {
					t.Fatalf("cached /pw byte %d = %#x after Load returned, want 0", i, c)
				}
			}
		})
	}
}
