package keyfile

import (
	"bytes"
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fuzzSeeds are key files of every container the classifier knows.
func fuzzSeeds(f *testing.F) [][]byte {
	f.Helper()
	ed := edKey(1)
	seeds := [][]byte{
		opensshPEM(f, ed, nil),
		sharedEncrypted(f), // the marker is the wrong passphrase for it
		legacyPEM(f, ecKey(f), nil),
		legacyPEM(f, ecKey(f), []byte(leakMarker)),
		[]byte("PuTTY-User-Key-File-3: ssh-ed25519\n"),
		pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte{0x30, 0}}),
	}
	entries, err := os.ReadDir("testdata")
	if err != nil {
		f.Fatalf("testdata: %v", err)
	}
	for _, e := range entries {
		if e.Type().IsRegular() {
			b, err := os.ReadFile(filepath.Join("testdata", e.Name()))
			if err != nil {
				f.Fatal(err)
			}
			seeds = append(seeds, b)
		}
	}
	return seeds
}

// FuzzClassify: the container/header classifier (no KDF — fast) never
// panics, and an accepted OpenSSH key always carries its public key and a
// bcrypt round count within x/crypto's cap.
func FuzzClassify(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cls, err := classify("/k", data)
		if err != nil {
			if strings.ContainsRune(err.Error(), '\x1b') {
				t.Fatalf("error carries a raw escape byte: %q", err)
			}
			return
		}
		if cls.format == formatOpenSSH && cls.pub == nil {
			t.Fatal("accepted OpenSSH key without a public key")
		}
		if cls.rounds > maxBcryptRounds {
			t.Fatalf("accepted %d rounds", cls.rounds)
		}
	})
}

// leakMarker is the injected high-entropy passphrase whose bytes must never
// appear in an error or a log line.
const leakMarker = "Zq8vL2pX9mR4kT7w"

// fuzzMaxRounds clamps the KDF work per input: x/crypto's own marshaler
// uses 16, and more only slows the fuzzer down.
const fuzzMaxRounds = 16

// FuzzDecrypt runs the whole Load over arbitrary key bytes with the marker
// as both the per-key and the default passphrase: whatever the bytes, the
// marker never reaches an error or the log.
func FuzzDecrypt(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if bytes.Contains(data, []byte(leakMarker)) {
			t.Skip("the input itself carries the marker")
		}
		if cls, err := classify("/k", data); err == nil && cls.rounds > fuzzMaxRounds {
			t.Skip("bcrypt rounds clamped")
		}
		fsys := newFS().key("/k", data).key("/pw", []byte(leakMarker+"\n"))
		log, buf := logBuffer()
		for _, pp := range []Passphrases{{PerKey: map[string]string{"/k": "/pw"}}, {Default: "/pw"}} {
			_, err := Load(context.Background(), []Spec{{"/k"}}, pp, nil, fsys, log)
			if err != nil && strings.Contains(err.Error(), leakMarker) {
				t.Fatalf("passphrase leaked into the error: %q", err)
			}
		}
		if strings.Contains(buf.String(), leakMarker) {
			t.Fatalf("passphrase leaked into the log: %q", buf.String())
		}
	})
}
