package keyfile

import (
	"encoding/pem"
	"strings"
	"testing"
)

func TestClassifyAccepts(t *testing.T) {
	ed := edKey(1)
	tests := []struct {
		name      string
		data      []byte
		format    format
		encrypted bool
	}{
		{"openssh unencrypted", opensshPEM(t, ed, nil), formatOpenSSH, false},
		{"openssh aes256-ctr bcrypt", sharedEncrypted(t), formatOpenSSH, true},
		{"openssh aes256-cbc", editOpenSSH(t, sharedEncrypted(t), func(h *opensshHeader) { h.CipherName = "aes256-cbc" }), formatOpenSSH, true},
		{"openssh bcrypt at the 2048-round cap", withRounds(t, sharedEncrypted(t), 2048), formatOpenSSH, true},
		{"legacy EC PEM", legacyPEM(t, ecKey(t), nil), formatPEM, false},
		{"legacy EC PEM encrypted", legacyPEM(t, ecKey(t), []byte("pw")), formatPEM, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cls, err := classify("/k", tt.data)
			if err != nil {
				t.Fatalf("classify: %v", err)
			}
			if cls.format != tt.format || cls.encrypted != tt.encrypted {
				t.Errorf("classification = %+v, want format %d encrypted %v", cls, tt.format, tt.encrypted)
			}
			if tt.format == formatOpenSSH && cls.pub == nil {
				t.Error("OpenSSH classification lacks the embedded public key")
			}
		})
	}
}

func TestClassifyRefusesBeforeAnyPrompt(t *testing.T) {
	ed := edKey(1)
	enc := sharedEncrypted(t)
	plain := opensshPEM(t, ed, nil)
	tests := []struct {
		name string
		data []byte
		want []string
	}{
		{"PuTTY", []byte("PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n"), []string{"is a PuTTY key", "puttygen /k -O private-openssh"}},
		{"not PEM at all", []byte("hello"), []string{"no PEM block", "ssh-keygen -p -f /k"}},
		{"encrypted PKCS#8", pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{0x30, 0}}), []string{"encrypted PKCS#8", "ssh-keygen -p -f /k"}},
		{"legacy encrypted PKCS#8 header", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00000000000000000000000000000000"}, Bytes: []byte{0}}), []string{"encrypted PKCS#8"}},
		{"DSA PEM", pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte{0x30, 0}}), []string{"ssh-dss is disabled by default in OpenSSH"}},
		{"unknown block", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE\x1b[31m", Bytes: []byte{0}}), []string{`unsupported key block "CERTIFICATE\x1b[31m"`}},
		{"gcm cipher", editOpenSSH(t, enc, func(h *opensshHeader) { h.CipherName = "aes256-gcm@openssh.com" }), []string{`cipher "aes256-gcm@openssh.com" is not supported`, "ssh-keygen -p -f /k"}},
		{"chacha cipher", editOpenSSH(t, enc, func(h *opensshHeader) { h.CipherName = "chacha20-poly1305@openssh.com" }), []string{`cipher "chacha20-poly1305@openssh.com"`}},
		{"unknown KDF", editOpenSSH(t, enc, func(h *opensshHeader) { h.KdfName = "scrypt" }), []string{`KDF "scrypt" is not supported`}},
		{"cipher without KDF", editOpenSSH(t, enc, func(h *opensshHeader) { h.KdfName = "none" }), []string{"cipher without a KDF"}},
		{"KDF without cipher", editOpenSSH(t, enc, func(h *opensshHeader) { h.CipherName = "none" }), []string{"KDF without a cipher"}},
		{"malformed KDF options", editOpenSSH(t, enc, func(h *opensshHeader) { h.KdfOpts = "x" }), []string{"malformed bcrypt KDF options"}},
		{"rounds over 2048", withRounds(t, enc, 2049), []string{"bcrypt KDF rounds 2049 exceed the supported maximum of 2048", "ssh-keygen -p -a 100 -f /k"}},
		{"two keys", editOpenSSH(t, plain, func(h *opensshHeader) { h.NumKeys = 2 }), []string{"holds 2 keys"}},
		{"ssh-dss public section", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = dssBlob() }), []string{"ssh-dss is disabled by default"}},
		{"sk-ed25519 hardware key", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = pubBlob("sk-ssh-ed25519@openssh.com") }), []string{"hardware keys must be used via ssh-agent"}},
		{"sk-ecdsa hardware key", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = pubBlob("sk-ecdsa-sha2-nistp256@openssh.com") }), []string{"hardware keys must be used via ssh-agent"}},
		{"garbage public section", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = []byte{1, 2} }), []string{"malformed embedded public key"}},
		{"unknown public key type", editOpenSSH(t, plain, func(h *opensshHeader) { h.PubKey = pubBlob("ssh-foo") }), []string{`unsupported embedded public key "ssh-foo"`}},
		{"bad magic", pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("openssh-key-v0\x00")}), []string{"malformed OpenSSH private key"}},
		{"legacy PEM unknown cipher", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "BF-CBC,0000000000000000"}, Bytes: []byte{0}}), []string{`PEM encryption "BF-CBC,0000000000000000" is not supported`}},
		{"legacy PEM no DEK-Info", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{0}}), []string{"PEM encryption"}},
		{"legacy PEM bad IV", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00"}, Bytes: []byte{0}}), []string{"bad IV"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := classify("/k", tt.data)
			if err == nil {
				t.Fatal("classify accepted it")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("err = %q, want it to contain %q", err, w)
				}
			}
			if strings.ContainsRune(err.Error(), '\x1b') {
				t.Errorf("err %q carries a raw escape byte", err)
			}
		})
	}
}
