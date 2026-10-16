package keyfile

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestPermissionRule(t *testing.T) {
	tests := []struct {
		name    string
		info    FileInfo
		wantErr string
	}{
		{"own regular 0644 refused", FileInfo{Mode: 0o644, UID: 1000}, "permissions 0644 for /k are too open (chmod 600 /k)"},
		{"own regular 0640 refused", FileInfo{Mode: 0o640, UID: 1000}, "permissions 0640 for /k are too open"},
		{"own regular 0600 ok", FileInfo{Mode: 0o600, UID: 1000}, ""},
		{"own regular 0400 ok", FileInfo{Mode: 0o400, UID: 1000}, ""},
		{"other-uid regular 0644 ok (root-owned secret mount)", FileInfo{Mode: 0o644, UID: 0}, ""},
		{"own FIFO 0440 ok (macOS <(...))", FileInfo{Mode: fs.ModeNamedPipe | 0o440, UID: 1000}, ""},
		{"own char device 0620 ok (/dev/stdin on a tty)", FileInfo{Mode: fs.ModeDevice | fs.ModeCharDevice | 0o620, UID: 1000}, ""},
		{"own socket 0777 ok", FileInfo{Mode: fs.ModeSocket | 0o777, UID: 1000}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := permOK("/k", tt.info, 1000)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("permOK = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("permOK = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestReadCheckedErrors(t *testing.T) {
	t.Run("EACCES names uid, owner and mode", func(t *testing.T) {
		f := newFS()
		f.files["/k"] = &fakeFile{openErr: fs.ErrPermission, info: FileInfo{Mode: 0o600, UID: 0}}
		_, err := readChecked(f, "/k", maxKeyFile, "key file")
		want := "cannot read key file /k as uid 1000 (owner 0, mode 0600) — see README 'Container usage'"
		if err == nil || !strings.Contains(err.Error(), want) || !errors.Is(err, fs.ErrPermission) {
			t.Fatalf("err = %v, want %q wrapping fs.ErrPermission", err, want)
		}
	})
	t.Run("missing file", func(t *testing.T) {
		_, err := readChecked(newFS(), "/nope", maxKeyFile, "key file")
		if err == nil || err.Error() != "key file /nope: file does not exist" {
			t.Fatalf("err = %v, want the bare not-exist message", err)
		}
	})
	t.Run("key file over 64 KiB", func(t *testing.T) {
		f := newFS().key("/big", bytes.Repeat([]byte("a"), maxKeyFile+1))
		_, err := readChecked(f, "/big", maxKeyFile, "key file")
		if err == nil || !strings.Contains(err.Error(), "larger than 65536 bytes") {
			t.Fatalf("err = %v, want the size cap", err)
		}
	})
	t.Run("exactly 64 KiB is fine", func(t *testing.T) {
		f := newFS().key("/edge", bytes.Repeat([]byte("a"), maxKeyFile))
		if b, err := readChecked(f, "/edge", maxKeyFile, "key file"); err != nil || len(b) != maxKeyFile {
			t.Fatalf("readChecked = (%d bytes, %v), want the whole file", len(b), err)
		}
	})
	t.Run("passphrase file over 4 KiB", func(t *testing.T) {
		f := newFS().key("/pw", bytes.Repeat([]byte("p"), maxPassphraseFile+1))
		_, err := readChecked(f, "/pw", maxPassphraseFile, "passphrase file")
		if err == nil || !strings.Contains(err.Error(), "passphrase file /pw is larger than 4096 bytes") {
			t.Fatalf("err = %v, want the passphrase size cap", err)
		}
	})
}

func TestReadPassphrases(t *testing.T) {
	t.Run("strips exactly one trailing newline", func(t *testing.T) {
		f := newFS().key("/a", []byte("pa\n\n")).key("/b", []byte("pb\r\n")).key("/c", []byte("pc"))
		cache, err := readPassphrases(f, Passphrases{Default: "/a", PerKey: map[string]string{"/k1": "/b", "/k2": "/c"}})
		if err != nil {
			t.Fatalf("readPassphrases: %v", err)
		}
		for path, want := range map[string]string{"/a": "pa\n", "/b": "pb", "/c": "pc"} {
			if got := string(cache[path]); got != want {
				t.Errorf("%s = %q, want %q", path, got, want)
			}
		}
	})
	t.Run("one FILE in two mappings and as the default is read once", func(t *testing.T) {
		f := newFS().fifo("/dev/fd/63", []byte("shared\n"))
		cache, err := readPassphrases(f, Passphrases{Default: "/dev/fd/63", PerKey: map[string]string{"/k1": "/dev/fd/63", "/k2": "/dev/fd/63"}})
		if err != nil || string(cache["/dev/fd/63"]) != "shared" {
			t.Fatalf("readPassphrases = (%q, %v), want the pipe's content", cache["/dev/fd/63"], err)
		}
		if n := f.opens["/dev/fd/63"]; n != 1 {
			t.Errorf("opens = %d, want exactly 1 (a pipe can be read once)", n)
		}
	})
	t.Run("empty after stripping is refused, naming the file", func(t *testing.T) {
		f := newFS().key("/empty", []byte("\n"))
		_, err := readPassphrases(f, Passphrases{Default: "/empty"})
		if err == nil || err.Error() != "passphrase file /empty is empty" {
			t.Fatalf("err = %v, want the empty-file refusal", err)
		}
	})
	t.Run("errors for every file are joined", func(t *testing.T) {
		f := newFS().regular("/open", []byte("x"), 0o644)
		_, err := readPassphrases(f, Passphrases{Default: "/missing", PerKey: map[string]string{"/k": "/open"}})
		if err == nil || !strings.Contains(err.Error(), "/missing") || !strings.Contains(err.Error(), "permissions 0644 for /open") {
			t.Fatalf("err = %v, want both failures", err)
		}
	})
}

func TestReadPublicAndExists(t *testing.T) {
	line := []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDuMHZjvr0ZLvHjYpgGLg6Pz6LKS3Y8VTVFJ81a3aG3F label\n")
	f := newFS().key("/ok.pub", line).key("/junk.pub", []byte("not a key"))
	if readPublic(f, "/ok.pub") == nil {
		t.Error("readPublic(valid) = nil")
	}
	if readPublic(f, "/junk.pub") != nil || readPublic(f, "/absent.pub") != nil {
		t.Error("an unparseable or absent .pub must be ignored (nil)")
	}
	if !exists(f, "/ok.pub") || exists(f, "/absent.pub") {
		t.Error("exists disagrees with the FS")
	}
}
