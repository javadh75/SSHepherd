package keyfile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"

	"golang.org/x/crypto/ssh"
)

const (
	// maxKeyFile caps a key file read (64 KiB): an RSA-16384 key is ~12 KiB,
	// so anything larger is a mistake (or /dev/zero).
	maxKeyFile = 64 << 10
	// maxPassphraseFile caps a passphrase file read (4 KiB).
	maxPassphraseFile = 4 << 10
)

// FileInfo is what the permission rule needs from fstat of an open
// descriptor: the full mode (type bits included) and the owner's uid.
type FileInfo struct {
	Mode fs.FileMode
	UID  int
}

// FS is the file access Load needs. Open returns a reader over one opened
// descriptor plus the FileInfo of THAT descriptor (fstat), so a file is
// opened once, checked on the descriptor and read from the same one (no
// stat-then-open race). Stat is used only to explain an unreadable file.
// UID is the current process's uid. OSFS is the real implementation.
type FS interface {
	Open(path string) (io.ReadCloser, FileInfo, error)
	Stat(path string) (FileInfo, error)
	UID() int
}

// readChecked opens path once, applies the permission rule to that
// descriptor, and reads at most limit bytes from it.
func readChecked(fsys FS, path string, limit int, what string) ([]byte, error) {
	r, info, err := fsys.Open(path)
	if err != nil {
		return nil, openError(fsys, path, what, err)
	}
	defer func() { _ = r.Close() }() // errcheck: read-only file, close error uninteresting
	if err := permOK(path, info, fsys.UID()); err != nil {
		return nil, err
	}
	b, err := readBounded(r, limit)
	if errors.Is(err, errTooLarge) {
		return nil, fmt.Errorf("%s %s is larger than %d bytes — refusing to read it", what, path, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", what, path, err) // "passphrase file F: read: …"
	}
	return b, nil
}

// errTooLarge is readBounded's verdict for input over its limit.
var errTooLarge = errors.New("input over the size limit")

// readBounded reads r to EOF into ONE buffer of limit+1 bytes, allocated
// up front: unlike io.ReadAll it never regrows, so no partial copy of a
// secret is left behind for the wipe to miss. More than limit bytes is
// errTooLarge; on any error the buffer is cleared.
func readBounded(r io.Reader, limit int) ([]byte, error) {
	buf := make([]byte, limit+1)
	n := 0
	for n < len(buf) {
		m, err := r.Read(buf[n:])
		n += m
		if errors.Is(err, io.EOF) {
			return buf[:n], nil
		}
		if err != nil {
			clear(buf)
			return nil, fmt.Errorf("read: %w", err)
		}
	}
	clear(buf)
	return nil, errTooLarge
}

// openError explains a failed open; EACCES names the uid we run as and the
// file's owner and mode, the usual container mismatch.
func openError(fsys FS, path, what string, err error) error {
	if errors.Is(err, fs.ErrPermission) {
		msg := fmt.Sprintf("cannot read %s %s as uid %d", what, path, fsys.UID())
		if info, serr := fsys.Stat(path); serr == nil {
			msg += fmt.Sprintf(" (owner %d, mode %04o)", info.UID, info.Mode.Perm())
		}
		return fmt.Errorf("%s — see README 'Container usage': %w", msg, fs.ErrPermission)
	}
	var pe *fs.PathError
	if errors.As(err, &pe) {
		err = pe.Err // the path is already in the message
	}
	return fmt.Errorf("%s %s: %w", what, path, err)
}

// permOK is OpenSSH's sshkey_perm_ok, for regular files only: a regular
// file the current uid owns must not be group/other accessible. A regular
// file owned by another uid (a root-owned secret mount) is accepted, as ssh
// accepts it. FIFOs, sockets and character devices (/dev/fd/N, <(...),
// /dev/stdin) are exempt: their mode bits do not describe a file at rest.
func permOK(path string, info FileInfo, uid int) error {
	if !info.Mode.IsRegular() || info.UID != uid {
		return nil
	}
	if perm := info.Mode.Perm(); perm&0o077 != 0 {
		return fmt.Errorf("permissions %04o for %s are too open (chmod 600 %s)", perm, path, path)
	}
	return nil
}

// readPassphrases reads every distinct passphrase file exactly once (a
// pipe can only be read once), strips exactly one trailing \n or \r\n, and
// refuses a file that is then empty. Read errors are joined; the files
// that did read are cached anyway, so the caller can wipe them.
func readPassphrases(fsys FS, pp Passphrases) (map[string][]byte, error) {
	var paths []string
	if pp.Default != "" {
		paths = append(paths, pp.Default)
	}
	perKey := make([]string, 0, len(pp.PerKey))
	for _, f := range pp.PerKey {
		perKey = append(perKey, f)
	}
	sort.Strings(perKey) // deterministic error order
	paths = append(paths, perKey...)

	cache := make(map[string][]byte, len(paths))
	seen := make(map[string]bool, len(paths))
	var errs []error
	for _, p := range paths {
		if seen[p] {
			continue // one FILE in two mappings (or also the default): read once
		}
		seen[p] = true
		b, err := readChecked(fsys, p, maxPassphraseFile, "passphrase file")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		b = stripNewline(b)
		if len(b) == 0 {
			errs = append(errs, fmt.Errorf("passphrase file %s is empty", p))
			continue
		}
		cache[p] = b
	}
	return cache, errors.Join(errs...)
}

// stripNewline removes exactly one trailing "\n" or "\r\n".
func stripNewline(b []byte) []byte {
	if bytes.HasSuffix(b, []byte("\r\n")) {
		return b[:len(b)-2]
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// readPublic parses a sibling public key file; nil when it is absent or
// unparseable (it is only a label, never the fingerprint).
func readPublic(fsys FS, path string) ssh.PublicKey {
	r, _, err := fsys.Open(path)
	if err != nil {
		return nil
	}
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(io.LimitReader(r, maxKeyFile))
	if err != nil {
		return nil
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(b)
	if err != nil {
		return nil
	}
	return pub
}

// exists reports whether path can be stat'ed.
func exists(fsys FS, path string) bool {
	_, err := fsys.Stat(path)
	return err == nil
}
