package keyfile

import (
	"bytes"
	"io"
	"io/fs"
)

// fakeFile is one file in fakeFS.
type fakeFile struct {
	data    []byte
	info    FileInfo
	openErr error
	pipe    bool // readable once: later opens see EOF at once, like a drained FIFO
}

// fakeFS is an in-memory FS that counts opens per path.
type fakeFS struct {
	uid   int
	files map[string]*fakeFile
	opens map[string]int
}

func newFS() *fakeFS {
	return &fakeFS{uid: 1000, files: map[string]*fakeFile{}, opens: map[string]int{}}
}

// regular adds a regular file owned by the current uid with mode perm.
func (f *fakeFS) regular(path string, data []byte, perm fs.FileMode) *fakeFS {
	f.files[path] = &fakeFile{data: data, info: FileInfo{Mode: perm, UID: f.uid}}
	return f
}

// key adds a 0600 key file owned by the current uid.
func (f *fakeFS) key(path string, data []byte) *fakeFS { return f.regular(path, data, 0o600) }

// fifo adds a one-shot named pipe (mode 0440, owned by the caller — what
// macOS reports for <(...)).
func (f *fakeFS) fifo(path string, data []byte) *fakeFS {
	f.files[path] = &fakeFile{data: data, info: FileInfo{Mode: fs.ModeNamedPipe | 0o440, UID: f.uid}, pipe: true}
	return f
}

func (f *fakeFS) Open(path string) (io.ReadCloser, FileInfo, error) {
	ff, ok := f.files[path]
	if !ok {
		return nil, FileInfo{}, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	if ff.openErr != nil {
		return nil, FileInfo{}, &fs.PathError{Op: "open", Path: path, Err: ff.openErr}
	}
	f.opens[path]++
	if ff.pipe && f.opens[path] > 1 {
		return io.NopCloser(bytes.NewReader(nil)), ff.info, nil
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(ff.data))), ff.info, nil
}

func (f *fakeFS) Stat(path string) (FileInfo, error) {
	ff, ok := f.files[path]
	if !ok {
		return FileInfo{}, &fs.PathError{Op: "stat", Path: path, Err: fs.ErrNotExist}
	}
	return ff.info, nil
}

func (f *fakeFS) UID() int { return f.uid }
