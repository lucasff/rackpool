// Package serve exposes the pool over WebDAV, for media players and OS file
// managers. Reads stream with seeking; writes stream into the pool as the
// client uploads. Renames aren't supported (the pool has no server-side
// move), and only files you added can be overwritten or deleted.
package serve

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"sync"
	"time"

	"golang.org/x/net/webdav"

	"mediapool/internal/client"
	"mediapool/internal/vfs"
)

// WebDAV returns a handler serving the pool. readOnly refuses all writes.
func WebDAV(v *vfs.FS, readOnly bool, logf func(string, ...any)) http.Handler {
	h := &webdav.Handler{
		FileSystem: &davFS{v: v, readOnly: readOnly, dirs: map[string]time.Time{}},
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil && logf != nil {
				logf("webdav %s %s: %v", r.Method, r.URL.Path, err)
			}
		},
	}
	return h
}

type davFS struct {
	v        *vfs.FS
	readOnly bool

	mu   sync.Mutex
	dirs map[string]time.Time // created with MKCOL but still empty
}

type info struct{ e vfs.Entry }

func (i info) Name() string { return i.e.Name }
func (i info) Size() int64  { return i.e.Size }
func (i info) Mode() fs.FileMode {
	if i.e.IsDir {
		return fs.ModeDir | 0o755
	}
	return 0o644
}
func (i info) ModTime() time.Time { return i.e.ModTime }
func (i info) IsDir() bool        { return i.e.IsDir }
func (i info) Sys() any           { return nil }

func (d *davFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	e, err := d.v.Stat(ctx, name)
	if err != nil {
		d.mu.Lock()
		t, ok := d.dirs[vfs.Clean(name)]
		d.mu.Unlock()
		if ok {
			return info{vfs.Entry{Path: vfs.Clean(name), Name: path.Base(name), IsDir: true, ModTime: t}}, nil
		}
		return nil, err
	}
	return info{e}, nil
}

func (d *davFS) Mkdir(_ context.Context, name string, _ os.FileMode) error {
	if d.readOnly {
		return os.ErrPermission
	}
	d.mu.Lock()
	d.dirs[vfs.Clean(name)] = time.Now()
	d.mu.Unlock()
	return nil
}

func (d *davFS) RemoveAll(ctx context.Context, name string) error {
	if d.readOnly {
		return os.ErrPermission
	}
	d.mu.Lock()
	delete(d.dirs, vfs.Clean(name))
	d.mu.Unlock()
	_, notOwned, err := d.v.RemoveAll(ctx, name, false)
	if err == nil && len(notOwned) > 0 {
		return os.ErrPermission
	}
	return err
}

func (d *davFS) Rename(context.Context, string, string) error {
	return os.ErrPermission // no server-side move in the pool
}

func (d *davFS) OpenFile(ctx context.Context, name string, flag int, _ os.FileMode) (webdav.File, error) {
	if flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC) != 0 {
		if d.readOnly {
			return nil, os.ErrPermission
		}
		return d.create(name)
	}
	e, err := d.Stat(ctx, name)
	if err != nil {
		return nil, err
	}
	if e.IsDir() {
		return &dir{d: d, ctx: ctx, e: e.(info).e}, nil
	}
	f, _, err := d.v.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	return &file{File: f, e: e.(info).e}, nil
}

type file struct {
	*client.File
	e vfs.Entry
}

func (f *file) Readdir(int) ([]fs.FileInfo, error) { return nil, errors.New("not a directory") }
func (f *file) Stat() (fs.FileInfo, error)         { return info{f.e}, nil }
func (f *file) Write([]byte) (int, error)          { return 0, os.ErrPermission }

type dir struct {
	d    *davFS
	ctx  context.Context
	e    vfs.Entry
	done bool
}

func (x *dir) Close() error                   { return nil }
func (x *dir) Read([]byte) (int, error)       { return 0, errors.New("is a directory") }
func (x *dir) Seek(int64, int) (int64, error) { return 0, nil }
func (x *dir) Write([]byte) (int, error)      { return 0, os.ErrPermission }
func (x *dir) Stat() (fs.FileInfo, error)     { return info{x.e}, nil }
func (x *dir) Readdir(count int) ([]fs.FileInfo, error) {
	if x.done {
		if count > 0 {
			return nil, io.EOF
		}
		return nil, nil
	}
	x.done = true
	list, err := x.d.v.List(x.ctx, x.e.Path, false)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	out := make([]fs.FileInfo, 0, len(list))
	for _, e := range list {
		out = append(out, info{e})
	}
	return out, nil
}

// upload streams a PUT body into the pool through a pipe; Close waits for
// the pool to finish storing it and reports any failure to the client.
type upload struct {
	pw   *io.PipeWriter
	name string
	done chan error
}

func (d *davFS) create(name string) (webdav.File, error) {
	pr, pw := io.Pipe()
	u := &upload{pw: pw, name: name, done: make(chan error, 1)}
	go func() {
		_, err := d.v.Put(context.Background(), name, pr, time.Now())
		pr.CloseWithError(err)
		u.done <- err
	}()
	return u, nil
}

func (u *upload) Write(p []byte) (int, error) { return u.pw.Write(p) }
func (u *upload) Close() error {
	u.pw.Close()
	return <-u.done
}
func (u *upload) Read([]byte) (int, error)           { return 0, os.ErrPermission }
func (u *upload) Seek(int64, int) (int64, error)     { return 0, errors.New("uploads can't seek") }
func (u *upload) Readdir(int) ([]fs.FileInfo, error) { return nil, errors.New("not a directory") }
func (u *upload) Stat() (fs.FileInfo, error) {
	return info{vfs.Entry{Path: vfs.Clean(u.name), Name: path.Base(u.name), ModTime: time.Now()}}, nil
}
