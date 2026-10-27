// Package mediapool is an rclone backend for a mediapool pool: an
// encrypted, erasure-coded media pool shared by its members.
//
// The pool is a flat set of absolute, slash-separated file paths;
// directories are implicit. Files can only be overwritten or removed by the
// member who added them, modification times are fixed at upload, and the
// pool exposes no hashes and no server-side copy or move.
package mediapool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/backend/overview"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/config/obscure"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/encoder"
	"github.com/rclone/rclone/lib/readers"

	"mediapool/pkg/mediapool"
)

func init() {
	// fs.Register looks the backend up in rclone's embedded docs data,
	// which only knows in-tree backends, and logs an "internal error" for
	// anything else. Keep that out of every command's output and describe
	// the backend ourselves.
	ci := fs.GetConfig(context.Background())
	level := ci.LogLevel
	ci.LogLevel = fs.LogLevelCritical
	info := &fs.RegInfo{
		Name:        "mediapool",
		Description: "Mediapool shared media pool",
		NewFs:       NewFs,
		Options: []fs.Option{{
			Name:     "coord_url",
			Help:     "Coordinator base URL, e.g. http://coord.example:7000.",
			Required: true,
		}, {
			Name:     "pool_file",
			Help:     "Path to the pool membership file (pool.json).",
			Required: true,
		}, {
			Name:      "member",
			Help:      "Member name, as listed in the pool file.",
			Required:  true,
			Sensitive: true,
		}, {
			Name:     "key_file",
			Help:     "Path to the member's private key file.",
			Required: true,
		}, {
			Name:       "secret",
			Help:       "Pool secret.\n\nLeave blank to use the MEDIAPOOL_SECRET environment variable.",
			IsPassword: true,
			Sensitive:  true,
		}, {
			Name:     "catalog_path",
			Help:     "Local file to keep a replica of the pool catalog in between runs.\n\nWith it, startup syncs only new entries. Leave blank to keep it in memory.",
			Advanced: true,
		}, {
			Name:     "read_ahead",
			Help:     "How far past the segment being read to fetch in the background.",
			Default:  fs.SizeSuffix(32 << 20),
			Advanced: true,
		}, {
			Name:     "cache_size",
			Help:     "Memory for segments shared by all open files.\n\nSeveral readers of one file (playback, a probe at the end, subtitle extraction) share it instead of cancelling each other's fetches.",
			Default:  fs.SizeSuffix(256 << 20),
			Advanced: true,
		}, {
			Name:     config.ConfigEncoding,
			Help:     config.ConfigEncodingHelp,
			Advanced: true,
			// The catalog stores paths in JSON, which can't carry invalid
			// UTF-8, and cleans paths, which would eat "." and "..".
			Default: encoder.Base | encoder.EncodeInvalidUtf8,
		}},
	}
	fs.Register(info)
	ci.LogLevel = level
	info.Overview = &overview.BackendConfig{Backend: "mediapool", Name: "Mediapool", Precision: 1}
}

// Options defines the configuration for this backend.
type Options struct {
	CoordURL    string               `config:"coord_url"`
	PoolFile    string               `config:"pool_file"`
	Member      string               `config:"member"`
	KeyFile     string               `config:"key_file"`
	Secret      string               `config:"secret"`
	CatalogPath string               `config:"catalog_path"`
	ReadAhead   fs.SizeSuffix        `config:"read_ahead"`
	CacheSize   fs.SizeSuffix        `config:"cache_size"`
	Enc         encoder.MultiEncoder `config:"encoding"`
}

// Fs is a view of a pool rooted at a directory.
type Fs struct {
	name     string
	root     string // directory this Fs is rooted at, "/" or "/a/b", unencoded
	opt      Options
	client   *mediapool.Client
	features *fs.Features

	mu sync.Mutex
	// Directories (unencoded, absolute) made by Mkdir or emptied by Remove
	// in this process, so they can be listed and removed though the pool
	// only knows files.
	dirs map[string]bool
}

// Object is a file in the pool.
type Object struct {
	fs      *Fs
	remote  string
	size    int64
	modTime time.Time
	author  string
}

// Clients are shared between Fs instances with the same options, so two
// roots on one remote never write the same catalog replica file.
var (
	clientsMu sync.Mutex
	clients   = map[Options]*mediapool.Client{}
)

func openClient(opt Options) (*mediapool.Client, error) {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	if c, ok := clients[opt]; ok {
		return c, nil
	}
	secret := opt.Secret
	if secret != "" {
		var err error
		if secret, err = obscure.Reveal(secret); err != nil {
			return nil, fmt.Errorf("mediapool: secret: %w", err)
		}
	}
	c, err := mediapool.Open(mediapool.Config{
		CoordURL: opt.CoordURL, PoolFile: opt.PoolFile, Member: opt.Member,
		KeyFile: opt.KeyFile, Secret: secret, CatalogPath: opt.CatalogPath,
		ReadAhead: int64(opt.ReadAhead), CacheSize: int64(opt.CacheSize),
	})
	if err != nil {
		return nil, err
	}
	clients[opt] = c
	return c, nil
}

// NewFs constructs an Fs from the path.
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)
	if err := configstruct.Set(m, opt); err != nil {
		return nil, err
	}
	c, err := openClient(*opt)
	if err != nil {
		return nil, err
	}
	f := &Fs{name: name, root: path.Clean("/" + root), opt: *opt, client: c, dirs: map[string]bool{}}
	f.features = (&fs.Features{
		CanHaveEmptyDirectories: false,
		ReadMimeType:            false,
	}).Fill(ctx, f)

	if f.root != "/" {
		_, err := c.Stat(ctx, opt.Enc.FromStandardPath(f.root))
		if err == nil {
			// The root is a file: point at its directory, as rclone expects.
			f.root = path.Dir(f.root)
			return f, fs.ErrorIsFile
		}
		if !errors.Is(err, mediapool.ErrNotExist) {
			return nil, err
		}
	}
	return f, nil
}

// std is the absolute, unencoded path of remote.
func (f *Fs) std(remote string) string { return path.Join(f.root, remote) }

// abs is the pool path of remote.
func (f *Fs) abs(remote string) string { return f.opt.Enc.FromStandardPath(f.std(remote)) }

// Name of the remote (as passed into NewFs).
func (f *Fs) Name() string { return f.name }

// Root of the remote (as passed into NewFs).
func (f *Fs) Root() string { return strings.TrimPrefix(f.root, "/") }

// String converts this Fs to a string.
func (f *Fs) String() string { return fmt.Sprintf("mediapool root '%s'", f.Root()) }

// Features returns the optional features of this Fs.
func (f *Fs) Features() *fs.Features { return f.features }

// Precision of modification times: stored to the nanosecond, but they can't
// be changed after upload (see SetModTime).
func (f *Fs) Precision() time.Duration { return time.Nanosecond }

// Hashes returns the supported hash sets: none.
func (f *Fs) Hashes() hash.Set { return hash.Set(hash.None) }

func (f *Fs) newObject(e mediapool.Entry) *Object {
	return &Object{fs: f, remote: f.rel(f.opt.Enc.ToStandardPath(e.Path)), size: e.Size, modTime: e.ModTime, author: e.Author}
}

// NewObject finds the Object at remote.
func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	e, err := f.client.Stat(ctx, f.abs(remote))
	if errors.Is(err, mediapool.ErrNotExist) {
		return nil, fs.ErrorObjectNotFound
	}
	if err != nil {
		return nil, err
	}
	return f.newObject(e), nil
}

// dirPrefix is the unencoded path prefix of everything under directory dir.
func (f *Fs) dirPrefix(dir string) string {
	p := f.std(dir)
	if p == "/" {
		return p
	}
	return p + "/"
}

// rel is the remote of unencoded path p, which must be under the root.
func (f *Fs) rel(p string) string {
	return strings.TrimPrefix(strings.TrimPrefix(p, f.root), "/")
}

// walk lists everything under dir. With recurse it returns every file below
// dir and every directory implied by them; without, only dir's direct
// children. found reports whether dir exists at all.
func (f *Fs) walk(ctx context.Context, dir string, recurse bool) (entries fs.DirEntries, found bool, err error) {
	all, err := f.client.List(ctx)
	if err != nil {
		return nil, false, err
	}
	prefix := f.dirPrefix(dir)
	seen := map[string]bool{}
	// add sends p (an unencoded path under prefix): a directory, or a file when
	// e is set. Without recurse, anything deeper becomes its top directory.
	add := func(p string, e *mediapool.Entry) {
		found = true
		parts := strings.Split(p[len(prefix):], "/")
		if !recurse && len(parts) > 1 {
			parts, e = parts[:1], nil
		}
		for i := 1; i < len(parts); i++ { // implied directories
			d := path.Join(dir, path.Join(parts[:i]...))
			if !seen[d] {
				seen[d] = true
				entries = append(entries, fs.NewDir(d, time.Time{}))
			}
		}
		last := path.Join(dir, path.Join(parts...))
		if e != nil {
			entries = append(entries, f.newObject(*e))
		} else if !seen[last] {
			seen[last] = true
			entries = append(entries, fs.NewDir(last, time.Time{}))
		}
	}
	for i := range all {
		if p := f.opt.Enc.ToStandardPath(all[i].Path); strings.HasPrefix(p, prefix) {
			add(p, &all[i])
		}
	}
	// Directories made by Mkdir that may hold no files yet.
	f.mu.Lock()
	defer f.mu.Unlock()
	for d := range f.dirs {
		if d == f.std(dir) {
			found = true
		} else if strings.HasPrefix(d, prefix) {
			add(d, nil)
		}
	}
	if f.std(dir) == "/" {
		found = true // the pool root always exists
	}
	return entries, found, nil
}

// List the objects and directories in dir into entries.
func (f *Fs) List(ctx context.Context, dir string) (fs.DirEntries, error) {
	entries, found, err := f.walk(ctx, dir, false)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fs.ErrorDirNotFound
	}
	return entries, nil
}

// ListR lists everything under dir recursively. The pool is listed in one
// call, so this is much cheaper than walking directory by directory.
func (f *Fs) ListR(ctx context.Context, dir string, callback fs.ListRCallback) error {
	entries, found, err := f.walk(ctx, dir, true)
	if err != nil {
		return err
	}
	if !found {
		return fs.ErrorDirNotFound
	}
	return callback(entries)
}

// Put uploads in to the pool and returns the new Object.
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	o := &Object{fs: f, remote: src.Remote()}
	return o, o.Update(ctx, in, src, options...)
}

// PutStream uploads data of unknown size; the pool streams uploads anyway.
func (f *Fs) PutStream(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	return f.Put(ctx, in, src, options...)
}

// Mkdir records dir and its parents so they can be listed and removed while
// they hold no files. Directories are implicit in the pool, so this lasts
// only as long as the process.
func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	f.keepDirs(f.std(dir))
	return nil
}

// keepDirs records directory p and its parents.
func (f *Fs) keepDirs(p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for ; p != "/"; p = path.Dir(p) {
		f.dirs[p] = true
	}
}

// Rmdir removes an empty directory.
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	entries, found, err := f.walk(ctx, dir, false)
	if err != nil {
		return err
	}
	if !found {
		return fs.ErrorDirNotFound
	}
	if len(entries) > 0 {
		return fs.ErrorDirectoryNotEmpty
	}
	f.mu.Lock()
	delete(f.dirs, f.std(dir))
	f.mu.Unlock()
	return nil
}

// Fs returns the parent Fs.
func (o *Object) Fs() fs.Info { return o.fs }

// String returns the remote path.
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path.
func (o *Object) Remote() string { return o.remote }

// Hash is unsupported: the pool exposes no content hashes.
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	return "", hash.ErrUnsupported
}

// Size returns the size of the object in bytes.
func (o *Object) Size() int64 { return o.size }

// ModTime returns the modification time recorded at upload.
func (o *Object) ModTime(ctx context.Context) time.Time { return o.modTime }

// SetModTime is unsupported: modification times are fixed at upload.
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return fs.ErrorCantSetModTime
}

// Storable returns whether this object can be stored.
func (o *Object) Storable() bool { return true }

// Open the object for reading, honouring seek and range options.
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (io.ReadCloser, error) {
	var offset, limit int64 = 0, -1
	for _, option := range options {
		switch x := option.(type) {
		case *fs.RangeOption:
			offset, limit = x.Decode(o.size)
		case *fs.SeekOption:
			offset = x.Offset
		default:
			if option.Mandatory() {
				fs.Logf(o, "Unsupported mandatory option: %v", option)
			}
		}
	}
	r, err := o.fs.client.OpenRange(ctx, o.fs.abs(o.remote), offset, limit)
	if errors.Is(err, mediapool.ErrNotExist) {
		return nil, fs.ErrorObjectNotFound
	}
	if err != nil {
		return nil, err
	}
	if limit >= 0 {
		return readers.NewLimitedReadCloser(r, limit), nil
	}
	return r, nil
}

// errNotAuthor explains why another member's file can't be changed.
func (o *Object) errNotAuthor(op string) error {
	return fmt.Errorf("can't %s %s: added by member %q, only they can change it: %w",
		op, o.remote, o.author, fs.ErrorPermissionDenied)
}

// Update replaces the object's contents. Only the member who added a file
// can overwrite it.
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) error {
	if o.author != "" && o.author != o.fs.opt.Member {
		return o.errNotAuthor("overwrite")
	}
	e, err := o.fs.client.Put(ctx, o.fs.abs(o.remote), in, src.ModTime(ctx))
	if err != nil {
		return err
	}
	o.size, o.modTime, o.author = e.Size, e.ModTime, e.Author
	return nil
}

// Remove deletes the object. Only the member who added it can.
func (o *Object) Remove(ctx context.Context) error {
	if o.author != "" && o.author != o.fs.opt.Member {
		return o.errNotAuthor("remove")
	}
	err := o.fs.client.Remove(ctx, o.fs.abs(o.remote))
	if errors.Is(err, mediapool.ErrNotExist) {
		return fs.ErrorObjectNotFound
	}
	if err == nil {
		// Like a filesystem, the directory outlives its last file.
		o.fs.keepDirs(path.Dir(o.fs.std(o.remote)))
	}
	return err
}

// Check the interfaces are satisfied.
var (
	_ fs.Fs          = (*Fs)(nil)
	_ fs.PutStreamer = (*Fs)(nil)
	_ fs.ListRer     = (*Fs)(nil)
	_ fs.Object      = (*Object)(nil)
)
