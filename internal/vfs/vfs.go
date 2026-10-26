// Package vfs presents the pool's flat list of file paths as a directory
// tree, for listing commands, the rc API, WebDAV and HTTP serving. A
// directory exists while some file lives under it.
package vfs

import (
	"context"
	"io"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"mediapool/internal/client"
	"mediapool/internal/proto"
)

type Entry struct {
	Path    string    `json:"Path"` // absolute, e.g. /movies/A.mkv
	Name    string    `json:"Name"`
	Size    int64     `json:"Size"`
	ModTime time.Time `json:"ModTime"`
	IsDir   bool      `json:"IsDir"`
	Author  string    `json:"Author,omitempty"`
}

// FS wraps a client with a short-lived listing cache, so a WebDAV client
// issuing dozens of PROPFINDs doesn't sync the catalog each time.
type FS struct {
	C   *client.Client
	TTL time.Duration

	mu      sync.Mutex
	files   []client.Manifest
	fetched time.Time
}

func New(c *client.Client) *FS { return &FS{C: c, TTL: 2 * time.Second} }

func Clean(p string) string {
	p = strings.TrimPrefix(p, "pool:")
	return path.Clean("/" + p)
}

func (f *FS) all(ctx context.Context) ([]client.Manifest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.files != nil && time.Since(f.fetched) < f.TTL {
		return f.files, nil
	}
	ms, err := f.C.List(ctx)
	if err != nil {
		return nil, err
	}
	f.files, f.fetched = ms, time.Now()
	return ms, nil
}

// Invalidate drops the cache after a write.
func (f *FS) Invalidate() {
	f.mu.Lock()
	f.files = nil
	f.mu.Unlock()
}

func fileEntry(m client.Manifest) Entry {
	e := Entry{Path: m.Path, Name: path.Base(m.Path), Size: m.Size, Author: m.Author}
	if m.ModTime != 0 {
		e.ModTime = time.Unix(0, m.ModTime)
	}
	return e
}

// Stat returns a file or a directory entry.
func (f *FS) Stat(ctx context.Context, p string) (Entry, error) {
	p = Clean(p)
	ms, err := f.all(ctx)
	if err != nil {
		return Entry{}, err
	}
	if p == "/" {
		return Entry{Path: "/", Name: "/", IsDir: true}, nil
	}
	dir := Entry{Path: p, Name: path.Base(p), IsDir: true}
	found := false
	for _, m := range ms {
		if m.Path == p {
			return fileEntry(m), nil
		}
		if strings.HasPrefix(m.Path, p+"/") {
			found = true
			if t := time.Unix(0, m.ModTime); m.ModTime != 0 && t.After(dir.ModTime) {
				dir.ModTime = t
			}
		}
	}
	if found {
		return dir, nil
	}
	return Entry{}, &os.PathError{Op: "stat", Path: p, Err: os.ErrNotExist}
}

// List returns the entries in dir. With recurse it returns every file
// below dir (and no directory entries), like rclone's ls.
func (f *FS) List(ctx context.Context, dir string, recurse bool) ([]Entry, error) {
	dir = Clean(dir)
	ms, err := f.all(ctx)
	if err != nil {
		return nil, err
	}
	prefix := strings.TrimSuffix(dir, "/") + "/"
	var out []Entry
	dirs := map[string]*Entry{}
	any := false
	for _, m := range ms {
		if m.Path == dir {
			return []Entry{fileEntry(m)}, nil // listing a file lists the file
		}
		rest, ok := strings.CutPrefix(m.Path, prefix)
		if !ok {
			continue
		}
		any = true
		if recurse {
			out = append(out, fileEntry(m))
			continue
		}
		name, _, isDir := strings.Cut(rest, "/")
		if !isDir {
			out = append(out, fileEntry(m))
			continue
		}
		d := dirs[name]
		if d == nil {
			d = &Entry{Path: prefix + name, Name: name, IsDir: true}
			dirs[name] = d
		}
		d.Size += m.Size
		if t := time.Unix(0, m.ModTime); m.ModTime != 0 && t.After(d.ModTime) {
			d.ModTime = t
		}
	}
	if !any && dir != "/" {
		return nil, &os.PathError{Op: "list", Path: dir, Err: os.ErrNotExist}
	}
	for _, d := range dirs {
		out = append(out, *d)
	}
	slices.SortFunc(out, func(a, b Entry) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// Open opens a file for reading.
func (f *FS) Open(ctx context.Context, p string) (*client.File, client.Manifest, error) {
	m, err := f.C.Stat(ctx, Clean(p))
	if err != nil {
		return nil, client.Manifest{}, err
	}
	return f.C.Open(ctx, m), m, nil
}

// Put uploads r to p.
func (f *FS) Put(ctx context.Context, p string, r io.Reader, modTime time.Time) (client.AddStats, error) {
	defer f.Invalidate()
	return f.C.AddWithTime(ctx, r, Clean(p), nil, modTime)
}

// Remove deletes a file.
func (f *FS) Remove(ctx context.Context, p string) error {
	defer f.Invalidate()
	return f.C.Remove(ctx, Clean(p))
}

// RemoveAll deletes every file at or under p that this member owns. Files
// owned by others are skipped and returned as notOwned.
func (f *FS) RemoveAll(ctx context.Context, p string, dryRun bool) (removed, notOwned []string, err error) {
	p = Clean(p)
	ms, err := f.all(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer f.Invalidate()
	for _, m := range ms {
		if m.Path != p && !strings.HasPrefix(m.Path, strings.TrimSuffix(p, "/")+"/") {
			continue
		}
		if m.Author != f.C.Member {
			notOwned = append(notOwned, m.Path)
			continue
		}
		if !dryRun {
			if err := f.C.Remove(ctx, m.Path); err != nil {
				return removed, notOwned, err
			}
		}
		removed = append(removed, m.Path)
	}
	return removed, notOwned, nil
}

// About summarises the pool for `mp about` and operations/about.
type About struct {
	Files      int     `json:"files"`
	Bytes      int64   `json:"bytes"`
	MyFiles    int     `json:"my_files"`
	MyBytes    int64   `json:"my_bytes"`
	Segments   int     `json:"segments"`
	Nodes      int     `json:"nodes"`
	NodesUp    int     `json:"nodes_online"`
	Relayed    int     `json:"nodes_relayed"`
	Offered    int64   `json:"offered_bytes"` // used + free across online nodes
	Used       int64   `json:"used_bytes"`
	Unique     int64   `json:"unique_bytes"` // content after dedup
	Dedup      float64 `json:"dedup"`        // file bytes per unique byte
	Overhead   float64 `json:"overhead"`     // shard bytes stored per unique byte
	CatalogSeq uint64  `json:"catalog_seq"`
	Blocked    string  `json:"write_blocked,omitempty"`
}

func (f *FS) About(ctx context.Context) (About, proto.StatusResponse, error) {
	var a About
	ms, err := f.all(ctx)
	if err != nil {
		return a, proto.StatusResponse{}, err
	}
	for _, m := range ms {
		a.Files++
		a.Bytes += m.Size
		if m.Author == f.C.Member {
			a.MyFiles++
			a.MyBytes += m.Size
		}
	}
	st, err := f.C.Status(ctx)
	if err != nil {
		return a, st, err
	}
	a.Segments, a.Nodes, a.CatalogSeq, a.Blocked = len(st.Segments), len(st.Nodes), st.Head.Seq, st.WriteBlocked
	for _, sg := range st.Segments {
		a.Unique += int64(sg.Size)
	}
	for _, n := range st.Nodes {
		a.Used += n.Capacity.Used
		if n.Online {
			a.NodesUp++
			if n.Capacity.Free > 0 {
				a.Offered += n.Capacity.Used + n.Capacity.Free
			}
		}
		if n.Reach == "relay" {
			a.Relayed++
		}
	}
	if a.Unique > 0 {
		a.Overhead = float64(a.Used) / float64(a.Unique)
		a.Dedup = float64(a.Bytes) / float64(a.Unique)
	}
	return a, st, nil
}
