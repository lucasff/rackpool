// Package mediapool is the public Go API for using a pool as a member:
// list, read, write and remove files. It's what out-of-tree integrations
// (the rclone backend, media servers) build against; everything else in
// this module is internal and may change.
//
// Paths are slash-separated and absolute ("/movies/A.mkv"). Directories are
// implicit: a directory exists when some file path has it as a prefix.
package mediapool

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/client"
)

// ErrNotExist is returned (wrapped) for paths that aren't in the pool.
var ErrNotExist = os.ErrNotExist

type Config struct {
	CoordURL string // coordinator base URL, e.g. http://coord.example:7000
	PoolFile string // path to pool.json
	Member   string // member name as listed in pool.json
	KeyFile  string // member's private key file
	Secret   string // pool secret; if empty, $MEDIAPOOL_SECRET
	// CatalogPath keeps a local replica of the catalog between runs, so
	// startup syncs only new entries. Empty keeps it in memory.
	CatalogPath string
	// ReadAhead is how many bytes past the segment being read to fetch in
	// the background (default 32 MiB). CacheSize bounds the segments kept
	// in memory, shared by every open file (default 256 MiB).
	ReadAhead int64
	CacheSize int64
}

type Client struct{ c *client.Client }

type Entry struct {
	Path    string
	Size    int64
	ModTime time.Time // zero if the uploader didn't record one
	Author  string    // member who added it; only they can overwrite or remove it
}

func Open(cfg Config) (*Client, error) {
	if cfg.Secret == "" {
		cfg.Secret = os.Getenv("MEDIAPOOL_SECRET")
	}
	if cfg.CoordURL == "" || cfg.PoolFile == "" || cfg.Member == "" || cfg.KeyFile == "" || cfg.Secret == "" {
		return nil, errors.New("mediapool: coordinator URL, pool file, member, key file and secret are required")
	}
	pool, err := auth.LoadPool(cfg.PoolFile)
	if err != nil {
		return nil, err
	}
	key, err := auth.LoadOrCreateKey(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	c, err := client.New(cfg.CoordURL, []byte(cfg.Secret), cfg.Member, key, pool, cfg.CatalogPath)
	if err != nil {
		return nil, err
	}
	if cfg.ReadAhead > 0 {
		c.ReadAhead = cfg.ReadAhead
	}
	if cfg.CacheSize > 0 {
		c.CacheSize = cfg.CacheSize
	}
	return &Client{c: c}, nil
}

func (c *Client) Close() error { return c.c.Close() }

func entry(m client.Manifest) Entry {
	e := Entry{Path: m.Path, Size: m.Size, Author: m.Author}
	if m.ModTime != 0 {
		e.ModTime = time.Unix(0, m.ModTime)
	}
	return e
}

// List returns every file in the pool, sorted by path.
func (c *Client) List(ctx context.Context) ([]Entry, error) {
	ms, err := c.c.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, len(ms))
	for i, m := range ms {
		out[i] = entry(m)
	}
	return out, nil
}

func (c *Client) Stat(ctx context.Context, path string) (Entry, error) {
	m, err := c.c.Stat(ctx, path)
	if err != nil {
		return Entry{}, err
	}
	return entry(m), nil
}

// Reader reads a pool file. It supports Seek and concurrent ReadAt, and
// prefetches the next segment during sequential reads.
type Reader interface {
	io.ReadSeekCloser
	io.ReaderAt
	Size() int64
}

func (c *Client) Open(ctx context.Context, path string) (Reader, error) {
	return c.OpenRange(ctx, path, 0, -1)
}

// OpenRange opens a file for reading length bytes from offset (-1 for to
// the end), positioned at offset. Read-ahead stops at the end of the range,
// so bounded reads don't fetch data nobody asked for.
func (c *Client) OpenRange(ctx context.Context, path string, offset, length int64) (Reader, error) {
	m, err := c.c.Stat(ctx, path)
	if err != nil {
		return nil, err
	}
	end := int64(-1)
	if length >= 0 {
		end = offset + length
	}
	f := c.c.OpenRange(ctx, m, end)
	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return f, nil
}

// Put stores r at path. Overwriting is only allowed for files this member
// added. The data is uploaded as it's read; nothing is buffered to disk.
func (c *Client) Put(ctx context.Context, path string, r io.Reader, modTime time.Time) (Entry, error) {
	if modTime.IsZero() {
		modTime = time.Now()
	}
	if _, err := c.c.AddWithTime(ctx, r, path, nil, modTime); err != nil {
		return Entry{}, fmt.Errorf("mediapool: put %s: %w", path, err)
	}
	return c.Stat(ctx, path)
}

// Remove deletes a file this member added.
func (c *Client) Remove(ctx context.Context, path string) error {
	return c.c.Remove(ctx, path)
}
