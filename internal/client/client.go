// Package client adds files to the pool and reads them back. It holds the
// pool secret and the member's key: it is the only component that sees
// plaintext. It keeps its own verified replica of the catalog, so listing
// and opening files never downloads the whole library.
package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"mediapool/internal/auth"
	"mediapool/internal/bridge"
	"mediapool/internal/catalog"
	"mediapool/internal/codec"
	"mediapool/internal/proto"
	"mediapool/internal/transfer"
)

const DefaultSegmentSize = 64 << 20

type Client struct {
	CoordURL    string
	PoolSecret  []byte
	Member      string
	SegmentSize int
	HTTP        *http.Client

	key *auth.Identity
	cat *catalog.Catalog
}

// New opens a client for member, keeping its catalog replica at catalogPath
// ("" for memory only).
func New(coordURL string, poolSecret []byte, member string, key ed25519.PrivateKey, pool *auth.Pool, catalogPath string) (*Client, error) {
	coordKey, err := pool.CoordinatorKey()
	if err != nil {
		return nil, err
	}
	cat, err := catalog.Open(catalogPath, coordKey)
	if err != nil {
		return nil, err
	}
	pool.Attach(cat)
	return &Client{
		CoordURL: coordURL, PoolSecret: poolSecret, Member: member,
		SegmentSize: DefaultSegmentSize, HTTP: &http.Client{},
		key: auth.NewIdentity(key), cat: cat,
	}, nil
}

func (c *Client) Close() error { return c.cat.Close() }

// Sync pulls new catalog entries from the coordinator.
func (c *Client) Sync(ctx context.Context) error {
	_, err := c.cat.Sync(ctx, c.HTTP, c.CoordURL, c.key.Signer())
	return err
}

// Manifest describes one file. It is sealed with the pool secret before it
// reaches the catalog, so names, sizes and keys stay private.
type Manifest struct {
	Path     string         `json:"path"`
	Size     int64          `json:"size"`
	ModTime  int64          `json:"mtime,omitempty"` // unix nanoseconds; 0 if unknown
	Segments []SegmentEntry `json:"segments"`
	Author   string         `json:"-"`
}

type SegmentEntry struct {
	ID        string `json:"id"`
	Key       []byte `json:"key"`
	PlainSize int64  `json:"plain_size"`
}

// Source names the public torrent a file came from, which lets bridge nodes
// verify and repair it from the swarm.
type Source struct {
	Infohash string
	File     string
}

const manifestPurpose = "manifest"

type AddStats struct {
	Segments  int
	Deduped   int
	Uploaded  int64 // shard bytes sent
	PlainSize int64
}

func cleanPath(p string) string { return path.Clean("/" + p) }

func (c *Client) pathID(p string) string { return codec.KeyedID(c.PoolSecret, "path", []byte(p)) }

// AddFile stores the file at localPath in the pool under poolPath.
func (c *Client) AddFile(ctx context.Context, localPath, poolPath string, src *Source) (AddStats, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return AddStats{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return AddStats{}, err
	}
	return c.AddWithTime(ctx, f, poolPath, src, fi.ModTime())
}

func (c *Client) Add(ctx context.Context, r io.Reader, poolPath string, src *Source) (AddStats, error) {
	return c.AddWithTime(ctx, r, poolPath, src, time.Now())
}

// AddWithTime is Add with an explicit modification time for the file.
func (c *Client) AddWithTime(ctx context.Context, r io.Reader, poolPath string, src *Source, modTime time.Time) (AddStats, error) {
	var params codec.Params
	if err := transfer.GetJSON(ctx, c.HTTP, c.key, c.CoordURL+"/v1/params", &params); err != nil {
		return AddStats{}, err
	}
	m := Manifest{Path: cleanPath(poolPath), ModTime: modTime.UnixNano()}
	var st AddStats
	buf := make([]byte, c.SegmentSize)
	for {
		nr, err := io.ReadFull(r, buf)
		if nr > 0 {
			var ref *bridge.SourceRef
			if src != nil {
				ref = &bridge.SourceRef{Infohash: src.Infohash, File: src.File, Offset: m.Size, Length: int64(nr)}
			}
			e, deduped, sent, perr := c.putSegment(ctx, params, buf[:nr], ref)
			if perr != nil {
				return st, fmt.Errorf("segment %d: %w", len(m.Segments), perr)
			}
			m.Segments = append(m.Segments, e)
			m.Size += int64(nr)
			st.Segments++
			st.Uploaded += sent
			if deduped {
				st.Deduped++
			}
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return st, err
		}
	}
	st.PlainSize = m.Size
	return st, c.putManifest(ctx, m)
}

func (c *Client) putSegment(ctx context.Context, params codec.Params, plain []byte, ref *bridge.SourceRef) (SegmentEntry, bool, int64, error) {
	key, ct, id, err := codec.SealSegment(c.PoolSecret, plain)
	if err != nil {
		return SegmentEntry{}, false, 0, err
	}
	entry := SegmentEntry{ID: id, Key: key, PlainSize: int64(len(plain))}
	shards, err := codec.Encode(params, ct)
	if err != nil {
		return entry, false, 0, err
	}
	tree := codec.NewTree(shards)
	root := codec.HashToHex(tree.Root)

	req := proto.PrepareRequest{Segment: id, CipherSize: len(ct), Root: root}
	if ref != nil {
		if req.SourceBlob, err = bridge.SealRef(c.PoolSecret, *ref); err != nil {
			return entry, false, 0, err
		}
	}
	var prep proto.PrepareResponse
	if err := transfer.PostJSON(ctx, c.HTTP, c.key, c.CoordURL+"/v1/prepare", req, &prep); err != nil {
		return entry, false, 0, err
	}
	if prep.Exists {
		return entry, true, 0, nil // someone already added these exact bytes
	}

	var mu sync.Mutex
	var placed []proto.Location
	var sent int64
	var wg sync.WaitGroup
	for _, t := range prep.Targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := transfer.PutShard(ctx, c.HTTP, t.Addr, id, t.Index, shards[t.Index], tree.Proof(t.Index), &t.Ticket); err != nil {
				return // the coordinator repairs any shortfall above k
			}
			mu.Lock()
			placed = append(placed, t.Location)
			sent += int64(len(shards[t.Index]))
			mu.Unlock()
		}()
	}
	wg.Wait()
	if len(placed) < params.K {
		return entry, false, sent, fmt.Errorf("only %d of %d shards placed, need %d", len(placed), len(prep.Targets), params.K)
	}
	err = transfer.PostJSON(ctx, c.HTTP, c.key, c.CoordURL+"/v1/commit", proto.CommitRequest{Segment: id, Root: root, Placed: placed}, nil)
	return entry, false, sent, err
}

// putManifest writes or overwrites a file entry signed by this member.
func (c *Client) putManifest(ctx context.Context, m Manifest) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	blob, err := codec.SealBlob(c.PoolSecret, manifestPurpose, b)
	if err != nil {
		return err
	}
	if err := c.Sync(ctx); err != nil {
		return err
	}
	fp := catalog.FilePut{PathID: c.pathID(m.Path), Author: c.Member, Manifest: blob}
	if cur, ok := c.cat.File(fp.PathID); ok {
		fp.Replaces = cur.Seq
	}
	for _, s := range m.Segments {
		if !slices.Contains(fp.Segments, s.ID) {
			fp.Segments = append(fp.Segments, s.ID)
		}
	}
	fp.Sig = c.key.SignRaw(fp.Message())
	return transfer.PostJSON(ctx, c.HTTP, c.key, c.CoordURL+"/v1/files", fp, nil)
}

// Remove deletes a file this member added. Its segments are collected once
// no other file references them.
func (c *Client) Remove(ctx context.Context, poolPath string) error {
	if err := c.Sync(ctx); err != nil {
		return err
	}
	id := c.pathID(cleanPath(poolPath))
	cur, ok := c.cat.File(id)
	if !ok {
		return fmt.Errorf("%s: %w", poolPath, os.ErrNotExist)
	}
	fd := catalog.FileDel{PathID: id, Author: c.Member, Replaces: cur.Seq}
	fd.Sig = c.key.SignRaw(fd.Message())
	return transfer.PostJSON(ctx, c.HTTP, c.key, c.CoordURL+"/v1/files/delete", fd, nil)
}

func (c *Client) open(f catalog.File) (Manifest, bool) {
	b, err := codec.OpenBlob(c.PoolSecret, manifestPurpose, f.Manifest)
	if err != nil {
		return Manifest{}, false
	}
	var m Manifest
	if json.Unmarshal(b, &m) != nil {
		return Manifest{}, false
	}
	m.Author = f.Author
	return m, true
}

// List syncs the catalog and returns every readable file, sorted by path.
func (c *Client) List(ctx context.Context) ([]Manifest, error) {
	if err := c.Sync(ctx); err != nil {
		return nil, err
	}
	var out []Manifest
	for _, f := range c.cat.Files() {
		if m, ok := c.open(f); ok {
			out = append(out, m)
		}
	}
	slices.SortFunc(out, func(a, b Manifest) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

// Stat looks a path up in the local replica, syncing first.
func (c *Client) Stat(ctx context.Context, poolPath string) (Manifest, error) {
	if err := c.Sync(ctx); err != nil {
		return Manifest{}, err
	}
	p := cleanPath(poolPath)
	if f, ok := c.cat.File(c.pathID(p)); ok {
		if m, ok := c.open(f); ok {
			return m, nil
		}
	}
	return Manifest{}, fmt.Errorf("%s: %w", p, os.ErrNotExist)
}

// Status returns the coordinator's view of the pool.
func (c *Client) Status(ctx context.Context) (proto.StatusResponse, error) {
	var st proto.StatusResponse
	err := transfer.GetJSON(ctx, c.HTTP, c.key, c.CoordURL+"/v1/status", &st)
	return st, err
}

// ReadSegment fetches, verifies, decodes and decrypts one segment.
func (c *Client) ReadSegment(ctx context.Context, e SegmentEntry) ([]byte, error) {
	var loc proto.LocateResponse
	if err := transfer.GetJSON(ctx, c.HTTP, c.key, c.CoordURL+"/v1/locate/"+e.ID, &loc); err != nil {
		return nil, err
	}
	// Verify against the root in our own replica, not the coordinator's word.
	s, ok := c.cat.Segment(e.ID)
	if !ok || s.ShardRoot != loc.Root {
		return nil, fmt.Errorf("segment %.12s: coordinator root disagrees with the catalog", e.ID)
	}
	root, err := codec.HexToHash(s.ShardRoot)
	if err != nil {
		return nil, err
	}
	shards, err := transfer.FetchAny(ctx, c.HTTP, c.key, e.ID, loc.Shards, root, loc.Params.K, loc.Params.MaxN)
	if err != nil {
		return nil, err
	}
	ct, err := codec.Join(loc.Params, shards, s.CipherSize)
	if err != nil {
		return nil, err
	}
	if codec.HashHex(ct) != e.ID {
		return nil, errors.New("reassembled segment doesn't match its id")
	}
	return codec.OpenSegment(e.Key, ct)
}

// Open returns a seekable reader over a pool file. It keeps the current
// segment in memory and prefetches the next, so sequential playback rarely
// waits on the network.
func (c *Client) Open(ctx context.Context, m Manifest) *File {
	return &File{c: c, ctx: ctx, m: m, cache: map[int]*segmentLoad{}}
}

type segmentLoad struct {
	done chan struct{}
	data []byte
	err  error
}

type File struct {
	c   *Client
	ctx context.Context
	m   Manifest
	off int64

	mu    sync.Mutex
	cache map[int]*segmentLoad
}

func (f *File) Size() int64 { return f.m.Size }

// Close releases cached segments.
func (f *File) Close() error {
	f.mu.Lock()
	f.cache = map[int]*segmentLoad{}
	f.mu.Unlock()
	return nil
}

func (f *File) load(i int) *segmentLoad {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l, ok := f.cache[i]; ok {
		return l
	}
	l := &segmentLoad{done: make(chan struct{})}
	f.cache[i] = l
	go func() {
		l.data, l.err = f.c.ReadSegment(f.ctx, f.m.Segments[i])
		close(l.done)
	}()
	for k := range f.cache { // keep only the segments around the playhead
		if k < i-1 || k > i+1 {
			delete(f.cache, k)
		}
	}
	return l
}

func (f *File) segmentAt(off int64) (idx int, start int64) {
	for i, s := range f.m.Segments {
		if off < start+s.PlainSize {
			return i, start
		}
		start += s.PlainSize
	}
	return len(f.m.Segments), start
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	n := 0
	for n < len(p) {
		if off >= f.m.Size {
			return n, io.EOF
		}
		i, start := f.segmentAt(off)
		l := f.load(i)
		if i+1 < len(f.m.Segments) {
			f.load(i + 1)
		}
		<-l.done
		if l.err != nil {
			f.mu.Lock()
			delete(f.cache, i) // don't keep a failed load around
			f.mu.Unlock()
			return n, l.err
		}
		c := copy(p[n:], l.data[off-start:])
		n += c
		off += int64(c)
	}
	return n, nil
}

func (f *File) Read(p []byte) (int, error) {
	n, err := f.ReadAt(p, f.off)
	f.off += int64(n)
	return n, err
}

func (f *File) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += f.off
	case io.SeekEnd:
		offset += f.m.Size
	default:
		return 0, errors.New("seek: bad whence")
	}
	if offset < 0 {
		return 0, errors.New("seek: negative offset")
	}
	f.off = offset
	return offset, nil
}
