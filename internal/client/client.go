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
	"mediapool/internal/merkle"
	"mediapool/internal/proto"
	"mediapool/internal/transfer"
)

type Client struct {
	CoordURL   string
	PoolSecret []byte
	Member     string
	HTTP       *http.Client

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
		HTTP: &http.Client{},
		key:  auth.NewIdentity(key), cat: cat,
	}, nil
}

func (c *Client) Close() error { return c.cat.Close() }

// PoolConfig returns the parameters the pool was created with, from the
// signed catalog. Every member cuts files with the same segment size, which
// is what lets identical files dedup.
func (c *Client) PoolConfig(ctx context.Context) (catalog.PoolConfig, error) {
	if cfg, ok := c.cat.Config(); ok {
		return cfg, nil
	}
	if err := c.Sync(ctx); err != nil {
		return catalog.PoolConfig{}, err
	}
	if cfg, ok := c.cat.Config(); ok {
		return cfg, nil
	}
	return catalog.PoolConfig{}, errors.New("the pool's catalog has no configuration entry")
}

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
	cfg, err := c.PoolConfig(ctx)
	if err != nil {
		return AddStats{}, err
	}
	params := codec.Params{K: cfg.K, MaxN: cfg.MaxN}
	m := Manifest{Path: cleanPath(poolPath), ModTime: modTime.UnixNano()}
	var st AddStats
	buf := make([]byte, cfg.SegmentSize)
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

// located is where a segment's shards are, checked against our catalog.
type located struct {
	loc  proto.LocateResponse
	seg  catalog.Segment
	root merkle.Hash
}

func (c *Client) locate(ctx context.Context, id string) (located, error) {
	var l located
	if err := transfer.GetJSON(ctx, c.HTTP, c.key, c.CoordURL+"/v1/locate/"+id, &l.loc); err != nil {
		return l, err
	}
	// Verify against the root in our own replica, not the coordinator's word.
	s, ok := c.cat.Segment(id)
	if !ok || s.ShardRoot != l.loc.Root {
		return l, fmt.Errorf("segment %.12s: coordinator root disagrees with the catalog", id)
	}
	root, err := codec.HexToHash(s.ShardRoot)
	if err != nil {
		return l, err
	}
	l.seg, l.root = s, root
	return l, nil
}

// ReadSegment fetches, verifies, decodes and decrypts one whole segment.
func (c *Client) ReadSegment(ctx context.Context, e SegmentEntry) ([]byte, error) {
	l, err := c.locate(ctx, e.ID)
	if err != nil {
		return nil, err
	}
	return c.decodeSegment(ctx, e, l)
}

// decodeSegment rebuilds a segment from any k shards and checks it with the
// GCM tag: the path that works whichever shards are online.
func (c *Client) decodeSegment(ctx context.Context, e SegmentEntry, l located) ([]byte, error) {
	loc, s, root := l.loc, l.seg, l.root
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
