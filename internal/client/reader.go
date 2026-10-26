package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"

	"mediapool/internal/codec"
	"mediapool/internal/proto"
	"mediapool/internal/transfer"
)

// Open returns a seekable reader over a pool file.
//
// A read fetches only the ChunkSize pieces it needs from the segment's data
// shards. The erasure code keeps the first k shards as plain slices of the
// ciphertext, and each chunk is verified against Merkle proofs chaining to
// the segment root in the signed catalog, then decrypted on its own, so
// playback and seeks start as soon as one chunk arrives. Meanwhile the rest
// of the segment streams in from all its data shards in parallel (so
// throughput adds up across holders) and the next segment is prefetched.
// If a chunk can't be fetched from any holder of its shard, the segment is
// rebuilt from any k shards and checked with its GCM tag instead.
func (c *Client) Open(ctx context.Context, m Manifest) *File {
	return &File{c: c, ctx: ctx, m: m, segs: map[int]*segLoad{}}
}

type File struct {
	c   *Client
	ctx context.Context
	m   Manifest
	off int64

	mu   sync.Mutex
	segs map[int]*segLoad
	cur  int // segment most recently read
}

type segLoad struct {
	entry  SegmentEntry
	cancel context.CancelFunc
	setup  chan struct{} // closed once the fields below are set

	err       error
	firstDone chan struct{} // closed once the first requested chunk has arrived
	l         located
	shardSize int
	perShard  int // chunks per shard
	plain     []byte

	mu     sync.Mutex
	ready  []chan struct{}
	closed []bool
	failed error // set if the segment couldn't be read at all
	once   sync.Once
}

func (f *File) Size() int64 { return f.m.Size }

// Close stops background fetches and drops cached segments.
func (f *File) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, l := range f.segs {
		l.cancel()
		delete(f.segs, i)
	}
	return nil
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

// load returns segment i's loader, starting it (fetching from offset o
// first) if needed, prefetching segment i+1, and dropping segments that
// are no longer near the read position.
func (f *File) load(i int, o int64) *segLoad {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cur = i
	l := f.segs[i]
	if l == nil {
		l = f.start(i, o)
		f.segs[i] = l
	}
	select {
	case <-l.firstDone:
		f.prefetchLocked(i)
	default: // prefetched when its first chunk arrives (see afterFirst)
	}
	for k, x := range f.segs {
		if k < i-1 || k > i+1 {
			x.cancel()
			delete(f.segs, k)
		}
	}
	return l
}

// prefetchLocked starts the segment after i, keeping exactly one segment of
// read-ahead. Caller holds f.mu.
func (f *File) prefetchLocked(i int) {
	if i+1 < len(f.m.Segments) && f.segs[i+1] == nil {
		f.segs[i+1] = f.start(i+1, 0)
	}
}

// afterFirst runs when segment i's first chunk has arrived. If the reader
// is in that segment, the next one is prefetched now: starting it earlier
// would compete with the chunk being waited for.
func (f *File) afterFirst(i int, l *segLoad) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.segs[i] == l && f.cur == i {
		f.prefetchLocked(i)
	}
}

func (f *File) start(i int, first int64) *segLoad {
	ctx, cancel := context.WithCancel(f.ctx)
	l := &segLoad{entry: f.m.Segments[i], cancel: cancel, setup: make(chan struct{}), firstDone: make(chan struct{})}
	go l.run(ctx, f.c, first, func() { f.afterFirst(i, l) })
	return l
}

func (l *segLoad) run(ctx context.Context, c *Client, first int64, afterFirst func()) {
	loc, err := c.locate(ctx, l.entry.ID)
	if err == nil && int64(codec.PlainSize(loc.seg.CipherSize)) != l.entry.PlainSize {
		err = fmt.Errorf("segment %.12s: size in manifest doesn't match the catalog", l.entry.ID)
	}
	if err != nil {
		l.err = err
		close(l.setup)
		close(l.firstDone)
		return
	}
	p := loc.loc.Params
	l.l = loc
	l.shardSize = codec.ShardSize(p, loc.seg.CipherSize)
	l.perShard = codec.NumChunks(l.shardSize)
	l.plain = make([]byte, l.entry.PlainSize)
	total := p.K * l.perShard
	l.ready, l.closed = make([]chan struct{}, total), make([]bool, total)
	for g := range l.ready {
		l.ready[g] = make(chan struct{})
		if s, e := l.span(g); s >= e {
			l.markLocked(g, nil) // past the end of the plaintext: nothing to fetch
		}
	}
	close(l.setup)

	holders := map[int][]proto.Location{}
	for _, s := range loc.loc.Shards {
		if s.Index < p.K {
			holders[s.Index] = append(holders[s.Index], s)
		}
	}
	// First the chunk the reader is waiting for, alone, so it gets its
	// holder's whole upload.
	g0 := l.chunkFor(first)
	if !l.isReady(g0) && !l.fetch(ctx, c, g0, holders) {
		l.fallback(ctx, c)
		close(l.firstDone)
		afterFirst()
		return
	}
	close(l.firstDone)
	afterFirst()
	// Then the rest, round-robin across the data shards starting where the
	// reader is, so every holder is busy at once and throughput adds up.
	queue := make(chan int, total)
	d0, c0 := g0/l.perShard, g0%l.perShard
	for step := range l.perShard {
		for dd := range p.K {
			queue <- ((d0+dd)%p.K)*l.perShard + (c0+step)%l.perShard
		}
	}
	close(queue)
	var wg sync.WaitGroup
	for range min(3*p.K, total) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for g := range queue {
				if ctx.Err() != nil {
					return
				}
				if !l.isReady(g) && !l.fetch(ctx, c, g, holders) {
					l.fallback(ctx, c)
					return
				}
			}
		}()
	}
	wg.Wait()
}

// span returns the plaintext byte range chunk g covers.
func (l *segLoad) span(g int) (start, end int) {
	d, cc := g/l.perShard, g%l.perShard
	start = d*l.shardSize + cc*codec.ChunkSize
	end = d*l.shardSize + min((cc+1)*codec.ChunkSize, l.shardSize)
	return min(start, len(l.plain)), min(end, len(l.plain))
}

func (l *segLoad) chunkFor(o int64) int {
	d := int(o) / l.shardSize
	return d*l.perShard + (int(o)%l.shardSize)/codec.ChunkSize
}

func (l *segLoad) isReady(g int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed[g]
}

// markLocked publishes chunk g's plaintext (if data is non-nil, copying it
// in first) and wakes its readers. Caller holds l.mu, or is the only
// goroutine with access (during setup).
func (l *segLoad) markLocked(g int, data []byte) {
	if l.closed[g] {
		return
	}
	if data != nil {
		s, _ := l.span(g)
		copy(l.plain[s:], data)
	}
	l.closed[g] = true
	close(l.ready[g])
}

// fetch gets chunk g from any holder of its shard and publishes it.
func (l *segLoad) fetch(ctx context.Context, c *Client, g int, holders map[int][]proto.Location) bool {
	d, cc := g/l.perShard, g%l.perShard
	start, end := l.span(g)
	hs := holders[d]
	for _, i := range rand.Perm(len(hs)) {
		h := hs[i]
		data, err := transfer.GetChunk(ctx, c.HTTP, c.key, h.Addr, l.entry.ID, d, l.l.root, l.l.loc.Params.MaxN, l.shardSize, cc)
		if err != nil || len(data) < end-start {
			continue
		}
		plain, err := codec.DecryptRange(l.entry.Key, data[:end-start], int64(start))
		if err != nil {
			continue
		}
		l.mu.Lock()
		l.markLocked(g, plain)
		l.mu.Unlock()
		return true
	}
	return false
}

// fallback rebuilds the whole segment from any k shards and fills in every
// chunk not already published.
func (l *segLoad) fallback(ctx context.Context, c *Client) {
	l.once.Do(func() {
		plain, err := c.decodeSegment(ctx, l.entry, l.l)
		l.mu.Lock()
		defer l.mu.Unlock()
		if err == nil && len(plain) != len(l.plain) {
			err = errors.New("rebuilt segment has the wrong size")
		}
		if err != nil {
			l.failed = err
		}
		for g := range l.ready {
			if err != nil {
				if !l.closed[g] {
					l.closed[g] = true
					close(l.ready[g])
				}
				continue
			}
			s, e := l.span(g)
			l.markLocked(g, plain[s:e])
		}
	})
}

// wait blocks until the chunk holding offset o is available and returns
// where that chunk's plaintext ends.
func (l *segLoad) wait(ctx context.Context, o int64) (end int, err error) {
	select {
	case <-l.setup:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	if l.err != nil {
		return 0, l.err
	}
	g := l.chunkFor(o)
	select {
	case <-l.ready[g]:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	l.mu.Lock()
	failed := l.failed
	l.mu.Unlock()
	if failed != nil {
		return 0, failed
	}
	_, end = l.span(g)
	return end, nil
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	n := 0
	for n < len(p) {
		if off >= f.m.Size {
			return n, io.EOF
		}
		i, segStart := f.segmentAt(off)
		o := off - segStart
		l := f.load(i, o)
		end, err := l.wait(f.ctx, o)
		if err != nil {
			f.mu.Lock()
			if f.segs[i] == l {
				l.cancel()
				delete(f.segs, i) // retry from scratch on the next read
			}
			f.mu.Unlock()
			return n, err
		}
		c := copy(p[n:], l.plain[o:end])
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

// Loading reports whether segment i is loaded or loading (for tests).
func (f *File) Loading(i int) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.segs[i] != nil
}
