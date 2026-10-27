package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"mediapool/internal/codec"
	"mediapool/internal/proto"
	"mediapool/internal/transfer"
)

// Reading
//
// Segments are loaded into a cache shared by every open file of a Client,
// keyed by segment ID. Media players and servers read one file from several
// places at once (ffprobe jumping to the end for an MKV's index and
// attachments, subtitle extraction reading from the start, playback at the
// current position), and layers like rclone open a fresh handle for most
// range reads. With a shared cache none of them cancel each other's work:
// a seek starts what it needs at high priority and leaves everything else
// running, and a later reader of the same segment gets it from memory.
//
// Within a segment, the chunk being waited for is fetched on its own first
// (so it gets its holder's whole upload), then every data shard streams its
// remaining chunks in one request each, in parallel. The erasure code keeps
// the first k shards as plain slices of the ciphertext, and each chunk is
// verified against Merkle proofs chaining to the segment root in the signed
// catalog and decrypted on its own. If a chunk can't be fetched from any
// holder, the segment is rebuilt from any k shards and checked with its GCM
// tag instead.

const (
	DefaultReadAhead = 32 << 20
	DefaultCacheSize = 256 << 20
	// idleTimeout cancels a segment still loading that nobody has read
	// from, waited on or kept in a read-ahead window for this long: the
	// reader that started it went away (as rclone's downloaders do).
	idleTimeout = 5 * time.Second
)

type segCache struct {
	waiting atomic.Int32 // readers blocked on any segment right now

	mu    sync.Mutex
	loads map[string]*segLoad
	bytes int64
}

type segLoad struct {
	entry  SegmentEntry
	cancel context.CancelFunc
	setup  chan struct{} // closed once the fields below are set

	err       error
	firstDone chan struct{} // closed once the first requested chunk is in
	l         located
	lay       codec.Layout
	shardSize int
	perShard  int // chunks per shard
	plain     []byte

	mu        sync.Mutex
	ready     []chan struct{}
	closed    []bool
	remaining int
	failed    error // set if the segment couldn't be read at all
	once      sync.Once
	lastUsed  time.Time    // guarded by segCache.mu
	waiters   atomic.Int32 // readers blocked on this segment right now
}

// segment returns the shared load for e, starting it (fetching the chunk
// at offset o first) if it isn't cached. An existing load that hasn't got
// o's chunk yet fetches it now, ahead of its other work.
func (c *Client) segment(e SegmentEntry, o int64) *segLoad {
	sc := c.cache
	sc.mu.Lock()
	l := sc.loads[e.ID]
	if l == nil {
		ctx, cancel := context.WithCancel(c.bg)
		l = &segLoad{entry: e, cancel: cancel, setup: make(chan struct{}), firstDone: make(chan struct{})}
		sc.loads[e.ID] = l
		sc.bytes += e.PlainSize
		go l.run(ctx, c, o)
		c.evictLocked()
	}
	l.lastUsed = time.Now()
	sc.mu.Unlock()
	go l.prioritize(c, o)
	return l
}

// reapIdle cancels loads nobody wants any more. Called periodically.
func (c *Client) reapIdle() {
	sc := c.cache
	sc.mu.Lock()
	defer sc.mu.Unlock()
	for id, l := range sc.loads {
		if !l.done() && l.waiters.Load() == 0 && time.Since(l.lastUsed) > idleTimeout {
			l.cancel()
			delete(sc.loads, id)
			sc.bytes -= l.entry.PlainSize
		}
	}
}

// touch marks the cached segments with these IDs as still wanted.
func (c *Client) touch(ids []string) {
	sc := c.cache
	sc.mu.Lock()
	defer sc.mu.Unlock()
	now := time.Now()
	for _, id := range ids {
		if l := sc.loads[id]; l != nil {
			l.lastUsed = now
		}
	}
}

// evictLocked drops finished segments, least recently used first, until
// the cache fits its budget. Loads still in progress are never dropped, so
// a seek can't cancel work another reader is waiting on.
func (c *Client) evictLocked() {
	sc := c.cache
	for sc.bytes > c.CacheSize {
		var victim *segLoad
		for _, l := range sc.loads {
			if l.done() && (victim == nil || l.lastUsed.Before(victim.lastUsed)) {
				victim = l
			}
		}
		if victim == nil {
			return
		}
		victim.cancel()
		delete(sc.loads, victim.entry.ID)
		sc.bytes -= victim.entry.PlainSize
	}
}

func (c *Client) evict() {
	c.cache.mu.Lock()
	defer c.cache.mu.Unlock()
	c.evictLocked()
}

// forget drops a failed load so the next read starts over.
func (c *Client) forget(l *segLoad) {
	sc := c.cache
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.loads[l.entry.ID] == l {
		l.cancel()
		delete(sc.loads, l.entry.ID)
		sc.bytes -= l.entry.PlainSize
	}
}

func (l *segLoad) done() bool {
	select {
	case <-l.setup:
	default:
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.err != nil || l.failed != nil || l.remaining == 0
}

func (l *segLoad) run(ctx context.Context, c *Client, first int64) {
	// A finished load may now be evictable, and may let older ones go.
	defer c.evict()
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
	l.lay = codec.NewLayout(p.K, loc.seg.CipherSize)
	l.shardSize = l.lay.ShardSize()
	l.perShard = l.lay.Chunks()
	l.plain = make([]byte, l.entry.PlainSize)
	total := p.K * l.perShard
	l.ready, l.closed = make([]chan struct{}, total), make([]bool, total)
	for g := range l.ready {
		l.ready[g] = make(chan struct{})
		if s, e := l.span(g); s >= e {
			l.closed[g] = true // past the end of the plaintext: nothing to fetch
			close(l.ready[g])
		} else {
			l.remaining++
		}
	}
	close(l.setup)

	// The chunk the first reader wants, alone.
	g0 := l.chunkFor(first)
	if !l.isReady(g0) && !l.fetch(ctx, c, g0) {
		l.fallback(ctx, c)
		close(l.firstDone)
		return
	}
	close(l.firstDone)

	// Then every data shard streams the rest of its chunks, all at once,
	// starting at the reader's stripe and wrapping around to the earlier
	// ones, so what's read next arrives first.
	c0 := g0 % l.perShard
	var wg sync.WaitGroup
	for d := range p.K {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if !l.fetchShard(ctx, c, d, c0) && ctx.Err() == nil {
				l.fallback(ctx, c)
			}
		}()
	}
	wg.Wait()
}

func (l *segLoad) holders(d int) []proto.Location {
	var hs []proto.Location
	for _, s := range l.l.loc.Shards {
		if s.Index == d {
			hs = append(hs, s)
		}
	}
	rand.Shuffle(len(hs), func(i, j int) { hs[i], hs[j] = hs[j], hs[i] })
	return hs
}

// fetchShard gets every chunk of data shard d not yet present: chunks
// [c0, end) first, then [0, c0), streaming runs from its holders and
// filling gaps one chunk at a time.
func (l *segLoad) fetchShard(ctx context.Context, c *Client, d, c0 int) bool {
	if c0 > 0 && !l.fetchRange(ctx, c, d, c0, l.perShard) {
		return false
	}
	return l.fetchRange(ctx, c, d, 0, l.perShard)
}

// fetchRange gets the missing chunks in [lo, hi) of data shard d.
func (l *segLoad) fetchRange(ctx context.Context, c *Client, d, lo, hi int) bool {
	next := func(from int) int {
		for cc := from; cc < hi; cc++ {
			if !l.isReady(d*l.perShard + cc) {
				return cc
			}
		}
		return hi
	}
	from := next(lo)
	for _, h := range l.holders(d) {
		for from < hi && ctx.Err() == nil {
			to := min(from+transfer.MaxChunkRun, hi)
			_, err := transfer.GetChunks(ctx, c.HTTP, c.key, h.Addr, l.entry.ID, d, l.l.root, l.l.loc.Params.MaxN, l.shardSize, from, to,
				func() { l.yield(ctx, c) },
				func(cc int, data []byte) { l.publish(d*l.perShard+cc, data) })
			from = next(from)
			if err != nil {
				break // try the next holder for what's left
			}
		}
		if from >= hi {
			return true
		}
	}
	// Last resort per chunk, then the caller falls back to parity.
	for cc := from; cc < hi; cc++ {
		if g := d*l.perShard + cc; !l.isReady(g) && !l.fetch(ctx, c, g) {
			return false
		}
	}
	return true
}

// yield pauses this segment's background streaming while a reader waits on
// some other segment, so holders' upload goes to what's needed now: a
// player seeking to an MKV's index at the end isn't stuck behind
// read-ahead. Blocking here stops reading the response, and TCP
// backpressure stops the holder sending.
func (l *segLoad) yield(ctx context.Context, c *Client) {
	for c.cache.waiting.Load() > 0 && l.waiters.Load() == 0 && ctx.Err() == nil {
		time.Sleep(2 * time.Millisecond)
	}
}

// fetch gets one chunk from any holder of its shard.
func (l *segLoad) fetch(ctx context.Context, c *Client, g int) bool {
	d, cc := g/l.perShard, g%l.perShard
	for _, h := range l.holders(d) {
		data, err := transfer.GetChunk(ctx, c.HTTP, c.key, h.Addr, l.entry.ID, d, l.l.root, l.l.loc.Params.MaxN, l.shardSize, cc)
		if err == nil && l.publish(g, data) {
			return true
		}
	}
	return false
}

// publish decrypts chunk g's ciphertext and wakes its readers.
func (l *segLoad) publish(g int, data []byte) bool {
	start, end := l.span(g)
	if len(data) < end-start {
		return false
	}
	plain, err := codec.DecryptRange(l.entry.Key, data[:end-start], int64(start))
	if err != nil {
		return false
	}
	l.mu.Lock()
	l.markLocked(g, plain)
	l.mu.Unlock()
	return true
}

// prioritize makes sure the chunk at offset o is being fetched now: for a
// reader that seeks into a segment another reader started elsewhere.
func (l *segLoad) prioritize(c *Client, o int64) {
	<-l.setup
	if l.err != nil {
		return
	}
	<-l.firstDone // the first chunk is fetched by run itself
	g := l.chunkFor(o)
	if l.isReady(g) {
		return
	}
	ctx, cancel := context.WithTimeout(c.bg, time.Minute)
	defer cancel()
	l.fetch(ctx, c, g) // run's shard streams or fallback cover a failure
}

// span returns the plaintext byte range chunk g covers (chunk g is chunk
// g%perShard of data shard g/perShard).
func (l *segLoad) span(g int) (start, end int) {
	start, end = l.lay.Span(g/l.perShard, g%l.perShard)
	return min(start, len(l.plain)), min(end, len(l.plain))
}

func (l *segLoad) chunkFor(o int64) int {
	d, cc := l.lay.Locate(int(o))
	return d*l.perShard + cc
}

func (l *segLoad) isReady(g int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closed[g]
}

// markLocked publishes chunk g's plaintext and wakes its readers. Caller
// holds l.mu.
func (l *segLoad) markLocked(g int, plain []byte) {
	if l.closed[g] {
		return
	}
	s, _ := l.span(g)
	copy(l.plain[s:], plain)
	l.closed[g] = true
	l.remaining--
	close(l.ready[g])
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
			if l.closed[g] {
				continue
			}
			if err != nil {
				l.closed[g] = true
				close(l.ready[g])
				continue
			}
			s, e := l.span(g)
			l.markLocked(g, plain[s:e])
		}
	})
}

// wait blocks until the chunk holding offset o is available and returns
// where that chunk's plaintext ends.
func (l *segLoad) wait(ctx context.Context, c *Client, o int64) (end int, err error) {
	select {
	case <-l.setup:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	if l.err != nil {
		return 0, l.err
	}
	g := l.chunkFor(o)
	if !l.isReady(g) {
		l.waiters.Add(1)
		c.cache.waiting.Add(1)
		defer l.waiters.Add(-1)
		defer c.cache.waiting.Add(-1)
	}
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

// Open returns a seekable reader over a pool file.
func (c *Client) Open(ctx context.Context, m Manifest) *File {
	return c.OpenRange(ctx, m, -1)
}

// OpenRange is Open for a reader that won't read past byte end (-1 for no
// limit): read-ahead stops there, so a bounded range read doesn't fetch
// data nobody asked for.
func (c *Client) OpenRange(ctx context.Context, m Manifest, end int64) *File {
	if end < 0 || end > m.Size {
		end = m.Size
	}
	return &File{c: c, ctx: ctx, m: m, end: end, ahead: map[int]bool{}}
}

type File struct {
	c   *Client
	ctx context.Context
	m   Manifest
	end int64 // read-ahead limit
	off int64

	mu    sync.Mutex
	cur   int          // segment most recently read
	ahead map[int]bool // read-ahead scheduled after these segments
}

func (f *File) Size() int64 { return f.m.Size }

// Close is a no-op: segments belong to the client's shared cache.
func (f *File) Close() error { return nil }

func (f *File) segmentAt(off int64) (idx int, start int64) {
	for i, s := range f.m.Segments {
		if off < start+s.PlainSize {
			return i, start
		}
		start += s.PlainSize
	}
	return len(f.m.Segments), start
}

// readAhead starts the segments after i that fall within the read-ahead
// window, once segment i's first chunk is in (so they don't compete with
// it), and only while the reader is still in segment i.
func (f *File) readAhead(i int, l *segLoad) {
	f.mu.Lock()
	f.cur = i
	if f.ahead[i] {
		f.mu.Unlock()
		return
	}
	f.ahead[i] = true
	f.mu.Unlock()
	go func() {
		select {
		case <-l.firstDone:
		case <-f.ctx.Done():
			return
		}
		f.mu.Lock()
		stillHere := f.cur == i
		f.mu.Unlock()
		if !stillHere {
			return
		}
		// Segments starting within ReadAhead bytes after this one ends.
		start := f.segStart(i + 1)
		limit := start + f.c.ReadAhead
		for j := i + 1; j < len(f.m.Segments) && start < f.end && start < limit; j++ {
			f.c.segment(f.m.Segments[j], 0)
			start += f.m.Segments[j].PlainSize
		}
	}()
}

// window lists the IDs of the segments read-ahead covers after segment i.
func (f *File) window(i int) []string {
	var ids []string
	start := f.segStart(i + 1)
	limit := start + f.c.ReadAhead
	for j := i + 1; j < len(f.m.Segments) && start < f.end && start < limit; j++ {
		ids = append(ids, f.m.Segments[j].ID)
		start += f.m.Segments[j].PlainSize
	}
	return ids
}

func (f *File) segStart(i int) int64 {
	var s int64
	for j := range i {
		s += f.m.Segments[j].PlainSize
	}
	return s
}

func (f *File) ReadAt(p []byte, off int64) (int, error) {
	n := 0
	for n < len(p) {
		if off >= f.m.Size {
			return n, io.EOF
		}
		i, segStart := f.segmentAt(off)
		o := off - segStart
		l := f.c.segment(f.m.Segments[i], o)
		f.readAhead(i, l)
		f.c.touch(f.window(i))
		end, err := l.wait(f.ctx, f.c, o)
		if err != nil {
			if f.ctx.Err() == nil {
				f.c.forget(l) // retry from scratch on the next read
			}
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

// Cached reports whether segment i of this file is loaded or loading in
// the client's shared cache (for tests).
func (f *File) Cached(i int) bool {
	f.c.cache.mu.Lock()
	defer f.c.cache.mu.Unlock()
	return f.c.cache.loads[f.m.Segments[i].ID] != nil
}
