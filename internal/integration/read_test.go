package integration

import (
	"bytes"
	"fmt"
	"io"
	"math/rand/v2"
	"testing"
	"time"

	"mediapool/internal/coord"
	"mediapool/internal/proto"
)

// Range reads return exactly the right bytes at arbitrary offsets, across
// chunk, shard and segment boundaries (8 MiB segments, k=4: 2 MiB shards of
// eight chunks each).
func TestRangeReads(t *testing.T) {
	c := newCluster(t, 12, func(cfg *coord.Config) {
		cfg.SegmentSize = 8 << 20
		cfg.OfflineAfter, cfg.DownAfter = 10*time.Second, time.Minute // big uploads, no churn here
	})
	data := randomFile(t, 19<<20+12345) // 3 segments, the last one short
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/big.mkv", nil); err != nil {
		t.Fatal(err)
	}
	m, err := c.client.Stat(c.ctx, "/big.mkv")
	if err != nil {
		t.Fatal(err)
	}
	f := c.client.Open(c.ctx, m)
	defer f.Close()
	r := rand.New(rand.NewPCG(1, 2))
	offsets := []int64{0, 1<<20 - 3, 2<<20 - 1, 8<<20 - 5, 8 << 20, 16<<20 + 7, int64(len(data)) - 100}
	for range 40 {
		offsets = append(offsets, r.Int64N(int64(len(data))))
	}
	for _, off := range offsets {
		n := min(int64(r.IntN(3<<20)+1), int64(len(data))-off)
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
			t.Fatalf("ReadAt(%d, %d): %v", off, n, err)
		}
		if !bytes.Equal(buf, data[off:off+n]) {
			t.Fatalf("ReadAt(%d, %d) returned wrong bytes", off, n)
		}
	}
	if got := c.readBack(c.client, "/big.mkv"); !bytes.Equal(got, data) {
		t.Fatal("sequential read mismatch")
	}
}

// With the data shards' holders offline, reads fall back to rebuilding
// segments from parity shards.
func TestRangeReadFallsBackToParity(t *testing.T) {
	c := newCluster(t, 14, nil)
	data := randomFile(t, 50<<10) // one segment: 4 data shards, 5 parity
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/x.mkv", nil); err != nil {
		t.Fatal(err)
	}
	c.settle("placed", 5*time.Second, func(s proto.SegmentStatus) bool { return s.Durable == 9 })
	// Take down every node holding one of its data shards (index < k).
	for _, n := range c.nodes {
		inv, _ := n.Inventory()
		for _, k := range inv {
			if k.Index < 4 && !n.IsBridge() {
				c.pause(n)
				break
			}
		}
	}
	c.heartbeat()
	if got := c.readBack(c.client, "/x.mkv"); !bytes.Equal(got, data) {
		t.Fatal("fallback read mismatch")
	}
}

// Sequential reading prefetches one segment ahead all the way through, so
// every segment is already loading when the reader reaches it.
func TestSequentialReadPrefetchesEverySegment(t *testing.T) {
	c := newCluster(t, 12, func(cfg *coord.Config) {
		cfg.OfflineAfter, cfg.DownAfter = 10*time.Second, time.Minute
	})
	data := randomFile(t, 640<<10) // ten 64 KiB segments
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/s.mkv", nil); err != nil {
		t.Fatal(err)
	}
	m, _ := c.client.Stat(c.ctx, "/s.mkv")
	f := c.client.Open(c.ctx, m)
	defer f.Close()
	buf := make([]byte, 16<<10)
	for off := int64(0); off < int64(len(data)); off += int64(len(buf)) {
		if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if seg := int(off / (64 << 10)); seg+1 < len(m.Segments) && off%(64<<10) == 48<<10 {
			// Three quarters into a segment, the next must already be loading.
			if !f.Cached(seg + 1) {
				t.Fatalf("segment %d not prefetched while reading segment %d", seg+1, seg)
			}
		}
	}
}

// A media server reads one file from several places at once: playback at
// the current position, a probe jumping to the end (an MKV's index and
// attachments), and subtitle extraction reading from the start. They share
// the client's segment cache, so none cancels the others' work and all
// return the right bytes.
func TestConcurrentReadersDontCancelEachOther(t *testing.T) {
	c := newCluster(t, 12, func(cfg *coord.Config) {
		cfg.SegmentSize = 1 << 20
		cfg.OfflineAfter, cfg.DownAfter = 10*time.Second, time.Minute
	})
	data := randomFile(t, 12<<20)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/movie.mkv", nil); err != nil {
		t.Fatal(err)
	}
	m, _ := c.client.Stat(c.ctx, "/movie.mkv")
	errs := make(chan error, 3)
	check := func(name string, off, n int64) {
		f := c.client.Open(c.ctx, m)
		buf := make([]byte, n)
		if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
			errs <- fmt.Errorf("%s: %v", name, err)
			return
		}
		if !bytes.Equal(buf, data[off:off+n]) {
			errs <- fmt.Errorf("%s: wrong bytes", name)
			return
		}
		errs <- nil
	}
	go check("playback", 6<<20, 4<<20)
	go check("probe at the end", int64(len(data))-(300<<10), 300<<10)
	go check("subtitle extraction", 0, int64(len(data)))
	for range 3 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	// The segments they fetched stay cached for the next reader.
	f := c.client.Open(c.ctx, m)
	for i := range m.Segments {
		if !f.Cached(i) {
			t.Fatalf("segment %d not kept in the shared cache", i)
		}
	}
}

// A bounded open (an rclone range read) doesn't prefetch past its range.
func TestBoundedOpenStopsReadAhead(t *testing.T) {
	c := newCluster(t, 12, func(cfg *coord.Config) {
		cfg.OfflineAfter, cfg.DownAfter = 10*time.Second, time.Minute
	})
	data := randomFile(t, 640<<10) // ten 64 KiB segments
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/r.mkv", nil); err != nil {
		t.Fatal(err)
	}
	m, _ := c.client.Stat(c.ctx, "/r.mkv")
	f := c.client.OpenRange(c.ctx, m, 128<<10) // the first two segments
	buf := make([]byte, 128<<10)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond) // give read-ahead a chance to (wrongly) start
	if f.Cached(2) || f.Cached(3) {
		t.Fatal("read ahead past the end of a bounded open")
	}
}

// Finished segments are evicted to keep the cache within its budget.
func TestSegmentCacheBudget(t *testing.T) {
	c := newCluster(t, 12, func(cfg *coord.Config) {
		cfg.OfflineAfter, cfg.DownAfter = 10*time.Second, time.Minute
	})
	c.client.CacheSize = 256 << 10 // four 64 KiB segments
	data := randomFile(t, 1280<<10)
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/b.mkv", nil); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c.readBack(c.client, "/b.mkv"), data) {
		t.Fatal("mismatch")
	}
	m, _ := c.client.Stat(c.ctx, "/b.mkv")
	f := c.client.Open(c.ctx, m)
	cached := 0
	for i := range m.Segments {
		if f.Cached(i) {
			cached++
		}
	}
	if cached > 6 { // the budget, plus loads that were still in flight at eviction time
		t.Fatalf("%d of %d segments cached with a 4-segment budget", cached, len(m.Segments))
	}
}
