package integration

import (
	"bytes"
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
			if !f.Loading(seg + 1) {
				t.Fatalf("segment %d not prefetched while reading segment %d", seg+1, seg)
			}
		}
	}
}
