package mediapool

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config"
	"github.com/rclone/rclone/vfs"
	"github.com/rclone/rclone/vfs/vfscommon"

	"mediapool/pkg/mediapool"
	"mediapool/pkg/mediapool/mediapooltest"
)

// readerAt is what each workload reader needs: a handle that can ReadAt.
type readerAt interface {
	io.ReaderAt
	io.Closer
}

type opener func(t *testing.T) readerAt

type workloadResult struct {
	name           string
	probe          time.Duration // header + last 2 MiB
	playFirst      time.Duration // first 256 KiB at 40%
	playMbps       float64       // the following 24 MiB
	extract        time.Duration // the whole file from the start
	extractMbps    float64
	playAloneFirst time.Duration // first byte with no other reader running
}

// jellyfin runs what a media server does when a file is opened: a probe
// reading the header and then the end (an MKV's index and attachments),
// playback from the middle, and subtitle extraction reading everything
// from the start, all at once on separate handles.
func jellyfin(t *testing.T, name string, open opener, data []byte) workloadResult {
	r := workloadResult{name: name}
	size := int64(len(data))
	read := func(h readerAt, off, n int64) {
		buf := make([]byte, n)
		if _, err := h.ReadAt(buf, off); err != nil && err != io.EOF {
			t.Errorf("%s: ReadAt(%d, %d): %v", name, off, n, err)
			return
		}
		if !bytes.Equal(buf, data[off:off+n]) {
			t.Errorf("%s: wrong bytes at %d", name, off)
		}
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		h := open(t)
		defer h.Close()
		start := time.Now()
		read(h, 0, 64<<10)
		read(h, size-2<<20, 2<<20)
		r.probe = time.Since(start)
	}()
	go func() {
		defer wg.Done()
		h := open(t)
		defer h.Close()
		off := size * 4 / 10
		start := time.Now()
		read(h, off, 256<<10)
		r.playFirst = time.Since(start)
		start = time.Now()
		for o := off + 256<<10; o < off+24<<20; o += 1 << 20 {
			read(h, o, 1<<20)
		}
		r.playMbps = float64(24<<20*8) / time.Since(start).Seconds() / 1e6
	}()
	go func() {
		defer wg.Done()
		h := open(t)
		defer h.Close()
		start := time.Now()
		for o := int64(0); o < size; o += 1 << 20 {
			read(h, o, min(1<<20, size-o))
		}
		r.extract = time.Since(start)
		r.extractMbps = float64(size*8) / r.extract.Seconds() / 1e6
	}()
	wg.Wait()
	return r
}

// TestBenchmarkMediaServerWorkload compares our client with rclone's VFS on
// top of the backend, with every node's upload capped at 10 Mbit/s. Run
// with: MP_BENCH=1 go test ./backend/mediapool -run BenchmarkMediaServer -v -timeout 30m
func TestBenchmarkMediaServerWorkload(t *testing.T) {
	if os.Getenv("MP_BENCH") == "" {
		t.Skip("set MP_BENCH=1 to run the media-server benchmark")
	}
	const size = 96 << 20
	data := make([]byte, size)
	rand.Read(data)

	var results []workloadResult
	for _, sc := range []struct {
		name string
		mk   func(t *testing.T, p *mediapooltest.Pool, member string) opener
	}{
		{"our client, shared cache", func(t *testing.T, p *mediapooltest.Pool, member string) opener {
			c := client(t, p, member)
			return func(t *testing.T) readerAt { return mustOpen(t, c) }
		}},
		{"our client, a client per reader", func(t *testing.T, p *mediapooltest.Pool, member string) opener {
			return func(t *testing.T) readerAt { return mustOpen(t, client(t, p, member)) }
		}},
		{"rclone vfs, cache off", func(t *testing.T, p *mediapooltest.Pool, member string) opener {
			return vfsOpener(t, p, member, func(o *vfscommon.Options) {})
		}},
		{"rclone vfs, cache full (suggested)", func(t *testing.T, p *mediapooltest.Pool, member string) opener {
			ci := fs.GetConfig(context.Background())
			ci.BufferSize = 32 << 20
			return vfsOpener(t, p, member, func(o *vfscommon.Options) {
				o.CacheMode = vfscommon.CacheModeFull
				o.ChunkSize = 16 << 20
				o.ReadAhead = 64 << 20
			})
		}},
	} {
		// A fresh pool per scenario, so no scenario reads another's cache.
		p := mediapooltest.StartWith(t, 16, mediapooltest.Options{K: 10, MaxN: 20, AnchoredN: 12, OrphanN: 14, SegmentSize: 16 << 20})
		up := client(t, p, "alice")
		if _, err := up.Put(context.Background(), "/movies/Bench (2026)/Bench (2026).mkv", bytes.NewReader(data), time.Now()); err != nil {
			t.Fatal(err)
		}
		for _, n := range p.Nodes {
			n.SetLimits(0, 10e6/8, 0, false) // a home uplink
		}
		time.Sleep(time.Second) // let a heartbeat report the caps
		// Playback alone, on its own client/VFS so it doesn't warm the
		// workload's cache; 1 MiB so it's past the holders' burst allowance.
		h := sc.mk(t, p, "bob")(t) // another member: rclone shares a client per identical config
		start := time.Now()
		buf := make([]byte, 1<<20)
		if _, err := h.ReadAt(buf, size/10); err != nil {
			t.Fatal(err)
		}
		alone := time.Since(start)
		h.Close()
		time.Sleep(time.Second) // let holders' rate limits recover
		r := jellyfin(t, sc.name, sc.mk(t, p, "alice"), data)
		r.playAloneFirst = alone
		results = append(results, r)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "\n96 MiB file, 16 nodes each capped at 10 Mbit/s upload, 16 MiB segments, k=10\n")
	fmt.Fprintf(&b, "%-36s %10s %12s %12s %12s %14s\n", "scenario", "first byte", "probe", "play first", "play rate", "extract (rate)")
	fmt.Fprintf(&b, "%-36s %10s %12s %12s %12s %14s\n", "", "(1MiB,alone)", "(concurrent)", "(concurrent)", "(concurrent)", "(concurrent)")
	for _, r := range results {
		fmt.Fprintf(&b, "%-36s %8dms %10dms %10dms %7.0fMbit/s %6.1fs (%3.0fMbit/s)\n",
			r.name, r.playAloneFirst.Milliseconds(), r.probe.Milliseconds(), r.playFirst.Milliseconds(), r.playMbps, r.extract.Seconds(), r.extractMbps)
	}
	t.Log(b.String())
	fmt.Println(b.String())
}

func client(t *testing.T, p *mediapooltest.Pool, member string) *mediapool.Client {
	c, err := mediapool.Open(p.Config(member))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func mustOpen(t *testing.T, c *mediapool.Client) readerAt {
	r, err := c.Open(context.Background(), "/movies/Bench (2026)/Bench (2026).mkv")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func vfsOpener(t *testing.T, p *mediapooltest.Pool, member string, tune func(*vfscommon.Options)) opener {
	if err := config.SetCacheDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	f := newFs(t, p, member, "")
	opt := vfscommon.Opt
	tune(&opt)
	v := vfs.New(context.Background(), f, &opt)
	t.Cleanup(func() { v.Shutdown() })
	return func(t *testing.T) readerAt {
		h, err := v.OpenFile("movies/Bench (2026)/Bench (2026).mkv", os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
}
