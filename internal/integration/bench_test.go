package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"mediapool/internal/client"
	"mediapool/internal/codec"
	"mediapool/internal/coord"
	"mediapool/internal/node"
)

// latencyProxy forwards TCP connections, delaying every byte by a fixed
// one-way delay without limiting throughput (data is queued with its
// arrival time and released when the delay has passed).
type latencyProxy struct {
	ln     net.Listener
	target string
	delay  atomic.Int64 // nanoseconds, one way
}

func newLatencyProxy(t *testing.T, target string) *latencyProxy {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &latencyProxy{ln: ln, target: target}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.pipe(c)
		}
	}()
	return p
}

func (p *latencyProxy) url() string { return "http://" + p.ln.Addr().String() }

func (p *latencyProxy) pipe(c net.Conn) {
	u, err := net.Dial("tcp", p.target)
	if err != nil {
		c.Close()
		return
	}
	go p.copy(u, c)
	p.copy(c, u)
}

func (p *latencyProxy) copy(dst, src net.Conn) {
	type pkt struct {
		b  []byte
		at time.Time
	}
	q := make(chan pkt, 4096)
	go func() {
		defer close(q)
		for {
			buf := make([]byte, 32<<10)
			n, err := src.Read(buf)
			if n > 0 {
				q <- pkt{buf[:n], time.Now()}
			}
			if err != nil {
				return
			}
		}
	}()
	for k := range q {
		time.Sleep(time.Until(k.at.Add(time.Duration(p.delay.Load()))))
		if _, err := dst.Write(k.b); err != nil {
			break
		}
	}
	dst.Close()
	src.Close()
}

func hostOf(u string) string {
	x, _ := url.Parse(u)
	return x.Host
}

type benchResult struct {
	name                string
	ttfb, seek, oldTTFB time.Duration
	mbps                float64
}

func median(ds []time.Duration) time.Duration {
	slices.Sort(ds)
	return ds[len(ds)/2]
}

// TestBenchmarkReadPaths measures how fast a member can start and sustain
// playback. Run with: MP_BENCH=1 go test ./internal/integration -run BenchmarkReadPaths -v -timeout 30m
func TestBenchmarkReadPaths(t *testing.T) {
	if os.Getenv("MP_BENCH") == "" {
		t.Skip("set MP_BENCH=1 to run the read-path benchmark")
	}
	const fileSize = 96 << 20
	data := randomFile(t, fileSize)
	var results []benchResult
	for _, seg := range []int{16 << 20, 64 << 20} {
		for _, path := range []string{"direct", "relay"} {
			results = append(results, benchCluster(t, data, seg, path)...)
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n%-28s %10s %10s %12s %14s\n", "scenario", "first byte", "seek", "throughput", "old first byte")
	for _, r := range results {
		fmt.Fprintf(&b, "%-28s %8dms %8dms %7.0f Mbit/s %12dms\n", r.name, r.ttfb.Milliseconds(), r.seek.Milliseconds(), r.mbps, r.oldTTFB.Milliseconds())
	}
	t.Log(b.String())
	fmt.Println(b.String())
}

func benchCluster(t *testing.T, data []byte, seg int, path string) []benchResult {
	c := newCluster(t, 16, func(cfg *coord.Config) {
		cfg.Params = codec.Params{K: 10, MaxN: 20}
		cfg.AnchoredN, cfg.OrphanN = 12, 14
		cfg.SegmentSize = seg
		cfg.OfflineAfter, cfg.DownAfter = time.Minute, 10*time.Minute
		cfg.ProofsPerTick = 0
		cfg.Logf = func(string, ...any) {}
	})
	for _, n := range c.nodes {
		_ = n // nodes log via t.Logf; fine
	}
	if _, err := c.client.Add(c.ctx, bytes.NewReader(data), "/bench.mkv", nil); err != nil {
		t.Fatal(err)
	}

	var proxies []*latencyProxy
	ctx, cancel := context.WithCancel(c.ctx)
	t.Cleanup(cancel)
	switch path {
	case "direct":
		for _, n := range c.nodes {
			addr, _ := n.Addr()
			p := newLatencyProxy(t, hostOf(addr))
			proxies = append(proxies, p)
			n.SetAddr(p.url(), "direct")
		}
	case "relay":
		p := newLatencyProxy(t, hostOf(c.url))
		proxies = append(proxies, p)
		for _, n := range c.nodes {
			c.direct[n].blocked.Store(true)
			go n.RunReachability(ctx, node.ReachOptions{Mode: "relay", RelayURL: p.url()})
		}
		deadline := time.Now().Add(10 * time.Second)
		for len(c.relay.Connected()) < len(c.nodes) {
			if time.Now().After(deadline) {
				t.Fatalf("only %d nodes tunnelled", len(c.relay.Connected()))
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	c.heartbeat()

	m, err := c.client.Stat(c.ctx, "/bench.mkv")
	if err != nil {
		t.Fatal(err)
	}
	measure := func(cond string) benchResult {
		r := benchResult{name: fmt.Sprintf("%dMi %s %s", seg>>20, path, cond)}
		var tt, sk, old []time.Duration
		buf := make([]byte, 64<<10)
		// A fresh client for every measurement: the shared segment cache
		// would otherwise serve repeats from memory.
		// Each is closed after use so its read-ahead stops competing.
		var open []*client.Client
		fresh := func() *client.Client {
			cl := c.newClient("alice")
			open = append(open, cl)
			return cl
		}
		closeAll := func() {
			for _, cl := range open {
				cl.Close()
			}
			open = nil
			time.Sleep(500 * time.Millisecond) // let holders' rate limits recover
		}
		for i := range 3 {
			f := fresh().Open(c.ctx, m)
			start := time.Now()
			if _, err := f.ReadAt(buf, 0); err != nil {
				t.Fatal(err)
			}
			tt = append(tt, time.Since(start))
			f.Close()
			closeAll()

			f = fresh().Open(c.ctx, m)
			off := int64(len(data))*3/4 + int64(i)*12345
			start = time.Now()
			if _, err := f.ReadAt(buf, off); err != nil {
				t.Fatal(err)
			}
			sk = append(sk, time.Since(start))
			closeAll()
			if !bytes.Equal(buf, data[off:off+int64(len(buf))]) {
				t.Fatal("seek read wrong bytes")
			}
			f.Close()

			start = time.Now()
			if _, err := fresh().ReadSegment(c.ctx, m.Segments[0]); err != nil {
				t.Fatal(err)
			}
			old = append(old, time.Since(start))
			closeAll()
		}
		r.ttfb, r.seek, r.oldTTFB = median(tt), median(sk), median(old)
		f := fresh().Open(c.ctx, m)
		start := time.Now()
		n, err := io.Copy(io.Discard, f)
		if err != nil || n != int64(len(data)) {
			t.Fatalf("sequential read: %d bytes, %v", n, err)
		}
		r.mbps = float64(n*8) / time.Since(start).Seconds() / 1e6
		f.Close()
		return r
	}

	var out []benchResult
	out = append(out, measure("raw"))
	for _, n := range c.nodes {
		n.SetLimits(0, 10e6/8, 0, false) // 10 Mbit/s upload, like a home connection
	}
	for _, p := range proxies {
		p.delay.Store(int64(20 * time.Millisecond)) // 40 ms round trip
	}
	c.heartbeat()
	out = append(out, measure("home (10Mbit/node, 40ms)"))
	return out
}
